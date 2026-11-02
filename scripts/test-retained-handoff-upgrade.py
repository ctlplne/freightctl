#!/usr/bin/env python3
"""Refusal contracts for rehearsal boundaries; real PostgreSQL evidence is separate."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("handoff_upgrade", Path(__file__).with_name("qualify-retained-handoff-upgrade.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class UpgradeBoundaries(unittest.TestCase):
    def snapshots(self):
        old = {"migration_ledger": [{"version": i, "digest": "a" * 64} for i in range(1, 34)],
               "role_authority_sha256": "unchanged-role-authority", "sequences": [["events_global_seq", "7|t"]],
               "forced_rls_tables": 1, "tables": [{"table": "freightctl_schema", "rows": 33, "sha256": "old-ledger"},
                                                 {"table": "workflow_runs", "rows": 2, "sha256": "all-old-fields"}]}
        new = copy.deepcopy(old)
        new["migration_ledger"] += [{"version": 34, "digest": "b" * 64}, {"version": 35, "digest": "c" * 64}]
        new["tables"][0].update(rows=35, sha256="appended-ledger")
        new["tables"].append({"table": module.NEW_TABLE, "rows": 0, "sha256": "empty"})
        new["forced_rls_tables"] += 1
        return old, new

    def catalogs(self):
        function = ["freightctl_collected_run_status", "x uuid", "CREATE OR REPLACE FUNCTION public.freightctl_collected_run_status(x uuid) RETURNS boolean AS 'original' LANGUAGE sql", "postgres", None, None]
        old = {"relations": [[name, "r", True, True, "postgres", "runtime-rw", None] for name in ("workflow_runs", "events", "delivery_intents")],
               "columns": [["workflow_runs", 1, "run_id"]], "constraints": [["workflow_runs", "run_fk", "original"]],
               "indexes": [["workflow_runs", "existing_index", "original"]], "policies": [["workflow_runs", "scope", "tenant AND actor"]],
               "schemas": [["public", "postgres", "original"]], "default_grants": None,
               "triggers": [["workflow_runs", "existing_guard", "original trigger"]],
               "functions": [function, ["unrelated_function", "", "original body", "postgres", "restricted", None]]}
        new = copy.deepcopy(old)
        indexes = sorted({"handoff_pk", "handoff_planned_unique", "collection_handoff_pending", "collection_handoff_successor", "collection_handoff_history", "collection_handoff_input"})
        new["relations"].append([module.NEW_TABLE, "r", True, True, "postgres", "runtime-rw", None])
        for name in indexes:
            new["relations"].append([name, "i", False, False, "postgres", None, None])
            new["indexes"].append([module.NEW_TABLE, name, "new index"])
        new["columns"].append([module.NEW_TABLE, 1, "id"])
        for name in sorted(module.ADDED_FUNCTIONS):
            if name.endswith("_v33"):
                renamed = copy.deepcopy(function)
                renamed[0] = name
                renamed[2] = renamed[2].replace("public.freightctl_collected_run_status(", "public." + name + "(")
                new["functions"].append(renamed)
            else:
                new["functions"].append([name, "", "expected new body", "postgres", None, None])
        new["functions"][0][2] = "new wrapper body"
        new["triggers"] += [[table, name, "new guard"] for table, name in sorted(module.ADDED_TRIGGERS)]
        new["constraints"] += [[table, name, "TRIGGER DEFERRABLE INITIALLY DEFERRED"] for table, name in sorted(module.ADDED_CONSTRAINTS)]
        return old, new

    def test_exact_additive_rows_pass_but_history_authority_sequences_and_invented_handoffs_fail(self):
        old, new = self.snapshots()
        module.compare_rows(old, new)
        for mutate in [lambda d: d["tables"][1].update(sha256="rewritten-plan"),
                       lambda d: d["tables"][-1].update(rows=1),
                       lambda d: d.update(role_authority_sha256="new-role"),
                       lambda d: d.update(sequences=[]),
                       lambda d: d.update(forced_rls_tables=1),
                       lambda d: d["migration_ledger"][1].update(digest="changed-applied-migration")]:
            changed = copy.deepcopy(new)
            mutate(changed)
            with self.assertRaises(RuntimeError):
                module.compare_rows(old, changed)

    def test_catalog_refuses_changed_rls_grants_policy_indexes_triggers_and_unrelated_functions(self):
        old, new = self.catalogs()
        module.compare_catalog(old, new)
        for mutate in [lambda d: d["relations"][0].__setitem__(3, False),
                       lambda d: d["relations"][0].__setitem__(5, "PUBLIC write"),
                       lambda d: d["policies"][0].__setitem__(2, "true"),
                       lambda d: d["indexes"][0].__setitem__(2, "different index"),
                       lambda d: d["constraints"][0].__setitem__(2, "changed original constraint"),
                       lambda d: d["constraints"][-1].__setitem__(2, "TRIGGER NOT DEFERRABLE"),
                       lambda d: d["triggers"][0].__setitem__(2, "different trigger"),
                       lambda d: d["functions"][0].__setitem__(4, "PUBLIC write"),
                       lambda d: d["functions"][1].__setitem__(2, "different unrelated body"),
                       lambda d: d["functions"].append(["unexpected_function", "", "new authority", "postgres", None, None]),
                       lambda d: d["indexes"].pop()]:
            changed = copy.deepcopy(new)
            mutate(changed)
            with self.assertRaises(RuntimeError):
                module.compare_catalog(old, changed)
        changed = copy.deepcopy(new)
        next(r for r in changed["functions"] if r[0].endswith("_v33"))[2] = "relaxed original guard"
        with self.assertRaises(RuntimeError):
            module.compare_catalog(old, changed)

    def test_query_or_identity_substitution_cannot_redirect_administrative_init(self):
        good = b"postgres://postgres:synthetic-password@127.0.0.1:25432/freightctl?sslmode=disable"
        module.retained_dsn(good)
        for bad in [good.replace(b"127.0.0.1", b"example.invalid"), good.replace(b"25432", b"5432"),
                    good.replace(b"/freightctl", b"/other"), good.replace(b"postgres:synthetic", b"other:synthetic"),
                    good + b"&host=example.invalid", good + b"&dbname=other", good + b"&sslmode=disable",
                    good + b"#ignored", good.replace(b"sslmode=disable", b"sslmode=require")]:
            with self.assertRaises(ValueError):
                module.retained_dsn(bad)

    def test_refs_refuse_symlinks_broad_permissions_and_unbounded_reads(self):
        with tempfile.TemporaryDirectory(prefix="freightctl-handoff-upgrade-refs-") as tmp:
            p = Path(tmp) / "reference"
            p.write_bytes(b"synthetic")
            p.chmod(0o600)
            self.assertEqual(module.read_protected(p, 32), b"synthetic")
            with self.assertRaises(ValueError):
                module.read_protected(p, 1)
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                module.read_protected(p, 32)
            p.chmod(0o600)
            link = Path(tmp) / "symlink"
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                module.read_protected(link, 32)

    def test_wrong_binary_schema_refuses_before_reading_refs_or_starting_postgresql(self):
        with tempfile.TemporaryDirectory(prefix="freightctl-upgrade-version-refusal-") as tmp:
            version = Path(tmp) / "version.json"
            version.write_text(json.dumps({"schema_version": 36}))
            exercise = module.Upgrade.__new__(module.Upgrade)
            exercise.binary = Path(tmp) / "unexecuted-binary"
            calls = []
            def observe(label, arguments):
                calls.append(arguments)
                return version
            exercise.command = observe
            with self.assertRaisesRegex(RuntimeError, "schema35 binary"):
                exercise.run()
            self.assertEqual(calls, [[str(exercise.binary), "schema-version"]])


if __name__ == "__main__":
    unittest.main()
