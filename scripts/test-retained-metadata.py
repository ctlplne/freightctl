#!/usr/bin/env python3
"""Refuse resource substitution/exposure before any backup maintenance command."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location("retained_metadata", Path(__file__).with_name("qualify-retained-metadata.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MaintenanceBoundaries(unittest.TestCase):
    def setUp(self):
        self.cid = "a" * 64
        self.metadata = {
            "Id": self.cid, "Name": "/freightctl-postgres-v1", "State": {"Running": False},
            "Config": {"Labels": {"freightctl.workspace": str(module.ROOT)}},
            "HostConfig": {"Memory": 536870912, "NanoCpus": 1000000000,
                           "PortBindings": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25432"}]}},
        }

    def test_synced_manifest_is_private_and_cannot_replace_original_evidence(self):
        with tempfile.TemporaryDirectory(prefix="freightctl-manifest-refusal-") as tmp:
            exercise = SimpleNamespace(private=Path(tmp), manifest={"state": "first failure"})
            path = module.save_manifest(exercise)
            original = path.read_bytes()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            exercise.manifest = {"state": "later retry"}
            with self.assertRaises(FileExistsError):
                module.save_manifest(exercise)
            self.assertEqual(path.read_bytes(), original)

    def test_refuses_identity_resource_and_network_substitution(self):
        module.validate_resource(self.metadata, self.cid)
        replacements = [
            ("Id", "b" * 64), ("Name", "/another-postgres"),
            ("Config", {"Labels": {"freightctl.workspace": "/another/workspace"}}),
            ("State", {"Running": True}),
        ]
        for field, value in replacements:
            with self.subTest(field=field):
                bad = copy.deepcopy(self.metadata)
                bad[field] = value
                with self.assertRaises(ValueError):
                    module.validate_resource(bad, self.cid)
        for field, value in [("Memory", 0), ("NanoCpus", 0),
                             ("PortBindings", {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "25432"}]})]:
            with self.subTest(field=field):
                bad = copy.deepcopy(self.metadata)
                bad["HostConfig"][field] = value
                with self.assertRaises(ValueError):
                    module.validate_resource(bad, self.cid)
        for unsafe_id in ["freightctl-postgres-v1", "a" * 63, "b" * 64, "a" * 64 + "; stop other"]:
            with self.subTest(container_id=unsafe_id), self.assertRaises(ValueError):
                module.validate_resource(self.metadata, unsafe_id)

    def test_evidence_parent_refuses_broad_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="freightctl-metadata-refusal-") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            module.private_directory(root)
            exposed = root / "exposed"
            exposed.mkdir(mode=0o755)
            exposed.chmod(0o755)
            link = root / "linked"
            link.symlink_to(root, target_is_directory=True)
            for path in [exposed, link]:
                with self.subTest(path=path.name), self.assertRaises(ValueError):
                    module.private_directory(path)

    def test_checksum_ledger_starts_with_schema_and_refuses_changed_or_missing_versions(self):
        directory = module.ROOT / "internal/store"
        ledger = [{"version": 1, "digest": module.digest(directory / "schema.sql")},
                  {"version": 2, "digest": module.digest(directory / "002_event_binding.sql")}]
        module.verify_migrations(ledger)
        changed = copy.deepcopy(ledger)
        changed[1]["digest"] = "0" * 64
        for bad in [[], ledger[1:], list(reversed(ledger)), changed]:
            with self.subTest(ledger=bad), self.assertRaises(RuntimeError):
                module.verify_migrations(bad)

    def test_policy_parser_comparison_refuses_changed_data_grants_authority_and_predicates(self):
        # These are comparison/refusal contracts, not PostgreSQL runtime evidence.
        with tempfile.TemporaryDirectory(prefix="freightctl-policy-refusal-") as tmp:
            exercise = module.Exercise.__new__(module.Exercise)
            exercise.private = Path(tmp)
            exercise.restore_name = "freightctl_metadata_restore_" + "a" * 32
            exercise.manifest = {}
            old = ["example", "scope", "PERMISSIVE", ["public"], "ALL", "((tenant_id = 'x'))", "((tenant_id = 'x'))"]
            canonical = old[:5] + ["(tenant_id = 'x')", "(tenant_id = 'x')"]
            tables = [{"rows": 1, "sha256": "exact"}]
            old_catalog = {"policies": [old], "constraints": [], "relations": [["example", "protected"]]}
            new_catalog = {**old_catalog, "policies": [canonical]}
            def save_catalog(label, catalog):
                wire = json.dumps(catalog)
                (exercise.private / (label + "-catalog.stdout")).write_text(wire + "\n")
                return {"tables": tables, "catalog_sha256": hashlib.sha256(wire.encode()).hexdigest()}
            def save_actual(catalog):
                return save_catalog("restored", catalog)
            def parse_source(label, query, database):
                self.assertEqual(database, exercise.restore_name)
                self.assertTrue(query.endswith("ROLLBACK;"))
                return json.dumps(canonical)
            exercise.sql = parse_source
            original = save_catalog("original-before", old_catalog)
            restored = save_actual(new_catalog)
            exercise.compare_restore(original, restored)
            changed_rows = {**restored, "tables": [{"rows": 0, "sha256": "changed"}]}
            with self.assertRaises(RuntimeError):
                exercise.compare_restore(original, changed_rows)
            changed_grants = save_actual({**new_catalog, "relations": [["example", "PUBLIC write"]]})
            with self.assertRaisesRegex(RuntimeError, "protected catalog evidence"):
                exercise.compare_restore(original, restored)
            with self.assertRaises(RuntimeError):
                exercise.compare_restore(original, changed_grants)
            changed_authority = canonical[:3] + [["other_role"]] + canonical[4:]
            changed_role = save_actual({**new_catalog, "policies": [changed_authority]})
            with self.assertRaises(RuntimeError):
                exercise.compare_restore(original, changed_role)
            # Source parser output never equals a restored, permissive replacement.
            permissive = save_actual({**new_catalog, "policies": [canonical[:5] + ["true", "true"]]})
            with self.assertRaises(RuntimeError):
                exercise.compare_restore(original, permissive)

    def test_check_parser_requires_the_original_constraint_identity_and_definition(self):
        exercise = module.Exercise.__new__(module.Exercise)
        exercise.restore_name = "freightctl_metadata_restore_" + "a" * 32
        exercise.manifest = {}
        old = ["example", "valid_size", "CHECK (((size >= 0)))"]
        canonical = ["example", "valid_size", "CHECK ((size >= 0))"]
        def parse_check(label, query, database):
            self.assertEqual(database, exercise.restore_name)
            self.assertIn('ALTER TABLE public."example" ADD CONSTRAINT "freightctl_check_probe_', query)
            self.assertIn(old[2], query)
            self.assertNotIn("DROP CONSTRAINT", query)
            self.assertTrue(query.endswith("ROLLBACK;"))
            return json.dumps(canonical)
        exercise.sql = parse_check
        exercise.compare_restore_checks([old], [canonical])
        self.assertEqual(exercise.manifest["check_parser_roundtrip"]["constraints"], [{"table": "example", "name": "valid_size"}])
        for changed in ([], [["example", "different_name", canonical[2]]],
                        [["example", "valid_size", "UNIQUE (size)"]],
                        [["example", "valid_size", "CHECK (true)"]]):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                exercise.compare_restore_checks([old], changed)


if __name__ == "__main__":
    unittest.main()
