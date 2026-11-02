#!/usr/bin/env python3
"""Reject stale, incomplete or exposing metadata CI evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("ci_metadata", Path(__file__).with_name("ci-metadata-summary.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MetadataSummaryContracts(unittest.TestCase):
    def fixture(self):
        source = module.ROOT / "internal/store"
        paths = [source / "schema.sql"] + sorted(source.glob("[0-9][0-9][0-9]_*.sql"))
        before = {"runtime_role_safe": True, "migration_ledger": [{"version": i+1, "digest": hashlib.sha256(p.read_bytes()).hexdigest()} for i, p in enumerate(paths)],
                  "tables": [{"table": "protected-"+str(i), "rows": 1, "sha256": "a"*64} for i in range(module.PROFILE["metadata_tables"])],
                  "forced_rls_tables": module.PROFILE["forced_rls_tables"], "role_authority_sha256": "b"*64, "sequences": [["protected-sequence", "7|t"]]}
        return {"state": "passed", "backup": {"file_and_directory_synced": True}, "before": before, "restored": copy.deepcopy(before),
                "restored_metadata_matches": True, "retained_database_unchanged": True, "original_stopped_state_restored": True,
                "exact_restore_database_removed": True, "inference_performed": False, "scanner_engine_started": False,
                "steps": [{"name": "protected-operation", "exit_code": 0, "stderr_reference": "private-errors"}],
                "private_payload": "must-not-appear-in-public-summary"}

    def summary(self, manifest):
        raw = json.dumps(manifest).encode()
        return module.summarize({"state": "passed", "manifest_sha256": hashlib.sha256(raw).hexdigest()}, manifest, raw)

    def test_exact_profile_has_one_safe_result_with_no_raw_records_or_paths(self):
        summary = self.summary(self.fixture())
        self.assertEqual(summary["schema"], 35)
        self.assertEqual(summary["metadata_tables"], 64)
        self.assertEqual(summary["forced_rls_tables"], 63)
        self.assertEqual(summary["restored_rows"], 64)
        for value in ["protected-operation", "protected-sequence", "private-errors", "must-not-appear", "protected-0"]:
            self.assertNotIn(value, json.dumps(summary))

    def test_stale_schema_checksum_or_missing_version_cannot_report_a_pass(self):
        for change in [lambda m: m["before"]["migration_ledger"].pop(),
                       lambda m: m["before"]["migration_ledger"][0].update(digest="f"*64),
                       lambda m: m["restored"]["migration_ledger"].reverse()]:
            manifest = self.fixture()
            change(manifest)
            with self.assertRaisesRegex(module.EvidenceError, "schema_profile"):
                self.summary(manifest)

    def test_cleanup_sync_runtime_or_native_step_failure_cannot_report_a_pass(self):
        for change in [lambda m: m.update(original_stopped_state_restored=False),
                       lambda m: m.update(exact_restore_database_removed=False),
                       lambda m: m["backup"].update(file_and_directory_synced=False),
                       lambda m: m["before"].update(runtime_role_safe=False),
                       lambda m: m["steps"][0].update(exit_code=1),
                       lambda m: m["steps"][0].update(exit_code=False),
                       lambda m: m.update(steps=[]),
                       lambda m: m.update(state="failed"),
                       lambda m: m.update(scanner_engine_started=True),
                       lambda m: m.update(inference_performed=True)]:
            manifest = self.fixture()
            change(manifest)
            with self.assertRaises(module.EvidenceError):
                self.summary(manifest)

    def test_changed_rows_grants_sequences_rls_or_table_counts_cannot_report_a_pass(self):
        for change in [lambda m: m["restored"]["tables"][0].update(sha256="f"*64),
                       lambda m: m["before"]["tables"].pop(),
                       lambda m: m["before"].update(forced_rls_tables=0),
                       lambda m: m["restored"].update(role_authority_sha256="f"*64),
                       lambda m: m["restored"].update(sequences=[]),
                       lambda m: m["before"].pop("role_authority_sha256"),
                       lambda m: m["before"]["tables"][0].update(rows=True)]:
            manifest = self.fixture()
            change(manifest)
            with self.assertRaises(module.EvidenceError):
                self.summary(manifest)

    def test_manifest_substitution_does_not_keep_the_verified_hash(self):
        manifest = self.fixture()
        data = json.dumps(manifest).encode()
        with self.assertRaisesRegex(module.EvidenceError, "hash_mismatch"):
            module.summarize({"state": "passed", "manifest_sha256": "0"*64}, manifest, data)

    def test_missing_or_wrongly_typed_evidence_is_a_fixed_safe_refusal(self):
        for change in [lambda m: m.update(before=[]), lambda m: m.update(restored=None),
                       lambda m: m.update(backup=[]), lambda m: m.update(steps=[None])]:
            manifest = self.fixture()
            change(manifest)
            with self.assertRaises(module.EvidenceError):
                self.summary(manifest)
        with self.assertRaises(module.EvidenceError):
            module.summarize([], {}, b"{}")

    def test_evidence_file_must_be_bounded_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory(prefix="freightctl-ci-metadata-") as tmp:
            path = Path(tmp) / "manifest"
            path.write_bytes(b"{}")
            self.assertEqual(module.read_bounded(path), b"{}")
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(module.EvidenceError):
                module.read_bounded(link)
            path.write_bytes(b"")
            with self.assertRaises(module.EvidenceError):
                module.read_bounded(path)


if __name__ == "__main__":
    unittest.main()
