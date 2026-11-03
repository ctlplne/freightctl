#!/usr/bin/env python3
"""Synthetic evidence refuses false public passes; never qualifies FTPS."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from ftps_contract import CLI_PAYLOAD, LFTP_CASES, LFTP_DOWNLOADS, NATIVE_PARENT_TESTS, NATIVE_TESTS

spec = importlib.util.spec_from_file_location("summary", Path(__file__).with_name("ci-ftps-summary.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class SummaryContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="freightctl-ftps-report-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / ".private" / ("ftps-" + "1" * 32)
        self.directory.mkdir(parents=True)
        self.path = self.directory / "manifest.json"
        self.result = self.root / ".private/result.json"
        source = self.root / "synthetic-source"
        source.write_text("report-contract fixture; no FTP execution\n")
        names = ("native-ftps-integration", "stock-lftp-version", "cli-explicit-upload", "cli-explicit-download", "cli-implicit-upload", "cli-implicit-download", "cli-explicit-lftp-probe", "cli-implicit-lftp-probe", "drop-exact-test-database")
        empty = hashlib.sha256(b"").hexdigest()
        steps = []
        for name in names:
            for extension in ("stdout", "stderr"):
                (self.directory / (name + "." + extension)).write_bytes(b"")
            steps.append({"name": name, "exit_code": 0, "stdout_sha256": empty, "stderr_sha256": empty})
        for step in steps:
            if step["name"] == "native-ftps-integration":
                data = "\n".join("--- PASS: " + name + " (0.01s)" for name in sorted(NATIVE_TESTS)).encode()
            elif step["name"] in ("cli-explicit-download", "cli-implicit-download"):
                data = CLI_PAYLOAD
            elif step["name"].endswith("-lftp-probe"):
                data = json.dumps({"state": "passed", "cases": LFTP_CASES, "stock_client_qualification": True, "payload_bytes": len(CLI_PAYLOAD), "payload_sha256": hashlib.sha256(CLI_PAYLOAD).hexdigest()}).encode()
            else:
                continue
            (self.directory / (step["name"] + ".stdout")).write_bytes(data)
            step["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        for mode in ("explicit", "implicit"):
            directory = self.directory / ("cli-" + mode + ".lftp")
            directory.mkdir()
            for name in LFTP_DOWNLOADS:
                (directory / name).write_bytes(CLI_PAYLOAD)
        before = {"runtime_role_safe": True, "migration_ledger": [{} for _ in range(35)], "forced_rls_tables": 63, "tables": [{} for _ in range(64)]}
        self.manifest = {"schema_version": 1, "kind": "stock-ftps-custody", "starting_commit": "a" * 40, "state": "passed",
                         "stock_curl_qualified": True, "stock_lftp_qualified": True, "retained_metadata_and_roles_unchanged": True,
                         "isolated_database_removed": True, "original_resource_state_restored": True, "sources_unchanged": True,
                         "native_client_only": False, "inference_performed": False, "scanner_engine_started": False,
                         "full_foundation_aggregate_executed": False, "full_journeys_qualified": False,
                         "cleanup_failures": [], "retained_before": before, "retained_after": copy.deepcopy(before),
                         "native_tests": {"required": NATIVE_PARENT_TESTS, "pass_records": len(NATIVE_TESTS), "failed_records": 0, "skipped_records": 0},
                         "steps": steps, "source_sha256": {"synthetic-source": hashlib.sha256(source.read_bytes()).hexdigest()}}

    def write(self):
        self.path.write_text(json.dumps(self.manifest))
        self.result.write_text(json.dumps({"state": "passed", "manifest_reference": str(self.path.relative_to(self.root)), "manifest_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}))

    def check(self):
        self.write()
        return summary.summarize(self.root, self.result, "a" * 40)

    def test_complete_synthetic_record_checks_only_reporting(self):
        report = self.check()
        self.assertEqual(report["state"], "passed")
        self.assertNotIn("retained_before", report)
        self.assertNotIn("steps", report)

    def test_standin_cannot_be_reported_as_stock(self):
        self.manifest["native_client_only"] = True
        with self.assertRaises(ValueError): self.check()

    def test_missing_or_skipped_tests_refuse(self):
        original = copy.deepcopy(self.manifest)
        for field, value in (("required", []), ("skipped_records", 1), ("pass_records", 0)):
            self.manifest = copy.deepcopy(original)
            self.manifest["native_tests"][field] = value
            with self.assertRaises(ValueError): self.check()

    def test_cleanup_authority_and_scope_changes_refuse(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (("isolated_database_removed", False), ("retained_metadata_and_roles_unchanged", False), ("scanner_engine_started", True), ("starting_commit", "b" * 40)):
            self.manifest = copy.deepcopy(original); self.manifest[key] = value
            with self.assertRaises(ValueError): self.check()
        self.manifest = copy.deepcopy(original)
        self.manifest["retained_after"]["runtime_role_safe"] = False
        with self.assertRaises(ValueError): self.check()

    def test_changed_native_output_refuses(self):
        self.write()
        (self.directory / "cli-explicit-upload.stdout").write_text("unexpected bytes")
        with self.assertRaises(ValueError): summary.summarize(self.root, self.result, "a" * 40)

    def test_changed_source_or_missing_command_refuses(self):
        self.write()
        (self.root / "synthetic-source").write_text("changed")
        with self.assertRaises(ValueError): summary.summarize(self.root, self.result, "a" * 40)
        self.manifest["steps"] = self.manifest["steps"][1:]
        with self.assertRaises(ValueError): self.check()

    def test_manifest_escape_and_checksum_refuse(self):
        self.write()
        header = json.loads(self.result.read_text()); header["manifest_reference"] = "../outside"
        self.result.write_text(json.dumps(header))
        with self.assertRaises(ValueError): summary.summarize(self.root, self.result, "a" * 40)
        self.write(); self.path.write_text("{}")
        with self.assertRaises(ValueError): summary.summarize(self.root, self.result, "a" * 40)

    def test_reported_test_counts_cannot_replace_native_execution(self):
        data = b"No native tests executed\n"
        (self.directory / "native-ftps-integration.stdout").write_bytes(data)
        self.manifest["steps"][0]["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError): self.check()

    def test_reported_success_cannot_replace_stock_download_bytes(self):
        data = b"different bytes"
        (self.directory / "cli-implicit-download.stdout").write_bytes(data)
        step = next(s for s in self.manifest["steps"] if s["name"] == "cli-implicit-download")
        step["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError): self.check()

    def test_lftp_qualification_and_commands_cannot_be_omitted(self):
        original = copy.deepcopy(self.manifest)
        self.manifest.pop("stock_lftp_qualified")
        with self.assertRaises(ValueError): self.check()
        self.manifest = original
        self.manifest["steps"] = [s for s in self.manifest["steps"] if s["name"] != "cli-implicit-lftp-probe"]
        with self.assertRaises(ValueError): self.check()

    def test_lftp_report_cannot_replace_actual_downloads(self):
        (self.directory / "cli-implicit.lftp/active.download").write_bytes(b"different bytes")
        with self.assertRaises(ValueError): self.check()

    def test_lftp_report_cannot_omit_required_cases(self):
        data = json.dumps({"state": "passed", "cases": [], "stock_client_qualification": True, "payload_bytes": len(CLI_PAYLOAD), "payload_sha256": hashlib.sha256(CLI_PAYLOAD).hexdigest()}).encode()
        (self.directory / "cli-explicit-lftp-probe.stdout").write_bytes(data)
        step = next(s for s in self.manifest["steps"] if s["name"] == "cli-explicit-lftp-probe")
        step["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError): self.check()

    def test_failure_diagnostics_only_emit_fixed_names_and_categories(self):
        secret = "sensitive fixture identity or password"
        report = {"state": "failed", "stage": "transfers", "code": "tls-transfer-refused", "reason": secret, "extra": secret}
        name = "TestFTPSStockLFTPCustody/explicit"
        data = ("stock lftp probe failed: " + json.dumps(report) + "\n--- FAIL: " + name + " (0.01s)\n--- FAIL: " + secret + " (0.01s)\n").encode()
        (self.directory / "native-ftps-integration.stdout").write_bytes(data)
        self.manifest["steps"][0]["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        self.manifest["state"] = "failed"
        self.write()
        result = summary.failure_diagnostics(self.root, self.result, "a" * 40)
        self.assertEqual(result, {"failed_native_tests": [name], "lftp_failures": [{"stage": "transfers", "code": "tls-transfer-refused"}]})
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(summary.failure_diagnostics(self.root, self.result, "b" * 40), {})

    def test_unverified_or_arbitrary_failure_diagnostics_refuse(self):
        data = json.dumps({"state": "failed", "stage": "transfers", "code": "private-value-must-not-escape", "reason": "sensitive"}).encode()
        (self.directory / "cli-explicit-lftp-probe.stdout").write_bytes(data)
        step = next(s for s in self.manifest["steps"] if s["name"] == "cli-explicit-lftp-probe")
        step["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        self.write()
        self.assertEqual(summary.failure_diagnostics(self.root, self.result, "a" * 40)["lftp_failures"], [])
        (self.directory / "native-ftps-integration.stdout").write_text("changed")
        self.assertEqual(summary.failure_diagnostics(self.root, self.result, "a" * 40), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
