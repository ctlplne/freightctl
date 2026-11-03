#!/usr/bin/env python3
"""Synthetic evidence refuses false public passes; never qualifies FTPS."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import ftps_cli_governance as governance
import ftps_browser_evidence as browser

from ftps_contract import CLI_PAYLOAD, LFTP_CASES, LFTP_DOWNLOADS, NATIVE_PARENT_TESTS, NATIVE_TESTS

spec = importlib.util.spec_from_file_location("summary", Path(__file__).with_name("ci-ftps-summary.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def synthetic_governance_outputs():
    """Bookkeeping fixtures only; no CLI or FTP execution is represented."""
    values = {name: b"" for name in governance.COMMANDS}
    actor = "a1b2c3d4-1111-4111-8111-000000000001"
    good_id, bad_id = "a1b2c3d4-1111-4111-8111-000000000002", "a1b2c3d4-1111-4111-8111-000000000003"
    def put(name, value):
        values[name] = json.dumps(value).encode()
    accounts = []
    for revision, state in ((1, "active"), (2, "active"), (3, "revoked")):
        accounts.append({"id": actor, "revision": revision, "authority_revision": revision, "state": state, "changed_event_id": "event-" + str(revision), "observed_at": "synthetic"})
    for name, account in zip(("credential-account-create", "credential-account-rotate", "credential-account-revoke"), accounts):
        put(name, {"account": account, "replayed": False})
    put("credential-final-account", dict(accounts[2], observed_at="later synthetic query"))
    for name, account in (("credential-rotate-replay", accounts[1]), ("credential-revoke-replay", accounts[2])):
        put(name, {"account": account, "replayed": True})
    put("credential-rotated-identity", {"actor_id": actor, "authority_revision": 2})
    entry = {"path": "/guard.bin", "file_id": "synthetic-guard", "revision": 1}
    for name in ("credential-original-stat", "credential-rotated-stat", "credential-final-stat"):
        put(name, entry)
    put("credential-page-one", {"entries": [entry], "next": "/guard.bin"})
    put("credential-page-two", {"entries": [{"path": "/rotated-accepted.bin"}], "next": ""})
    put("intake-held-list", {"entries": [], "next": ""})
    put("intake-check-list", {"checks": [{"path": path, "file_id": ident, "state": "held"} for path, ident in (("/good.csv", good_id), ("/bad.csv", bad_id))]})
    for name, ident, payload in (("good", good_id, governance.GOOD_CSV), ("bad", bad_id, governance.BAD_CSV)):
        put("intake-" + name + "-held", {"check": {"state": "held", "file_id": ident, "binding": {"file": {"sha256": hashlib.sha256(payload).hexdigest()}}}})
    policy_hash = "b" * 64
    put("intake-good-passed", {"check": {"file_id": good_id, "state": "passed", "attempts": 1, "code": "valid_csv", "report_hash": "a" * 64, "policy_hash": policy_hash}})
    put("intake-bad-rejected", {"check": {"file_id": bad_id, "state": "rejected", "attempts": 1, "code": "invalid_cell", "report_hash": "", "policy_hash": policy_hash}})
    put("intake-policy-register", {"resource": {"definition_hash": policy_hash}})
    put("intake-published-stat", {"file_id": good_id})
    for first, again, resource in (("intake-good-release", "intake-release-replay", {"file_id": good_id, "state": "released"}), ("intake-policy-revoke", "intake-policy-replay", {"state": "revoked"})):
        put(first, {"resource": resource, "replayed": False}); put(again, {"resource": resource, "replayed": True})
    for name, states, count in (("credential-peer", ["writer-open-before-rotation", "writer-open-before-revocation"], 2), ("intake-peer", ["uploads-held", "passed-still-unreleased", "only-approved-revision-published"], 4)):
        messages = [{"state": state, "resumed": True} for state in states]
        messages.append({"state": "passed", "case_count": count, "all_data_resumed": True})
        values[name] = b"\n".join(json.dumps(m).encode() for m in messages) + b"\n"
    return values


class SummaryContracts(unittest.TestCase):
    def test_browser_binding_uses_the_go_file_size_bytes_contract(self):
        payload = governance.GOOD_CSV
        check = {"attempts":1,"policy_hash":"a" * 64,"binding":{"file":{"size_bytes":len(payload),"sha256":hashlib.sha256(payload).hexdigest()}}}
        browser.verify_check_binding(check,"a" * 64,payload)
        for mutation in (lambda v:v["binding"]["file"].update(size_bytes=len(payload)+1),lambda v:v["binding"]["file"].update(sha256="0"*64),lambda v:v.update(attempts=2),lambda v:v["binding"]["file"].pop("size_bytes")):
            changed = copy.deepcopy(check);mutation(changed)
            with self.assertRaises(ValueError): browser.verify_check_binding(changed,"a"*64,payload)
        with self.assertRaises(ValueError): browser.verify_check_binding(check,"b"*64,payload)

    def test_browser_evidence_diagnostics_refuse_arbitrary_private_messages(self):
        exact = "browser check byte/policy binding differs"
        self.manifest["browser_evidence_failure"] = {"mode":"explicit","invariant":exact}
        self.write()
        self.assertEqual(summary.failure_diagnostics(self.root,self.result,"a"*40)["browser_evidence_failure"],{"mode":"explicit","invariant":exact})
        self.manifest["browser_evidence_failure"]["invariant"] = "private browser data must not be printed"
        self.write()
        self.assertNotIn("browser_evidence_failure",summary.failure_diagnostics(self.root,self.result,"a"*40))
        self.assertEqual(browser.safe_failure(ValueError("private")),"unclassified browser evidence failure")
        self.assertEqual(browser.safe_failure(KeyError("private")),"missing required browser evidence field")

    def test_browser_http_refusal_requires_exact_label_status_and_error(self):
        exact = json.dumps({"error":"operation_state_conflict"})
        browser.verify_http_outcome("bad-release",409,exact)
        browser.verify_http_outcome("wire-0",200,'{}')
        for label,status,body in (("bad-release",200,exact),("bad-release",403,exact),("bad-release",500,exact),("wire-0",409,exact),("unknown",409,exact),("bad-release",409,'{"error":"database_unavailable"}'),("bad-release",409,'{"error":"operation_state_conflict","extra":"private"}')):
            with self.assertRaises(ValueError):
                browser.verify_http_outcome(label,status,body)

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
        names = ("native-ftps-integration", "stock-lftp-version", "cli-explicit-upload", "cli-explicit-download", "cli-implicit-upload", "cli-implicit-download", "cli-explicit-lftp-probe", "cli-implicit-lftp-probe", "drop-exact-test-database") + tuple("cli-" + mode + "-gov-" + name for mode in ("explicit", "implicit") for name in governance.COMMANDS)
        empty = hashlib.sha256(b"").hexdigest()
        steps = []
        governance_outputs = synthetic_governance_outputs()
        for name in names:
            for extension in ("stdout", "stderr"):
                (self.directory / (name + "." + extension)).write_bytes(b"")
            steps.append({"name": name, "exit_code": 0, "stdout_sha256": empty, "stderr_sha256": empty})
        for step in steps:
            suffix = governance.command_suffix(step["name"])
            if suffix:
                data = governance_outputs[suffix]
                if suffix in governance.REFUSALS:
                    diagnostic = governance.REFUSALS[suffix]
                    (self.directory / (step["name"] + ".stderr")).write_bytes(diagnostic)
                    step["exit_code"] = 1
                    step["stderr_sha256"] = hashlib.sha256(diagnostic).hexdigest()
            elif step["name"] == "native-ftps-integration":
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

    def test_required_browser_profile_cannot_be_satisfied_by_stock_only(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root, self.result, "a" * 40, require_browser=True)

    def test_browser_claim_without_closed_original_outputs_is_refused(self):
        self.manifest["browser_requested"] = True
        self.manifest["browser_governance"] = {"explicit":{"state":"passed"},"implicit":{"state":"passed"}}
        with self.assertRaises(ValueError): self.check()

    def test_browser_failure_diagnostics_only_reveal_fixed_phase_and_source_line(self):
        secret = "private browser selector, tenant or credential"
        name = "browser-explicit-operator"
        data = (json.dumps({"state":"failed","phase":"policy-register","line":321,"failure":secret}) + "\n" + json.dumps({"state":"failed","audit":"credential-create-review","accessibility_rule_ids":["color-contrast"],"selector":secret})).encode()
        (self.directory / (name + ".stdout")).write_bytes(data)
        self.manifest["steps"].append({"name":name,"exit_code":1,"stdout_sha256":hashlib.sha256(data).hexdigest()})
        self.write()
        report = summary.failure_diagnostics(self.root, self.result, "a" * 40)
        self.assertEqual(report["browser_failures"], [{"command":name,"phase":"policy-register","source_line":321}])
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(report["accessibility_failures"], [{"command":name,"audit":"credential-create-review","rule_ids":["color-contrast"]}])
        data = json.dumps({"state":"failed","phase":secret,"line":321,"audit":"credential-create-review","accessibility_rule_ids":[secret]}).encode()
        (self.directory / (name + ".stdout")).write_bytes(data)
        self.manifest["steps"][-1]["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        self.write()
        self.assertNotIn("browser_failures",summary.failure_diagnostics(self.root,self.result,"a" * 40))
        self.assertNotIn("accessibility_failures",summary.failure_diagnostics(self.root,self.result,"a" * 40))

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
        self.assertEqual(result, {"failed_native_tests": [name], "lftp_failures": [{"stage": "transfers", "code": "tls-transfer-refused"}], "failed_cli_commands": []})
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

    def test_optimized_python_cannot_disable_wire_assertions(self):
        for name in ("ftps-probe.py", "ftps-governance-probe.py"):
            result = subprocess.run([sys.executable, "-O", str(Path(__file__).with_name(name)), "--reference", str(self.root / "unread-reference")], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            report = json.loads(result.stdout)
            self.assertEqual(report["state"], "failed")
            self.assertEqual(report["failure_class"], "UnsafeOptimization")

    def replace_output(self, name, data, extension="stdout"):
        (self.directory / (name + "." + extension)).write_bytes(data)
        step = next(s for s in self.manifest["steps"] if s["name"] == name)
        step[extension + "_sha256"] = hashlib.sha256(data).hexdigest()

    def test_cli_expected_refusal_cannot_hide_an_unrelated_error(self):
        self.replace_output("cli-explicit-gov-intake-wrong-release-refused", b"freightctl: database unavailable\n", "stderr")
        with self.assertRaises(ValueError): self.check()

    def test_cli_failure_diagnostics_never_emit_raw_errors(self):
        name = "cli-explicit-gov-intake-wrong-release-refused"
        self.replace_output(name, b"private diagnostic must not be public", "stderr")
        self.write()
        result = summary.failure_diagnostics(self.root, self.result, "a" * 40)
        self.assertEqual(result["failed_cli_commands"], [name])
        self.assertNotIn("private diagnostic", json.dumps(result))

    def test_cli_replay_cannot_change_the_committed_receipt(self):
        data = json.loads((self.directory / "cli-explicit-gov-credential-rotate-replay.stdout").read_bytes())
        data["account"]["authority_revision"] = 9
        self.replace_output("cli-explicit-gov-credential-rotate-replay", json.dumps(data).encode())
        with self.assertRaises(ValueError): self.check()

    def test_cli_namespace_and_wire_proofs_cannot_be_claims_only(self):
        self.replace_output("cli-implicit-gov-credential-peer", b'{"state":"passed","case_count":2,"all_data_resumed":true}\n')
        with self.assertRaises(ValueError): self.check()

    def test_cli_governance_commands_and_revision_binding_are_required(self):
        original = copy.deepcopy(self.manifest["steps"])
        self.manifest["steps"] = [s for s in self.manifest["steps"] if s["name"] != "cli-explicit-gov-intake-policy-revoke"]
        with self.assertRaises(ValueError): self.check()
        self.manifest["steps"] = original
        self.replace_output("cli-implicit-gov-intake-published-stat", b'{"file_id":"another-revision"}')
        with self.assertRaises(ValueError): self.check()


if __name__ == "__main__":
    unittest.main(verbosity=2)
