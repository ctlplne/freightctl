#!/usr/bin/env python3
"""Exercise ledger refusals. Synthetic metadata never qualifies a protocol."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VALIDATE = runpy.run_path(str(ROOT / "scripts/check-records.py"))["validate"]


class RecordContracts(unittest.TestCase):
    def setUp(self):
        self.records = {p.stem: json.loads(p.read_text())
                        for p in (ROOT / "docs/qualification").glob("*.json")}

    def profile(self, ident="PP-AS2"):
        return next(p for p in self.records["protocol-profiles"]["profiles"] if p["id"] == ident)

    def row(self, ident="P-AS2-SEND"):
        return next(r for r in self.records["parity"]["rows"] if r["id"] == ident)

    def refused(self, root=ROOT):
        with self.assertRaises((AssertionError, KeyError)):
            VALIDATE(self.records, root)

    def declared_result(self, root):
        # A real file checks digest/path handling, not protocol behavior.
        proof = root / "synthetic-metadata.txt"
        proof.write_text("Metadata checker fixture; no protocol execution.\n")
        artifact = {"reference": proof.name, "sha256": hashlib.sha256(proof.read_bytes()).hexdigest()}
        profile = self.profile()
        for prerequisite in profile["prerequisites"]:
            prerequisite.update(state="resolved", evidence=[artifact])
        contract = profile["parity_rows"]["P-AS2-SEND"]
        result = {
            "candidate": "1" * 40,
            "environment": {"kind": "synthetic metadata fixture"},
            "steps": ["Test only the ledger validator"],
            "peer": {"independently_implemented": True, "version": "fixture", "artifact_sha256": "2" * 64},
            "observed_roles": contract["required_roles"],
            "cases": {case: {"state": "passed", "evidence": [artifact]}
                      for case in contract["required_cases"]},
        }
        profile["qualification"]["P-AS2-SEND"] = result
        self.row().update(state="verified locally", evidence=[proof.name])
        return result

    def test_current_records_remain_unqualified(self):
        self.assertEqual(VALIDATE(self.records, ROOT), (83, 12, 6))
        for profile in self.records["protocol-profiles"]["profiles"]:
            self.assertFalse(profile["qualification"])
            for ident in profile["parity_rows"]:
                self.assertEqual(self.row(ident)["state"], "planned")

    def test_unknown_profile_is_refused(self):
        self.row("P-AS4-SEND")["protocol_profile"] = "PP-NOT-PINNED"
        self.refused()

    def test_omitted_row_mapping_is_refused(self):
        del self.profile()["parity_rows"]["P-AS2-RECEIVE"]
        self.refused()

    def test_duplicate_profile_is_refused(self):
        self.records["protocol-profiles"]["profiles"].append(copy.deepcopy(self.profile()))
        self.refused()

    def test_version_drift_is_refused(self):
        self.records["protocol-profiles"]["baseline_version"] = "unreviewed"
        self.refused()

    def test_optimized_python_cannot_skip_record_checks(self):
        result = subprocess.run([sys.executable, "-O", str(ROOT / "scripts/check-records.py")],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remove Python -O/PYTHONOPTIMIZE", result.stderr)

    def test_marketing_is_not_a_normative_specification(self):
        self.profile()["specification"]["source_ids"] = ["GA-F"]
        self.refused()

    def test_unknown_acceptance_case_is_refused(self):
        self.profile()["parity_rows"]["P-AS2-SEND"]["required_cases"].append("AS2-INVENTED")
        self.refused()

    def test_custody_and_exact_as2_retry_cannot_be_dropped(self):
        original = copy.deepcopy(self.records)
        for case in ["C-DURABLE", "AS2-RETRY"]:
            with self.subTest(case=case):
                self.records = copy.deepcopy(original)
                self.profile()["parity_rows"]["P-AS2-SEND"]["required_cases"].remove(case)
                self.refused()

    def test_as4_push_and_pull_roles_are_required(self):
        original = copy.deepcopy(self.records)
        for row, role in [("P-AS4-SEND", "pull-responder"), ("P-AS4-SEND", "push-initiator"),
                          ("P-AS4-RECEIVE", "pull-initiator"), ("P-AS4-RECEIVE", "push-responder")]:
            with self.subTest(row=row):
                self.records = copy.deepcopy(original)
                self.profile("PP-AS4")["parity_rows"][row]["required_roles"].remove(role)
                self.refused()

    def test_document_or_open_prerequisites_cannot_qualify(self):
        self.row().update(state="verified locally", evidence=["GOAL.md"])
        self.refused()

    def test_complete_declared_metadata_only_passes_bookkeeping(self):
        with tempfile.TemporaryDirectory(prefix="freightctl-records-") as directory:
            root = Path(directory)
            self.declared_result(root)
            self.assertEqual(VALIDATE(self.records, root), (83, 12, 6))

    def test_skipped_or_missing_case_cannot_qualify(self):
        original = copy.deepcopy(self.records)
        for mode in ["skipped", "missing"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="freightctl-records-") as directory:
                self.records = copy.deepcopy(original)
                root = Path(directory)
                result = self.declared_result(root)
                if mode == "skipped":
                    result["cases"]["C-PEER"]["state"] = "skipped"
                else:
                    del result["cases"]["C-PEER"]
                self.refused(root)

    def test_peer_and_observed_roles_are_required(self):
        original = copy.deepcopy(self.records)
        for mode in ["peer", "roles", "digest"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="freightctl-records-") as directory:
                self.records = copy.deepcopy(original)
                root = Path(directory)
                result = self.declared_result(root)
                if mode == "peer":
                    result["peer"]["independently_implemented"] = False
                elif mode == "digest":
                    result["peer"]["artifact_sha256"] = "not-a-digest"
                else:
                    result["observed_roles"] = []
                self.refused(root)

    def test_modified_or_escaping_artifact_is_refused(self):
        original = copy.deepcopy(self.records)
        for mode in ["modified", "escape"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="freightctl-records-") as directory:
                self.records = copy.deepcopy(original)
                root = Path(directory)
                result = self.declared_result(root)
                if mode == "modified":
                    (root / "synthetic-metadata.txt").write_text("changed\n")
                else:
                    result["cases"]["C-PEER"]["evidence"] = [{"reference": "../outside", "sha256": "0" * 64}]
                self.refused(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
