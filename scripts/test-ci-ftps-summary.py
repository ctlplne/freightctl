#!/usr/bin/env python3
"""Synthetic evidence refuses false public passes; never qualifies FTPS."""
import copy
import hashlib
import importlib.util
import json
import shutil
from metadata_contract import CURRENT_PROFILE, PREVIOUS_PROFILE, LEGACY_PROFILE, RETAINED_PROFILE, migration_ledger
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import ftps_cli_governance as governance
import ftps_browser_evidence as browser
import ftps_ticket_governance as tickets
import ftps_browser_tickets as browser_tickets

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
    def test_collection_browser_progress_and_first_failure_are_private_typed_and_source_bound(self):
        name = 'cli-explicit-collection-browser'
        progress = {'kind': 'ftps-collection-browser-progress', 'mode': 'explicit', 'stage': 'preview-visible'}
        failure = {'kind': 'ftps-collection-browser-failure', 'mode': 'explicit', 'stage': 'preview-visible',
            'error_kind': 'assertion', 'source_file': 'driver', 'source_line': 203}
        def report(values):
            raw = b'\n'.join(json.dumps(v).encode() for v in values)+b'\n'
            (self.directory/(name+'.stdout')).write_bytes(raw)
            (self.directory/(name+'.stderr')).write_bytes(b'private-evidence-canary')
            self.manifest['steps'] = [s for s in self.manifest['steps'] if s['name'] != name]+[{
                'name': name, 'exit_code': 1, 'stdout_sha256': hashlib.sha256(raw).hexdigest(),
                'stderr_sha256': hashlib.sha256(b'private-evidence-canary').hexdigest()}]
            self.write()
            return summary.failure_diagnostics(self.root, self.result, 'a'*40)
        result = report([progress, failure, dict(progress, stage='complete'), dict(failure, stage='files-ready')])
        self.assertEqual(result['collection_browser_progress'], [{'command': name, **progress}])
        self.assertEqual(result['collection_browser_failures'], [{'command': name, **failure}])
        self.assertNotIn('private-evidence-canary', json.dumps(result))
        for change in ({'stage': 'private-evidence-canary'}, {'source_file': '/private/key'},
                {'source_line': True}, {'source_line': 4001}, {'exception': 'private-evidence-canary'},
                {'error_kind': 'private-evidence-canary'}, {'mode': 'implicit'}):
            result = report([dict(failure, **change)])
            self.assertNotIn('collection_browser_failures', result)
            self.assertNotIn('private-evidence-canary', json.dumps(result))
        (self.directory/(name+'.stdout')).write_bytes(b'changed')
        self.assertEqual(summary.failure_diagnostics(self.root, self.result, 'a'*40), {})

    def test_collection_browser_failure_only_exposes_its_fixed_command_name(self):
        name = 'cli-explicit-collection-browser'
        raw = b'private-evidence-canary /private/credential'
        (self.directory/(name+'.stdout')).write_bytes(b'')
        (self.directory/(name+'.stderr')).write_bytes(raw)
        self.manifest['steps'].append({'name': name, 'exit_code': 'timeout',
            'stdout_sha256': hashlib.sha256(b'').hexdigest(), 'stderr_sha256': hashlib.sha256(raw).hexdigest()})
        self.write()
        result = summary.failure_diagnostics(self.root, self.result, 'a'*40)
        self.assertIn(name, result['failed_cli_commands'])
        self.assertNotIn('private-evidence-canary', json.dumps(result))
        self.assertNotIn('/private/credential', json.dumps(result))

    def test_collection_browser_requirement_refuses_missing_nonboolean_and_claim_only_profiles(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root, self.result, 'a'*40, require_workflow_collection_browser=True)
        self.assertNotIn('ftps_collection_browser_phases', self.check())
        for value in (True, 1, 'true'):
            self.manifest['workflow_collection_browser_requested'] = value
            with self.assertRaises(ValueError):
                self.check()

    def test_collection_browser_reporter_reopens_both_modes_and_refuses_forged_aggregate(self):
        old = {'state': 'passed', 'synthetic': True}
        checked = {'state': 'passed', 'browser_phases': 1, 'accessibility_audits': 3,
            'source_contacts': 0, 'source_work_performed': False, 'bytes_qualified': False}
        self.manifest.update(workflow_dispatch_approvals_requested=True, workflow_collection_metadata_requested=True,
            workflow_collection_browser_requested=True,
            workflow_dispatch_governance={m: old for m in ('explicit', 'implicit')},
            collection_metadata_governance={m: old for m in ('explicit', 'implicit')},
            collection_browser_governance={m: checked for m in ('explicit', 'implicit')},
            collection_browser_output_sha256={m: {'synthetic': 'a'*64} for m in ('explicit', 'implicit')})
        with patch.object(summary.dispatch, 'validate', return_value=old), patch.object(summary.collection_metadata, 'validate', return_value=old):
            with self.assertRaises(ValueError):
                self.check()
            with patch.object(summary.collection_browser, 'validate', return_value=checked) as verify:
                result = self.check()
                self.assertEqual(result['ftps_collection_browser_phases'], 2)
                self.assertEqual(result['ftps_collection_accessibility_audits'], 6)
                self.assertFalse(result['ftps_collection_browser_bytes_qualified'])
                self.assertEqual([call.args[2] for call in verify.call_args_list], ['explicit', 'implicit'])
                self.manifest['collection_browser_governance']['implicit'] = dict(checked, source_contacts=True)
                with self.assertRaises(ValueError):
                    self.check()

    def test_collection_metadata_requirement_cannot_be_satisfied_by_absence_or_profile_claims(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root, self.result, 'a'*40, require_workflow_collection_metadata=True)
        self.assertNotIn('ftps_collection_metadata_commands', self.check())
        for value in (True, 'true', 1):
            self.manifest['workflow_collection_metadata_requested'] = value
            with self.assertRaises(ValueError):
                self.check()

    def test_collection_metadata_reporter_reopens_both_original_scopes_and_refuses_claim_only(self):
        old = {'state': 'passed', 'synthetic': True}
        checked = {'state': 'passed', 'commands': 16, 'source_contacts': 0, 'attempts': 0, 'fences': 0,
            'saved_key_replays': 5, 'current_state': 'cancelled', 'source_state': 'revoked',
            'bytes_qualified': False, 'browser_qualified': False}
        self.manifest.update(workflow_dispatch_approvals_requested=True, workflow_collection_metadata_requested=True,
            workflow_dispatch_governance={mode: old for mode in ('explicit', 'implicit')},
            collection_metadata_governance={mode: checked for mode in ('explicit', 'implicit')},
            collection_metadata_output_sha256={'explicit': {'original': 'a'*64}, 'implicit': {'original': 'b'*64}})
        # These two stubs test reporter composition only. The actual collection
        # verifier's original file/hash/refusal contracts run in its own suite.
        with patch.object(summary.dispatch, 'validate', return_value=old):
            with self.assertRaises(ValueError):
                self.check()
            with patch.object(summary.collection_metadata, 'validate', return_value=checked) as verify:
                result = self.check()
                self.assertEqual(result['ftps_collection_metadata_commands'], 32)
                self.assertEqual(result['ftps_collection_metadata_saved_key_replays'], 10)
                self.assertFalse(result['ftps_collection_metadata_bytes_qualified'])
                self.assertFalse(result['ftps_collection_metadata_browser_qualified'])
                self.assertEqual([call.args[1] for call in verify.call_args_list], ['explicit', 'implicit'])
                self.manifest['collection_metadata_governance']['implicit'] = dict(checked, attempts=True)
                with self.assertRaises(ValueError):
                    self.check()

    def test_collection_metadata_failure_diagnostics_only_expose_bound_commands_and_fixed_categories(self):
        name = 'cli-explicit-collection-metadata-collection-start'
        raw = b'private-evidence-canary'
        (self.directory/(name+'.stdout')).write_bytes(b'')
        (self.directory/(name+'.stderr')).write_bytes(raw)
        self.manifest['steps'].append({'name': name, 'exit_code': 1,
            'stdout_sha256': hashlib.sha256(b'').hexdigest(), 'stderr_sha256': hashlib.sha256(raw).hexdigest()})
        self.manifest['collection_metadata_evidence_failure'] = {'mode': 'explicit', 'category': 'original-output-contract'}
        self.write()
        result = summary.failure_diagnostics(self.root, self.result, 'a'*40)
        self.assertIn(name, result['failed_cli_commands'])
        self.assertEqual(result['collection_metadata_evidence_failure'], {'mode': 'explicit', 'category': 'original-output-contract'})
        self.assertNotIn('private-evidence-canary', json.dumps(result))
        for field in ('mode', 'category'):
            self.manifest['collection_metadata_evidence_failure'][field] = 'private-evidence-canary'
            self.write()
            result = summary.failure_diagnostics(self.root, self.result, 'a'*40)
            self.assertNotIn('collection_metadata_evidence_failure', result)
            self.assertNotIn('private-evidence-canary', json.dumps(result))

    def test_encrypted_workflow_requires_explicit_profile_and_closed_original_outputs(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root,self.result,"a"*40,require_workflow_dispatch_encryption=True)
        for encrypted in (True, "true", 1):
            with self.subTest(encrypted=encrypted):
                self.manifest["workflow_dispatch_encryption_requested"]=encrypted
                with self.assertRaises(ValueError): self.check()
        self.manifest["workflow_dispatch_encryption_requested"]=True
        self.manifest["workflow_dispatch_approvals_requested"]=True
        self.manifest["workflow_dispatch_governance"]={mode:{"state":"passed","recipient_encrypted":True} for mode in ("explicit","implicit")}
        with self.assertRaises(ValueError): self.check()

    def test_required_workflow_dispatch_cannot_be_replaced_with_direct_or_claim_only_evidence(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root,self.result,"a"*40,require_workflow_dispatch_approvals=True)
        self.manifest["workflow_dispatch_approvals_requested"]=True
        self.manifest["workflow_dispatch_governance"]={mode:{"state":"passed"} for mode in ("explicit","implicit")}
        with self.assertRaises(ValueError): self.check()

    def test_check_failure_diagnostic_cannot_publish_paths_ids_errors_or_unbounded_counts(self):
        check = {"action": "refresh", "wire_phase": "waiting", "error_kind": "other",
                 "exact_file_visible": True, "exact_path_visible": True, "run_enabled": False,
                 "refresh_enabled": True, "original_responses": 12}
        self.assertEqual(browser.safe_check_diagnostic(check), check)
        for changed in (dict(check, raw_path="private"), dict(check, action="private filename"),
                        dict(check, wire_phase="private server error"), dict(check, error_kind="private exception"),
                        dict(check, exact_file_visible="private ID"), dict(check, original_responses=101),
                        dict(check, original_responses=True)):
            with self.subTest(changed=changed):
                self.assertIsNone(browser.safe_check_diagnostic(changed))

    def test_required_dispatch_cannot_accept_an_old_or_claim_only_profile(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root, self.result, "a" * 40, require_dispatch_approvals=True)
        self.manifest["dispatch_approvals_requested"] = True
        self.manifest["dispatch_governance"] = {mode: {"state": "passed"} for mode in ("explicit", "implicit")}
        with self.assertRaises(ValueError):
            self.check()

    def test_current_schema_cannot_be_rejected_by_stale_retained_profile(self):
        self.manifest["retained_schema"] = CURRENT_PROFILE["schema"]
        self.manifest["retained_before"]["migration_ledger"] = migration_ledger(self.root,CURRENT_PROFILE["schema"])
        self.manifest["retained_after"] = copy.deepcopy(self.manifest["retained_before"])
        self.assertEqual(self.check()["state"], "passed")

    def test_explicit_previous_schema38_remains_an_exact_read_only_profile(self):
        self.manifest["retained_schema"] = PREVIOUS_PROFILE["schema"]
        self.manifest["retained_before"]["migration_ledger"] = migration_ledger(self.root,PREVIOUS_PROFILE["schema"])
        self.manifest["retained_after"] = copy.deepcopy(self.manifest["retained_before"])
        self.assertEqual(self.check()["state"], "passed")

    def test_explicit_legacy_schema37_remains_an_exact_read_only_profile(self):
        self.manifest["retained_schema"] = LEGACY_PROFILE["schema"]
        self.manifest["retained_before"]["migration_ledger"] = migration_ledger(self.root,LEGACY_PROFILE["schema"])
        self.manifest["retained_after"] = copy.deepcopy(self.manifest["retained_before"])
        self.assertEqual(self.check()["state"], "passed")

    def test_explicit_direct_ftps_schema36_remains_an_exact_read_only_profile(self):
        self.manifest["retained_schema"] = 36
        self.manifest["retained_before"]["migration_ledger"] = migration_ledger(self.root,36)
        self.manifest["retained_after"] = copy.deepcopy(self.manifest["retained_before"])
        self.assertEqual(self.check()["state"], "passed")

    def test_explicit_unchanged_retained_schema35_is_a_separate_read_only_profile(self):
        self.manifest["retained_schema"] = RETAINED_PROFILE["schema"]
        self.manifest["retained_before"]["migration_ledger"] = migration_ledger(self.root,RETAINED_PROFILE["schema"])
        self.manifest["retained_after"] = copy.deepcopy(self.manifest["retained_before"])
        self.assertEqual(self.check()["state"],"passed")

    def test_failed_profile_diagnostic_cannot_print_raw_snapshot_or_failure_text(self):
        self.manifest["retained_schema"]="private reference must not appear"
        self.manifest["retained_before"]["migration_ledger"][0]["digest"]="private migration record"
        self.manifest["failure"]="private server failure text"
        self.write()
        result=summary.failure_diagnostics(self.root,self.result,"a"*40)
        self.assertEqual(result["postgres_profile"],{"declared_schema":None,"migration_records":CURRENT_PROFILE["schema"],"metadata_tables":64,"forced_rls_tables":63,"matches_exact_source_profile":False})
        self.assertNotIn("private",json.dumps(result))

    def test_declared_profile_cannot_substitute_missing_changed_or_unknown_migrations(self):
        for change in (
            lambda m:m.update(retained_schema=35),
            lambda m:m.update(retained_schema=CURRENT_PROFILE["schema"]+1),
            lambda m:m.update(retained_schema=True),
            lambda m:m.pop("retained_schema"),
            lambda m:m["retained_before"]["migration_ledger"].pop(),
            lambda m:m["retained_before"]["migration_ledger"][0].update(digest="f"*64),
            lambda m:m["retained_before"].update(forced_rls_tables=0),
        ):
            original=copy.deepcopy(self.manifest)
            change(self.manifest)
            self.manifest["retained_after"]=copy.deepcopy(self.manifest["retained_before"])
            with self.assertRaises(ValueError): self.check()
            self.manifest=original

    def test_browser_ticket_failure_diagnostic_reveals_only_fixed_stage(self):
        name="browser-ticket-explicit-browser"
        for stage in ("prepare","private-selector-or-credential"):
            data=json.dumps({"state":"failed","stage":stage,"failure":"private request details"}).encode()
            (self.directory/(name+".stdout")).write_bytes(data)
            (self.directory/(name+".stderr")).write_bytes(b"")
            step={"name":name,"exit_code":1,"stdout_sha256":hashlib.sha256(data).hexdigest(),"stderr_sha256":hashlib.sha256(b"").hexdigest()}
            self.manifest["steps"]=[s for s in self.manifest["steps"] if s["name"]!=name]+[step]
            self.write();result=summary.failure_diagnostics(self.root,self.result,"a"*40)
            self.assertNotIn("private",json.dumps(result))
            if stage=="prepare":self.assertEqual(result["browser_ticket_failures"],[{"command":name,"stage":"prepare"}])
            else:self.assertNotIn("browser_ticket_failures",result)

    def test_browser_ticket_api_refusal_requires_exact_original_category(self):
        browser_tickets.verify_http_outcome("foreign-status",404,b'{"error":"not_found"}')
        for label,status,body in (("foreign-status",200,b'{"error":"not_found"}'),("foreign-status",500,b'{"error":"not_found"}'),("foreign-status",404,b'{"error":"database_unavailable"}'),("foreign-status",404,b'{"error":"not_found","extra":"private"}'),("unknown",404,b'{"error":"not_found"}'),("create-0",200,b'{}')):
            with self.assertRaises(ValueError): browser_tickets.verify_http_outcome(label,status,body)

    def test_browser_ticket_replay_cannot_substitute_intent_key_or_receipt(self):
        first=({"idempotency_key":"original","selection":{"path":"/recovered.csv"}},{"upload":{"id":"one"},"replayed":False})
        second=copy.deepcopy(first);second[1]["replayed"]=True
        browser_tickets.verify_saved_replay(first,second)
        for mutate in (lambda v:v[0].update(idempotency_key="new"),lambda v:v[0]["selection"].update(path="/other.csv"),lambda v:v[1]["upload"].update(id="other"),lambda v:v[1].update(replayed=False)):
            changed=copy.deepcopy(second);mutate(changed)
            with self.assertRaises(ValueError): browser_tickets.verify_saved_replay(first,changed)

    def test_browser_ticket_dom_reading_cannot_substitute_bound_acceptance(self):
        u={"id":"11111111-1111-4111-8111-111111111111","state":"completed","committed_offset":len(tickets.PAYLOAD),"file_id":"22222222-2222-4222-8222-222222222222"}
        v={"state":"completed","path":"/recovered.csv","expected_size":str(len(tickets.PAYLOAD)),"committed_offset":str(len(tickets.PAYLOAD)),"expected_sha256":tickets.SHA256,"sftp_path":"/.freightctl/uploads/"+u["id"],"ftps_path":"/.freightctl/uploads/"+u["id"],"file_id":u["file_id"],"acceptance":"Accepted and held for checks and release"}
        browser_tickets.verify_visible_receipt(v,u)
        for changes in ({"file_id":"other"},{"path":"/other.csv"},{"committed_offset":"65536"},{"expected_sha256":"0"*64},{"acceptance":"published"},{"ftps_path":"/.freightctl/uploads/another"}):
            with self.assertRaises(ValueError): browser_tickets.verify_visible_receipt(dict(v,**changes),u)

    def test_required_browser_ticket_profile_cannot_be_satisfied_by_old_browser_or_cli_claims(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root, self.result, "a" * 40, require_browser_tickets=True)
        self.manifest["browser_requested"] = True
        self.manifest["browser_tickets_requested"] = True
        self.manifest["browser_ticket_governance"] = {"explicit":{"state":"passed"},"implicit":{"state":"passed"}}
        with self.assertRaises(ValueError): self.check()

    def test_browser_ticket_sigkill_cannot_approve_other_process_outcomes(self):
        browser_tickets.verify_outcome("browser-ticket-explicit-crash",-9,b"",b"")
        browser_tickets.verify_outcome("browser-ticket-implicit-crash",-9,b"",b"")
        for name,code in (("browser-ticket-explicit-browser",-9),("browser-ticket-explicit-peer",-9),("browser-ticket-explicit-restarted",-9),("browser-ticket-explicit-crash",0),("browser-ticket-explicit-crash",-15),("browser-ticket-unknown-crash",-9)):
            with self.assertRaises(ValueError): browser_tickets.verify_outcome(name,code,b"",b"")

    def test_required_public_ticket_profile_cannot_be_satisfied_by_old_profile(self):
        self.write()
        with self.assertRaises(ValueError):
            summary.summarize(self.root, self.result, "a" * 40, require_tickets=True)

    def test_ticket_claim_without_original_outputs_is_refused(self):
        self.manifest["tickets_requested"] = True
        self.manifest["ticket_governance"] = {"explicit": {"state": "passed"}, "implicit": {"state": "passed"}}
        with self.assertRaises(ValueError): self.check()

    def test_sigkill_is_allowed_only_for_exact_controlled_ftps_step(self):
        for mode in ("explicit", "implicit"):
            tickets.verify_outcome("ticket-" + mode + "-crash", -9, b"", b"")
        for name, code in (("cli-explicit", -9), ("ticket-explicit-restarted", -9), ("ticket-explicit-crash", 0),
                           ("ticket-explicit-crash", -15), ("ticket-unknown-crash", -9), ("ticket-explicit-crash-extra", -9)):
            with self.assertRaises(ValueError): tickets.verify_outcome(name, code, b"", b"")

    def test_ticket_refusal_requires_exact_result(self):
        tickets.verify_outcome("ticket-explicit-foreign-refused", 1, b"freightctl: not found\n", b"")
        for code, err, out in ((0,b"freightctl: not found\n",b""),(1,b"unavailable\n",b""),(1,b"freightctl: not found\n",b"private result")):
            with self.assertRaises(ValueError): tickets.verify_outcome("ticket-explicit-foreign-refused", code, err, out)
        tickets.verify_outcome("ticket-explicit-foreign-api", 0, b"", b"404")
        for code, err, out in ((0,b"",b"200"),(0,b"",b"500"),(0,b"warning",b"404"),(1,b"",b"404")):
            with self.assertRaises(ValueError): tickets.verify_outcome("ticket-explicit-foreign-api", code, err, out)

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
        source_root=Path(__file__).resolve().parents[1]/"internal/store"
        target=self.root/"internal/store"
        target.mkdir(parents=True)
        for p in [source_root/"schema.sql"]+sorted(source_root.glob("[0-9][0-9][0-9]_*.sql")):
            shutil.copyfile(p,target/p.name)
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
        before = {"runtime_role_safe": True, "migration_ledger": migration_ledger(self.root,CURRENT_PROFILE["schema"]), "forced_rls_tables": 63, "tables": [{} for _ in range(64)]}
        self.manifest = {"schema_version": 1, "retained_schema":CURRENT_PROFILE["schema"], "kind": "stock-ftps-custody", "starting_commit": "a" * 40, "state": "passed",
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

    def test_dispatch_failure_diagnostics_require_exact_bounded_phase_and_wire_observations(self):
        name = "cli-explicit-workflow-dispatch-browser-withdraw"
        probe = {"kind":"ftps-dispatch-failure", "phase":"withdraw", "stage":"dialog-close", "wire":"fulfill-replay",
                 "response_count":2, "response_overflow":False, "dialog_open":True, "decision_error_visible":False}
        (self.directory / (name + ".stderr")).write_bytes(b"private browser exception")
        self.manifest["steps"].append({"name":name,"exit_code":1,"stdout_sha256":"", "stderr_sha256":hashlib.sha256(b"private browser exception").hexdigest()})
        def report(value):
            self.replace_output(name, json.dumps(value).encode())
            self.write()
            return summary.failure_diagnostics(self.root,self.result,"a" * 40)
        self.assertEqual(report(probe)["dispatch_browser_failures"],[{"command":name, **probe}])
        for change in ({"stage":"private selector"}, {"phase":"request"}, {"wire":"private error"},
                       {"response_count":True}, {"response_count":9}, {"response_overflow":True},
                       {"dialog_open":"private path"}, {"stage":{}}, {"reason":"private credential"}):
            self.assertNotIn("dispatch_browser_failures",report(dict(probe, **change)))
        self.replace_output(name,b"changed without updating the original digest")
        (self.directory / (name + ".stdout")).write_bytes(b"unbound record")
        self.write()
        self.assertEqual(summary.failure_diagnostics(self.root,self.result,"a" * 40),{})

    def test_actual_dispatch_failure_emitter_keeps_errors_private_without_launching_browser(self):
        counter = self.directory / "emitter-counter.json"
        counter.write_text(json.dumps({"schema_version":1,"kind":"freightctl-ftps-contact-spy","accepted_connections":0,"stopped":False,"budget_exhausted":False}))
        script = '''
import assert from 'node:assert/strict';
const {qualifyOutboundDispatch}=await import(process.argv[2]);
const privateError=new Error('private selector or credential');
const region={getByText:()=>({isVisible:async()=>false})};
const page={getByRole:(kind)=>kind==='region'?region:{click:async()=>{throw privateError}},locator:()=>({isVisible:async()=>false})};
let failure;try{await qualifyOutboundDispatch(page,{url:'https://127.0.0.1:443',tenant:'synthetic',partner:'synthetic',dispatch_protocol:'ftps',dispatch_phase:'withdraw',receiver_log:process.argv[1]},()=>{},()=>{},()=>{})}catch(e){failure=e}
assert.equal(failure,privateError);
'''
        result = subprocess.run(["node","--input-type=module","-e",script,str(counter),Path(__file__).with_name("outbound-dispatch-browser.mjs").as_uri()],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0)
        self.assertNotIn(b"private selector or credential",result.stdout)
        messages=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(messages[-1],{"kind":"ftps-dispatch-failure","phase":"withdraw","stage":"navigation","wire":"idle","response_count":0,"response_overflow":False,"dialog_open":False,"decision_error_visible":False})
        self.assertEqual([m["stage"] for m in messages[:-1]],["contacts-before","navigation"])
        for m in messages[:-1]:self.assertIsNotNone(summary.dispatch.safe_browser_progress(m))

    def test_actual_stalled_dispatch_retains_progress_without_reaching_catch(self):
        counter=self.directory/"stalled-counter.json"
        counter.write_text(json.dumps({"schema_version":1,"kind":"freightctl-ftps-contact-spy","accepted_connections":0,"stopped":False,"budget_exhausted":False}))
        script='''
const {qualifyOutboundDispatch}=await import(process.argv[2]);
const page={getByRole:kind=>kind==='region'?{}:{click:async()=>new Promise(()=>{})}};
setTimeout(()=>process.exit(0),100);
await qualifyOutboundDispatch(page,{url:'https://127.0.0.1:443',tenant:'synthetic',partner:'synthetic',dispatch_protocol:'ftps',dispatch_phase:'withdraw',receiver_log:process.argv[1]},()=>{},()=>{},()=>{});
'''
        result=subprocess.run(["node","--input-type=module","-e",script,str(counter),Path(__file__).with_name("outbound-dispatch-browser.mjs").as_uri()],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0)
        messages=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([m["stage"] for m in messages],["contacts-before","navigation"])
        for m in messages:self.assertIsNotNone(summary.dispatch.safe_browser_progress(m))
        self.assertTrue(all(m["kind"]=="ftps-dispatch-progress" for m in messages))

    def test_failed_dispatch_progress_and_outcome_are_bounded_and_hash_bound(self):
        name="cli-implicit-workflow-dispatch-browser-withdraw"
        progress={"kind":"ftps-dispatch-progress","phase":"withdraw","stage":"dialog-close","wire":"fulfill-replay","response_count":2,"response_overflow":False,"dialog_open":None,"decision_error_visible":None}
        (self.directory/(name+".stderr")).write_bytes(b"private renderer exception")
        step={"name":name,"exit_code":"timeout","seconds":150.1234,"stdout_sha256":"","stderr_sha256":hashlib.sha256(b"private renderer exception").hexdigest()}
        self.manifest["steps"].append(step)
        def report(value):
            self.replace_output(name,json.dumps(value).encode());self.write()
            return summary.failure_diagnostics(self.root,self.result,"a"*40)
        result=report(progress)
        self.assertEqual(result["dispatch_browser_progress"],[{"command":name,**progress}])
        self.assertEqual(result["dispatch_command_outcomes"],[{"command":name,"outcome":"timeout","elapsed_seconds":150.123}])
        for changed in (dict(progress,stage="/private/credential"),dict(progress,phase="request"),dict(progress,response_count=999),dict(progress,secret="PRIVATE KEY"),dict(progress,wire="private error")):
            self.assertNotIn("dispatch_browser_progress",report(changed))
        for duration in (True,-1,3601,"private value"):
            step["seconds"]=duration
            self.assertIsNone(report(progress)["dispatch_command_outcomes"][0]["elapsed_seconds"])
        self.replace_output(name,json.dumps(progress).encode());self.write()
        (self.directory/(name+".stdout")).write_bytes(b"unbound progress")
        self.assertEqual(summary.failure_diagnostics(self.root,self.result,"a"*40),{})

    def test_dispatch_lifecycle_diagnostic_requires_exact_fixed_hash_bound_observation(self):
        name="cli-implicit-workflow-dispatch-browser-withdraw"
        (self.directory/(name+".stderr")).write_bytes(b"private startup or shutdown exception")
        self.manifest["steps"].append({"name":name,"exit_code":"timeout","seconds":150,"stdout_sha256":"","stderr_sha256":hashlib.sha256(b"private startup or shutdown exception").hexdigest()})
        lifecycle={"kind":"ftps-dispatch-lifecycle","phase":"withdraw","stage":"browser-close"}
        def report(value):
            self.replace_output(name,json.dumps(value).encode());self.write()
            return summary.failure_diagnostics(self.root,self.result,"a"*40)
        self.assertEqual(report(lifecycle)["dispatch_browser_lifecycle"],[{"command":name,**lifecycle}])
        for changed in (dict(lifecycle,stage="/private/key"),dict(lifecycle,phase="approve"),dict(lifecycle,exception="PRIVATE KEY"),dict(lifecycle,stage={})):self.assertNotIn("dispatch_browser_lifecycle",report(changed))
        self.replace_output(name,json.dumps(lifecycle).encode());self.write()
        (self.directory/(name+".stderr")).write_bytes(b"changed original exception")
        self.assertEqual(summary.failure_diagnostics(self.root,self.result,"a"*40),{})

    def test_lftp_failure_progress_is_a_bounded_fixed_action_from_original_output(self):
        spec = importlib.util.spec_from_file_location("lftp_probe",Path(__file__).with_name("lftp-probe.py"))
        probe = importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
        self.assertEqual(probe.observed_action(b"freightctl-stock-phase:setup\nfreightctl-stock-phase:pasv-download\nprivate error\n"),"pasv-download")
        for data in (b"private selector",b"freightctl-stock-phase:private-credential\n",b"prefix freightctl-stock-phase:active-upload\n",b"x" * ((4 << 20) + 1)):
            self.assertIsNone(probe.observed_action(data))
        name="cli-explicit-lftp-probe"
        for action, expected in (("active-upload",{"action":"active-upload"}),("private credential",{}),({},{})):
            self.replace_output(name,json.dumps({"state":"failed","stage":"transfers","code":"client-command-failed","action":action,"reason":"private value"}).encode())
            self.write()
            report=summary.failure_diagnostics(self.root,self.result,"a" * 40)
            self.assertEqual(report["lftp_failures"],[{"stage":"transfers","code":"client-command-failed",**expected}])
            self.assertNotIn("private value",json.dumps(report))

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


class TicketOriginalEvidenceContracts(unittest.TestCase):
    """Adversarial bookkeeping fixtures; these never qualify protocol execution."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="freightctl-ticket-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.prefix = "ticket-explicit-"
        self.steps, self.inventory = [], {}
        ident = "a1b2c3d4-1111-4111-8111-000000000001"
        created = {"id":ident,"path":"/recovered.csv","ftps_path":"/.freightctl/uploads/"+ident,"sftp_path":"/.freightctl/uploads/"+ident,
                   "expected_size":len(tickets.PAYLOAD),"expected_sha256":tickets.SHA256,"state":"open","committed_offset":0,"chunk_count":0}
        checkpoint = dict(created,committed_offset=65536,chunk_count=1)
        completed = dict(created,committed_offset=len(tickets.PAYLOAD),chunk_count=4,state="completed",file_id="synthetic-file",acceptance=tickets.ACCEPTANCE)
        receipt = {"upload":completed,"replayed":True,"acceptance":tickets.ACCEPTANCE,"file":{"id":"synthetic-file","sha256":tickets.SHA256,"size_bytes":len(tickets.PAYLOAD)}}
        held = {"file_id":"synthetic-file","policy_hash":"a"*64,"state":"held","binding":{"file":{"sha256":tickets.SHA256,"size_bytes":len(tickets.PAYLOAD)}}}
        checked = dict(held,state="passed",attempts=1,code="valid_csv",report_hash="b"*64)
        values = {"create":{"upload":created,"replayed":False},"create-replay":{"upload":created,"replayed":True},
                  "checkpoint":checkpoint,"after-restart":checkpoint,"completed":completed,"receipt-cli":receipt,
                  "policy-register":{"resource":{"definition_hash":"a"*64}},"held":{"check":held},"checked":{"check":checked},
                  "release":{"resource":{"file_id":"synthetic-file"},"replayed":False},"release-replay":{"resource":{"file_id":"synthetic-file"},"replayed":True},
                  "published-stat":{"file_id":"synthetic-file"},"published-list":{"entries":[{"file_id":"synthetic-file"}]},
                  "checkpoint-poll-00":checkpoint,"completed-poll-00":completed}
        names = list(tickets.COMMANDS)
        names.insert(names.index("checkpoint"),"checkpoint-poll-00")
        names.insert(names.index("completed"),"completed-poll-00")
        for name in names:
            code = -9 if name == "crash" else 1 if name in tickets.REFUSALS else 0
            out = str(tickets.HTTP[name]).encode() if name in tickets.HTTP else json.dumps(values.get(name,{})).encode()
            if name == "peer":
                messages = [{"state":s,"resumed":True} for s in tickets.STATES[:-1]] + [{"state":"passed","case_count":6,"all_data_resumed":True}]
                out = b"\n".join(json.dumps(m).encode() for m in messages)+b"\n"
            if name in tickets.REFUSALS:
                out = b""
            self.steps.append({"name":self.prefix+name,"exit_code":code})
            self.write_command(name,out,tickets.REFUSALS.get(name,b""))
        for name, value in (("checkpoint-api",checkpoint),("after-restart-api",checkpoint),("foreign-api",{"error":"not_found"}),("completed-api",completed),("receipt-api",receipt)):
            self.write_file(name+".body",json.dumps(value).encode())
        self.write_file("download",tickets.PAYLOAD)

    def write_file(self,name,data):
        path = self.directory/(self.prefix+name)
        path.write_bytes(data)
        self.inventory[path.name] = hashlib.sha256(data).hexdigest()

    def write_command(self,name,out,err=b""):
        step = next(s for s in self.steps if s["name"] == self.prefix+name)
        for ext,data in (("stdout",out),("stderr",err)):
            (self.directory/(self.prefix+name+"."+ext)).write_bytes(data)
            step[ext+"_sha256"] = hashlib.sha256(data).hexdigest()

    def check(self):
        return tickets.validate(self.directory,"explicit",self.steps,self.inventory)

    def test_complete_synthetic_record_proves_only_checker_contract(self):
        self.assertEqual(self.check()["cases"],6)

    def test_rehashed_wrong_retrieved_bytes_cannot_pass(self):
        self.write_file("download",b"wrong immutable bytes")
        with self.assertRaises(ValueError): self.check()

    def test_rehashed_foreign_error_cannot_pass(self):
        self.write_file("foreign-api.body",b'{"error":"database_unavailable"}')
        with self.assertRaises(ValueError): self.check()

    def test_rehashed_cross_surface_checkpoint_disagreement_cannot_pass(self):
        value=json.loads((self.directory/(self.prefix+"after-restart-api.body")).read_text())
        value["committed_offset"] += 97
        self.write_file("after-restart-api.body",json.dumps(value).encode())
        with self.assertRaises(ValueError): self.check()

    def test_rehashed_receipts_cannot_bind_another_file(self):
        value=json.loads((self.directory/(self.prefix+"receipt-cli.stdout")).read_text())
        value["file"]["id"]="another-file"
        self.write_command("receipt-cli",json.dumps(value).encode())
        self.write_file("receipt-api.body",json.dumps(value).encode())
        with self.assertRaises(ValueError): self.check()

    def test_rehashed_check_cannot_bind_another_policy_or_bytes(self):
        value=json.loads((self.directory/(self.prefix+"checked.stdout")).read_text())
        value["check"]["policy_hash"]="c"*64
        self.write_command("checked",json.dumps(value).encode())
        with self.assertRaises(ValueError): self.check()

    def test_missing_original_process_and_wire_phases_cannot_pass(self):
        self.steps=[s for s in self.steps if s["name"] != self.prefix+"restarted"]
        with self.assertRaises(ValueError): self.check()

    def test_late_crash_cannot_pass_as_checkpoint_recovery(self):
        crash=next(s for s in self.steps if s["name"] == self.prefix+"crash")
        self.steps.remove(crash);self.steps.append(crash)
        with self.assertRaises(ValueError): self.check()


if __name__ == "__main__":
    unittest.main(verbosity=2)
