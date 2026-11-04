#!/usr/bin/env python3
"""Bounded spy/refusal contracts; these do not qualify the product journey."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest

import ftps_dispatch_qualification as dispatch


class ContactContracts(unittest.TestCase):
    def rotation_fixture(self):
        directory = Path(self.temporary.name)
        ca = directory / "ca.pem"
        ca.write_bytes(b"synthetic metadata CA; no TLS claim")
        (directory / "rotated-ca.pem").write_bytes(ca.read_bytes())
        password = directory / "receiver-password"
        password.write_bytes(b"synthetic metadata credential; no authentication claim")
        (directory / "rotated-password").write_bytes(password.read_bytes())
        definition = {"directory": "/original-inbox", "ftps": {
            "destination": {"address": "127.0.0.1:49151", "server_name": "localhost", "mode": "explicit", "user": "original-contact-only",
                            "ca_reference": str(ca), "ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
                            "password_reference": str(password), "password_sha256": hashlib.sha256(password.read_bytes()).hexdigest()},
            "staging_directory": "/original-stage", "receiver_contract": {"schema_version": 1, "document_sha256": "d" * 64,
            "staging_visibility": "receiver-private", "rename": "may-replace", "duplicates": "receiver-deduplicates-delivery-id", "receipt": "exact-readback"}}}
        address = "127.0.0.1:49152"
        (directory / "rotation-address.json").write_text(json.dumps(address))
        (directory / "rotation-receiver.json").write_text(json.dumps({"schema_version": 1, "kind": dispatch.SPY_KIND,
            "accepted_connections": 0, "stopped": True, "budget_exhausted": False}))
        original = {"id": "connection", "definition_hash": "a" * 64}
        values = {"connection-register": {"resource": original}, "connection-version": {"resource": {"definition_hash": "b" * 64}}}
        for version, (field, value) in enumerate(dispatch.connection_rotation_requests(directory, definition, address).items(), 3):
            label = "connection-rotate-" + field
            expected = dispatch.expected_connection_rotation(original, value, version)
            values[label] = {"resource": expected, "replayed": False}
            values[label + "-replay"] = {"resource": copy.deepcopy(expected), "replayed": True}
            values[label + "-status"] = copy.deepcopy(expected)
        return directory, definition, values

    def test_each_rotation_changes_one_original_field_without_rebinding_or_contact(self):
        directory, definition, values = self.rotation_fixture()
        before = copy.deepcopy(definition)
        cases = dispatch.connection_rotation_requests(directory, definition, "127.0.0.1:49152")
        self.assertEqual(tuple(cases), dispatch.ROTATION_FIELDS)
        def leaves(value, prefix=()):
            return {path: item for key, item in value.items() for path, item in
                    (leaves(item, prefix + (key,)).items() if type(item) is dict else [(prefix + (key,), item)])}
        for field, value in cases.items():
            original_leaves, changed_leaves = leaves(definition), leaves(value)
            self.assertEqual(set(original_leaves), set(changed_leaves))
            self.assertEqual(sum(original_leaves[k] != v for k, v in changed_leaves.items()), 1, field)
        self.assertEqual(definition, before)
        dispatch.validate_connection_rotations(directory, values.__getitem__, definition)
        for address in ("192.0.2.1:443", "127.0.0.1:49151", "127.0.0.1:0", "127.0.0.1:65536", "localhost:49152"):
            with self.assertRaises(ValueError):
                dispatch.connection_rotation_requests(directory, definition, address)

    def test_rotation_reporter_rejects_wrong_hash_version_replay_or_private_reference(self):
        directory, definition, values = self.rotation_fixture()
        dispatch.validate_connection_rotations(directory, values.__getitem__, definition)
        for change in (
            lambda v: v["connection-rotate-mode"]["resource"].update(definition_hash="f" * 64),
            lambda v: v["connection-rotate-ca-proof-status"].update(version=1),
            lambda v: v["connection-rotate-address-replay"].update(replayed=False),
            lambda v: v["connection-rotate-password-proof"]["resource"]["ftps"].update(password_sha256=definition["ftps"]["destination"]["password_sha256"]),
            lambda v: v["connection-rotate-password-reference-status"]["ftps"].update(password_reference=definition["ftps"]["destination"]["password_reference"]),
            lambda v: v.pop("connection-rotate-final-directory-status"),
        ):
            altered = copy.deepcopy(values)
            change(altered)
            with self.assertRaises((ValueError, KeyError)):
                dispatch.validate_connection_rotations(directory, altered.__getitem__, definition)

    def test_rotation_requires_both_protected_aliases_and_a_stopped_zero_contact_spy(self):
        directory, definition, values = self.rotation_fixture()
        original = (directory / "rotated-password").read_bytes()
        (directory / "rotated-password").write_bytes(b"different")
        with self.assertRaises(ValueError):
            dispatch.validate_connection_rotations(directory, values.__getitem__, definition)
        (directory / "rotated-password").write_bytes(original)
        counter = json.loads((directory / "rotation-receiver.json").read_bytes())
        for change in ({"stopped": False}, {"accepted_connections": 1}, {"budget_exhausted": True}):
            (directory / "rotation-receiver.json").write_text(json.dumps(dict(counter, **change)))
            with self.assertRaises(ValueError):
                dispatch.validate_connection_rotations(directory, values.__getitem__, definition)

    def test_workflow_namespace_keeps_exact_refusals_and_private_errors_out_of_diagnostics(self):
        for mode in ("explicit","implicit"):
            for suffix,expected in dispatch.WORKFLOW_REFUSALS.items():
                label="cli-"+mode+"-workflow-dispatch-"+suffix
                dispatch.verify_outcome(label,1,expected)
                with self.assertRaises(ValueError): dispatch.verify_outcome(label,1,b"private unrelated error\n")
                with self.assertRaises(ValueError): dispatch.verify_outcome(label,0,expected)
        self.assertEqual(dispatch.safe_failure(ValueError("private credential or path")),"dispatch-evidence")
        self.assertEqual(dispatch.safe_failure(ValueError("dispatch workflow intent binding differs")),"workflow-binding")

    def test_workflow_metadata_cannot_substitute_protocol_version_or_execution_binding(self):
        c={"id":"connection","version":1,"revision":1,"state":"active","protocol":"ftps","definition_hash":"a"*64,"ftps":{"mode":"explicit"}}
        step={"id":"send","kind":"ftps.deliver","connection":{"id":"connection","version":1,"hash":"a"*64},"filename":"approved.bin"}
        definition={"schema_version":1,"name":"Synthetic evidence only","steps":[step]}
        draft={"id":"workflow","version":1,"revision":1,"state":"draft","definition_hash":"b"*64,"definition":definition}
        approved=dict(draft,revision=2,state="approved")
        source={"id":"file"}
        run={"id":"run","file_id":"file","workflow_id":"workflow","workflow_version":1,"workflow_hash":"b"*64,"source":source}
        binding={"workflow_id":"workflow","workflow_version":1,"workflow_hash":"b"*64,"run_id":"run","step_id":"send","connection_id":"connection","connection_version":1,"connection_hash":"a"*64}
        delivery={"id":"delivery","file_id":"file","definition":{"workflow_binding":binding,"source":source}}
        values={"connection-register":{"resource":c,"replayed":False},"connection-register-replay":{"resource":c,"replayed":True},"connection-status":c,
                "workflow-draft":{"resource":draft},"workflow-approve":{"resource":approved},
                "workflow-validate":{"definition":definition,"definition_hash":"b"*64,"source":source,"external_contact":False,"approval_required":True,"effects":[{"protocol":"ftps","ftps":c["ftps"]}]},
                "workflow-run":{"resource":run},"workflow-run-status":{"run":run,"steps":[{"delivery_id":"delivery"}]},
                "connection-version":{"resource":dict(c,version=2,definition_hash="c"*64)},"connection-revoke":{"resource":dict(c,revision=2,state="revoked")}}
        dispatch.validate_workflow_outputs(values.__getitem__,delivery,"explicit")
        for change in (lambda v:v["workflow-run-status"]["steps"][0].update(delivery_id="other"),
                       lambda v:v["connection-status"].update(protocol="sftp"),
                       lambda v:v["workflow-validate"].update(external_contact=True),
                       lambda v:v["connection-version"]["resource"].update(version=1),
                       lambda v:v["workflow-run"]["resource"].update(id="other")):
            altered=copy.deepcopy(values);change(altered)
            with self.assertRaises(ValueError):dispatch.validate_workflow_outputs(altered.__getitem__,delivery,"explicit")

    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory(prefix="freightctl-contact-contract-", dir="/private/tmp" if Path("/private/tmp").is_dir() else None)
        self.path = Path(self.temporary.name) / "receiver.json"

    def tearDown(self):
        self.temporary.cleanup()
        os.umask(self.previous_umask)

    def test_actual_zero_contact_spy_stops_and_keeps_protected_atomic_record(self):
        spy = dispatch.ContactSpy(self.path)
        try:
            dispatch.check_counter(json.loads(self.path.read_bytes()), False)
            self.assertEqual(self.path.stat().st_mode & 0o077, 0)
        finally:
            spy.stop()
        dispatch.check_counter(json.loads(self.path.read_bytes()), True)
        self.assertFalse(spy.thread.is_alive())
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_actual_pending_connection_cannot_escape_stop_drain(self):
        spy = dispatch.ContactSpy(self.path)
        try:
            with socket.create_connection(("127.0.0.1", spy.port), timeout=1):
                pass
        finally:
            spy.stop()
        counter = json.loads(self.path.read_bytes())
        self.assertEqual(counter["accepted_connections"], 1)
        self.assertTrue(counter["stopped"])
        with self.assertRaises(ValueError):
            dispatch.check_counter(counter, True)

    def test_actual_contact_budget_closes_listener_after_sixteen_accepts(self):
        spy = dispatch.ContactSpy(self.path)
        try:
            for _ in range(16):
                with socket.create_connection(("127.0.0.1", spy.port), timeout=1) as connection:
                    # The spy closes each contact immediately; it never speaks TLS.
                    connection.settimeout(1)
                    self.assertEqual(connection.recv(1), b"")
        finally:
            spy.stop()
        counter = json.loads(self.path.read_bytes())
        self.assertEqual(counter["accepted_connections"], 16)
        self.assertTrue(counter["budget_exhausted"])
        self.assertTrue(counter["stopped"])
        with self.assertRaises(ValueError):
            dispatch.check_counter(counter, True)

    def test_counter_cannot_hide_contact_unknown_format_exhaustion_or_live_thread(self):
        counter = {"schema_version": 1, "kind": dispatch.SPY_KIND, "accepted_connections": 0,
                   "stopped": True, "budget_exhausted": False}
        dispatch.check_counter(counter, True)
        for field, value in (("schema_version", True), ("kind", "private diagnostic"),
                             ("accepted_connections", True), ("accepted_connections", 0.0),
                             ("accepted_connections", 1), ("stopped", False), ("budget_exhausted", True)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                dispatch.check_counter(dict(counter, **{field: value}), True)
        for field in counter:
            missing = copy.deepcopy(counter)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                dispatch.check_counter(missing, True)
        with self.assertRaises(ValueError):
            dispatch.check_counter(dict(counter, raw_secret="must not be accepted"), True)

    def test_cli_refusals_require_original_fixed_category_and_empty_result(self):
        for mode in ("explicit", "implicit"):
            for suffix, expected in dispatch.REFUSALS.items():
                label = "cli-" + mode + "-dispatch-" + suffix
                dispatch.verify_outcome(label, 1, expected)
                for code, stderr, stdout in ((0, expected, b""), (1, b"unrelated error\n", b""),
                                             (1, expected, b"success"), (True, expected, b"")):
                    with self.subTest(label=label), self.assertRaises(ValueError):
                        dispatch.verify_outcome(label, code, stderr, stdout)
            with self.assertRaises(ValueError):
                dispatch.verify_outcome("cli-" + mode + "-dispatch-unknown", 1, b"error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
