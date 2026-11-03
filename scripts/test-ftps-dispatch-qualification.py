#!/usr/bin/env python3
"""Bounded spy/refusal contracts; these do not qualify the product journey."""
import copy
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest

import ftps_dispatch_qualification as dispatch


class ContactContracts(unittest.TestCase):
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
