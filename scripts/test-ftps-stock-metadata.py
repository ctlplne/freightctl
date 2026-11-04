#!/usr/bin/env python3
"""Pure evidence and task-owned file fixtures; no stock server or sockets."""
from contextlib import redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest.mock import patch

import ftps_stock_metadata as metadata

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stock_receiver_fixture', ROOT/'scripts/test-ftps-client-summary.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def witness(mode):
    ready = metadata.files(mode)[mode+'-ready.json']
    return {'kind': 'freightctl-stock-ftps-metadata-v1', 'mode': mode,
        'ready_size': len(ready), 'ready_sha256': hashlib.sha256(ready).hexdigest(),
        'maximum_size': metadata.LIMIT, 'maximum_sha256': hashlib.sha256(b'M'*metadata.LIMIT).hexdigest(),
        'empty_size': 0, 'empty_sha256': hashlib.sha256(b'').hexdigest(),
        'oversize_refused': True, 'session_usable_after_refusal': True}


class StockMetadataContracts(unittest.TestCase):
    def setUp(self):
        self.case = fixture.ReceiverEvidence('runTest')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.directory = self.case.directory
        self.records = [witness(mode) for mode in ('explicit', 'implicit')]
        self.native = (self.directory/'native-stock-receiver.stdout').read_bytes()
        self.case.m['collection_metadata_requested'] = True
        self.inventory = metadata.inventory()
        self.persist()
        self.case.m['collection_metadata'] = metadata.validate(self.directory, metadata.read_original)

    def persist(self):
        for name in ('seed-source-metadata', 'independent-source-metadata'):
            self.case.output(name, json.dumps(self.inventory).encode())
        self.case.output('native-stock-receiver', self.native+b''.join(json.dumps(r).encode()+b'\n' for r in self.records))

    def check(self):
        self.case.write()
        return fixture.summary.summarize(self.case.root, self.case.result, 'b'*40, require_collection_metadata=True)

    def test_profile_reopens_both_native_modes_and_original_independent_source_inventories(self):
        result = self.check()['stock_collection_metadata']
        self.assertEqual(result['modes'], 2)
        self.assertEqual(result['cases_per_mode'], 4)
        self.assertEqual(result['maximum_bytes'], 32768)
        self.assertEqual(result['source_files_unchanged'], 6)
        self.assertFalse(result['full_collection_qualified'])
        self.assertNotIn('password', json.dumps(result))

    def test_legacy_profile_or_boolean_aliases_cannot_satisfy_required_metadata(self):
        for value in (False, 1, 'true'):
            self.case.m['collection_metadata_requested'] = value
            with self.assertRaises(ValueError):
                self.check()

    def test_rehashed_missing_mode_changed_digest_and_unperformed_boundary_are_refused(self):
        original = copy.deepcopy(self.records)
        changes = (lambda r: r.pop(), lambda r: r[0].update(ready_sha256='a'*64),
            lambda r: r[1].update(oversize_refused=False), lambda r: r[0].update(empty_size=False),
            lambda r: r[0].update(maximum_size=32769), lambda r: r[1].update(session_usable_after_refusal=False))
        for change in changes:
            self.records = copy.deepcopy(original)
            change(self.records)
            self.persist()
            with self.assertRaises(ValueError):
                self.check()

    def test_rehashed_before_after_source_changes_or_claim_only_result_are_refused(self):
        original = copy.deepcopy(self.inventory)
        for change in (lambda v: v.pop('explicit-ready.json'),
                lambda v: v['implicit-max.metadata'].update(mode=0o600),
                lambda v: v['explicit-oversize.metadata'].update(size=32768)):
            self.inventory = copy.deepcopy(original)
            change(self.inventory)
            self.persist()
            with self.assertRaises(ValueError):
                self.check()
        self.inventory = original
        self.persist()
        self.case.m['collection_metadata']['full_collection_qualified'] = True
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_or_noninteger_json_fields_are_not_original_proof(self):
        for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.0}'):
            with self.assertRaises(ValueError):
                metadata.load(body)
        self.case.output('seed-source-metadata', b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            self.check()

    def test_real_seed_and_observer_use_only_exclusive_task_files_and_preserve_private_modes(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-stock-metadata-files-') as temporary:
            directory = Path(temporary).resolve()
            args = ['stock-source-seed', str(directory), pwd.getpwuid(os.getuid()).pw_name]
            previous = os.umask(0o077)
            try:
                with patch.object(sys, 'argv', args), patch.object(sys, 'path', [str(ROOT), *sys.path]), redirect_stdout(io.StringIO()) as out:
                    exec(metadata.SEED, {})
                self.assertEqual(json.loads(out.getvalue()), metadata.inventory())
                self.assertEqual(set(p.name for p in directory.iterdir()), set(metadata.inventory()))
                with patch.object(sys, 'argv', args), patch.object(sys, 'path', [str(ROOT), *sys.path]), redirect_stdout(io.StringIO()) as observed:
                    exec(metadata.OBSERVE, {})
                self.assertEqual(json.loads(observed.getvalue()), metadata.inventory())
                before = {p.name: p.read_bytes() for p in directory.iterdir()}
                with patch.object(sys, 'argv', args), patch.object(sys, 'path', [str(ROOT), *sys.path]), self.assertRaises(RuntimeError):
                    exec(metadata.SEED, {})
                self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})
            finally:
                os.umask(previous)


if __name__ == '__main__':
    unittest.main()
