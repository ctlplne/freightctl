#!/usr/bin/env python3
"""Lifecycle/permission stand-ins only; no source process, signal or socket."""
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import ftps_collection_source as source


class SourceLifecycleContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='freightctl-source-lifecycle-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.private = self.root/'.private'/('ftps-'+'a'*32)
        self.private.mkdir(parents=True, mode=0o700)
        self.private.parent.chmod(0o700)
        self.steps = []
        self.database = 'freightctl_ftps_'+'b'*32

    def test_non_github_refuses_before_files_or_process(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(source.subprocess, 'Popen') as start:
            with self.assertRaises(ValueError):
                source.Source(self.root, self.private, 'explicit', self.database, self.steps, lambda: None)
            start.assert_not_called()
        self.assertEqual(list(self.private.iterdir()), [])

    def exercise(self, mode='explicit', bad=False):
        config = self.private/('source-helper-'+mode)/'counter.json'
        value = {'schema_version': 1, 'kind': 'freightctl-ftps-source-witness-v1', 'mode': mode,
            'port': 49151, 'accepted_connections': 0, 'budget_exhausted': False, 'stopped': False}
        class Process:
            pid = 475123
            code = None
            def poll(self): return self.code
            def wait(self, timeout): return self.code
        child = Process()
        def start(argv, **options):
            self.assertEqual(argv, [str(self.private/'source-ftps'), str(config.parent/'config.json')])
            self.assertTrue(options['start_new_session'])
            self.assertEqual(options['env']['GOMEMLIMIT'], '192MiB')
            self.assertEqual(options['env']['GOMAXPROCS'], '1')
            self.assertNotIn('private-evidence-canary', str(argv))
            source.metadata.private_write(config, json.dumps(value).encode())
            if bad:
                value['accepted_connections'] = 1
                config.write_text(json.dumps(value))
            return child
        signals = []
        def stop(pid, sig):
            self.assertEqual(pid, child.pid)
            self.assertEqual(sig, signal.SIGTERM)
            signals.append((pid, sig))
            child.code = 0
            value['stopped'] = True
            config.write_text(json.dumps(value))
        previous = os.umask(0o022)
        try:
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_WORKSPACE': str(self.root)}), \
                    patch.object(source.metadata.platform, 'system', return_value='Linux'), \
                    patch.object(source.subprocess, 'Popen', side_effect=start), patch.object(source.os, 'killpg', side_effect=stop):
                fixture = source.Source(self.root, self.private, mode, self.database, self.steps, lambda: None)
                if bad:
                    with self.assertRaises(ValueError): fixture.start()
                else:
                    self.assertEqual(fixture.start()['accepted_connections'], 0)
                    self.assertFalse(fixture.snapshot()['stopped'])
                    self.assertTrue(fixture.stop()['stopped'])
                fixture.stop()
                self.assertEqual(len(signals), 1)
                for p in (fixture.config, fixture.out_path, fixture.err_path, config):
                    self.assertEqual(p.stat().st_mode & 0o777, 0o600)
                self.assertEqual(fixture.directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual(len(self.steps), 1)
                self.assertEqual(self.steps[0]['exit_code'], 0)
        finally:
            os.umask(previous)

    def test_both_modes_wait_on_counter_without_probe_and_stop_only_exact_child_once(self):
        for mode in ('explicit', 'implicit'):
            self.steps = []
            self.exercise(mode)

    def test_failed_readiness_closes_its_owned_source_and_preserves_original_files(self):
        self.exercise(bad=True)

    def test_counter_refuses_ambiguous_numbers_budgets_modes_and_lifecycle(self):
        path = self.private/'counter.json'
        base = {'schema_version': 1, 'kind': 'freightctl-ftps-source-witness-v1', 'mode': 'explicit',
            'port': 49151, 'accepted_connections': 0, 'budget_exhausted': False, 'stopped': False}
        for change in ({'schema_version': True}, {'accepted_connections': False}, {'port': 65536},
                {'accepted_connections': 17}, {'budget_exhausted': True}, {'stopped': True}, {'mode': 'implicit'}):
            path.write_text(json.dumps(dict(base, **change)))
            with self.assertRaises(ValueError): source.counter(path, 'explicit', False)

    def test_process_creation_failure_keeps_original_error_and_closes_private_outputs(self):
        first = RuntimeError('first-source-launch-failure')
        streams = []
        def fail(_argv, **options):
            streams.extend((options['stdout'], options['stderr']))
            raise first
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_WORKSPACE': str(self.root)}), \
                patch.object(source.metadata.platform, 'system', return_value='Linux'), \
                patch.object(source.subprocess, 'Popen', side_effect=fail), patch.object(source.os, 'killpg') as signals:
            fixture = source.Source(self.root, self.private, 'explicit', self.database, self.steps, lambda: None)
            with self.assertRaises(RuntimeError) as caught: fixture.start()
            self.assertIs(caught.exception, first)
            self.assertTrue(fixture.closed)
            self.assertTrue(all(stream.closed for stream in streams))
            fixture.stop()
            signals.assert_not_called()
            self.assertEqual(self.steps, [])

    def test_startup_failure_survives_a_second_cleanup_error_with_exact_child_evidence(self):
        first = RuntimeError('original-source-readiness-failure')
        class Process:
            pid = 475123
            code = None
            def poll(self): return self.code
            def wait(self, timeout): return self.code
        child = Process()
        def start(_argv, **_options):
            source.metadata.private_write(self.private/'source-helper-explicit/counter.json', b'{}')
            return child
        def stop(pid, sig):
            self.assertEqual((pid, sig), (child.pid, signal.SIGTERM))
            child.code = 1
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_WORKSPACE': str(self.root)}), \
                patch.object(source.metadata.platform, 'system', return_value='Linux'), \
                patch.object(source.subprocess, 'Popen', side_effect=start), \
                patch.object(source.os, 'killpg', side_effect=stop) as signals, \
                patch.object(source.Source, 'snapshot', side_effect=first):
            fixture = source.Source(self.root, self.private, 'explicit', self.database, self.steps, lambda: None)
            with self.assertRaises(RuntimeError) as caught: fixture.start()
            self.assertIs(caught.exception, first)
            self.assertTrue(fixture.cleanup_failed)
            self.assertTrue(fixture.closed)
            self.assertTrue(fixture.stdout.closed and fixture.stderr.closed)
            self.assertEqual(self.steps[0]['exit_code'], 1)
            signals.assert_called_once()


if __name__ == '__main__':
    unittest.main()
