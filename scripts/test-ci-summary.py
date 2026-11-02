#!/usr/bin/env python3
"""Refuse success without evidence and prevent protected manifest disclosure."""
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('ci_summary', Path(__file__).with_name('ci-qualification-summary.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SummaryBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='freightctl-ci-summary-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'manifest.json'
        self.commit = 'a' * 40
        self.manifest = {'schema_version': 1, 'state': 'passed', 'starting_commit': self.commit,
                         'sources_unchanged_during_run': True, 'isolated_database_removed': True,
                         'inference_performed': False, 'scanner_engine_started': False,
                         'source_sha256': {'protected-filename': 'b' * 64},
                         'steps': [{'exit_code': 0, 'expected_exit_code': 0, 'command': ['secret-token']}],
                         'cleanup_failures': [], 'output_closure_failure': None,
                         'output_artifacts_verified': 2, 'duration_seconds': 1.5,
                         'failure': None, 'private_reference': 'private-path', 'untrusted_content': 'private-content'}

    def summary(self):
        self.path.write_text(json.dumps(self.manifest))
        return module.summarize(self.path, self.commit)

    def test_protected_fields_never_reach_public_summary(self):
        report = self.summary()
        self.assertEqual(report['state'], 'passed')
        rendered = json.dumps(report)
        for private in ('protected-filename', 'secret-token', 'private-content', 'private-path'):
            self.assertNotIn(private, rendered)

    def test_incomplete_output_cleanup_and_unexpected_effects_stay_red(self):
        for field, value in (('output_closure_failure', 'protected detail'), ('cleanup_failures', ['private resource']),
                             ('sources_unchanged_during_run', False), ('inference_performed', True),
                             ('scanner_engine_started', True), ('isolated_database_removed', False)):
            original = self.manifest[field]
            self.manifest[field] = value
            self.assertEqual(self.summary()['state'], 'failed')
            self.manifest[field] = original
        self.manifest['steps'][0]['exit_code'] = 1
        self.assertEqual(self.summary()['state'], 'failed')
        self.manifest['steps'][0]['exit_code'] = 0
        self.manifest['output_artifacts_verified'] = 1
        self.assertEqual(self.summary()['state'], 'failed')

    def test_missing_closure_cannot_report_success(self):
        del self.manifest['output_closure_failure']
        with self.assertRaises(ValueError):
            self.summary()

    def test_successful_transport_cannot_hide_rejected_http_command(self):
        self.manifest['steps'][0].update(http_status=400, expected_status=200)
        report = self.summary()
        self.assertEqual(report['state'], 'failed')
        self.assertEqual(report['unexpected_command_exits'], 0)
        self.assertEqual(report['unexpected_http_statuses'], 1)
        self.manifest['steps'][0]['http_status'] = 'private-response'
        with self.assertRaises(ValueError):
            self.summary()

    def test_wrong_commit_and_untrusted_outcome_text_are_refused(self):
        for field, value in (('starting_commit', 'c' * 40), ('state', 'secret-state'),
                             ('duration_seconds', float('nan')), ('output_artifacts_verified', True)):
            original = self.manifest[field]
            self.manifest[field] = value
            with self.assertRaises(ValueError):
                self.summary()
            self.manifest[field] = original

    def test_missing_and_symlinked_manifest_are_refused(self):
        with self.assertRaises(ValueError):
            module.summarize(self.path, self.commit)
        target = self.path.with_name('protected.json')
        target.write_text(json.dumps(self.manifest))
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            module.summarize(self.path, self.commit)

    def test_browser_diagnostic_exposes_only_pinned_source_location_and_counts(self):
        report = {'state': 'failed', 'runtime_errors': ['secret-page-error'],
                  'external_egress': ['https://private.invalid'],
                  'failure': 'private-content at /private-path/scripts/routing-browser.mjs:77:3'}
        data = json.dumps(report).encode()
        report_path = self.path.with_name('native-browser-route.browser.json')
        report_path.write_bytes(data)
        self.manifest['steps'][0].update(name='native-browser-route', browser_report_sha256=hashlib.sha256(data).hexdigest())
        result = self.summary()
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['browser_failure_locations'], ['routing-browser.mjs:77:3'])
        self.assertEqual(result['browser_runtime_errors'], 1)
        for private in ('secret-page-error', 'private.invalid', 'private-content', 'private-path'):
            self.assertNotIn(private, json.dumps(result))
        report_path.write_bytes(b'{}')
        with self.assertRaises(ValueError):
            self.summary()


if __name__ == '__main__':
    unittest.main()
