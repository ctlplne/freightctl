#!/usr/bin/env python3
"""Real temporary-output refusal tests; no service, model or scanner startup."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from native_evidence import NativeEvidence


class NativeOutputContracts(unittest.TestCase):
    def fixture(self):
        tmp = tempfile.TemporaryDirectory(prefix='freightctl-native-evidence-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        steps = []
        proof = NativeEvidence(root, steps)
        counter = root / 'actual-command-effects'

        def command(name):
            proof.reserve(name)
            with (root / (name + '.stdout')).open('wb') as out, (root / (name + '.stderr')).open('wb') as err:
                subprocess.run([sys.executable, '-c', 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text()+"effect\\n" if p.exists() else "effect\\n"); print("native output")', str(counter)], check=True, stdout=out, stderr=err)
            body = root / (name + '.json')
            body.write_text('{"receipt":"first committed response"}\n')
            steps.append({'name':name, 'stdout_sha256':hashlib.sha256((root/(name+'.stdout')).read_bytes()).hexdigest(), 'stderr_sha256':hashlib.sha256((root/(name+'.stderr')).read_bytes()).hexdigest(), 'response_sha256':hashlib.sha256(body.read_bytes()).hexdigest()})
        return root, steps, proof, counter, command

    def test_retry_label_is_refused_before_second_command_or_overwrite(self):
        root, steps, proof, counter, command = self.fixture()
        command('original-operation')
        original = (root/'original-operation.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'already reserved'):
            command('original-operation')
        self.assertEqual(counter.read_text(), 'effect\n')
        self.assertEqual((root/'original-operation.json').read_bytes(), original)
        self.assertEqual(proof.verify(), 3)

    def test_changed_response_cannot_reuse_the_original_hash(self):
        root, steps, proof, counter, command = self.fixture()
        command('original-operation')
        (root/'original-operation.json').write_text('{"receipt":"different replay response"}\n')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            proof.verify()

    def test_missing_output_cannot_report_a_complete_run(self):
        root, steps, proof, counter, command = self.fixture()
        command('original-operation')
        (root/'original-operation.stderr').unlink()
        with self.assertRaisesRegex(ValueError, 'missing or unsafe'):
            proof.verify()

    def test_unregistered_or_duplicate_steps_are_refused(self):
        root, steps, proof, counter, command = self.fixture()
        command('original-operation')
        steps.append(dict(steps[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate, unregistered or incomplete'):
            proof.verify()

    def test_distinct_retry_outputs_preserve_both_actual_responses(self):
        root, steps, proof, counter, command = self.fixture()
        command('original-operation')
        command('original-operation-replay')
        self.assertEqual(counter.read_text(), 'effect\neffect\n')
        self.assertEqual(proof.verify(), 6)

    def test_existing_or_escaping_output_refuses_before_execution(self):
        root, steps, proof, counter, command = self.fixture()
        (root/'existing.json').write_text('keep')
        for name in ('existing', '../escape'):
            with self.assertRaises(ValueError):
                command(name)
        self.assertFalse(counter.exists())
        self.assertEqual((root/'existing.json').read_text(), 'keep')

    def test_browser_invocations_survive_common_summary_overwrite(self):
        root, steps, proof, counter, command = self.fixture()
        report = root/'common-browser-report.json'
        for name in ('first-browser', 'second-browser'):
            command(name)
            subprocess.run([sys.executable, '-c', 'import json,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(json.dumps({"state":"passed","runtime_errors":[],"external_egress":[],"invocation":sys.argv[2]}))', str(report), name], check=True)
            proof.capture_browser(name, report)
        self.assertEqual(json.loads((root/'first-browser.browser.json').read_text())['invocation'], 'first-browser')
        self.assertEqual(json.loads((root/'second-browser.browser.json').read_text())['invocation'], 'second-browser')
        self.assertEqual(json.loads(report.read_text())['invocation'], 'second-browser')
        self.assertEqual(proof.verify(), 8)

    def test_browser_page_errors_or_egress_refuse_a_reported_pass(self):
        for errors, egress in [(['actual page exception'], []), ([], ['https://untrusted.invalid'])]:
            root, steps, proof, counter, command = self.fixture()
            command('browser-errors')
            report = root/'common-browser-report.json'
            report.write_text(json.dumps({'state':'passed', 'runtime_errors':errors, 'external_egress':egress}))
            with self.assertRaisesRegex(ValueError, 'page errors/external egress'):
                proof.capture_browser('browser-errors', report)
            self.assertEqual((root/'browser-errors.browser.json').read_bytes(), report.read_bytes())
            self.assertEqual(proof.verify(), 4)

    def test_existing_browser_capture_refuses_before_command_effects(self):
        root, steps, proof, counter, command = self.fixture()
        (root/'existing.browser.json').write_text('retain first invocation')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            command('existing')
        self.assertFalse(counter.exists())
        self.assertEqual((root/'existing.browser.json').read_text(), 'retain first invocation')


if __name__ == '__main__':
    unittest.main(verbosity=2)
