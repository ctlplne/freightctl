#!/usr/bin/env python3
"""Run orchestration against a Docker-command stand-in; no daemon or scan."""
import contextlib
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


runner = module('peer_scan_runner', 'scan-peer-image.py')
contracts = module('peer_scan_contracts', 'test-ci-peer-image-summary.py')
REAL_RUN = subprocess.run


class ScanOrchestration(unittest.TestCase):
    def exercise(self, mode='clean', arch='amd64'):
        with tempfile.TemporaryDirectory(prefix='freightctl-peer-scan-contract-') as directory:
            root = Path(directory)
            (root/'.private').mkdir(mode=0o700)
            (root/'scripts').mkdir()
            shutil.copyfile(HERE/'ci-peer-image-summary.py', root/'scripts/ci-peer-image-summary.py')
            report, version, image = contracts.inputs(datetime.now(timezone.utc), arch)
            created, removed, invocations = {}, [], []
            original_cwd = Path.cwd()
            def docker(arguments, *, stdout, stderr, timeout):
                invocations.append(arguments)
                if arguments[0] != 'docker':
                    if arguments[:2] == ['git', 'rev-parse']:
                        stdout.write((contracts.COMMIT+'\n').encode())
                        return subprocess.CompletedProcess(arguments, 0)
                    return REAL_RUN(arguments, stdout=stdout, stderr=stderr, timeout=timeout)
                action = arguments[1:3]
                if action == ['image', 'inspect']:
                    value = image if arguments[-1] != runner.gate.SCANNER_IMAGE else [dict(Architecture=arch, Os='linux')]
                    stdout.write(json.dumps(value).encode())
                elif action == ['image', 'save']:
                    self.assertEqual(arguments[-1], contracts.IMAGE)
                    Path(arguments[arguments.index('--output')+1]).write_bytes(b'synthetic image archive')
                elif arguments[1] == 'pull':
                    self.assertEqual(arguments[-1], runner.gate.SCANNER_IMAGE)
                elif arguments[1] == 'create':
                    ident = f'{len(created)+1:064x}'
                    created[ident] = arguments
                    stdout.write((ident+'\n').encode())
                elif arguments[1] == 'start':
                    create = created[arguments[-1]]
                    options = create[create.index(runner.gate.SCANNER_IMAGE)+1:]
                    mounts = [create[n+1] for n, arg in enumerate(create) if arg == '--mount']
                    source = lambda destination: Path(next(m.split(',src=', 1)[1].split(',dst=', 1)[0]
                        for m in mounts if ',dst='+destination in m))
                    cache = source('/cache')
                    if '--download-db-only' in options:
                        if mode == 'timeout':
                            raise subprocess.TimeoutExpired(contracts.PRIVATE, timeout)
                        (cache/'db').mkdir()
                        (cache/'db/trivy.db').write_bytes(b'synthetic feed database')
                        (cache/'db/metadata.json').write_text(json.dumps(version['VulnerabilityDB']))
                    elif 'version' in options:
                        stdout.write(json.dumps(version).encode())
                    else:
                        self.assertIn('--ignore-unfixed=false', options)
                        self.assertIn('--show-suppressed', options)
                        self.assertIn('--list-all-pkgs', options)
                        self.assertEqual(options[options.index('--input')+1], '/input/peer.tar')
                        self.assertIn('--skip-db-update', options)
                        if mode == 'high':
                            report['Results'][0]['Vulnerabilities'] = [{'Severity': 'HIGH', 'VulnerabilityID': 'CVE-2026-12345'}]
                        if mode == 'foreign':
                            report['Metadata']['ImageID'] = 'sha256:'+'c'*64
                        if mode == 'input-change':
                            # Simulate unexpected mutation outside the read-only mount.
                            (cache/'db/trivy.db').write_bytes(b'changed feed database')
                        (source('/output')/'report.json').write_text(json.dumps(report))
                elif arguments[1:3] == ['rm', '--force']:
                    self.assertIn(arguments[-1], created)
                    removed.append(arguments[-1])
                else:
                    self.fail('unexpected stand-in command')
                stderr.write(contracts.PRIVATE.encode())
                return subprocess.CompletedProcess(arguments, 0)
            try:
                stream = io.StringIO()
                with patch.object(runner, 'ROOT', root), patch.object(sys, 'argv', ['scan-peer-image.py', '--architecture', arch]), \
                     patch.dict('os.environ', {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': contracts.COMMIT}), \
                     patch.object(runner.platform, 'system', return_value='Linux'), \
                     patch.object(runner.platform, 'machine', return_value='x86_64' if arch == 'amd64' else 'aarch64'), \
                     patch.object(runner.subprocess, 'run', side_effect=docker), contextlib.redirect_stdout(stream):
                    code = runner.main()
                output = stream.getvalue()
                self.assertNotIn(contracts.PRIVATE, output)
                self.assertEqual(set(created), set(removed))
                if mode == 'timeout':
                    failure = json.loads(next((root/'.private').glob('*/failure.json')).read_text())
                    interrupted = [s for s in failure['steps'] if s.get('incomplete')]
                    self.assertEqual(len(interrupted), 1)
                    self.assertEqual(interrupted[0]['phase'], 'feed-download')
                    self.assertRegex(interrupted[0]['stdout_sha256'], '^[0-9a-f]{64}$')
                    self.assertRegex(interrupted[0]['stderr_sha256'], '^[0-9a-f]{64}$')
                for create in created.values():
                    for fixed in ('--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                                  '--memory=1g', '--memory-swap=1g', '--cpus=1', '--pids-limit=128'):
                        self.assertIn(fixed, create)
                    self.assertNotIn('/var/run/docker.sock', str(create))
                    options = create[create.index(runner.gate.SCANNER_IMAGE)+1:]
                    self.assertEqual(create[create.index('--network')+1], 'bridge' if '--download-db-only' in options else 'none')
                    cache_mount = next(create[n+1] for n, arg in enumerate(create)
                                       if arg == '--mount' and ',dst=/cache' in create[n+1])
                    self.assertEqual(cache_mount.endswith(',readonly'), '--download-db-only' not in options)
                return code, json.loads(output), created
            finally:
                runner.os.chdir(original_cwd)

    def test_exact_image_both_native_contracts_and_bounded_offline_commands(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                code, output, created = self.exercise(arch=arch)
                self.assertEqual(code, 0)
                self.assertEqual(output['state'], 'passed')
                self.assertEqual(output['image_id'], contracts.IMAGE)
                self.assertEqual(len(created), 3)
                self.assertRegex(output['manifest_sha256'], '^[0-9a-f]{64}$')

    def test_actual_python_converter_nonzero_blocks_an_exit_zero_scanner(self):
        code, output, _ = self.exercise(mode='high')
        self.assertEqual(code, 1)
        self.assertEqual(output['severities']['HIGH'], 1)
        self.assertEqual(output['state'], 'failed')

    def test_foreign_image_report_refused_without_exposing_private_diagnostics(self):
        code, output, _ = self.exercise(mode='foreign')
        self.assertEqual(code, 2)
        self.assertEqual(output['phase'], 'enforcing-summary')

    def test_archive_or_feed_change_refuses_completion(self):
        code, output, _ = self.exercise(mode='input-change')
        self.assertEqual(code, 2)
        self.assertEqual(output['phase'], 'input-closure')

    def test_command_timeout_removes_only_the_exact_owned_container(self):
        code, output, created = self.exercise(mode='timeout')
        self.assertEqual(code, 2)
        self.assertEqual(output['phase'], 'feed-download')
        self.assertEqual(len(created), 1)

    def test_non_github_invocation_refuses_before_any_subprocess(self):
        with patch.object(sys, 'argv', ['scan-peer-image.py', '--architecture', 'amd64']), \
             patch.dict('os.environ', {'GITHUB_ACTIONS': 'false'}), \
             patch.object(runner.subprocess, 'run') as invoked, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
            invoked.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['reason'], 'native-github-peer-scan-required')


if __name__ == '__main__':
    unittest.main()
