#!/usr/bin/env python3
"""Run orchestration against a Docker-command stand-in; no daemon or scan."""
import contextlib
from datetime import datetime, timezone
import hashlib
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
            volume = {'mounted': False, 'unmounted': False}
            original_cwd = Path.cwd()
            def docker(arguments, *, stdout, stderr, timeout):
                invocations.append(arguments)
                if arguments[0] == 'mkfs.ext4':
                    volume['backing'] = arguments[-1]
                    self.assertEqual(Path(arguments[-1]).stat().st_size, 2 << 30)
                    return subprocess.CompletedProcess(arguments, 0)
                if arguments[:3] == ['sudo', '-n', 'mount']:
                    volume['root'] = arguments[-1]
                    self.assertEqual(arguments[arguments.index('--source')+1], volume['backing'])
                    self.assertIn('loop,nodev,nosuid,noexec', arguments)
                    volume['mounted'] = True
                    if mode == 'mount-timeout':
                        raise subprocess.TimeoutExpired(contracts.PRIVATE, timeout)
                    return subprocess.CompletedProcess(arguments, 0)
                if arguments[0] == 'findmnt':
                    self.assertEqual(arguments[arguments.index('--mountpoint')+1], volume['root'])
                    stdout.write(json.dumps({'filesystems': [{'source': '/dev/loop123', 'fstype': 'ext4',
                        'target': volume['root'], 'options': 'rw,nodev,nosuid,noexec,relatime'}]}).encode())
                    return subprocess.CompletedProcess(arguments, 0)
                if arguments[0] == 'losetup':
                    self.assertEqual(arguments[arguments.index('--associated')+1], volume['backing'])
                    stdout.write(json.dumps({'loopdevices': [{'name': '/dev/loop123',
                        'back-file': volume['backing'] if mode != 'foreign-volume' else contracts.PRIVATE}]}).encode())
                    return subprocess.CompletedProcess(arguments, 0)
                if arguments[:3] == ['sudo', '-n', 'umount']:
                    self.assertNotEqual(mode, 'foreign-volume')
                    self.assertEqual(arguments[3:], ['--', volume['root']])
                    if mode == 'changed-state':
                        (Path(volume['root']).parent/'feed-download-state.stdout').write_text(
                            json.dumps({'OOMKilled': True, 'Running': False, 'ExitCode': 137}))
                    volume['mounted'], volume['unmounted'] = False, True
                    return subprocess.CompletedProcess(arguments, 0)
                if arguments[0] != 'docker':
                    if arguments[:2] == ['git', 'rev-parse']:
                        stdout.write((contracts.COMMIT+'\n').encode())
                        return subprocess.CompletedProcess(arguments, 0)
                    self.assertEqual(arguments[:2], [sys.executable, str(root/'scripts/ci-peer-image-summary.py')])
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
                        if mode in ('oom', 'killed', 'foreign-state', 'bad-state', 'state-failed', 'changed-state'):
                            stderr.write(contracts.PRIVATE.encode())
                            return subprocess.CompletedProcess(arguments, 137)
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
                elif arguments[1] == 'inspect':
                    self.assertEqual(arguments[2:4], ['--format', '{{json .State}}'])
                    self.assertIn(arguments[-1], created)
                    if mode == 'state-failed':
                        stderr.write(contracts.PRIVATE.encode())
                        return subprocess.CompletedProcess(arguments, 1)
                    state = {'OOMKilled': mode == 'oom', 'Running': mode == 'timeout',
                             'ExitCode': 0 if mode in ('timeout', 'foreign-state') else 137,
                             'Error': contracts.PRIVATE}
                    if mode == 'bad-state':
                        state['OOMKilled'] = 'private-not-a-boolean'
                    stdout.write(json.dumps(state).encode())
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
                self.assertEqual(volume['unmounted'], mode != 'foreign-volume')
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
                    self.assertIn('TMPDIR=/scratch', create)
                    options = create[create.index(runner.gate.SCANNER_IMAGE)+1:]
                    self.assertEqual(create[create.index('--network')+1], 'bridge' if '--download-db-only' in options else 'none')
                    cache_mount = next(create[n+1] for n, arg in enumerate(create)
                                       if arg == '--mount' and ',dst=/cache' in create[n+1])
                    self.assertEqual(cache_mount.endswith(',readonly'), '--download-db-only' not in options)
                    scratch_mount = next(create[n+1] for n, arg in enumerate(create)
                        if arg == '--mount' and ',dst=/scratch' in create[n+1])
                    self.assertEqual(scratch_mount, 'type=bind,src='+str(Path(volume['root'])/'tmp')+',dst=/scratch')
                    self.assertTrue(cache_mount.startswith('type=bind,src='+str(Path(volume['root'])/'cache')+','))
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
                self.assertEqual(output['scratch_bytes'], 2 << 30)
                self.assertEqual(output['scratch_cleanup'], 'unmounted')

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
        self.assertEqual(output['command']['category'], 'deadline-exceeded')
        self.assertEqual(output['command']['command_phase'], 'feed-download')
        self.assertEqual(output['scratch_cleanup'], 'unmounted')

    def test_non_github_invocation_refuses_before_any_subprocess(self):
        with patch.object(sys, 'argv', ['scan-peer-image.py', '--architecture', 'amd64']), \
             patch.dict('os.environ', {'GITHUB_ACTIONS': 'false'}), \
             patch.object(runner.subprocess, 'run') as invoked, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
            invoked.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['reason'], 'native-github-peer-scan-required')

    def test_mount_timeout_still_unmounts_only_the_exact_owned_backing(self):
        code, output, created = self.exercise(mode='mount-timeout')
        self.assertEqual(code, 2)
        self.assertEqual(output['phase'], 'scratch-volume')
        self.assertEqual(output['command']['category'], 'deadline-exceeded')
        self.assertEqual(output['scratch_cleanup'], 'unmounted')
        self.assertEqual(created, {})

    def test_foreign_loop_backing_is_never_unmounted_or_exposed_to_scanner(self):
        code, output, created = self.exercise(mode='foreign-volume')
        self.assertEqual(code, 2)
        self.assertEqual(output['phase'], 'scratch-volume')
        self.assertEqual(output['scratch_cleanup'], 'unproven')
        self.assertEqual(created, {})

    def test_recorded_container_oom_is_bound_before_exact_cleanup_without_changing_limits(self):
        code, output, created = self.exercise(mode='oom')
        self.assertEqual(code, 2)
        self.assertEqual(len(created), 1)
        self.assertEqual(output['command']['category'], 'container-oom')
        state = output['command']['container_state']
        self.assertTrue(state['oom_killed'])
        self.assertFalse(state['running'])
        self.assertEqual(state['exit_code'], 137)
        self.assertRegex(state['state_sha256'], '^[0-9a-f]{64}$')
        self.assertEqual(output['scratch_cleanup'], 'unmounted')

    def test_exit137_alone_and_invalid_or_mismatched_state_do_not_invent_oom(self):
        for mode in ('killed', 'foreign-state', 'bad-state', 'state-failed', 'changed-state'):
            code, output, _ = self.exercise(mode=mode)
            self.assertEqual(code, 2)
            self.assertEqual(output['command']['exit_code'], 137)
            self.assertEqual(output['command']['category'], 'unrecognized-diagnostic')
            if mode in ('bad-state', 'state-failed', 'changed-state'):
                self.assertNotIn('container_state', output['command'])

    def test_fixed_diagnostic_categories_never_publish_raw_strings(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-image-diagnostic-') as directory:
            root = Path(directory)
            for category, patterns in runner.DIAGNOSTICS.items():
                with self.subTest(category=category):
                    path = root/'feed-download.stderr'
                    raw = contracts.PRIVATE.encode()+b'\n'+patterns[0]+b'\n'
                    path.write_bytes(raw)
                    failed = {'phase': 'feed-download', 'exit_code': 1,
                              'stdout_sha256': 'a'*64, 'stderr_sha256': hashlib.sha256(raw).hexdigest()}
                    # Cleanup succeeds after the failure; it must not hide it.
                    result = runner.failure_observation([failed, {'phase': 'feed-download-cleanup', 'exit_code': 0}], root)
                    self.assertEqual(result['category'], category)
                    self.assertEqual(result['exit_code'], 1)
                    self.assertNotIn(contracts.PRIVATE, json.dumps(result))
                    self.assertEqual(set(result), {'command_phase', 'exit_code', 'category', 'stdout_sha256', 'stderr_sha256'})

    def test_ambiguous_unbound_missing_or_private_observations_stay_unrecognized(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-image-diagnostic-') as directory:
            root = Path(directory)
            path = root/'feed-download.stderr'
            for raw in (contracts.PRIVATE.encode(), b'unknown flag; unauthorized'):
                path.write_bytes(raw)
                row = {'phase': 'feed-download', 'exit_code': 1, 'stderr_sha256': hashlib.sha256(raw).hexdigest()}
                self.assertEqual(runner.failure_observation([row], root)['category'], 'unrecognized-diagnostic')
            path.write_bytes(b'unknown flag')
            row = {'phase': 'feed-download', 'exit_code': 1, 'stderr_sha256': 'a'*64}
            self.assertEqual(runner.failure_observation([row], root)['category'], 'unrecognized-diagnostic')
            row['phase'] = '../'+contracts.PRIVATE
            result = runner.failure_observation([row], root)
            self.assertEqual(result['command_phase'], 'not-recorded')
            self.assertNotIn(contracts.PRIVATE, json.dumps(result))
            row['phase'], row['exit_code'] = 'feed-download', True
            self.assertEqual(runner.failure_observation([row], root)['command_phase'], 'not-recorded')
            row['phase'], row['exit_code'] = [contracts.PRIVATE], 1
            self.assertEqual(runner.failure_observation([row], root)['command_phase'], 'not-recorded')
            row['phase'], row['stderr_sha256'] = 'feed-download', contracts.PRIVATE
            result = runner.failure_observation([row], root)
            self.assertIsNone(result['stderr_sha256'])
            self.assertNotIn(contracts.PRIVATE, json.dumps(result))
            path.unlink()
            row['exit_code'] = 1
            self.assertEqual(runner.failure_observation([row], root)['category'], 'unrecognized-diagnostic')


if __name__ == '__main__':
    unittest.main()
