#!/usr/bin/env python3
"""Parser/process stand-ins only: no Windows API execution or platform claim."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('windows_fs_gate', Path(__file__).with_name('qualify-windows-fs.py'))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
SOURCE = 'a'*40


def op(attempted=False, code=0):
    return dict(attempted=attempted, code=code)


def acl(queried=True):
    return dict(queried=queried, code=0, null=False, protected=queried, owner_current=queried,
        expected_descriptor=queried, ace_count=2 if queried else 0)


def observation():
    cases = []
    for name in gate.CASES:
        file = name in ('go-file', 'win-file-write-through')
        cases.append(dict(case=name, open=op(True), write=op(file), flush=op(True, 0 if file else 5),
            close=op(True), parent_close=op(name == 'reopened-directory-read-write'), readback=file,
            mode_bits=0o600 if file else 0, acl=acl()))
    return dict(schema_version=1, kind='freightctl-windows-fs-api-observation-v1', state='recorded',
        source_commit=SOURCE, system='Windows', architecture='amd64', go_version='go1.26.10',
        phase='complete', error=op(), elevated=False, filesystem='NTFS', directory_acl=acl(),
        cases=cases, cleanup=op(True), cleanup_absent=True, qualification_claim=False)


class WindowsObservationContracts(unittest.TestCase):
    def test_observation_retains_access_denied_without_qualifying_durability(self):
        value = observation()
        self.assertEqual(gate.validate(json.dumps(value).encode(), SOURCE), value)
        self.assertEqual(value['cases'][1]['flush']['code'], 5)
        value['cases'][2].update(open=op(True, 5), flush=op(), close=op(), acl=acl(False))
        self.assertEqual(gate.validate(json.dumps(value).encode(), SOURCE), value)

    def test_original_shape_scope_counts_and_nonclaim_are_mandatory(self):
        changes = [lambda v:v.update(qualification_claim=True), lambda v:v.update(source_commit='b'*40),
            lambda v:v.update(system='Linux'), lambda v:v.update(architecture='arm64'),
            lambda v:v.update(go_version='go1.0'), lambda v:v.update(cleanup_absent=False),
            lambda v:v.update(schema_version=True), lambda v:v['cases'].reverse(),
            lambda v:v['cases'].pop(), lambda v:v['cases'][0].update(mode_bits=0o1000),
            lambda v:v['cases'][0]['acl'].update(ace_count=65536),
            lambda v:v['cases'][0]['flush'].update(code=True),
            lambda v:v['cases'][0]['open'].update(code=-1),
            lambda v:v['cases'][0]['close'].update(attempted=False),
            lambda v:v['cases'][0]['acl'].update(null=True),
            lambda v:v['cases'][1].update(readback=True),
            lambda v:v['cases'][1]['parent_close'].update(attempted=True)]
        for change in changes:
            value = observation(); change(value)
            with self.assertRaises(gate.InvalidEvidence):
                gate.validate(json.dumps(value).encode(), SOURCE)

    def test_account_paths_unknown_fields_duplicates_floats_constants_never_pass(self):
        for field in ('sid', 'sddl', 'path', 'stderr'):
            value = observation(); value[field] = 'private-canary'
            with self.assertRaises(gate.InvalidEvidence):
                gate.validate(json.dumps(value).encode(), SOURCE)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":0.1}', b' '*((1 << 20)+1)):
            with self.assertRaises(gate.InvalidEvidence):
                gate.load(raw)

    def test_local_foreign_host_refuses_before_resources_or_commands(self):
        for actions, system, machine in [('false', 'Windows', 'AMD64'), ('true', 'Darwin', 'arm64'),
                ('true', 'Windows', 'ARM64')]:
            with patch.dict(os.environ, {'GITHUB_ACTIONS':actions, 'GITHUB_SHA':SOURCE}), patch.object(gate.platform, 'system', return_value=system), patch.object(gate.platform, 'machine', return_value=machine), patch.object(gate.tempfile, 'mkdtemp') as mkdir, patch.object(gate, 'command') as command:
                self.assertEqual(gate.run()['phase'], 'preflight')
                mkdir.assert_not_called(); command.assert_not_called()

    def test_environment_drops_credentials_model_database_target_flags(self):
        with patch.dict(os.environ, {'GITHUB_SHA':SOURCE, 'Path':'owned-path', 'SystemRoot':'owned-system',
                'GH_TOKEN':'private-canary', 'DATABASE_URL':'private-canary', 'OLLAMA_HOST':'private-canary',
                'GOFLAGS':'foreign', 'GOOS':'linux', 'GOARCH':'arm64'}, clear=True):
            value = gate.environment()
            self.assertEqual(value['Path'], 'owned-path')
            self.assertEqual(value['SystemRoot'], 'owned-system')
            self.assertNotIn('private-canary', str(value)); self.assertNotIn('GOFLAGS', value)
            self.assertNotIn('GOOS', value); self.assertNotIn('GOARCH', value)
            self.assertEqual(value['GOTOOLCHAIN'], 'local')
            self.assertNotIn('GOMAXPROCS', value)
            self.assertNotIn('GOMEMLIMIT', value)

    def execute_standin(self, mutate=None):
        with tempfile.TemporaryDirectory(prefix='freightctl-windows-contract-') as directory:
            root = Path(directory)
            for name in gate.SOURCES:
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'source')
            def command(cwd, work, name, argv, timeout, env):
                self.assertEqual(cwd, root)
                body = b''
                if name == 'source': body = (SOURCE+'\n').encode()
                if name == 'native-go': body = json.dumps(dict(GOOS='windows', GOARCH='amd64', GOHOSTOS='windows', GOHOSTARCH='amd64', GOVERSION='go1.26.10')).encode()
                if name == 'build':
                    self.assertEqual(timeout, 120)
                    self.assertIn('-mod=readonly', argv); self.assertIn('-trimpath', argv)
                    (work/'windows-fs.exe').write_bytes(b'synthetic-not-executed')
                if name == 'observe':
                    self.assertEqual(argv, [str(work/'windows-fs.exe')]); self.assertEqual(timeout, 45)
                    body = json.dumps(observation()).encode()
                (work/(name+'.out')).write_bytes(body); (work/(name+'.err')).write_bytes(b'')
                result = dict(name=name, exit_code=0, stdout_sha256=gate.digest(work/(name+'.out'), empty=True), stderr_sha256=gate.digest(work/(name+'.err'), empty=True))
                if name == 'observe' and mutate: mutate(root, work)
                return result
            with patch.object(gate, 'ROOT', root), patch.object(gate, 'preflight', return_value=SOURCE), patch.object(gate, 'environment', return_value={}), patch.object(gate, 'command', side_effect=command):
                return gate.run()

    def test_full_orchestrator_binds_original_binary_source_outputs_and_cleanup(self):
        value = self.execute_standin()
        self.assertEqual(value['state'], 'recorded'); self.assertTrue(value['cleanup_absent'])
        self.assertEqual([c['name'] for c in value['commands']], ['source', 'source-clean', 'native-go', 'build', 'observe'])
        self.assertFalse(value['windows_platform_qualified']); self.assertFalse(value['durability_qualified'])
        self.assertFalse(value['private_acl_qualified'])
        for mutate in (lambda root,work:(root/gate.SOURCES[0]).write_bytes(b'changed'),
                lambda root,work:(work/'windows-fs.exe').write_bytes(b'changed'),
                lambda root,work:(work/'source.out').write_bytes(b'changed')):
            value = self.execute_standin(mutate)
            self.assertEqual((value['state'], value['phase']), ('failed', 'closure'))
            self.assertNotIn('observation', value)

    def test_timeout_kills_only_exact_live_owned_process_tree(self):
        process = Mock(pid=1234); process.poll.return_value = None
        with patch.object(gate.platform, 'system', return_value='Windows'), patch.object(gate.subprocess, 'run') as run:
            gate.stop(process)
            self.assertEqual(run.call_args.args[0], ['taskkill.exe', '/PID', '1234', '/T', '/F'])
            process.wait.assert_called_once_with(timeout=10)
        process.poll.return_value = 0
        with patch.object(gate.subprocess, 'run') as run:
            gate.stop(process); run.assert_not_called()
        process.poll.return_value = None
        with patch.object(gate.platform, 'system', return_value='Darwin'), patch.object(gate.subprocess, 'run') as run:
            with self.assertRaises(gate.InvalidEvidence): gate.stop(process)
            run.assert_not_called()

    def test_original_timeout_is_failure_and_outputs_are_bounded(self):
        for oversized in (False, True):
            with tempfile.TemporaryDirectory(prefix='freightctl-windows-timeout-') as directory:
                work = Path(directory); process = Mock(pid=1234); process.poll.return_value = None
                def start(*args, **kwargs):
                    if oversized: kwargs['stdout'].write(b'x'*(gate.MAX_OUTPUT+1)); kwargs['stdout'].flush()
                    return process
                with patch.object(gate.subprocess, 'CREATE_NEW_PROCESS_GROUP', 512, create=True), patch.object(gate.subprocess, 'Popen', side_effect=start), patch.object(gate.time, 'monotonic', side_effect=[0, 121]), patch.object(gate, 'stop') as stop:
                    with self.assertRaises(gate.InvalidEvidence):
                        gate.command(work, work, 'build', ['go', 'build'], 120, {})
                    stop.assert_called_once_with(process)

    def test_failure_reports_never_print_private_exception_or_paths(self):
        with patch.object(gate, 'preflight', side_effect=OSError('private-canary')):
            value = gate.run()
            self.assertEqual((value['state'], value['phase']), ('failed', 'preflight'))
            self.assertNotIn('private-canary', json.dumps(value))


if __name__ == '__main__':
    unittest.main()
