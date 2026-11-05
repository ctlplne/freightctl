#!/usr/bin/env python3
"""Real orchestration/checker with compiler/process/archive stand-ins only."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('repro_builds', HERE/'qualify-repro-builds.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
COMMIT = 'a'*40
SUM = 'h1:'+'A'*43+'='
ASSET = b'<html>qualification fixture, never served</html>\n'
BINARY = b'synthetic native binary; never executed\x00'+ASSET
PACKAGE_SPEC = importlib.util.spec_from_file_location('go_package_fixture', HERE/'test-core-go-packages.py')
package_fixture = importlib.util.module_from_spec(PACKAGE_SPEC)
PACKAGE_SPEC.loader.exec_module(package_fixture)


def build_info(arch='amd64'):
    return {'GoVersion': runner.GO_VERSION, 'Path': runner.MODULE+'/cmd/freightctl',
        'Main': {'Path': runner.MODULE, 'Version': '(devel)'},
        'Settings': [{'Key': k, 'Value': v} for k, v in {'GOOS': 'linux', 'GOARCH': arch, 'CGO_ENABLED': '0',
            '-trimpath': 'true', '-buildmode': 'exe', '-compiler': 'gc',
            'GOAMD64' if arch == 'amd64' else 'GOARM64': 'v1' if arch == 'amd64' else 'v8.0'}.items()],
        'Deps': [{'Path': name, 'Version': 'v1.0.0', 'Sum': SUM} for name in
            ('github.com/jackc/pgx/v5', 'github.com/ProtonMail/go-crypto')]+[
            {'Path': 'github.com/fclairamb/ftpserverlib', 'Version': 'v0.32.7',
                'Replace': {'Path': './third_party/ftpserverlib', 'Version': '(devel)'}}]}


def archive(path, extra=None):
    package = {'name': 'qualification-ui', 'version': '0.0.0', 'dependencies': {'example': '1.2.3'}}
    lock = {'lockfileVersion': 3, 'packages': {'': package, 'node_modules/example': {'version': '1.2.3',
        'resolved': 'https://registry.npmjs.org/example/-/example-1.2.3.tgz', 'integrity': 'sha512-'+'A'*86+'=='}}}
    web = {'web/package.json': json.dumps(package).encode(), 'web/package-lock.json': json.dumps(lock).encode()}
    browser = {'schema_version': 1, 'sources': [{'path': k, 'sha256': hashlib.sha256(v).hexdigest()} for k,v in web.items()],
        'outputs': [{'name': 'index.html', 'sha256': hashlib.sha256(ASSET).hexdigest(), 'size': len(ASSET)}],
        'bundled_packages': ['node_modules/example/index.js']}
    values = {'go.mod': ('module '+runner.MODULE+'\n').encode(),
        'go.sum': ('\n'.join(name+' v1.0.0 '+SUM for name in
            ('github.com/jackc/pgx/v5', 'github.com/ProtonMail/go-crypto'))+'\n').encode(),
        'cmd/freightctl/main.go': b'// stand-in source; never compiled\n',
        'third_party/ftpserverlib/UPSTREAM.json': b'{"scope":"synthetic pinned source"}\n', **web,
        'internal/browser/assets/manifest.json': json.dumps(browser).encode(), 'internal/browser/assets/index.html': ASSET}
    with tarfile.open(path, 'w:') as output:
        for name, body in values.items():
            member = tarfile.TarInfo(name); member.mode = 0o644; member.size = len(body)
            output.addfile(member, io.BytesIO(body))
        if extra is not None:
            output.addfile(extra, io.BytesIO(b'x'*extra.size) if extra.isfile() else None)


class ReproBuildContracts(unittest.TestCase):
    def exercise(self, arch='amd64', mode='clean'):
        with tempfile.TemporaryDirectory(prefix='freightctl-repro-contract-') as directory:
            root = Path(directory).resolve()
            temporary = root/'temporary'; temporary.mkdir()
            calls = []
            goroot = root/'toolchain'; goroot.mkdir()
            packages = package_fixture.fixture(goroot, build_info(arch))
            def command(work, steps, label, argv, cwd, env, timeout):
                calls.append({'label': label, 'argv': list(map(str, argv)), 'cwd': cwd, 'env': env, 'timeout': timeout})
                out, err = work/(label+'.stdout'), work/(label+'.stderr')
                data = b''
                self.assertNotIn('GITHUB_TOKEN', env)
                self.assertNotIn('FREIGHTCTL_TEST_RUNTIME_FILE', env)
                self.assertNotIn('GOFLAGS', env)
                self.assertEqual(env['GOMAXPROCS'], '1')
                self.assertEqual(env['GOMEMLIMIT'], '192MiB')
                self.assertEqual(env['GOTOOLCHAIN'], 'local')
                if label == 'source-identity':
                    data = (('b'*40 if mode == 'wrong-commit' else COMMIT)+'\n').encode()
                elif label == 'native-go':
                    data = json.dumps({'GOHOSTOS': 'linux', 'GOOS': 'linux', 'GOHOSTARCH': arch,
                        'GOARCH': arch, 'GOVERSION': 'go1.25.0' if mode == 'wrong-toolchain' else runner.GO_VERSION,
                        'GOROOT':str(goroot)}).encode()
                elif label == 'source-archive':
                    archive(Path(str(argv[3]).split('=', 1)[1]))
                elif label == 'module-download':
                    self.assertEqual(env['GOPROXY'], 'https://proxy.golang.org,direct')
                    if mode == 'prime-source-change':
                        (cwd/'go.sum').write_text('changed')
                elif label.startswith('module-verify-'):
                    self.assertEqual(env['GOPROXY'], 'off')
                    self.assertEqual(argv[1:], ['mod', 'verify'])
                    if mode == 'final-binary-change' and label == 'module-verify-after':
                        (work/'freightctl-a').write_bytes(b'changed after all earlier observations')
                    if mode == 'final-toolchain-change' and label == 'module-verify-after':
                        (goroot/'src/fmt/print.go').write_bytes(b'changed after both package captures')
                    if mode == 'final-reader-change' and label == 'module-verify-after':
                        (work/'tool-cache/tool/buildid').write_bytes(b'changed stock reader')
                elif label == 'prepare-build-id-tool':
                    self.assertEqual(list(map(str,argv[1:])), ['tool','-n','buildid'])
                    self.assertEqual(timeout, 120)
                    reader = work/'tool-cache/tool/buildid'; reader.parent.mkdir(parents=True)
                    reader.write_bytes(b'synthetic pinned reader; never executed')
                    data = ((str(root/'outside-reader') if mode == 'foreign-reader' else str(reader))+'\n').encode()
                elif label.startswith('build-id-'):
                    self.assertEqual(list(map(str, argv)), [str(work/'tool-cache/tool/buildid'), str(work/('freightctl-'+label[-1]))])
                    self.assertEqual(timeout, 10)
                    data = b'original-build-id\n' if mode == 'retained-build-id' else b'\n'
                elif label.startswith('build-'):
                    self.assertEqual(env['GOPROXY'], 'off')
                    self.assertEqual(argv[1:8], ['build', '-p', '1', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-buildid='])
                    self.assertFalse(Path(env['GOCACHE']).exists())
                    Path(env['GOCACHE']).mkdir()
                    binary = Path(argv[argv.index('-o')+1])
                    binary.write_bytes(b'different' if mode == 'different-binary' and label == 'build-b' else BINARY)
                    if mode == 'prior-binary-change' and label == 'build-b':
                        (work/'freightctl-a').write_bytes(b'changed after first observation')
                    if mode == 'prior-source-change' and label == 'build-b':
                        (work/'one/source/cmd/freightctl/main.go').write_text('changed after first build')
                    if mode == 'build-source-change':
                        (cwd/'cmd/freightctl/main.go').write_text('changed')
                elif label.startswith('inventory-'):
                    info = build_info(arch)
                    if mode == 'wrong-dependency':
                        info['Deps'][0]['Sum'] = 'h1:'+'B'*43+'='
                    if mode == 'foreign-replacement':
                        info['Deps'][2]['Replace']['Path'] = '/private-canary'
                    if mode == 'cgo-enabled':
                        next(v for v in info['Settings'] if v['Key'] == 'CGO_ENABLED')['Value'] = '1'
                    if mode == 'vcs-setting':
                        info['Settings'].append({'Key': 'vcs.revision', 'Value': COMMIT})
                    if mode == 'unexpected-ldflags':
                        info['Settings'].append({'Key': '-ldflags', 'Value': '-buildid='})
                    data = json.dumps(info).encode()
                elif label.startswith('packages-'):
                    self.assertEqual(timeout, 60)
                    self.assertEqual(env['GOPROXY'], 'off')
                    self.assertEqual(list(map(str,argv[1:])), ['list', '-p', '1', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-buildid=', '-deps', '-json', './cmd/freightctl'])
                    current = copy.deepcopy(packages)
                    if mode == 'missing-package' and label == 'packages-b': current.pop()
                    data = package_fixture.raw(current)
                elif label.startswith('help-'):
                    self.assertEqual(argv[1:], ['--help'])
                    self.assertEqual(env['GOPROXY'], 'off')
                    data = b'freightctl: schema-version | serve-ftps\n'
                    if mode == 'different-help' and label == 'help-b':
                        data += b'changed\n'
                    if mode == 'prior-log-change' and label == 'help-b':
                        (work/'source-identity.stdout').write_bytes(b'private-canary')
                out.write_bytes(data); err.write_bytes(b'')
                steps.append({'name': label, 'exit_code': 0, 'stdout_sha256': hashlib.sha256(data).hexdigest(),
                    'stderr_sha256': hashlib.sha256(b'').hexdigest()})
                return out
            values = {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': COMMIT, 'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(temporary),
                'GITHUB_TOKEN': 'private-canary', 'FREIGHTCTL_TEST_RUNTIME_FILE': '/private-canary', 'GOFLAGS': '-tags=private-canary'}
            buffer = io.StringIO()
            schema_result = {'engine': 'stand-in-only-not-qualified'}
            with patch.object(runner, 'ROOT', root), patch.dict(os.environ, values), patch.object(runner.platform, 'system', return_value='Linux'), patch.object(runner.platform, 'machine', return_value='x86_64' if arch == 'amd64' else 'aarch64'), patch.object(runner, 'command', command), patch.object(runner.shutil, 'which', return_value='/synthetic/go'), patch.object(runner.schema_gate, 'validate', return_value=schema_result, side_effect=ValueError('private-canary') if mode == 'schema-refusal' else None) as schema, patch('sys.argv', ['qualify-repro-builds.py', '--architecture', arch]), contextlib.redirect_stdout(buffer):
                code = runner.main()
                if code == 0:
                    schema.assert_called_once()
                    self.assertEqual(schema.call_args.args[1]['bomFormat'], 'CycloneDX')
            result = json.loads(buffer.getvalue())
            work = next(temporary.iterdir())
            manifest = runner.load(work/('manifest.json' if code == 0 else 'failure.json'))
            return code, result, manifest, calls

    def test_two_native_profiles_use_different_source_roots_empty_caches_and_exact_original_bytes(self):
        for arch in ('amd64', 'arm64'):
            code, result, manifest, calls = self.exercise(arch)
            self.assertEqual(code, 0)
            self.assertEqual(result['state'], 'passed')
            self.assertEqual(result['dependency_modules'], 3)
            self.assertFalse(result['artifact_published'])
            self.assertFalse(result['complete_sbom'])
            self.assertFalse(result['disconnected_install_qualified'])
            self.assertFalse(result['signing_qualified'])
            self.assertFalse(result['production_platform_qualified'])
            self.assertEqual(tuple(c['label'] for c in calls), runner.COMMANDS)
            builds = [c for c in calls if c['label'] in ('build-a', 'build-b')]
            self.assertNotEqual(builds[0]['cwd'], builds[1]['cwd'])
            self.assertNotEqual(builds[0]['env']['GOCACHE'], builds[1]['env']['GOCACHE'])
            self.assertEqual(builds[0]['env']['GOMODCACHE'], builds[1]['env']['GOMODCACHE'])
            self.assertNotIn('private-canary', json.dumps(result))
            self.assertEqual(manifest['binary_sha256'], result['binary_sha256'])
            self.assertEqual(result['component_inventory_format'], 'CycloneDX1.6')
            self.assertRegex(result['component_inventory_sha256'], '^[0-9a-f]{64}$')
            self.assertEqual(result['component_schema_validation'], {'engine': 'stand-in-only-not-qualified'})
            self.assertEqual(result['go_standard_library_packages'], 3)

    def test_real_orchestration_refuses_changed_source_binary_inventory_platform_and_help(self):
        for mode in ('different-binary', 'different-help', 'wrong-dependency', 'foreign-replacement',
                'cgo-enabled', 'vcs-setting', 'prime-source-change', 'build-source-change', 'wrong-commit', 'wrong-toolchain',
                'prior-binary-change', 'prior-source-change', 'prior-log-change', 'final-binary-change', 'schema-refusal',
                'unexpected-ldflags', 'retained-build-id', 'final-toolchain-change', 'missing-package', 'final-reader-change', 'foreign-reader'):
            with self.subTest(mode=mode):
                code, result, manifest, _ = self.exercise(mode=mode)
                self.assertEqual(code, 2)
                self.assertEqual(result['state'], 'failed')
                self.assertEqual(manifest['phase'], result['phase'])
                self.assertFalse(result['artifact_published'])
                self.assertNotIn('private-canary', json.dumps(result))

    def test_archive_parser_refuses_links_special_files_duplicates_and_path_escape(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-repro-archive-') as directory:
            base = Path(directory)
            for index, (name, type_) in enumerate((('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                    ('bad\\escape', tarfile.REGTYPE), ('go.mod', tarfile.REGTYPE), ('linked', tarfile.SYMTYPE),
                    ('hard', tarfile.LNKTYPE), ('special', tarfile.FIFOTYPE), ('.private/credential', tarfile.REGTYPE))):
                member = tarfile.TarInfo(name); member.type = type_; member.linkname = '/private-canary'
                if member.isfile():
                    member.size = 1
                path = base/('archive-'+str(index)+'.tar'); archive(path, member)
                with self.assertRaises((ValueError, FileExistsError)):
                    runner.extract(path, base/('source-'+str(index)))
            self.assertFalse((base/'escape').exists())

    def test_inventory_requires_complete_original_dependency_and_exact_source_checksum(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-repro-inventory-') as directory:
            root = Path(directory); path = root/'source.tar'; archive(path); source = root/'source'; runner.extract(path, source)
            original = build_info()
            for mutate in (lambda v: v.update(Deps=[]), lambda v: v['Deps'][0].update(Sum='private-canary'),
                    lambda v: v.update(GoVersion='go1.26.9'), lambda v: v.update(Path='other'),
                    lambda v: v['Settings'].append(copy.deepcopy(v['Settings'][0])),
                    lambda v: v['Deps'].append(copy.deepcopy(v['Deps'][0]))):
                value = copy.deepcopy(original); mutate(value)
                with self.assertRaises(ValueError):
                    runner.inventory(value, source, 'amd64')

    def test_local_or_wrong_arch_preflight_stops_before_any_process_or_directory_creation(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch('sys.argv', ['runner', '--architecture', 'amd64']), patch.object(runner, 'command') as command, patch.object(runner.tempfile, 'mkdtemp') as create, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
            command.assert_not_called(); create.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['phase'], 'preflight')
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': COMMIT,
                'GITHUB_WORKSPACE': str(runner.ROOT)}), patch.object(runner.platform, 'system', return_value='Linux'), patch.object(runner.platform, 'machine', return_value='aarch64'), patch('sys.argv', ['runner', '--architecture', 'amd64']), patch.object(runner, 'command') as command, patch.object(runner.tempfile, 'mkdtemp') as create, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
            command.assert_not_called(); create.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['check'], 'runner-identity')

    def test_timeout_signals_only_its_own_child_and_keeps_original_timeout_failure(self):
        with tempfile.TemporaryDirectory(prefix='freightctl-repro-process-') as directory:
            work = Path(directory); steps = []
            child = unittest.mock.Mock(pid=12345)
            child.wait.side_effect = [subprocess.TimeoutExpired('private-canary', 1), 0]
            with patch.object(runner.subprocess, 'Popen', return_value=child) as spawn, patch.object(runner.os, 'killpg') as stop:
                with self.assertRaises(ValueError):
                    runner.command(work, steps, 'build-a', ['not-executed'], work, {}, 1)
                self.assertTrue(spawn.call_args.kwargs['start_new_session'])
                stop.assert_called_once_with(12345, signal.SIGTERM)
                self.assertEqual(steps[0]['exit_code'], 'timeout')


if __name__ == '__main__':
    unittest.main(verbosity=2)
