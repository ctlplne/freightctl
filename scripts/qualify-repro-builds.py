#!/usr/bin/env python3
"""GitHub-only native core binary reproduction; no artifact publication.

Two committed-source copies and empty build caches share verified module input.
The embedded Go inventory is not a complete release SBOM or offline bundle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import signal
import subprocess
import tarfile
import tempfile

import core_component_inventory as components
import core_bom_schema as schema_gate

ROOT = Path(__file__).resolve().parents[1]
GO_VERSION = 'go1.26.10'
MODULE = 'github.com/ctlplne/freightctl'
SOURCE_MAX = 64 << 20
BINARY_MAX = 128 << 20
WORKING_MAX = 4 << 30
COMMANDS = ('source-identity', 'source-clean', 'native-go', 'source-archive', 'module-download', 'module-verify-before',
    'build-a', 'build-id-a', 'inventory-a', 'help-a', 'build-b', 'build-id-b', 'inventory-b', 'help-b', 'module-verify-after')
PHASES = frozenset(('preflight', *COMMANDS, 'source-extract', 'source-closure', 'binary-closure', 'inventory-closure', 'component-inventory', 'component-schema', 'record'))
CHECKS = frozenset(('evidence', 'binary-identity', 'build-settings', 'dependency-inventory', 'dependency-entry',
    'local-replacement', 'dependency-checksum', 'native-configuration', 'binary-equality', 'source-unchanged',
    'command-status', 'working-budget', 'runner-identity', 'build-id', 'structure', 'filesystem'))


class InvalidEvidence(ValueError):
    def __init__(self, check):
        self.check = check if check in CHECKS else 'evidence'
        super().__init__('reproducible-build-evidence-invalid')


def require(value, check='evidence'):
    if not value:
        raise InvalidEvidence(check)


def digest(path, maximum, allow_empty=False):
    require(path.is_file() and not path.is_symlink() and (0 if allow_empty else 1) <= path.stat().st_size <= maximum)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 4 << 20)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique, parse_constant=lambda _: require(False))


def extract(archive, destination):
    """No archive link, special file, overwrite or path escape is accepted."""
    require(archive.stat().st_size <= SOURCE_MAX and not destination.exists())
    destination.mkdir(mode=0o700)
    total, seen = 0, set()
    with tarfile.open(archive, 'r:') as stream:
        for member in stream:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and name.parts and len(name.parts) <= 64 and len(member.name) <= 4096
                and all(p not in ('', '.', '..') for p in name.parts)
                and name.as_posix().rstrip('/') == member.name.rstrip('/') and '\\' not in member.name
                and name.parts[0] not in ('.git', '.private', '.cache') and member.name not in seen
                and len(seen) < 8192 and (member.isdir() or member.isfile()) and 0 <= member.size <= 16 << 20)
            seen.add(member.name)
            target = destination.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            total += member.size
            require(total <= SOURCE_MAX)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            original = stream.extractfile(member)
            require(original is not None)
            with original, target.open('xb') as output:
                shutil.copyfileobj(original, output, 65536)
            require(target.stat().st_size == member.size)
            target.chmod(0o700 if member.mode & 0o111 else 0o600)
    require(seen and (destination/'go.mod').is_file() and (destination/'go.sum').is_file())


def sources(root):
    result = {}
    for directory, children, files in os.walk(root, followlinks=False):
        for name in children:
            require(not (Path(directory)/name).is_symlink())
        for name in files:
            path = Path(directory)/name
            require(len(result) < 8192 and not path.is_symlink() and path.is_file()
                and path.stat().st_size <= 16 << 20)
            with path.open('rb') as stream:
                result[path.relative_to(root).as_posix()] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return result


def working_bytes(root):
    total, count = 0, 0
    for directory, children, files in os.walk(root, followlinks=False):
        require(not any((Path(directory)/name).is_symlink() for name in children))
        for name in files:
            path = Path(directory)/name
            require(not path.is_symlink() and path.is_file())
            count += 1
            total += path.stat().st_size
            require(count <= 100000 and total <= WORKING_MAX, 'working-budget')
    return total


def inventory(value, source, arch):
    require(type(value) is dict and value.get('GoVersion') == GO_VERSION
        and value.get('Path') == MODULE+'/cmd/freightctl'
        and type(value.get('Main')) is dict and value['Main'].get('Path') == MODULE
        and value['Main'].get('Version') == '(devel)', 'binary-identity')
    settings = {}
    require(type(value.get('Settings')) is list and len(value['Settings']) <= 64, 'build-settings')
    for item in value['Settings']:
        require(type(item) is dict and set(item) == {'Key', 'Value'} and type(item['Key']) is str
            and type(item['Value']) is str and item['Key'] not in settings and not item['Key'].startswith('vcs'), 'build-settings')
        settings[item['Key']] = item['Value']
    for key, wanted in {'GOOS': 'linux', 'GOARCH': arch, 'CGO_ENABLED': '0', '-trimpath': 'true',
            '-buildmode': 'exe', '-compiler': 'gc'}.items():
        require(settings.get(key) == wanted, 'build-settings')
    # Go1.26 intentionally omits -ldflags when -trimpath is set (go.dev/issue/52372).
    # The original build command still requires -buildid=; independently inspect
    # the resulting executable's physical build ID below rather than invent a
    # flag entry that this toolchain cannot emit.
    require('-ldflags' not in settings, 'build-settings')
    require(settings.get('GOAMD64' if arch == 'amd64' else 'GOARM64') == ('v1' if arch == 'amd64' else 'v8.0'), 'build-settings')
    sums = set((source/'go.sum').read_text().splitlines())
    dependencies = value.get('Deps')
    require(type(dependencies) is list and 1 <= len(dependencies) <= 512, 'dependency-inventory')
    names, replacements = set(), 0
    for item in dependencies:
        require(type(item) is dict and type(item.get('Path')) is str and type(item.get('Version')) is str
            and item['Path'] not in names and 0 < len(item['Path']) <= 512 and item['Version'].startswith('v'), 'dependency-entry')
        names.add(item['Path'])
        if 'Replace' in item:
            replacement = item['Replace']
            require(item['Path'] == 'github.com/fclairamb/ftpserverlib' and item['Version'] == 'v0.32.7'
                and type(replacement) is dict and replacement.get('Path') == './third_party/ftpserverlib'
                and replacement.get('Version', '') in ('', '(devel)')
                and not replacement.get('Sum') and (source/'third_party/ftpserverlib/UPSTREAM.json').is_file(), 'local-replacement')
            replacements += 1
        else:
            checksum = item.get('Sum')
            require(type(checksum) is str and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', checksum)
                and ' '.join((item['Path'], item['Version'], checksum)) in sums, 'dependency-checksum')
    require(replacements == 1 and {'github.com/jackc/pgx/v5', 'github.com/ProtonMail/go-crypto'} <= names, 'dependency-inventory')
    return len(names)


def environment(work, download):
    # Do not inherit credentials, model/database settings, proxy URLs or GOFLAGS.
    env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'TZ', 'GOROOT') if key in os.environ}
    env.update(GOMAXPROCS='1', GOMEMLIMIT='192MiB', GOTOOLCHAIN='local', GOENV='off',
        GOTELEMETRY='off', GOPATH=str(work/'gopath'), GOMODCACHE=str(work/'modules'),
        GOCACHE=str(work/'tool-cache'),
        GOPROXY='https://proxy.golang.org,direct' if download else 'off', GOSUMDB='sum.golang.org',
        GOOS='linux', CGO_ENABLED='0', GOAMD64='v1', GOARM64='v8.0', TMPDIR=str(work/'tmp'))
    return env


def command(work, steps, label, argv, cwd, env, timeout):
    require(label in COMMANDS and not any(step['name'] == label for step in steps))
    out, err = (work/(label+'.'+name) for name in ('stdout', 'stderr'))
    def bounded():
        resource.setrlimit(resource.RLIMIT_FSIZE, (BINARY_MAX, BINARY_MAX))
    code = 'incomplete'
    with out.open('xb') as stdout, err.open('xb') as stderr:
        child = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, start_new_session=True, preexec_fn=bounded)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            code = 'timeout'
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
        stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
    steps.append({'name': label, 'exit_code': code,
        'stdout_sha256': hashlib.sha256(out.read_bytes()).hexdigest() if out.stat().st_size <= 32 << 20 else None,
        'stderr_sha256': hashlib.sha256(err.read_bytes()).hexdigest() if err.stat().st_size <= 32 << 20 else None})
    require(type(code) is int and code == 0 and out.stat().st_size <= 32 << 20 and err.stat().st_size <= 32 << 20, 'command-status')
    working_bytes(work)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--architecture', required=True, choices=('amd64', 'arm64'))
    args = parser.parse_args()
    commit, arch = os.environ.get('GITHUB_SHA', ''), args.architecture
    phase, work, steps = 'preflight', None, []
    try:
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and platform.system() == 'Linux'
            and platform.machine() == {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch]
            and re.fullmatch('[0-9a-f]{40}', commit)
            and Path(os.environ.get('GITHUB_WORKSPACE', '.')).resolve() == ROOT, 'runner-identity')
        temporary = Path(os.environ.get('RUNNER_TEMP', '')).resolve()
        require(os.environ.get('RUNNER_TEMP') and temporary.is_dir() and not temporary.is_symlink())
        os.umask(0o077)
        work = Path(tempfile.mkdtemp(prefix='freightctl-repro-', dir=temporary))
        (work/'tmp').mkdir(mode=0o700)
        go = shutil.which('go')
        require(go is not None)
        env = environment(work, False)
        def run(label, argv, cwd=ROOT, variables=None, timeout=30):
            nonlocal phase
            phase = label
            return command(work, steps, label, argv, cwd, variables or env, timeout)
        require(run('source-identity', ['git', 'rev-parse', 'HEAD']).read_text().strip() == commit)
        run('source-clean', ['git', 'diff', '--quiet', 'HEAD', '--'])
        native = load(run('native-go', [go, 'env', '-json', 'GOHOSTOS', 'GOHOSTARCH', 'GOOS', 'GOARCH', 'GOVERSION']))
        require(native == {'GOHOSTOS': 'linux', 'GOOS': 'linux', 'GOHOSTARCH': arch, 'GOARCH': arch, 'GOVERSION': GO_VERSION}, 'native-configuration')
        archive = work/'source.tar'
        run('source-archive', ['git', 'archive', '--format=tar', '--output='+str(archive), commit])
        source_sha = digest(archive, SOURCE_MAX)
        phase = 'source-extract'
        first, second = work/'one/source', work/'different-parent/two/source'
        first.parent.mkdir(mode=0o700)
        second.parent.mkdir(mode=0o700, parents=True)
        extract(archive, first); extract(archive, second)
        original = sources(first)
        require(original == sources(second))
        prime = environment(work, True)
        prime['GOCACHE'] = str(work/'prime-cache')
        run('module-download', [go, 'mod', 'download', '-json'], first, prime, 300)
        run('module-verify-before', [go, 'mod', 'verify'], first, timeout=60)
        phase = 'source-closure'
        require(sources(first) == original and sources(second) == original, 'source-unchanged')
        results, infos, help_hashes = [], [], []
        for label, source in (('a', first), ('b', second)):
            build_env = dict(env, GOCACHE=str(work/('cache-'+label)))
            require(not Path(build_env['GOCACHE']).exists())
            binary = work/('freightctl-'+label)
            run('build-'+label, [go, 'build', '-p', '1', '-mod=readonly', '-trimpath', '-buildvcs=false',
                '-ldflags=-buildid=', '-o', binary, './cmd/freightctl'], source, build_env, 300)
            results.append(digest(binary, BINARY_MAX))
            build_id = run('build-id-'+label, [go, 'tool', 'buildid', binary], timeout=10)
            require(build_id.read_bytes() == b'\n'
                and (work/('build-id-'+label+'.stderr')).read_bytes() == b'', 'build-id')
            info = load(run('inventory-'+label, [go, 'version', '-m', '-json', binary]))
            phase = 'inventory-closure'
            count = inventory(info, source, arch)
            infos.append(info)
            output = run('help-'+label, [binary, '--help'], source, build_env, 10)
            help_bytes = output.read_bytes()
            require(help_bytes.startswith(b'freightctl: schema-version') and b'serve-ftps' in help_bytes
                and (work/('help-'+label+'.stderr')).read_bytes() == b'')
            help_hashes.append(hashlib.sha256(help_bytes).hexdigest())
            phase = 'source-closure'
            require(sources(source) == original, 'source-unchanged')
        phase = 'binary-closure'
        require(results[0] == results[1] and infos[0] == infos[1] and help_hashes[0] == help_hashes[1]
            and [digest(work/('freightctl-'+label), BINARY_MAX) for label in ('a', 'b')] == results, 'binary-equality')
        run('module-verify-after', [go, 'mod', 'verify'], first, timeout=60)
        phase = 'source-closure'
        require(sources(first) == original and sources(second) == original
            and tuple(step['name'] for step in steps) == COMMANDS, 'source-unchanged')
        for step in steps:
            for stream in ('stdout', 'stderr'):
                require(digest(work/(step['name']+'.'+stream), 32 << 20, allow_empty=True) == step[stream+'_sha256'])
        require(digest(archive, SOURCE_MAX) == source_sha)
        phase = 'binary-closure'
        require([digest(work/('freightctl-'+label), BINARY_MAX) for label in ('a', 'b')] == results, 'binary-equality')
        phase = 'component-inventory'
        docs = [components.encoded(components.create(source, original, info, commit, arch,
            work/('freightctl-'+label), results[index]))
            for index, (label, source, info) in enumerate((('a', first, infos[0]), ('b', second, infos[1])))]
        require(docs[0] == docs[1])
        component_path = work/'core.cdx.json'
        component_path.write_bytes(docs[0])
        require(component_path.read_bytes() == docs[0] and len(docs[0]) <= 4 << 20)
        component_sha = digest(component_path, 4 << 20)
        phase = 'component-schema'
        schema_validation = schema_gate.validate(first, components.load(component_path.read_bytes()))
        phase = 'record'
        manifest = {'schema_version': 1, 'kind': 'freightctl-native-reproducible-core-v1', 'state': 'passed',
            'source_commit': commit, 'architecture': arch, 'native_go': native, 'source_archive_sha256': source_sha,
            'source_files': len(original), 'source_tree_sha256': hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest(),
            'binary_sha256': results[0], 'dependency_modules': count, 'help_sha256': help_hashes[0], 'steps': steps,
            'component_inventory_sha256': component_sha, 'component_inventory_format': 'CycloneDX1.6',
            'component_schema_validation': schema_validation,
            'working_bytes_after_steps': working_bytes(work), 'working_bytes_after_steps_max': WORKING_MAX,
            'artifact_published': False, 'complete_sbom': False, 'disconnected_install_qualified': False,
            'signing_qualified': False, 'production_platform_qualified': False}
        path = work/'manifest.json'; path.write_text(json.dumps(manifest, indent=2)+'\n')
        print(json.dumps({key: manifest[key] for key in ('state', 'source_commit', 'architecture', 'binary_sha256',
            'source_archive_sha256', 'source_files', 'dependency_modules', 'component_inventory_sha256', 'component_inventory_format', 'component_schema_validation', 'artifact_published', 'complete_sbom',
            'disconnected_install_qualified', 'signing_qualified', 'production_platform_qualified')}
            | {'manifest_sha256': digest(path, 4 << 20)}, sort_keys=True))
        return 0
    except Exception as error:
        # The original private outputs remain on this disposable runner only.
        result = {'state': 'failed', 'reason': 'native-reproducible-build-failed',
            'phase': phase if phase in PHASES else 'preflight', 'artifact_published': False,
            'check': error.check if isinstance(error, InvalidEvidence) else 'filesystem' if isinstance(error, OSError) else 'structure'}
        if work is not None:
            try:
                path = work/'failure.json'; path.write_text(json.dumps({'steps': steps, **result}, indent=2)+'\n')
                result['manifest_sha256'] = digest(path, 4 << 20)
            except OSError:
                pass
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
