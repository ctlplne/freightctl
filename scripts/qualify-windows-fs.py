#!/usr/bin/env python3
"""Native Windows API observations, never permission/durability qualification."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 1 << 20
MAX_BINARY = 32 << 20
CASES = ('go-file', 'go-directory', 'win-directory-read', 'win-directory-read-write',
    'win-directory-write-through', 'reopened-directory-read-write', 'win-file-write-through')
SOURCES = ('scripts/peers/windowsfs/main_windows.go', 'scripts/qualify-windows-fs.py', 'go.mod', 'go.sum')
PHASES = ('preflight', 'source', 'native-go', 'build', 'observe', 'closure', 'cleanup', 'complete')


class InvalidEvidence(ValueError):
    def __init__(self):
        super().__init__('windows-fs-observation-invalid')


def require(value):
    if not value:
        raise InvalidEvidence()


def digest(path, maximum=MAX_OUTPUT, empty=False):
    require(path.is_file() and not path.is_symlink() and (0 if empty else 1) <= path.stat().st_size <= maximum)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise InvalidEvidence()
    return json.loads(raw, object_pairs_hook=unique, parse_float=invalid, parse_constant=invalid)


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys.split()))


def boolean(value):
    require(type(value) is bool)


def integer(value, maximum):
    require(type(value) is int and 0 <= value <= maximum)


def operation(value):
    exact(value, 'attempted code')
    boolean(value['attempted']); integer(value['code'], (1 << 32)-1)
    require(value['attempted'] or value['code'] == 0)


def acl(value):
    exact(value, 'queried code null protected owner_current expected_descriptor ace_count')
    for key in ('queried', 'null', 'protected', 'owner_current', 'expected_descriptor'):
        boolean(value[key])
    integer(value['code'], (1 << 32)-1); integer(value['ace_count'], 65535)
    require(value['queried'] or value == dict(queried=False, code=0, null=False, protected=False,
        owner_current=False, expected_descriptor=False, ace_count=0))
    require(not value['null'] or (value['ace_count'] == 0 and not value['expected_descriptor']))


def validate(raw, source):
    value = load(raw)
    exact(value, 'schema_version kind state source_commit system architecture go_version phase error elevated filesystem directory_acl cases cleanup cleanup_absent qualification_claim')
    require(type(value['schema_version']) is int and value['schema_version'] == 1)
    require(value['kind'] == 'freightctl-windows-fs-api-observation-v1' and value['state'] == 'recorded')
    require(value['source_commit'] == source and re.fullmatch('[0-9a-f]{40}', source))
    require(value['system'] == 'Windows' and value['architecture'] == 'amd64' and value['go_version'] == 'go1.27.3')
    require(value['phase'] == 'complete' and value['qualification_claim'] is False)
    boolean(value['elevated']); boolean(value['cleanup_absent'])
    require(value['filesystem'] in ('NTFS', 'ReFS', 'FAT', 'FAT32', 'exFAT', 'other', 'unobserved'))
    operation(value['error']); operation(value['cleanup']); acl(value['directory_acl'])
    require(value['error'] == {'attempted':False, 'code':0})
    require(value['cleanup'] == {'attempted':True, 'code':0} and value['cleanup_absent'])
    require(type(value['cases']) is list and len(value['cases']) == len(CASES))
    for item, name in zip(value['cases'], CASES):
        exact(item, 'case open write flush close parent_close readback mode_bits acl')
        require(item['case'] == name)
        for key in ('open', 'write', 'flush', 'close', 'parent_close'):
            operation(item[key])
        boolean(item['readback']); integer(item['mode_bits'], 0o777); acl(item['acl'])
        require(item['open']['attempted'])
        if item['open']['code'] == 0:
            require(item['close']['attempted'] and item['acl']['queried'])
            if name in ('go-file', 'win-file-write-through'):
                require(item['write']['attempted'])
                require(item['write']['code'] != 0 or item['flush']['attempted'])
            else:
                require(item['flush']['attempted'])
        else:
            require(not any(item[key]['attempted'] for key in ('write', 'flush', 'close'))
                and not item['acl']['queried'] and not item['readback'] and item['mode_bits'] == 0)
        if name not in ('go-file', 'win-file-write-through'):
            require(not item['write']['attempted'] and not item['readback'])
        if name != 'reopened-directory-read-write':
            require(not item['parent_close']['attempted'])
    return value


def preflight():
    source = os.environ.get('GITHUB_SHA', '')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and platform.system() == 'Windows'
        and platform.machine().lower() in ('amd64', 'x86_64') and re.fullmatch('[0-9a-f]{40}', source))
    return source


def environment():
    allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'GOROOT'}
    result = {k:v for k,v in os.environ.items() if k.upper() in allowed}
    result.update(GOENV='off', GOTOOLCHAIN='local', GOTELEMETRY='off', GOWORK='off', CGO_ENABLED='0',
        GITHUB_ACTIONS='true', GITHUB_SHA=os.environ['GITHUB_SHA'])
    return result


def stop(process):
    """Kill only this live owned child and its descendants; never an image name."""
    if process.poll() is not None:
        return
    require(platform.system() == 'Windows' and type(process.pid) is int and process.pid > 0)
    subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
    process.wait(timeout=10)


def command(root, work, name, argv, timeout, env):
    out, err = work/(name+'.out'), work/(name+'.err')
    with out.open('xb') as stdout, err.open('xb') as stderr:
        process = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
            stderr=stderr, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        deadline = time.monotonic()+timeout
        try:
            while process.poll() is None:
                require(time.monotonic() < deadline and out.stat().st_size <= MAX_OUTPUT and err.stat().st_size <= MAX_OUTPUT)
                time.sleep(0.05)
        except BaseException:
            stop(process)
            raise
    result = {'name':name, 'exit_code':process.returncode,
        'stdout_sha256':digest(out, empty=True), 'stderr_sha256':digest(err, empty=True)}
    # Go may write public module-download progress to stderr during the build.
    # Retain/hash it privately; every other command must have empty stderr.
    require(process.returncode == 0 and (name == 'build' or err.stat().st_size == 0))
    return result


def run():
    phase = 'preflight'
    work = None
    result = {'kind':'freightctl-windows-fs-api-gate-v1', 'state':'failed', 'phase':phase,
        'windows_platform_qualified':False, 'durability_qualified':False, 'private_acl_qualified':False}
    try:
        source = preflight()
        env = environment()
        work = Path(tempfile.mkdtemp(prefix='freightctl-windows-fs-wrapper-'))
        commands = []
        phase = 'source'
        commands.append(command(ROOT, work, phase, ['git', 'rev-parse', 'HEAD'], 10, env))
        require((work/'source.out').read_bytes().strip().decode('ascii') == source)
        commands.append(command(ROOT, work, 'source-clean', ['git', 'status', '--porcelain', '--untracked-files=normal'], 10, env))
        require((work/'source-clean.out').stat().st_size == 0)
        sources = {name:digest(ROOT/name) for name in SOURCES}
        phase = 'native-go'
        commands.append(command(ROOT, work, phase, ['go', 'env', '-json', 'GOOS', 'GOARCH', 'GOHOSTOS', 'GOHOSTARCH', 'GOVERSION'], 10, env))
        require(load((work/'native-go.out').read_bytes()) == dict(GOOS='windows', GOARCH='amd64', GOHOSTOS='windows', GOHOSTARCH='amd64', GOVERSION='go1.27.3'))
        phase = 'build'
        binary = work/'windows-fs.exe'
        commands.append(command(ROOT, work, phase, ['go', 'build', '-p', '1', '-mod=readonly', '-trimpath', '-buildvcs=false', '-o', str(binary), './scripts/peers/windowsfs'], 120, env))
        binary_hash = digest(binary, MAX_BINARY)
        phase = 'observe'
        commands.append(command(ROOT, work, phase, [str(binary)], 45, env))
        observation = validate((work/'observe.out').read_bytes(), source)
        phase = 'closure'
        require(digest(binary, MAX_BINARY) == binary_hash and sources == {name:digest(ROOT/name) for name in SOURCES})
        for item in commands:
            require(digest(work/(item['name']+'.out'), empty=True) == item['stdout_sha256']
                and digest(work/(item['name']+'.err'), empty=True) == item['stderr_sha256'])
        result.update(source_commit=source, binary_sha256=binary_hash, sources=sources, commands=commands, observation=observation)
        phase = 'cleanup'
        shutil.rmtree(work)
        require(not work.exists())
        work = None
        result.update(state='recorded', phase='complete', cleanup_absent=True)
    except Exception:
        # Never print subprocess output, account SID, local path or exception text.
        result = {k:v for k,v in result.items() if k in ('kind', 'windows_platform_qualified', 'durability_qualified', 'private_acl_qualified')}
        result.update(state='failed', phase=phase if phase in PHASES else 'preflight')
    finally:
        if work is not None:
            try:
                shutil.rmtree(work)
            except OSError:
                result.update(state='failed', phase='cleanup')
    return result


if __name__ == '__main__':
    result = run()
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    raise SystemExit(0 if result['state'] == 'recorded' else 1)
