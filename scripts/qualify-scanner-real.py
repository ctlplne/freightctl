#!/usr/bin/env python3
"""Exercise a pre-authorized real clamd runtime; never load an inference model.

The runtime must be an exact freightctl-owned container with application, stock
curl, protected Unix socket and standard database, under one shared 4 GiB/1 CPU
cgroup. It is stopped on completion, including failure; volumes/evidence remain.
No native-platform, general malware-corpus or complete J02 claim is made.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import time
import traceback
import uuid
import zipfile
from urllib.parse import urlencode

os.umask(0o077)
root = Path(__file__).resolve().parents[1]
os.chdir(root)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime-reference', required=True)
args = parser.parse_args()
reference = (root / args.runtime_reference).resolve()
if not reference.is_relative_to(root / '.private') or reference.name != 'state.json':
    raise SystemExit('Select an exact protected runtime state reference')
runtime = json.loads(reference.read_text())
name = runtime['container']
if not name.startswith('freightctl-scanner-real-'):
    raise SystemExit('Only a named task-owned scanner runtime is accepted')
run = 'scanner-real-journey-' + uuid.uuid4().hex
private = root / '.private' / run
raw = root / 'evidence/raw' / run
for path in (private, raw):
    path.mkdir(mode=0o700, parents=True)
certificate = '/freightctl/' + run + '.crt'
tls_key = '/freightctl/' + run + '.key'
started = time.monotonic()
steps = []
server = None
server_log = None
owned = False
paused = False
failure = None
cleanup_failures = []
state = 'failed'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sources():
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).decode().split('\0')
    return [{'path': p, 'sha256': digest((root / p).read_bytes())}
            for p in sorted(set(paths)) if p and ((root / p).suffix in ('.go', '.sql', '.sh', '.py', '.ts', '.tsx', '.mjs') or p in ('go.mod', 'go.sum', 'web/package.json', 'web/package-lock.json'))]


def command(label, argv, data=None, success=True, timeout=35):
    try:
        result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as err:
        (raw / (label + '.stdout')).write_bytes(err.stdout or b'')
        (raw / (label + '.stderr')).write_bytes(err.stderr or b'')
        steps.append({'name': label, 'state': 'timed_out', 'timeout_seconds': timeout})
        raise
    for stream in ('stdout', 'stderr'):
        (raw / (label + '.' + stream)).write_bytes(getattr(result, stream))
    steps.append({'name': label, 'exit_code': result.returncode,
                  'expected_success': success, 'stdout_sha256': digest(result.stdout),
                  'stderr_sha256': digest(result.stderr)})
    if (result.returncode == 0) != success:
        raise RuntimeError(label + ': unexpected exit; inspect protected retained outputs')
    return result.stdout


def execute(label, argv, **kw):
    return command(label, ['docker', 'exec', '-i', name, *argv], **kw)


def write(label, filename, data):
    if not filename.startswith('/freightctl/') or any(c in filename for c in "'\n\r"):
        raise RuntimeError('Invalid task-owned output reference')
    execute(label, ['/bin/sh', '-ec', "umask 077; cat > '" + filename + "'"], data=data)
    return filename


def cli(label, operation, *extra, success=True):
    return execute(label, ['/freightctl/freightctl', operation,
                           '--dsn-file', '/freightctl/runtime.dsn', *map(str, extra)], success=success)


def call(label, operation, *extra, success=True):
    data = cli(label, operation, '--tenant', tenant, '--partner', partner,
               '--token-file', '/freightctl/owner.token', '--storage', '/freightctl/custody', *extra, success=success)
    return json.loads(data) if success else None


def http(label, route, method='GET', body=None, expected=200, key=None, identity=0):
    output = '/freightctl/http-' + label
    argv = ['/usr/bin/env', 'LD_LIBRARY_PATH=/freightctl/curl-root/usr/lib:/freightctl/curl-root/lib',
            '/freightctl/curl-root/lib/ld-musl-x86_64.so.1', '/freightctl/curl-root/usr/bin/curl',
            '--silent', '--show-error', '--cacert', certificate, '--max-time', '25',
            '--request', method, '--output', output, '--write-out', '%{http_code}',
            '--header', '@/freightctl/identity-' + str(identity) + '.headers']
    if key:
        argv += ['--header', 'Idempotency-Key: ' + key]
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        request = write(label + '-request', '/freightctl/request-' + label, data)
        argv += ['--data-binary', '@' + request]
        if isinstance(body, bytes):
            argv += ['--header', 'X-File-Size: ' + str(len(data)), '--header', 'X-Content-SHA256: ' + digest(data)]
        else:
            argv += ['--header', 'Content-Type: application/json']
    code = int(execute(label + '-curl', [*argv, bases[identity] + route]).decode())
    data = execute(label + '-response', ['cat', output])
    steps.append({'name': label, 'http_status': code, 'expected_status': expected, 'body_sha256': digest(data)})
    if code != expected:
        raise RuntimeError(label + ': HTTP ' + str(code) + ', expected ' + str(expected))
    try:
        return json.loads(data)
    except ValueError:
        return data


def upload(label, body):
    result = http(label, '/namespace/file?' + urlencode({'path': '/' + label + '.csv'}), 'PUT', body, 201, label)
    assert result['acceptance'] == 'durable-held-pending-checks-and-release'
    file = result['file']
    assert file['sha256'] == digest(body) and file['size_bytes'] == len(body)
    http(label + '-held-id', '/files/' + file['id'], expected=409)
    http(label + '-unpublished', '/namespace/file?' + urlencode({'path': '/' + label + '.csv'}), expected=404)
    return file


def scan(label, file, verdict, code):
    original = call(label + '-cli-run', 'check-run', '--file-id', file['id'], '--idempotency-key', label)
    replay = http(label + '-api-replay', '/checks/' + file['id'] + '/run', 'POST', key=label)
    assert replay['replayed'] and replay['resource'] == original['resource']
    view = http(label + '-report', '/checks/' + file['id'])
    check = view['check']
    assert check['code'] == code
    proof = check['report']['scanner']
    assert proof['result']['verdict'] == verdict
    assert proof['result']['sha256'] == file['sha256'] and proof['result']['bytes_scanned'] == file['size_bytes']
    assert proof['result']['configuration_sha256'] == runtime['configuration_sha256']
    assert proof['result']['version']['engine_version'] == '1.5.4'
    assert proof['result']['version']['database_version'] == 28168
    if verdict == 'clean' and code == 'valid_csv':
        assert check['state'] == 'passed' and check['report_hash']
    else:
        assert check['state'] == 'rejected' and not check['report_hash']
        http(label + '-denied', '/files/' + file['id'], expected=409)
    return check


def zip_bytes(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, data in files:
            item = zipfile.ZipInfo(filename, (2026, 10, 29, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, data)
    return out.getvalue()


starting_sources = sources()
try:
    inspected = json.loads(command('preflight-inspect', ['docker', 'inspect', name]))[0]
    host = inspected['HostConfig']
    assert inspected['Config']['Labels']['freightctl.workspace'] == str(root)
    assert inspected['Config']['Labels']['freightctl.role'] == 'real-scanner-qualification'
    assert inspected['Id'] == runtime['container_id'] and inspected['State']['Running']
    assert inspected['Config']['User'] == '100:101'
    assert host['Memory'] == 4294967296 and host['MemorySwap'] == 4294967296 and host['NanoCpus'] == 1000000000
    assert host['ReadonlyRootfs'] and host['PidsLimit'] == 128 and host['CapDrop'] == ['ALL']
    assert host['SecurityOpt'] == ['no-new-privileges']
    postgres_id = command('exact-postgres-id', ['docker', 'inspect', '--format', '{{.Id}}', 'freightctl-postgres-v1']).decode().strip()
    assert postgres_id == '754aca4bb7999e3601e18ece3b2be174319f734de4bae8349846c110ed4c2314'
    assert host['NetworkMode'] == 'container:' + postgres_id
    assert not host['PortBindings']
    assert any(m['Destination'] == '/var/lib/clamav' and not m['RW'] and m['Name'] == 'freightctl-clamav-standard-v154' for m in inspected['Mounts'])
    owned = True
    assert execute('kernel-caps', ['cat', '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/cpu.max']) == b'4294967296\n100000 100000\n'
    execute('bounded-daemon-readiness', ['/bin/sh', '-ec', 'for i in $(seq 1 30); do if test -S /freightctl/run/s; then exit 0; fi; sleep 1; done; exit 1'])
    execute('runtime-tools', ['/bin/sh', '-ec', 'uname -a; sha256sum /usr/sbin/clamd /freightctl/freightctl /freightctl/clamd.conf /var/lib/clamav/*.cvd; stat -c "%u:%g:%a" /freightctl/run /freightctl/run/s /freightctl/clamd.conf /var/lib/clamav /tmp/freightctl'])
    version = execute('observed-engine-version', ['clamdscan', '--config-file=/freightctl/clamd.conf', '--version']).decode().strip()
    assert version.startswith('ClamAV 1.5.4/28168/')
    now = datetime.now(timezone.utc)
    definition = {'schema_version': 1, 'kind': 'clamd-instream-v1', 'socket_reference': '/freightctl/run/s',
                  'configuration_reference': '/freightctl/clamd.conf', 'configuration_sha256': runtime['configuration_sha256'],
                  'expected_version': version, 'valid_until': (now + timedelta(hours=2)).isoformat(),
                  'max_bytes': 8 << 20, 'timeout_seconds': 10, 'max_result_age_seconds': 120}
    # Administrative enrollment stays on the host. The sandbox gets only the ordinary runtime role.
    tenant, partner = str(uuid.uuid4()), str(uuid.uuid4())
    identities = ((tenant, partner), (tenant, str(uuid.uuid4())), (str(uuid.uuid4()), str(uuid.uuid4())))
    bases = [f'https://127.0.0.1:29446/v1/tenants/{tid}/partners/{pid}' for tid, pid in identities]
    for index, (tid, pid) in enumerate(identities):
        token = private / ('identity-' + str(index) + '.token')
        command('token-' + str(index), [str(root / '.cache/freightctl'), 'token', '--token-file', str(token)])
        command('enroll-' + str(index), [str(root / '.cache/freightctl'), 'enroll', '--token-file', str(token), '--tenant', tid, '--partner', pid])
        if index == 0:
            write('protected-owner-token', '/freightctl/owner.token', token.read_bytes())
        write('protected-header-' + str(index), '/freightctl/identity-' + str(index) + '.headers', b'Authorization: Bearer ' + token.read_bytes() + b'\n')
    cli('generate-local-tls', 'dev-cert', '--cert', certificate, '--key', tls_key)
    port = 29446
    base = f'https://127.0.0.1:{port}/v1/tenants/{tenant}/partners/{partner}'
    server_log = (raw / 'application.log').open('wb')
    server = subprocess.Popen(['docker', 'exec', name, '/freightctl/freightctl', 'serve', '--dsn-file', '/freightctl/runtime.dsn', '--listen', f'127.0.0.1:{port}', '--storage', '/freightctl/custody', '--cert', certificate, '--key', tls_key], stdout=server_log, stderr=server_log)
    time.sleep(0.5)
    request = write('scanner-request', '/freightctl/scanner.json', json.dumps({'expected_version': 0, 'definition': definition}).encode())
    profile = call('register-observed-profile', 'scanner-register', '--request-file', request, '--idempotency-key', 'scanner')['resource']
    replay = call('profile-cli-replay', 'scanner-register', '--request-file', request, '--idempotency-key', 'scanner')
    assert replay['replayed'] and replay['resource'] == profile
    assert 'socket_reference' not in profile and 'configuration_reference' not in profile
    assert http('sanitized-profile', '/scanners/' + profile['id'] + '/1') == profile
    for index in (1, 2):
        http('foreign-profile-' + str(index), '/scanners/' + profile['id'] + '/1', expected=404, identity=index)
    policy = {'expected_version': 0, 'definition': {'schema_version': 1, 'kind': 'csv', 'columns': [
        {'name': 'account', 'type': 'text', 'required': True, 'max_bytes': 64},
        {'name': 'amount', 'type': 'decimal', 'required': True, 'max_bytes': 64, 'precision': 12, 'scale': 2},
        {'name': 'day', 'type': 'date', 'required': True, 'max_bytes': 10}],
        'max_bytes': 8 << 20, 'max_rows': 100000, 'max_record_bytes': 65536, 'timeout_seconds': 30,
        'scanner': {'id': profile['id'], 'version': 1, 'hash': profile['definition_hash']}}}
    registered_policy = http('required-policy', '/intake-policy', 'POST', policy, key='policy')['resource']
    clean_bytes = b'account,amount,day\n0001,1.01,2026-10-29\n'
    clean = upload('clean', clean_bytes)
    clean_check = scan('clean', clean, 'clean', 'valid_csv')
    http('clean-scan-still-needs-release', '/files/' + clean['id'], expected=409)
    decision = {'sha256': clean['sha256'], 'policy_hash': registered_policy['definition_hash'], 'report_hash': clean_check['report_hash'], 'expected_revision': clean_check['revision']}
    released = http('separate-release', '/checks/' + clean['id'] + '/release', 'POST', decision, key='release')
    assert http('release-replay', '/checks/' + clean['id'] + '/release', 'POST', decision, key='release')['resource'] == released['resource']
    assert http('independent-stock-curl-bytes', '/namespace/file?path=/clean.csv') == clean_bytes
    # Harmless standard test marker, assembled only in ignored runtime storage.
    marker = bytes.fromhex('58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a')
    assert len(marker) == 68 and digest(marker) == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    for label, body in (('eicar', marker), ('eicar-zip', zip_bytes([('test.txt', marker)])), ('eicar-nested', zip_bytes([('inner.zip', zip_bytes([('test.txt', marker)]))]))):
        file = upload(label, body)
        scan(label, file, 'detected', 'scanner_detected')
    malformed = upload('clean-invalid-csv', b'account,amount,day\n0001,not-money,2026-10-29\n')
    scan('clean-invalid-csv', malformed, 'clean', 'invalid_cell')
    many = upload('archive-file-limit', zip_bytes([(f'file-{i}.txt', b'harmless bounded test\n') for i in range(103)]))
    scan('archive-file-limit', many, 'blocked', 'scanner_blocked')
    deep = b'harmless bounded test\n'
    for level in range(7):
        deep = zip_bytes([(f'layer-{level}.zip', deep)])
    scan('archive-recursion-limit', upload('archive-recursion-limit', deep), 'blocked', 'scanner_blocked')
    expanded = zip_bytes([(f'part-{i}.txt', b'A' * (6 << 20)) for i in range(3)])
    scan('archive-expanded-limit', upload('archive-expanded-limit', expanded), 'blocked', 'scanner_blocked')
    harmless = private / 'harmless.txt'
    harmless.write_bytes(b'Harmless encrypted archive qualification fixture.\n')
    encrypted = private / 'encrypted.zip'
    command('stock-zip-encrypted-fixture', ['/usr/bin/zip', '-q', '-j', '-P', 'public-qualification-password', str(encrypted), str(harmless)])
    scan('encrypted-archive', upload('encrypted-archive', encrypted.read_bytes()), 'blocked', 'scanner_blocked')
    # Stop only the exact scanner PID. The application stays alive in its cgroup.
    offline = upload('scanner-timeout', clean_bytes)
    command('pause-exact-daemon', ['docker', 'kill', '--signal', 'STOP', name])
    paused = True
    assert http('fresh-released-proof-readable-during-outage', '/files/' + clean['id']) == clean_bytes
    began = time.monotonic()
    http('paused-engine-check', '/checks/' + offline['id'] + '/run', 'POST', key='paused')
    elapsed = time.monotonic() - began
    assert 9 <= elapsed < 20
    check = http('paused-engine-not-clean', '/checks/' + offline['id'])['check']
    assert check['state'] == 'failed' and check['code'] == 'scanner_unavailable' and not check['report_hash']
    http('paused-engine-held', '/files/' + offline['id'], expected=409)
    command('resume-exact-daemon', ['docker', 'kill', '--signal', 'CONT', name])
    paused = False
    # Current protected configuration is checked again at publication/read time.
    execute('configuration-tamper', ['/bin/sh', '-ec', "printf '# qualification change\\n' >> /freightctl/clamd.conf"])
    http('changed-configuration-denies-published-bytes', '/files/' + clean['id'], expected=409)
    write('restore-exact-configuration', '/freightctl/clamd.conf', (reference.parent / 'input/clamd.conf').read_bytes())
    assert http('restored-current-proof-byte-check', '/files/' + clean['id']) == clean_bytes
    http('revoke-profile', '/scanners/' + profile['id'] + '/1/revoke', 'POST', {'definition_hash': profile['definition_hash'], 'expected_revision': profile['revision']}, key='revoke')
    http('revoked-proof-denies-bytes', '/files/' + clean['id'], expected=409)
    state = 'passed'
except Exception:
    failure = traceback.format_exc()
finally:
    def cleanup(action):
        try:
            return action()
        except Exception:
            cleanup_failures.append(traceback.format_exc())
            return None
    if owned:
        if paused:
            cleanup(lambda: command('finally-resume-daemon', ['docker', 'kill', '--signal', 'CONT', name]))
        cleanup(lambda: execute('final-cgroup-observations', ['/bin/sh', '-ec', 'cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/cpu.stat; du -sk /tmp/freightctl; sha256sum /var/lib/clamav/*.cvd /freightctl/clamd.conf']))
        cleanup(lambda: command('daemon-final-log', ['docker', 'logs', name]))
        cleanup(lambda: command('stop-task-runtime', ['docker', 'stop', '--time', '10', name]))
        terminal = cleanup(lambda: command('terminal-inspect', ['docker', 'inspect', name]))
        if terminal:
            terminal_state = json.loads(terminal)[0]['State']
            if terminal_state['Running'] or terminal_state['OOMKilled']:
                cleanup_failures.append('Runtime still running or experienced OOM; inspect retained terminal state')
    if server is not None:
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            cleanup_failures.append('Application exec client failed to finish after runtime stop')
            server.terminate()
            cleanup(lambda: server.wait(timeout=5))
    if server_log:
        server_log.close()
    if cleanup_failures:
        state = 'failed'
ending_sources = sources()
manifest = {'schema_version': 1, 'state': state, 'failure': failure, 'observed_at': datetime.now(timezone.utc).isoformat(),
            'cleanup_failures': cleanup_failures,
            'starting_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
            'source_files': ending_sources, 'sources_unchanged_during_run': starting_sources == ending_sources,
            'runtime_reference': {'reference': str(reference.relative_to(root)), 'sha256': digest(reference.read_bytes())},
            'duration_seconds': round(time.monotonic() - started, 3), 'steps': steps,
            'scanner_engine_started': owned, 'standard_signature_database_loaded': owned,
            'local_model_processes_started': 0, 'inference_performed': False,
            'limits': ['Actual Linux/amd64 execution emulated on arm64 macOS; cross-build alone proves nothing. No native production platform qualified.',
                       'Only harmless standard marker and bounded synthetic archive/CSV cases; no general malware detection corpus, ICAP/DLP or full J02 qualification.',
                       'Shared scanner/application/curl kernel cgroup: 4 GiB memory and swap combined, one CPU. PostgreSQL and host observer are separate existing resources.',
                       'Protected socket/operator remain trusted. No model runtime, inference, shared Docker lifecycle change, publication or deployment.']}
if not manifest['sources_unchanged_during_run']:
    manifest['state'] = 'failed'
(raw / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
(root / '.private/scanner-real-journey-current').write_text(str(raw) + '\n')
print(raw / 'manifest.json', flush=True)
if failure:
    print(failure, flush=True)
raise SystemExit(0 if manifest['state'] == 'passed' else 1)
