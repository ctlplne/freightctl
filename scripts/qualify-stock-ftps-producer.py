#!/usr/bin/env python3
"""Run the independent read-only FTPS producer journey and verify its own evidence."""

from contextlib import ExitStack
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
PEER = ROOT / 'scripts/peers/stock-ftps-producer'
TEST = 'TestStockFTPSProducerToAgentAndSeparatelyApprovedStockSFTP'
PACKAGE = 'github.com/ctlplne/freightctl/internal/workflow'
BATCH = '00000000-0000-4000-8000-000000000509'
BODY = b'abc'
MANIFEST = 'settlement.ready.json'
FILE = 'one.csv'
CONTROL = 2121
STOCK = {
    'aarch64': ('arm64', 'edb450c4e263459666f6b2139b16793a6a6df040b21d531f00ac978da903c8ce',
                'ec3127316a53372ae3052cf3fa34c75108f2e391f2bfe49f49eb1c5cc0a86ce6'),
    'x86_64': ('amd64', 'd821bd6a3485c6330f381f8c0b8920f01114900bfae3575be0369902254f13ce',
               '1f9d7aa222c2cd571b659b08c26f435e64705adcfba6759d1acaefd0ab25f69b'),
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record_file(path):
    with path.open('rb') as stream:
        return {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'bytes': path.stat().st_size}


def check_postgres(private):
    endpoints = []
    for name in ('FREIGHTCTL_TEST_ADMIN_FILE', 'FREIGHTCTL_TEST_RUNTIME_FILE'):
        reference = Path(os.environ.get(name, ''))
        require(reference.is_file() and not reference.is_symlink() and reference.resolve().is_relative_to(private)
                and reference.stat().st_mode & 0o077 == 0, 'protected PostgreSQL references are required')
        with reference.open('rb') as stream:
            raw = stream.read(4097)
        require(0 < len(raw) <= 4096, 'invalid PostgreSQL reference size')
        dsn = urlsplit(raw.decode())
        require(dsn.scheme in ('postgres', 'postgresql') and dsn.hostname and dsn.port
                and ipaddress.ip_address(dsn.hostname).is_loopback and dsn.path.startswith('/')
                and dsn.query == 'sslmode=disable' and not dsn.fragment,
                'PostgreSQL must be on the task loopback endpoint')
        endpoints.append((dsn.hostname, dsn.port, dsn.path))
    require(endpoints[0] == endpoints[1], 'PostgreSQL references select different databases')


def command(directory, phase, args, *, timeout=20, expected=0, data=None, env=None):
    out = directory / (phase + '.stdout')
    err = directory / (phase + '.stderr')
    try:
        with out.open('xb') as stdout, err.open('xb') as stderr:
            process = subprocess.run(args, cwd=ROOT, input=data, stdout=stdout, stderr=stderr,
                                     env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError(phase + ' deadline exceeded') from None
    require(process.returncode == expected, f'{phase} exited {process.returncode}')
    return out, err


def reserve_ports():
    for _ in range(64):
        start = 49152 + secrets.randbelow(16379)
        ports = range(start, start + 6)
        try:
            with ExitStack() as held:
                for port in ports:
                    held.enter_context(socket.socket()).bind(('127.0.0.1', port))
                control = held.enter_context(socket.socket())
                control.bind(('127.0.0.1', 0))
                return control.getsockname()[1], ports.start, ports.stop - 1
        except OSError:
            continue
    raise RuntimeError('passive port range unavailable')


def fixture(directory, binary, mode, address):
    files = directory / 'fixture'
    inbox = files / 'inbox'
    inbox.mkdir(parents=True)
    published = {FILE: BODY, MANIFEST: json.dumps({
        'schema_version': 1, 'batch_id': BATCH,
        'files': [{'name': FILE, 'size_bytes': len(BODY), 'sha256': digest(BODY)}],
    }, separators=(',', ':')).encode()}
    for name, data in published.items():
        path = inbox / name
        path.write_bytes(data)
        path.chmod(0o444)
    secret = files / 'password'
    secret.write_text(secrets.token_hex(32))
    cert, key = files / 'producer.pem', files / 'producer.key'
    command(directory, 'dev-certificate', [binary, 'dev-cert', '--cert', cert, '--key', key])
    ref = directory / 'destination.json'
    ref.write_text(json.dumps({'address': address, 'server_name': 'localhost', 'mode': mode,
                               'user': 'ftp-source', 'ca_reference': str(cert),
                               'ca_sha256': digest(cert.read_bytes()), 'password_reference': str(secret),
                               'password_sha256': digest(secret.read_bytes())}))

    def root_owner(member):
        member.uid = member.gid = 0
        member.uname = member.gname = 'root'
        return member

    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        tar.add(files, arcname='fixture', filter=root_owner)
    return ref, published, archive.getvalue()


def ready(container):
    # Check the actual listener without adding a control session to its witness.
    for _ in range(30):
        check = subprocess.run(['docker', 'exec', container, 'awk',
                                f'$2 ~ /:{CONTROL:04X}$/ && $4 == "0A" {{found=1}} END {{exit !found}}',
                                '/proc/net/tcp'], capture_output=True, timeout=5, check=False)
        if check.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError('stock inetd did not become ready')


def verify_journeys(log, mode):
    events = [json.loads(row) for row in log.read_text().splitlines()]
    require(all(e.get('Action') not in ('fail', 'skip') for e in events), 'journey failed or skipped')
    passes = [e.get('Test') for e in events if e.get('Package') == PACKAGE and e.get('Action') == 'pass']
    require(passes == [TEST + '/' + mode, TEST] * 2 + [None], 'two exact journeys did not run')


def verify_source(archive, xferlog, native, published):
    require(archive.stat().st_size <= 16 << 10, 'unexpected producer archive size')
    with tarfile.open(archive, mode='r:') as tar:
        members = tar.getmembers()
        require(len(members) == 3 and {entry.name for entry in members} ==
                {'inbox', *(f'inbox/{name}' for name in published)}, 'unexpected producer file tree')
        require(tar.getmember('inbox').isdir(), 'producer inbox is no longer a directory')
        for name, body in published.items():
            member = tar.getmember(f'inbox/{name}')
            require(member.isfile() and member.mode == 0o444 and member.size == len(body),
                    'producer file permissions or length changed')
            with tar.extractfile(member) as stream:
                require(stream.read() == body, 'producer bytes changed')
    rows = [line.split() for line in xferlog.read_text().splitlines()]
    require(len(rows) == 4 and all(len(row) == 18 and row[9] == 'b'
                                   and row[11:15] == ['o', 'r', 'ftp-source', 'ftp'] and row[-1] == 'c'
                                   for row in rows), 'incomplete or unexpected producer transfers')
    require([(row[8], row[7]) for row in rows] ==
            [(f'/inbox/{name}', str(len(published[name]))) for name in (MANIFEST, FILE)] * 2,
            'producer transfer order, path or length changed')
    events = re.findall(r'\] (?:\[ftp-source\] )?([A-Z]+(?: [A-Z]+)?): ', native.read_text())
    require([e for e in events if e != 'DEBUG'] ==
            ['CONNECT', 'CONNECT', 'OK LOGIN', 'OK DOWNLOAD', 'OK DOWNLOAD',
             'CONNECT', 'OK LOGIN', 'OK DOWNLOAD', 'OK DOWNLOAD'], 'unexpected producer control events')


def verify_identity(path, native_arch, vsftpd, inetd):
    require(path.read_text().splitlines() == [native_arch, '3.24.4',
            f'{vsftpd}  /usr/sbin/vsftpd', f'{inetd}  /bin/busybox-extras'],
            'stock peer architecture or executable identity changed')


def worker_lifecycle(path):
    if not path.exists():
        return None
    with path.open('rb') as stream:
        data = stream.read(257)
    if len(data) > 256:
        return {'state': 'outside-evidence-bound'}
    starts, exits = 0, []
    for line in data.splitlines():
        if line == b'started':
            starts += 1
            continue
        result = re.fullmatch(rb'exit ([0-9]{1,3})', line)
        if not result or not 0 <= int(result[1]) <= 255 or len(exits) >= starts:
            return {'state': 'invalid-record'}
        exits.append(int(result[1]))
    return {'state': 'recorded', 'started': starts, 'exit_codes': exits}


def tls12_diagnosis(directory):
    stderr = directory / 'reject-tls12.stderr'
    if not stderr.exists():
        return None
    err = stderr.read_bytes().lower()
    clues = {
        'protocol-version-alert': (b'alert protocol version',),
        'unexpected-eof': (b'unexpected eof', b'unexpected end of file'),
        'connection-refused': (b'connection refused', b'errno=111', b'errno=61'),
        'connection-reset': (b'connection reset', b'errno=104', b'errno=54'),
        'ftp-upgrade-refused': (b"didn't find auth tls", b'ftp response'),
        'other-tls-alert': (b'alert handshake failure', b'alert internal error'),
    }
    matches = [name for name, tokens in clues.items() if any(token in err for token in tokens)]
    categories = matches or ['unclassified']
    native = directory / 'vsftpd.log'
    count = native.read_bytes().count(b'] CONNECT: ') if native.exists() else None
    return {'categories': categories, 'stock_control_connections': count,
            'client_hello_attempted': b'tls write client hello' in err,
            'stock_worker_lifecycle': worker_lifecycle(directory / 'worker.log')}


def remove_owned(kind, name, label, directory):
    field = {'container': '.Config.Labels', 'image': '.Config.Labels', 'network': '.Labels'}[kind]
    inspect = subprocess.run(['docker', kind, 'inspect', '--format', '{{index ' + field +
                              ' "freightctl.run"}}', name], capture_output=True, timeout=15, check=False)
    if inspect.returncode != 0:
        require(b'No such' in inspect.stderr or b'not found' in inspect.stderr, kind + ' inspection failed')
        return
    require(inspect.stdout.decode().strip() == label, kind + ' ownership changed')
    options = ['-f'] if kind == 'container' else []
    command(directory, 'remove-' + kind, ['docker', kind, 'rm', *options, name])


def replay(directory, image, label, mode, binary, native_arch, identities):
    directory.mkdir()
    container = 'freightctl-stock-ftps-' + label + '-' + mode
    network = container + '-net'
    mark = 'freightctl.run=' + label
    control, first, last = reserve_ports()
    address = f'127.0.0.1:{control}'
    ref, published, tar = fixture(directory, binary, mode, address)
    with ExitStack() as cleanup:
        cleanup.callback(remove_owned, 'network', network, label, directory)
        command(directory, 'network', ['docker', 'network', 'create', '--label', mark, network])
        cleanup.callback(remove_owned, 'container', container, label, directory)
        command(directory, 'create', ['docker', 'create', '--pull=never', '--name', container, '--label', mark,
                                      '--network', network, '--memory', '128m', '--cpus', '1', '--pids-limit', '48',
                                      '--cap-drop', 'ALL', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
                                      '--cap-add', 'SYS_CHROOT', '--security-opt', 'no-new-privileges',
                                      '--publish', f'{address}:{CONTROL}',
                                      '--publish', f'127.0.0.1:{first}-{last}:{first}-{last}',
                                      '--env', f'PRODUCER_MODE={mode}', '--env', f'PRODUCER_PASV_MIN={first}',
                                      '--env', f'PRODUCER_PASV_MAX={last}', image])
        command(directory, 'install-fixture', ['docker', 'cp', '-', container + ':/'], data=tar)
        command(directory, 'start', ['docker', 'start', container])
        try:
            ready(container)
            info, _ = command(directory, 'peer-identity', ['docker', 'exec', container, 'sh', '-ec',
                              'uname -m; cat /etc/alpine-release; sha256sum /usr/sbin/vsftpd /bin/busybox-extras'])
            verify_identity(info, native_arch, *identities)
            _, tls = command(directory, 'reject-tls12',
                             ['openssl', 's_client', '-connect', address, '-tls1_2', '-brief', '-state',
                              *(['-starttls', 'ftp'] if mode == 'explicit' else [])], expected=1, data=b'')
            require(b'alert protocol version' in tls.read_bytes(), 'producer did not reject TLS 1.2 by policy')
            env = {**os.environ, 'FREIGHTCTL_TEST_STOCK_FTPS_PRODUCER_FILE': str(ref)}
            journeys, _ = command(directory, 'journeys', ['sh', 'scripts/go.sh', 'test', '-json', '-race',
                                   '-tags=integration,stockftpsproducer', '-count=2', '-timeout=180s',
                                   '-run', f'^{TEST}$', './internal/workflow'], timeout=240, env=env)
            verify_journeys(journeys, mode)
            archive, _ = command(directory, 'producer-files', ['docker', 'cp', container + ':/producer/inbox', '-'])
            xferlog, native = directory / 'xfer.log', directory / 'vsftpd.log'
            worker = directory / 'worker.log'
            for log in (xferlog, native, worker):
                command(directory, 'copy-' + log.stem, ['docker', 'cp', f'{container}:/tmp/freightctl-{log.name}', log])
            verify_source(archive, xferlog, native, published)
            state, _ = command(directory, 'continuity', ['docker', 'inspect', '--format',
                               '{{.Id}} {{.State.Running}} {{.State.OOMKilled}} {{.RestartCount}}', container])
            created = (directory / 'create.stdout').read_text().strip()
            require(state.read_text().split() == [created, 'true', 'false', '0'], 'stock producer stopped or restarted')
            return {'journeys': 2, 'confirmed_downloads': 4, 'tls12_refused': True,
                    'unchanged_source': True, 'listener_restarts': 0,
                    'stock_worker_lifecycle': worker_lifecycle(worker),
                    'evidence': {p.name: record_file(p) for p in (info, tls, journeys, archive, xferlog, native, worker, state)}}
        finally:
            try:
                with (directory / 'container.log').open('xb') as log:
                    subprocess.run(['docker', 'logs', '--tail=50', container], stdout=log,
                                   stderr=subprocess.STDOUT, timeout=10, check=False)
            except subprocess.TimeoutExpired:
                pass
            for name in ('vsftpd.log', 'worker.log'):
                log = directory / name
                if log.exists():
                    continue
                try:
                    subprocess.run(['docker', 'cp', f'{container}:/tmp/freightctl-{name}', log],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                except subprocess.TimeoutExpired:
                    pass


def main():
    os.umask(0o077)
    private = ROOT / '.private'
    private.mkdir(exist_ok=True)
    require(not private.is_symlink() and private.is_dir() and private.stat().st_mode & 0o077 == 0,
            'a private workspace directory is required')
    directory = Path(tempfile.mkdtemp(prefix='freightctl-stock-ftps-', dir=private))
    label = secrets.token_hex(6)
    result = {'schema_version': 1, 'kind': 'freightctl-stock-ftps-producer-v1', 'state': 'failed', 'modes': {}}
    try:
        check_postgres(private)
        machine = platform.machine()
        host = platform.system()
        require(host in ('Linux', 'Darwin') and machine in (*STOCK, 'arm64'), 'unsupported qualification host')
        native_arch = 'aarch64' if machine == 'arm64' else machine
        arch, vsftpd, inetd = STOCK[native_arch]
        head, _ = command(directory, 'source', ['git', 'rev-parse', 'HEAD'])
        commit = head.read_text().strip()
        require(re.fullmatch('[0-9a-f]{40}', commit) and os.getenv('GITHUB_SHA', commit) == commit,
                'source does not match the qualification checkout')
        result.update(commit=commit, host=host, architecture=arch,
                      package_lock=record_file(PEER / (arch + '.sha256')), vsftpd_sha256=vsftpd, inetd_sha256=inetd)
        clients = {}
        for name, args in (('go', ['sh', 'scripts/go.sh', 'version']), ('curl', ['curl', '--version']),
                           ('ssh', ['ssh', '-V']), ('openssl', ['openssl', 'version'])):
            stdout, stderr = command(directory, name + '-version', args)
            clients[name] = record_file(stdout if stdout.stat().st_size else stderr)
        result['tool_versions'] = clients
        binary = directory / 'freightctl'
        command(directory, 'build-freightctl', ['sh', 'scripts/go.sh', 'build', '-trimpath', '-buildvcs=false',
                                               '-o', binary, './cmd/freightctl'], timeout=180)
        result['fixture_certificate_tool'] = record_file(binary)
        image = 'freightctl-stock-ftps-producer:' + label
        with ExitStack() as cleanup:
            cleanup.callback(remove_owned, 'image', image, label, directory)
            command(directory, 'build-peer', ['docker', 'build', '--platform', 'linux/' + arch, '--tag', image,
                    '--label', 'freightctl.run=' + label, '--progress=plain', PEER], timeout=240)
            info, _ = command(directory, 'image', ['docker', 'image', 'inspect', '--format',
                              '{{.Id}} {{.Os}} {{.Architecture}}', image])
            image_id, os_name, image_arch = info.read_text().split()
            require(re.fullmatch('sha256:[0-9a-f]{64}', image_id) and (os_name, image_arch) == ('linux', arch),
                    'producer image does not match the requested platform')
            result['image'] = image_id
            for mode in ('explicit', 'implicit'):
                result['modes'][mode] = replay(directory / mode, image, label, mode, binary, native_arch, (vsftpd, inetd))
        result['state'] = 'passed'
    except RuntimeError as err:
        result['failure'] = str(err)
    except (OSError, ValueError, tarfile.TarError, subprocess.TimeoutExpired) as err:
        result['failure'] = type(err).__name__
    finally:
        if result['state'] == 'failed':
            result['tls12_diagnosis'] = {mode: report for mode in ('explicit', 'implicit')
                                         if (report := tls12_diagnosis(directory / mode)) is not None}
            observations = {'build-peer.stdout', 'journeys.stdout', 'continuity.stdout', 'container.log', 'vsftpd.log', 'worker.log'}
            result['diagnostics'] = {str(p.relative_to(directory)): record_file(p) for p in sorted(directory.rglob('*'))
                                     if (p.suffix == '.stderr' or p.name in observations) and p.stat().st_size}
        payload = json.dumps(result, sort_keys=True)
        (directory / 'summary.json').write_text(payload + '\n')
        print(payload)
    return 0 if result['state'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
