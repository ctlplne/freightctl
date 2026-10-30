"""Assisted combined signed/scanned/encrypted exchange; no production launcher.

Only called by the explicit resource-authorized real scanner qualification.
Private GnuPG keys stay with the independent native peer. The bounded socat
fixture forwards opaque SSH bytes, with the ordinary receiver host pin intact.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from urllib.parse import urlencode
import uuid


def qualify(e, peer_reference, marker_reference):
    root, private, raw = e['root'], e['private'], e['raw']
    command, execute, write, cli = e['command'], e['execute'], e['write'], e['cli']
    fixtures = []
    for reference in (peer_reference, marker_reference):
        path = (root / reference).resolve()
        assert path.is_relative_to(root / '.private') and path.name == 'manifest.json'
        manifest = json.loads(path.read_text())
        assert manifest['state'] == 'passed' and manifest['peer_backend'] == 'native-macos'
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(manifest['observed_at'])).total_seconds()
        assert 0 <= age < 2700, 'Refresh synthetic signer fixtures; do not relax signature age'
        for item in manifest['files']:
            assert hashlib.sha256((root / item['path']).read_bytes()).hexdigest() == item['sha256']
        fixtures.append((path.parent, manifest))
    fixture, peer = fixtures[0]
    marker, marker_peer = fixtures[1]
    data = (fixture / 'source.csv').read_bytes()
    assert data == b'account,amount,day\n' + b'00000001,100.01,2026-10-28\n' * 65536
    assert hashlib.sha256((marker / 'source.csv').read_bytes()).hexdigest() == '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    fingerprint = peer['fingerprints']
    scope = (str(uuid.uuid4()), str(uuid.uuid4()))
    prefix = '/freightctl/combined-' + uuid.uuid4().hex[:10]
    execute('combined-private-directory', ['mkdir', '-m', '700', prefix])
    owner = private / 'combined-owner.token'
    command('combined-token', [str(root / '.cache/freightctl'), 'token', '--token-file', str(owner)])
    command('combined-enroll', [str(root / '.cache/freightctl'), 'enroll', '--tenant', scope[0], '--partner', scope[1], '--token-file', str(owner)])
    token = write('combined-token-reference', prefix + '/owner.token', owner.read_bytes())
    write('combined-header-reference', '/freightctl/identity-3.headers', b'Authorization: Bearer ' + owner.read_bytes() + b'\n')
    e['bases'].append('https://127.0.0.1:29448/v1/tenants/' + scope[0] + '/partners/' + scope[1])
    def h(label, route, **kwargs):
        return e['http']('combined-' + label, route, identity=3, **kwargs)
    def c(label, operation, *args):
        return json.loads(cli('combined-' + label, operation, '--tenant', scope[0], '--partner', scope[1], '--token-file', token, '--storage', '/freightctl/custody', *args))
    def request(label, body):
        return write('combined-request-' + label, prefix + '/' + label + '.json', json.dumps(body).encode())
    def ref(resource):
        return {'id': resource['id'], 'version': resource['version'], 'hash': resource['definition_hash']}
    def decision(resource):
        return {'definition_hash': resource['definition_hash'], 'expected_revision': resource['revision']}
    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]
    receiver = None
    receiver_log = (raw / 'combined-receiver.log').open('ab')
    api = relay = None
    api_log = (raw / 'combined-application.log').open('ab')
    relay_log = (raw / 'combined-relay.log').open('ab')
    paused = False
    def start_receiver():
        nonlocal receiver
        receiver = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)], stdout=receiver_log, stderr=receiver_log, start_new_session=True)
        for _ in range(100):
            if receiver.poll() is not None:
                raise RuntimeError('Exact combined receiver exited; inspect retained log')
            try:
                with socket.create_connection(('127.0.0.1', receiver_port), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        raise RuntimeError('Exact receiver did not become ready')
    def stop_receiver():
        nonlocal receiver
        if receiver and receiver.poll() is None:
            os.killpg(receiver.pid, signal.SIGTERM)
            try:
                receiver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(receiver.pid, signal.SIGKILL)
                receiver.wait(timeout=5)
        receiver = None
    def start_api():
        nonlocal api
        api = subprocess.Popen(['docker', 'exec', e['name'], '/bin/sh', '-ec', 'umask 077; echo $$ > ' + prefix + '/api.pid; exec /freightctl/freightctl serve --dsn-file /freightctl/runtime.dsn --listen 127.0.0.1:29448 --storage /freightctl/custody --cert ' + e['certificate'] + ' --key ' + e['tls_key']], stdout=api_log, stderr=api_log)
        time.sleep(.5)
        assert api.poll() is None
    def start_relay():
        nonlocal relay
        # Four children and 30 seconds of inactivity; all processes remain in
        # the already verified 4 GiB/one CPU/PID-limited scanner cgroup.
        relay = subprocess.Popen(['docker', 'exec', e['name'], '/usr/bin/env', 'LD_LIBRARY_PATH=/freightctl/transport-root/usr/lib:/freightctl/transport-root/lib', '/freightctl/transport-root/lib/ld-musl-x86_64.so.1', '/freightctl/transport-root/usr/bin/socat', '-d', '-d', '-T30', 'TCP4-LISTEN:29447,bind=127.0.0.1,reuseaddr,fork,max-children=4', 'TCP4:host.docker.internal:' + str(receiver_port) + ',connect-timeout=3'], stdout=relay_log, stderr=relay_log)
        time.sleep(.5)
        assert relay.poll() is None
    try:
        inbox = private / 'combined-inbox'
        inbox.mkdir(mode=0o700)
        for label in ('combined-host', 'combined-client'):
            command(label + '-keygen', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(private / label)])
        (private / 'combined-authorized-keys').write_bytes((private / 'combined-client.pub').read_bytes())
        user = command('combined-receiver-os-account', ['id', '-un']).decode().strip()
        receiver_port = free_port()
        config = private / 'combined-sshd.conf'
        config.write_text(f'''Port {receiver_port}
ListenAddress 127.0.0.1
HostKey {private/'combined-host'}
PidFile {private/'combined-sshd.pid'}
AuthorizedKeysFile {private/'combined-authorized-keys'}
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
PermitRootLogin no
AllowUsers {user}
StrictModes yes
PermitTTY no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
Subsystem sftp internal-sftp
ForceCommand internal-sftp -d {inbox}
LogLevel VERBOSE
''')
        start_receiver()
        start_api()
        start_relay()
        execute('combined-transport-version-and-hash', ['/bin/sh', '-ec', 'LD_LIBRARY_PATH=/freightctl/transport-root/usr/lib:/freightctl/transport-root/lib /freightctl/transport-root/lib/ld-musl-x86_64.so.1 /freightctl/transport-root/usr/bin/socat -V; sha256sum /freightctl/transport-root/usr/bin/socat; cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max'])
        definition = dict(e['definition'], valid_until=(datetime.now(timezone.utc) + timedelta(hours=2)).isoformat())
        profile = c('profile', 'scanner-register', '--request-file', request('profile', {'expected_version': 0, 'definition': definition}), '--idempotency-key', 'combined-profile')['resource']
        def enroll_key(label, directory, manifest, purpose=None):
            body = {'expected_version': 0, 'fingerprint': manifest['fingerprints'][label], 'public_key': base64.b64encode((directory / (label + '-public.gpg')).read_bytes()).decode()}
            if purpose:
                body['purpose'] = purpose
            return h('key-' + label + ('-marker' if directory == marker else ''), '/pgp-keys', method='POST', body=body, key='key-' + label + ('-marker' if directory == marker else ''))['resource']
        signer = enroll_key('good', fixture, peer)
        recipient = enroll_key('recipient', fixture, peer, 'encrypt')
        policy = {'expected_version': 0, 'definition': dict(e['policy']['definition'])}
        policy['definition']['scanner'] = ref(profile)
        policy['definition']['signature'] = {'key': ref(signer), 'max_age_seconds': 3600}
        # Original F023 column bound is64; the fixed business fixture fits it.
        policy_view = h('required-signature-and-scanner-policy', '/intake-policy', method='POST', body=policy, key='both-policy')['resource']
        def upload(label, body):
            result = h(label, '/namespace/file?' + urlencode({'path': '/' + label + '.csv'}), method='PUT', body=body, expected=201, key=label)
            assert result['acceptance'] == 'durable-held-pending-checks-and-release'
            file = result['file']
            assert file['sha256'] == hashlib.sha256(body).hexdigest() and file['size_bytes'] == len(body)
            h(label + '-held', '/files/' + file['id'], expected=409)
            return file
        def attach(label, file, wire):
            check = h(label + '-before-attach', '/checks/' + file['id'])['check']
            return h(label, '/checks/' + file['id'] + '/signature', method='PUT', body=wire, key=label, headers=['--header', 'If-Check-Revision: ' + str(check['revision']), '--header', 'X-Data-SHA256: ' + file['sha256'], '--header', 'X-Policy-Hash: ' + check['policy_hash']])
        source = upload('business', data)
        h('missing-signature-cannot-run', '/checks/' + source['id'] + '/run', method='POST', key='missing-signature', expected=409)
        assert h('missing-signature-spends-no-attempt', '/checks/' + source['id'])['check']['attempts'] == 0
        attach('exact-source-signature', source, (fixture / 'good.sig').read_bytes())
        original = c('check-cli', 'check-run', '--file-id', source['id'], '--idempotency-key', 'check')
        replay = h('check-api-replay', '/checks/' + source['id'] + '/run', method='POST', key='check')
        assert replay['replayed'] and replay['resource'] == original['resource']
        check = h('combined-proof', '/checks/' + source['id'])['check']
        report = check['report']
        assert check['state'] == 'passed' and report['rows'] == 65536
        assert report['signature']['verification']['primary_fingerprint'] == fingerprint['good']
        assert report['signature']['verification']['signer_fingerprint'] == fingerprint['subkey']
        assert report['scanner']['profile'] == ref(profile) and report['scanner']['result']['verdict'] == 'clean'
        assert report['scanner']['result']['sha256'] == source['sha256']
        h('passed-still-held', '/files/' + source['id'], expected=409)
        release = {'sha256': source['sha256'], 'policy_hash': policy_view['definition_hash'], 'report_hash': check['report_hash'], 'expected_revision': check['revision']}
        h('reviewed-release', '/checks/' + source['id'] + '/release', method='POST', body=release, key='release')
        assert h('released-byte-verification', '/files/' + source['id']) == data
        paths = {label: write('combined-copy-' + label, prefix + '/' + label, (private / label).read_bytes()) for label in ('combined-host.pub', 'combined-client', 'combined-client.pub')}
        connection = c('registered-pinned-receiver', 'connection-register', '--request-file', request('connection', {'expected_version': 0, 'address': '127.0.0.1:29447', 'user': user, 'directory': str(inbox), 'host_public_file': paths['combined-host.pub'], 'key_file': paths['combined-client'], 'key_public_file': paths['combined-client.pub']}), '--idempotency-key', 'connection')['resource']
        workflow_definition = {'schema_version': 1, 'name': 'signed scanned encrypted settlement', 'steps': [{'id': 'send', 'kind': 'sftp.deliver', 'connection': ref(connection), 'filename': 'settlement.pgp', 'encryption': {'key': ref(recipient), 'profile': 'seipd-v1-aes256'}}]}
        preview = c('review-effect', 'workflow-validate', '--request-file', request('preview', {'definition': workflow_definition, 'file_id': source['id']}))
        assert not preview['external_contact'] and preview['effects'][0]['recipient_fingerprint'] == fingerprint['recipient']
        draft = h('workflow-draft', '/workflows/drafts', method='POST', body={'expected_version': 0, 'definition': workflow_definition}, key='draft')['resource']
        workflow = h('approve-exact-workflow', '/workflows/' + draft['id'] + '/1/approve', method='POST', body=decision(draft), key='approve')['resource']
        run = h('start-approved-run', '/workflow-runs', method='POST', body={'workflow': ref(workflow), 'file_id': source['id']}, key='run')['resource']
        stop_receiver()
        prepared = h('receiver-outage-prepares-only-ciphertext', '/workflow-runs/' + run['id'] + '/work', method='POST', key='work')
        assert prepared['status']['steps'][0]['state'] == 'retry'
        cipher = prepared['status']['steps'][0]['ciphertext']
        assert cipher['source_sha256'] == source['sha256'] and cipher['proof']['primary_fingerprint'] == fingerprint['recipient']
        execute('combined-before-restart-cgroup', ['cat', '/sys/fs/cgroup/memory.current', '/sys/fs/cgroup/memory.peak', '/sys/fs/cgroup/memory.events'])
        command('combined-stop-exact-runtime', ['docker', 'stop', '--time', '10', e['name']])
        api.wait(timeout=15)
        relay.wait(timeout=15)
        command('combined-start-same-runtime', ['docker', 'start', e['name']])
        execute('combined-restarted-kernel-caps-and-readiness', ['/bin/sh', '-ec', 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max; for i in $(seq 1 30); do if test -S /freightctl/run/s; then exit 0; fi; sleep 1; done; exit 1'])
        assert execute('combined-restarted-observed-version', ['clamdscan', '--config-file=/freightctl/clamd.conf', '--version']).decode().strip() == definition['expected_version']
        start_api()
        start_relay()
        assert h('original-ciphertext-after-restart', '/workflow-runs/' + run['id'])['steps'][0]['ciphertext'] == cipher
        start_receiver()
        intent = c('original-retry-deadline', 'delivery-status', '--delivery-id', prepared['dispatch']['delivery_id'])
        remaining = max(0, datetime.fromisoformat(intent['next_at'].replace('Z', '+00:00')).timestamp() - time.time())
        assert remaining < 30
        if remaining:
            time.sleep(remaining + .1)
        done = h('dispatch-original-ciphertext', '/workflow-runs/' + run['id'] + '/work', method='POST', key='work')
        assert done['replayed'] and done['dispatch'] == prepared['dispatch'] and done['status']['run']['state'] == 'succeeded'
        assert done['status']['steps'][0]['ciphertext'] == cipher
        known = private / 'combined-known-hosts'
        known.write_text(f'[127.0.0.1]:{receiver_port} ' + (private / 'combined-host.pub').read_text())
        target = inbox / (done['dispatch']['delivery_id'] + '-settlement.pgp')
        received = private / 'combined-received.pgp'
        batch = private / 'combined-retrieve.batch'
        batch.write_text(f'get {target} {received}\n')
        command('combined-independent-stock-sftp-retrieval', ['sftp', '-F', '/dev/null', '-P', str(receiver_port), '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oUserKnownHostsFile=' + str(known), '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-i', str(private / 'combined-client'), '-b', str(batch), user + '@127.0.0.1'])
        assert received.read_bytes() != data and hashlib.sha256(received.read_bytes()).hexdigest() == cipher['sha256']
        assert sorted(x.name for x in inbox.iterdir()) == [target.name]
        signature = private / 'combined-received.sig'
        signature.write_bytes(h('independent-signature-retrieval', '/checks/' + source['id'] + '/signature'))
        assert signature.read_bytes() == (fixture / 'good.sig').read_bytes()
        plain = private / 'combined-decrypted.csv'
        native = ['python3', 'scripts/pgp-native-peer.py', '--config', str(root / '.private/freightctl-gnupg-native.json')]
        decrypt = command('combined-independent-native-decrypt', [*native, '--metrics', str(raw / 'combined-native-decrypt-metrics.json'), 'decrypt', '--key', str(fixture / 'recipient-private.gpg'), '--cipher', str(received), '--output', str(plain)])
        assert plain.read_bytes() == data and b'DECRYPTION_OKAY' in decrypt and b'GOODMDC' in decrypt
        verification = command('combined-independent-native-verify', [*native, '--metrics', str(raw / 'combined-native-verify-metrics.json'), 'verify', '--key', str(fixture / 'good-public.gpg'), '--signature', str(signature), '--source', str(plain)])
        assert b'VALIDSIG ' + fingerprint['subkey'].upper().encode() in verification
        queued_recheck_run = h('freeze-original-queued-run', '/workflow-runs', method='POST', body={'workflow': ref(workflow), 'file_id': source['id']}, key='queued-original-recheck')['resource']
        # Invalid signature is rejected before any scanner contact, even while
        # the genuine daemon cannot answer. The ten-second scan timeout stays.
        wrong = upload('wrong-signer', data)
        attach('wrong-sidecar', wrong, (fixture / 'other.sig').read_bytes())
        command('combined-pause-exact-daemon', ['docker', 'kill', '--signal', 'STOP', e['name']])
        paused = True
        began = time.monotonic()
        h('wrong-signer-before-unavailable-scanner', '/checks/' + wrong['id'] + '/run', method='POST', key='wrong-check')
        assert time.monotonic() - began < 5
        refused = h('wrong-signature-verdict', '/checks/' + wrong['id'])['check']
        assert refused['state'] == 'rejected' and refused['code'] == 'signature_invalid' and 'scanner' not in refused['report']
        command('combined-resume-exact-daemon', ['docker', 'kill', '--signal', 'CONT', e['name']])
        paused = False
        marker_signer = enroll_key('good', marker, marker_peer)
        policy['expected_version'] = 1
        policy['definition']['signature']['key'] = ref(marker_signer)
        h('explicit-marker-test-policy', '/intake-policy', method='POST', body=policy, key='marker-policy')
        unsafe = upload('valid-signature-detected-marker', (marker / 'source.csv').read_bytes())
        attach('valid-marker-signature', unsafe, (marker / 'good.sig').read_bytes())
        h('signed-marker-scan', '/checks/' + unsafe['id'] + '/run', method='POST', key='marker-check')
        detected = h('signed-marker-remains-rejected', '/checks/' + unsafe['id'])['check']
        assert detected['state'] == 'rejected' and detected['code'] == 'scanner_detected' and not detected['report_hash']
        assert detected['report']['signature']['verification']['primary_fingerprint'] == marker_peer['fingerprints']['good']
        assert detected['report']['scanner']['result']['verdict'] == 'detected'
        assert detected['report']['scanner']['result']['detection_sha256'] == hashlib.sha256(b'Eicar-Test-Signature').hexdigest()
        assert detected['report']['rows'] == 0
        h('signed-marker-cannot-start-delivery', '/workflow-runs', method='POST', body={'workflow': ref(workflow), 'file_id': unsafe['id']}, key='unsafe-run', expected=409)
        h('signed-marker-bytes-held', '/files/' + unsafe['id'], expected=409)
        audit_key, audit_public = private / 'combined-audit.key', private / 'combined-audit.pub'
        command('combined-audit-signing-identity', [str(root / '.cache/freightctl'), 'audit-keygen', '--audit-key-file', str(audit_key), '--audit-public-file', str(audit_public)])
        audit_reference = write('combined-audit-protected-key', prefix + '/audit.key', audit_key.read_bytes())
        cli('combined-signed-audit-export', 'audit-export', '--tenant', scope[0], '--partner', scope[1], '--token-file', token, '--audit-key-file', audit_reference, '--output', prefix + '/audit.json')
        exported = private / 'combined-audit.json'
        exported.write_bytes(execute('combined-audit-artifact', ['cat', prefix + '/audit.json']))
        audit_verification = json.loads(command('combined-independent-openssl-audit', ['python3', 'scripts/verify-audit.py', '--export', str(exported), '--trusted-key', str(audit_public), '--tenant', scope[0], '--partner', scope[1]]))
        assert audit_verification['verified']
        payload = base64.b64decode(json.loads(exported.read_bytes())['payload_base64'], validate=True)
        audit = json.loads(payload)
        assert data not in payload and (marker / 'source.csv').read_bytes() not in payload
        events = audit['events']
        assert any(x['resource_id'] == source['id'] and x['kind'] == 'FileAccepted' and x['payload']['sha256'] == source['sha256'] for x in events)
        released_events = [x for x in events if x['resource_id'] == source['id'] and x['kind'] == 'FileCheckChanged' and x['payload']['state'] == 'released']
        assert len(released_events) == 1
        assert released_events[0]['payload']['report_hash'] == check['report_hash']
        assert released_events[0]['payload']['report']['scanner']['profile'] == ref(profile)
        assert released_events[0]['payload']['report']['signature']['verification']['signer_fingerprint'] == fingerprint['subkey']
        assert any(x['kind'] == 'DeliveryCiphertextPrepared' and x['payload']['sha256'] == cipher['sha256'] for x in events)
        delivered_events = [x for x in events if x['resource_id'] == done['dispatch']['delivery_id'] and x['kind'] == 'DeliveryTransitioned' and x['payload']['state'] == 'succeeded']
        assert len(delivered_events) == 1 and delivered_events[0]['payload']['observation'] == done['status']['steps'][0]['observation']
        assert any(x['resource_id'] == run['id'] and x['kind'] == 'WorkflowRunChanged' and x['payload']['state'] == 'succeeded' for x in events)
        assert any(x['resource_id'] == unsafe['id'] and x['kind'] == 'FileCheckChanged' and x['payload']['code'] == 'scanner_detected' for x in events)
        audit_proof = {'verification': audit_verification, 'release_event_id': released_events[0]['id'], 'delivery_event_id': delivered_events[0]['id'], 'snapshot_sha256': hashlib.sha256(exported.read_bytes()).hexdigest()}
        from recheck_scanner_journey import qualify as qualify_rechecks
        recheck_qualification = qualify_rechecks(locals())
        return {'state': 'passed', 'governed_rechecks': recheck_qualification, 'source_size': len(data), 'source_sha256': source['sha256'], 'file_id': source['id'], 'check_report_hash': check['report_hash'], 'scanner_profile': ref(profile), 'signer': ref(signer), 'recipient': ref(recipient), 'workflow': ref(workflow), 'run_id': run['id'], 'ciphertext': cipher, 'delivery_observation': done['status']['steps'][0]['observation'], 'same_ciphertext_after_restart': True, 'independent_decrypted_source_match': True, 'independent_signature_verified': True, 'signed_marker_rejected': True, 'invalid_signature_precedes_scanner': True, 'receiver': 'separate native stock OpenSSH daemon/filesystem and stock SFTP client on macOS; actual Linux app uses bounded opaque SSH relay', 'peer_manifests': [str((path / 'manifest.json').relative_to(root)) for path, _ in fixtures], 'native_scanner_versions_before_and_after_restart_equal': True, 'general_business_receipt': False, 'signed_audit': audit_proof}
    finally:
        if paused:
            command('combined-finally-resume-daemon', ['docker', 'kill', '--signal', 'CONT', e['name']])
        stop_receiver()
        receiver_log.close()
        # Remote API/relay exec processes finish when the parent's exact
        # runtime cleanup stops the container. Do not kill unrelated PIDs.
        e['combined_exec_clients'].extend(x for x in (api, relay) if x is not None)
        api_log.close()
        relay_log.close()
