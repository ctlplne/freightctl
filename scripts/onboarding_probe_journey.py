"""Extend the owned workflow fixture with actual read-only SFTP probes.

No model, scanner engine, shared service lifecycle or non-fixture resources.
The original workflow and independent receiver assertions still run afterward.
"""
from pathlib import Path
import json
import os
import signal
import subprocess
import time
import uuid


def exercise(e):
    root, private, raw = e['root'], e['private'], e['raw']
    invoke, post, get, write, ref = (e[k] for k in ('invoke', 'post', 'get', 'write', 'ref'))
    tenant, partner, connection = (e[k] for k in ('tenant', 'partner', 'connection'))
    contact, requirement, plan_id = (str(uuid.uuid4()) for _ in range(3))
    definition = {'schema_version': 1, 'name': 'Native receiver onboarding', 'contacts': [{'id': contact, 'name': 'Synthetic operations', 'role': 'Transfer support', 'email': 'operations@freightctl.invalid', 'phone': ''}], 'requirements': [{'id': requirement, 'name': 'Registered SFTP receiver', 'contact_id': contact, 'direction': 'send', 'protocol': 'sftp', 'required_receipt': 'business', 'receipt_contract': 'Independent business acknowledgment remains required', 'notes': 'Probe cannot establish this business contract.'}]}
    command = {'plan_id': plan_id, 'expected_version': 0, 'expected_authority_revision': 1, 'definition': definition}
    plan = invoke('probe-record-requirements', 'partner-onboarding-save', '--request-file', write('probe-plan', command), '--idempotency-key', 'probe-plan')['plan']
    initial_files = sorted(p.name for p in e['inbox'].iterdir())
    config = {'root': str(root), 'private': str(private), 'raw': str(raw), 'url': f"https://127.0.0.1:{e['http_port']}", 'certificate': str(e['cert']), 'tenant': tenant, 'partner': partner, 'identities': [{'tenant': tenant, 'partner': partner, 'token': str(e['owner'])}], 'probe_plan': plan, 'probe_connection': connection}
    cfg = write('probe-browser', config)
    node = os.environ.get('FREIGHTCTL_NODE_BIN') or e['command'](['which', 'node']).decode().strip()
    env = dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='192MiB', NODE_OPTIONS='--max-old-space-size=192', PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
    browser = subprocess.run([node, 'scripts/browser-journey.mjs', str(cfg), 'probes'], stdout=(raw/'native-onboarding-probes.log').open('wb'), stderr=subprocess.STDOUT, timeout=100, env=env)
    assert browser.returncode == 0, 'native probe journey failed; inspect retained output and screenshot'
    observed = json.loads((private/'probe-browser-observations.json').read_text())
    assert observed['state'] == 'succeeded' and observed['start_requests'] == 2 and observed['work_requests'] == 3
    result = get('probe-native-result', '/onboarding-probes/' + observed['probe_id'])
    assert result['probe']['state'] == 'succeeded' and result['current_bindings'] and result['evidence_strength'] == 'connectivity_only'
    assert not result['file_exchange_performed'] and not result['production_active']
    assert e['sql'](f"SELECT count(*) FROM events WHERE tenant_id='{tenant}' AND resource_id='{observed['probe_id']}' AND kind='OnboardingProbeChanged'").strip() == b'3'
    assert (raw/'receiver.log').read_text().count('Accepted publickey for ') == 1, 'receipt recovery repeated SSH contact'
    invoke('probe-cli-history', 'partner-onboarding-probe-list', '--onboarding-id', plan_id)

    def request(c, p=plan):
        return {'plan': ref(p), 'requirement_id': requirement, 'connection': ref(c), 'expected_authority_revision': 1}

    def start(label, c, p=plan):
        return post(label, '/onboarding-probes', request(c, p), key=label)['resource']

    def work(label, p, key=None):
        return post(label, '/onboarding-probes/' + p['id'] + '/work', {'definition_hash': p['definition_hash']}, key=key or label)

    post('probe-invented-endpoint-refused', '/onboarding-probes', dict(request(connection), endpoint='https://untrusted.invalid'), 400, key='probe-invented')
    post('probe-invented-success-refused', '/onboarding-probes', dict(request(connection), succeeded=True), 400, key='probe-invented-result')
    post('probe-duplicate-keys-refused', '/onboarding-probes', b'{"plan":{},"plan":{}}', 400, key='probe-duplicate')
    other_header = private/'probe-other.headers'
    other_header.write_bytes(b'Authorization: Bearer ' + e['other'].read_bytes() + b'\n')
    get('probe-other-actor-refused', '/onboarding-probes/' + observed['probe_id'], expected=404, who=other_header)
    post('probe-cross-partner-refused', '/onboarding-probes', request(connection), 401, key='probe-cross', scope_ids=(tenant, str(uuid.uuid4())))

    variants = [
        ('wrong-host', {'host_public_file': str(private/'other-host.pub')}, 'connection_failed'),
        ('wrong-login-key', {'key_file': str(private/'other-host'), 'key_public_file': str(private/'other-host.pub')}, 'connection_failed'),
        ('missing-directory', {'directory': str(private/'missing-probe-directory')}, 'directory_unavailable'),
    ]
    link = private/'probe-directory-link'
    link.symlink_to(e['inbox'], target_is_directory=True)
    variants.append(('linked-directory', {'directory': str(link)}, 'directory_unavailable'))
    for label, changes, code in variants:
        c = invoke('probe-register-' + label, 'connection-register', '--request-file', write('probe-' + label, dict(e['conn_request'], **changes)), '--idempotency-key', 'probe-register-' + label)['resource']
        p = start('probe-start-' + label, c)
        v = work('probe-work-' + label, p)
        assert v['probe']['state'] == 'failed' and v['probe']['observation']['code'] == code and not v['file_exchange_performed']
        assert work('probe-recover-' + label, p, key='probe-work-' + label)['probe'] == v['probe']
    c = invoke('probe-register-revocation', 'connection-register', '--request-file', write('probe-revocation-connection', e['conn_request']), '--idempotency-key', 'probe-register-revocation')['resource']
    p = start('probe-start-revocation', c)
    post('probe-revoke-before-contact', '/connections/' + c['id'] + '/1/revoke', e['decision'](c), key='probe-revoke-connection')
    assert work('probe-work-revoked', p)['probe']['state'] == 'blocked'

    # Kill only the exact task-owned CLI worker while the task-owned SSH master
    # is stopped. TCP can connect, but authentication cannot finish before kill.
    p = start('probe-start-worker-death', connection)
    receiver = e['servers']['receiver']
    assert receiver.poll() is None
    os.kill(receiver.pid, signal.SIGSTOP)
    worker = None
    try:
        with (raw/'probe-killed-worker.stdout').open('wb') as out, (raw/'probe-killed-worker.stderr').open('wb') as err:
            worker = subprocess.Popen(e['args']('partner-onboarding-probe-work', '--onboarding-probe-id', p['id'], '--definition-hash', p['definition_hash'], '--idempotency-key', 'probe-killed-worker'), stdout=out, stderr=err, start_new_session=True)
            e['children'].append(worker)
            deadline = time.monotonic() + 4
            while e['sql'](f"SELECT state FROM onboarding_probes WHERE tenant_id='{tenant}' AND probe_id='{p['id']}'").strip() != b'running':
                assert worker.poll() is None and time.monotonic() < deadline, 'probe claim did not become durable before kill'
                time.sleep(.02)
            os.killpg(worker.pid, signal.SIGKILL)
            worker.wait(timeout=5)
            assert worker.returncode == -signal.SIGKILL
    finally:
        os.kill(receiver.pid, signal.SIGCONT)
        if worker is not None and worker.poll() is None:
            os.killpg(worker.pid, signal.SIGKILL)
            worker.wait(timeout=5)
    wait_started = time.monotonic()
    while e['sql'](f"SELECT clock_timestamp()>=lease_until FROM onboarding_probes WHERE tenant_id='{tenant}' AND probe_id='{p['id']}'").strip() != b't':
        assert time.monotonic() - wait_started < 25, 'unchanged production probe lease failed to expire'
        time.sleep(.25)
    accepted_before = (raw/'receiver.log').read_text().count('Accepted publickey for ')
    expired = work('probe-dead-worker-expiry', p, key='probe-killed-worker')
    assert expired['probe']['state'] == 'expired' and expired['probe']['observation']['code'] == 'lease_expired'
    assert (raw/'receiver.log').read_text().count('Accepted publickey for ') == accepted_before
    e['steps'].append({'name': 'actual-probe-worker-killed-and-original-lease-expired', 'pid': worker.pid, 'exit_code': worker.returncode, 'lease_seconds': 20, 'wait_seconds': round(time.monotonic()-wait_started, 3), 'new_contact_on_recovery': False})
    stale = start('probe-start-before-plan-edit', connection)
    command['expected_version'] = 1
    command['definition']['name'] = 'Current native onboarding review'
    invoke('probe-edit-plan', 'partner-onboarding-save', '--request-file', write('probe-plan-v2', command), '--idempotency-key', 'probe-plan-v2')
    assert work('probe-stale-plan-refused', stale)['probe']['state'] == 'blocked'
    assert not get('probe-historical-success-is-not-current', '/onboarding-probes/' + observed['probe_id'])['current_bindings']
    assert sorted(p.name for p in e['inbox'].iterdir()) == initial_files
    e['steps'].append({'name': 'read-only-probes-preserve-receiver-files-and-separate-business-evidence', 'native_browser': 'probes-result.json', 'probe_id': observed['probe_id'], 'file_exchange_performed': False, 'production_active': False, 'inference_performed': False})
