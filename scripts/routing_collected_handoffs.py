"""Actual encrypted-key rotation through browser handoff and stock receivers."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import uuid


def qualify_collected_handoffs(g):
    post, command, browser = g['post'], g['command'], g['browser']
    invoke, write, owner, ref, decision = (g[k] for k in ('invoke', 'write', 'owner', 'ref', 'decision'))
    fixture = Path(command('handoff-independent-gpg-fixture', ['python3', 'scripts/prepare-pgp-fixture.py'], timeout=180).decode().strip())
    peer = json.loads((fixture / 'manifest.json').read_text())
    if peer.get('peer_backend') == 'native-macos':
        limits = peer['resource_limits']
        assert limits['sampled_child_rss_budget_bytes'] <= 128 << 20
        assert limits['sampled_process_family_peak_rss_bytes'] <= limits['sampled_child_rss_budget_bytes']
        assert limits['wall_seconds'] <= 120
    else:
        assert peer['resource_limits'] == {'memory_bytes': 128 << 20, 'cpus': 1, 'pids': 64, 'network': 'none'}
    keys = []
    for index, label in enumerate(('recipient', 'recipient-rsa')):
        body = {'expected_version': 0, 'purpose': 'encrypt', 'fingerprint': peer['fingerprints'][label],
                'public_key': base64.b64encode((fixture / (label + '-public.gpg')).read_bytes()).decode()}
        keys.append(post('handoff-recipient-' + str(index), '/pgp-keys', body, key='handoff-public-' + str(index))['resource'])
    source = copy.deepcopy(g['source_definition'])
    data = b'account,amount\n0042,19.00\n'
    name = 'handoff-payroll.csv'
    (g['producer'] / name).write_bytes(data)
    manifest = {'schema_version': 1, 'batch_id': str(uuid.uuid4()),
                'files': [{'name': name, 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]}
    (g['producer'] / source['manifest']).write_text(json.dumps(manifest))
    definition = {'schema_version': 2, 'name': 'Governed recipient key replacement', 'source': source,
                  'steps': [{'id': 'send', 'kind': 'sftp.deliver', 'connection': ref(g['destination']),
                             'filename': 'handoff-v1.pgp', 'encryption': {'key': ref(keys[0]), 'profile': 'seipd-v1-aes256'}}],
                  'program': {'nodes': [{'kind': 'deliver', 'step': 'send'}]}}
    workflow = post('handoff-original-workflow', '/workflows/drafts', {'expected_version': 0, 'definition': definition}, key='handoff-workflow')['resource']
    workflow = post('handoff-original-approval', '/workflows/' + workflow['id'] + '/1/approve', decision(workflow), key='handoff-workflow-approve')['resource']
    selection = {'workflow': ref(workflow), 'timeout_seconds': 300, 'expected_authority_revision': 1}
    preview = post('handoff-collection-preview', '/workflow-collections/preview', selection)
    queued = post('handoff-collection-start', '/workflow-collections', {'selection': selection, 'definition_hash': preview['definition_hash']}, key='handoff-collection')['resource']
    invoke('handoff-capture', 'workflow-collection-work', '--collection-id', queued['id'], '--request-file', write('handoff-capture', {'definition_hash': queued['definition_hash']}), '--idempotency-key', 'handoff-capture', token=owner)
    captured = post('handoff-captured', '/workflow-collections/' + queued['id'], method='GET')
    item = captured['inputs'][0]
    assert captured['job']['captured'] and len(captured['inputs']) == 1 and item['run_id'] is None
    invoke('handoff-check', 'check-run', '--file-id', item['file_id'], '--idempotency-key', 'handoff-check', token=owner)
    check = post('handoff-check-proof', '/checks/' + item['file_id'], method='GET')['check']
    assert check['state'] == 'passed' and check['report']['sha256'] == item['sha256']
    post('handoff-release', '/checks/' + item['file_id'] + '/release', {'sha256': item['sha256'], 'policy_hash': check['policy_hash'], 'report_hash': check['report_hash'], 'expected_revision': check['revision']}, key='handoff-release')
    post('handoff-queue-original', '/workflow-collections/' + queued['id'] + '/refresh', decision(captured['job']), key='handoff-admit')
    assigned = post('handoff-original-assignment', '/workflow-collections/' + queued['id'], method='GET')
    item = assigned['inputs'][0]
    old = post('handoff-original-run', '/workflow-runs/' + item['run_id'], method='GET')

    def approve_dispatch(label, delivery):
        effect = post(label + '-effect', '/outbound-deliveries/' + delivery, method='GET')
        choice = {'delivery_id': delivery, 'reviewer_id': g['reviewer'], **decision(effect)}
        preview = post(label + '-review-preview', '/outbound-dispatch-reviews/preview', choice)
        review = post(label + '-review-propose', '/outbound-dispatch-reviews', {'selection': choice, 'definition_hash': preview['definition_hash']}, key=label + '-propose')['resource']['review']
        post(label + '-review-approve', '/outbound-dispatch-reviews/' + review['id'] + '/approve', decision(review), key=label + '-approve', who=g['viewer_header'])

    approve_dispatch('handoff-old-consent', old['steps'][0]['delivery_id'])
    frozen = tuple(g['contacts'](n) for n in ('source', 'receiver', 'audit'))
    (g['producer'] / name).rename(g['producer'] / 'retired-handoff.csv')
    (g['producer'] / source['manifest']).unlink()
    post('handoff-revoke-old-recipient', '/pgp-keys/' + keys[0]['id'] + '/1/revoke', decision(keys[0]), key='handoff-key-revoke')
    post('handoff-revoked-old-work-refused', '/workflow-runs/' + item['run_id'] + '/work', key='handoff-old-work-refused', expected=409)
    updated = copy.deepcopy(definition)
    updated['steps'][0]['filename'] = 'handoff-v2.pgp'
    updated['steps'][0]['encryption']['key'] = ref(keys[1])
    target = post('handoff-replacement-workflow', '/workflows/drafts', {'workflow_id': workflow['id'], 'expected_version': 1, 'definition': updated}, key='handoff-workflow-v2')['resource']
    target = post('handoff-replacement-approval', '/workflows/' + target['id'] + '/2/approve', decision(target), key='handoff-workflow-v2-approve')['resource']
    assert tuple(g['contacts'](n) for n in ('source', 'receiver', 'audit')) == frozen
    choice = {'input_id': item['id'], 'source_run_id': item['run_id'], 'workflow': ref(target), 'expected_authority_revision': 1}
    counts = "SELECT (SELECT count(*) FROM events)||','||(SELECT count(*) FROM workflow_receipts)||','||(SELECT count(*) FROM workflow_runs)||','||(SELECT count(*) FROM delivery_intents)"
    before_preview = g['recorded_sql']('handoff-preview-counts-before', counts)
    prepared = post('handoff-http-preview', '/workflow-collections/' + assigned['job']['id'] + '/handoffs/preview', choice)
    cli_prepared = invoke('handoff-cli-preview', 'workflow-collection-handoff-preview', '--collection-id', assigned['job']['id'], '--request-file', write('handoff-selection', choice), token=owner)
    assert prepared == cli_prepared and not prepared['external_contact'] and prepared['approval_required']
    assert g['recorded_sql']('handoff-preview-counts-after', counts) == before_preview
    governed = browser('handoff-govern', job=assigned['job'], handoff_input_id=item['id'], handoff_target=target)
    h, next_run = governed['handoff'], governed['runs'][0]
    assert h['state'] == 'completed' and next_run['run']['id'] == h['planned_run_id']
    assert governed['view']['job'] == assigned['job'] and governed['view']['inputs'] == assigned['inputs']
    assert next_run['run']['source'] == old['run']['source']
    assert next_run['run']['execution_plan']['facts'] == old['run']['execution_plan']['facts']
    assert len(next_run['steps']) == 1 and next_run['steps'][0]['attempts'] == 0
    post('handoff-new-run-needs-new-consent', '/workflow-runs/' + next_run['run']['id'] + '/work', key='handoff-new-work-refused', expected=409)
    effect = post('handoff-new-effect', '/outbound-deliveries/' + next_run['steps'][0]['delivery_id'], method='GET')
    assert effect['attempts'] == 0 and not effect['current_approval']
    assert tuple(g['contacts'](n) for n in ('source', 'receiver', 'audit')) == frozen
    approve_dispatch('handoff-new-consent', next_run['steps'][0]['delivery_id'])
    before_files = {p.name for p in g['inbox'].iterdir()}
    completed = browser('send-handoff', job=assigned['job'], target_file_id=item['file_id'], target_step='send', audit_send=True)
    assert completed['runs'][0]['run']['id'] == next_run['run']['id'] and completed['runs'][0]['observed_state'] == 'succeeded'
    assert g['contacts']('source') == frozen[0]
    target_file = g['inbox'] / (next_run['steps'][0]['delivery_id'] + '-handoff-v2.pgp')
    assert {p.name for p in g['inbox'].iterdir()} == before_files | {target_file.name}
    cipher = g['private'] / 'handoff-cipher.pgp'
    g['stock']('handoff-stock-retrieval', g['receiver_port'], g['destination_known'], f'get {target_file} {cipher}\n', 'receiver')
    assert cipher.read_bytes() != data and data not in cipher.read_bytes()
    assert not (g['inbox'] / (old['steps'][0]['delivery_id'] + '-handoff-v1.pgp')).exists()
    plain = g['private'] / 'handoff-plain.csv'
    if peer.get('peer_backend') == 'native-macos':
        command('handoff-independent-decrypt', ['python3', 'scripts/pgp-native-peer.py', '--config', os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'], '--metrics', str(g['raw'] / 'handoff-decryption-metrics.json'), 'decrypt', '--key', str(fixture / 'recipient-rsa-private.gpg'), '--cipher', str(cipher), '--output', str(plain)])
    else:
        assert peer['peer_platform'] == 'linux/amd64' and peer['peer_image'].startswith('sha256:')
        program = 'mkdir -m 700 /tmp/gpg; : > /tmp/gpg/common.conf; gpg --homedir /tmp/gpg --batch --import /fixture/recipient-rsa-private.gpg; gpg --homedir /tmp/gpg --batch --status-fd 1 --output /result/handoff-plain.csv --decrypt /result/handoff-cipher.pgp'
        status = command('handoff-independent-decrypt', ['docker', 'run', '--rm', '--name', 'freightctl-handoff-decrypt-' + uuid.uuid4().hex, '--label', 'freightctl.workspace=' + str(g['root']), '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=128m', '--cpus=1', '--pids-limit=64', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--user', str(os.getuid()) + ':' + str(os.getgid()), '-v', str(fixture) + ':/fixture:ro', '-v', str(g['private']) + ':/result', peer['peer_image'], '/bin/sh', '-ec', program])
        assert b'[GNUPG:] DECRYPTION_OKAY' in status and b'[GNUPG:] GOODMDC' in status
    assert plain.read_bytes() == data
    final = post('handoff-final-original-assignment', '/workflow-collections/' + assigned['job']['id'], method='GET')
    assert final['job'] == assigned['job'] and final['inputs'] == assigned['inputs']
    assert final['replacements'][0]['current_run_id'] == next_run['run']['id']
    return {'state': 'passed', 'browser_saved_propose_approve_execute_receipts_after_reload': True,
            'browser_withdrawal_preserves_work': True, 'original_job_input_and_facts_unchanged': True,
            'new_key_requires_new_workflow_handoff_and_independent_dispatch_consent': True,
            'stock_ciphertext_decrypted_by_independent_gnupg': True, 'verified_stock_outputs': 1,
            'source_not_recontacted_after_capture': True, 'inference_performed': False, 'scanner_engine_started': False}
