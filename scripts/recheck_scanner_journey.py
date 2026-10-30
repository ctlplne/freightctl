"""Genuine scanner profile re-enrollment and governed checked revisions.

Only called from the explicitly authorized combined real-scanner qualifier.
No inference, feed-update, business-acceptance or production-platform claim.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from urllib.parse import urlencode


def qualify(e):
    h, c, request, ref = (e[k] for k in ('h', 'c', 'request', 'ref'))
    command, execute, cli = (e[k] for k in ('command', 'execute', 'cli'))
    root, private, raw, scope = (e[k] for k in ('root', 'private', 'raw', 'scope'))
    old_profile, source, unsafe = (e[k] for k in ('profile', 'source', 'unsafe'))
    original_source_check = h('recheck-original-source-snapshot', '/checks/' + source['id'])['check']
    original_detected_check = h('recheck-original-detection-snapshot', '/checks/' + unsafe['id'])['check']
    assert original_source_check['state'] == 'released'
    assert original_detected_check['state'] == 'rejected' and original_detected_check['code'] == 'scanner_detected'
    refreshed = dict(e['definition'], valid_until=(datetime.now(timezone.utc) + timedelta(hours=2)).isoformat())
    enrollment = {'scanner_id': old_profile['id'], 'expected_version': old_profile['version'], 'definition': refreshed}
    registered = c('recheck-enroll-observed-profile-version', 'scanner-register', '--request-file', request('recheck-profile', enrollment), '--idempotency-key', 'recheck-profile')
    profile = registered['resource']
    assert profile['id'] == old_profile['id'] and profile['version'] == old_profile['version'] + 1
    assert profile['expected_engine'] == old_profile['expected_engine']
    assert profile['configuration_sha256'] == old_profile['configuration_sha256']
    assert profile['definition_hash'] != old_profile['definition_hash']
    replay = c('recheck-profile-original-key-recovery', 'scanner-register', '--request-file', request('recheck-profile-replay', enrollment), '--idempotency-key', 'recheck-profile')
    assert replay['replayed'] and replay['resource'] == registered['resource']
    h('recheck-explicit-old-profile-revocation', '/scanners/' + old_profile['id'] + '/' + str(old_profile['version']) + '/revoke', method='POST', body=e['decision'](old_profile), key='recheck-revoke-old-profile')
    assert h('recheck-old-profile-stays-revoked', '/scanners/' + old_profile['id'] + '/' + str(old_profile['version']))['state'] == 'revoked'
    h('recheck-old-source-unavailable', '/files/' + source['id'], expected=409)
    # First retain the original marker signer. A fresh version/profile/check
    # must not launder an earlier genuine detection into clean content.
    policy = json.loads(json.dumps(e['policy']))
    policy['expected_version'] = 2
    policy['definition']['scanner'] = ref(profile)
    marker_policy = h('recheck-marker-current-policy', '/intake-policy', method='POST', body=policy, key='recheck-marker-policy')['resource']
    private_reason = 'SYNTHETIC_PRIVATE_RECHECK_REVIEW'

    def copy_revision(label, original, policy_view, target=''):
        options = {'target_path': target, 'signature_mode': 'reuse_exact', 'reason': private_reason + ' ' + label}
        preview = c(label + '-preview-cli', 'check-recheck-preview', '--file-id', original['id'], '--request-file', request(label + '-options', options))
        assert preview['plan']['policy'] == ref(policy_view)
        assert preview['plan']['source']['file'] == original
        assert preview['plan']['signature_mode'] == 'reuse_exact'
        before = h(label + '-source-before-copy', '/checks/' + original['id'])['check']
        saved = c(label + '-save-cli', 'check-recheck-propose', '--file-id', original['id'], '--request-file', request(label + '-plan', {'plan': preview['plan']}), '--idempotency-key', label + '-save')
        row = saved['resource']['recheck']
        again = h(label + '-save-api-replay', '/checks/' + original['id'] + '/rechecks', method='POST', body={'plan': preview['plan']}, key=label + '-save')
        assert again['replayed'] and again['resource'] == saved['resource']
        h(label + '-unapproved-copy-refused', '/rechecks/' + row['id'] + '/copy', method='POST', key=label + '-too-early', expected=409)
        approval = {'operation': 'approve', 'definition_hash': row['definition_hash'], 'expected_revision': row['revision']}
        approved = h(label + '-reviewed-approval', '/rechecks/' + row['id'] + '/decide', method='POST', body=approval, key=label + '-approve')['resource']['recheck']
        assert approved['state'] == 'approved' and approved['definition_hash'] == row['definition_hash']
        copied = c(label + '-copy-cli', 'check-recheck-copy', '--recheck-id', row['id'], '--idempotency-key', label + '-copy')
        replayed = h(label + '-copy-api-replay', '/rechecks/' + row['id'] + '/copy', method='POST', key=label + '-copy')
        assert replayed['replayed'] and replayed['resource'] == copied['resource']
        finished = copied['resource']['recheck']
        child = finished['result']['file']
        assert finished['state'] == 'copied' and finished['new_file_id'] == child['id'] != original['id']
        assert finished['definition_hash'] == row['definition_hash']
        assert child['sha256'] == original['sha256'] and child['size_bytes'] == original['size_bytes']
        assert child['policy'] == 'intake-csv-v1:' + policy_view['definition_hash']
        assert finished['result']['signature']['sha256'] == before['report']['signature']['sha256']
        assert finished['result']['signature']['object_id'] != before['report']['signature']['object_id']
        assert h(label + '-original-proof-preserved', '/checks/' + original['id'])['check'] == before
        pending = h(label + '-new-held-check', '/checks/' + child['id'])['check']
        assert pending['state'] == 'held' and pending['attempts'] == 0 and not pending['report_hash']
        h(label + '-copy-is-not-release', '/files/' + child['id'], expected=409)
        return finished, child

    marker_intent, marker_child = copy_revision('recheck-detected', unsafe, marker_policy)
    h('recheck-detected-run-fresh-genuine-scan', '/checks/' + marker_child['id'] + '/run', method='POST', key='recheck-detected-run')
    detected = h('recheck-detected-stays-rejected', '/checks/' + marker_child['id'])['check']
    assert detected['state'] == 'rejected' and detected['code'] == 'scanner_detected' and not detected['report_hash']
    assert detected['report']['scanner']['profile'] == ref(profile)
    assert detected['report']['scanner']['result']['verdict'] == 'detected'
    assert detected['report']['scanner']['result']['detection_sha256'] == hashlib.sha256(b'Eicar-Test-Signature').hexdigest()
    assert detected['report']['signature']['sha256'] == original_detected_check['report']['signature']['sha256']
    assert detected['report']['rows'] == 0
    h('recheck-detected-cannot-dispatch', '/workflow-runs', method='POST', body={'workflow': ref(e['workflow']), 'file_id': marker_child['id']}, key='recheck-detected-delivery', expected=409)
    h('recheck-detected-never-published', '/files/' + marker_child['id'], expected=409)
    # Restore the selected business signer in a new reviewed policy. No
    # signature/scanner requirement or age/processing bound is removed.
    policy['expected_version'] = 3
    policy['definition']['signature']['key'] = ref(e['signer'])
    selected_policy = h('recheck-business-current-policy', '/intake-policy', method='POST', body=policy, key='recheck-business-policy')['resource']
    clean_intent, child = copy_revision('recheck-business', source, selected_policy, '/business.csv')
    command('recheck-pause-exact-genuine-daemon', ['docker', 'kill', '--signal', 'STOP', e['e']['name']])
    paused = True
    try:
        h('recheck-unavailable-engine-is-not-clean', '/checks/' + child['id'] + '/run', method='POST', key='recheck-unavailable-run')
        unavailable = h('recheck-unavailable-child-held', '/checks/' + child['id'])['check']
        assert unavailable['state'] == 'failed' and unavailable['code'] == 'scanner_unavailable'
        assert unavailable['attempts'] == 1 and not unavailable['report_hash']
        assert unavailable['report']['signature']['verification']['primary_fingerprint'] == e['fingerprint']['good']
        h('recheck-unavailable-bytes-denied', '/files/' + child['id'], expected=409)
    finally:
        if paused:
            command('recheck-resume-exact-genuine-daemon', ['docker', 'kill', '--signal', 'CONT', e['e']['name']])
    checked = c('recheck-fresh-clean-worker', 'check-run', '--file-id', child['id'], '--idempotency-key', 'recheck-clean-run')
    repeated = h('recheck-fresh-clean-worker-replay', '/checks/' + child['id'] + '/run', method='POST', key='recheck-clean-run')
    assert repeated['replayed'] and repeated['resource'] == checked['resource']
    check = h('recheck-fresh-combined-proof', '/checks/' + child['id'])['check']
    assert check['state'] == 'passed' and check['attempts'] == 2 and check['report']['rows'] == 65536
    assert check['report']['scanner']['profile'] == ref(profile)
    assert check['report']['scanner']['result']['verdict'] == 'clean'
    assert check['report']['scanner']['result']['sha256'] == child['sha256']
    assert check['report']['scanner']['result']['configuration_sha256'] == profile['configuration_sha256']
    assert check['report']['signature']['verification']['signer_fingerprint'] == e['fingerprint']['subkey']
    h('recheck-passed-still-held', '/files/' + child['id'], expected=409)
    release = {'sha256': child['sha256'], 'policy_hash': check['policy_hash'], 'report_hash': check['report_hash'], 'expected_revision': check['revision']}
    h('recheck-separate-exact-release', '/checks/' + child['id'] + '/release', method='POST', body=release, key='recheck-child-release')
    assert h('recheck-conditional-path-now-child', '/namespace/file?' + urlencode({'path': '/business.csv'})) == e['data']
    h('recheck-original-raw-id-stays-denied', '/files/' + source['id'], expected=409)
    h('recheck-original-job-stays-policy-blocked', '/workflow-runs/' + e['queued_recheck_run']['id'], expected=409)
    h('recheck-original-job-cannot-follow-child', '/workflow-runs/' + e['queued_recheck_run']['id'] + '/work', method='POST', key='recheck-no-redirect', expected=409)
    preview = c('recheck-review-new-explicit-run', 'workflow-validate', '--request-file', request('recheck-run-preview', {'definition': e['workflow_definition'], 'file_id': child['id']}))
    assert not preview['external_contact'] and preview['effects'][0]['recipient_fingerprint'] == e['fingerprint']['recipient']
    run = h('recheck-start-new-reviewed-run', '/workflow-runs', method='POST', body={'workflow': ref(e['workflow']), 'file_id': child['id']}, key='recheck-new-run')['resource']
    done = h('recheck-deliver-new-revision', '/workflow-runs/' + run['id'] + '/work', method='POST', key='recheck-new-work')
    assert done['status']['run']['state'] == 'succeeded'
    assert done['status']['run']['file_id'] == child['id']
    cipher = done['status']['steps'][0]['ciphertext']
    assert cipher['source_sha256'] == child['sha256']
    target = e['inbox'] / (done['dispatch']['delivery_id'] + '-settlement.pgp')
    received = private / 'recheck-received.pgp'
    batch = private / 'recheck-receiver.batch'
    batch.write_text('get ' + str(target) + ' ' + str(received) + '\n')
    command('recheck-independent-stock-sftp', ['sftp', '-F', '/dev/null', '-P', str(e['receiver_port']), '-oBatchMode=yes', '-oStrictHostKeyChecking=yes', '-oUserKnownHostsFile=' + str(e['known']), '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-i', str(private / 'combined-client'), '-b', str(batch), e['user'] + '@127.0.0.1'])
    assert hashlib.sha256(received.read_bytes()).hexdigest() == cipher['sha256'] and received.read_bytes() != e['data']
    assert sorted(p.name for p in e['inbox'].iterdir()) == sorted([e['target'].name, target.name])
    signature = private / 'recheck-received.sig'
    signature.write_bytes(h('recheck-independent-signature-bytes', '/checks/' + child['id'] + '/signature'))
    assert signature.read_bytes() == (e['fixture'] / 'good.sig').read_bytes()
    plain = private / 'recheck-decrypted.csv'
    native = e['native']
    decrypted = command('recheck-independent-native-decrypt', [*native, '--metrics', str(raw / 'recheck-decrypt-metrics.json'), 'decrypt', '--key', str(e['fixture'] / 'recipient-private.gpg'), '--cipher', str(received), '--output', str(plain)])
    assert plain.read_bytes() == e['data'] and b'DECRYPTION_OKAY' in decrypted and b'GOODMDC' in decrypted
    verified = command('recheck-independent-native-signature', [*native, '--metrics', str(raw / 'recheck-signature-metrics.json'), 'verify', '--key', str(e['fixture'] / 'good-public.gpg'), '--signature', str(signature), '--source', str(plain)])
    assert b'VALIDSIG ' + e['fingerprint']['subkey'].upper().encode() in verified
    assert h('recheck-final-original-check-identical', '/checks/' + source['id'])['check'] == original_source_check
    assert h('recheck-final-original-detection-identical', '/checks/' + unsafe['id'])['check'] == original_detected_check
    # Verify the larger lineage audit independently, retaining the earlier
    # original exchange audit and its assertions unchanged.
    output = e['prefix'] + '/rechecks-audit.json'
    cli('recheck-signed-lineage-audit-export', 'audit-export', '--tenant', scope[0], '--partner', scope[1], '--token-file', e['token'], '--audit-key-file', e['audit_reference'], '--output', output)
    exported = private / 'rechecks-audit.json'
    exported.write_bytes(execute('recheck-audit-artifact', ['cat', output]))
    audit_proof = json.loads(command('recheck-independent-openssl-audit', ['python3', 'scripts/verify-audit.py', '--export', str(exported), '--trusted-key', str(e['audit_public']), '--tenant', scope[0], '--partner', scope[1]]))
    assert audit_proof['verified']
    payload = base64.b64decode(json.loads(exported.read_bytes())['payload_base64'], validate=True)
    audit = json.loads(payload)
    assert e['data'] not in payload and (e['marker'] / 'source.csv').read_bytes() not in payload
    assert private_reason.encode() not in payload
    events = audit['events']
    for intent, original, derived in [(marker_intent, unsafe, marker_child), (clean_intent, source, child)]:
        accepted = [x for x in events if x['kind'] == 'FileAccepted' and x['resource_id'] == derived['id']]
        assert len(accepted) == 1 and accepted[0]['payload']['recheck_id'] == intent['id']
        assert accepted[0]['payload']['source_file_id'] == original['id']
        assert accepted[0]['payload']['recheck_definition_hash'] == intent['definition_hash']
        changes = [x for x in events if x['kind'] == 'FileRecheckChanged' and x['resource_id'] == intent['id']]
        assert len(changes) == 3 and all(x['payload']['redacted'] for x in changes)
    releases = [x for x in events if x['kind'] == 'FileCheckChanged' and x['resource_id'] == child['id'] and x['payload']['state'] == 'released']
    assert len(releases) == 1 and releases[0]['payload']['report_hash'] == check['report_hash']
    assert releases[0]['payload']['report']['scanner']['profile'] == ref(profile)
    old_queued = [x for x in events if x['kind'] == 'WorkflowRunChanged' and x['resource_id'] == e['queued_recheck_run']['id']]
    assert len(old_queued) == 1 and old_queued[0]['payload']['file_id'] == source['id']
    assert any(x['kind'] == 'DeliveryCiphertextPrepared' and x['payload']['sha256'] == cipher['sha256'] for x in events)
    assert any(x['kind'] == 'DeliveryTransitioned' and x['resource_id'] == done['dispatch']['delivery_id'] and x['payload']['state'] == 'succeeded' for x in events)
    return {'state': 'passed', 'profile_before': ref(old_profile), 'profile_after': ref(profile), 'engine_and_database_unchanged': True, 'signature_feed_update_performed': False, 'clean_source_id': source['id'], 'clean_recheck_id': clean_intent['id'], 'clean_child_id': child['id'], 'clean_report_hash': check['report_hash'], 'detected_source_id': unsafe['id'], 'detected_recheck_id': marker_intent['id'], 'detected_child_id': marker_child['id'], 'new_detection_stays_held': True, 'old_checks_unchanged': True, 'original_job_not_redirected': True, 'new_explicit_run_id': run['id'], 'new_ciphertext': cipher, 'independent_plaintext_and_signature_match': True, 'audit_verification': audit_proof, 'audit_artifact_sha256': hashlib.sha256(exported.read_bytes()).hexdigest(), 'strongest_delivery_observation': done['status']['steps'][0]['observation'], 'business_acceptance': 'unknown'}
