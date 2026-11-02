"""Real checked-file revocation across captured corrected-routing boundaries."""
import copy
import hashlib
import json
import uuid


def qualify_intake_revocation(g):
    post, invoke, write = g['post'], g['invoke'], g['write']
    decision, ref = g['decision'], g['ref']
    contacts, sql = g['contacts'], g['recorded_sql']
    producer, owner = g['producer'], g['owner']
    original = g['workflow']
    captures = []
    for index in range(2):
        label = 'intake-routing-' + str(index)
        name = 'north-intake-revocation-' + str(index) + '.csv'
        data = ('account,amount\n00' + str(index) + '1,42.00\n').encode()
        digest = hashlib.sha256(data).hexdigest()
        (producer / name).write_bytes(data)
        manifest = {'schema_version': 1, 'batch_id': str(uuid.uuid4()),
                    'files': [{'name': name, 'size_bytes': len(data), 'sha256': digest}]}
        (producer / 'settlement.ready.json').write_text(json.dumps(manifest))
        selection = dict(g['selection'], workflow=ref(original))
        preview = post(label + '-collection-preview', '/workflow-collections/preview', selection)
        queued = post(label + '-collection-start', '/workflow-collections',
                      {'selection': selection, 'definition_hash': preview['definition_hash']},
                      key=label + '-capture')['resource']
        invoke(label + '-source-work', 'workflow-collection-work', '--collection-id', queued['id'],
               '--request-file', write(label + '-source-request', {'definition_hash': queued['definition_hash']}),
               '--idempotency-key', label + '-source-work', token=owner)
        captured = post(label + '-captured', '/workflow-collections/' + queued['id'], method='GET')
        assert captured['job']['captured'] and len(captured['inputs']) == 1
        item = captured['inputs'][0]
        assert item['run_id'] is None and item['sha256'] == digest
        invoke(label + '-check', 'check-run', '--file-id', item['file_id'],
               '--idempotency-key', label + '-check', token=owner)
        check = post(label + '-check-proof', '/checks/' + item['file_id'], method='GET')['check']
        assert check['state'] == 'passed' and check['policy_hash'] == g['policy']['definition_hash']
        assert check['report']['sha256'] == digest
        release = {'sha256': digest, 'policy_hash': check['policy_hash'],
                   'report_hash': check['report_hash'], 'expected_revision': check['revision']}
        post(label + '-release', '/checks/' + item['file_id'] + '/release', release, key=label + '-release')
        current = post(label + '-released-proof', '/checks/' + item['file_id'], method='GET')
        assert current['current'] and current['check']['state'] == 'released'
        captures.append((label, captured, item))

    captured_contacts = tuple(contacts(name) for name in ('source', 'receiver', 'audit'))
    def receiver_files():
        result = {}
        for peer in ('inbox', 'audit_inbox'):
            paths = sorted(g[peer].iterdir())
            assert all(p.is_file() and not p.is_symlink() for p in paths)
            result[peer] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        return result
    original_receivers = receiver_files()

    # Correct both frozen batches only after they exist. The target changes
    # north to south while preserving the exact source and recipient catalog.
    definition = copy.deepcopy(g['definition'])
    branch = definition['program']['nodes'][0]
    branch['then'], branch['else'][0]['then'] = branch['else'][0]['then'], branch['then']
    target = post('intake-routing-corrected-draft', '/workflows/drafts',
                  {'workflow_id': original['id'], 'expected_version': original['version'], 'definition': definition},
                  key='intake-routing-corrected-draft')['resource']
    target = post('intake-routing-corrected-approve', '/workflows/' + target['id'] + '/' + str(target['version']) + '/approve',
                  decision(target), key='intake-routing-corrected-approve')['resource']
    assert target['version'] == original['version'] + 1
    assert target['definition']['source'] == original['definition']['source']
    assert target['definition']['steps'] == original['definition']['steps']
    deliveries = []
    for index, (label, captured, item) in enumerate(captures):
        base = '/workflow-collections/' + captured['job']['id']
        selection = {'collection': decision(captured['job']), 'workflow': ref(target), 'expected_authority_revision': 1}
        preview = post(label + '-routing-preview', base + '/routing/preview', selection)
        plan = post(label + '-input-preview', base + '/routing/inputs/' + item['id'] + '/preview', selection)
        assert plan['execution_plan']['selected_steps'] == ['south'] and not plan['external_contact']
        proposal = post(label + '-routing-propose', base + '/routing/proposals',
                        {'selection': selection, 'definition_hash': preview['definition_hash']},
                        key=label + '-routing-propose')['resource']
        approved = post(label + '-routing-approve', base + '/routing/' + proposal['id'] + '/approve',
                        decision(proposal), key=label + '-routing-approve')['resource']
        assert approved['state'] == 'approved'
        ready = post(label + '-ready-before-revocation', base, method='GET')
        assert ready['current_authority'] and all(s['state'] == 'published' for s in ready['local_states'])
        if index == 0:
            continue
        post(label + '-queue-corrected', base + '/refresh', decision(captured['job']), key=label + '-queue')
        view = post(label + '-queued', base, method='GET')
        assert view['job'] == captured['job'] and len(view['inputs']) == 1
        status = post(label + '-run', '/workflow-runs/' + view['inputs'][0]['run_id'], method='GET')
        assert status['run']['routing_authorization_id'] == approved['id']
        assert status['run']['workflow_version'] == target['version'] and status['run']['workflow_hash'] == target['definition_hash']
        assert len(status['steps']) == 1 and status['steps'][0]['id'] == 'south'
        delivery = status['steps'][0]['delivery_id']
        effect = post(label + '-delivery', '/outbound-deliveries/' + delivery, method='GET')
        choice = {'delivery_id': delivery, 'reviewer_id': g['reviewer'], **decision(effect)}
        review_preview = post(label + '-dispatch-preview', '/outbound-dispatch-reviews/preview', choice)
        review = post(label + '-dispatch-propose', '/outbound-dispatch-reviews',
                      {'selection': choice, 'definition_hash': review_preview['definition_hash']},
                      key=label + '-dispatch-propose')['resource']['review']
        post(label + '-dispatch-approve', '/outbound-dispatch-reviews/' + review['id'] + '/approve',
             decision(review), key=label + '-dispatch-approve', who=g['viewer_header'])
        effect = post(label + '-consent-current', '/outbound-deliveries/' + delivery, method='GET')
        assert effect['current_approval'] and effect['attempts'] == 0
        deliveries.append((label, status['run']['id'], delivery))

    before_contacts = tuple(contacts(name) for name in ('source', 'receiver', 'audit'))
    assert before_contacts == captured_contacts
    counts = "SELECT (SELECT count(*) FROM workflow_runs)||','||(SELECT count(*) FROM delivery_intents)||','||(SELECT coalesce(sum(attempts),0) FROM delivery_intents)"
    before_counts = sql('intake-routing-before-counts', counts)
    policy = g['policy']
    post('intake-routing-revoke-policy', '/intake-policy/revoke',
         {'definition_hash': policy['definition_hash'], 'expected_version': policy['version'], 'expected_revision': policy['revision']},
         key='intake-routing-revoke-policy')
    for index, (label, captured, item) in enumerate(captures):
        base = '/workflow-collections/' + captured['job']['id']
        check = post(label + '-stale-check', '/checks/' + item['file_id'], method='GET')
        assert not check['current'] and check['check']['state'] == 'released'
        post(label + '-download-refused', '/files/' + item['file_id'], method='GET', expected=409)
        ready = post(label + '-not-ready', base, method='GET')
        assert all(s['state'] == 'held_or_unavailable' for s in ready['local_states'])
        # Ordinary refresh may record a waiting receipt. It must not create a
        # run or reinterpret the captured job while the required check is stale.
        post(label + '-refresh-after-revoke', base + '/refresh', decision(captured['job']), key=label + '-refresh-after-revoke')
        after = post(label + '-unchanged-capture', base, method='GET')
        assert after['job'] == captured['job']
        if index == 0:
            assert after['inputs'] == captured['inputs'] and after['inputs'][0]['run_id'] is None
        else:
            assert after['inputs'][0]['run_id'] == deliveries[0][1]
    for label, run, delivery in deliveries:
        denied = post(label + '-work-refused', '/workflow-runs/' + run + '/work', key=label + '-work-refused', expected=409)
        assert denied['error'] in ('operation_state_conflict', 'collection_authority_input_or_lease_required')
        # Delivery metadata also requires current file access. Preserve its
        # refusal and independently inspect the untouched durable intent.
        denied_view = post(label + '-delivery-metadata-refused', '/outbound-deliveries/' + delivery, method='GET', expected=409)
        assert denied_view['error'] == 'operation_state_conflict'
        assert str(uuid.UUID(delivery)) == delivery
        tenant, partner = str(uuid.UUID(g['tenant'])), str(uuid.UUID(g['partner']))
        retained = sql(label + '-retained-consent-zero-attempts',
                       "SELECT d.attempts::text||','||(SELECT count(*) FROM outbound_dispatch_reviews r WHERE (r.tenant_id,r.partner_id,r.delivery_id)=(d.tenant_id,d.partner_id,d.delivery_id) AND r.state='approved') FROM delivery_intents d WHERE (d.tenant_id,d.partner_id,d.delivery_id)=('" + tenant + "'::uuid,'" + partner + "'::uuid,'" + delivery + "'::uuid)")
        assert retained == '0,1'
    assert sql('intake-routing-after-counts', counts) == before_counts
    assert tuple(contacts(name) for name in ('source', 'receiver', 'audit')) == before_contacts
    assert receiver_files() == original_receivers
    return {'state': 'passed', 'captured_batches': 2, 'corrected_version': target['version'],
            'released_checks_stale_after_revocation': True, 'waiting_input_not_admitted': True,
            'queued_preapproved_effect_zero_attempts': True, 'captured_jobs_unchanged': True,
            'no_contact_after_revocation': True, 'inference_performed': False, 'scanner_engine_started': False}
