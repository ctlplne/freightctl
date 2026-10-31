"""Native pre-publication crash recovery; exact parent-owned fixtures only."""
import json, os, signal, subprocess, time


def prepare_prepublication(c, h):
    post, production = h['post'], h['production']
    raw, private = c['raw'], c['private']
    preview, original = production('prepublication-staged-production', h['release'], h['req'], h['accepted'])
    status = post('prepublication-initial-status', '/onboarding-production/' + original['run']['id'], method='GET')
    delivery = status['status']['steps'][0]['delivery_id']
    c['sql']("CREATE FUNCTION freightctl_prepublication_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='" + delivery + "' AND NEW.state='publishing' THEN PERFORM pg_sleep(8); END IF; RETURN NEW; END $$; CREATE TRIGGER freightctl_prepublication_barrier BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_prepublication_barrier()")
    args = [c['binary'], 'workflow-work', '--dsn-file', c['runtime'], '--tenant', c['tenant'], '--partner', c['partner'], '--storage', c['storage'], '--token-file', h['owner'], '--run-id', original['run']['id'], '--idempotency-key', 'prepublication-killed-worker']
    out, err = raw / 'prepublication-killed-worker.stdout', raw / 'prepublication-killed-worker.stderr'
    started = time.monotonic()
    with out.open('wb') as stdout, err.open('wb') as stderr:
        child = subprocess.Popen(list(map(str, args)), stdout=stdout, stderr=stderr, env=c['env'], start_new_session=True)
        c['servers']['prepublication-worker'] = child
        deadline = time.monotonic() + 12
        while c['sql']("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='freightctl' AND wait_event='PgSleep' AND query LIKE 'UPDATE delivery_intents%')") != 't':
            assert child.poll() is None and time.monotonic() < deadline, 'worker did not reach exact pre-publication transaction boundary'
            time.sleep(.03)
        before = post('prepublication-before-kill', '/onboarding-production/' + original['run']['id'], method='GET')
        step = before['status']['steps'][0]
        partial = c['inbox'] / ('.freightctl-' + delivery + '-1.partial')
        assert step['state'] == 'staging' and step['attempts'] == 1 and step['ciphertext'] and partial.is_file()
        assert c['sha'](partial) == step['ciphertext']['sha256']
        assert not (c['inbox'] / (delivery + '-handoff-data.bin')).exists()
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
        assert child.returncode == -signal.SIGKILL
        c['servers'].pop('prepublication-worker')
    c['steps'].append({'name': 'prepublication-killed-worker', 'command': list(map(str, args)), 'exit_code': child.returncode, 'expected_exit_code': -signal.SIGKILL, 'duration_seconds': round(time.monotonic()-started, 3), 'stdout_sha256': c['sha'](out), 'stderr_sha256': c['sha'](err)})
    # DDL waits for only this exact fixture transaction to roll back. The
    # production 30-second lease is retained, not shortened or forged expired.
    c['sql']('DROP TRIGGER freightctl_prepublication_barrier ON delivery_intents; DROP FUNCTION freightctl_prepublication_barrier()')
    after = post('prepublication-after-kill', '/onboarding-production/' + original['run']['id'], method='GET')
    assert after['status']['steps'][0]['state'] == 'staging' and after['status']['steps'][0]['ciphertext'] == step['ciphertext']
    assert c['sql']("SELECT count(*) FROM events WHERE resource_id='" + delivery + "' AND kind='DeliveryTransitioned' AND payload->>'state' IN ('publishing','ambiguous','succeeded')") == '0'

    # A separate real final publication with a failed local receipt must remain
    # ineligible, even after its old lease expires and trust rotates.
    _, uncertain = production('prepublication-uncertain-production', h['release'], h['req'], h['accepted'])
    uncertain_status = post('prepublication-uncertain-status', '/onboarding-production/' + uncertain['run']['id'], method='GET')
    uncertain_id = uncertain_status['status']['steps'][0]['delivery_id']
    c['sql']("CREATE FUNCTION freightctl_prepublication_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='" + uncertain_id + "' AND NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned receipt unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER freightctl_prepublication_receipt_failure BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_prepublication_receipt_failure()")
    try:
        post('prepublication-real-ambiguous-receipt', '/workflow-runs/' + uncertain['run']['id'] + '/work', key='prepublication-uncertain-worker', expected=503)
    finally:
        c['sql']('DROP TRIGGER freightctl_prepublication_receipt_failure ON delivery_intents; DROP FUNCTION freightctl_prepublication_receipt_failure()')
    uncertain_status = post('prepublication-published-without-receipt', '/onboarding-production/' + uncertain['run']['id'], method='GET')
    uncertain_step = uncertain_status['status']['steps'][0]
    assert uncertain_step['state'] == 'publishing' and uncertain_step['attempts'] == 1
    final = c['inbox'] / (uncertain_id + '-handoff-data.bin')
    assert final.is_file() and c['sha'](final) == uncertain_step['ciphertext']['sha256']
    return dict(original=original, preview=preview, before=before, delivery=delivery, partial=partial, ciphertext=step['ciphertext'], uncertain=uncertain, uncertain_id=uncertain_id, uncertain_ciphertext=uncertain_step['ciphertext'])


def qualify_prepublication(c, h, prepared):
    post, invoke, write, command, receive = (h[x] for x in ('post','invoke','write','command','receive'))
    raw, inbox = c['raw'], c['inbox']
    target, child = h['target'], h['child']
    selection = dict(h['selection'], source_run_id=prepared['original']['run']['id'], source_hash=prepared['original']['dispatch']['definition_hash'], profile='prepublication-production-handoff-v1')
    deadline = time.monotonic() + 35
    while c['sql']("SELECT lease_until<=clock_timestamp() FROM delivery_intents WHERE delivery_id='" + prepared['delivery'] + "'") != 't':
        assert time.monotonic() < deadline, 'original lease did not expire'
        time.sleep(.1)
    post('prepublication-default-still-refuses-attempt', '/onboarding-handoffs/preview', {k:v for k,v in selection.items() if k!='profile'}, expected=409)
    preview = post('prepublication-exact-preview', '/onboarding-handoffs/preview', selection)
    proof = preview['definition']['prepublication_proof']
    assert preview['definition']['source']['state'] == 'staging' and preview['definition']['source']['attempts'] == 1
    assert proof['transitions'] == preview['definition']['source']['delivery']['revision'] and proof['ciphertext']['object_id'] == prepared['ciphertext']['object_id'] and proof['ciphertext']['sha256'] == prepared['ciphertext']['sha256']
    assert invoke('prepublication-cli-preview','partner-onboarding-handoff-preview','--request-file',write('prepublication-selection',selection),token=h['owner']) == preview
    deadline = time.monotonic() + 35
    while c['sql']("SELECT lease_until<=clock_timestamp() FROM delivery_intents WHERE delivery_id='" + prepared['uncertain_id'] + "'") != 't':
        assert time.monotonic() < deadline, 'original publishing lease did not expire'
        time.sleep(.1)
    post('prepublication-publishing-source-refused','/onboarding-handoffs/preview',dict(selection,source_run_id=prepared['uncertain']['run']['id'],source_hash=prepared['uncertain']['dispatch']['definition_hash']),expected=409)
    browser_raw = raw / 'prepublication-browser'
    browser_raw.mkdir(mode=0o700)
    before_files = sorted(x.name for x in inbox.iterdir())
    cfg = dict(c['cfg'], raw=str(browser_raw), receiver_log=str(raw/'receiver.log'), plan=h['plan'], test_only=False, release_only=False, handoff_only=True, handoff_selection=selection, handoff_hash=preview['definition_hash'], prepublication_proof=proof, new_recipient=h['recipient']['fingerprint'], handoff_contacts_before=h['contacts'](), handoff_files_before=before_files, postgres_container_id=c['pg'], database=c['database'])
    command('native-browser-prepublication-handoff',[c['node'],'scripts/onboarding-exchange-browser.mjs',write('prepublication-browser',cfg)],timeout=180)
    result = json.loads((browser_raw/'onboarding-handoff-browser-result.json').read_text())
    assert result['state'] == 'passed'
    handoff = result['handoff']
    original = post('prepublication-original-preserved','/onboarding-production/'+prepared['original']['run']['id'],method='GET')
    assert original['dispatch'] == prepared['original']['dispatch'] and original['status']['run']['state'] == 'cancelled' and original['status']['steps'][0]['attempts'] == 1 and original['status']['steps'][0]['ciphertext'] == prepared['ciphertext']
    assert prepared['partial'].is_file() and c['sha'](prepared['partial']) == prepared['ciphertext']['sha256'] and not (inbox/(prepared['delivery']+'-handoff-data.bin')).exists()
    successor = post('prepublication-successor-status','/onboarding-production/'+handoff['replacement_run_id'],method='GET')
    assert successor['status']['run']['source'] == child and successor['status']['steps'][0]['ciphertext']['object_id'] != prepared['ciphertext']['object_id']
    receive('prepublication-final-successor',successor['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    replay = post('prepublication-original-receipt-preserved','/onboarding-production',{'definition':prepared['preview']['definition']},key='prepublication-staged-production')
    assert replay['replayed'] and replay['resource'] == prepared['original']
    post('prepublication-old-worker-refused','/workflow-runs/'+prepared['original']['run']['id']+'/work',key='prepublication-killed-worker',expected=401)

    # The genuine connection-outage retry is eligible only through this new
    # explicit profile and its own complete journal, never the default path.
    retry_selection = dict(selection,source_run_id=h['attempted']['run']['id'],source_hash=h['attempted']['dispatch']['definition_hash'])
    retry_preview = post('prepublication-retry-preview','/onboarding-handoffs/preview',retry_selection)
    assert retry_preview['definition']['source']['state']=='retry' and retry_preview['definition']['source']['attempts']==1
    retry = post('prepublication-retry-propose','/onboarding-handoffs',{'definition':retry_preview['definition']},key='prepublication-retry-propose')['resource']['handoff']
    for action in ['approve','execute']:
        retry = post('prepublication-retry-'+action,'/onboarding-handoffs/'+retry['id']+'/'+action,h['decision'](retry),key='prepublication-retry-'+action)['resource']['handoff']
    completed = post('prepublication-retry-separate-work','/workflow-runs/'+retry['replacement_run_id']+'/work',key='prepublication-retry-work')
    receive('prepublication-retry-successor',completed['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    uncertain = post('prepublication-uncertain-remains-visible','/onboarding-production/'+prepared['uncertain']['run']['id'],method='GET')
    assert uncertain['status']['steps'][0]['state']=='publishing' and uncertain['status']['steps'][0]['ciphertext']==prepared['uncertain_ciphertext']
    assert c['sql']("SELECT lease_until<=clock_timestamp() FROM delivery_intents WHERE delivery_id='"+prepared['uncertain_id']+"'")=='t'
    assert c['sha'](inbox/(prepared['uncertain_id']+'-handoff-data.bin'))==prepared['uncertain_ciphertext']['sha256']
    history=invoke('prepublication-cli-history','partner-onboarding-handoff-list','--onboarding-id',h['plan']['id'],token=h['owner']);assert len(history['handoffs'])==3
    (raw/'prepublication-result.json').write_text(json.dumps({'state':'passed','original_run_id':prepared['original']['run']['id'],'replacement_run_id':handoff['replacement_run_id'],'original_delivery_state':'staging with actual original lease expired','original_attempts_preserved':1,'original_ciphertext':proof['ciphertext'],'retained_remote_partial':prepared['partial'].name,'original_final_never_published':True,'complete_journal':proof,'retry_successor':retry['replacement_run_id'],'published_source_refused_even_after_lease_expiry':True,'uncertain_final_preserved':prepared['uncertain_id'],'stock_sftp_and_new_recipient_decryption':'exact original bytes for both successors','default_profile_still_refuses_attempts':True,'inference_performed':False,'scanner_started':False},indent=2)+'\n')

    if c['options'].observations:
        from onboarding_observations_qualification import qualify_observations
        qualify_observations(c,h,prepared)
