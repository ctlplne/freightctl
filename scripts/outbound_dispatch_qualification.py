"""All current outbound SFTP intent paths share exact dispatch consent."""
import json,time,uuid

def qualify_dispatch(c,h,a):
    post,invoke,write,command=(h[x] for x in ('post','invoke','write','command'));raw,private=c['raw'],c['private'];owner=h['owner'];ref,decision=c['ref'],c['decision'];reviewer_id=a['reviewer_id'];reviewer_token=a['token'];contacts=lambda:(raw/'receiver.log').read_text().count('Accepted publickey for ')
    reviewer_headers=private/'dispatch-reviewer.headers';reviewer_headers.write_bytes(b'Authorization: Bearer '+reviewer_token.read_bytes()+b'\n')
    workflow=c['workflows']['approval-fresh'];run_body={'workflow':ref(workflow),'file_id':h['child']['id']}
    legacy=post('dispatch-legacy-ordinary-queue','/workflow-runs',run_body,key='dispatch-legacy-ordinary')['resource']
    policy={'expected_revision':0,'mode':'independent'};before=contacts();saved=invoke('dispatch-policy-cli-set','dispatch-policy-set','--request-file',write('dispatch-policy',policy),'--idempotency-key','dispatch-policy',token=owner)
    replay=post('dispatch-policy-api-replay','/outbound-dispatch-policy',policy,key='dispatch-policy');assert replay['replayed'] and replay['resource']==saved['resource']
    assert invoke('dispatch-policy-cli-status','dispatch-policy-status',token=owner)==post('dispatch-policy-api-status','/outbound-dispatch-policy',method='GET')
    old=post('dispatch-original-run-receipt-replay','/workflow-runs',run_body,key='dispatch-legacy-ordinary');assert old['replayed'] and old['resource']==legacy
    denied=post('dispatch-legacy-policy-work-denied','/workflow-runs/'+legacy['id']+'/work',key='dispatch-legacy-worker',expected=409);assert denied['error']=='dispatch_approval_required'
    stale=post('dispatch-legacy-policy-status','/workflow-runs/'+legacy['id'],method='GET');assert stale['steps'][0]['attempts']==0 and contacts()==before
    fresh=post('dispatch-current-ordinary-queue','/workflow-runs',run_body,key='dispatch-current-ordinary')['resource'];status=post('dispatch-current-ordinary-status','/workflow-runs/'+fresh['id'],method='GET');delivery_id=status['steps'][0]['delivery_id']
    post('dispatch-current-worker-before-review','/workflow-runs/'+fresh['id']+'/work',key='dispatch-current-worker',expected=409)
    view=post('dispatch-owner-delivery-view','/outbound-deliveries/'+delivery_id,method='GET');assert view['reviewable'] and not view['current_approval'] and view['policy']=={'revision':1,'mode':'independent'} and view['attempts']==0
    assert invoke('dispatch-owner-delivery-cli-view','dispatch-delivery-status','--delivery-id',delivery_id,token=owner)==view
    other=private/'dispatch-other.headers';other.write_bytes(b'Authorization: Bearer '+c['other'].read_bytes()+b'\n')
    def browser(phase,delivery=None,review=None,token=None):
        directory=raw/('dispatch-'+phase+'-browser');directory.mkdir(mode=0o700)
        cfg=dict(c['cfg'],raw=str(directory),token=str(token or owner),plan=h['plan'],test_only=False,release_only=False,handoff_only=False,observation_only=False,approval_only=False,dispatch_approval_only=True,dispatch_phase=phase,dispatch_delivery=delivery,dispatch_review=review,dispatch_reviewer_id=reviewer_id,receiver_log=str(raw/'receiver.log'))
        command('native-browser-dispatch-'+phase,[c['node'],'scripts/onboarding-exchange-browser.mjs',write('dispatch-'+phase+'-browser',cfg)],timeout=180)
        return json.loads((directory/'outbound-dispatch-browser-result.json').read_text())['review']
    review=browser('request',delivery=view)
    post('dispatch-reviewer-original-intent-denied','/outbound-deliveries/'+delivery_id,who=reviewer_headers,method='GET',expected=403)
    post('dispatch-reviewer-source-download-denied','/files/'+h['child']['id'],who=reviewer_headers,method='GET',expected=403)
    post('dispatch-unassigned-manager-review-denied','/outbound-dispatch-reviews/'+review['id'],who=other,method='GET',expected=404)
    approved=browser('approve',review=review,token=reviewer_token)
    # Rotate the reviewer's credential before any attempt. A new named approval
    # resumes the same immutable intent, not a different send or recipient.
    rotated=private/'dispatch-reviewer-rotated.token';command('dispatch-rotated-reviewer-token',[c['binary'],'token','--token-file',rotated])
    post('dispatch-reviewer-credential-rotate','/accounts/commands',{'operation':'rotate','account_id':reviewer_id,'expected_revision':1,'credential_sha256':c['sha'](rotated)},key='dispatch-reviewer-rotate')
    post('dispatch-old-reviewer-token-denied','/outbound-dispatch-reviews/'+review['id'],who=reviewer_headers,method='GET',expected=401)
    before=contacts();post('dispatch-rotated-consent-worker-denied','/workflow-runs/'+fresh['id']+'/work',key='dispatch-current-worker',expected=409)
    still=post('dispatch-rotated-consent-same-intent','/outbound-deliveries/'+delivery_id,method='GET');assert still['id']==view['id'] and still['definition_hash']==view['definition_hash'] and still['attempts']==0 and not still['current_approval'] and contacts()==before
    post('dispatch-author-withdraw-old-consent','/outbound-dispatch-reviews/'+approved['id']+'/withdraw',decision(approved),key='dispatch-withdraw-old')
    fresh_review=browser('request-again',delivery=still)
    headers=private/'dispatch-current-reviewer.headers';headers.write_bytes(b'Authorization: Bearer '+rotated.read_bytes()+b'\n')
    current=post('dispatch-new-reviewer-authority','/outbound-dispatch-reviews/'+fresh_review['id'],who=headers,method='GET');assert current['definition']['reviewer_authority_revision']==2
    browser('approve-again',review=fresh_review,token=rotated)
    done=post('dispatch-ordinary-execute-original-work-key','/workflow-runs/'+fresh['id']+'/work',key='dispatch-current-worker');assert done['replayed'] and done['status']['observed_state']=='succeeded';h['receive']('dispatch-ordinary-exact',done['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    def approve_api(label,id):
        v=post(label+'-view','/outbound-deliveries/'+id,method='GET');selection=dict(delivery_id=id,reviewer_id=reviewer_id,**decision(v));p=invoke(label+'-cli-preview','dispatch-review-preview','--request-file',write(label+'-selection',selection),token=owner);assert not p['external_contact'] and not p['grants_file_access']
        r=post(label+'-propose','/outbound-dispatch-reviews',{'selection':selection,'definition_hash':p['definition_hash']},key=label+'-propose')['resource']['review']
        receipt=invoke(label+'-reviewer-cli-approve','dispatch-review-decide','--dispatch-review-id',r['id'],'--dispatch-review-action','approve','--request-file',write(label+'-decision',decision(r)),'--idempotency-key',label+'-approve',token=rotated)
        replay=post(label+'-approval-api-replay','/outbound-dispatch-reviews/'+r['id']+'/approve',decision(r),key=label+'-approve',who=headers);assert replay['replayed'] and replay['resource']==receipt['resource'];return replay['resource']['review']
    # A fresh onboarding test also holds at the same shared sender gate.
    trial=c['create_run']('dispatch-governed-test',{'key':ref(h['recipient']),'profile':'seipd-v1-aes256'},p=h['plan'],probe=a['probe'],requirement_id=h['req'],connection0=a['connection'],authority=2,filename0='handoff-data.bin',prior_workflow=workflow,file0=h['child'],recipient_fingerprint=h['recipient']['fingerprint'])
    before=contacts();post('dispatch-onboarding-test-before-consent','/workflow-runs/'+trial['id']+'/work',key='dispatch-governed-test-worker',expected=409);trial_state=post('dispatch-governed-test-held','/onboarding-tests/'+trial['id'],method='GET');assert trial_state['status']['steps'][0]['attempts']==0 and contacts()==before
    approve_api('dispatch-onboarding-test',trial_state['status']['steps'][0]['delivery_id'])
    completed=post('dispatch-onboarding-test-execute','/workflow-runs/'+trial['id']+'/work',key='dispatch-governed-test-worker');assert completed['status']['observed_state']=='succeeded';h['receive']('dispatch-onboarding-test',completed['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    # Production release approval and exact-file dispatch approval are cumulative.
    post('dispatch-layered-suspend-prior-release','/onboarding-releases/'+a['release']['id']+'/suspend',decision(a['release']),key='dispatch-layered-suspend')
    selection={'plan':ref(h['plan']),'test_ids':[c['tests']['dispatch-governed-test']['id']],'expected_authority_revision':2};p=post('dispatch-layered-release-preview','/onboarding-releases/preview',selection);release=post('dispatch-layered-release-propose','/onboarding-releases',{'selection':selection,'definition_hash':p['definition_hash']},key='dispatch-layered-release')['resource']['release']
    select_review=dict(release_id=release['id'],reviewer_id=reviewer_id,**decision(release));p=post('dispatch-layered-config-review-preview','/onboarding-approval-reviews/preview',select_review);review0=post('dispatch-layered-config-review-propose','/onboarding-approval-reviews',{'selection':select_review,'definition_hash':p['definition_hash']},key='dispatch-layered-config-review')['resource']['review'];post('dispatch-layered-config-review-approve','/onboarding-approval-reviews/'+review0['id']+'/approve',decision(review0),key='dispatch-layered-config-review-approve',who=headers)
    for action in ['approve','activate']:release=post('dispatch-layered-release-'+action,'/onboarding-releases/'+release['id']+'/'+action,decision(release),key='dispatch-layered-release-'+action)['resource']['release']
    _,production=h['production']('dispatch-layered-production',release,h['req'],h['child']);before=contacts();post('dispatch-production-release-alone-denied','/workflow-runs/'+production['run']['id']+'/work',key='dispatch-layered-worker',expected=409);state=post('dispatch-layered-production-held','/onboarding-production/'+production['run']['id'],method='GET');assert state['status']['steps'][0]['attempts']==0 and contacts()==before
    approve_api('dispatch-layered-file',state['status']['steps'][0]['delivery_id']);done=post('dispatch-layered-production-execute','/workflow-runs/'+production['run']['id']+'/work',key='dispatch-layered-worker');assert done['status']['observed_state']=='succeeded';h['receive']('dispatch-layered-production',done['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    def direct(label):
        request={'file_id':h['child']['id'],'address':a['connection']['address'],'user':c['user'],'directory':str(c['inbox']),'filename':label+'.csv','host_public_file':str(private/'handoff-host-b.pub'),'key_file':str(private/'handoff-client-b'),'key_public_file':str(private/'handoff-client-b.pub')}
        d=invoke(label+'-cli-create','delivery-create','--request-file',write(label+'-create',request),'--idempotency-key',label+'-create',token=owner)['delivery']
        d=invoke(label+'-cli-queue','delivery-approve','--delivery-id',d['id'],'--definition-hash',d['definition_hash'],'--expected-revision',str(d['revision']),'--idempotency-key',label+'-queue',token=owner)['delivery'];return d
    def plain_receive(label,d):
        target=c['inbox']/(d['id']+'-'+label+'.csv');out=private/(label+'-stock-received.csv');batch=private/(label+'-stock.batch');batch.write_text(f'get {target} {out}\n');command(label+'-independent-stock-sftp',['sftp','-F','/dev/null','-P',str(c['receiver_port']),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(c['known']),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'handoff-client-b','-b',batch,c['user']+'@127.0.0.1']);assert out.read_bytes()==c['data'];return target
    d=direct('dispatch-direct');before=contacts();invoke('dispatch-direct-worker-before-consent','delivery-work','--delivery-id',d['id'],token=owner,expected=1);assert contacts()==before;approve_api('dispatch-direct',d['id']);sent=invoke('dispatch-direct-worker-approved','delivery-work','--delivery-id',d['id'],token=owner);assert sent['state']=='succeeded';plain_receive('dispatch-direct',d)
    uncertain=direct('dispatch-uncertain');consent=approve_api('dispatch-uncertain',uncertain['id']);id=uncertain['id']
    c['sql']("CREATE FUNCTION freightctl_dispatch_real_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='"+id+"' AND NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned dispatch receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_dispatch_real_receipt_failure BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_dispatch_real_receipt_failure()")
    try:invoke('dispatch-uncertain-real-worker','delivery-work','--delivery-id',id,token=owner,expected=1)
    finally:c['sql']('DROP TRIGGER freightctl_dispatch_real_receipt_failure ON delivery_intents;DROP FUNCTION freightctl_dispatch_real_receipt_failure()')
    original=invoke('dispatch-uncertain-published-status','delivery-status','--delivery-id',id,token=owner);assert original['state']=='publishing' and original['attempts']==1;target=plain_receive('dispatch-uncertain',uncertain);wire=c['sha'](target)
    withdrawn=browser('withdraw',review=consent,token=rotated);assert withdrawn['state']=='withdrawn';invoke('dispatch-withdrawn-real-worker-denied','delivery-work','--delivery-id',id,token=owner,expected=1)
    deadline=time.monotonic()+35
    while c['sql']("SELECT lease_until<=clock_timestamp() FROM delivery_intents WHERE delivery_id='"+id+"'")!='t':assert time.monotonic()<deadline,'original publication lease did not expire';time.sleep(.1)
    recovered=invoke('dispatch-withdrawn-readonly-reconcile','delivery-reconcile','--delivery-id',id,token=owner);assert recovered['state']=='succeeded' and recovered['attempts']==1 and recovered['fence']==original['fence'] and recovered['observation']['reconciled'] and recovered['observation']['business_acceptance']=='unknown' and c['sha'](target)==wire
    history=invoke('dispatch-reviewer-cli-history','dispatch-review-list',token=rotated);assert any(r['id']==consent['id'] and r['state']=='withdrawn' for r in history['reviews'])
    (raw/'outbound-dispatch-result.json').write_text(json.dumps({'state':'passed','legacy_policy_not_rebound':True,'ordinary_workflow_requires_review':True,'onboarding_test_requires_review':True,'production_release_and_dispatch_approvals_cumulative':True,'direct_cli_requires_review':True,'same_untouched_delivery_after_reviewer_rotation':delivery_id,'least_privilege_private_review':True,'all_metadata_browser_actions_no_receiver_contact':True,'lost_response_original_key_recovery':True,'independent_stock_retrieval_and_authenticated_decryption':'exact original73-byte source','withdrawn_consent_blocks_sending':True,'read_only_uncertain_receipt_recovered_without_new_attempt':id,'original_publication_lease_retained':True,'business_acceptance':'unknown','full_journeys_qualified':False,'inference_performed':False,'scanner_started':False},indent=2)+'\n')
