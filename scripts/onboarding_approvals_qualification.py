"""Named independent review, real browser/CLI/API and existing stock receiver."""
import json

def qualify_approvals(c,h):
    post,invoke,write,command=(h[x] for x in ('post','invoke','write','command'))
    raw,private=c['raw'],c['private'];owner=h['owner'];decision=c['decision'];ref=c['ref']
    contacts=lambda:(raw/'receiver.log').read_text().count('Accepted publickey for ')
    # Refresh the connection/test that the preceding genuine revocation case
    # intentionally invalidated. No security check is relaxed or bypassed.
    post('approval-suspend-prior-release','/onboarding-releases/'+h['target']['id']+'/suspend',decision(h['target']),key='approval-suspend-prior')
    connection=h['register_connection']('approval-current-connection',2,h['connection_b'],'handoff-client-b','handoff-host-b')
    probe=h['probe']('approval-current-probe',h['plan'],h['req'],connection,2)
    run=c['create_run']('approval-fresh',{'key':ref(h['recipient']),'profile':'seipd-v1-aes256'},p=h['plan'],probe=probe,requirement_id=h['req'],connection0=connection,authority=2,filename0='handoff-data.bin',prior_workflow=c['workflows']['handoff-after'],file0=h['child'],recipient_fingerprint=h['recipient']['fingerprint'])
    done=post('approval-fresh-test-execute','/workflow-runs/'+run['id']+'/work',key='approval-fresh-test-execute');h['receive']('approval-fresh-test',done['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    before=contacts();files={p.name:c['sha'](p) for p in c['inbox'].iterdir()}
    change={'expected_revision':0,'mode':'independent'}
    policy=invoke('approval-policy-cli-set','partner-onboarding-approval-policy-set','--request-file',write('approval-policy-change',change),'--idempotency-key','approval-policy-change',token=owner)
    replay=post('approval-policy-api-replay','/onboarding-approval-policy',change,key='approval-policy-change');assert replay['replayed'] and replay['resource']==policy['resource']
    assert invoke('approval-policy-cli-status','partner-onboarding-approval-policy-status',token=owner)==post('approval-policy-api-status','/onboarding-approval-policy',method='GET')
    identity=invoke('approval-author-identity','identity',token=owner)
    token=private/'approval-reviewer.token';command('approval-reviewer-token',[c['binary'],'token','--token-file',token]);reviewer_id=c['secure_id']() if 'secure_id' in c else __import__('uuid').uuid4().__str__()
    account={'operation':'create','account_id':reviewer_id,'credential_sha256':c['sha'](token),'policy':{'label':'Independent production reviewer','namespace_root':'/','permissions':['inspect','workflow_approve']}}
    post('approval-create-reviewer','/accounts/commands',account,key='approval-create-reviewer')
    header=private/'approval-reviewer.headers';header.write_bytes(b'Authorization: Bearer '+token.read_bytes()+b'\n')
    selection={'plan':ref(h['plan']),'test_ids':[c['tests']['approval-fresh']['id']],'expected_authority_revision':2}
    p=post('approval-release-preview','/onboarding-releases/preview',selection);assert p['definition']['approval_policy']=={'revision':1,'mode':'independent'}
    release=post('approval-release-propose','/onboarding-releases',{'selection':selection,'definition_hash':p['definition_hash']},key='approval-release')['resource']['release']
    post('approval-owner-alone-denied','/onboarding-releases/'+release['id']+'/approve',decision(release),key='approval-owner-alone',expected=409)
    post('approval-self-review-denied','/onboarding-approval-reviews/preview',dict(release_id=release['id'],reviewer_id=identity['actor_id'],**decision(release)),expected=403)
    assert contacts()==before and files=={p.name:c['sha'](p) for p in c['inbox'].iterdir()}
    def browser(phase,**extra):
        directory=raw/('approval-'+phase+'-browser');directory.mkdir(mode=0o700)
        cfg=dict(c['cfg'],raw=str(directory),token=str(token if phase=='review' else owner),plan=h['plan'],test_only=False,release_only=False,handoff_only=False,observation_only=False,approval_only=True,approval_phase=phase,approval_release=release,approval_reviewer_id=reviewer_id,approval_author_id=identity['actor_id'],receiver_log=str(raw/'receiver.log'),**extra)
        command('native-browser-independent-'+phase,[c['node'],'scripts/onboarding-exchange-browser.mjs',write('approval-'+phase+'-browser',cfg)],timeout=180)
        return json.loads((directory/'onboarding-approval-browser-result.json').read_text())
    review=browser('request')['review']
    seen=post('approval-reviewer-api-status','/onboarding-approval-reviews/'+review['id'],who=header,method='GET')
    assert invoke('approval-reviewer-cli-status','partner-onboarding-approval-review-status','--onboarding-approval-id',review['id'],token=token)==seen
    post('approval-reviewer-private-plan-denied','/onboarding-plans/'+h['plan']['id'],who=header,method='GET',expected=403)
    post('approval-reviewer-private-release-denied','/onboarding-releases/'+release['id'],who=header,method='GET',expected=403)
    other=private/'approval-unassigned.headers';other.write_bytes(b'Authorization: Bearer '+c['other'].read_bytes()+b'\n')
    post('approval-unassigned-review-denied','/onboarding-approval-reviews/'+review['id'],who=other,method='GET',expected=404)
    approved=browser('review',approval_review=review)['review'];assert approved['state']=='approved'
    assert contacts()==before and files=={p.name:c['sha'](p) for p in c['inbox'].iterdir()}
    browser('activate');release=post('approval-active-release','/onboarding-releases/'+release['id'],method='GET')['release'];assert release['state']=='active'
    preview,production=h['production']('approval-production',release,h['req'],h['child'])
    done=post('approval-production-execute','/workflow-runs/'+production['run']['id']+'/work',key='approval-production-execute');assert done['status']['observed_state']=='succeeded';h['receive']('approval-production',done['status'],'handoff-client-b',h['new_fixture']/'recipient-private.gpg',h['recipient']['fingerprint'])
    _,queued=h['production']('approval-revoked-queued',release,h['req'],h['child'])
    post('approval-withdraw-current-review','/onboarding-approval-reviews/'+approved['id']+'/withdraw',decision(approved),key='approval-withdraw-current')
    before=contacts();post('approval-withdrawn-worker-denied','/workflow-runs/'+queued['run']['id']+'/work',key='approval-withdrawn-worker',expected=409);status=post('approval-withdrawn-queued-status','/onboarding-production/'+queued['run']['id'],method='GET');assert status['status']['steps'][0]['attempts']==0 and contacts()==before and not status['current_bindings']
    history=invoke('approval-reviewer-cli-history','partner-onboarding-approval-review-list',token=token);assert len(history['reviews'])==1 and history['reviews'][0]['state']=='withdrawn'
    (raw/'onboarding-approval-result.json').write_text(json.dumps({'state':'passed','release_id':release['id'],'review_id':review['id'],'reviewer_id':reviewer_id,'least_privilege_reviewer_permissions':['inspect','workflow_approve'],'separate_author_and_reviewer':True,'self_and_unassigned_refused':True,'private_sources_not_granted':True,'review_metadata_no_receiver_contact':True,'lost_response_original_key_recovery':True,'production_exact_original_bytes_independently_decrypted':True,'withdrawn_queued_work_no_attempt_or_contact':True,'full_journeys_qualified':False,'inference_performed':False,'scanner_started':False},indent=2)+'\n')
