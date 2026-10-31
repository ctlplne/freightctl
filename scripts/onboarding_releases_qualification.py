"""Selected real pre-contact approval/activation/production journey.

Called only by the explicitly configured local qualifier. Uses its existing
scoped services and stock peer; owns no shared process/container lifecycle.
"""
import json,uuid
from pathlib import Path

def qualify_releases(c):
 post,invoke,write,command,ref,decision=(c[x] for x in ('post','invoke','write','command','ref','decision'))
 raw,private,inbox,connection,owner,accepted=(c[x] for x in ('raw','private','inbox','connection','owner','accepted'))
 integrity_a,integrity_b,plan_id=[str(uuid.uuid4()) for _ in range(3)]
 definition={'schema_version':1,'name':'Qualified production release','contacts':c['definition']['contacts'],'requirements':[dict(c['definition']['requirements'][0],id=ident,name=name) for ident,name in [(integrity_a,'Plain production exchange'),(integrity_b,'Encrypted production exchange')]]}
 saved={'plan_id':plan_id,'expected_version':0,'expected_authority_revision':1,'definition':definition}
 plan=invoke('release-record-requirements','partner-onboarding-save','--request-file',write('release-plan',saved),'--idempotency-key','release-plan',token=owner)['plan']
 records=[];runs=[]
 for ident,label,encryption in [(integrity_a,'release-plain',None),(integrity_b,'release-encrypted',{'key':ref(c['recipient']),'profile':'seipd-v1-aes256'})]:
  p=post(label+'-probe-start','/onboarding-probes',{'plan':ref(plan),'requirement_id':ident,'connection':ref(connection),'expected_authority_revision':1},key=label+'-probe')['resource']
  p=post(label+'-probe-work','/onboarding-probes/'+p['id']+'/work',{'definition_hash':p['definition_hash']},key=label+'-probe-work')['probe'];assert p['state']=='succeeded'
  run=c['create_run'](label,encryption,p=plan,probe=p,requirement_id=ident);records.append(c['tests'][label]);runs.append(run)
  done=post(label+'-complete','/workflow-runs/'+run['id']+'/work',key=label+'-complete');assert done['status']['observed_state']=='succeeded'
 def received(label,status,filename):
  step=status['steps'][0];target=inbox/(step['delivery_id']+'-'+filename);output=private/(label+'-received.bin');batch=private/(label+'.batch');batch.write_text(f'get {target} {output}\n')
  command(label+'-stock-sftp',['sftp','-F','/dev/null','-P',str(c['receiver_port']),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(c['known']),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,c['user']+'@127.0.0.1'])
  if 'ciphertext' in step:
   cipher=step['ciphertext'];assert c['sha'](output)==cipher['sha256'] and output.read_bytes()!=c['data'];decrypted=private/(label+'-plaintext.csv')
   proof=command(label+'-stock-authenticated-decryption',['python3','scripts/pgp-native-peer.py','--config',c['native_config'],'--metrics',raw/(label+'-decryption-metrics.json'),'decrypt','--key',c['fixture']/'recipient-private.gpg','--cipher',output,'--output',decrypted]);assert decrypted.read_bytes()==c['data'] and b'GOODMDC' in proof and b'DECRYPTION_OKAY' in proof
  else:assert output.read_bytes()==c['data'] and c['sha'](output)==c['digest']
 for label,run in zip(['release-plain','release-encrypted'],runs):
  status=post(label+'-completed-status','/workflow-runs/'+run['id'],method='GET');received(label,status,label+'.bin')
 selection={'plan':ref(plan),'test_ids':[t['id'] for t in records],'expected_authority_revision':1}
 post('release-omitted-requirement-denied','/onboarding-releases/preview',dict(selection,test_ids=selection['test_ids'][:1]),expected=400)
 business_id,business_plan_id=[str(uuid.uuid4()) for _ in range(2)]
 business_def=dict(definition,name='Qualified business receipt refusal',requirements=[dict(definition['requirements'][0],id=business_id,name='Requires downstream acceptance',required_receipt='business')])
 business_plan=invoke('release-business-plan','partner-onboarding-save','--request-file',write('release-business-plan',{'plan_id':business_plan_id,'expected_version':0,'expected_authority_revision':1,'definition':business_def}),'--idempotency-key','release-business-plan',token=owner)['plan']
 bp=post('release-business-probe-start','/onboarding-probes',{'plan':ref(business_plan),'requirement_id':business_id,'connection':ref(connection),'expected_authority_revision':1},key='release-business-probe')['resource']
 bp=post('release-business-probe-work','/onboarding-probes/'+bp['id']+'/work',{'definition_hash':bp['definition_hash']},key='release-business-probe-work')['probe'];assert bp['state']=='succeeded'
 business_run=c['create_run']('release-business',p=business_plan,probe=bp,requirement_id=business_id)
 business_done=post('release-business-exchange','/workflow-runs/'+business_run['id']+'/work',key='release-business-exchange');assert business_done['status']['observed_state']=='succeeded';received('release-business',business_done['status'],'release-business.bin')
 post('release-business-obligation-denied','/onboarding-releases/preview',{'plan':ref(business_plan),'test_ids':[c['tests']['release-business']['id']],'expected_authority_revision':1},expected=409)
 before=(raw/'receiver.log').read_text().count('Accepted publickey for ');files=sorted(x.name for x in inbox.iterdir())
 preview=post('release-preview','/onboarding-releases/preview',selection);assert not preview['external_contact'] and not preview['production_active'] and len(preview['definition']['proofs'])==2
 cli=invoke('release-cli-preview','partner-onboarding-release-preview','--request-file',write('release-selection',selection),token=owner);assert cli==preview
 assert before==(raw/'receiver.log').read_text().count('Accepted publickey for ') and files==sorted(x.name for x in inbox.iterdir())
 cfg=dict(c['cfg'],plan=plan,test_only=False,release_only=True,release_selection=selection,production_file=accepted['id'])
 command('native-browser-release-lifecycle',[c['node'],'scripts/onboarding-exchange-browser.mjs',write('release-browser',cfg)],timeout=150)
 browser=json.loads((raw/'onboarding-release-browser-result.json').read_text());assert browser['state']=='passed';release=browser['release'];production=browser['production']
 view=post('release-final-status','/onboarding-releases/'+release['id'],method='GET');assert view['release']['state']=='active' and view['release']['revision']==5 and view['production_active']
 cli=invoke('release-cli-status','partner-onboarding-release-status','--onboarding-release-id',release['id'],token=owner);assert cli==view
 old=post('release-old-epoch-state','/onboarding-production/'+browser['stale']['id'],method='GET');assert not old['current_bindings'] and old['status']['observed_state']=='attention' and old['status']['steps'][0]['attempts']==0
 post('release-old-epoch-work-denied','/workflow-runs/'+browser['stale']['id']+'/work',key='old-epoch-denied',expected=409)
 status=post('release-browser-production-state','/onboarding-production/'+production['id'],method='GET');assert status['status']['observed_state']=='succeeded';received('release-browser-production',status['status'],'release-plain.bin')
 assert invoke('production-cli-status','partner-onboarding-production-status','--run-id',production['id'],token=owner)==status
 history=post('release-production-history','/onboarding-releases/'+release['id']+'/runs',method='GET');assert len(history['dispatches'])==2
 assert invoke('production-cli-history','partner-onboarding-production-list','--onboarding-release-id',release['id'],token=owner)==history
 # Exercise the encrypted requirement through the active production route too.
 selection0={'definition_hash':release['definition_hash'],'expected_revision':5,'requirement_id':integrity_b,'file_id':accepted['id']}
 preview0=post('encrypted-production-preview','/onboarding-releases/'+release['id']+'/production-preview',selection0)
 assert invoke('encrypted-production-cli-preview','partner-onboarding-production-preview','--onboarding-release-id',release['id'],'--request-file',write('encrypted-production-selection',selection0),token=owner)==preview0
 body={'definition':preview0['definition']};queued=post('encrypted-production-start','/onboarding-production',body,key='encrypted-production')['resource']
 assert invoke('encrypted-production-cli-replay','partner-onboarding-production-start','--request-file',write('encrypted-production-start',body),'--idempotency-key','encrypted-production',token=owner)['resource']==queued
 done=post('encrypted-production-work','/workflow-runs/'+queued['run']['id']+'/work',key='encrypted-production-work');assert done['status']['observed_state']=='succeeded';received('encrypted-production',done['status'],'release-encrypted.bin')
 # A changed plan makes the active projection stale; explicit suspension remains
 # available, while the original evidence/approval and production receipts survive.
 saved['expected_version']=1;saved['definition']['name']='Changed production requirements'
 invoke('release-plan-change','partner-onboarding-save','--request-file',write('release-plan-v2',saved),'--idempotency-key','release-plan-v2',token=owner)
 stale=post('release-current-binding-refusal','/onboarding-releases/'+release['id'],method='GET');assert not stale['production_active'] and not stale['current_bindings'] and stale['release']['state']=='active'
 post('release-stale-production-preview-denied','/onboarding-releases/'+release['id']+'/production-preview',selection0,expected=409)
 invoke('release-cli-suspend-stale','partner-onboarding-release-decide','--onboarding-release-id',release['id'],'--onboarding-release-action','suspend','--request-file',write('release-suspend',{'definition_hash':release['definition_hash'],'expected_revision':5}),'--idempotency-key','stale-suspend',token=owner)
 post('release-stale-reactivation-denied','/onboarding-releases/'+release['id']+'/activate',{'definition_hash':release['definition_hash'],'expected_revision':6},key='stale-reactivation',expected=409)
