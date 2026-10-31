"""Real queued encrypted exchange across SSH/recipient/operator rotation.

Uses only the parent qualifier's task-owned fixtures, database and loopback
peers. No model/scanner/global keyring or shared container lifecycle operation.
"""
import json,os,shutil,subprocess,time,uuid
from pathlib import Path

def qualify_handoffs(c):
 post,invoke,write,command,ref,decision=(c[x] for x in ('post','invoke','write','command','ref','decision'))
 raw,private,inbox,owner,accepted=(c[x] for x in ('raw','private','inbox','owner','accepted'))
 receiver_args=['/usr/sbin/sshd','-D','-e','-f',c['sshconf']]
 def contacts():return (raw/'receiver.log').read_text().count('Accepted publickey for ')
 def register_connection(label,version=0,prior=None,client='client',host='host'):
  request={'expected_version':version,'address':c['connection']['address'],'user':c['user'],'directory':str(inbox),'host_public_file':str(private/(host+'.pub')),'key_file':str(private/client),'key_public_file':str(private/(client+'.pub'))}
  if prior:request['connection_id']=prior['id']
  return invoke(label,'connection-register','--request-file',write(label,request),'--idempotency-key',label,token=owner)['resource']
 def probe(label,plan,requirement,connection,authority):
  p=post(label+'-start','/onboarding-probes',{'plan':ref(plan),'requirement_id':requirement,'connection':ref(connection),'expected_authority_revision':authority},key=label)['resource']
  p=post(label+'-work','/onboarding-probes/'+p['id']+'/work',{'definition_hash':p['definition_hash']},key=label+'-work')['probe'];assert p['state']=='succeeded';return p
 def activate(label,plan,test,authority):
  selection={'plan':ref(plan),'test_ids':[test['id']],'expected_authority_revision':authority};preview=post(label+'-preview','/onboarding-releases/preview',selection)
  release=post(label+'-propose','/onboarding-releases',{'selection':selection,'definition_hash':preview['definition_hash']},key=label)['resource']['release']
  for action in ['approve','activate']:release=post(label+'-'+action,'/onboarding-releases/'+release['id']+'/'+action,decision(release),key=label+'-'+action)['resource']['release']
  assert release['state']=='active';return release
 def production(label,release,requirement,file):
  p=post(label+'-preview','/onboarding-releases/'+release['id']+'/production-preview',dict(decision(release),requirement_id=requirement,file_id=file['id']))
  result=post(label+'-queue','/onboarding-production',{'definition':p['definition']},key=label)['resource'];assert result['run']['state']=='queued';return p,result
 def receive(label,status,client,recipient_private,expected_fingerprint):
  step=status['steps'][0];assert step['state']=='succeeded';cipher=step['ciphertext'];assert cipher['encryption']['key']['id'] and cipher['source_sha256']==c['digest']
  target=inbox/(step['delivery_id']+'-handoff-data.bin');out=private/(label+'-cipher.pgp');batch=private/(label+'.batch');batch.write_text(f'get {target} {out}\n')
  command(label+'-independent-sftp',['sftp','-F','/dev/null','-P',str(c['receiver_port']),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(c['known']),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/client,'-b',batch,c['user']+'@127.0.0.1']);assert c['sha'](out)==cipher['sha256'] and out.read_bytes()!=c['data']
  plain=private/(label+'-plaintext.csv');proof=command(label+'-independent-decrypt',['python3','scripts/pgp-native-peer.py','--config',c['native_config'],'--metrics',raw/(label+'-decryption.json'),'decrypt','--key',recipient_private,'--cipher',out,'--output',plain]);assert plain.read_bytes()==c['data'] and b'GOODMDC' in proof and b'DECRYPTION_OKAY' in proof
  assert cipher['proof']['primary_fingerprint']==expected_fingerprint
  return out
 connection=register_connection('handoff-old-connection');req,plan_id=[str(uuid.uuid4()) for _ in range(2)]
 definition={'schema_version':1,'name':'Qualified queued key rotation','contacts':c['definition']['contacts'],'requirements':[dict(c['definition']['requirements'][0],id=req,name='Encrypted queued delivery')]}
 plan=invoke('handoff-record-plan','partner-onboarding-save','--request-file',write('handoff-plan',{'plan_id':plan_id,'expected_version':0,'expected_authority_revision':1,'definition':definition}),'--idempotency-key','handoff-plan',token=owner)['plan']
 p=probe('handoff-old-probe',plan,req,connection,1)
 old_recipient=c['recipient'];encryption={'key':ref(old_recipient),'profile':'seipd-v1-aes256'}
 test_run=c['create_run']('handoff-data',encryption,p=plan,probe=p,requirement_id=req,connection0=connection)
 done=post('handoff-old-test-execute','/workflow-runs/'+test_run['id']+'/work',key='handoff-old-test-execute');receive('handoff-old-test',done['status'],'client',c['fixture']/'recipient-private.gpg',old_recipient['fingerprint'])
 old_workflow=c['workflows']['handoff-data'];release=activate('handoff-old-release',plan,c['tests']['handoff-data'],1)
 old_preview,original=production('handoff-original-production',release,req,accepted)
 # Exhaust only this fresh fixture database's two ordinary crypto slots.
 # The actual workflow dispatcher commits its prepared receipt, then the sender
 # refuses capacity before acquiring a delivery lease or contacting the peer.
 capacity_log=(raw/'handoff-capacity-fixture.log').open('wb');name='handoff-capacity-fixture'
 gate=subprocess.Popen(['docker','exec','-i',c['pg'],'psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d',c['database']],stdin=subprocess.PIPE,stdout=capacity_log,stderr=capacity_log,env=c['env'],start_new_session=True);c['servers'][name]=gate;c['logs'][name]=capacity_log
 try:
  gate.stdin.write(b'SELECT pg_advisory_lock(721815038,0);SELECT pg_advisory_lock(721815038,1);\n');gate.stdin.flush();deadline=time.monotonic()+10
  while c['sql']("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted AND classid=721815038 AND objid IN (0,1) AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")!='2':
   assert gate.poll() is None and time.monotonic()<deadline;time.sleep(.05)
  post('handoff-actual-prepared-worker-capacity-refusal','/workflow-runs/'+original['run']['id']+'/work',key='handoff-prepared-worker',expected=413)
 finally:
  if gate.poll() is None:gate.stdin.write(b'\\q\n');gate.stdin.flush();gate.stdin.close();gate.wait(timeout=10)
  assert gate.returncode==0;c['servers'].pop(name);c['logs'].pop(name).close()
 prepared=post('handoff-prepared-source','/onboarding-production/'+original['run']['id'],method='GET');assert prepared['status']['run']['state']=='running' and prepared['status']['steps'][0]['attempts']==0 and prepared['status']['steps'][0]['state']=='queued'
 # A real recorded attempt is different even if the connection failed before
 # publication. Retain its ciphertext/outcome; the handoff must refuse it.
 _,attempted=production('handoff-attempted-production',release,req,accepted)
 c['stop']('receiver')
 try:
  attempted_result=post('handoff-real-receiver-outage','/workflow-runs/'+attempted['run']['id']+'/work',key='handoff-real-outage');assert attempted_result['status']['steps'][0]['attempts']==1 and attempted_result['status']['steps'][0]['state']=='retry'
 finally:c['start']('receiver',receiver_args,c['receiver_port'])
 prepared_prepublication=None
 if c['options'].prepublication:
  from onboarding_prepublication_qualification import prepare_prepublication
  prepared_prepublication=prepare_prepublication(c,dict(locals()))
 # Rotate the synthetic operator through the existing second-manager policy.
 old_token=private/'handoff-owner-before-rotation.token';shutil.copy2(owner,old_token)
 old_header=private/'handoff-old-owner.headers';shutil.copy2(c['header'],old_header)
 identity=invoke('handoff-owner-identity','identity',token=owner);new_token=private/'handoff-owner-rotated.token';command('handoff-new-owner-token',[c['binary'],'token','--token-file',new_token]);assert len(new_token.read_bytes())==64
 manager_header=private/'handoff-manager.headers';manager_header.write_bytes(b'Authorization: Bearer '+c['other'].read_bytes()+b'\n')
 post('handoff-operator-credential-rotation','/accounts/commands',{'operation':'rotate','account_id':identity['actor_id'],'expected_revision':1,'credential_sha256':c['sha'](new_token)},key='handoff-rotate-owner',who=manager_header)
 shutil.copyfile(new_token,owner);c['header'].write_bytes(b'Authorization: Bearer '+owner.read_bytes()+b'\n')
 post('handoff-old-credential-refused','/onboarding-production/'+original['run']['id'],method='GET',who=old_header,expected=401)
 release=post('handoff-suspend-old-release','/onboarding-releases/'+release['id']+'/suspend',decision(release),key='handoff-suspend-old')['resource']['release']
 for name in ['handoff-host-b','handoff-client-b']:command(name+'-key',['ssh-keygen','-q','-t','ed25519','-N','','-f',private/name])
 c['stop']('receiver');shutil.copy2(private/'authorized_keys',private/'handoff-authorized-keys-before-rotation');shutil.copy2(c['known'],private/'handoff-known-hosts-before-rotation')
 (private/'authorized_keys').write_bytes((private/'handoff-client-b.pub').read_bytes());c['sshconf'].write_text(c['sshconf'].read_text().replace('HostKey '+str(private/'host'),'HostKey '+str(private/'handoff-host-b')))
 c['known'].write_text(f"[127.0.0.1]:{c['receiver_port']} "+(private/'handoff-host-b.pub').read_text());c['start']('receiver',receiver_args,c['receiver_port'])
 # Independent old-client authentication now fails against the new trusted host.
 batch=private/'handoff-old-client.batch';batch.write_text('ls\n');command('handoff-old-client-refused',['sftp','-F','/dev/null','-P',str(c['receiver_port']),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(c['known']),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,c['user']+'@127.0.0.1'],expected=255)
 connection_b=register_connection('handoff-new-connection',1,connection,'handoff-client-b','handoff-host-b');assert connection_b['key_fingerprint']!=connection['key_fingerprint'] and connection_b['host_fingerprint']!=connection['host_fingerprint']
 post('handoff-revoke-old-connection','/connections/'+connection['id']+'/1/revoke',decision(connection),key='handoff-revoke-connection')
 new_fixture=Path(command('handoff-new-recipient-fixture',['python3','scripts/prepare-pgp-fixture.py','--native-config',c['native_config'],'--rows','2'],timeout=150).decode().strip());peer=json.loads((new_fixture/'manifest.json').read_text());assert peer['state']=='passed' and peer['peer_backend']=='native-macos' and peer['fingerprints']['recipient']!=old_recipient['fingerprint']
 recipient=invoke('handoff-register-rotated-recipient','pgp-key-register','--request-file',write('handoff-recipient',{'key_id':old_recipient['id'],'expected_version':1,'fingerprint':peer['fingerprints']['recipient'],'purpose':'encrypt'}),'--pgp-public-file',new_fixture/'recipient-public.gpg','--idempotency-key','handoff-new-recipient',token=owner)['resource']
 post('handoff-revoke-old-recipient','/pgp-keys/'+old_recipient['id']+'/1/revoke',decision(old_recipient),key='handoff-revoke-recipient')
 # Derive a governed identical-byte checked revision, then run fresh ordinary
 # checks and a separate exact release. No scanner engine/database is loaded.
 policy={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':4096},{'name':'amount','type':'decimal','required':True,'max_bytes':64,'precision':12,'scale':2},{'name':'day','type':'date','required':True,'max_bytes':10}],'max_bytes':4<<20,'max_rows':100,'max_record_bytes':65536,'timeout_seconds':30}}
 post('handoff-register-current-intake-policy','/intake-policy',policy,key='handoff-current-intake')
 recheck=post('handoff-source-recheck-preview','/checks/'+accepted['id']+'/recheck-preview',{'target_path':'','signature_mode':'not_required','reason':'Preserve queued bytes under current policy after credential rotation'})
 saved=post('handoff-source-recheck-propose','/checks/'+accepted['id']+'/rechecks',{'plan':recheck['plan']},key='handoff-source-recheck')['resource']['recheck']
 saved=post('handoff-source-recheck-approve','/rechecks/'+saved['id']+'/decide',dict(decision(saved),operation='approve'),key='handoff-recheck-approve')['resource']['recheck']
 copied=post('handoff-source-recheck-copy','/rechecks/'+saved['id']+'/copy',key='handoff-source-copy')['resource']['recheck'];child_id=copied['new_file_id']
 post('handoff-child-fresh-checks','/checks/'+child_id+'/run',key='handoff-child-check');checked=post('handoff-child-check-status','/checks/'+child_id,method='GET')['check'];assert checked['state']=='passed' and checked['attempts']==1
 post('handoff-child-separate-release','/checks/'+child_id+'/release',{'sha256':checked['binding']['file']['sha256'],'policy_hash':checked['policy_hash'],'report_hash':checked['report_hash'],'expected_revision':checked['revision']},key='handoff-child-release');child=checked['binding']['file'];assert child['sha256']==accepted['sha256'] and child['size_bytes']==accepted['size_bytes'] and child['id']!=accepted['id']
 p=probe('handoff-new-probe',plan,req,connection_b,2)
 target_run=c['create_run']('handoff-after',{'key':ref(recipient),'profile':'seipd-v1-aes256'},p=plan,probe=p,requirement_id=req,connection0=connection_b,authority=2,filename0='handoff-data.bin',prior_workflow=old_workflow,file0=child,recipient_fingerprint=recipient['fingerprint'])
 done=post('handoff-new-test-execute','/workflow-runs/'+target_run['id']+'/work',key='handoff-new-test-execute');receive('handoff-new-test',done['status'],'handoff-client-b',new_fixture/'recipient-private.gpg',recipient['fingerprint'])
 target=activate('handoff-new-release',plan,c['tests']['handoff-after'],2)
 selection={'source_run_id':original['run']['id'],'source_hash':original['dispatch']['definition_hash'],'target_release':{'id':target['id'],'revision':target['revision'],'hash':target['definition_hash']},'file_id':child['id']}
 preview=post('handoff-current-preview','/onboarding-handoffs/preview',selection);assert not preview['external_contact'] and preview['definition']['source_recheck_id']==saved['id'] and preview['definition']['source']['attempts']==0 and preview['definition']['source']['run_revision']==2
 assert invoke('handoff-cli-preview','partner-onboarding-handoff-preview','--request-file',write('handoff-selection',selection),token=owner)==preview
 post('handoff-attempted-source-refused','/onboarding-handoffs/preview',dict(selection,source_run_id=attempted['run']['id'],source_hash=attempted['dispatch']['definition_hash']),expected=409)
 before=contacts();files=sorted(x.name for x in inbox.iterdir())
 cfg=dict(c['cfg'],plan=plan,test_only=False,release_only=False,handoff_only=True,handoff_selection=selection,handoff_hash=preview['definition_hash'],new_recipient=recipient['fingerprint'],handoff_contacts_before=before,handoff_files_before=files,postgres_container_id=c['pg'],database=c['database'])
 command('native-browser-queued-handoff',[c['node'],'scripts/onboarding-exchange-browser.mjs',write('handoff-browser',cfg)],timeout=180)
 result=json.loads((raw/'onboarding-handoff-browser-result.json').read_text());assert result['state']=='passed';h=result['handoff']
 old=post('handoff-original-status','/onboarding-production/'+original['run']['id'],method='GET');assert old['dispatch']==original['dispatch'] and old['status']['run']['source']==accepted and old['status']['run']['state']=='cancelled' and old['status']['steps'][0]['attempts']==0
 successor=post('handoff-successor-status','/onboarding-production/'+h['replacement_run_id'],method='GET');assert successor['status']['observed_state']=='succeeded' and successor['status']['run']['source']==child and successor['dispatch']['definition']==preview['definition']['target']
 encrypted=receive('handoff-final-successor',successor['status'],'handoff-client-b',new_fixture/'recipient-private.gpg',recipient['fingerprint'])
 command('handoff-old-recipient-cannot-decrypt',['python3','scripts/pgp-native-peer.py','--config',c['native_config'],'--metrics',raw/'handoff-old-key-decrypt-metrics.json','decrypt','--key',c['fixture']/'recipient-private.gpg','--cipher',encrypted,'--output',private/'handoff-old-key-refused.csv'],expected=1)
 post('handoff-late-old-worker-refused','/workflow-runs/'+original['run']['id']+'/work',key='handoff-prepared-worker',expected=401)
 replay=post('handoff-original-queue-receipt-preserved','/onboarding-production',{'definition':old_preview['definition']},key='handoff-original-production');assert replay['replayed'] and replay['resource']==original
 status=invoke('handoff-cli-status','partner-onboarding-handoff-status','--onboarding-handoff-id',h['id'],token=owner);assert status['handoff']['state']=='completed' and status['handoff']['replacement_run_id']==h['replacement_run_id']
 history=invoke('handoff-cli-history','partner-onboarding-handoff-list','--onboarding-id',plan['id'],token=owner);assert len(history['handoffs'])==1
 atomic=json.loads((raw/'handoff-atomic-before-transfer.json').read_text());assert atomic['distinct_transactions']==1 and atomic['source_run_id']==original['run']['id'] and atomic['replacement_run_id']==h['replacement_run_id']

 # Only the successor transfer and independent fetch should contact after
 # preview; proposal/approval/metadata handoff itself is checked in the browser.
 (raw/'onboarding-handoff-result.json').write_text(json.dumps({'state':'passed','source_run_id':original['run']['id'],'replacement_run_id':h['replacement_run_id'],'source_sha256':accepted['sha256'],'source_size':accepted['size_bytes'],'checked_revision':child,'linked_recheck_id':saved['id'],'old_client_fingerprint':connection['key_fingerprint'],'new_client_fingerprint':connection_b['key_fingerprint'],'old_host_fingerprint':connection['host_fingerprint'],'new_host_fingerprint':connection_b['host_fingerprint'],'old_recipient_fingerprint':old_recipient['fingerprint'],'new_recipient_fingerprint':recipient['fingerprint'],'old_credential_refused':True,'prepared_source_attempts':0,'attempted_source_refused':True,'single_atomic_handoff':True,'new_fixture_manifest':str(new_fixture/'manifest.json'),'receiver_contacts_before_handoff':before,'receiver_contacts_after':contacts(),'receiver_files_before_handoff':files,'receiver_files_after':sorted(x.name for x in inbox.iterdir()),'inference_performed':False,'scanner_started':False},indent=2)+'\n')

 if prepared_prepublication is not None:
  from onboarding_prepublication_qualification import qualify_prepublication
  qualify_prepublication(c,dict(locals()),prepared_prepublication)
