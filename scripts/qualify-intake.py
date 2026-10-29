#!/usr/bin/env python3
"""Held intake journey: real PostgreSQL, bounded CSV checks and stock HTTPS/SFTP peers.

Only synthetic bytes and loopback traffic. Exact task-owned processes are stopped
in finally. No system SSH configuration is changed.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
import traceback
import uuid
from urllib.parse import urlencode

os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
run_id='intake-'+uuid.uuid4().hex
private=root/'.private'/run_id;private.mkdir(mode=0o700)
raw=root/'evidence/raw'/run_id;raw.mkdir(parents=True,mode=0o700)
binary=root/'.cache/freightctl';servers={};logs={};children=[];steps=[];started=time.monotonic()
owned_database=False
data=b'';digest=hashlib.sha256(data).hexdigest()
def command(args,timeout=60):
 r=subprocess.run(args,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError(Path(args[0]).name+' failed: '+r.stderr.decode(errors='replace')[:1000])
 return r.stdout
def cli(*args):return command([str(binary),*args])
def sql(text):return command(['docker','exec','-i','freightctl-postgres-v1','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','freightctl','-At','-c',text])
def free_port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def start(name,args,port):
 logs[name]=(raw/(name+'.log')).open('ab');servers[name]=subprocess.Popen(args,stdout=logs[name],stderr=logs[name],start_new_session=True)
 for _ in range(100):
  if servers[name].poll() is not None:raise RuntimeError(name+' exited; inspect retained log')
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.2):return
  except OSError:time.sleep(.05)
 raise RuntimeError(name+' unavailable')
def stop(name):
 p=servers.pop(name,None)
 if p is not None:
  if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
 if name in logs:logs.pop(name).close()
try:
 metadata=json.loads(command(['docker','inspect','freightctl-postgres-v1']))[0]
 assert metadata['Config']['Labels']['freightctl.workspace']==str(root)
 owned_database=True
 command(['sh','scripts/go.sh','build','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/freightctl']);cli('init')
 tenant,partner=str(uuid.uuid4()),str(uuid.uuid4());http_port,receiver_port=free_port(),free_port()
 storage=private/'custody';inbox=private/'inbox';inbox.mkdir(mode=0o700)
 def identity(label,permissions=None):
  token=private/(label+'.token');cli('token','--token-file',str(token))
  args=['enroll','--tenant',tenant,'--partner',partner,'--token-file',str(token)]
  if permissions is not None:args+=['--permissions',permissions]
  cli(*args);return token
 owner=identity('owner');other=identity('other');old_grants=identity('old-grants','read,write,list,manage_paths,inspect,audit_read,admin')
 header=private/'owner.headers';header.write_bytes(b'Authorization: Bearer '+owner.read_bytes()+b'\n')
 cert,tls_key=private/'localhost.crt',private/'localhost.key';cli('dev-cert','--cert',str(cert),'--key',str(tls_key))
 start('https',[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key)],http_port)
 for label in ['receiver-host','client','other-host']:
  command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(private/label)])
 (private/'authorized_keys').write_bytes((private/'client.pub').read_bytes())
 user=command(['id','-un']).decode().strip() # OS account for the isolated SSH fixture, never a Git identity.
 config=private/'sshd_config'
 config.write_text(f'''Port {receiver_port}
ListenAddress 127.0.0.1
HostKey {private/'receiver-host'}
PidFile {private/'sshd.pid'}
AuthorizedKeysFile {private/'authorized_keys'}
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
 start('receiver',['/usr/sbin/sshd','-D','-e','-f',str(config)],receiver_port)
 known_hosts=private/'known_hosts';known_hosts.write_text(f'[127.0.0.1]:{receiver_port} '+(private/'receiver-host.pub').read_text())
 data=b'account,amount,day\n'+b'00000001,100.01,2026-10-28\n'*65536
 payload=private/'synthetic.bin';payload.write_bytes(data);digest=hashlib.sha256(data).hexdigest()
 accepted=json.loads(command(['curl','--silent','--show-error','--fail','--cacert',str(cert),'--max-time','20','--header','@'+str(header),'--header','Idempotency-Key: outbound-source','--header','X-File-Size: '+str(len(data)),'--header','X-Content-SHA256: '+digest,'--data-binary','@'+str(payload),f'https://127.0.0.1:{http_port}/v1/tenants/{tenant}/partners/{partner}/files']))['file']
 steps.append({'name':'stock-curl-durable-source','size_bytes':len(data),'sha256':digest})
 common=['--tenant',tenant,'--partner',partner,'--token-file',str(owner),'--storage',str(storage)]
 def args(command_name,*extra,token=None):
  result=[str(binary),command_name,*common,*map(str,extra)]
  if token is not None:result+=['--token-file',str(token)]
  return result
 def invoke(label,command_name,*extra,success=True,token=None):
  r=subprocess.run(args(command_name,*extra,token=token),capture_output=True,timeout=100)
  (raw/(label+'.stdout')).write_bytes(r.stdout);(raw/(label+'.stderr')).write_bytes(r.stderr)
  steps.append({'name':label,'exit_code':r.returncode,'expected_success':success,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
  if (r.returncode==0)!=success:raise RuntimeError(label+': unexpected exit '+str(r.returncode)+' '+r.stderr.decode(errors='replace')[:1000])
  return json.loads(r.stdout) if r.returncode==0 else None
 def post(label,route,body=None,expected=200,key=None,who=None,method='POST',scope_ids=None,extra=()):
  output=raw/(label+'.out');args0=['curl','--silent','--show-error','--cacert',str(cert),'--max-time','30','--header','@'+str(who or header),'--request',method,'--output',str(output),'--write-out','%{http_code}']
  if key:args0+=['--header','Idempotency-Key: '+key]
  if body is not None:
   request=private/(label+'.request.json');request.write_bytes(body if isinstance(body,bytes) else json.dumps(body).encode());args0+=['--header','Content-Type: application/json','--data-binary','@'+str(request)]
  scope_tenant,scope_partner=scope_ids or (tenant,partner)
  code=int(command([*args0,*extra,f'https://127.0.0.1:{http_port}/v1/tenants/{scope_tenant}/partners/{scope_partner}'+route]))
  steps.append({'name':label,'http_status':code,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()})
  if code!=expected:raise RuntimeError(f'{label}: HTTP {code}, expected {expected}: '+output.read_text()[:700])
  return json.loads(output.read_bytes())
 def get(label,route,**kw):return post(label,route,method='GET',**kw)
 def write(label,body):
  p=private/(label+'.json');p.write_text(json.dumps(body));return p
 def ref(c):return {'id':c['id'],'version':c['version'],'hash':c['definition_hash']}
 def decision(c):return {'definition_hash':c['definition_hash'],'expected_revision':c['revision']}
 def wfroute(c):return '/workflows/'+c['id']+'/'+str(c['version'])
 # Model runtimes, inference and malware scanners are not started by this test.
 policy_request={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':4096},{'name':'amount','type':'decimal','required':True,'max_bytes':64,'precision':12,'scale':2},{'name':'day','type':'date','required':True,'max_bytes':10}],'max_bytes':32<<20,'max_rows':1000000,'max_record_bytes':65536,'timeout_seconds':30}}
 pp=write('intake-policy',policy_request)
 policy=invoke('original-intake-policy-command','intake-policy-register','--request-file',pp,'--idempotency-key','policy')['resource']
 assert post('policy-idempotent-replay','/intake-policy',policy_request,key='policy')['resource']==policy
 post('unknown-executable-policy-field-refused','/intake-policy',dict(policy_request,run_shell='ignored'),400,key='bad-policy')
 old_header=private/'old.headers';old_header.write_bytes(b'Authorization: Bearer '+old_grants.read_bytes()+b'\n')
 other_header=private/'other.headers';other_header.write_bytes(b'Authorization: Bearer '+other.read_bytes()+b'\n')
 post('old-grants-cannot-administer-policy','/intake-policy',policy_request,403,key='old-policy',who=old_header)
 def upload(label,path,body):
  digest0=hashlib.sha256(body).hexdigest()
  result=post(label,'/namespace/file?'+urlencode({'path':path}),body,201,key=label,method='PUT',extra=['--header','X-File-Size: '+str(len(body)),'--header','X-Content-SHA256: '+digest0])
  assert result['acceptance']=='durable-held-pending-checks-and-release' and result['file']['policy']=='intake-csv-v1:'+policy['definition_hash']
  return result['file']
 held=upload('https-intake-held','/from-https.csv',data)
 get('held-raw-id-denied','/files/'+held['id'],expected=409)
 get('held-path-not-published','/namespace/stat?path=/from-https.csv',expected=404)
 post('ordinary-publish-cannot-bypass-hold','/namespace/commands',{'operation':'publish','path':'/bypass.csv','file_id':held['id']},409,key='bypass')
 get('other-actor-check-denied','/checks/'+held['id'],expected=404,who=other_header)
 post('old-grants-cannot-run-checks','/checks/'+held['id']+'/run',expected=403,key='old-run',who=old_header)
 app_port=free_port();app_host=private/'app-host';app_public=private/'app-host.pub'
 cli('ssh-host-keygen','--ssh-host-key-file',str(app_host),'--ssh-public-file',str(app_public))
 sender=private/'sender';command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(sender)])
 invoke('enroll-sftp-sender','ssh-key-enroll','--ssh-public-file',str(sender)+'.pub')
 username=invoke('sftp-sender-identity','identity')['ssh_username']
 app_trust=private/'app-known-hosts';app_trust.write_text(f'[127.0.0.1]:{app_port} '+app_public.read_text())
 app_args=[str(binary),'serve-sftp','--listen',f'127.0.0.1:{app_port}','--storage',str(storage),'--ssh-host-key-file',str(app_host),'--max-file-bytes',str(32<<20)]
 start('sftp',app_args,app_port)
 def sftp_batch(label,text,success=True):
  batch_file=private/(label+'.batch');batch_file.write_text(text+'\n')
  r=subprocess.run(['sftp','-F','/dev/null','-P',str(app_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(app_trust),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(sender),'-b',str(batch_file),username+'@127.0.0.1'],capture_output=True,timeout=40)
  (raw/(label+'.stdout')).write_bytes(r.stdout);(raw/(label+'.stderr')).write_bytes(r.stderr)
  steps.append({'name':label,'exit_code':r.returncode,'expected_success':success,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
  if (r.returncode==0)!=success:raise RuntimeError(label+': unexpected SFTP result '+r.stderr.decode(errors='replace')[:700])
 sftp_batch('stock-sftp-durable-held-upload',f'put -p {payload} /from-sftp.csv')
 retrieved=private/'received.csv'
 sftp_batch('stock-sftp-held-read-denied',f'get /from-sftp.csv {retrieved}',False)
 checks_list=invoke('private-cli-intake-list','check-list')['checks']
 sftp_file=next(c['file_id'] for c in checks_list if c.get('path')=='/from-sftp.csv')
 ticket=post('create-resumable-intake','/uploads',{'path':'/from-ticket.csv','expected_size':len(data),'expected_sha256':digest},201,key='ticket')['upload']
 offset=0
 while offset<len(data):
  chunk=data[offset:offset+(1<<20)]
  post('checkpoint-'+str(offset),'/uploads/'+ticket['id'],chunk,key='chunk-'+str(offset),method='PATCH',extra=['--header','Upload-Offset: '+str(offset),'--header','X-File-Size: '+str(len(chunk)),'--header','X-Content-SHA256: '+hashlib.sha256(chunk).hexdigest()]);offset+=len(chunk)
 complete=post('complete-resume-into-hold','/uploads/'+ticket['id']+'/complete',key='complete');assert complete['acceptance']=='durable-held-pending-checks-and-release'
 ticket_file=complete['file']['id'];all_files=[held['id'],sftp_file,ticket_file]
 stop('https');stop('sftp')
 https_args=[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key)]
 start('https',https_args,http_port);start('sftp',app_args,app_port)
 for index,fid in enumerate(all_files):assert get('held-after-restart-'+str(index),'/checks/'+fid)['check']['state']=='held'
 connection_request={'expected_version':0,'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'host_public_file':str(private/'receiver-host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}
 connection=invoke('register-ordinary-receiver','connection-register','--request-file',write('connection',connection_request),'--idempotency-key','connection')['resource']
 definition={'schema_version':1,'name':'checked settlement delivery','steps':[{'id':'send','kind':'sftp.deliver','connection':ref(connection),'filename':'checked.csv'}]}
 draft=post('ordinary-typed-draft','/workflows/drafts',{'expected_version':0,'definition':definition},key='draft')['resource']
 workflow=post('ordinary-workflow-approval',wfroute(draft)+'/approve',decision(draft),key='workflow-approve')['resource']
 post('held-workflow-dispatch-denied','/workflow-runs',{'workflow':ref(workflow),'file_id':held['id']},409,key='held-run')
 assert sql(f"SELECT count(*) FROM delivery_intents WHERE tenant_id='{tenant}'").strip()==b'0'
 def release_decision(c):return {'sha256':c['binding']['file']['sha256'],'policy_hash':c['policy_hash'],'report_hash':c['report_hash'],'expected_revision':c['revision']}
 for index,fid in enumerate(all_files):
  first=invoke('cli-bounded-check-'+str(index),'check-run','--file-id',fid,'--idempotency-key','parse-'+str(index))
  repeated=post('check-attempt-replay-'+str(index),'/checks/'+fid+'/run',key='parse-'+str(index));assert repeated['resource']==first['resource'] and repeated['replayed']
  c=get('checked-still-held-'+str(index),'/checks/'+fid)['check'];assert c['state']=='passed' and c['report']['rows']==65536 and c['report']['sha256']==digest
  get('passing-result-needs-release-'+str(index),'/files/'+fid,expected=409)
  bad=release_decision(c);bad['sha256']='0'*64
  post('wrong-byte-approval-denied-'+str(index),'/checks/'+fid+'/release',bad,409,key='wrong-'+str(index))
  released=invoke('cli-exact-release-'+str(index),'check-release','--file-id',fid,'--request-file',write('decision-'+str(index),release_decision(c)),'--idempotency-key','release-'+str(index))
  replay=post('release-replay-'+str(index),'/checks/'+fid+'/release',release_decision(c),key='release-'+str(index));assert replay['replayed'] and replay['resource']==released['resource']
 sftp_batch('stock-sftp-approved-exact-retrieval',f'get /from-sftp.csv {retrieved}');assert retrieved.read_bytes()==data
 run=post('ordinary-run-of-checked-bytes','/workflow-runs',{'workflow':ref(workflow),'file_id':held['id']},key='run')['resource']
 done=post('ordinary-delivery-of-checked-revision','/workflow-runs/'+run['id']+'/work',key='work');assert done['status']['run']['state']=='succeeded'
 target=inbox/(done['dispatch']['delivery_id']+'-checked.csv');assert target.read_bytes()==data
 batch_file=private/'independent-retrieval.batch';batch_file.write_text(f'get {target} {retrieved}\n')
 command(['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(private/'client'),'-b',str(batch_file),user+'@127.0.0.1'])
 assert retrieved.read_bytes()==data;steps.append({'name':'independent-stock-receiver-exact-bytes','size_bytes':len(data),'sha256':digest})
 bad_data=b'account,amount,day\nSYNTHETIC_PRIVATE_CELL,1e9,2026-10-28\n'
 bad_file=upload('invalid-content-held','/invalid.csv',bad_data)
 post('invalid-content-checked','/checks/'+bad_file['id']+'/run',key='invalid-run')
 rejected=get('invalid-content-remains-rejected','/checks/'+bad_file['id'])['check'];assert rejected['state']=='rejected' and 'SYNTHETIC_PRIVATE_CELL' not in json.dumps(rejected['report'])
 post('rejected-bytes-cannot-release','/checks/'+bad_file['id']+'/release',{'sha256':bad_file['sha256'],'policy_hash':rejected['policy_hash'],'report_hash':'0'*64,'expected_revision':rejected['revision']},409,key='invalid-release')
 get('rejected-raw-id-denied','/files/'+bad_file['id'],expected=409)
 # Pause one actual worker after its durable attempt becomes visible. A second
 # process must use the unchanged database lease budget; resuming the old owner
 # after its replacement succeeds must not overwrite the newer result.
 delayed_data=b'account,amount,day\n'+b'00000001,100.01,2026-10-28\n'*900000
 delayed=upload('delayed-worker-source','/delayed.csv',delayed_data)
 out=(raw/'delayed-worker.stdout').open('wb');errlog=(raw/'delayed-worker.stderr').open('wb')
 old_worker=subprocess.Popen(args('check-run','--file-id',delayed['id'],'--idempotency-key','delayed-attempt'),stdout=out,stderr=errlog);children.append(old_worker)
 paused=False
 for _ in range(150):
  poll=command(['curl','--silent','--show-error','--cacert',str(cert),'--max-time','3','--header','@'+str(header),f'https://127.0.0.1:{http_port}/v1/tenants/{tenant}/partners/{partner}/checks/'+delayed['id']])
  if json.loads(poll)['check']['state']=='running' and old_worker.poll() is None:
   os.kill(old_worker.pid,signal.SIGSTOP);paused=True;break
  if old_worker.poll() is not None:break
  time.sleep(.005)
 assert paused,'The exact worker finished before the native pause boundary could be observed'
 waiting=get('paused-worker-retains-durable-lease','/checks/'+delayed['id'])['check'];assert waiting['state']=='running' and waiting['attempts']==1
 post('live-lease-refuses-competing-worker','/checks/'+delayed['id']+'/run',expected=409,key='competing-live')
 before=time.monotonic();print('Waiting for the unchanged 70-second database lease on the exact paused worker.',flush=True)
 while sql(f"SELECT clock_timestamp()>=lease_until FROM file_checks WHERE tenant_id='{tenant}' AND file_id='{delayed['id']}'").strip()!=b't':
  if time.monotonic()-before>75:raise RuntimeError('real database lease did not expire within its published bound')
  time.sleep(2)
 replacement=invoke('expired-worker-replacement','check-run','--file-id',delayed['id'],'--idempotency-key','replacement')
 assert replacement['resource']['attempt']==2
 os.kill(old_worker.pid,signal.SIGCONT);old_worker.wait(timeout=10);out.close();errlog.close();assert old_worker.returncode!=0
 newer=get('stale-worker-cannot-overwrite-result','/checks/'+delayed['id'])['check'];assert newer['state']=='passed' and newer['attempts']==2 and newer['report']['rows']==900000
 selected=post('original-attempt-replay-never-reexecutes','/checks/'+delayed['id']+'/run',key='delayed-attempt');assert selected['replayed'] and selected['resource']['attempt']==1
 post('release-recovered-exact-revision','/checks/'+delayed['id']+'/release',release_decision(newer),key='release-recovered')
 steps.append({'name':'actual-paused-worker-fencing','old_exit_code':old_worker.returncode,'replacement_attempt':2,'lease_budget_seconds':70,'wait_seconds':round(time.monotonic()-before,3)})
 # Rotation affects controlled revisions and cannot make an old result current.
 queued_recheck_run=post('queue-original-before-policy-rotation','/workflow-runs',{'workflow':ref(workflow),'file_id':held['id']},key='queued-original-recheck')['resource']
 policy_request['expected_version']=1;policy_request['definition']['max_rows']=950000
 policy=post('rotate-exact-intake-policy','/intake-policy',policy_request,key='rotate')['resource']
 get('old-released-policy-now-stale','/files/'+held['id'],expected=409)
 sftp_batch('stock-sftp-stale-policy-denied',f'get /from-sftp.csv {retrieved}',False)
 assert not get('historical-check-view','/checks/'+held['id'])['current']
 from rechecks_journey import qualify_rechecks
 qualify_rechecks(locals())
 # Existing integrity-only revisions keep their original explicit scope; policy
 # registration controls new acceptance, not a retroactive malware verdict.
 legacy=command(['curl','--silent','--show-error','--fail','--cacert',str(cert),'--header','@'+str(header),f'https://127.0.0.1:{http_port}/v1/tenants/{tenant}/partners/{partner}/files/'+accepted['id']]);assert legacy==data
 steps.append({'name':'historical-integrity-only-scope-preserved','sha256':hashlib.sha256(legacy).hexdigest()})
 revoke={'definition_hash':policy['definition_hash'],'expected_version':policy['version'],'expected_revision':policy['revision']}
 post('revoke-intake-policy','/intake-policy/revoke',revoke,key='revoke')
 post('revocation-never-falls-back-to-unchecked-intake','/files',b'abc',409,key='after-revoke',extra=['--header','X-File-Size: 3','--header','X-Content-SHA256: '+hashlib.sha256(b'abc').hexdigest()])
 assert sql(f"SELECT count(*) FROM events WHERE tenant_id='{tenant}' AND payload::text LIKE '%SYNTHETIC_PRIVATE_CELL%'").strip()==b'0'
 state='passed';failure=None
except Exception:
 state='failed';failure=traceback.format_exc()
finally:
 for child in children:
  if child.poll() is None:child.kill();child.wait(timeout=5)
 for name in list(servers):stop(name)
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py','.js','.mjs','.ts','.tsx','.css','.html') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'state':state,'observed_at':datetime.now(timezone.utc).isoformat(),'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'duration_seconds':round(time.monotonic()-started,3),'payload_size_bytes':len(data),'payload_sha256':digest,'steps':steps,'failure':failure,'receiver':'Native stock OpenSSH 10.5p1, separate daemon and filesystem on the same macOS host','inference_performed':False,'local_model_processes_started':0,'malware_scanning_performed':False,'limits':['Bounded UTF-8 comma-separated CSV contract only; this is not antivirus, signature verification or a complete business-file workflow.','New acceptance uses configured policy; historical integrity-only revisions retain their original scope. No retroactive check verdict.','F025 adds actor-owned reviewed re-check revisions, actual copy-worker death/recovery and browser response-loss review. Genuine scanner re-enrollment/re-scan, delegated reviewers, automatic workers, retention/cleanup and full lifecycle remain open.','Local development storage and loopback SFTP with required sync/hardlink extensions. Transport integrity is not downstream business acceptance.','Assisted same-host fixture, not independent adoption, native Linux/Windows, HA, performance/endurance or full journey qualification.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/intake-current').write_text(str(raw)+'\n')
print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
raise SystemExit(0 if state=='passed' else 1)
