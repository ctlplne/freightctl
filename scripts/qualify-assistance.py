#!/usr/bin/env python3
"""No-inference assistance control journey: real PostgreSQL/HTTPS/CLI and a tiny JSON test peer.

Only synthetic bytes and loopback traffic. Fault triggers affect this run's exact
tenant/intent and are removed in finally. No system SSH configuration is changed.
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

os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
run_id='assistance-contract-'+uuid.uuid4().hex
private=root/'.private'/run_id;private.mkdir(mode=0o700)
raw=root/'evidence/raw'/run_id;raw.mkdir(parents=True,mode=0o700)
binary=root/'.cache/freightctl';servers={};logs={};children=[];steps=[];started=time.monotonic()
owned_database=False
fault_name='freightctl_workflow_test_'+uuid.uuid4().hex
run_fault_name=fault_name+'_run'
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
def drop_fault():
 if not owned_database:return
 sql(f'DROP TRIGGER IF EXISTS {fault_name} ON delivery_intents; DROP FUNCTION IF EXISTS {fault_name}()')
 sql(f'DROP TRIGGER IF EXISTS {run_fault_name} ON workflow_runs; DROP FUNCTION IF EXISTS {run_fault_name}()')
def fault(delivery_id,body):
 # All identifiers/selectors below are generated UUIDs, never partner text.
 drop_fault()
 sql(f"CREATE FUNCTION {fault_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.delivery_id='{delivery_id}'::uuid THEN {body} END IF; RETURN NEW; END $$; CREATE TRIGGER {fault_name} BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION {fault_name}()")
def fault_run(run_id):
 drop_fault()
 sql(f"CREATE FUNCTION {run_fault_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.run_id='{run_id}'::uuid AND NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned workflow projection commit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {run_fault_name} BEFORE UPDATE ON workflow_runs FOR EACH ROW EXECUTE FUNCTION {run_fault_name}()")
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
 data=(b'synthetic outbound settlement,0001,42.00\n'*100000)[:2<<20]
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
 def post(label,route,body=None,expected=200,key=None,who=None,method='POST',scope_ids=None):
  output=raw/(label+'.out');args0=['curl','--silent','--show-error','--cacert',str(cert),'--max-time','30','--header','@'+str(who or header),'--request',method,'--output',str(output),'--write-out','%{http_code}']
  if key:args0+=['--header','Idempotency-Key: '+key]
  if body is not None:
   request=private/(label+'.request.json');request.write_bytes(body if isinstance(body,bytes) else json.dumps(body).encode());args0+=['--header','Content-Type: application/json','--data-binary','@'+str(request)]
  scope_tenant,scope_partner=scope_ids or (tenant,partner)
  code=int(command([*args0,f'https://127.0.0.1:{http_port}/v1/tenants/{scope_tenant}/partners/{scope_partner}'+route]))
  steps.append({'name':label,'http_status':code,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()})
  if code!=expected:raise RuntimeError(f'{label}: HTTP {code}, expected {expected}: '+output.read_text()[:700])
  return json.loads(output.read_bytes())
 def get(label,route,**kw):return post(label,route,method='GET',**kw)
 def write(label,body):
  p=private/(label+'.json');p.write_text(json.dumps(body));return p
 def ref(c):return {'id':c['id'],'version':c['version'],'hash':c['definition_hash']}
 def decision(c):return {'definition_hash':c['definition_hash'],'expected_revision':c['revision']}
 def wfroute(c):return '/workflows/'+c['id']+'/'+str(c['version'])
 # This responder is a small protocol test peer. It has no weights, inference
 # libraries, runtime launcher or connection to any installed model server.
 import http.server,threading
 peer_state={'mode':'ready','calls':[],'last_context':None}
 class JsonPeer(http.server.BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def reply(self,data):
   b=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
  def do_GET(self):
   peer_state['calls'].append(self.path)
   self.reply({'models':[{'name':'freightctl-contract-peer','digest':'a'*64}]})
  def do_POST(self):
   peer_state['calls'].append(self.path);n=int(self.headers.get('Content-Length','0'));assert n<32<<10
   request=json.loads(self.rfile.read(n));assert request['think'] is False and request['stream'] is False and request['keep_alive']==0
   prompt=request['prompt'];assert 'SYNTHETIC_SECRET' not in prompt and 'recipient-sensitive.csv' not in prompt and 'key_reference' not in prompt
   context=json.loads(prompt.split('CONTEXT:\n',1)[1].split('\nSCHEMA:',1)[0]);peer_state['last_context']=context
   if peer_state['mode']=='inject':output={'status':'ready','order':['outside'],'missing':[],'approved':True}
   elif peer_state['mode']=='forge':output={'code':'transport_complete','evidence':['forged'],'next_check':'obtain_business_receipt'}
   elif context['kind']=='propose':output={'status':'ready','order':list(reversed(context['destinations'])),'missing':[]}
   else:
    finding=context['supported_findings'][0] if context.get('supported_findings') else {'code':'insufficient_evidence','evidence':[],'next_check':'gather_evidence'}
    output={'code':finding['code'],'evidence':finding['evidence'],'next_check':finding['next_check']}
   self.reply({'model':'freightctl-contract-peer','response':json.dumps(output),'thinking':'SYNTHETIC_THOUGHT_NOT_FOR_OUTPUT','done':True,'done_reason':'stop','eval_count':40,'prompt_eval_count':100})
 json_peer=http.server.ThreadingHTTPServer(('127.0.0.1',0),JsonPeer);json_thread=threading.Thread(target=json_peer.serve_forever,daemon=True);json_thread.start()
 profile_request={'expected_version':0,'definition':{'schema_version':1,'endpoint':'http://127.0.0.1:'+str(json_peer.server_port),'model':'freightctl-contract-peer','model_digest':'a'*64,'tokenizer_digest':'b'*64,'allow_operator_text':True,'allow_remote':False,'context_bytes':8192,'context_tokens':4096,'output_tokens':512,'timeout_seconds':3}}
 pp=write('synthetic-profile',profile_request)
 profile=invoke('register-synthetic-profile','ai-profile-register','--request-file',pp,'--idempotency-key','profile')['resource']
 assert not peer_state['calls']
 conn_request={'expected_version':0,'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'host_public_file':str(private/'receiver-host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}
 cp=write('connection',conn_request);connection=invoke('register-ordinary-connection','connection-register','--request-file',cp,'--idempotency-key','connection')['resource']
 request={'profile':ref(profile),'kind':'propose','name':'private workflow label','requirements':'Send the selected file. password=SYNTHETIC_SECRET','destinations':[{'connection':ref(connection),'filename':'recipient-sensitive.csv'}]}
 post('unknown-authority-field-is-client-error','/ai/jobs',dict(request,approved=True),400,key='bad-field')
 post('duplicate-kind-is-client-error','/ai/jobs',b'{"kind":"propose","kind":"diagnose"}',400,key='duplicate-kind')
 post('oversized-context-is-client-error','/ai/jobs',b' '*(33<<10),400,key='oversized-context')
 assert not peer_state['calls']
 job=post('prepare-proposal-context','/ai/jobs',request,key='prepare')['resource']
 assert job['state']=='prepared' and not peer_state['calls'] and 'SYNTHETIC_SECRET' not in json.dumps(job) and 'recipient-sensitive.csv' not in json.dumps(job['context'])
 assert post('prepare-idempotent-replay','/ai/jobs',request,key='prepare')['resource']==job
 post('disabled-generation-no-contact','/ai/jobs/'+job['id']+'/generate',expected=503,key='disabled')
 invoke('cli-disabled-generation-no-contact','ai-generate','--ai-job-id',job['id'],'--idempotency-key','cli-disabled',success=False)
 assert not peer_state['calls']
 wrong={'context_hash':'0'*64,'expected_revision':1};post('wrong-disclosure-hash-denied','/ai/jobs/'+job['id']+'/approve',wrong,409,key='wrong')
 decision0={'context_hash':job['context_hash'],'expected_revision':1}
 approved=post('approve-exact-context','/ai/jobs/'+job['id']+'/approve',decision0,key='approve')['resource'];assert approved['state']=='approved' and not peer_state['calls']
 assert post('disclosure-approval-replay','/ai/jobs/'+job['id']+'/approve',decision0,key='approve')['replayed']
 # Enable endpoint requests only against the above synthetic peer. No model is
 # available to this test, and no runtime start/load/pull operation exists.
 stop('https');start('https',[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key),'--ai-enabled'],http_port)
 generated=post('generate-json-contract-response','/ai/jobs/'+job['id']+'/generate',key='generate')['job'];assert generated['state']=='succeeded' and generated['result']['proposal']['status']=='ready'
 calls=len(peer_state['calls']);again=post('generation-replay-no-second-request','/ai/jobs/'+job['id']+'/generate',key='generate');assert again['replayed'] and len(peer_state['calls'])==calls
 assert 'SYNTHETIC_THOUGHT' not in json.dumps(generated)
 adoption={'context_hash':job['context_hash'],'expected_revision':generated['revision']}
 draft=post('adopt-only-an-unapproved-draft','/ai/jobs/'+job['id']+'/adopt',adoption,key='adopt')['resource'];assert draft['state']=='draft' and draft['approval_authority']==0
 assert post('adoption-idempotent-replay','/ai/jobs/'+job['id']+'/adopt',adoption,key='adopt')['resource']==draft
 assert sql(f"SELECT count(*) FROM workflow_runs WHERE tenant_id='{tenant}'").strip()==b'0'
 assert sql(f"SELECT count(*) FROM events WHERE tenant_id='{tenant}' AND payload::text LIKE '%SYNTHETIC_SECRET%'").strip()==b'0'
 wfroute='/workflows/'+draft['id']+'/1'
 approved_workflow=post('ordinary-human-workflow-approval',wfroute+'/approve',{'definition_hash':draft['definition_hash'],'expected_revision':draft['revision']},key='ordinary-approve')['resource']
 # Existing transfers still execute after restarting with assistance disabled.
 stop('https');start('https',[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key)],http_port)
 run=post('ordinary-run-with-assistance-off','/workflow-runs',{'workflow':ref(approved_workflow),'file_id':accepted['id']},key='ordinary-run')['resource']
 completed=post('ordinary-dispatch-with-assistance-off','/workflow-runs/'+run['id']+'/work',key='ordinary-work');assert completed['status']['run']['state']=='succeeded'
 target=inbox/(completed['dispatch']['delivery_id']+'-recipient-sensitive.csv');assert target.read_bytes()==data
 output=private/'independent-retrieval.bin';batch=private/'retrieve.batch';batch.write_text(f'get {target} {output}\n')
 command(['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(private/'client'),'-b',str(batch),user+'@127.0.0.1'])
 assert output.read_bytes()==data and len(peer_state['calls'])==calls;steps.append({'name':'stock-sftp-receipt-with-assistance-off','sha256':hashlib.sha256(output.read_bytes()).hexdigest()})
 post('completed-generation-disabled-by-default','/ai/jobs/'+job['id']+'/generate',expected=503,key='still-disabled');assert len(peer_state['calls'])==calls
 stop('https');start('https',[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key),'--ai-enabled'],http_port)
 injected=post('prepare-injection-contract','/ai/jobs',request,key='injection-prepare')['resource']
 post('approve-injection-test-context','/ai/jobs/'+injected['id']+'/approve',{'context_hash':injected['context_hash'],'expected_revision':1},key='injection-approve')
 peer_state['mode']='inject';rejected=post('reject-authority-recipient-injection','/ai/jobs/'+injected['id']+'/generate',key='injection-generate')['job'];assert rejected['state']=='rejected' and rejected['result']=={}
 post('rejected-output-cannot-be-adopted','/ai/jobs/'+injected['id']+'/adopt',{'context_hash':injected['context_hash'],'expected_revision':rejected['revision']},409,key='injection-adopt');peer_state['mode']='ready'
 diagnosis_request={'profile':ref(profile),'kind':'diagnose','run_id':run['id']}
 diagnosis=post('prepare-redacted-diagnostic-evidence','/ai/jobs',diagnosis_request,key='diagnosis-prepare')['resource'];assert 'recipient-sensitive.csv' not in json.dumps(diagnosis['context']) and run['id'] not in json.dumps(diagnosis['context'])
 post('approve-diagnostic-context','/ai/jobs/'+diagnosis['id']+'/approve',{'context_hash':diagnosis['context_hash'],'expected_revision':1},key='diagnosis-approve')
 diagnosed=post('validate-supported-diagnostic-selection','/ai/jobs/'+diagnosis['id']+'/generate',key='diagnosis-generate')['job'];assert diagnosed['state']=='succeeded' and diagnosed['result']['diagnosis']['code']=='transport_complete' and 'unknown' in diagnosed['result']['explanation']
 for index,cite in enumerate(diagnosed['result']['citations']):
  observed=get('resolve-event-citation-'+str(index),'/ai/jobs/'+diagnosis['id']+'/evidence/'+cite['event_id']);assert observed==cite
 get('forged-event-citation-denied','/ai/jobs/'+diagnosis['id']+'/evidence/'+str(uuid.uuid4()),expected=404)
 other_header=private/'other.headers';other_header.write_bytes(b'Authorization: Bearer '+other.read_bytes()+b'\n')
 get('other-actor-context-denied','/ai/jobs/'+diagnosis['id'],expected=404,who=other_header)
 get('other-actor-profile-denied','/ai/profiles/'+profile['id']+'/1',expected=404,who=other_header)
 pending=post('queued-run-for-stale-evidence','/workflow-runs',{'workflow':ref(approved_workflow),'file_id':accepted['id']},key='queued-run')['resource']
 forged=post('prepare-forged-diagnosis-contract','/ai/jobs',{'profile':ref(profile),'kind':'diagnose','run_id':pending['id']},key='forge-prepare')['resource']
 post('approve-forged-diagnosis-context','/ai/jobs/'+forged['id']+'/approve',{'context_hash':forged['context_hash'],'expected_revision':1},key='forge-approve')
 peer_state['mode']='forge';bad=post('reject-unsupported-completion-and-citation','/ai/jobs/'+forged['id']+'/generate',key='forge-generate')['job'];assert bad['state']=='rejected' and bad['result']=={};peer_state['mode']='ready'
 stale=post('prepare-before-run-change','/ai/jobs',{'profile':ref(profile),'kind':'diagnose','run_id':pending['id']},key='stale-prepare')['resource']
 post('approve-before-run-change','/ai/jobs/'+stale['id']+'/approve',{'context_hash':stale['context_hash'],'expected_revision':1},key='stale-approve')
 post('ordinary-run-cancellation-changes-evidence','/workflow-runs/'+pending['id']+'/cancel',{'definition_hash':pending['workflow_hash'],'expected_revision':pending['revision']},key='cancel-pending')
 before=len(peer_state['calls']);post('stale-context-denied-before-contact','/ai/jobs/'+stale['id']+'/generate',expected=409,key='stale-generate');assert len(peer_state['calls'])==before
 assert not get('stale-context-marked-historical','/ai/jobs/'+stale['id'])['current']
 invoke('revoke-profile-without-contact','ai-profile-revoke','--ai-profile-id',profile['id'],'--version',1,'--definition-hash',profile['definition_hash'],'--expected-revision',1,'--idempotency-key','profile-revoke')
 post('revoked-profile-denied-before-contact','/ai/jobs/'+job['id']+'/generate',expected=409,key='revoked-profile');assert len(peer_state['calls'])==before
 assert sql(f"SELECT count(*) FROM events WHERE tenant_id='{tenant}' AND payload::text LIKE '%SYNTHETIC_THOUGHT%'").strip()==b'0'
 steps.append({'name':'synthetic-peer-only','http_requests':len(peer_state['calls']),'inference_performed':False,'model_processes_started':0})
 state='passed';failure=None
except Exception:
 state='failed';failure=traceback.format_exc()
finally:
 for p in children:
  if p.poll() is None:p.kill();p.wait(timeout=5)
 try:drop_fault()
 except Exception:
  if 'failure' not in globals() or failure is None:state='failed';failure=traceback.format_exc()
 for name in list(servers):stop(name)
 if 'json_peer' in globals():json_peer.shutdown();json_peer.server_close();json_thread.join(timeout=3)
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'state':state,'observed_at':datetime.now(timezone.utc).isoformat(),'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'failure':failure,'receiver':'native stock OpenSSH 10.5p1; separate daemon and filesystem, same macOS machine','inference_performed':False,'peer_type':'tiny synthetic JSON responder, not a model','local_model_processes_started':0,'limits':['No model was started, loaded, warmed or evaluated. These are transport/governance contracts, not AI quality or profile qualification.','loopback development profile','synthetic 2 MiB payload','OpenSSH fsync and atomic hardlink extensions required','file integrity observation is not downstream business acceptance','same-host operator-assisted experiment; no independent adoption or enterprise qualification','ordered sftp.deliver steps only; schedules, branching, visual UI and processing remain open','ordinary execution has no model dependency; no AI capability is qualified']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/assistance-current').write_text(str(raw)+'\n')
print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
raise SystemExit(0 if state=='passed' else 1)
