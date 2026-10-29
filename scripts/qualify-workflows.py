#!/usr/bin/env python3
"""Versioned typed workflow journey through real PostgreSQL, HTTPS/CLI and stock OpenSSH.

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
run_id='workflows-'+uuid.uuid4().hex
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
 inbox_b=private/'inbox-b';inbox_b.mkdir(mode=0o700)
 conn_request={'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'host_public_file':str(private/'receiver-host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub'),'expected_version':0}
 cp=write('connection',conn_request)
 connection=invoke('register-connection','connection-register','--request-file',cp,'--idempotency-key','register-connection')['resource']
 assert invoke('register-replay','connection-register','--request-file',cp,'--idempotency-key','register-connection')['replayed']
 visible=get('connection-redacted','/connections/'+connection['id']+'/1');assert visible==connection and 'key_reference' not in json.dumps(visible) and 'Wire' not in json.dumps(visible)
 definition={'schema_version':1,'name':'settlement delivery','steps':[{'id':'first','kind':'sftp.deliver','connection':ref(connection),'filename':'first.csv'},{'id':'second','kind':'sftp.deliver','connection':ref(connection),'filename':'second.csv'}]}
 preview_request={'definition':definition,'file_id':accepted['id']}
 events_before=sql(f"SELECT count(*) FROM events WHERE tenant_id='{tenant}'")
 stop('receiver')
 preview=post('offline-recipient-preview','/workflows/validate',preview_request);assert not preview['external_contact'] and preview['approval_required'] and len(preview['effects'])==2 and preview['source']['id']==accepted['id']
 pp=write('preview',preview_request);cli_preview=invoke('cli-shared-preview','workflow-validate','--request-file',pp);assert cli_preview==preview
 assert sql(f"SELECT count(*) FROM events WHERE tenant_id='{tenant}'")==events_before and list(inbox.iterdir())==[]
 start('receiver',['/usr/sbin/sshd','-D','-e','-f',str(config)],receiver_port)
 unsupported=json.loads(json.dumps(preview_request));unsupported['definition']['steps'][0]['kind']='shell.exec';post('unsupported-task-denied','/workflows/validate',unsupported,400)
 unsafe=json.loads(json.dumps(preview_request));unsafe['definition']['steps'][0]['key_file']='/unexpected/key';post('model-key-reference-denied','/workflows/validate',unsafe,400)
 raw_request=json.dumps(preview_request).replace('"filename": "first.csv"','"filename": "first.csv", "filename": "redirected.csv"').encode();post('duplicate-recipient-fields-denied','/workflows/validate',raw_request,400)
 post('oversized-definition-denied','/workflows/validate',b' '*(33<<10),400)
 draft=post('create-draft','/workflows/drafts',{'definition':definition,'expected_version':0},key='draft')['resource']
 assert draft['state']=='draft' and draft['definition_hash']==preview['definition_hash']
 assert post('draft-replay','/workflows/drafts',{'definition':definition,'expected_version':0},key='draft')['replayed']
 run_request={'workflow':ref(draft),'file_id':accepted['id']}
 post('unapproved-run-denied','/workflow-runs',run_request,409,key='unapproved')
 bad_decision=decision(draft);bad_decision['definition_hash']='0'*64
 post('wrong-approval-hash-denied',wfroute(draft)+'/approve',bad_decision,409,key='wrong-approval')
 approved=post('approve-workflow',wfroute(draft)+'/approve',decision(draft),key='approve')['resource'];assert approved['state']=='approved'
 assert post('approve-replay',wfroute(draft)+'/approve',decision(draft),key='approve')['replayed']
 run=post('start-run','/workflow-runs',run_request,key='run')['resource']
 assert post('run-idempotent-replay','/workflow-runs',run_request,key='run')['resource']==run
 state=get('queued-run-status','/workflow-runs/'+run['id']);assert len(state['steps'])==2 and state['observed_state']=='queued' and all(s['state']=='queued' and s['attempts']==0 for s in state['steps'])
 other_header=private/'other.headers';other_header.write_bytes(b'Authorization: Bearer '+other.read_bytes()+b'\n')
 get('other-actor-workflow-denied',wfroute(approved),expected=404,who=other_header)
 get('other-actor-run-denied','/workflow-runs/'+run['id'],expected=404,who=other_header)
 post('other-actor-connection-reference-denied','/workflows/validate',preview_request,404,who=other_header)
 for label,tid,pid in [('other-partner',tenant,str(uuid.uuid4())),('other-tenant',str(uuid.uuid4()),str(uuid.uuid4()))]:
  tok=private/(label+'.token');cli('token','--token-file',str(tok));cli('enroll','--tenant',tid,'--partner',pid,'--token-file',str(tok))
  hdr=private/(label+'.headers');hdr.write_bytes(b'Authorization: Bearer '+tok.read_bytes()+b'\n')
  get(label+'-workflow-denied',wfroute(approved),expected=404,who=hdr,scope_ids=(tid,pid))
  get(label+'-run-denied','/workflow-runs/'+run['id'],expected=404,who=hdr,scope_ids=(tid,pid))
 invoke('direct-later-step-denied','delivery-work','--delivery-id',state['steps'][1]['delivery_id'],success=False)
 # New definitions are versioned. The already queued run retains version one.
 next_connection=dict(conn_request,connection_id=connection['id'],expected_version=1,directory=str(inbox_b))
 cp2=write('connection-v2',next_connection);connection2=invoke('register-connection-v2','connection-register','--request-file',cp2,'--idempotency-key','register-v2')['resource'];assert connection2['version']==2
 definition2=json.loads(json.dumps(definition));definition2['name']='new destination draft'
 for step in definition2['steps']:step['connection']=ref(connection2)
 definition2['steps'][0]['filename']='revised.csv'
 draft2=post('new-workflow-version','/workflows/drafts',{'workflow_id':approved['id'],'expected_version':1,'definition':definition2},key='draft-v2')['resource'];assert draft2['version']==2 and draft2['state']=='draft'
 difference=get('review-version-diff',wfroute(draft2)+'/diff?against=1');assert difference['changed_steps']==['first','second'] and difference['name_changed'] and difference['before']==definition and difference['after']==definition2
 post('changed-draft-request-key-denied','/workflows/drafts',{'definition':definition2,'expected_version':0},409,key='draft')
 first=post('execute-first-step','/workflow-runs/'+run['id']+'/work',key='work-first');assert first['dispatch']['step_id']=='first' and first['status']['steps'][0]['state']=='succeeded' and first['status']['steps'][1]['state']=='queued'
 final1=inbox/(state['steps'][0]['delivery_id']+'-first.csv');final2=inbox/(state['steps'][1]['delivery_id']+'-second.csv')
 assert final1.read_bytes()==data and not final2.exists() and list(inbox_b.iterdir())==[]
 repeated=post('repeat-dispatch-cannot-advance','/workflow-runs/'+run['id']+'/work',key='work-first');assert repeated['replayed'] and repeated['dispatch']==first['dispatch'] and repeated['status']['steps'][1]['state']=='queued' and not final2.exists()
 stop('https');start('https',[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key)],http_port)
 repeated=invoke('restart-same-dispatch','workflow-work','--run-id',run['id'],'--idempotency-key','work-first');assert repeated['replayed'] and repeated['dispatch']==first['dispatch'] and not final2.exists()
 second=invoke('execute-second-step','workflow-work','--run-id',run['id'],'--idempotency-key','work-second');assert second['status']['run']['state']=='succeeded' and final2.read_bytes()==data and list(inbox_b.iterdir())==[]
 retrieved=private/'independent-sftp-retrieval.bin';batch=private/'retrieve.batch';batch.write_text(f'get {final1} {retrieved}\n')
 command(['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(private/'client'),'-b',str(batch),user+'@127.0.0.1'])
 assert retrieved.read_bytes()==data;steps.append({'name':'stock-sftp-independent-workflow-receipt','sha256':hashlib.sha256(retrieved.read_bytes()).hexdigest()})
 approved2=post('approve-new-version',wfroute(draft2)+'/approve',decision(draft2),key='approve-v2')['resource']
 run2=post('run-new-version','/workflow-runs',{'workflow':ref(approved2),'file_id':accepted['id']},key='run-v2')['resource']
 post('revoke-connection-version','/connections/'+connection2['id']+'/2/revoke',decision(connection2),key='revoke-connection-v2')
 post('revoked-connection-stops-run','/workflow-runs/'+run2['id']+'/work',expected=409,key='revoked-work')
 view2=get('revoked-connection-visible','/workflow-runs/'+run2['id']);assert view2['observed_reason']=='connection_revoked' and list(inbox_b.iterdir())==[]
 invoke('revoked-connection-direct-worker-denied','delivery-work','--delivery-id',view2['steps'][0]['delivery_id'],success=False)
 # An explicitly selected old approved version continues until it is revoked.
 queued=post('old-approved-version-still-explicit','/workflow-runs',run_request,key='old-explicit')['resource']
 post('revoke-workflow-version',wfroute(approved)+'/revoke',decision(approved),key='revoke-v1')
 post('revoked-workflow-stops-run','/workflow-runs/'+queued['id']+'/work',expected=409,key='revoked-workflow')
 view=get('revoked-workflow-visible','/workflow-runs/'+queued['id']);assert view['observed_reason']=='workflow_not_approved'
 invoke('revoked-workflow-direct-worker-denied','delivery-work','--delivery-id',view['steps'][0]['delivery_id'],success=False)
 # Reuse active connection v1 in a newly reviewed workflow version.
 draft3=post('recovery-draft','/workflows/drafts',{'workflow_id':approved['id'],'expected_version':2,'definition':definition},key='draft-v3')['resource']
 approved3=post('approve-recovery-version',wfroute(draft3)+'/approve',decision(draft3),key='approve-v3')['resource']
 request3={'workflow':ref(approved3),'file_id':accepted['id']}
 uncertain=post('uncertain-run','/workflow-runs',request3,key='uncertain-run')['resource'];uv=get('uncertain-run-intents','/workflow-runs/'+uncertain['id'])
 first_id,second_id=[s['delivery_id'] for s in uv['steps']]
 fault(first_id,"IF NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned workflow receipt commit failure'; END IF;")
 post('workflow-remote-success-local-failure','/workflow-runs/'+uncertain['id']+'/work',expected=503,key='uncertain-first')
 assert (inbox/(first_id+'-first.csv')).read_bytes()==data and not (inbox/(second_id+'-second.csv')).exists();drop_fault()
 invoke('ambiguous-predecessor-direct-skip-denied','delivery-work','--delivery-id',second_id,success=False)
 remaining=max(0,float(sql(f"SELECT extract(epoch FROM lease_until-clock_timestamp()) FROM delivery_intents WHERE tenant_id='{tenant}' AND delivery_id='{first_id}'").decode().strip()))
 if remaining:time.sleep(remaining+.2)
 ambiguous=post('same-dispatch-recovers-as-ambiguous','/workflow-runs/'+uncertain['id']+'/work',key='uncertain-first');assert ambiguous['replayed'] and ambiguous['dispatch']['delivery_id']==first_id and ambiguous['status']['observed_state']=='attention'
 invoke('read-only-workflow-receipt-recovery','delivery-reconcile','--delivery-id',first_id)
 repeated=post('recovered-dispatch-still-does-not-advance','/workflow-runs/'+uncertain['id']+'/work',key='uncertain-first');assert repeated['status']['steps'][0]['state']=='succeeded' and repeated['status']['steps'][1]['state']=='queued' and not (inbox/(second_id+'-second.csv')).exists()
 fault_run(uncertain['id'])
 post('delivery-complete-run-projection-fails','/workflow-runs/'+uncertain['id']+'/work',expected=503,key='uncertain-second')
 lagging=get('exact-receipts-survive-projection-failure','/workflow-runs/'+uncertain['id']);assert lagging['run']['state']=='running' and lagging['observed_state']=='succeeded' and (inbox/(second_id+'-second.csv')).read_bytes()==data
 post('completed-run-cannot-be-relabelled-cancelled','/workflow-runs/'+uncertain['id']+'/cancel',{'definition_hash':lagging['run']['workflow_hash'],'expected_revision':lagging['run']['revision']},409,key='invalid-late-cancel')
 drop_fault()
 completed=post('fresh-dispatch-after-recovery','/workflow-runs/'+uncertain['id']+'/work',key='uncertain-second');assert completed['replayed'] and completed['status']['run']['state']=='succeeded' and (inbox/(second_id+'-second.csv')).read_bytes()==data
 cancelled=post('cancel-queued-run','/workflow-runs',request3,key='cancel-run')['resource']
 cancel_decision={'definition_hash':cancelled['workflow_hash'],'expected_revision':cancelled['revision']}
 cancel_result=post('cancel-run-decision','/workflow-runs/'+cancelled['id']+'/cancel',cancel_decision,key='cancel')['resource'];assert cancel_result['run']['state']=='cancelled' and all(s['state']=='cancelled' for s in cancel_result['steps'])
 assert post('cancel-idempotent-replay','/workflow-runs/'+cancelled['id']+'/cancel',cancel_decision,key='cancel')['replayed']
 post('cancelled-run-does-not-execute','/workflow-runs/'+cancelled['id']+'/work',expected=409,key='cancelled-work')
 invoke('cancelled-direct-worker-denied','delivery-work','--delivery-id',cancel_result['steps'][0]['delivery_id'],success=False)
 # A draft editor has no approval or execution grant, even for its own references.
 editor=identity('editor');editor_cp=write('editor-connection',conn_request)
 editor_conn=invoke('editor-register-before-restriction','connection-register','--request-file',editor_cp,'--idempotency-key','editor-conn',token=editor)['resource']
 editor_header=private/'editor.headers';editor_header.write_bytes(b'Authorization: Bearer '+editor.read_bytes()+b'\n')
 info=json.loads(cli('identity','--tenant',tenant,'--partner',partner,'--token-file',str(editor)))
 sql(f"UPDATE credentials SET permissions=ARRAY['read','workflow_manage','deliver']::text[] WHERE tenant_id='{tenant}' AND partner_id='{partner}' AND actor_id='{info['actor_id']}'")
 editor_def=json.loads(json.dumps(definition));
 for step in editor_def['steps']:step['connection']=ref(editor_conn)
 editor_draft=post('editor-can-draft','/workflows/drafts',{'definition':editor_def,'expected_version':0},key='editor-draft',who=editor_header)['resource']
 post('editor-cannot-approve',wfroute(editor_draft)+'/approve',decision(editor_draft),403,key='editor-approve',who=editor_header)
 post('editor-cannot-execute','/workflow-runs',{'workflow':ref(editor_draft),'file_id':accepted['id']},403,key='editor-run',who=editor_header)
 # Revoking any referenced connection freezes the same run through both entry
 # points, even after the step using that credential has already completed.
 cp3=write('connection-v3',dict(conn_request,connection_id=connection['id'],expected_version=2,directory=str(inbox_b)))
 connection3=invoke('register-connection-v3','connection-register','--request-file',cp3,'--idempotency-key','register-v3')['resource']
 mixed=json.loads(json.dumps(definition));mixed['name']='mixed connection review';mixed['steps'][1]['connection']=ref(connection3)
 draft4=post('mixed-connections-draft','/workflows/drafts',{'workflow_id':approved['id'],'expected_version':3,'definition':mixed},key='mixed-draft')['resource']
 approved4=post('approve-mixed-connections',wfroute(draft4)+'/approve',decision(draft4),key='mixed-approve')['resource']
 mixed_run=post('mixed-connection-run','/workflow-runs',{'workflow':ref(approved4),'file_id':accepted['id']},key='mixed-run')['resource']
 mixed_first=post('mixed-first-completes','/workflow-runs/'+mixed_run['id']+'/work',key='mixed-first');assert mixed_first['status']['steps'][0]['state']=='succeeded'
 post('revoke-already-used-connection','/connections/'+connection['id']+'/1/revoke',decision(connection),key='revoke-used-v1')
 invoke('whole-plan-revocation-direct-step-denied','delivery-work','--delivery-id',mixed_first['status']['steps'][1]['delivery_id'],success=False)
 post('whole-plan-revocation-workflow-denied','/workflow-runs/'+mixed_run['id']+'/work',expected=409,key='mixed-second')
 assert get('historic-success-survives-connection-revocation','/workflow-runs/'+uncertain['id'])['observed_state']=='succeeded'
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
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'state':state,'observed_at':datetime.now(timezone.utc).isoformat(),'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'failure':failure,'receiver':'native stock OpenSSH 10.5p1; separate daemon and filesystem, same macOS machine','limits':['loopback development profile','synthetic 2 MiB payload','OpenSSH fsync and atomic hardlink extensions required','file integrity observation is not downstream business acceptance','same-host operator-assisted experiment; no independent adoption or enterprise qualification','ordered sftp.deliver steps only; schedules, branching, visual UI and processing remain open','ordinary execution has no model dependency; no AI capability is qualified']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/workflow-current').write_text(str(raw)+'\n')
print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
raise SystemExit(0 if state=='passed' else 1)
