#!/usr/bin/env python3
"""Real PostgreSQL, freightctl HTTPS/CLI, and a task-owned stock OpenSSH receiver.

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
run_id='deliveries-'+uuid.uuid4().hex
private=root/'.private'/run_id;private.mkdir(mode=0o700)
raw=root/'evidence/raw'/run_id;raw.mkdir(parents=True,mode=0o700)
binary=root/'.cache/freightctl';servers={};logs={};children=[];steps=[];started=time.monotonic()
owned_database=False
fault_name='freightctl_delivery_test_'+uuid.uuid4().hex
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
def fault(delivery_id,body):
 # All identifiers/selectors below are generated UUIDs, never partner text.
 drop_fault()
 sql(f"CREATE FUNCTION {fault_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.delivery_id='{delivery_id}'::uuid THEN {body} END IF; RETURN NEW; END $$; CREATE TRIGGER {fault_name} BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION {fault_name}()")
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
 def create(label,changes=None):
  request={'file_id':accepted['id'],'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'filename':label+'.bin','host_public_file':str(private/'receiver-host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}
  request.update(changes or {});path=private/(label+'.json');path.write_text(json.dumps(request))
  result=invoke(label,'delivery-create','--request-file',path,'--idempotency-key',label)
  return result['delivery'],path
 def action(label,d,action='approve',**kw):
  return invoke(label,'delivery-'+action,'--delivery-id',d['id'],'--definition-hash',d['definition_hash'],'--expected-revision',d['revision'],'--idempotency-key',label,**kw)
 def status(label,d):return invoke(label,'delivery-status','--delivery-id',d['id'])
 def final(d):return inbox/(d['id']+'-'+json.loads(json.dumps(d['definition']))['filename'])
 d,request=create('delivery');assert d['state']=='draft' and list(inbox.iterdir())==[]
 replay=invoke('create-replay','delivery-create','--request-file',request,'--idempotency-key','delivery');assert replay['replayed'] and replay['delivery']==d
 invoke('other-actor-denied','delivery-status','--delivery-id',d['id'],success=False,token=other)
 invoke('legacy-grants-denied','delivery-status','--delivery-id',d['id'],success=False,token=old_grants)
 invoke('unapproved-worker-denied','delivery-work','--delivery-id',d['id'],success=False)
 invoke('wrong-approval-denied','delivery-approve','--delivery-id',d['id'],'--definition-hash','0'*64,'--expected-revision',1,'--idempotency-key','wrong',success=False)
 approved=action('approve',d)['delivery'];assert approved['state']=='queued'
 assert action('approve',d)['replayed']
 p1=subprocess.Popen(args('delivery-work','--delivery-id',d['id']),stdout=(raw/'worker-a.stdout').open('wb'),stderr=(raw/'worker-a.stderr').open('wb'));children.append(p1)
 p2=subprocess.Popen(args('delivery-work','--delivery-id',d['id']),stdout=(raw/'worker-b.stdout').open('wb'),stderr=(raw/'worker-b.stderr').open('wb'));children.append(p2)
 exits=[p1.wait(timeout=100),p2.wait(timeout=100)];assert sorted(exits)==[0,1],exits
 steps.append({'name':'two-processes-one-intent','exit_codes':exits})
 delivered=status('delivery-status',d);assert delivered['state']=='succeeded' and delivered['fence']==1
 assert final(d).read_bytes()==data and delivered['observation']['business_acceptance']=='unknown'
 received=private/'independent-retrieval.bin';batch=private/'retrieve.batch';batch.write_text(f'get {final(d)} {received}\n')
 command(['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(private/'client'),'-b',str(batch),user+'@127.0.0.1'])
 assert received.read_bytes()==data;steps.append({'name':'stock-openssh-independent-retrieval','sha256':hashlib.sha256(received.read_bytes()).hexdigest()})
 invoke('repeat-worker-no-resend','delivery-work','--delivery-id',d['id'],success=False)
 changed=json.loads(request.read_text());changed['filename']='retargeted.bin';request.write_text(json.dumps(changed))
 invoke('changed-key-meaning-denied','delivery-create','--request-file',request,'--idempotency-key','delivery',success=False)
 bad,bad_request=create('changed-host',{'host_public_file':str(private/'other-host.pub')});action('approve-changed-host',bad)
 denied=invoke('changed-host-no-bytes','delivery-work','--delivery-id',bad['id']);assert denied['state']=='retry' and denied['observation']['code']=='receiver_connection_failed' and not final(bad).exists()
 collision,_=create('collision');action('approve-collision',collision);final(collision).write_bytes(b'preexisting unrelated bytes')
 blocked=invoke('collision-no-overwrite','delivery-work','--delivery-id',collision['id']);assert blocked['state']=='blocked' and final(collision).read_bytes()==b'preexisting unrelated bytes'
 unsafe=private/'directory-link';unsafe.symlink_to(inbox,target_is_directory=True)
 bad,_=create('unsafe-directory',{'directory':str(unsafe)});action('approve-unsafe-directory',bad)
 denied=invoke('symlink-directory-denied','delivery-work','--delivery-id',bad['id']);assert denied['state']=='retry' and denied['observation']['code']=='receiver_directory_unsafe'
 changed['directory']=str(inbox)+'/../inbox';bad_request.write_text(json.dumps(changed));invoke('traversal-denied','delivery-create','--request-file',bad_request,'--idempotency-key','traversal',success=False)
 wrong_store=private/'wrong-store';wrong_store.mkdir(mode=0o700);marker=wrong_store/'.freightctl-storage-id';marker.write_text(str(uuid.uuid4()));marker.chmod(0o400)
 pending,_=create('wrong-store');action('approve-wrong-store',pending)
 invoke('storage-identity-denied','delivery-work','--delivery-id',pending['id'],'--storage',wrong_store,success=False);assert status('wrong-store-still-queued',pending)['state']=='queued'
 # Kill the exact worker before publication while a task-only trigger delays that transition.
 crash,_=create('stage-crash');action('approve-stage-crash',crash)
 fault(crash['id'],"IF NEW.state='publishing' THEN PERFORM pg_sleep(20); END IF;")
 child=subprocess.Popen(args('delivery-work','--delivery-id',crash['id']),stdout=(raw/'crash-worker.stdout').open('wb'),stderr=(raw/'crash-worker.stderr').open('wb'));children.append(child)
 deadline=time.monotonic()+12
 while time.monotonic()<deadline:
  matches=list(inbox.glob('.freightctl-'+crash['id']+'-*.partial'))
  if matches and matches[0].stat().st_size==len(data):break
  if child.poll() is not None:raise RuntimeError('worker ended before staging crash')
  time.sleep(.02)
 assert matches and not final(crash).exists();child.kill();child.wait(timeout=5);drop_fault()
 staged=status('after-stage-process-kill',crash);assert staged['state']=='staging'
 steps.append({'name':'actual-process-kill-unpublished','exit_code':child.returncode,'fence':staged['fence']})
 remaining=max(0,float(sql(f"SELECT extract(epoch FROM lease_until-clock_timestamp()) FROM delivery_intents WHERE tenant_id='{tenant}' AND delivery_id='{crash['id']}'").decode().strip()))
 if remaining:time.sleep(remaining+.2)
 resumed=invoke('recover-expired-stage','delivery-work','--delivery-id',crash['id']);assert resumed['state']=='succeeded' and resumed['fence']==2 and final(crash).read_bytes()==data
 assert matches[0].exists();steps.append({'name':'old-stage-retained-new-fence-published','fence':resumed['fence']})
 # Refuse just this intent's final DB update AFTER the independent peer has bytes.
 uncertain,_=create('commit-uncertain');action('approve-uncertain',uncertain)
 fault(uncertain['id'],"IF NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned simulated receipt commit failure'; END IF;")
 invoke('remote-published-local-commit-fails','delivery-work','--delivery-id',uncertain['id'],success=False)
 assert final(uncertain).read_bytes()==data
 publishing=status('recorded-publishing-after-failure',uncertain);assert publishing['state']=='publishing';drop_fault()
 invoke('live-publishing-cannot-resend','delivery-work','--delivery-id',uncertain['id'],success=False)
 remaining=max(0,float(sql(f"SELECT extract(epoch FROM lease_until-clock_timestamp()) FROM delivery_intents WHERE tenant_id='{tenant}' AND delivery_id='{uncertain['id']}'").decode().strip()))
 if remaining:time.sleep(remaining+.2)
 ambiguous=invoke('expired-publication-is-ambiguous','delivery-work','--delivery-id',uncertain['id']);assert ambiguous['state']=='ambiguous' and ambiguous['fence']==publishing['fence']
 held=private/'receiver-consumed-or-moved.bin';final(uncertain).rename(held)
 missing=invoke('missing-receipt-stays-ambiguous','delivery-reconcile','--delivery-id',uncertain['id']);assert missing['state']=='ambiguous' and not final(uncertain).exists()
 held.rename(final(uncertain))
 reconciled=invoke('read-only-exact-receipt-recovery','delivery-reconcile','--delivery-id',uncertain['id']);assert reconciled['state']=='succeeded' and reconciled['observation']['reconciled'] and not reconciled['observation']['file_fsync_acknowledged']
 assert final(uncertain).read_bytes()==data
 bad,_=create('corrupt-source');action('approve-corrupt-source',bad)
 source=storage/(tenant+'_'+partner+'_'+accepted['id']);source.chmod(0o600);source.write_bytes(b'x'*len(data));source.chmod(0o400)
 denied=invoke('corrupt-source-not-dispatched','delivery-work','--delivery-id',bad['id']);assert denied['state']=='blocked' and not final(bad).exists()
 source.chmod(0o600);source.write_bytes(data);source.chmod(0o400)
 # Revoking authority freezes old approvals and receipt replays before any new bytes.
 revoked,_=create('authority-revoked');action('approve-revoked',revoked)
 sql(f"UPDATE credentials SET permissions=array_remove(permissions,'deliver') WHERE tenant_id='{tenant}' AND partner_id='{partner}' AND token_hash=(SELECT token_hash FROM credentials WHERE tenant_id='{tenant}' AND actor_id=(SELECT actor_id FROM delivery_intents WHERE tenant_id='{tenant}' AND delivery_id='{revoked['id']}'))")
 invoke('revoked-worker-denied','delivery-work','--delivery-id',revoked['id'],success=False)
 action('approve-revoked',revoked,success=False)
 assert not final(revoked).exists()
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
manifest={'schema_version':1,'state':state,'observed_at':datetime.now(timezone.utc).isoformat(),'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'failure':failure,'receiver':'native stock OpenSSH 10.5p1; separate daemon and filesystem, same macOS machine','limits':['loopback development profile','synthetic 2 MiB payload','OpenSSH fsync and atomic hardlink extensions required','file integrity observation is not downstream business acceptance','same-host operator-assisted experiment; no independent adoption or enterprise qualification']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/delivery-current').write_text(str(raw)+'\n')
print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
raise SystemExit(0 if state=='passed' else 1)
