#!/usr/bin/env python3
"""Signed and recipient-encrypted delivery with stock GnuPG and SFTP peers.

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
run_id='encryption-'+uuid.uuid4().hex
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
fault_name='freightctl_enc_fault_'+uuid.uuid4().hex[:16]
def drop_fault():
 if not owned_database:return
 sql(f'DROP TRIGGER IF EXISTS {fault_name} ON delivery_ciphertexts; DROP TRIGGER IF EXISTS {fault_name} ON delivery_intents; DROP FUNCTION IF EXISTS {fault_name}()')
def fault(table,delivery_id,body):
 drop_fault()
 sql(f"CREATE FUNCTION {fault_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.delivery_id='{delivery_id}'::uuid THEN {body} END IF; RETURN NEW; END $$; CREATE TRIGGER {fault_name} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION {fault_name}()")
def wait_lease(delivery_id):
 remaining=max(0,float(sql(f"SELECT extract(epoch FROM lease_until-clock_timestamp()) FROM delivery_intents WHERE tenant_id='{tenant}' AND delivery_id='{delivery_id}'").decode().strip()))
 if remaining:
  print('Waiting for the unchanged delivery lease on '+delivery_id,flush=True)
  time.sleep(remaining+.2)
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
 fixture=Path(command(['python3','scripts/prepare-pgp-fixture.py','--rows','65536'],timeout=150).decode().strip())
 peer_manifest=json.loads((fixture/'manifest.json').read_text());assert (fixture/'source.csv').read_bytes()==data
 fingerprints=peer_manifest['fingerprints'];peer_image=peer_manifest['peer_image']
 import base64
 def key_request(name):return {'expected_version':0,'fingerprint':fingerprints[name],'public_key':base64.b64encode((fixture/(name+'-public.gpg')).read_bytes()).decode()}
 primary=invoke('original-pgp-key-command','pgp-key-register','--request-file',write('key-metadata',{'expected_version':0,'fingerprint':fingerprints['good']}),'--pgp-public-file',fixture/'good-public.asc','--idempotency-key','pgp-key')['resource']
 replay=post('key-registration-replay','/pgp-keys',key_request('good'),key='pgp-key');assert replay['replayed'] and replay['resource']==primary
 assert 'public_packets' not in primary and 'synthetic signer' not in json.dumps(primary)
 rsa=post('register-rsa3072-peer-key','/pgp-keys',key_request('rsa'),key='rsa-key')['resource']
 post('expired-key-refused','/pgp-keys',key_request('expired'),400,key='expired-key')
 for label,name in [('revoked-key','revoked-public.gpg'),('private-key','private-rejection.gpg')]:
  request={'expected_version':0,'fingerprint':fingerprints['good'],'public_key':base64.b64encode((fixture/name).read_bytes()).decode()}
  post(label+'-refused','/pgp-keys',request,400,key=label)
 wrong=key_request('good');wrong['fingerprint']=fingerprints['other'];post('wrong-primary-pin-refused','/pgp-keys',wrong,400,key='wrong-pin')
 old_header=private/'old.headers';old_header.write_bytes(b'Authorization: Bearer '+old_grants.read_bytes()+b'\n')
 other_header=private/'other.headers';other_header.write_bytes(b'Authorization: Bearer '+other.read_bytes()+b'\n')
 post('old-grants-cannot-register-key','/pgp-keys',key_request('good'),403,key='old-key',who=old_header)
 policy_request={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':4096},{'name':'amount','type':'decimal','required':True,'max_bytes':64,'precision':12,'scale':2},{'name':'day','type':'date','required':True,'max_bytes':10}],'max_bytes':8<<20,'max_rows':100000,'max_record_bytes':65536,'timeout_seconds':30,'signature':{'key':ref(primary),'max_age_seconds':3600}}}
 policy=post('require-exact-signer-and-csv','/intake-policy',policy_request,key='policy')['resource']
 app_port=free_port();app_host=private/'app-host';app_public=private/'app-host.pub'
 cli('ssh-host-keygen','--ssh-host-key-file',str(app_host),'--ssh-public-file',str(app_public))
 sender=private/'sender';command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(sender)])
 invoke('enroll-sftp-sender','ssh-key-enroll','--ssh-public-file',str(sender)+'.pub')
 username=invoke('sftp-sender-identity','identity')['ssh_username']
 app_trust=private/'app-known-hosts';app_trust.write_text(f'[127.0.0.1]:{app_port} '+app_public.read_text())
 app_args=[str(binary),'serve-sftp','--listen',f'127.0.0.1:{app_port}','--storage',str(storage),'--ssh-host-key-file',str(app_host)]
 start('sftp',app_args,app_port)
 def batch(label,text,success=True):
  p=private/(label+'.batch');p.write_text(text+'\n')
  result=subprocess.run(['sftp','-F','/dev/null','-P',str(app_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(app_trust),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(sender),'-b',str(p),username+'@127.0.0.1'],capture_output=True,timeout=40)
  (raw/(label+'.stdout')).write_bytes(result.stdout);(raw/(label+'.stderr')).write_bytes(result.stderr)
  steps.append({'name':label,'exit_code':result.returncode,'expected_success':success,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()})
  if (result.returncode==0)!=success:raise RuntimeError(label+': unexpected SFTP result '+result.stderr.decode(errors='replace')[:700])
 batch('stock-sftp-receive-signed-business-file',f'put {payload} /signed.csv')
 fid=next(c['file_id'] for c in invoke('discover-owned-held-revision','check-list')['checks'] if c.get('path')=='/signed.csv')
 c=get('held-before-signature','/checks/'+fid)['check'];assert c['state']=='held'
 post('signature-required-before-attempt','/checks/'+fid+'/run',expected=409,key='missing')
 assert get('missing-signature-spends-no-attempt','/checks/'+fid)['check']['attempts']==0
 def attach(label,fid,c,wire,expected=200,who=None):return post(label,'/checks/'+fid+'/signature',wire,expected,key=label,who=who,method='PUT',extra=['--header','If-Check-Revision: '+str(c['revision']),'--header','X-Data-SHA256: '+c['binding']['file']['sha256'],'--header','X-Policy-Hash: '+c['policy_hash']])
 good_sig=(fixture/'good.sig').read_bytes()
 attach('weak-signature-digest-refused',fid,c,(fixture/'weak.sig').read_bytes(),400)
 attach('mixed-signatures-refused',fid,c,good_sig+(fixture/'other.sig').read_bytes(),400)
 attach('private-packets-not-a-sidecar',fid,c,(fixture/'private-rejection.gpg').read_bytes(),400)
 attach('other-actor-cannot-attach',fid,c,good_sig,404,other_header)
 attached=invoke('cli-bind-exact-detached-signature','check-signature','--file-id',fid,'--signature-file',fixture/'good.sig','--data-sha256',digest,'--policy-hash',c['policy_hash'],'--expected-revision',c['revision'],'--idempotency-key','signature')['resource']
 replay=post('signature-attachment-replay','/checks/'+fid+'/signature',good_sig,key='signature',method='PUT',extra=['--header','If-Check-Revision: '+str(c['revision']),'--header','X-Data-SHA256: '+digest,'--header','X-Policy-Hash: '+c['policy_hash']]);assert replay['replayed'] and replay['resource']==attached
 get('sidecar-is-not-a-raw-file','/files/'+attached['object_id'],expected=404)
 get('other-actor-sidecar-denied','/checks/'+fid+'/signature',expected=404,who=other_header)
 stop('https');stop('sftp')
 https_args=[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key)]
 start('https',https_args,http_port);start('sftp',app_args,app_port)
 persisted=get('data-and-sidecar-survive-restart','/checks/'+fid);assert persisted['check']['state']=='held' and persisted['signature']['sha256']==hashlib.sha256(good_sig).hexdigest()
 first=post('verify-exact-gpg-signature-and-csv','/checks/'+fid+'/run',key='check')
 replay=post('signature-check-replay','/checks/'+fid+'/run',key='check');assert replay['replayed'] and replay['resource']==first['resource']
 c=get('inspect-authorized-signature-proof','/checks/'+fid)['check'];assert c['state']=='passed' and c['report']['rows']==65536
 proof=c['report']['signature'];assert proof['key']==ref(primary) and proof['verification']['primary_fingerprint']==fingerprints['good'] and proof['verification']['signer_fingerprint']==fingerprints['subkey'] and proof['verification']['hash_algorithm']=='SHA-256'
 get('verified-signature-does-not-release-by-itself','/files/'+fid,expected=409)
 def release_decision(c):return {'sha256':c['binding']['file']['sha256'],'policy_hash':c['policy_hash'],'report_hash':c['report_hash'],'expected_revision':c['revision']}
 post('approve-exact-signed-revision','/checks/'+fid+'/release',release_decision(c),key='release')
 reconciliation=invoke('reconcile-sidecar-as-durable-artifact','reconcile');assert reconciliation['consistent'] and reconciliation['counts']['verified_signature']==1
 request={'expected_version':0,'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'host_public_file':str(private/'receiver-host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}
 connection=invoke('register-independent-receiver','connection-register','--request-file',write('connection',request),'--idempotency-key','connection')['resource']
 recipient_request=key_request('recipient');recipient_request['purpose']='encrypt'
 recipient=post('register-explicit-recipient','/pgp-keys',recipient_request,key='recipient')['resource']
 assert recipient['purpose']=='encrypt' and 'seipd-v1-aes256' in recipient['recipient']['profiles']
 rsa_recipient_request=key_request('recipient-rsa');rsa_recipient_request['purpose']='encrypt'
 rsa_recipient=post('register-rsa-encryption-recipient','/pgp-keys',rsa_recipient_request,key='rsa-recipient')['resource']
 definition={'schema_version':1,'name':'verified signed encrypted settlement delivery','steps':[{'id':'send','kind':'sftp.deliver','connection':ref(connection),'filename':'signed.pgp','encryption':{'key':ref(recipient),'profile':'seipd-v1-aes256'}}]}
 preview=invoke('original-workflow-encryption-validation','workflow-validate','--request-file',write('encryption-preview',{'definition':definition,'file_id':fid}))
 assert not preview['external_contact'] and preview['effects'][0]['recipient_fingerprint']==fingerprints['recipient'] and preview['effects'][0]['encryption_fingerprint']==recipient['recipient']['encryption_fingerprint']
 draft=post('typed-delivery-draft','/workflows/drafts',{'expected_version':0,'definition':definition},key='draft')['resource']
 workflow=post('ordinary-workflow-approval',wfroute(draft)+'/approve',decision(draft),key='approve-workflow')['resource']
 run=post('run-only-released-signed-bytes','/workflow-runs',{'workflow':ref(workflow),'file_id':fid},key='run')['resource']
 stop('receiver')
 prepared=post('prepare-encrypted-artifact-with-receiver-offline','/workflow-runs/'+run['id']+'/work',key='work')
 assert prepared['status']['steps'][0]['state']=='retry';ciphertext=prepared['status']['steps'][0]['ciphertext']
 assert ciphertext['source_sha256']==digest and ciphertext['proof']['primary_fingerprint']==fingerprints['recipient']
 stop('https');start('https',[str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key)],http_port)
 retained=get('ciphertext-survives-app-restart','/workflow-runs/'+run['id'])['steps'][0]['ciphertext'];assert retained==ciphertext
 start('receiver',['/usr/sbin/sshd','-D','-e','-f',str(config)],receiver_port)
 pending=invoke('inspect-original-retry-deadline','delivery-status','--delivery-id',prepared['dispatch']['delivery_id'])
 remaining=max(0,datetime.fromisoformat(pending['next_at'].replace('Z','+00:00')).timestamp()-time.time())
 if remaining:time.sleep(remaining+.1)
 done=post('dispatch-original-ciphertext-after-restart','/workflow-runs/'+run['id']+'/work',key='work');assert done['replayed'] and done['dispatch']==prepared['dispatch'] and done['status']['run']['state']=='succeeded'
 assert done['status']['steps'][0]['ciphertext']==ciphertext
 encrypted_reconciliation=invoke('reconcile-durable-ciphertext','reconcile');assert encrypted_reconciliation['consistent'] and encrypted_reconciliation['counts']['verified_ciphertext']==1
 target=inbox/(done['dispatch']['delivery_id']+'-signed.pgp');retrieved=private/'received.pgp';b=private/'retrieve.batch';b.write_text(f'get {target} {retrieved}\n')
 command(['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(private/'client'),'-b',str(b),user+'@127.0.0.1'])
 assert retrieved.read_bytes()!=data and hashlib.sha256(retrieved.read_bytes()).hexdigest()==ciphertext['sha256'];steps.append({'name':'independent-stock-receiver-exact-ciphertext','size_bytes':len(retrieved.read_bytes()),'sha256':ciphertext['sha256']})
 served_sig=private/'received.sig';command(['curl','--silent','--show-error','--fail','--cacert',str(cert),'--header','@'+str(header),'--output',str(served_sig),f'https://127.0.0.1:{http_port}/v1/tenants/{tenant}/partners/{partner}/checks/'+fid+'/signature']);assert served_sig.read_bytes()==good_sig
 verify_script="mkdir -m 700 /tmp/verify; : > /tmp/verify/common.conf; gpg --homedir /tmp/verify --batch --import /fixture/good-public.gpg /fixture/recipient-private.gpg; gpg --homedir /tmp/verify --batch --status-fd 1 --output /tmp/plain.csv --decrypt /result/received.pgp && cmp /tmp/plain.csv /fixture/source.csv && gpg --homedir /tmp/verify --batch --status-fd 1 --verify /result/received.sig /tmp/plain.csv"
 if peer_manifest.get('peer_backend')=='native-macos':
  plain=private/'native-received.csv'
  verified=command(['python3','scripts/pgp-native-peer.py','--config',os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/'native-decryption-metrics.json'),'decrypt','--key',str(fixture/'recipient-private.gpg'),'--cipher',str(retrieved),'--output',str(plain)])
  assert plain.read_bytes()==data
  verified+=command(['python3','scripts/pgp-native-peer.py','--config',os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/'native-verification-metrics.json'),'verify','--key',str(fixture/'good-public.gpg'),'--signature',str(served_sig),'--source',str(plain)])
  existing=subprocess.run(['python3','scripts/pgp-native-peer.py','--config',os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/'receiver-output-exists-native-metrics.json'),'decrypt','--key',str(fixture/'recipient-private.gpg'),'--cipher',str(retrieved),'--output',str(plain)],capture_output=True,timeout=30)
  (raw/'receiver-output-exists.status').write_bytes(existing.stderr)
  assert existing.returncode!=0 and b'FileExistsError' in existing.stderr and plain.read_bytes()==data and not Path(str(plain)+'.part').exists()
  steps.append({'name':'native-peer-never-overwrites-existing-receiver-output','status_sha256':hashlib.sha256(existing.stderr).hexdigest()})
 else:
  verified=command(['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=32','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-v',str(fixture)+':/fixture:ro','-v',str(private)+':/result:ro',peer_image,'/bin/sh','-c',verify_script])
 (raw/'independent-gpg-verification.txt').write_bytes(verified);assert b'VALIDSIG '+fingerprints['subkey'].upper().encode() in verified and b'DECRYPTION_OKAY' in verified and b'GOODMDC' in verified and b'DECRYPTION_INFO 2 9 0' in verified
 steps.append({'name':'independent-gpg-decrypts-exact-source-and-verifies-signature','output_sha256':hashlib.sha256(verified).hexdigest()})
 # Negative receiver operations cannot turn unauthenticated bytes into a result.
 corrupt=private/'corrupt.pgp';bad=bytearray(retrieved.read_bytes());bad[-1]^=1;corrupt.write_bytes(bad)
 for label,secret_name,filename in [('wrong-recipient','recipient-rsa','received.pgp'),('corrupt-ciphertext','recipient','corrupt.pgp')]:
  program=f'mkdir -m 700 /tmp/refusal; : > /tmp/refusal/common.conf; gpg --homedir /tmp/refusal --batch --import /fixture/{secret_name}-private.gpg; gpg --homedir /tmp/refusal --batch --status-fd 2 --output /dev/null --decrypt /result/{filename}'
  if peer_manifest.get('peer_backend')=='native-macos':
   result=subprocess.run(['python3','scripts/pgp-native-peer.py','--config',os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/(label+'-native-metrics.json')),'decrypt','--key',str(fixture/(secret_name+'-private.gpg')),'--cipher',str(private/filename),'--output',str(private/(label+'-discard.csv'))],capture_output=True,timeout=30)
  else:
   result=subprocess.run(['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=32','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-v',str(fixture)+':/fixture:ro','-v',str(private)+':/result:ro',peer_image,'/bin/sh','-c',program],capture_output=True,timeout=30)
  (raw/(label+'.status')).write_bytes(result.stderr);assert result.returncode!=0
  assert (b'NO_SECKEY' if label=='wrong-recipient' else b'BADMDC') in result.stderr
  if peer_manifest.get('peer_backend')=='native-macos':
   assert not (private/(label+'-discard.csv')).exists() and not (private/(label+'-discard.csv.part')).exists(), 'failed native decryption exposed a receiver result'
  steps.append({'name':label+'-independently-refused','exit_code':result.returncode,'status_sha256':hashlib.sha256(result.stderr).hexdigest()})
 # Kill one actual CLI worker after durable ciphertext sync but before its
 # acceptance transaction commits. Production leases and timeouts stay intact.
 crashed=post('crash-boundary-encryption-run','/workflow-runs',{'workflow':ref(workflow),'file_id':fid},key='crash-run')['resource']
 crash_view=get('crash-boundary-intent','/workflow-runs/'+crashed['id']);crash_id=crash_view['steps'][0]['delivery_id']
 prior_objects={p.name for p in storage.iterdir()}
 fault('delivery_ciphertexts',crash_id,'PERFORM pg_sleep(8);')
 child=subprocess.Popen(args('workflow-work','--run-id',crashed['id'],'--idempotency-key','crash-work'),stdout=(raw/'crashed-worker.stdout').open('wb'),stderr=(raw/'crashed-worker.stderr').open('wb'));children.append(child)
 boundary=False
 for _ in range(150):
  if child.poll() is not None:raise RuntimeError('encryption worker exited before crash boundary')
  boundary=sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='freightctl' AND wait_event='PgSleep' AND query LIKE 'INSERT INTO delivery_ciphertexts%')").decode().strip()=='t'
  if boundary:break
  time.sleep(.03)
 assert boundary
 orphan_objects={p.name for p in storage.iterdir()}-prior_objects;assert len(orphan_objects)==1
 orphan=storage/next(iter(orphan_objects));assert orphan.stat().st_mode&0o777==0o400
 child.kill();child.wait(timeout=5);drop_fault()
 assert sql(f"SELECT count(*) FROM delivery_ciphertexts WHERE tenant_id='{tenant}' AND delivery_id='{crash_id}'").decode().strip()=='0'
 wait_lease(crash_id)
 recovered=post('recover-killed-encryption-worker','/workflow-runs/'+crashed['id']+'/work',key='crash-work');assert recovered['replayed'] and recovered['dispatch']['delivery_id']==crash_id and recovered['status']['run']['state']=='succeeded'
 recovered_artifact=recovered['status']['steps'][0]['ciphertext'];assert recovered_artifact['object_id']!=orphan.name.split('_')[2] and hashlib.sha256(orphan.read_bytes()).hexdigest()!=recovered_artifact['sha256']
 recovered_report=invoke('crash-orphan-remains-observable','reconcile');assert recovered_report['counts']['unreferenced_bytes']==1 and recovered_report['counts']['verified_ciphertext']==2
 # Remote success followed by failed local recording must retain ambiguity and
 # the same ciphertext. Only read-only remote observation may resolve it.
 uncertain=post('encrypted-uncertain-run','/workflow-runs',{'workflow':ref(workflow),'file_id':fid},key='uncertain-run')['resource']
 uncertain_view=get('encrypted-uncertain-intent','/workflow-runs/'+uncertain['id']);uncertain_id=uncertain_view['steps'][0]['delivery_id']
 fault('delivery_intents',uncertain_id,"IF NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned encrypted receipt failure';END IF;")
 post('encrypted-remote-success-local-receipt-failure','/workflow-runs/'+uncertain['id']+'/work',expected=503,key='uncertain-work');drop_fault()
 uncertain_state=get('encrypted-receipt-uncertainty-visible','/workflow-runs/'+uncertain['id']);uncertain_artifact=uncertain_state['steps'][0]['ciphertext']
 assert uncertain_state['steps'][0]['state']=='publishing' and hashlib.sha256((inbox/(uncertain_id+'-signed.pgp')).read_bytes()).hexdigest()==uncertain_artifact['sha256']
 wait_lease(uncertain_id)
 ambiguous=post('same-dispatch-retains-encrypted-ambiguity','/workflow-runs/'+uncertain['id']+'/work',key='uncertain-work');assert ambiguous['replayed'] and ambiguous['status']['steps'][0]['state']=='ambiguous'
 invoke('read-only-encrypted-receipt-reconciliation','delivery-reconcile','--delivery-id',uncertain_id)
 observed=post('refresh-original-encrypted-dispatch','/workflow-runs/'+uncertain['id']+'/work',key='uncertain-work');assert observed['status']['run']['state']=='succeeded' and observed['status']['steps'][0]['ciphertext']==uncertain_artifact
 queued=post('queue-before-recipient-revocation','/workflow-runs',{'workflow':ref(workflow),'file_id':fid},key='queue-revoked-recipient')['resource']
 post('revoke-exact-recipient','/pgp-keys/'+recipient['id']+'/1/revoke',decision(recipient),key='revoke-recipient')
 post('revoked-recipient-prevents-dispatch','/workflow-runs/'+queued['id']+'/work',expected=409,key='revoked-recipient-work')
 blocked=get('revoked-recipient-reason-visible','/workflow-runs/'+queued['id']);assert blocked['observed_reason']=='encryption_recipient_unavailable'
 assert not (inbox/(blocked['steps'][0]['delivery_id']+'-signed.pgp')).exists()
 definition['steps'][0]['encryption']['key']=ref(rsa_recipient);definition['steps'][0]['filename']='rsa-signed.pgp'
 rotated=post('review-explicit-recipient-rotation','/workflows/drafts',{'workflow_id':workflow['id'],'expected_version':1,'definition':definition},key='rotate-recipient')['resource']
 approved_rotation=post('approve-exact-recipient-rotation',wfroute(rotated)+'/approve',decision(rotated),key='approve-recipient-rotation')['resource']
 rsa_run=post('run-rsa-recipient','/workflow-runs',{'workflow':ref(approved_rotation),'file_id':fid},key='rsa-recipient-run')['resource']
 rsa_done=post('dispatch-rsa-recipient','/workflow-runs/'+rsa_run['id']+'/work',key='rsa-recipient-work');assert rsa_done['status']['run']['state']=='succeeded'
 rsa_target=inbox/(rsa_done['dispatch']['delivery_id']+'-rsa-signed.pgp');rsa_received=private/'rsa-received.pgp';b=private/'rsa-retrieve.batch';b.write_text(f'get {rsa_target} {rsa_received}\n')
 command(['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(private/'client'),'-b',str(b),user+'@127.0.0.1'])
 rsa_program=verify_script.replace('recipient-private.gpg','recipient-rsa-private.gpg').replace('received.pgp','rsa-received.pgp')
 if peer_manifest.get('peer_backend')=='native-macos':
  rsa_plain=private/'native-rsa-received.csv'
  rsa_verified=command(['python3','scripts/pgp-native-peer.py','--config',os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/'native-rsa-decryption-metrics.json'),'decrypt','--key',str(fixture/'recipient-rsa-private.gpg'),'--cipher',str(rsa_received),'--output',str(rsa_plain)])
  assert rsa_plain.read_bytes()==data
  rsa_verified+=command(['python3','scripts/pgp-native-peer.py','--config',os.environ['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/'native-rsa-verification-metrics.json'),'verify','--key',str(fixture/'good-public.gpg'),'--signature',str(served_sig),'--source',str(rsa_plain)])
 else:
  rsa_verified=command(['docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=32','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-v',str(fixture)+':/fixture:ro','-v',str(private)+':/result:ro',peer_image,'/bin/sh','-c',rsa_program])
 (raw/'independent-rsa-recipient.txt').write_bytes(rsa_verified);assert b'DECRYPTION_OKAY' in rsa_verified and b'GOODMDC' in rsa_verified and b'VALIDSIG '+fingerprints['subkey'].upper().encode() in rsa_verified
 assert hashlib.sha256(rsa_received.read_bytes()).hexdigest()==rsa_done['status']['steps'][0]['ciphertext']['sha256']
 steps.append({'name':'independent-rsa3072-recipient-decrypts-and-verifies-exact-source','status_sha256':hashlib.sha256(rsa_verified).hexdigest()})
 cli_run=post('ordinary-cli-approved-encryption-run','/workflow-runs',{'workflow':ref(approved_rotation),'file_id':fid},key='direct-cli-encryption-run')['resource']
 cli_view=get('ordinary-cli-encryption-intent','/workflow-runs/'+cli_run['id']);cli_id=cli_view['steps'][0]['delivery_id']
 cli_done=invoke('ordinary-cli-worker-uses-custody-quota','delivery-work','--delivery-id',cli_id);assert cli_done['state']=='succeeded' and cli_done['observation']['encryption']['primary_fingerprint']==fingerprints['recipient-rsa']
 cli_status=get('ordinary-cli-ciphertext-visible','/workflow-runs/'+cli_run['id']);assert cli_status['observed_state']=='succeeded' and cli_status['steps'][0]['ciphertext']['sha256']==cli_done['observation']['sha256']

 def upload(label,body):return post(label,'/namespace/file?'+urlencode({'path':'/'+label+'.csv'}),body,201,key=label,method='PUT',extra=['--header','X-File-Size: '+str(len(body)),'--header','X-Content-SHA256: '+hashlib.sha256(body).hexdigest()])['file']
 for label,body,wire in [('wrong-signer',data,(fixture/'other.sig').read_bytes()),('changed-data',data.replace(b'100.01',b'100.02',1),good_sig),('aged-signature',data,(fixture/'aged.sig').read_bytes())]:
  bad=upload(label,body);current=get(label+'-held','/checks/'+bad['id'])['check'];attach(label+'-attach',bad['id'],current,wire)
  post(label+'-verify','/checks/'+bad['id']+'/run',key=label+'-check');rejected=get(label+'-verdict','/checks/'+bad['id'])['check'];assert rejected['state']=='rejected' and rejected['code']=='signature_invalid'
  get(label+'-raw-denied','/files/'+bad['id'],expected=409)
 revoke={'definition_hash':primary['definition_hash'],'expected_revision':primary['revision']}
 post('revoke-selected-signer','/pgp-keys/'+primary['id']+'/1/revoke',revoke,key='revoke-key')
 get('revoked-signer-blocks-prior-release','/files/'+fid,expected=409)
 batch('stock-sftp-refuses-revoked-signer',f'get /signed.csv {private/"blocked.csv"}',False)
 assert not get('revoked-signature-context-is-historical','/checks/'+fid)['current']
 # A new policy selects the independently generated RSA key. Existing source
 # jobs cannot silently change their signer or policy to this new version.
 policy_request['expected_version']=1;policy_request['definition']['signature']['key']=ref(rsa)
 post('explicit-policy-rotation-to-rsa','/intake-policy',policy_request,key='rsa-policy')
 rsa_file=upload('rsa-signed-intake',data);rsa_check=get('rsa-intake-held','/checks/'+rsa_file['id'])['check'];attach('attach-rsa3072-signature',rsa_file['id'],rsa_check,(fixture/'rsa.sig').read_bytes())
 post('verify-rsa3072-signed-intake','/checks/'+rsa_file['id']+'/run',key='rsa-check');rsa_check=get('rsa3072-proof','/checks/'+rsa_file['id'])['check'];assert rsa_check['state']=='passed' and rsa_check['report']['signature']['verification']['primary_fingerprint']==fingerprints['rsa']
 post('release-exact-rsa-signed-revision','/checks/'+rsa_file['id']+'/release',release_decision(rsa_check),key='rsa-release')
 state='passed';failure=None
except Exception:
 state='failed';failure=traceback.format_exc()
finally:
 for child in children:
  if child.poll() is None:child.kill();child.wait(timeout=5)
 try:drop_fault()
 except Exception:pass
 for name in list(servers):stop(name)
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'state':state,'observed_at':datetime.now(timezone.utc).isoformat(),'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'duration_seconds':round(time.monotonic()-started,3),'payload_size_bytes':len(data),'payload_sha256':digest,'steps':steps,'failure':failure,'receiver':'Native stock OpenSSH 10.5p1, separate daemon/filesystem on this macOS host','peer_manifest':str((fixture/'manifest.json').relative_to(root)) if 'fixture' in globals() else None,'peer_image':peer_image if 'peer_image' in globals() else None,'peer_backend':peer_manifest.get('peer_backend','docker') if 'peer_manifest' in globals() else None,'inference_performed':False,'local_model_processes_started':0,'malware_scanning_performed':False,'limits':['Signed CSV intake followed by explicitly approved recipient encryption and SFTP delivery. Decryption/private signing inside freightctl, malware scanning and complete business acknowledgment remain required.','Independent peer details and native/Docker resource enforcement are recorded in the exact peer manifest. Native macOS runs use a sampled 128 MiB child RSS watchdog and deny IP networking; no kernel CPU/RSS cap or native Linux server qualification is claimed.','V4 Ed25519 signature verification; encryption uses Curve25519 and RSA3072 subkeys with AES256 SEIPDv1/MDC GnuPG peers. SEIPDv2/AES256-OCB and v6 have library/unit coverage only; independent peer qualification remains required.','Explicit fingerprint enrollment, frozen source/recipient/destination and durable ciphertext reuse. KMS/HSM, private signing/decryption, delegated review, broader peers/algorithms, remaining encryption/decryption crash boundaries and full journeys remain open.','Historical integrity-only revisions retain their original scope; no retroactive cryptographic verdict is claimed.','Assisted same-host loopback exercise, not production performance, HA, independent adoption or enterprise/release qualification.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/encryption-current').write_text(str(raw)+'\n')
print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
raise SystemExit(0 if state=='passed' else 1)
