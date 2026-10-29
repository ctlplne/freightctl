#!/usr/bin/env python3
"""Qualify durable upload checkpoints through real TLS, PostgreSQL and OpenSSH."""
import hashlib,json,os,signal,socket,subprocess,time,traceback,uuid
from pathlib import Path
from urllib.parse import urlencode
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
run_id='uploads-'+uuid.uuid4().hex;private=root/'.private'/run_id;private.mkdir(mode=0o700)
raw=root/'evidence/raw'/run_id;raw.mkdir(parents=True,mode=0o700)
binary=root/'.cache/freightctl';steps=[];servers={};logs={};client=None;started=time.monotonic()
def command(args,timeout=60):
 r=subprocess.run(args,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError(Path(args[0]).name+' failed: '+r.stderr.decode(errors='replace')[:1000])
 return r.stdout
def cli(*args):return command([str(binary),*args])
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def stop(name):
 p=servers.pop(name,None)
 if p is not None:
  p.terminate()
  try:p.wait(timeout=8)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 if name in logs:logs.pop(name).close()
try:
 command(['sh','scripts/go.sh','build','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/freightctl']);cli('init')
 tenant,partner=str(uuid.uuid4()),str(uuid.uuid4());http_port,ssh_port,wrong_port=port(),port(),port()
 storage=private/'custody';other_storage=private/'other-custody';base=f'https://127.0.0.1:{http_port}/v1/tenants/{tenant}/partners/{partner}'
 cert,tls_key=private/'localhost.crt',private/'localhost.key';cli('dev-cert','--cert',str(cert),'--key',str(tls_key))
 host_key,host_pub=private/'host.key',private/'host.pub';cli('ssh-host-keygen','--ssh-host-key-file',str(host_key),'--ssh-public-file',str(host_pub))
 known_hosts=private/'known_hosts';known_hosts.write_text(f'[127.0.0.1]:{ssh_port} '+host_pub.read_text())
 def identity(label):
  token=private/(label+'.token');key=private/(label+'.key');header=private/(label+'.headers')
  cli('token','--token-file',str(token));cli('enroll','--tenant',tenant,'--partner',partner,'--token-file',str(token))
  header.write_bytes(b'Authorization: Bearer '+token.read_bytes()+b'\n');command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
  cli('ssh-key-enroll','--tenant',tenant,'--partner',partner,'--token-file',str(token),'--ssh-public-file',str(key)+'.pub')
  info=json.loads(cli('identity','--tenant',tenant,'--partner',partner,'--token-file',str(token)))
  return {'token':token,'key':key,'header':header,'username':info['ssh_username']}
 owner,other=identity('owner'),identity('other')
 def start(name,ssh=False,wrong=False):
  address=f'127.0.0.1:{ssh_port if ssh else wrong_port if wrong else http_port}';path=other_storage if wrong else storage
  args=[str(binary),'serve-sftp' if ssh else 'serve','--listen',address,'--storage',str(path),'--max-file-bytes',str(8<<20),'--max-stored-bytes',str(128<<20),'--upload-checkpoint-bytes',str(64<<10)]
  args+=['--ssh-host-key-file',str(host_key)] if ssh else ['--cert',str(cert),'--key',str(tls_key)]
  log=(raw/(name+'.log')).open('ab');logs[name]=log;servers[name]=subprocess.Popen(args,stdout=log,stderr=log)
  for _ in range(100):
   if servers[name].poll() is not None:raise RuntimeError(name+' exited; inspect retained log')
   try:
    with socket.create_connection(('127.0.0.1',int(address.rsplit(':',1)[1])),timeout=.2):return
   except OSError:time.sleep(.05)
  raise RuntimeError(name+' unavailable')
 def curl(label,route,expected=200,who=None,extra=(),wrong=False):
  who=who or owner;output=raw/(label+'.out');target=base.replace(':'+str(http_port),':'+str(wrong_port)) if wrong else base
  status=int(command(['curl','--silent','--show-error','--cacert',str(cert),'--max-time','20','--header','@'+str(who['header']),'--output',str(output),'--write-out','%{http_code}',*extra,target+route]))
  steps.append({'name':label,'http_status':status,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()})
  if status!=expected:raise RuntimeError(f'{label}: HTTP {status}, expected {expected}: '+output.read_text(errors='replace')[:300])
  return output
 def ns(route,path):return '/namespace/'+route+'?'+urlencode({'path':path})
 def create(label,path,data):
  request=private/(label+'.json');request.write_text(json.dumps({'path':path,'expected_size':len(data),'expected_sha256':hashlib.sha256(data).hexdigest()}))
  result=json.loads(curl(label,'/uploads',201,extra=['--header','Idempotency-Key: '+label,'--header','Content-Type: application/json','--data-binary','@'+str(request)]).read_text())
  return result['upload'],request
 def append(label,u,offset,data,expected=200,digest=None,wrong=False,key=None):
  chunk=private/(label+'.chunk');chunk.write_bytes(data)
  return curl(label,'/uploads/'+u['id'],expected,extra=['--request','PATCH','--header','Idempotency-Key: '+(key or label),'--header','Upload-Offset: '+str(offset),'--header','X-File-Size: '+str(len(data)),'--header','X-Content-SHA256: '+(digest or hashlib.sha256(data).hexdigest()),'--data-binary','@'+str(chunk)],wrong=wrong)
 def ssh_args(who):return ['sftp','-F','/dev/null','-P',str(ssh_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(who['key'])]
 def batch(label,text,success=True,who=None):
  who=who or owner;path=private/(label+'.batch');path.write_text(text+'\n')
  result=subprocess.run([*ssh_args(who),'-b',str(path),who['username']+'@127.0.0.1'],capture_output=True,timeout=40)
  (raw/(label+'.stdout')).write_bytes(result.stdout);(raw/(label+'.stderr')).write_bytes(result.stderr)
  steps.append({'name':label,'exit_code':result.returncode,'expected_success':success,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()})
  if (result.returncode==0)!=success:raise RuntimeError(label+': unexpected SFTP result '+str(result.returncode)+': '+result.stderr.decode(errors='replace')[:1000])
 start('https');start('sftp',ssh=True)
 data=(b'synthetic durable resume,00001,42.01\n'*100000)[:2<<20];payload=private/'synthetic.bin';payload.write_bytes(data);digest=hashlib.sha256(data).hexdigest()
 u,request=create('create-resume','/resumed.bin',data)
 replay=json.loads(curl('create-idempotent-retry','/uploads',200,extra=['--header','Idempotency-Key: create-resume','--header','Content-Type: application/json','--data-binary','@'+str(request)]).read_text());assert replay['replayed'] and replay['upload']['id']==u['id']
 first=json.loads(append('first-checkpoint',u,0,data[:64<<10]).read_text());assert first['upload']['committed_offset']==64<<10
 replay=json.loads(append('repeat-checkpoint',u,0,data[:64<<10],key='first-checkpoint').read_text());assert replay['replayed'] and replay['upload']==first['upload']
 append('stale-offset-denied',u,0,data[:64<<10],409)
 append('wrong-chunk-digest-denied',u,64<<10,data[64<<10:128<<10],422,digest=hashlib.sha256(b'x'*(64<<10)).hexdigest())
 curl('other-actor-status-denied','/uploads/'+u['id'],404,who=other)
 curl('premature-complete-denied','/uploads/'+u['id']+'/complete',409,extra=['--request','POST','--header','Idempotency-Key: premature'])
 curl('destination-unpublished',ns('file','/resumed.bin'),404)
 checkpoint=next(p for p in storage.iterdir() if p.name.startswith(tenant+'_'+partner+'_'))
 curl('raw-checkpoint-download-denied','/files/'+checkpoint.name.rsplit('_',1)[1],404)
 receiver=private/'received.bin';batch('ticket-download-denied',f'get {u["sftp_path"]} {receiver}',False)
 batch('other-actor-resume-denied',f'reput {payload} {u["sftp_path"]}',False,who=other)
 start('wrong-store',wrong=True)
 curl('wrong-store-status-denied','/uploads/'+u['id'],409,wrong=True)
 append('wrong-store-checkpoint-denied',u,64<<10,data[64<<10:128<<10],409,wrong=True)
 assert not any(p.name.startswith(tenant+'_'+partner+'_') for p in other_storage.iterdir());stop('wrong-store')
 batch_file=private/'crash.batch';batch_file.write_text(f'reput {payload} {u["sftp_path"]}\n');client_log=(raw/'crash-client.log').open('wb')
 client=subprocess.Popen([*ssh_args(owner),'-l','512','-b',str(batch_file),owner['username']+'@127.0.0.1'],stdout=client_log,stderr=client_log,start_new_session=True)
 deadline=time.monotonic()+10;observed=None
 while time.monotonic()<deadline:
  observed=json.loads(curl('observe-'+str(len(steps)),'/uploads/'+u['id']).read_text())
  if observed['committed_offset']>=128<<10:break
  if client.poll() is not None:raise RuntimeError('SFTP ended before its next durable checkpoint')
  time.sleep(.05)
 assert observed['committed_offset']>=128<<10 and observed['committed_offset']<len(data)
 curl('still-unpublished-before-crash',ns('file','/resumed.bin'),404)
 servers['sftp'].kill();servers['sftp'].wait(timeout=5);servers.pop('sftp');logs.pop('sftp').close()
 client.wait(timeout=8);assert client.returncode!=0;client=None;client_log.close()
 recorded=json.loads(curl('head-after-process-kill','/uploads/'+u['id']).read_text());stop('https')
 store_id=(storage/'.freightctl-storage-id').read_text();start('https');start('sftp',ssh=True)
 restarted=json.loads(curl('head-after-restart','/uploads/'+u['id']).read_text());assert restarted['committed_offset']>=recorded['committed_offset']>=observed['committed_offset'];assert restarted['committed_offset']<len(data)
 assert (storage/'.freightctl-storage-id').read_text()==store_id
 cli_status=json.loads(cli('upload-status','--tenant',tenant,'--partner',partner,'--token-file',str(owner['token']),'--upload-id',u['id'],'--storage',str(storage)));assert cli_status==restarted
 report=json.loads(curl('checkpoint-reconciliation','/custody/reconcile').read_text());assert report['counts'].get('verified_checkpoint',0)>=2
 batch('stock-reput-after-restart',f'reput {payload} {u["sftp_path"]}')
 complete=json.loads(curl('completed-status','/uploads/'+u['id']).read_text());assert complete['state']=='completed' and complete['committed_offset']==len(data)
 assert curl('download-complete-file',ns('file','/resumed.bin')).read_bytes()==data
 repeat=json.loads(curl('complete-idempotent-result','/uploads/'+u['id']+'/complete',200,extra=['--request','POST','--header','Idempotency-Key: completed-again']).read_text());assert repeat['file']['id']==complete['file_id']
 repeat2=json.loads(curl('complete-replay','/uploads/'+u['id']+'/complete',200,extra=['--request','POST','--header','Idempotency-Key: completed-again']).read_text());assert repeat2['replayed'] and repeat2['file']==repeat['file']
 # All bytes can be checkpointed before CLOSE or completion was recorded.
 small=data[:64<<10];small_file=private/'small.bin';small_file.write_bytes(small)
 full,_=create('full-before-close','/full-before-close.bin',small);append('full-prefix',full,0,small)
 batch('same-size-reput-refused-by-client',f'reput {small_file} {full["sftp_path"]}',False)
 batch('ticket-retarget-denied',f'rename {full["sftp_path"]} /unapproved.bin',False)
 batch('finalize-full-prefix',f'rename {full["sftp_path"]} /full-before-close.bin')
 batch('finalize-replay',f'rename {full["sftp_path"]} /full-before-close.bin')
 state_full=json.loads(curl('full-prefix-completion','/uploads/'+full['id']).read_text());assert state_full['state']=='completed'
 assert curl('full-prefix-bytes',ns('file','/full-before-close.bin')).read_bytes()==small
 # CLI creation shares the same target, storage binding and native SFTP adapter.
 cli_request=private/'cli-create.json';cli_request.write_text(json.dumps({'path':'/cli-resumed.bin','expected_size':len(small),'expected_sha256':hashlib.sha256(small).hexdigest()}))
 cli_upload=json.loads(cli('upload-create','--tenant',tenant,'--partner',partner,'--token-file',str(owner['token']),'--request-file',str(cli_request),'--idempotency-key','cli-create','--storage',str(storage)))['upload']
 batch('stock-put-cli-ticket',f'put {small_file} {cli_upload["sftp_path"]}')
 assert curl('cli-ticket-bytes',ns('file','/cli-resumed.bin')).read_bytes()==small
 aborted,_=create('abort-ticket','/aborted.bin',small)
 curl('abort-action','/uploads/'+aborted['id']+'/abort',200,extra=['--request','POST','--header','Idempotency-Key: abort'])
 append('append-after-abort-denied',aborted,0,small,409)
 state='passed';failure=None
except Exception:state='failed';failure=traceback.format_exc()
finally:
 if client is not None:
  if client.poll() is None:os.killpg(client.pid,signal.SIGTERM)
  client.wait(timeout=8)
 for name in list(servers):stop(name)
paths=command(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and (Path(p).suffix in ('.go','.sql','.py','.sh') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'id':run_id,'state':state,'failure':failure,'starting_commit':command(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'environment':{'os':os.uname().sysname,'arch':os.uname().machine,'go':command(['sh','scripts/go.sh','version']).decode().strip(),'ssh':subprocess.run(['ssh','-V'],capture_output=True).stderr.decode().strip(),'checkpoint_bytes':64<<10},'steps':steps,'elapsed_seconds':round(time.monotonic()-started,3),'raw_evidence_reference':str(raw.relative_to(root)),'private_fixture_reference':str(private.relative_to(root)),'limits':['Assisted synthetic exchange on one Mac, one storage root and retained local PostgreSQL.','1 GiB engineering file ceiling, 4096 chunks/upload and 128 open tickets/actor; large-file and endurance gates remain open.','Checkpoints are immutable chunks; completion needs additional space to assemble a full new revision. Retention/approved cleanup remains open.','Only explicit upload-ticket SFTP paths resume. Ordinary SFTP filenames retain the previous unclosed-upload behavior.','No malware scan, file signature, downstream business receipt, independent operator or enterprise peer qualification.','No database power-loss, multi-host failover, distributed backend or complete product journey qualification.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/uploads-current').write_text(str(raw)+'\n');print(json.dumps({'state':state,'manifest':str(raw/'manifest.json'),'failure':failure},indent=2))
if state!='passed':raise SystemExit(1)
