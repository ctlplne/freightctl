#!/usr/bin/env python3
"""Real OpenSSH/curl exchange against task-owned loopback services; no secrets logged."""
import hashlib,json,os,signal,socket,struct,subprocess,time,uuid,traceback,select
from pathlib import Path
from urllib.parse import urlencode
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
run_id='sftp-'+uuid.uuid4().hex
private=root/'.private'/run_id;private.mkdir(mode=0o700)
raw=root/'evidence/raw'/run_id;raw.mkdir(parents=True,mode=0o700)
binary=root/'.cache/freightctl';steps=[];servers={};logs={};client=None;started=time.monotonic()
def command(args,timeout=60):
 r=subprocess.run(args,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError(f'{Path(args[0]).name} failed ({r.returncode}): '+r.stderr.decode(errors='replace')[:1000])
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
 log=logs.pop(name,None)
 if log is not None:log.close()
def ssh_options(key,known=None):return ['-F','/dev/null','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known or known_hosts),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-oConnectTimeout=5','-i',str(key)]
def batch(label,text,identity,success=True,known=None):
 path=private/(label+'.batch');path.write_text(text+'\n')
 args=['sftp','-b',str(path),'-P',str(ssh_port),*ssh_options(identity['key'],known),identity['username']+'@127.0.0.1']
 r=subprocess.run(args,capture_output=True,timeout=40)
 (raw/(label+'.stdout')).write_bytes(r.stdout);(raw/(label+'.stderr')).write_bytes(r.stderr)
 steps.append({'name':label,'exit_code':r.returncode,'expected_success':success,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
 if (r.returncode==0)!=success:raise RuntimeError(f'{label}: unexpected OpenSSH exit {r.returncode}; '+r.stderr.decode(errors='replace')[:1000])
 return r
try:
 command(['sh','scripts/go.sh','build','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/freightctl'])
 cli('init');tenant,partner=str(uuid.uuid4()),str(uuid.uuid4())
 storage=private/'custody';ssh_port,http_port=port(),port()
 host_key=private/'host.key';host_pub=private/'host.pub'
 cli('ssh-host-keygen','--ssh-host-key-file',str(host_key),'--ssh-public-file',str(host_pub))
 known_hosts=private/'known_hosts';known_hosts.write_text(f'[127.0.0.1]:{ssh_port} '+host_pub.read_text())
 cert,tls_key=private/'localhost.crt',private/'localhost.key';cli('dev-cert','--cert',str(cert),'--key',str(tls_key))
 base=f'https://127.0.0.1:{http_port}/v1/tenants/{tenant}/partners/{partner}'
 def enroll(label,permissions=None,mount='/',tid=None,pid=None):
  tid,pid=tid or tenant,pid or partner;token=private/(label+'.token');key=private/(label+'.key')
  cli('token','--token-file',str(token));args=['enroll','--tenant',tid,'--partner',pid,'--token-file',str(token),'--namespace-root',mount]
  if permissions is not None:args+=['--permissions',permissions]
  cli(*args)
  command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
  result=json.loads(cli('ssh-key-enroll','--tenant',tid,'--partner',pid,'--token-file',str(token),'--ssh-public-file',str(key)+'.pub'))
  repeated=json.loads(cli('ssh-key-enroll','--tenant',tid,'--partner',pid,'--token-file',str(token),'--ssh-public-file',str(key)+'.pub'));assert repeated==result
  info=json.loads(cli('identity','--tenant',tid,'--partner',pid,'--token-file',str(token)))
  header=private/(label+'.headers');header.write_bytes(b'Authorization: Bearer '+token.read_bytes()+b'\n')
  return {'token':token,'key':key,'registered':result,'username':info['ssh_username'],'header':header,'tenant':tid,'partner':pid}
 owner=enroll('owner')
 def start_sftp():
  log=(raw/'sftp-server.log').open('ab');logs['sftp']=log
  servers['sftp']=subprocess.Popen([str(binary),'serve-sftp','--listen',f'127.0.0.1:{ssh_port}','--storage',str(storage),'--ssh-host-key-file',str(host_key),'--max-file-bytes',str(8<<20),'--max-stored-bytes',str(128<<20)],stdout=log,stderr=log)
  for _ in range(100):
   if servers['sftp'].poll() is not None:raise RuntimeError('SFTP server exited; inspect retained log')
   try:
    with socket.create_connection(('127.0.0.1',ssh_port),timeout=.2):return
   except OSError:time.sleep(.05)
  raise RuntimeError('SFTP listener unavailable')
 def start_https():
  log=(raw/'https-server.log').open('ab');logs['https']=log
  servers['https']=subprocess.Popen([str(binary),'serve','--listen',f'127.0.0.1:{http_port}','--storage',str(storage),'--cert',str(cert),'--key',str(tls_key),'--max-file-bytes',str(8<<20),'--max-stored-bytes',str(128<<20)],stdout=log,stderr=log)
  for _ in range(100):
   if servers['https'].poll() is not None:raise RuntimeError('HTTPS server exited')
   r=subprocess.run(['curl','--silent','--cacert',str(cert),'--max-time','1',f'https://127.0.0.1:{http_port}/healthz'],capture_output=True)
   if r.returncode==0:return
   time.sleep(.05)
  raise RuntimeError('HTTPS listener unavailable')
 def curl(label,route,expected=200,identity=None,extra=()):
  identity=identity or owner;output=raw/(label+'.out')
  identity_base=f'https://127.0.0.1:{http_port}/v1/tenants/{identity["tenant"]}/partners/{identity["partner"]}'
  status=int(command(['curl','--silent','--show-error','--cacert',str(cert),'--max-time','15','--header','@'+str(identity['header']),'--output',str(output),'--write-out','%{http_code}',*extra,identity_base+route]))
  steps.append({'name':label,'http_status':status,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()})
  if status!=expected:raise RuntimeError(f'{label}: HTTP {status}, expected {expected}')
  return output
 def ns(route,path):return '/namespace/'+route+'?'+urlencode({'path':path})
 def stat(label,path):return json.loads(curl(label,ns('stat',path)).read_text())
 start_sftp();start_https()
 payload=private/'synthetic.csv';payload.write_bytes(b'synthetic settlement,000001,100.01\n'*32768);data=payload.read_bytes();digest=hashlib.sha256(data).hexdigest()
 receiver=private/'received.csv'
 batch('stock-put-get',f'mkdir /inbox\nput -p {payload} /inbox/data.csv\nls -l /inbox\nget /inbox/data.csv {receiver}',owner)
 assert receiver.read_bytes()==data
 first=stat('https-sees-sftp-file','/inbox/data.csv');assert first['size_bytes']==len(data)
 assert curl('https-downloads-sftp-revision',ns('file','/inbox/data.csv')).read_bytes()==data
 second=private/'second.csv';second.write_bytes(b'replacement synthetic contents\n')
 batch('stock-overwrite',f'put {second} /inbox/data.csv',owner)
 replaced=stat('immutable-overwrite-stat','/inbox/data.csv');assert replaced['id']==first['id'] and replaced['file_id']!=first['file_id'] and replaced['revision']>first['revision']
 assert curl('retained-original-revision','/files/'+first['file_id']).read_bytes()==data
 prefix=private/'prefix.csv';prefix.write_bytes(data[:65536])
 batch('committed-prefix-reput',f'put {prefix} /inbox/resume.csv\nreput {payload} /inbox/resume.csv\nget /inbox/resume.csv {receiver}',owner)
 assert receiver.read_bytes()==data
 batch('stock-modes-and-rename','chmod 0640 /inbox/data.csv\nrename /inbox /archive\nls -l /archive',owner)
 reader=enroll('reader','read,list','/archive')
 batch('mounted-reader-get',f'ls /\nget /data.csv {receiver}',reader);assert receiver.read_bytes()==second.read_bytes()
 batch('mounted-reader-write-denied',f'put {second} /bad.csv',reader,False)
 batch('mounted-traversal-denied',f'get /../private {receiver}',reader,False)
 hidden=json.loads(curl('owner-unbound-raw-upload','/files',201,extra=['--header','Idempotency-Key: hidden-raw','--header',f'X-File-Size: {len(data)}','--header','X-Content-SHA256: '+digest,'--data-binary','@'+str(payload)]).read_text())['file']
 curl('mounted-raw-id-outside-root-denied','/files/'+hidden['id'],404,reader)
 # A different partner/tenant has its own namespace despite a known path.
 foreign=enroll('foreign',tid=tenant,pid=str(uuid.uuid4()))
 batch('foreign-partner-path-denied',f'get /archive/data.csv {receiver}',foreign,False)
 foreign_tenant=enroll('foreign-tenant',tid=str(uuid.uuid4()),pid=partner)
 batch('foreign-tenant-path-denied',f'get /archive/data.csv {receiver}',foreign_tenant,False)
 wrong=private/'wrong.key';command(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(wrong)])
 wrong_identity={**owner,'key':wrong};batch('wrong-private-key-denied','pwd',wrong_identity,False)
 wrong_trust=private/'wrong_known_hosts';wrong_trust.write_text(f'[127.0.0.1]:{ssh_port} '+Path(str(wrong)+'.pub').read_text())
 batch('changed-host-identity-denied','pwd',owner,False,wrong_trust)
 batch('symlink-denied','ln -s /archive/data.csv /link',owner,False)
 # A stock modern scp download uses SFTP; legacy SCP remains unsupported.
 scp=subprocess.run(['scp','-P',str(ssh_port),*ssh_options(owner['key']),owner['username']+'@127.0.0.1:/archive/data.csv',str(receiver)],capture_output=True,timeout=30)
 (raw/'modern-scp.stderr').write_bytes(scp.stderr);(raw/'modern-scp.stdout').write_bytes(scp.stdout);steps.append({'name':'stock-modern-scp-download','exit_code':scp.returncode,'receiver_sha256':hashlib.sha256(receiver.read_bytes()).hexdigest(),'expected_sha256':hashlib.sha256(second.read_bytes()).hexdigest()});assert scp.returncode==0 and receiver.read_bytes()==second.read_bytes()
 # Modern scp upload uses the same sealed-write and SSH status contract.
 scp=subprocess.run(['scp','-P',str(ssh_port),*ssh_options(owner['key']),str(second),owner['username']+'@127.0.0.1:/archive/from-scp.csv'],capture_output=True,timeout=30)
 (raw/'modern-scp-upload.stderr').write_bytes(scp.stderr);steps.append({'name':'stock-modern-scp-upload','exit_code':scp.returncode});assert scp.returncode==0
 assert curl('https-verifies-modern-scp-upload',ns('file','/archive/from-scp.csv')).read_bytes()==second.read_bytes()
 for label,extra in [('shell-exec-denied',['true']),('forwarding-denied',['-W',f'127.0.0.1:{http_port}'])]:
  args=['ssh','-p',str(ssh_port),*ssh_options(owner['key'])]
  if label=='forwarding-denied':args+=extra+[owner['username']+'@127.0.0.1']
  else:args += [owner['username']+'@127.0.0.1',*extra]
  result=subprocess.run(args,input=b'',capture_output=True,timeout=10);(raw/(label+'.stderr')).write_bytes(result.stderr)
  assert result.returncode!=0 and (b'request failed' in result.stderr or b'administratively prohibited' in result.stderr)
  steps.append({'name':label,'exit_code':result.returncode})
 legacy=subprocess.run(['scp','-O','-P',str(ssh_port),*ssh_options(owner['key']),owner['username']+'@127.0.0.1:/archive/data.csv',str(receiver)],capture_output=True,timeout=10)
 (raw/'legacy-scp-denied.stderr').write_bytes(legacy.stderr);assert legacy.returncode!=0;steps.append({'name':'legacy-scp-exec-denied','exit_code':legacy.returncode})
 # Authenticate a stock SSH subsystem, then exercise malformed-frame and handle bounds.
 def packet(body):return struct.pack('>I',len(body))+body
 def raw_session(label,body,close_handles=False):
  if close_handles:
   return handle_budget_session(label,body)
  r=subprocess.run(['ssh','-p',str(ssh_port),*ssh_options(owner['key']),'-s',owner['username']+'@127.0.0.1','sftp'],input=body,capture_output=True,timeout=15)
  (raw/(label+'.stdout')).write_bytes(r.stdout);(raw/(label+'.stderr')).write_bytes(r.stderr)
  frames=[];rest=r.stdout
  while rest:
   assert len(rest)>=4
   n=struct.unpack('>I',rest[:4])[0];assert 1<=n<=256<<10 and len(rest)>=n+4
   frames.append(rest[4:4+n]);rest=rest[4+n:]
  assert frames and frames[0][0]==2
  steps.append({'name':label,'exit_code':r.returncode,'response_types':[x[0] for x in frames]})
  return r,frames
 def handle_budget_session(label,body):
  args=['ssh','-p',str(ssh_port),*ssh_options(owner['key']),'-s',owner['username']+'@127.0.0.1','sftp']
  proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
  initial=[]
  def exact(n):
   result=b'';deadline=time.monotonic()+10
   while len(result)<n:
    ready,_,_=select.select([proc.stdout],[],[],max(0,deadline-time.monotonic()))
    if not ready:raise RuntimeError('bounded raw SFTP response timed out')
    part=os.read(proc.stdout.fileno(),n-len(result))
    if not part:raise RuntimeError('raw SFTP connection ended before its response')
    result+=part
   return result
  try:
   proc.stdin.write(body);proc.stdin.flush()
   for _ in range(10):
    n=struct.unpack('>I',exact(4))[0];assert 1<=n<=256<<10;initial.append(exact(n))
   handles=[]
   for response in initial[1:9]:
    assert response[0]==102
    n=struct.unpack('>I',response[5:9])[0];assert 1<=n<=128 and len(response)==9+n;handles.append(response[9:])
   closes=b''.join(packet(bytes([4])+struct.pack('>II',100+i,len(handle))+handle) for i,handle in enumerate(handles))
   output,error=proc.communicate(input=closes,timeout=15)
  finally:
   if proc.poll() is None:proc.kill();proc.wait(timeout=5)
  frames=list(initial);tail=output
  while tail:
   assert len(tail)>=4;n=struct.unpack('>I',tail[:4])[0];assert 1<=n<=256<<10 and len(tail)>=n+4;frames.append(tail[4:4+n]);tail=tail[4+n:]
  (raw/(label+'.stdout')).write_bytes(b''.join(packet(f) for f in initial)+output);(raw/(label+'.stderr')).write_bytes(error)
  assert len(frames)==18 and all(x[0]==101 and struct.unpack('>I',x[5:9])[0]==0 for x in frames[10:])
  steps.append({'name':label,'exit_code':proc.returncode,'response_types':[x[0] for x in frames],'closed_handles':8})
  return proc,frames
 init=packet(bytes([1])+struct.pack('>I',3))
 response,frames=raw_session('oversized-frame-denied',init+struct.pack('>I',(256<<10)+1))
 assert response.returncode!=0 and len(frames)==1
 opens=b''.join(packet(bytes([11])+struct.pack('>II',i,1)+b'/') for i in range(1,10))
 response,frames=raw_session('open-handle-budget',init+opens,close_handles=True)
 assert response.returncode==0 and [x[0] for x in frames[1:9]]==[102]*8 and frames[9][0]==101 and struct.unpack('>I',frames[9][5:9])[0]==4
 # Independently publish through HTTPS, then retrieve through SFTP.
 curl('https-publish-for-sftp',ns('file','/archive/from-https.csv'),201,extra=['--request','PUT','--header','Idempotency-Key: cross-protocol','--header',f'X-File-Size: {len(data)}','--header','X-Content-SHA256: '+digest,'--data-binary','@'+str(payload)])
 batch('sftp-retrieves-https-file',f'get /archive/from-https.csv {receiver}',owner);assert receiver.read_bytes()==data
 def slow_upload(label,identity,target):
  global client
  batch_file=private/(label+'.batch');batch_file.write_text(f'put {payload} {target}\n')
  before=set(storage.iterdir());output=(raw/(label+'.log')).open('wb')
  client=subprocess.Popen(['sftp','-l','256','-b',str(batch_file),'-P',str(ssh_port),*ssh_options(identity['key']),identity['username']+'@127.0.0.1'],stdout=output,stderr=output,start_new_session=True)
  deadline=time.monotonic()+8
  while time.monotonic()<deadline:
   candidates=[p for p in storage.iterdir() if p not in before and p.name.startswith(tenant+"_"+partner+"_") and p.is_file() and 0<p.stat().st_size<len(data)]
   if candidates:output.close();return candidates[0]
   if client.poll() is not None:output.close();raise RuntimeError(label+': upload ended before staging was observed')
   time.sleep(.02)
  output.close();raise RuntimeError(label+': no staging bytes observed')
 partial=slow_upload('ordinary-disconnect',owner,'/archive/disconnected.csv')
 curl('active-upload-unpublished',ns('stat','/archive/disconnected.csv'),404)
 os.killpg(client.pid,signal.SIGTERM);client.wait(timeout=8);client=None
 deadline=time.monotonic()+5
 while partial.exists() and time.monotonic()<deadline:time.sleep(.02)
 assert not partial.exists();curl('disconnected-upload-unpublished',ns('stat','/archive/disconnected.csv'),404)
 steps.append({'name':'ordinary disconnect removes unsealed partial without publication','passed':True})
 batch('grant-partner-dropbox-mode','chmod 0770 /archive',owner)
 revocable=enroll('revocable-writer','read,write,list,manage_paths','/archive')
 partial=slow_upload('active-key-revocation',revocable,'/revoked.csv')
 cli('ssh-key-revoke','--tenant',tenant,'--partner',partner,'--token-file',str(revocable['token']),'--ssh-key-id',revocable['registered']['key_id'])
 client.wait(timeout=8);assert client.returncode!=0;client=None
 deadline=time.monotonic()+5
 while partial.exists() and time.monotonic()<deadline:time.sleep(.02)
 assert not partial.exists();curl('revoked-active-upload-unpublished',ns('stat','/archive/revoked.csv'),404)
 steps.append({'name':'live SSH key revocation aborts uncommitted upload','passed':True})
 partial=slow_upload('process-crash',owner,'/archive/crashed.csv')
 servers['sftp'].kill();servers['sftp'].wait(timeout=5);servers.pop('sftp');logs.pop('sftp').close()
 client.wait(timeout=8);assert client.returncode!=0;client=None
 assert partial.exists() and 0<partial.stat().st_size<len(data)
 curl('crashed-upload-unpublished',ns('stat','/archive/crashed.csv'),404)
 report=json.loads(curl('crash-reconciliation','/custody/reconcile').read_text());assert report['counts'].get('unreferenced_bytes')==1 and not report['consistent']
 start_sftp();batch('retry-after-server-crash',f'put {payload} /archive/crashed.csv\nget /archive/crashed.csv {receiver}',owner);assert receiver.read_bytes()==data and partial.exists()
 current=stat('crash-retry-new-revision','/archive/crashed.csv');assert not partial.name.endswith(current['file_id'])
 revoked=json.loads(cli('ssh-key-revoke','--tenant',tenant,'--partner',partner,'--token-file',str(reader['token']),'--ssh-key-id',reader['registered']['key_id']));assert revoked['revoked']
 batch('revoked-key-login-denied','pwd',reader,False)
 # Revoked enrollment retries must not silently restore access.
 r=subprocess.run([str(binary),'ssh-key-enroll','--tenant',tenant,'--partner',partner,'--token-file',str(reader['token']),'--ssh-public-file',str(reader['key'])+'.pub'],capture_output=True);assert r.returncode!=0
 steps.append({'name':'revoked key cannot be resurrected by enrollment retry','exit_code':r.returncode})
 state='passed';failure=None
except Exception as error:state='failed';failure=traceback.format_exc()
finally:
 if client is not None:
  if client.poll() is None:os.killpg(client.pid,signal.SIGTERM)
  client.wait(timeout=8)
 for name in list(servers):stop(name)
paths=command(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'id':run_id,'state':state,'failure':failure,'starting_commit':command(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'environment':{'os':os.uname().sysname,'arch':os.uname().machine,'go':command(['sh','scripts/go.sh','version']).decode().strip(),'ssh':subprocess.run(['ssh','-V'],capture_output=True).stderr.decode().strip()},'elapsed_seconds':round(time.monotonic()-started,3),'steps':steps,'private_fixture_reference':str(private.relative_to(root)),'raw_evidence_reference':str(raw.relative_to(root)),'limits':['Assisted synthetic exchange on one Mac and one local PostgreSQL container.','Server receive/download role only; no outbound SFTP connection adapter or independent enterprise peer.','Reput resumes a committed prefix; interrupted-upload session resume remains open.','One frame at a time, 256 KiB inbound frames, 100000 packets/session, eight handles/session, configured writers/time/file/storage budgets. No throughput claim.','Integrity-only: no malware scan, payload signature or business acknowledgment.','Legacy SCP, sparse expansion, read/write handles, ownership changes, fsync/hardlink/statvfs extensions are unsupported.','All full product journeys and release/native platform gates remain open.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/sftp-current').write_text(str(raw)+'\n')
print(json.dumps({'state':state,'manifest':str(raw/'manifest.json'),'failure':failure},indent=2))
if state!='passed':raise SystemExit(1)
