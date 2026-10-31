#!/usr/bin/env python3
"""Recorded onboarding evidence through real scoped services and independent peers.

Uses one exact retained task PostgreSQL instance, a fresh fixture database,
loopback HTTPS/stock SFTP and an explicitly selected bounded native crypto peer.
No inference, scanner or shared Docker lifecycle operation.
"""
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
import argparse,hashlib,json,os,re,signal,socket,subprocess,time,traceback,uuid
if not __debug__:
 raise RuntimeError("Qualification requires assertions; remove Python -O/PYTHONOPTIMIZE")
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
parser=argparse.ArgumentParser();parser.add_argument('--postgres-container-id',required=True);parser.add_argument('--recorded-tests',action='store_true');options=parser.parse_args()
assert re.fullmatch(r'[0-9a-f]{64}',options.postgres_container_id),'use the exact task-owned PostgreSQL container ID'
run='onboarding-exchange-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
binary=private/'freightctl';database='freightctl_'+run.replace('-','_');created=False;servers={};logs={};steps=[];cleanup=[];state='failed';failure=None;started=time.monotonic()
env=dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
pg=options.postgres_container_id
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 return {p:sha(root/p) for p in sorted(set(paths)) if p and (Path(p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p.startswith('web/tests/fixtures/') or p in ('go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'))}
initial=sources();(root/'.private/onboarding-exchange-runtime-current').write_text(str(raw)+'\n')
def command(label,args,expected=0,timeout=100):
 start=time.monotonic();out=raw/(label+'.stdout');err=raw/(label+'.stderr')
 with out.open('wb') as o,err.open('wb') as e:r=subprocess.run(list(map(str,args)),stdout=o,stderr=e,env=env,timeout=timeout)
 steps.append({'name':label,'command':list(map(str,args)),'exit_code':r.returncode,'expected_exit_code':expected,'duration_seconds':round(time.monotonic()-start,3),'stdout_sha256':sha(out),'stderr_sha256':sha(err)})
 if r.returncode!=expected:raise RuntimeError(label+' failed; inspect protected native output')
 return out.read_bytes()
def sql(text,db=None):return subprocess.check_output(['docker','exec',pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d',db or database,'-At','-c',text],env=env,timeout=30).decode().strip()
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def stop(name):
 p=servers.pop(name,None)
 if p is not None:
  if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
 if name in logs:logs.pop(name).close()
def start(name,args,number):
 assert name not in servers
 logs[name]=(raw/(name+'.log')).open('ab');servers[name]=subprocess.Popen(list(map(str,args)),stdout=logs[name],stderr=logs[name],env=env,start_new_session=True)
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  assert servers[name].poll() is None,name+' exited'
  try:
   with socket.create_connection(('127.0.0.1',number),timeout=.2):return
  except OSError:time.sleep(.05)
 raise RuntimeError(name+' unavailable')
def write(name,value):
 p=private/(name+'.json');p.write_text(json.dumps(value));return p
def ref(c):return {'id':c['id'],'version':c['version'],'hash':c['definition_hash']}
def decision(c):return {'definition_hash':c['definition_hash'],'expected_revision':c['revision']}
try:
 meta=json.loads(subprocess.check_output(['docker','inspect','--format','{"workspace":{{json (index .Config.Labels "freightctl.workspace")}},"running":{{json .State.Running}},"memory":{{json .HostConfig.Memory}},"cpu":{{json .HostConfig.NanoCpus}}}',pg]))
 assert meta=={'workspace':str(root),'running':True,'memory':536870912,'cpu':1000000000}
 native_config=Path(env['FREIGHTCTL_GNUPG_NATIVE_CONFIG']).resolve();assert native_config.is_file() and native_config.is_relative_to(root/'.private')
 command('build',['sh','scripts/go.sh','build','-p','1','-trimpath','-buildvcs=false','-o',binary,'./cmd/freightctl'])
 sql('CREATE DATABASE '+database,'freightctl');created=True
 for name in ['pg-admin.dsn','pg-runtime.dsn']:
  source=root/'.private'/name;assert source.is_file() and not source.is_symlink() and source.stat().st_mode&0o077==0
  (private/name).write_text(urlunsplit(urlsplit(source.read_text())._replace(path='/'+database)))
 admin,runtime=private/'pg-admin.dsn',private/'pg-runtime.dsn'
 command('migrate-isolated-database',[binary,'init','--admin-dsn-file',admin])
 tenant,partner=str(uuid.uuid4()),str(uuid.uuid4());storage=private/'custody'
 def invoke(label,op,*extra,token=None,expected=0):
  base=[binary,op,'--admin-dsn-file',admin,'--dsn-file',runtime,'--tenant',tenant,'--partner',partner,'--storage',storage]
  if token is not None:base+=['--token-file',token]
  data=command(label,[*base,*extra],expected=expected)
  return json.loads(data) if expected==0 and data else None
 def identity(name,permissions=None):
  token=private/(name+'.token');command(name+'-token',[binary,'token','--token-file',token])
  args=['--permissions',permissions] if permissions else []
  invoke(name+'-enroll','enroll',*args,token=token);return token
 owner=identity('owner');other=identity('other');limited=identity('limited','admin,read,accounts_manage,connections_manage')
 header=private/'owner.headers';header.write_bytes(b'Authorization: Bearer '+owner.read_bytes()+b'\n')
 cert,key=private/'cert.pem',private/'key.pem';command('certificate',[binary,'dev-cert','--cert',cert,'--key',key])
 http_port,receiver_port=port(),port();url='https://127.0.0.1:'+str(http_port);prefix=f'/v1/tenants/{tenant}/partners/{partner}'
 server_args=[binary,'serve','--dsn-file',runtime,'--storage',storage,'--listen',f'127.0.0.1:{http_port}','--cert',cert,'--key',key,'--max-file-bytes',str(4<<20)]
 start('https',server_args,http_port)
 def post(label,route,body=None,expected=200,key=None,who=None,scope=None,method='POST'):
  out=raw/(label+'.json');args=['curl','--silent','--show-error','--cacert',cert,'--max-time','30','--header','@'+str(who or header),'--request',method,'--output',out,'--write-out','%{http_code}']
  if key:args+=['--header','Idempotency-Key: '+key]
  if body is not None:
   p=private/(label+'.request');p.write_bytes(body if isinstance(body,bytes) else json.dumps(body).encode());args+=['--header','Content-Type: application/json','--data-binary','@'+str(p)]
  code=int(command(label,[*args,url+(scope or prefix)+route]).decode())
  steps[-1].update(http_status=code,expected_status=expected,response_sha256=sha(out))
  assert code==expected,(label,code,expected)
  return json.loads(out.read_bytes())
 for name in ['host','client']:
  command('ssh-key-'+name,['ssh-keygen','-q','-t','ed25519','-N','','-f',private/name])
 (private/'authorized_keys').write_bytes((private/'client.pub').read_bytes())
 user=command('native-os-receiver-account',['id','-un']).decode().strip();inbox=private/'inbox';inbox.mkdir(mode=0o700)
 sshconf=private/'sshd_config';sshconf.write_text(f'''Port {receiver_port}
ListenAddress 127.0.0.1
HostKey {private/'host'}
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
 start('receiver',['/usr/sbin/sshd','-D','-e','-f',sshconf],receiver_port)
 known=private/'known_hosts';known.write_text(f'[127.0.0.1]:{receiver_port} '+(private/'host.pub').read_text())
 connection=invoke('register-receiver','connection-register','--request-file',write('connection',{'expected_version':0,'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'host_public_file':str(private/'host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}),'--idempotency-key','connection',token=owner)['resource']
 fixture=Path(command('native-crypto-fixtures',['python3','scripts/prepare-pgp-fixture.py','--native-config',native_config,'--rows','2'],timeout=150).decode().strip());peer=json.loads((fixture/'manifest.json').read_text());assert peer['state']=='passed' and peer['peer_backend']=='native-macos'
 payload=fixture/'source.csv';data=payload.read_bytes();digest=sha(payload)
 out=raw/'accepted.json';command('stock-curl-source',['curl','--silent','--show-error','--fail','--cacert',cert,'--max-time','20','--header','@'+str(header),'--header','Idempotency-Key: source','--header','X-File-Size: '+str(len(data)),'--header','X-Content-SHA256: '+digest,'--data-binary','@'+str(payload),'--output',out,url+prefix+'/files'])
 accepted=json.loads(out.read_bytes())['file'];assert accepted['sha256']==digest
 contact,integrity,business,plan_id=[str(uuid.uuid4()) for _ in range(4)]
 definition={'schema_version':1,'name':'Qualified recorded exchange','contacts':[{'id':contact,'name':'Synthetic operations','role':'Transfer support','email':'operations@freightctl.invalid','phone':''}],'requirements':[{'id':ident,'name':label,'contact_id':contact,'direction':'send','protocol':'sftp','required_receipt':receipt,'receipt_contract':'SYNTHETIC_PRIVATE_CONTRACT','notes':'SYNTHETIC_PRIVATE_NOTES'} for ident,label,receipt in [(integrity,'Exact file integrity','integrity'),(business,'Business acceptance','business')]]}
 saved={'plan_id':plan_id,'expected_version':0,'expected_authority_revision':1,'definition':definition}
 plan=invoke('record-requirements','partner-onboarding-save','--request-file',write('plan',saved),'--idempotency-key','plan',token=owner)['plan']
 probes={}
 for ident,label in [(integrity,'integrity'),(business,'business')]:
  p=post('probe-start-'+label,'/onboarding-probes',{'plan':ref(plan),'requirement_id':ident,'connection':ref(connection),'expected_authority_revision':1},key='probe-'+label)['resource']
  v=post('probe-work-'+label,'/onboarding-probes/'+p['id']+'/work',{'definition_hash':p['definition_hash']},key='probe-work-'+label)
  assert v['probe']['state']=='succeeded' and not v['file_exchange_performed'];probes[label]=v['probe']
 assert list(inbox.iterdir())==[]
 tests={};workflows={}
 def create_run(label,encryption=None,p=None,probe=None):
  step={'id':'send','kind':'sftp.deliver','connection':ref(connection),'filename':label+'.bin'}
  if encryption:step['encryption']=encryption
  draft=post(label+'-draft','/workflows/drafts',{'expected_version':0,'definition':{'schema_version':1,'name':label,'steps':[step]}},key=label+'-draft')['resource']
  approved=post(label+'-approve','/workflows/'+draft['id']+'/1/approve',decision(draft),key=label+'-approve')['resource']
  workflows[label]=approved
  if options.recorded_tests:
   selection0={'plan':ref(p or plan),'requirement_id':integrity,'probe_id':(probe or probes['integrity'])['id'],'workflow':ref(approved),'file_id':accepted['id'],'expected_authority_revision':1}
   before=(raw/'receiver.log').read_text().count('Accepted publickey for ');before_files=sorted(x.name for x in inbox.iterdir())
   preview=post(label+'-test-preview','/onboarding-tests/preview',selection0)
   cli=invoke(label+'-test-cli-preview','partner-onboarding-test-preview','--request-file',write(label+'-test-selection',selection0),token=owner);assert cli==preview
   assert not preview['external_contact'] and not preview['production_active'] and preview['definition']['effect']['address']==connection['address'] and preview['definition']['effect']['filename']==label+'.bin'
   if encryption:assert preview['definition']['effect']['recipient_fingerprint']==recipient['fingerprint']
   body={'definition':preview['definition']};saved0=post(label+'-test-start','/onboarding-tests',body,key=label+'-test')['resource'];test=saved0['test'];tests[label]=test
   replay0=post(label+'-test-replay','/onboarding-tests',body,key=label+'-test');assert replay0['replayed'] and replay0['resource']==saved0
   cli=invoke(label+'-test-cli-replay','partner-onboarding-test-start','--request-file',write(label+'-test-start',body),'--idempotency-key',label+'-test',token=owner);assert cli['replayed'] and cli['resource']==saved0
   status=post(label+'-test-queued','/onboarding-tests/'+test['id'],method='GET');assert status['current_bindings'] and status['status']['observed_state']=='queued' and status['status']['steps'][0]['attempts']==0
   assert invoke(label+'-test-cli-status','partner-onboarding-test-status','--onboarding-test-id',test['id'],token=owner)==status
   assert before==(raw/'receiver.log').read_text().count('Accepted publickey for ') and before_files==sorted(x.name for x in inbox.iterdir()),'saving queued test contacted receiver'
   return saved0['run']
  return post(label+'-run','/workflow-runs',{'workflow':ref(approved),'file_id':accepted['id']},key=label+'-run')['resource']
 def selection(run,label='integrity',p=plan):return {'plan':ref(p),'requirement_id':integrity if label=='integrity' else business,'probe_id':probes[label]['id'],'run_id':run['id'],'step_id':'send','expected_authority_revision':1}
 plain=create_run('plain');pending=post('unfinished-exchange-is-not-proof','/onboarding-exchange-review',selection(plain));assert not pending['ready_for_approval_review'] and pending['reason']=='exchange_not_succeeded'
 def receive(label,run,expected):
  done=post(label+'-deliver','/workflow-runs/'+run['id']+'/work',key=label+'-work');assert done['status']['observed_state']=='succeeded'
  step=done['status']['steps'][0];target=inbox/(step['delivery_id']+'-'+label+'.bin');received=private/(label+'-received.bin');batch=private/(label+'.batch');batch.write_text(f'get {target} {received}\n')
  command(label+'-independent-stock-sftp',['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,user+'@127.0.0.1'])
  assert sha(received)==expected and received.read_bytes()==target.read_bytes()
  return received,step
 receive('plain',plain,digest)
 recipient=invoke('register-recipient','pgp-key-register','--request-file',write('recipient',{'expected_version':0,'fingerprint':peer['fingerprints']['recipient'],'purpose':'encrypt'}),'--pgp-public-file',fixture/'recipient-public.gpg','--idempotency-key','recipient',token=owner)['resource']
 cipher_run=create_run('encrypted',{'key':ref(recipient),'profile':'seipd-v1-aes256'})
 done=post('encrypted-deliver','/workflow-runs/'+cipher_run['id']+'/work',key='encrypted-work');assert done['status']['observed_state']=='succeeded';cipher=done['status']['steps'][0]['ciphertext']
 target=inbox/(done['status']['steps'][0]['delivery_id']+'-encrypted.bin');received=private/'encrypted-received.bin';batch=private/'encrypted.batch';batch.write_text(f'get {target} {received}\n')
 command('encrypted-independent-stock-sftp',['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,user+'@127.0.0.1']);assert sha(received)==cipher['sha256'] and received.read_bytes()!=data
 decrypted=private/'decrypted.csv';proof=command('independent-native-decryption',['python3','scripts/pgp-native-peer.py','--config',native_config,'--metrics',raw/'decryption-metrics.json','decrypt','--key',fixture/'recipient-private.gpg','--cipher',received,'--output',decrypted]);assert decrypted.read_bytes()==data and b'DECRYPTION_OKAY' in proof and b'GOODMDC' in proof
 resources=[plan['id'],connection['id'],recipient['id'],accepted['id'],plain['id'],plain['workflow_id'],cipher_run['id'],cipher_run['workflow_id'],*[p['id'] for p in probes.values()]]
 resource_filter="resource_id IN ("+','.join("'"+ident+"'::uuid" for ident in resources)+") OR kind IN ('DeliveryTransitioned','DeliveryCiphertextPrepared','WorkflowStepBound')"
 event_count=sql('SELECT count(*) FROM events WHERE '+resource_filter);contacts=(raw/'receiver.log').read_text().count('Accepted publickey for ');files=sorted(p.name for p in inbox.iterdir())
 results={}
 for label,run0 in [('plain',plain),('encrypted',cipher_run)]:
  req=selection(run0);review=post(label+'-api-review','/onboarding-exchange-review',req)
  assert review['ready_for_approval_review'] and review['reason']=='recorded_evidence_matches' and not review['production_active'] and not review['external_contact'] and review['business_acceptance']=='unknown'
  assert review['snapshot']['file']==accepted and review['snapshot']['connection']==ref(connection)
  assert review['snapshot']['transfer_sha256']==(digest if label=='plain' else cipher['sha256'])
  assert not any(s in json.dumps(review) for s in ['SYNTHETIC_PRIVATE_NOTES','SYNTHETIC_PRIVATE_CONTRACT',str(private/'client'),'key_file'])
  cli_review=invoke(label+'-cli-review','partner-onboarding-exchange-review','--request-file',write(label+'-review',req),token=owner)
  assert cli_review['snapshot_hash']==review['snapshot_hash'] and cli_review['snapshot']==review['snapshot'];results[label]=review
  if options.recorded_tests:
   test_review=post(label+'-precontact-lineage-review','/onboarding-tests/'+tests[label]['id']+'/review',method='GET');assert {k:v for k,v in test_review.items() if k!='observed_at'}=={k:v for k,v in review.items() if k!='observed_at'}
   cli_test_review=invoke(label+'-test-cli-review','partner-onboarding-test-review','--onboarding-test-id',tests[label]['id'],token=owner);assert {k:v for k,v in cli_test_review.items() if k!='observed_at'}=={k:v for k,v in review.items() if k!='observed_at'}
 business_review=post('integrity-does-not-meet-business-contract','/onboarding-exchange-review',selection(plain,'business'));assert not business_review['ready_for_approval_review'] and business_review['reason']=='business_receipt_missing' and business_review['snapshot']['observed_receipt']=='integrity'
 for name,tok,expected in [('other-actor',other,404),('missing-workflow-grant',limited,403)]:
  hdr=private/(name+'.headers');hdr.write_bytes(b'Authorization: Bearer '+tok.read_bytes()+b'\n');post(name+'-denied','/onboarding-exchange-review',selection(plain),expected=expected,who=hdr)
 post('cross-partner-denied','/onboarding-exchange-review',selection(plain),expected=401,scope=f'/v1/tenants/{tenant}/partners/{uuid.uuid4()}')
 for field in ['plan','requirement_id','probe_id','run_id','step_id','expected_authority_revision']:
  req=selection(plain);expected=409
  if field=='plan':req[field]=dict(req[field],hash='0'*64)
  elif field in ['probe_id','run_id']:req[field]=str(uuid.uuid4());expected=404
  elif field=='requirement_id':req[field]=business
  elif field=='step_id':req[field]='different'
  else:req[field]=2
  post('changed-'+field,'/onboarding-exchange-review',req,expected=expected)
 post('invented-receipt-denied','/onboarding-exchange-review',dict(selection(plain),receipt={'business_acceptance':'accepted'}),expected=400)
 stop('https');start('https',server_args,http_port)
 assert post('review-after-server-restart','/onboarding-exchange-review',selection(cipher_run))['snapshot_hash']==results['encrypted']['snapshot_hash']
 cfg={'root':str(root),'private':str(private),'raw':str(raw),'url':url,'certificate':str(cert),'tenant':tenant,'partner':partner,'token':str(owner),'plan':plan,'plain':selection(plain),'encrypted':selection(cipher_run),'business':selection(plain,'business'),'plain_hash':results['plain']['snapshot_hash'],'encrypted_hash':results['encrypted']['snapshot_hash']}
 node=env.get('FREIGHTCTL_NODE_BIN') or 'node';command('native-browser-review',[node,'scripts/onboarding-exchange-browser.mjs',write('browser',cfg)],timeout=120)
 assert event_count==sql('SELECT count(*) FROM events WHERE '+resource_filter) and contacts==(raw/'receiver.log').read_text().count('Accepted publickey for ') and files==sorted(p.name for p in inbox.iterdir()),'read-only review mutated exchange or recontacted receiver'
 if options.recorded_tests:
  cfg.update(test_only=True,test_selection={'plan':ref(plan),'requirement_id':integrity,'probe_id':probes['integrity']['id'],'workflow':ref(workflows['plain']),'file_id':accepted['id'],'expected_authority_revision':1})
  command('native-browser-recorded-test',[node,'scripts/onboarding-exchange-browser.mjs',write('test-browser',cfg)],timeout=120)
  observed=json.loads((raw/'onboarding-test-browser-result.json').read_text());browser_test=observed['test'];assert observed['state']=='passed'
  status=post('browser-test-status','/onboarding-tests/'+browser_test['id'],method='GET');assert status['status']['observed_state']=='succeeded'
  target=inbox/(status['status']['steps'][0]['delivery_id']+'-plain.bin');received=private/'browser-received.bin';batch=private/'browser.batch';batch.write_text(f'get {target} {received}\n')
  command('browser-test-independent-stock-sftp',['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,user+'@127.0.0.1']);assert received.read_bytes()==data
  stale=create_run('stale-queued');stale_contacts=(raw/'receiver.log').read_text().count('Accepted publickey for ')
  files=sorted(p.name for p in inbox.iterdir())
 saved['expected_version']=1;saved['definition']['name']='Changed saved requirements'
 current_plan=invoke('save-changed-requirements','partner-onboarding-save','--request-file',write('plan-v2',saved),'--idempotency-key','plan-v2',token=owner)['plan']
 post('old-probe-cannot-qualify-new-plan','/onboarding-exchange-review',selection(plain),expected=409)
 if options.recorded_tests:
  changed=post('stale-test-private-history','/onboarding-tests/'+tests['stale-queued']['id'],method='GET');assert not changed['current_bindings'] and changed['status']['observed_state']=='attention'
  post('stale-test-work-denied','/workflow-runs/'+stale['id']+'/work',key='stale-work',expected=409)
  changed=post('stale-test-no-attempt','/onboarding-tests/'+tests['stale-queued']['id'],method='GET');assert changed['status']['steps'][0]['attempts']==0 and stale_contacts==(raw/'receiver.log').read_text().count('Accepted publickey for ')
 fresh=post('current-plan-probe-start','/onboarding-probes',{'plan':ref(current_plan),'requirement_id':integrity,'connection':ref(connection),'expected_authority_revision':1},key='current-plan-probe')['resource']
 fresh=post('current-plan-probe-work','/onboarding-probes/'+fresh['id']+'/work',{'definition_hash':fresh['definition_hash']},key='current-plan-probe-work')['probe'];assert fresh['state']=='succeeded';probes['integrity']=fresh
 current_request=selection(cipher_run,p=current_plan)
 current_review=post('current-bindings-positive-control','/onboarding-exchange-review',current_request);assert current_review['ready_for_approval_review'] and current_review['snapshot']['selection']['plan']==ref(current_plan)
 if options.recorded_tests:
  fresh_run=create_run('revoke-queued',p=current_plan,probe=fresh)
 post('revoke-connection','/connections/'+connection['id']+'/1/revoke',decision(connection),key='revoke-connection')
 post('revoked-connection-denies-current-review','/onboarding-exchange-review',current_request,expected=409)
 if options.recorded_tests:
  changed=post('revoked-test-state','/onboarding-tests/'+tests['revoke-queued']['id'],method='GET');assert not changed['current_bindings'] and changed['status']['steps'][0]['attempts']==0
  post('revoked-test-work-denied','/workflow-runs/'+fresh_run['id']+'/work',key='revoked-work',expected=409)
  assert len(post('test-private-history','/onboarding-plans/'+plan['id']+'/tests',method='GET')['tests'])==5
 assert files==sorted(p.name for p in inbox.iterdir())
 state='passed'
except Exception:failure=traceback.format_exc()
finally:
 for name in list(servers):
  try:stop(name)
  except Exception:cleanup.append('process cleanup failed: '+name)
 if created:
  try:sql('DROP DATABASE '+database+' WITH (FORCE)','freightctl')
  except Exception:cleanup.append('exact fixture database cleanup failed')
 final=sources();unchanged=initial==final
 manifest={'schema_version':1,'recorded_tests':options.recorded_tests,'state':state if unchanged and not cleanup else 'failed','failure':failure,'cleanup_failures':cleanup,'observed_at':datetime.now(timezone.utc).isoformat(),'postgres_container_id':pg,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_sha256':initial,'sources_unchanged_during_run':unchanged,'changed_source_paths':[p for p in set(initial)|set(final) if initial.get(p)!=final.get(p)],'binary_sha256':sha(binary) if binary.exists() else None,'private_reference':str(private.relative_to(root)),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'isolated_database_removed':created and not cleanup,'peer_reference':str(fixture/'manifest.json') if 'fixture' in globals() else None,'inference_performed':False,'scanner_engine_started':False,'full_journeys_qualified':False,'limits':['Assisted same-host loopback qualification; independent operators, full J05 approval/activation and production remain open.','Native stock receiver and GnuPG are independent observers; no downstream business acceptance or directory power-loss durability is claimed.','No complete core replay is performed; F026 replay remains owner-deferred.','No model, scanner, signature database or shared Docker lifecycle operation. Native crypto uses its selected sampled 128 MiB process-family watchdog; observer/OS costs remain separate.']}
 (raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(str(raw/'manifest.json'),flush=True)
 if failure:print(failure,flush=True)
if manifest['state']!='passed':raise SystemExit(1)
