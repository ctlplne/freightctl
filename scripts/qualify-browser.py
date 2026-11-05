#!/usr/bin/env python3
"""Real native browser, PostgreSQL and filesystem journey; no inference or AV engine."""
from ci_resources import environment as ci_environment
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,os,shutil,socket,subprocess,time,uuid
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
parser=argparse.ArgumentParser();parser.add_argument('--signed',action='store_true');args=parser.parse_args()
profile='browser-signed' if args.signed else 'browser'
run=profile+'-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
server=None;log=None;steps=[];started=time.monotonic();env=ci_environment(dict(os.environ,GOMAXPROCS='1',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright')))
binary=root/'.cache/freightctl-browser'
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 special={'go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'}
 return [{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()}for p in sorted(set(paths))if p and ((root/p).suffix in('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml')or p in special)]
initial=sources()
def command(label,args,timeout=120):
 start=time.monotonic();p=raw/(label+'.log')
 with p.open('wb')as f:r=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,env=env,timeout=timeout)
 steps.append({'name':label,'command':args,'exit_code':r.returncode,'duration_seconds':round(time.monotonic()-start,3),'native_output':str(p.relative_to(root)),'native_output_sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 if r.returncode:raise RuntimeError(label+' failed; inspect retained native output')
def cli(*args):return subprocess.check_output([str(binary),*args],env=env)
def stop():
 global server,log
 if server is not None:
  server.terminate()
  try:server.wait(timeout=8)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
  server=None
 if log is not None:log.close();log=None
state='failed';failure=None
try:
 command('browser-artifacts',['npm','--prefix','web','run','check-built'])
 command('build',['sh','scripts/go.sh','build','-p','1','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/freightctl'])
 cli('init');cli('dev-cert','--cert',str(private/'cert.pem'),'--key',str(private/'key.pem'));cli('audit-keygen','--audit-key-file',str(private/'audit.key'),'--audit-public-file',str(private/'audit.pub'))
 tenant,partner,other_tenant,other_partner=[str(uuid.uuid4())for _ in range(4)];identities=[]
 for i,(tid,pid)in enumerate([(tenant,partner),(tenant,partner),(other_tenant,other_partner)]):
  token=private/f'account-{i}.token';cli('token','--token-file',str(token));cli('enroll','--tenant',tid,'--partner',pid,'--token-file',str(token));identities.append({'tenant':tid,'partner':pid,'token':str(token)})
 payload=b'account,amount,day\n'+b'00000001,100.01,2026-10-28\n'*100000;(private/'source.csv').write_bytes(payload);(private/'wrong.csv').write_bytes(payload.replace(b'100.01',b'100.02'))
 policy={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':64},{'name':'amount','type':'decimal','required':True,'max_bytes':64,'precision':12,'scale':2},{'name':'day','type':'date','required':True,'max_bytes':10}],'max_bytes':8<<20,'max_rows':100000,'max_record_bytes':65536,'timeout_seconds':30}}
 signature_config=None
 if args.signed:
  command('fresh-independent-signatures',['python3','scripts/prepare-pgp-fixture.py','--rows','100000'],150)
  fixture=Path((root/'.private/pgp-fixture-current').read_text().strip())
  peer_manifest=json.loads((fixture/'manifest.json').read_text());assert peer_manifest['state']=='passed' and (fixture/'source.csv').read_bytes()==payload
  metadata=private/'signer.json';metadata.write_text(json.dumps({'expected_version':0,'fingerprint':peer_manifest['fingerprints']['good']}))
  signer=json.loads(cli('pgp-key-register','--tenant',tenant,'--partner',partner,'--token-file',str(private/'account-0.token'),'--request-file',str(metadata),'--pgp-public-file',str(fixture/'good-public.asc'),'--idempotency-key','browser-signer'))['resource']
  policy['definition']['signature']={'key':{'id':signer['id'],'version':signer['version'],'hash':signer['definition_hash']},'max_age_seconds':3600}
  signature_config={'good':str(fixture/'good.sig.asc'),'wrongSigner':str(fixture/'other.sig'),'weak':str(fixture/'weak.sig'),'fixtureManifest':str(fixture/'manifest.json'),'publicKey':str(fixture/'good-public.gpg'),'primary':peer_manifest['fingerprints']['good'],'subkey':peer_manifest['fingerprints']['subkey'],'key':policy['definition']['signature']['key'],'keyRevision':signer['revision']}
 (private/'policy.json').write_text(json.dumps(policy));cli('intake-policy-register','--tenant',tenant,'--partner',partner,'--token-file',str(private/'account-0.token'),'--request-file',str(private/'policy.json'),'--idempotency-key','browser-policy')
 with socket.socket()as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 url='https://127.0.0.1:'+str(port)
 config={'root':str(root),'url':url,'tenant':tenant,'partner':partner,'identities':identities,'payload':str(private/'source.csv'),'wrongPayload':str(private/'wrong.csv'),'certificate':str(private/'cert.pem'),'private':str(private),'raw':str(raw),'signatures':signature_config};(private/'config.json').write_text(json.dumps(config))
 def start(lifetime=600):
  global server,log
  log=(raw/'server.log').open('ab');server=subprocess.Popen([str(binary),'serve','--listen','127.0.0.1:'+str(port),'--storage',str(private/'custody'),'--cert',str(private/'cert.pem'),'--key',str(private/'key.pem'),'--audit-key-file',str(private/'audit.key'),'--max-file-bytes',str(8<<20),'--browser-session-seconds',str(lifetime)],stdout=log,stderr=log,env=env)
  for _ in range(100):
   r=subprocess.run(['curl','--silent','--show-error','--cacert',str(private/'cert.pem'),'--max-time','1',url+'/healthz'],capture_output=True)
   if r.returncode==0:return
   if server.poll()is not None:raise RuntimeError('browser fixture server exited')
   time.sleep(.05)
  raise RuntimeError('browser fixture did not become healthy')
 node=os.environ.get('FREIGHTCTL_NODE_BIN')or shutil.which('node')
 if not node:raise RuntimeError('Node.js is required')
 start();command('native-pause',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'pause']);stop();start();command('native-resume-release-download',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'resume'])
 # The stock receiver uses its own explicit bearer reference and TLS trust.
 checkpoint=json.loads((private/'checkpoint.json').read_text());header=private/'receiver.headers';header.write_bytes(b'Authorization: Bearer '+(private/'account-0.token').read_bytes()+b'\n')
 from urllib.parse import urlencode
 command('independent-stock-curl-receiver',['curl','--silent','--show-error','--fail','--cacert',str(private/'cert.pem'),'--header','@'+str(header),'--output',str(private/'curl-received.csv'),url+f'/v1/tenants/{tenant}/partners/{partner}/namespace/file?'+urlencode({'path':'/business.csv'})])
 assert hashlib.sha256((private/'curl-received.csv').read_bytes()).hexdigest()==hashlib.sha256(payload).hexdigest()
 if args.signed:
  completed=json.loads((private/'checkpoint-completed.json').read_text());served=private/'served.sig'
  command('retrieve-stored-signature',['curl','--silent','--show-error','--fail','--cacert',str(private/'cert.pem'),'--header','@'+str(header),'--output',str(served),url+f'/v1/tenants/{tenant}/partners/{partner}/checks/'+completed['file_id']+'/signature'])
  assert served.read_bytes()==Path(signature_config['good']).read_bytes()
  for receiver in ['browser-received.csv','curl-received.csv']:
   label='independent-verify-'+receiver
   if env.get('FREIGHTCTL_GNUPG_NATIVE_CONFIG'):
    peer_command=['python3','scripts/pgp-native-peer.py','--config',env['FREIGHTCTL_GNUPG_NATIVE_CONFIG'],'--metrics',str(raw/(label+'-metrics.json')),'verify','--key',signature_config['publicKey'],'--signature',str(served),'--source',str(private/receiver)]
   else:
    peer_command=['docker','run','--rm','--name','freightctl-'+run+'-'+receiver,'--label','freightctl.workspace='+str(root),'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=64','--tmpfs','/tmp:rw,noexec,nosuid,size=8m','-v',signature_config['publicKey']+':/public.gpg:ro','-v',str(served)+':/signature.sig:ro','-v',str(private/receiver)+':/data.csv:ro',peer_manifest['peer_image'],'/bin/sh','-ec',"mkdir -m 700 /tmp/gnupg; export GNUPGHOME=/tmp/gnupg; gpg --batch --import /public.gpg; gpg --batch --no-auto-key-retrieve --status-fd 1 --verify /signature.sig /data.csv; gpgconf --kill all"]
   command(label,peer_command)
   verified=(raw/(label+'.log')).read_text().lower();assert '[gnupg:] validsig '+signature_config['subkey'] in verified and signature_config['primary'] in verified
  command('native-signature-refusals',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'signed-refusals'])
  command('native-signer-revocation',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'signed-revoked'])
 if not args.signed:
  command('native-account-lifecycle',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'accounts']);stop();start(3);command('native-session-expiry',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'expiry'])
 state='passed'
except Exception as e:
 import traceback
 failure=traceback.format_exc()
finally:stop()
final=sources();manifest={'schema_version':1,'state':state if initial==final else'failed','failure':failure,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':final,'sources_unchanged_during_run':initial==final,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()if binary.exists()else None,'observed_at':datetime.now(timezone.utc).isoformat(),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'private_fixture_reference':str(private.relative_to(root)),'inference_performed':False,'local_model_processes_started':0,'scanner_engine_started':False,'standard_signature_database_loaded':False,'full_journeys_qualified':False,'signed_profile':args.signed,'limits':['Assisted native Chromium on this macOS host with real PostgreSQL, storage and a stock curl retrieval, not independent operator adoption or an external business recipient.','Explicit fixture certificate SPKI trust; no global browser or host certificate-store changes.',('CSV with independent signature verification; genuine malware detection, SSO/MFA, clean first-admin enrollment, broad browser/native platforms and production/disconnected deployment remain open.' if args.signed else 'CSV-only policy for this journey; genuine malware detection, signed-browser profile, SSO/MFA, clean first-admin enrollment, broad browser/native platforms and production/disconnected deployment remain open.')]}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/('.private/'+profile+'-current')).write_text(str(raw)+'\n');print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
if manifest['state']!='passed':raise SystemExit(1)
