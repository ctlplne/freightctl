#!/usr/bin/env python3
"""First-run commands, empty real PostgreSQL, browser and stock curl; no inference."""
from ci_resources import environment as ci_environment
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
import hashlib,json,os,platform,shutil,socket,subprocess,time,traceback,uuid
if not __debug__:raise RuntimeError('First-run qualification requires assertions; remove Python optimization')
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
run='setup-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
name='freightctl_'+run.replace('-','_');binary=private/'freightctl';created=False;removed=False;server=None;log=None;steps=[];cleanup=[];started=time.monotonic();state='failed';failure=None;pg=None
env=ci_environment(dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright')))
def digest(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 special={'go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'}
 return {p:digest(root/p)for p in sorted(set(paths))if p and (Path(p).suffix in('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml')or p in special)}
initial=sources()
def command(label,args,expected=0,timeout=120):
 if any(s['name']==label for s in steps):raise RuntimeError('duplicate first-run command label')
 p=raw/(label+'.log');start=time.monotonic()
 with p.open('wb')as out:r=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT,env=env,timeout=timeout)
 steps.append({'name':label,'command':args,'exit_code':r.returncode,'expected_exit_code':expected,'duration_seconds':round(time.monotonic()-start,3),'native_output':str(p.relative_to(root)),'native_output_sha256':digest(p)})
 if r.returncode!=expected:raise RuntimeError(label+' failed; inspect protected output')
 return p
def sql(text,database='freightctl'):
 return subprocess.check_output(['docker','exec','-i',pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d',database,'-At','-c',text],env=env,timeout=30).decode().strip()
def stop():
 global server,log
 if server is not None:
  server.terminate()
  try:server.wait(timeout=8)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
  server=None
 if log is not None:log.close();log=None
try:
 metadata=json.loads(subprocess.check_output(['docker','inspect','freightctl-postgres-v1']))[0]
 assert metadata['Config'].get('Labels',{}).get('freightctl.workspace')==str(root) and metadata['State']['Running'] and metadata['HostConfig']['Memory']==536870912 and metadata['HostConfig']['NanoCpus']==1000000000
 pg=metadata['Id'];assert len(pg)==64 and all(c in '0123456789abcdef' for c in pg)
 command('build',['sh','scripts/go.sh','build','-p','1','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/freightctl'])
 sql('CREATE DATABASE '+name);created=True
 for source in ['pg-admin.dsn','pg-runtime.dsn']:
  reference=root/'.private'/source;assert reference.is_file()and not reference.is_symlink()and reference.stat().st_mode&0o077==0
  original=urlsplit(reference.read_text());(private/source).write_text(urlunsplit(original._replace(path='/'+name)))
 admin=str(private/'pg-admin.dsn');runtime=str(private/'pg-runtime.dsn');token=str(private/'admin.token');storage=str(private/'custody');plan=str(private/'setup.json')
 command('initialize-empty-database',[str(binary),'init','--admin-dsn-file',admin])
 assert sql('SELECT count(*) FROM tenants',name)=='0'
 command('save-first-run-plan',[str(binary),'setup-plan','--output',plan,'--token-file',token,'--storage',storage,'--tenant-label','Example customer','--partner-label','Settlement partner','--admin-label','First administrator'])
 saved=json.loads(Path(plan).read_text());assert saved['request']['credential_sha256']==digest(token) and len(Path(token).read_bytes())==64
 command('refuse-plan-overwrite',[str(binary),'setup-plan','--output',plan,'--token-file',token,'--storage',storage,'--tenant-label','Replacement','--partner-label','Replacement','--admin-label','Replacement'],expected=1)
 first=json.loads(command('commit-first-run',[str(binary),'setup','--admin-dsn-file',admin,'--request-file',plan]).read_text());assert not first['replayed']
 # The first response may be lost; only the saved plan selects the same receipt.
 replay=json.loads(command('recover-first-run-response',[str(binary),'setup','--admin-dsn-file',admin,'--request-file',plan]).read_text());assert replay['replayed']and replay['event_id']==first['event_id']and replay['initialized_at']==first['initialized_at']
 workspace=private/'workspace.json';workspace.write_text(json.dumps(replay))
 (private/'bad-workspace.json').write_text(json.dumps({'schema_version':1,'tenant_id':first['tenant_id'],'partner_id':'not-an-id'}))
 (private/'untrusted-workspace.json').write_text(json.dumps(dict(replay,endpoint='https://untrusted.invalid',permissions=['admin'],credential_file='/private/secret',command='execute instructions')))
 changed=json.loads(Path(plan).read_text());changed['request']['partner_label']='Changed decision';changed_path=private/'changed-plan.json';changed_path.write_text(json.dumps(changed))
 command('refuse-changed-plan',[str(binary),'setup','--admin-dsn-file',admin,'--request-file',str(changed_path)],expected=1)
 command('refuse-runtime-bootstrap',[str(binary),'setup','--admin-dsn-file',runtime,'--request-file',plan],expected=1)
 assert sql("SELECT (SELECT count(*) FROM tenants)||','||(SELECT count(*) FROM partners)||','||(SELECT count(*) FROM credentials)||','||(SELECT count(*) FROM installation_enrollments)",name)=='1,1,1,1'
 command('certificate',[str(binary),'dev-cert','--cert',str(private/'cert.pem'),'--key',str(private/'key.pem')])
 with socket.socket()as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 url='https://127.0.0.1:'+str(port);tenant=first['tenant_id'];partner=first['partner_id']
 def start():
  global server,log
  log=(raw/'server.log').open('ab');server=subprocess.Popen([str(binary),'serve','--dsn-file',runtime,'--listen','127.0.0.1:'+str(port),'--storage',storage,'--cert',str(private/'cert.pem'),'--key',str(private/'key.pem')],stdout=log,stderr=log,env=env)
  for _ in range(100):
   r=subprocess.run(['curl','--silent','--show-error','--cacert',str(private/'cert.pem'),'--max-time','1',url+'/healthz'],capture_output=True)
   if r.returncode==0:return
   if server.poll()is not None:raise RuntimeError('first-run server exited')
   time.sleep(.05)
  raise RuntimeError('first-run server unavailable')
 payload=private/'source.csv';payload.write_bytes(b'account,amount\n00000001,100.01\n00000002,200.02\n')
 config={'root':str(root),'url':url,'tenant':tenant,'partner':partner,'identities':[{'tenant':tenant,'partner':partner,'token':token}],'workspace':str(workspace),'badWorkspace':str(private/'bad-workspace.json'),'untrustedWorkspace':str(private/'untrusted-workspace.json'),'payload':str(payload),'certificate':str(private/'cert.pem'),'private':str(private),'raw':str(raw)}
 (private/'config.json').write_text(json.dumps(config));node=os.environ.get('FREIGHTCTL_NODE_BIN')or shutil.which('node');assert node
 start();command('native-first-run-exchange',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'setup'])
 headers=private/'receiver.headers';headers.write_bytes(b'Authorization: Bearer '+Path(token).read_bytes()+b'\n')
 def receive(label):
  command(label,['curl','--silent','--show-error','--fail','--cacert',str(private/'cert.pem'),'--header','@'+str(headers),'--output',str(private/(label+'.csv')),url+f'/v1/tenants/{tenant}/partners/{partner}/namespace/file?path=/setup.csv'])
  assert digest(private/(label+'.csv'))==digest(payload)
 receive('stock-curl-first-exchange');stop();start();receive('stock-curl-after-restart')
 final=json.loads(command('replay-after-ordinary-work',[str(binary),'setup','--admin-dsn-file',admin,'--request-file',plan]).read_text());assert final==replay
 state='passed'
except Exception:
 failure=traceback.format_exc()
finally:
 try:stop()
 except Exception:cleanup.append('exact-first-run-server-stop');failure=(failure or '')+'\nExact fixture server cleanup failed';state='failed'
 if created:
  try:sql('DROP DATABASE '+name+' WITH (FORCE)');removed=True
  except Exception:cleanup.append('exact-first-run-database-remove');failure=(failure or '')+'\nExact fixture database cleanup failed';state='failed'
final_sources=sources();unchanged=initial==final_sources
observed={}
for prefix,base,names in [('raw',raw,('setup-result.json','setup-login-axe.json','setup-published-files-axe.json')),('fixture',private,('source.csv','browser-received.csv','stock-curl-first-exchange.csv','stock-curl-after-restart.csv','setup.json','workspace.json'))]:
 for file in names:
  p=base/file
  if p.is_file() and not p.is_symlink():observed[prefix+'/'+file]=digest(p)
manifest={'schema_version':1,'kind':'native-first-run-browser','state':state if unchanged else 'failed','starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'observed_at':datetime.now(timezone.utc).isoformat(),'system':platform.system(),'architecture':platform.machine(),'source_sha256':final_sources,'sources_unchanged_during_run':unchanged,'steps':steps,'duration_seconds':round(time.monotonic()-started,3),'binary_sha256':digest(binary)if binary.exists()else None,'fixture_reference':str(private.relative_to(root)),'original_files_sha256':observed,'first_failure':'.private/first-run-first-failure','inference_performed':False,'scanner_engine_started':False,'database':name,'exact_fixture_database_removed':removed,'cleanup_failures':cleanup,'failure':failure,'limits':['Assisted same-host first tenant/partner/admin enrollment and exact-byte integrity-only exchange. No independent operator or disconnected bundle qualification.','One-time setup uses the separate deployment-admin reference; no unauthenticated network bootstrap endpoint exists. Ordinary partner lifecycle, invitations/providers/delegation and production activation remain open.','No model, malware engine, private signing/decryption or business acknowledgment is exercised.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/setup-current').write_text(str(raw)+'\n');print(str(raw/'manifest.json'),flush=True)
if manifest['state']!='passed':print(failure,flush=True);raise SystemExit(1)
