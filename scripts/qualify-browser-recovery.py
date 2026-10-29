#!/usr/bin/env python3
"""Real check-worker death, original database lease and browser recovery."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,shutil,signal,socket,subprocess,time,traceback,uuid
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
run='browser-recovery-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
binary=root/'.cache/freightctl-browser-recovery';env=dict(os.environ,GOMAXPROCS='1',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
steps=[];server=None;worker=None;handles=[];started=time.monotonic();failure=None;state='failed'
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 special={'go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'}
 return [{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()}for p in sorted(set(paths))if p and ((root/p).suffix in('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml')or p in special)]
initial=sources()
def command(label,args,timeout=120,expected=0):
 start=time.monotonic();path=raw/(label+'.log')
 with path.open('wb')as out:r=subprocess.run(args,stdout=out,stderr=subprocess.STDOUT,env=env,timeout=timeout)
 steps.append({'name':label,'command':args,'exit_code':r.returncode,'expected_exit_code':expected,'duration_seconds':round(time.monotonic()-start,3),'native_output':str(path.relative_to(root)),'native_output_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
 if r.returncode!=expected:raise RuntimeError(label+' failed; inspect protected output')
def cli(*args):return subprocess.check_output([str(binary),*args],env=env,timeout=30)
def get_check(label):
 output=private/(label+'.json')
 subprocess.run(['curl','--silent','--show-error','--fail','--cacert',str(private/'cert.pem'),'--max-time','3','--header','@'+str(private/'owner.headers'),'--output',str(output),url+prefix+'/checks/'+file_id],check=True,capture_output=True,timeout=5)
 return json.loads(output.read_text())
def stop():
 for p in [worker,server]:
  if p is not None and p.poll()is None:
   p.kill() if p is worker else p.terminate()
   try:p.wait(timeout=8)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 for h in handles:h.close()
try:
 command('browser-artifacts',['npm','--prefix','web','run','check-built'])
 command('build',['sh','scripts/go.sh','build','-p','1','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/freightctl'])
 cli('init');cli('dev-cert','--cert',str(private/'cert.pem'),'--key',str(private/'key.pem'))
 tenant,partner=str(uuid.uuid4()),str(uuid.uuid4());identities=[]
 for i in range(2):
  token=private/f'account-{i}.token';cli('token','--token-file',str(token));cli('enroll','--tenant',tenant,'--partner',partner,'--token-file',str(token));identities.append({'tenant':tenant,'partner':partner,'token':str(token)})
 common=['--tenant',tenant,'--partner',partner,'--token-file',identities[0]['token'],'--storage',str(private/'custody')]
 policy={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':64},{'name':'amount','type':'decimal','required':True,'max_bytes':64,'precision':12,'scale':2},{'name':'day','type':'date','required':True,'max_bytes':10}],'max_bytes':32<<20,'max_rows':1000000,'max_record_bytes':65536,'timeout_seconds':30}}
 (private/'policy.json').write_text(json.dumps(policy));cli('intake-policy-register',*common,'--request-file',str(private/'policy.json'),'--idempotency-key','recovery-policy')
 payload=b'account,amount,day\n'+b'00000001,100.01,2026-10-28\n'*900000;(private/'source.csv').write_bytes(payload);digest=hashlib.sha256(payload).hexdigest()
 with socket.socket()as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 url='https://127.0.0.1:'+str(port);prefix=f'/v1/tenants/{tenant}/partners/{partner}'
 log=(raw/'server.log').open('ab');handles.append(log);server=subprocess.Popen([str(binary),'serve','--listen','127.0.0.1:'+str(port),'--storage',str(private/'custody'),'--cert',str(private/'cert.pem'),'--key',str(private/'key.pem'),'--max-file-bytes',str(32<<20)],stdout=log,stderr=log,env=env)
 for _ in range(100):
  r=subprocess.run(['curl','--silent','--show-error','--cacert',str(private/'cert.pem'),'--max-time','1',url+'/healthz'],capture_output=True)
  if r.returncode==0:break
  if server.poll()is not None:raise RuntimeError('fixture server exited')
  time.sleep(.05)
 else:raise RuntimeError('fixture server health unavailable')
 (private/'owner.headers').write_bytes(b'Authorization: Bearer '+Path(identities[0]['token']).read_bytes()+b'\n')
 command('durable-held-source',['curl','--silent','--show-error','--fail','--cacert',str(private/'cert.pem'),'--header','@'+str(private/'owner.headers'),'--request','PUT','--header','Idempotency-Key: recovery-source','--header','X-File-Size: '+str(len(payload)),'--header','X-Content-SHA256: '+digest,'--data-binary','@'+str(private/'source.csv'),url+prefix+'/namespace/file?path=/recovery.csv'])
 file_id=json.loads((raw/'durable-held-source.log').read_text())['file']['id']
 out=(raw/'worker.stdout').open('wb');err=(raw/'worker.stderr').open('wb');handles.extend([out,err]);worker=subprocess.Popen([str(binary),'check-run',*common,'--file-id',file_id,'--idempotency-key','original-worker'],stdout=out,stderr=err,env=env)
 for _ in range(200):
  view=get_check('worker-observation')
  if view['check']['state']=='running' and worker.poll()is None:os.kill(worker.pid,signal.SIGSTOP);break
  if worker.poll()is not None:raise RuntimeError('worker completed before native death boundary')
  time.sleep(.005)
 else:raise RuntimeError('worker claim was not observed')
 before=get_check('claimed-before-death')['check'];assert before['state']=='running' and before['attempts']==1
 worker.kill();worker.wait(timeout=5);assert worker.returncode==-signal.SIGKILL
 steps.append({'name':'actual-task-worker-killed','pid':worker.pid,'exit_code':worker.returncode,'worker_id':before['worker_id'],'attempt':1,'original_lease_until':before['lease_until'],'original_revision':before['revision']})
 config={'root':str(root),'url':url,'tenant':tenant,'partner':partner,'identities':identities,'certificate':str(private/'cert.pem'),'private':str(private),'raw':str(raw),'fileID':file_id,'payload':str(private/'source.csv'),'sourceSHA256':digest,'leaseUntil':before['lease_until'],'originalWorker':before['worker_id']};(private/'config.json').write_text(json.dumps(config))
 node=os.environ.get('FREIGHTCTL_NODE_BIN')or shutil.which('node');assert node
 command('browser-live-lease',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'recovery-wait'])
 wait_started=time.monotonic()
 while True:
  view=get_check('lease-observation');lease=datetime.fromisoformat(view['check']['lease_until'].replace('Z','+00:00'))
  if view.get('recovery',{}).get('eligible') is True:break
  if time.monotonic()-wait_started>75:raise RuntimeError('unchanged database lease did not expire within bound')
  time.sleep(1)
 steps.append({'name':'original-lease-wait','lease_budget_seconds':70,'wait_seconds':round(time.monotonic()-wait_started,3),'lease_unchanged':view['check']['lease_until']==before['lease_until']})
 command('browser-expired-lease-recovery',[node,'scripts/browser-journey.mjs',str(private/'config.json'),'recovery-after'])
 replay=json.loads((raw/'recovery-response-loss.json').read_text());decision=private/'recovery-decision.json'
 cli_result=json.loads(cli('check-recover',*common,'--file-id',file_id,'--request-file',str(decision),'--idempotency-key',replay['keys'][0]));assert cli_result['replayed'] and cli_result['resource']['attempt']==2
 old=json.loads(cli('check-run',*common,'--file-id',file_id,'--idempotency-key','original-worker'));assert old['replayed'] and old['resource']['attempt']==1
 steps.append({'name':'cross-interface-recovery-receipt-and-original-worker-replay','recovery_attempt':2,'original_attempt':1})
 command('stock-curl-recovered-receiver',['curl','--silent','--show-error','--fail','--cacert',str(private/'cert.pem'),'--header','@'+str(private/'owner.headers'),'--output',str(private/'curl-recovered.csv'),url+prefix+'/files/'+file_id])
 assert hashlib.sha256((private/'curl-recovered.csv').read_bytes()).hexdigest()==digest and hashlib.sha256((private/'browser-recovered.csv').read_bytes()).hexdigest()==digest
 state='passed' 
except Exception:failure=traceback.format_exc()
finally:stop()
final=sources();manifest={'schema_version':1,'state':state if initial==final else'failed','failure':failure,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':final,'sources_unchanged_during_run':initial==final,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()if binary.exists()else None,'steps':steps,'duration_seconds':round(time.monotonic()-started,3),'private_fixture_reference':str(private.relative_to(root)),'inference_performed':False,'local_model_processes_started':0,'scanner_engine_started':False,'standard_signature_database_loaded':False,'full_journeys_qualified':False,'limits':['Assisted native macOS Chromium, real PostgreSQL/storage and exact task-worker death; not independent operators, native Linux/Windows, multi-host restore or production qualification.','Original 70-second lease and three-attempt budget retained. No host/database clock changes.','CSV-only recovery fixture; actual malware detection, signed recovery, governed re-scan/rebind and complete journey scope remain open.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/browser-recovery-current').write_text(str(raw)+'\n');print(raw/'manifest.json',flush=True)
if failure:print('Recovery journey failed; inspect protected manifest and native outputs.',flush=True)
if manifest['state']!='passed':raise SystemExit(1)
