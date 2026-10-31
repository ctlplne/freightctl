#!/usr/bin/env python3
"""Typed ready-manifest collection, durable input recovery and independent SFTP receipts.

Uses one exact retained task PostgreSQL instance, a fresh fixture database,
loopback HTTPS/stock SFTP and bounded task-owned application processes.
No inference, scanner or shared Docker lifecycle operation.
"""
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
import argparse,hashlib,json,os,re,signal,socket,subprocess,time,traceback,uuid
from native_evidence import NativeEvidence
if not __debug__:
 raise RuntimeError("Qualification requires assertions; remove Python -O/PYTHONOPTIMIZE")
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
parser=argparse.ArgumentParser();parser.add_argument('--postgres-container-id',required=True);parser.add_argument('--backend-only',action='store_true');options=parser.parse_args()
assert re.fullmatch(r'[0-9a-f]{64}',options.postgres_container_id),'use the exact task-owned PostgreSQL container ID'
run='collections-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
binary=private/'freightctl';database='freightctl_'+run.replace('-','_');created=False;servers={};logs={};steps=[];cleanup=[];state='failed';failure=None;started=time.monotonic()
output_proof=NativeEvidence(raw,steps)
reserve_step=output_proof.reserve
env=dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
pg=options.postgres_container_id
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 return {p:sha(root/p) for p in sorted(set(paths)) if p and (Path(p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p.startswith('web/tests/fixtures/') or p in ('go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'))}
initial=sources();(root/'.private/collection-runtime-current').write_text(str(raw)+'\n')
def command(label,args,expected=0,timeout=100):
 reserve_step(label)
 start=time.monotonic();out=raw/(label+'.stdout');err=raw/(label+'.stderr')
 with out.open('wb') as o,err.open('wb') as e:r=subprocess.run(list(map(str,args)),stdout=o,stderr=e,env=env,timeout=timeout)
 steps.append({'name':label,'command':list(map(str,args)),'exit_code':r.returncode,'expected_exit_code':expected,'duration_seconds':round(time.monotonic()-start,3),'stdout_sha256':sha(out),'stderr_sha256':sha(err)})
 if any(Path(str(a)).name=='onboarding-exchange-browser.mjs' for a in args):
  config=Path(args[-1]);settings=json.loads(config.read_bytes())
  steps[-1]['browser_configuration_reference']=str(config.relative_to(root))
  steps[-1]['browser_configuration_sha256']=sha(config)
  output_proof.capture_browser(label,Path(settings['raw'])/'onboarding-exchange-browser.json')
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
workers={}
def start_worker(label,job):
 reserve_step(label);args=cli_args('workflow-collection-work','--collection-id',job['id'],'--request-file',write(label+'-request',{'definition_hash':job['definition_hash']}),'--idempotency-key',label,token=owner)
 out=(raw/(label+'.stdout')).open('wb');err=(raw/(label+'.stderr')).open('wb');p=subprocess.Popen(list(map(str,args)),stdout=out,stderr=err,env=env,start_new_session=True);workers[label]=(p,out,err,args,time.monotonic());return p

def finish_worker(label,expected=0,kill=False,timeout=100):
 p,out,err,args,began=workers.pop(label)
 if kill and p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
 try:code=p.wait(timeout=timeout)
 except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait();raise
 finally:out.close();err.close()
 steps.append({'name':label,'command':list(map(str,args)),'exit_code':code,'expected_exit_code':expected,'duration_seconds':round(time.monotonic()-began,3),'stdout_sha256':sha(raw/(label+'.stdout')),'stderr_sha256':sha(raw/(label+'.stderr'))})
 assert code==expected,(label,code,expected)

def recorded_sql(label,query):return command(label,['docker','exec',pg,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d',database,'-At','-c',query]).decode().strip()
def wait_sql(query,expected='t',timeout=40):
 until=time.monotonic()+timeout
 while sql(query)!=expected:
  assert time.monotonic()<until,'original database condition timeout';time.sleep(.1)
def sql_string(text):return "'"+str(text).replace("'","''")+"'"
def utc(seconds):return datetime.fromtimestamp(seconds,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def headers(name,token):p=private/(name+'.headers');p.write_bytes(b'Authorization: Bearer '+token.read_bytes()+b'\n');return p
try:
 meta=json.loads(subprocess.check_output(['docker','inspect','--format','{"workspace":{{json (index .Config.Labels "freightctl.workspace")}},"running":{{json .State.Running}},"memory":{{json .HostConfig.Memory}},"cpu":{{json .HostConfig.NanoCpus}}}',pg]))
 assert meta=={'workspace':str(root),'running':True,'memory':536870912,'cpu':1000000000}
 command('go-toolchain',['sh','scripts/go.sh','version']);command('build',['sh','scripts/go.sh','build','-p','1','-trimpath','-buildvcs=false','-o',binary,'./cmd/freightctl'])
 sql('CREATE DATABASE '+database,'freightctl');created=True
 for name in ['pg-admin.dsn','pg-runtime.dsn']:
  source=root/'.private'/name;assert source.is_file() and not source.is_symlink() and source.stat().st_mode&0o077==0;(private/name).write_text(urlunsplit(urlsplit(source.read_text())._replace(path='/'+database)))
 admin,runtime=private/'pg-admin.dsn',private/'pg-runtime.dsn';command('migrate-isolated-database',[binary,'init','--admin-dsn-file',admin])
 tenant,partner=str(uuid.uuid4()),str(uuid.uuid4());storage=private/'custody'
 def cli_args(op,*extra,token=None):
  args=[binary,op,'--admin-dsn-file',admin,'--dsn-file',runtime,'--tenant',tenant,'--partner',partner,'--storage',storage]
  if token is not None:args+=['--token-file',token]
  return [*args,*extra]
 def invoke(label,op,*extra,token=None,expected=0):
  data=command(label,cli_args(op,*extra,token=token),expected=expected);return json.loads(data) if expected==0 and data else None
 def identity(name,permissions=None):
  token=private/(name+'.token');command(name+'-token',[binary,'token','--token-file',token]);invoke(name+'-enroll','enroll',*(['--permissions',permissions] if permissions else []),token=token);return token
 owner=identity('owner');viewer=identity('viewer','inspect,workflow_approve');other_admin=identity('other-admin');header=headers('owner',owner);viewer_header=headers('viewer',viewer);other_header=headers('other-admin',other_admin)
 cert,key=private/'cert.pem',private/'key.pem';command('certificate',[binary,'dev-cert','--cert',cert,'--key',key]);http_port,receiver_port=port(),port();url='https://127.0.0.1:'+str(http_port);prefix=f'/v1/tenants/{tenant}/partners/{partner}'
 start('https',[binary,'serve','--dsn-file',runtime,'--storage',storage,'--listen',f'127.0.0.1:{http_port}','--cert',cert,'--key',key,'--max-file-bytes',str(4<<20)],http_port)
 def post(label,route,body=None,expected=200,key=None,who=None,method='POST'):
  out=raw/(label+'.json');args=['curl','--silent','--show-error','--cacert',cert,'--max-time','30','--header','@'+str(who or header),'--request',method,'--output',out,'--write-out','%{http_code}']
  if key:args+=['--header','Idempotency-Key: '+key]
  if body is not None:p=private/(label+'.request');p.write_bytes(body if isinstance(body,bytes) else json.dumps(body).encode());args+=['--header','Content-Type: application/json','--data-binary','@'+str(p)]
  code=int(command(label,[*args,url+prefix+route]).decode());steps[-1].update(http_status=code,expected_status=expected,response_sha256=sha(out));assert code==expected,(label,code,expected);return json.loads(out.read_bytes())
 for name in ['source-host','receiver-host','client']:command('ssh-key-'+name,['ssh-keygen','-q','-t','ed25519','-N','','-f',private/name])
 (private/'authorized_keys').write_bytes((private/'client.pub').read_bytes());user=command('native-os-sftp-account',['id','-un']).decode().strip();assert re.fullmatch(r'[A-Za-z0-9_.-]+',user) # Stock OS fixture account, never Git identity.
 producer=private/'outbox';inbox=private/'inbox';producer.mkdir(mode=0o700);inbox.mkdir(mode=0o700);source_port=port()
 def receiver(name,number,directory,readonly):
  config=private/(name+'.conf');config.write_text(f'''Port {number}
ListenAddress 127.0.0.1
HostKey {private/(name+'-host')}
PidFile {private/(name+'.pid')}
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
ForceCommand internal-sftp {'-R ' if readonly else ''}-d {directory}
LogLevel VERBOSE
''');start(name,['/usr/sbin/sshd','-D','-e','-f',config],number);known=private/(name+'.known_hosts');known.write_text(f'[127.0.0.1]:{number} '+(private/(name+'-host.pub')).read_text());return known
 source_known=receiver('source',source_port,producer,True);destination_known=receiver('receiver',receiver_port,inbox,False)
 def contacts(name):return (raw/(name+'.log')).read_text().count('Accepted publickey for ')
 def stock(label,number,known,text,expected=0):
  batch=private/(label+'.batch');batch.write_text(text);return command(label,['sftp','-F','/dev/null','-P',str(number),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,user+'@127.0.0.1'],expected=expected)
 def register(label,number,directory,host):
  return invoke(label+'-register','connection-register','--request-file',write(label+'-connection',{'expected_version':0,'address':f'127.0.0.1:{number}','user':user,'directory':str(directory),'host_public_file':str(private/(host+'-host.pub')),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}),'--idempotency-key',label+'-register',token=owner)['resource']
 source_connection=register('source',source_port,producer,'source');destination=register('destination',receiver_port,inbox,'receiver');post('create-incoming-folder','/namespace/commands',{'operation':'mkdir','path':'/incoming'},key='incoming')
 data_by_name={'settlement-a.csv':b'account,amount\n0001,42.00\n'*64,'settlement-b.csv':b'account,amount\n0002,13.00\n'*48}
 for name,data in data_by_name.items():(producer/name).write_bytes(data)
 manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in data_by_name.items()]};(producer/'settlement.ready.json').write_text(json.dumps(manifest))
 source_snapshot={p.name:sha(p) for p in producer.iterdir()};probe=private/'readonly-probe.csv';probe.write_bytes(b'not permitted\n');stock('stock-readonly-source-refuses-put',source_port,source_known,f'put {probe} {producer}/forbidden.csv\n',expected=1);assert not (producer/'forbidden.csv').exists()
 source_definition={'kind':'sftp.collect','connection':ref(source_connection),'manifest':'settlement.ready.json','target_directory':'/incoming','completion_contract':'immutable-files-sha256-manifest-v1','max_files':4,'max_file_bytes':4<<20,'max_total_bytes':8<<20}
 definition={'schema_version':1,'name':'Ready settlement batch','steps':[{'id':label,'kind':'sftp.deliver','connection':ref(destination),'filename':label+'.csv'} for label in ['first','second']],'source':source_definition}
 before_source,before_destination=contacts('source'),contacts('receiver')
 preview=post('ordinary-workflow-preview','/workflows/validate',{'definition':definition});assert not preview['external_contact'] and preview['collection']['kind']=='sftp.collect' and preview['collection']['source']==source_definition and len(preview['effects'])==2
 workflow=post('ordinary-workflow-draft','/workflows/drafts',{'expected_version':0,'definition':definition},key='workflow')['resource'];workflow=post('ordinary-workflow-approve','/workflows/'+workflow['id']+'/1/approve',decision(workflow),key='workflow-approve')['resource']
 choices=post('approved-collection-workflow-choices','/workflow-collection-workflows',method='GET');assert choices['workflows']==[{'id':workflow['id'],'version':1,'hash':workflow['definition_hash'],'name':definition['name']}]
 assert post('outbound-schedule-choices-exclude-collection','/workflow-schedule-workflows',method='GET')['workflows']==[]
 def start_collection(label,workflow,timeout=120):
  selection={'workflow':ref(workflow),'timeout_seconds':timeout,'expected_authority_revision':1};p=post(label+'-preview','/workflow-collections/preview',selection);assert not p['external_contact'] and p['approval_required'];x={'selection':selection,'definition_hash':p['definition_hash']};r=post(label+'-start','/workflow-collections',x,key=label+'-start');j=post(label+'-status','/workflow-collections/'+r['resource']['id'],method='GET')['job'];again=post(label+'-start-replay','/workflow-collections',x,key=label+'-start');assert again['replayed'] and again['resource']==r['resource'];return j
 job=start_collection('first',workflow);assert contacts('source')==before_source and contacts('receiver')==before_destination and job['state']=='queued' and job['attempts']==0
 post('viewer-private-collection','/workflow-collections/'+job['id'],who=viewer_header,method='GET',expected=404);assert post('viewer-private-collection-list','/workflow-collections',who=viewer_header,method='GET')['jobs']==[]
 request=write('first-work',{'definition_hash':job['definition_hash']});work=invoke('first-actual-collection','workflow-collection-work','--collection-id',job['id'],'--request-file',request,'--idempotency-key','first-work',token=owner);assert work['resource']['state']=='captured',work
 status=post('first-collected-status','/workflow-collections/'+job['id'],method='GET');assert status['job']['state']=='captured' and status['job']['attempts']==1 and status['job']['fence']==1 and len(status['inputs'])==2 and all(i['state']=='accepted' and i['file_id']==i['object_id'] and i['run_id'] is None for i in status['inputs'])
 assert contacts('source')==before_source+1 and contacts('receiver')==before_destination and source_snapshot=={p.name:sha(p) for p in producer.iterdir()}
 before_source=contacts('source');again=invoke('first-work-original-key-replay','workflow-collection-work','--collection-id',job['id'],'--request-file',request,'--idempotency-key','first-work',token=owner);assert again['replayed'] and again['resource']==work['resource'] and contacts('source')==before_source
 before_refresh=contacts('source'),contacts('receiver');refreshed=post('queue-downstream-metadata','/workflow-collections/'+job['id']+'/refresh',decision(status['job']),key='queue-downstream');again=post('queue-downstream-metadata-replay','/workflow-collections/'+job['id']+'/refresh',decision(status['job']),key='queue-downstream');assert again['replayed'] and again['resource']==refreshed['resource'] and before_refresh==(contacts('source'),contacts('receiver'))
 status=post('downstream-queued-status','/workflow-collections/'+job['id'],method='GET');assert all(i['state']=='queued' and i['run_id'] for i in status['inputs'])
 for file_index,item in enumerate(status['inputs']):
  for step_index in range(2):invoke(f'run-{file_index}-ordered-step-{step_index}','workflow-work','--run-id',item['run_id'],'--idempotency-key',f'run-{file_index}-step-{step_index}',token=owner)
  run_status=post('run-'+str(file_index)+'-completed','/workflow-runs/'+item['run_id'],method='GET');assert run_status['observed_state']=='succeeded'
  for step_index,step in enumerate(run_status['steps']):
   target=inbox/(step['delivery_id']+'-'+definition['steps'][step_index]['filename']);received=private/(f'received-{file_index}-{step_index}.csv');stock(f'independent-receiver-{file_index}-{step_index}',receiver_port,destination_known,f'get {target} {received}\n');assert received.read_bytes()==data_by_name[item['source_name']] and target.read_bytes()==data_by_name[item['source_name']]
 assert source_snapshot=={p.name:sha(p) for p in producer.iterdir()}
 # A producer's bad second file must hold the first exact accepted revision as
 # well. It cannot be downloaded or selected by the ordinary namespace reader.
 good=b'account,amount\n0003,77.00\n';bad=b'account,amount\n0003,88.00\n';assert len(good)==len(bad)
 (producer/'good-new.csv').write_bytes(good);(producer/'bad-new.csv').write_bytes(bad);good_hash=hashlib.sha256(good).hexdigest();unfinished_manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(good),'sha256':good_hash} for name in ['good-new.csv','bad-new.csv']]};(producer/'settlement.ready.json').write_text(json.dumps(unfinished_manifest));unfinished=start_collection('unfinished',workflow)
 unfinished_request=write('unfinished-work',{'definition_hash':unfinished['definition_hash']});before_destination=contacts('receiver');failed_work=invoke('unfinished-real-source-work','workflow-collection-work','--collection-id',unfinished['id'],'--request-file',unfinished_request,'--idempotency-key','unfinished-work',token=owner);assert failed_work['resource']['state']=='retry',failed_work
 held=post('unfinished-batch-private-status','/workflow-collections/'+unfinished['id'],method='GET');assert not held['job']['captured'] and [i['state'] for i in held['inputs']]==['accepted','pending'] and contacts('receiver')==before_destination
 first_held=held['inputs'][0];post('unfinished-other-administrator-file-unavailable','/files/'+first_held['file_id'],who=other_header,method='GET',expected=409);post('unfinished-bare-file-unavailable','/files/'+first_held['file_id'],method='GET',expected=409);post('unfinished-path-not-published','/namespace/stat?path='+first_held['target_path'],method='GET',expected=404)
 (producer/'bad-new.csv').write_bytes(good);wait_sql("SELECT clock_timestamp()>=next_at FROM workflow_collection_jobs WHERE id='"+unfinished['id']+"'")
 repaired=invoke('producer-fixed-exact-digest-work','workflow-collection-work','--collection-id',unfinished['id'],'--request-file',unfinished_request,'--idempotency-key','fixed-unfinished-work',token=owner);assert repaired['resource']['state']=='captured';complete=post('fixed-batch-fully-captured','/workflow-collections/'+unfinished['id'],method='GET');assert complete['job']['captured'] and all(i['state']=='accepted' for i in complete['inputs'])
 for index,item in enumerate(complete['inputs']):post('fixed-batch-published-'+str(index),'/namespace/stat?path='+item['target_path'],method='GET')
 before_source=contacts('source');historical=invoke('failed-original-work-receipt-stays-historical','workflow-collection-work','--collection-id',unfinished['id'],'--request-file',unfinished_request,'--idempotency-key','unfinished-work',token=owner);assert historical['replayed'] and historical['resource']==failed_work['resource'] and contacts('source')==before_source
 # Kill the task worker only after a sealed object exists and the original
 # eight-second SQL barrier confirms acceptance has not yet committed.
 gamma_data=b'account,amount\n0004,123.00\n'*96;(producer/'gamma.csv').write_bytes(gamma_data);gamma_hash=hashlib.sha256(gamma_data).hexdigest();gamma_manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[manifest['files'][0],{'name':'gamma.csv','size_bytes':len(gamma_data),'sha256':gamma_hash}]};(producer/'settlement.ready.json').write_text(json.dumps(gamma_manifest));crash=start_collection('crash',workflow)
 pause='freightctl_collection_pause_'+uuid.uuid4().hex;recorded_sql('install-original-eight-second-acceptance-barrier',f"CREATE FUNCTION {pause}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sha256='{gamma_hash}' THEN PERFORM pg_sleep(8);END IF;RETURN NEW;END $$;CREATE TRIGGER {pause} BEFORE INSERT ON files FOR EACH ROW EXECUTE FUNCTION {pause}()")
 start_worker('stopped-collection',crash);wait_sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname='"+database+"' AND wait_event='PgSleep')");staging=post('actual-sealed-before-acceptance','/workflow-collections/'+crash['id'],method='GET');gamma=next(i for i in staging['inputs'] if i['source_name']=='gamma.csv');sealed=storage/(tenant+'_'+partner+'_'+gamma['object_id']);assert gamma['state']=='pending' and gamma['file_id'] is None and sealed.read_bytes()==gamma_data and sealed.stat().st_mode&0o777==0o400 and not staging['job']['captured']
 finish_worker('stopped-collection',expected=-signal.SIGKILL,kill=True);recorded_sql('remove-exact-acceptance-barrier',f'DROP TRIGGER {pause} ON files;DROP FUNCTION {pause}()');retained=post('retained-original-collection-lease','/workflow-collections/'+crash['id'],method='GET');assert retained['job']['state']=='reading' and retained['job']['attempts']==1 and retained['job']['fence']==1
 before_source=contacts('source');crash_request=write('same-stopped-work',{'definition_hash':crash['definition_hash']});invoke('replacement-cannot-shorten-lease','workflow-collection-work','--collection-id',crash['id'],'--request-file',crash_request,'--idempotency-key','stopped-collection',token=owner,expected=1);assert contacts('source')==before_source
 wait_sql("SELECT clock_timestamp()>=lease_until FROM workflow_collection_jobs WHERE id='"+crash['id']+"'");resumed=invoke('replacement-reuses-sealed-exact-object','workflow-collection-work','--collection-id',crash['id'],'--request-file',crash_request,'--idempotency-key','stopped-collection',token=owner);assert resumed['resource']['state']=='captured';recovered=post('recovered-collection-status','/workflow-collections/'+crash['id'],method='GET');recovered_gamma=next(i for i in recovered['inputs'] if i['source_name']=='gamma.csv');assert recovered['job']['attempts']==2 and recovered['job']['fence']==2 and recovered_gamma['file_id']==gamma['object_id'] and contacts('source')==before_source and sealed.read_bytes()==gamma_data
 post('recovered-queue-downstream','/workflow-collections/'+crash['id']+'/refresh',decision(recovered['job']),key='recovered-queue');routed=post('recovered-inputs-queued','/workflow-collections/'+crash['id'],method='GET');new_input=next(i for i in routed['inputs'] if i['source_name']=='gamma.csv');assert all(i['first_job_id']!=crash['id'] for i in routed['inputs'] if i['source_name']!='gamma.csv')
 for step_index in range(2):invoke('recovered-ordered-step-'+str(step_index),'workflow-work','--run-id',new_input['run_id'],'--idempotency-key','recovered-step-'+str(step_index),token=owner)
 done=post('recovered-downstream-complete','/workflow-runs/'+new_input['run_id'],method='GET');assert done['observed_state']=='succeeded'
 for index,step in enumerate(done['steps']):
  target=inbox/(step['delivery_id']+'-'+definition['steps'][index]['filename']);received=private/('recovered-received-'+str(index)+'.csv');stock('recovered-stock-receiver-'+str(index),receiver_port,destination_known,f'get {target} {received}\n');assert received.read_bytes()==gamma_data
 # Collection-only is a valid ordinary definition: no recipient or dummy send.
 post('collection-only-target-folder','/namespace/commands',{'operation':'mkdir','path':'/local-only'},key='local-only');local_source={**source_definition,'target_directory':'/local-only'};local_definition={'schema_version':1,'name':'Collect locally only','steps':[],'source':local_source};local=post('collection-only-workflow-draft','/workflows/drafts',{'expected_version':0,'definition':local_definition},key='local-workflow')['resource'];local=post('collection-only-workflow-approve','/workflows/'+local['id']+'/1/approve',decision(local),key='local-approve')['resource'];local_job=start_collection('local-only',local);before_destination=contacts('receiver');local_work=invoke('collection-only-real-work','workflow-collection-work','--collection-id',local_job['id'],'--request-file',write('local-only-work',{'definition_hash':local_job['definition_hash']}),'--idempotency-key','local-only-work',token=owner);assert local_work['resource']['state']=='captured'
 local_status=post('collection-only-local-receipts','/workflow-collections/'+local_job['id'],method='GET');assert local_status['job']['captured'] and all(i['run_id'] is None for i in local_status['inputs']) and contacts('receiver')==before_destination
 # Cross the execution cutoff after real source bytes are sealed. The exact
 # ordinary acceptance, input receipt and namespace changes must all roll back.
 late_data=b'account,amount\n0005,999.00\n';late_hash=hashlib.sha256(late_data).hexdigest();(producer/'late.csv').write_bytes(late_data);(producer/'settlement.ready.json').write_text(json.dumps({'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':'late.csv','size_bytes':len(late_data),'sha256':late_hash}]}));late=start_collection('live-cutoff',workflow,timeout=2);pause='freightctl_collection_cutoff_'+uuid.uuid4().hex;recorded_sql('install-original-three-second-cutoff-barrier',f"CREATE FUNCTION {pause}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sha256='{late_hash}' THEN PERFORM pg_sleep(3);END IF;RETURN NEW;END $$;CREATE TRIGGER {pause} BEFORE INSERT ON files FOR EACH ROW EXECUTE FUNCTION {pause}()")
 late_work=invoke('actual-source-crosses-original-cutoff','workflow-collection-work','--collection-id',late['id'],'--request-file',write('late-work',{'definition_hash':late['definition_hash']}),'--idempotency-key','late-work',token=owner);recorded_sql('remove-exact-cutoff-barrier',f'DROP TRIGGER {pause} ON files;DROP FUNCTION {pause}()');assert late_work['resource']['state']=='expired',late_work;late_status=post('expired-input-never-accepted-or-published','/workflow-collections/'+late['id'],method='GET');assert not late_status['job']['captured'] and all(i['file_id'] is None and i['run_id'] is None for i in late_status['inputs']);assert sql("SELECT count(*) FROM files WHERE sha256='"+late_hash+"'")=='0'
 browser_phases=[]
 if not options.backend_only:
  node=command('node-executable',['which','node']).decode().strip()
  post('browser-target-folder','/namespace/commands',{'operation':'mkdir','path':'/browser-incoming'},key='browser-target-folder')
  browser_data={'browser-a.csv':b'account,amount\n0061,31.00\n','browser-b.csv':b'account,amount\n0062,32.00\n'}
  for name,data in browser_data.items():(producer/name).write_bytes(data)
  browser_manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in browser_data.items()]};(producer/'browser.ready.json').write_text(json.dumps(browser_manifest))
  def browser(phase,**values):
   directory=raw/('browser-'+phase);directory.mkdir(mode=0o700);cfg={'root':str(root),'private':str(private),'url':url,'certificate':str(cert),'token':str(owner),'tenant':tenant,'partner':partner,'raw':str(directory),'collections_only':True,'collection_phase':phase,'source_log':str(raw/'source.log'),'receiver_log':str(raw/'receiver.log'),'source':source_connection,'destination':destination,**values};command('native-browser-'+phase,[node,'scripts/onboarding-exchange-browser.mjs',write('browser-'+phase,cfg)],timeout=180);browser_phases.append(phase);return json.loads((directory/'collection-browser-result.json').read_text())
  created_ui=browser('create');job_ui=post('browser-created-job','/workflow-collections/'+created_ui['job']['id'],method='GET')['job'];completed_ui=browser('work',job=job_ui)
  for file_index,run_status in enumerate(completed_ui['runs']):
   input=next(i for i in completed_ui['view']['inputs'] if i['run_id']==run_status['run']['id'])
   for step_index,step in enumerate(run_status['steps']):
    target=inbox/(step['delivery_id']+'-browser-'+str(step_index+1)+'.csv');received=private/(f'browser-received-{file_index}-{step_index}.csv');stock(f'browser-independent-receiver-{file_index}-{step_index}',receiver_port,destination_known,f'get {target} {received}\n');assert received.read_bytes()==browser_data[input['source_name']]
  browser_manifest['batch_id']=str(uuid.uuid4());(producer/'browser.ready.json').write_text(json.dumps(browser_manifest));revised=browser('revise',workflow=created_ui['workflow']);revision_job=post('browser-revised-job','/workflow-collections/'+revised['job']['id'],method='GET')['job'];deduped=browser('dedupe',job=revision_job)
  assert {i['id'] for i in deduped['view']['inputs']}=={i['id'] for i in completed_ui['view']['inputs']};assert deduped['view']['job']['state']=='cancelled' and deduped['view']['job']['captured']
 # Read-only collection must refuse real source symlinks, malformed ready
 # manifests and a changed meaning for a previously frozen producer batch ID.
 unsafe_data=b'synthetic unaccepted source revision\n';unsafe_hash=hashlib.sha256(unsafe_data).hexdigest();(producer/'unsafe-real.csv').write_bytes(unsafe_data);(producer/'unsafe-link.csv').symlink_to(producer/'unsafe-real.csv')
 refusal_cases=[('source-symlink',{'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':'unsafe-link.csv','size_bytes':len(unsafe_data),'sha256':unsafe_hash}]}),('manifest-malformed',{'schema_version':1,'batch_id':str(uuid.uuid4()),'approved':True,'files':[]}),('producer-batch-id-changed-meaning',{**manifest,'files':[{'name':'unsafe-real.csv','size_bytes':len(unsafe_data),'sha256':unsafe_hash}]})]
 for label,producer_manifest in refusal_cases:
  (producer/'settlement.ready.json').write_text(json.dumps(producer_manifest));bad_job=start_collection(label,workflow);before_receiver=contacts('receiver');r=invoke(label+'-real-worker','workflow-collection-work','--collection-id',bad_job['id'],'--request-file',write(label+'-work',{'definition_hash':bad_job['definition_hash']}),'--idempotency-key',label+'-work',token=owner)
  assert r['resource']['state'] in ('retry','attention');bad_view=post(label+'-refused-state','/workflow-collections/'+bad_job['id'],method='GET');assert not bad_view['job']['captured'] and all(i['file_id'] is None and i['run_id'] is None for i in bad_view['inputs']) and contacts('receiver')==before_receiver
  post(label+'-cancel-original-job','/workflow-collections/'+bad_job['id']+'/cancel',decision(bad_view['job']),key=label+'-cancel')
 assert sql("SELECT count(*) FROM files WHERE sha256='"+unsafe_hash+"'")=='0'
 wrong_source=register('wrong-source-pin',source_port,producer,'receiver');wrong_definition={'schema_version':1,'name':'Reject changed source host','steps':[],'source':{**source_definition,'connection':ref(wrong_source)}};wrong_workflow=post('wrong-source-draft','/workflows/drafts',{'expected_version':0,'definition':wrong_definition},key='wrong-source-draft')['resource'];wrong_workflow=post('wrong-source-approve','/workflows/'+wrong_workflow['id']+'/1/approve',decision(wrong_workflow),key='wrong-source-approve')['resource'];wrong_job=start_collection('wrong-source',wrong_workflow);before_peers=contacts('source'),contacts('receiver');wrong_work=invoke('wrong-source-pin-real-worker','workflow-collection-work','--collection-id',wrong_job['id'],'--request-file',write('wrong-source-pin-work',{'definition_hash':wrong_job['definition_hash']}),'--idempotency-key','wrong-source-pin-work',token=owner);assert wrong_work['resource']['state']=='retry';wrong_view=post('wrong-source-pin-no-inputs','/workflow-collections/'+wrong_job['id'],method='GET');assert wrong_view['inputs']==[] and not wrong_view['job']['captured'] and before_peers==(contacts('source'),contacts('receiver'))
 # Real ordinary CSV checks and separate releases remain cumulative with the
 # complete collection batch and each exact-file independent dispatch decision.
 policy_request={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':32},{'name':'amount','type':'decimal','required':True,'max_bytes':32,'precision':12,'scale':2}],'max_bytes':1048576,'max_rows':100,'max_record_bytes':1024,'timeout_seconds':10}}
 policy=post('collection-required-csv-policy','/intake-policy',policy_request,key='collection-csv-policy')['resource']
 post('collection-requires-independent-dispatch','/outbound-dispatch-policy',{'expected_revision':0,'mode':'independent'},key='collection-independent-dispatch')
 held_data={'checked-a.csv':b'account,amount\n0071,51.00\n','checked-b.csv':b'account,amount\n0072,52.00\n'}
 for name,data in held_data.items():(producer/name).write_bytes(data)
 (producer/'settlement.ready.json').write_text(json.dumps({'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in held_data.items()]}));held_job=start_collection('checked-collection',workflow)
 invoke('checked-source-captured-under-intake','workflow-collection-work','--collection-id',held_job['id'],'--request-file',write('checked-source-work',{'definition_hash':held_job['definition_hash']}),'--idempotency-key','checked-source-work',token=owner)
 held=post('checked-source-held-inputs','/workflow-collections/'+held_job['id'],method='GET');assert held['job']['captured'] and all(s['state']=='held_or_unavailable' for s in held['local_states']) and all(i['run_id'] is None for i in held['inputs'])
 before_peers=contacts('source'),contacts('receiver')
 for index,item in enumerate(held['inputs']):
  post('checked-input-bare-file-held-'+str(index),'/files/'+item['file_id'],method='GET',expected=409)
  invoke('checked-input-ordinary-parser-'+str(index),'check-run','--file-id',item['file_id'],'--idempotency-key','checked-input-parse-'+str(index),token=owner)
  check=post('checked-input-exact-proof-'+str(index),'/checks/'+item['file_id'],method='GET')['check'];assert check['state']=='passed' and check['policy_hash']==policy['definition_hash'] and check['report']['sha256']==item['sha256']
  post('checked-input-passed-still-held-'+str(index),'/files/'+item['file_id'],method='GET',expected=409)
  release={'sha256':item['sha256'],'policy_hash':check['policy_hash'],'report_hash':check['report_hash'],'expected_revision':check['revision']}
  post('checked-input-explicit-release-'+str(index),'/checks/'+item['file_id']+'/release',release,key='checked-input-release-'+str(index))
  post('checked-batch-current-admission-'+str(index),'/workflow-collections/'+held_job['id']+'/refresh',decision(held['job']),key='checked-batch-admit-'+str(index))
  partial=post('checked-batch-current-receipts-'+str(index),'/workflow-collections/'+held_job['id'],method='GET')
  if index==0:assert all(i['run_id'] is None for i in partial['inputs']) and [s['state'] for s in partial['local_states']]==['published','held_or_unavailable']
 assert before_peers==(contacts('source'),contacts('receiver')) and all(i['run_id'] for i in partial['inputs'])
 reviewer=invoke('collection-independent-reviewer','identity',token=viewer)['actor_id']
 for file_index,item in enumerate(partial['inputs']):
  for step_index in range(2):
   label=f'checked-file-{file_index}-step-{step_index}';status=post(label+'-status','/workflow-runs/'+item['run_id'],method='GET');intent=status['steps'][step_index]['delivery_id'];before_receiver=contacts('receiver')
   denied=post(label+'-before-review','/workflow-runs/'+item['run_id']+'/work',expected=409,key=label+'-work');assert denied['error']=='dispatch_approval_required' and contacts('receiver')==before_receiver
   effect=post(label+'-delivery','/outbound-deliveries/'+intent,method='GET');assert effect['attempts']==0 and not effect['current_approval']
   choice={'delivery_id':intent,'reviewer_id':reviewer,**decision(effect)};preview=post(label+'-review-preview','/outbound-dispatch-reviews/preview',choice);review=post(label+'-review-propose','/outbound-dispatch-reviews',{'selection':choice,'definition_hash':preview['definition_hash']},key=label+'-review')['resource']['review'];post(label+'-named-approval','/outbound-dispatch-reviews/'+review['id']+'/approve',decision(review),key=label+'-approve',who=viewer_header)
   invoke(label+'-ordinary-send','workflow-work','--run-id',item['run_id'],'--idempotency-key',label+'-work',token=owner)
   target=inbox/(intent+'-'+definition['steps'][step_index]['filename']);received=private/(label+'-received.csv');stock(label+'-stock-retrieval',receiver_port,destination_known,f'get {target} {received}\n');assert received.read_bytes()==held_data[item['source_name']]
 result={'state':'passed','scope':'selected typed collection and downstream SFTP component; full journey remains open','source_symlink_malformed_manifest_changed_batch_and_wrong_pin_refused':True,'all_sibling_intake_releases_required_before_routing':True,'independent_dispatch_consent_per_file_and_step':True,'ordinary_typed_workflow_source':True,'stock_source_enforces_readonly':True,'ready_manifest_exact_two_files':True,'original_key_work_and_queue_replays_no_contacts':True,'ordinary_ordered_two_step_runs_per_input':True,'independent_stock_receiver_retrieval_exact':True,'original_batch_producer_bytes_and_manifest_unchanged':True,'unfinished_batch_files_unavailable_until_complete':True,'other_administrator_cannot_bypass_shared_file_hold':True,'original_failed_receipt_remains_historical':True,'killed_after_seal_before_acceptance':True,'original_acceptance_barrier_seconds':8,'original_lease_seconds':30,'takeover_attempts':2,'takeover_fence':2,'sealed_object_reused_without_source_contact':True,'collection_only_no_dummy_recipient':True,'actual_cutoff_rolls_back_acceptance_and_publication':True,'full_journeys_qualified':False,'browser_qualified':not options.backend_only,'browser_phases':browser_phases,'inference_performed':False,'scanner_engine_started':False};(raw/'collection-result.json').write_text(json.dumps(result,indent=2)+'\n');state='passed'
except Exception:failure=traceback.format_exc()
finally:
 for name in list(workers):
  try:finish_worker(name,expected=-signal.SIGKILL,kill=True,timeout=5)
  except Exception:cleanup.append('worker cleanup failed: '+name)
 for name in list(servers):
  try:stop(name)
  except Exception:cleanup.append('process cleanup failed: '+name)
 if created:
  try:sql('DROP DATABASE '+database+' WITH (FORCE)','freightctl')
  except Exception:cleanup.append('isolated database cleanup failed')
 final=sources();unchanged=initial==final;output_failure=None;output_files=0
 try:output_files=output_proof.verify()
 except Exception:output_failure=traceback.format_exc()
 manifest={'schema_version':1,'state':state if unchanged and not cleanup and not output_failure else 'failed','failure':failure,'output_closure_failure':output_failure,'output_artifacts_verified':output_files,'cleanup_failures':cleanup,'observed_at':datetime.now(timezone.utc).isoformat(),'postgres_container_id':pg,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_sha256':initial,'sources_unchanged_during_run':unchanged,'changed_source_paths':[p for p in set(initial)|set(final) if initial.get(p)!=final.get(p)],'binary_sha256':sha(binary) if binary.exists() else None,'private_reference':str(private.relative_to(root)),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'isolated_database_removed':created and not cleanup,'inference_performed':False,'scanner_engine_started':False,'full_journeys_qualified':False,'backend_only':options.backend_only,'limits':['Preliminary assisted same-host typed collection and downstream SFTP component; full J03, calendar admission, late/missing arrival policy, operator and production qualification remain open.','No browser qualification in backend-only mode; otherwise four selected browser phases are required, not full operator qualification.','No business acceptance or exactly-once downstream business effect.','F026 full aggregate owner-deferred; model/scanner/shared Docker lifecycle untouched.']};(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(str(raw/'manifest.json'),flush=True)
 if failure:print(failure,flush=True)
 if output_failure:print(output_failure,flush=True)
if manifest['state']!='passed':raise SystemExit(1)
