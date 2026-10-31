#!/usr/bin/env python3
"""Scheduled ready-manifest arrivals, bounded observation and ordinary collection.

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
run='arrivals-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
binary=private/'freightctl';database='freightctl_'+run.replace('-','_');created=False;servers={};logs={};steps=[];cleanup=[];state='failed';failure=None;started=time.monotonic()
output_proof=NativeEvidence(raw,steps)
reserve_step=output_proof.reserve
env=dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
pg=options.postgres_container_id
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 return {p:sha(root/p) for p in sorted(set(paths)) if p and (Path(p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p.startswith('web/tests/fixtures/') or p in ('go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'))}
initial=sources();(root/'.private/arrival-runtime-current').write_text(str(raw)+'\n')
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
  data=command(label,cli_args(op,*extra,token=token),expected=expected)
  if expected!=0 or not data:return None
  if op=='workflow-schedule-worker':return [json.loads(line) for line in data.splitlines() if line]
  return json.loads(data)
 def identity(name,permissions=None):
  token=private/(name+'.token');command(name+'-token',[binary,'token','--token-file',token]);invoke(name+'-enroll','enroll',*(['--permissions',permissions] if permissions else []),token=token);return token
 owner=identity('owner');viewer=identity('viewer','inspect,workflow_approve');other_admin=identity('other-admin');header=headers('owner',owner);viewer_header=headers('viewer',viewer);other_header=headers('other-admin',other_admin)
 cert,key=private/'cert.pem',private/'key.pem';command('certificate',[binary,'dev-cert','--cert',cert,'--key',key]);http_port,receiver_port=port(),port();url='https://127.0.0.1:'+str(http_port);prefix=f'/v1/tenants/{tenant}/partners/{partner}'
 start('https',[binary,'serve','--dsn-file',runtime,'--storage',storage,'--listen',f'127.0.0.1:{http_port}','--cert',cert,'--key',key,'--max-file-bytes',str(4<<20)],http_port)
 def post(label,route,body=None,expected=200,key=None,who=None,method='POST'):
  out=raw/(label+'.json');args=['curl','--silent','--show-error','--cacert',cert,'--max-time','45','--header','@'+str(who or header),'--request',method,'--output',out,'--write-out','%{http_code}']
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
 data_by_name={'arrival-a.csv':b'account,amount\n0001,42.00\n','arrival-b.csv':b'account,amount\n0002,13.00\n'}
 for name,data in data_by_name.items():(producer/name).write_bytes(data)
 manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in data_by_name.items()]}
 (producer/'old.ready.json').write_text(json.dumps(manifest))
 probe=private/'readonly-probe.csv';probe.write_bytes(b'not permitted\n');stock('stock-source-refuses-write',source_port,source_known,f'put {probe} {producer}/forbidden.csv\n',expected=1);assert not (producer/'forbidden.csv').exists()
 source_definition={'kind':'sftp.collect','connection':ref(source_connection),'manifest':'settlement-{due_utc}.ready.json','target_directory':'/incoming','completion_contract':'immutable-files-sha256-scheduled-manifest-v1','max_files':4,'max_file_bytes':4<<20,'max_total_bytes':8<<20}
 definition={'schema_version':1,'name':'Scheduled settlement','steps':[{'id':'forward','kind':'sftp.deliver','connection':ref(destination),'filename':'settlement.csv'}],'source':source_definition}
 preview=post('scheduled-workflow-preview','/workflows/validate',{'definition':definition});assert not preview['external_contact']
 workflow=post('scheduled-workflow-draft','/workflows/drafts',{'expected_version':0,'definition':definition},key='arrival-workflow')['resource'];workflow=post('scheduled-workflow-approve','/workflows/'+workflow['id']+'/1/approve',decision(workflow),key='arrival-workflow-approve')['resource']
 choices=post('scheduled-source-picker','/workflow-schedule-workflows',method='GET');assert choices['workflows']==[{'id':workflow['id'],'version':1,'hash':workflow['definition_hash'],'name':definition['name'],'source':source_definition}]
 assert post('scheduled-source-manual-admission-refused','/workflow-collections/preview',{'workflow':ref(workflow),'timeout_seconds':60,'expected_authority_revision':1},expected=400)['error']=='invalid_workflow_collection'
 def schedule(label,arrival=30,execution=120,late=2):
  due=int(time.time())+2
  x={'name':label,'workflow':ref(workflow),'source':{'directory':'/incoming','filename_pattern':source_definition['manifest'],'recursive':False,'kind':'sftp.collect'},'calendar':{'time_zone':'UTC','starts_at':utc(due),'ends_at':utc(due+1),'local_times':[utc(due)[11:19]],'weekdays':list(range(7)),'holidays':[],'gap_policy':'skip','fold_policy':'both'},'missed_run_policy':'all','max_catch_up':4,'max_active_runs':2,'max_files_per_occurrence':4,'execution_deadline_seconds':execution,'late_start_grace_seconds':1,'expected_authority_revision':1,'arrival':{'late_after_seconds':late,'arrival_deadline_seconds':arrival,'poll_interval_seconds':1}}
  before=contacts('source'),contacts('receiver');p=post(label+'-preview','/workflow-schedules/preview',x);assert not p['external_contact'] and p['definition']['collection']['source']==source_definition
  s=post(label+'-draft','/workflow-schedules/drafts',{'expected_version':0,'selection':x,'definition_hash':p['definition_hash']},key=label+'-draft')['resource']['schedule'];s=post(label+'-activate','/workflow-schedules/'+s['id']+'/1/activate',decision(s),key=label+'-activate')['resource']['schedule'];assert before==(contacts('source'),contacts('receiver'))
  wait_until(due)
  r=post(label+'-tick','/workflow-schedules/'+s['id']+'/1/tick',{'limit':1},key=label+'-tick')['resource'];assert len(r['occurrences'])==1 and r['occurrences'][0]['kind']=='collection' and r['run_ids']==[] and before==(contacts('source'),contacts('receiver'))
  return s,r['occurrences'][0]
 def wait_until(timestamp):
  until=time.monotonic()+130
  while time.time()<timestamp:assert time.monotonic()<until;time.sleep(.05)
 def arrival(label,o):return post(label,'/workflow-schedule-arrivals/'+o['id'],method='GET')
 def probe_arrival(label,o,a,key=None,expected=200):return post(label,'/workflow-schedule-arrivals/'+o['id']+'/probe',{'definition_hash':a['definition_hash']},key=key or label,expected=expected)
 def due_name(o):return 'settlement-'+datetime.fromisoformat(o['due_at'].replace('Z','+00:00')).strftime('%Y%m%dT%H%M%SZ')+'.ready.json'
 late_schedule,o=schedule('late-settlement',arrival=45,execution=120)
 post('foreign-administrator-cannot-read-arrival','/workflow-schedule-arrivals/'+o['id'],method='GET',who=other_header,expected=404)
 post('foreign-reviewer-cannot-read-arrival','/workflow-schedule-arrivals/'+o['id'],method='GET',who=viewer_header,expected=404)
 post('foreign-administrator-cannot-probe-arrival','/workflow-schedule-arrivals/'+o['id']+'/probe',{'definition_hash':'a'*64},key='foreign-probe',who=other_header,expected=404)
 v=arrival('initial-exact-arrival',o);a=v['arrival'];assert a['state']=='waiting' and a['probes']==0 and a['definition']['manifest_name']==due_name(o)
 before=contacts('source');invoke('metadata-worker-does-not-read','workflow-schedule-worker','--schedule-id',late_schedule['id'],'--version','1','--max-polls','1',token=owner);assert contacts('source')==before
 for index in range(9):
  wait_until(datetime.fromisoformat(a['next_probe_at'].replace('Z','+00:00')).timestamp())
  r=probe_arrival('absent-probe-'+str(index),o,a);assert r['resource']['state']=='waiting' and r['resource']['external_contact']
  v=arrival('absent-status-'+str(index),o);a=v['arrival'];assert a['probes']==index+1 and a['collection_id'] is None and 'collection' not in v
 assert sql('SELECT count(*) FROM workflow_collection_jobs')=='0'
 assert v['observed_state']=='late_waiting' and v['arrival_timeliness']=='not_observed'
 (producer/due_name(o)).write_text(json.dumps(manifest));wait_until(datetime.fromisoformat(a['next_probe_at'].replace('Z','+00:00')).timestamp())
 ready=probe_arrival('late-ready-probe',o,a,key='late-ready-original');before=contacts('source');again=probe_arrival('late-ready-original-replay',o,a,key='late-ready-original');assert ready['resource']==again['resource'] and again['replayed'] and contacts('source')==before
 v=arrival('late-ready-frozen',o);a=v['arrival'];assert a['state']=='ready' and a['probes']==10 and v['arrival_timeliness']=='late' and a['manifest']==manifest and a['collection_id'] is None
 (producer/due_name(o)).unlink() # Bytes remain immutable; a later collector must use the frozen manifest.
 if not options.backend_only:
  config={'root':str(root),'url':url,'tenant':tenant,'partner':partner,'token':str(owner),'certificate':str(cert),'private':str(private),'raw':str(raw),'arrivals_only':True,'schedule':late_schedule,'occurrence':o,'workflow':ref(workflow),'source':source_definition,'source_log':str(raw/'source.log'),'receiver_log':str(raw/'receiver.log')}
  command('browser-arrival-reviews',['node','scripts/onboarding-exchange-browser.mjs',write('browser-arrivals',config)])
 else:
  admitted=post('frozen-ready-admit','/workflow-schedule-arrivals/'+o['id']+'/admit',decision(a),key='late-admit-original');replayed=post('frozen-ready-admit-replay','/workflow-schedule-arrivals/'+o['id']+'/admit',decision(a),key='late-admit-original');assert admitted['resource']==replayed['resource'] and replayed['replayed'] and contacts('source')==before
 v=arrival('scheduled-collection-admitted',o);job=v['collection']['job'];assert v['arrival']['state']=='admitted' and job['deadline_at']==o['deadline_at'] and job['definition']['schedule']['manifest_hash']==a['manifest_hash']
 invoke('ordinary-executing-schedule-worker','workflow-schedule-worker','--schedule-id',late_schedule['id'],'--version','1','--execute','--schedule-poll','1s','--max-polls','4',token=owner)
 v=arrival('scheduled-downstream-custody',o);assert v['collection']['job']['captured'] and v['collection']['job']['attempts']==1
 for index,item in enumerate(v['collection']['inputs']):
  run=post('ordinary-arrival-run-'+str(index),'/workflow-runs/'+item['run_id'],method='GET');assert run['observed_state']=='succeeded';intent=run['steps'][0]['delivery_id'];received=private/('arrival-retrieved-'+str(index)+'.csv');stock('stock-arrival-retrieval-'+str(index),receiver_port,destination_known,f'get {inbox}/{intent}-settlement.csv {received}\n');assert received.read_bytes()==data_by_name[item['source_name']]
 missing_schedule,missing=schedule('missing-settlement',arrival=3,execution=10,late=0);v=arrival('missing-initial',missing);probe_arrival('missing-first-absence',missing,v['arrival']);wait_until(datetime.fromisoformat(v['arrival']['definition']['arrival_deadline_at'].replace('Z','+00:00')).timestamp());before=contacts('source');invoke('missing-cutoff-executing-worker','workflow-schedule-worker','--schedule-id',missing_schedule['id'],'--version','1','--execute','--max-polls','1',token=owner);v=arrival('missing-recorded',missing);assert v['arrival']['state']=='missing' and v['arrival_timeliness']=='not_observed' and v['arrival']['collection_id'] is None and contacts('source')==before
 cancelled_schedule,cancelled=schedule('cancelled-arrival',arrival=10,execution=20,late=0);v=arrival('cancel-initial',cancelled);before=contacts('source');stopped=post('cancel-original','/workflow-schedule-arrivals/'+cancelled['id']+'/cancel',decision(v['arrival']),key='cancel-original');replay=post('cancel-original-replay','/workflow-schedule-arrivals/'+cancelled['id']+'/cancel',decision(v['arrival']),key='cancel-original');assert stopped['resource']==replay['resource'] and replay['replayed'] and contacts('source')==before
 suspended_schedule,suspended=schedule('suspended-ready',arrival=10,execution=30,late=0);(producer/due_name(suspended)).write_text(json.dumps({**manifest,'batch_id':str(uuid.uuid4())}));v=arrival('suspended-initial',suspended);probe_arrival('suspended-ready-probe',suspended,v['arrival']);v=arrival('suspended-ready-observed',suspended);current=post('suspended-calendar-current','/workflow-schedules/'+suspended_schedule['id']+'/1',method='GET')['schedule'];post('suspend-calendar-before-admission','/workflow-schedules/'+suspended_schedule['id']+'/1/suspend',decision(current),key='suspend-calendar');before=contacts('source');post('suspended-ready-cannot-admit','/workflow-schedule-arrivals/'+suspended['id']+'/admit',decision(v['arrival']),key='suspended-admit',expected=409);assert contacts('source')==before
 restart_schedule,restart=schedule('killed-probe',arrival=45,execution=60,late=0);v=arrival('killed-probe-initial',restart);request=write('killed-probe-request',{'definition_hash':v['arrival']['definition_hash']});label='killed-probe-original';args=cli_args('workflow-arrival-probe','--occurrence-id',restart['id'],'--request-file',request,'--idempotency-key',label,token=owner)
 reserve_step(label)
 os.killpg(servers['source'].pid,signal.SIGSTOP)
 out=(raw/(label+'.stdout')).open('wb');err=(raw/(label+'.stderr')).open('wb');p=subprocess.Popen(list(map(str,args)),stdout=out,stderr=err,env=env,start_new_session=True);workers[label]=(p,out,err,args,time.monotonic())
 wait_sql('SELECT state FROM workflow_schedule_arrivals WHERE occurrence_id='+sql_string(restart['id']),'probing',timeout=8);claimed=arrival('killed-probe-lease',restart)['arrival'];assert claimed['probes']==1 and claimed['fence']==1
 finish_worker(label,expected=-signal.SIGKILL,kill=True,timeout=5);os.killpg(servers['source'].pid,signal.SIGCONT)
 before=contacts('source');probe_arrival('early-takeover-refused',restart,claimed,key=label,expected=409);assert contacts('source')==before and arrival('lease-not-shortened',restart)['arrival']['lease_until']==claimed['lease_until']
 wait_until(datetime.fromisoformat(claimed['lease_until'].replace('Z','+00:00')).timestamp()+.1)
 invoke('original-key-probe-takeover','workflow-arrival-probe','--occurrence-id',restart['id'],'--request-file',request,'--idempotency-key',label,token=owner)
 recovered=arrival('probe-recovered-after-original-lease',restart)['arrival'];assert recovered['state']=='waiting' and recovered['probes']==2 and recovered['fence']==2 and recovered['collection_id'] is None
 result={'state':'passed','nine_absent_polls_do_not_consume_eight_byte_attempts':True,'utc_due_correlated_manifest_only':True,'verified_observation_classifies_late':True,'ready_snapshot_survives_manifest_removal_before_collection':True,'ordinary_scheduled_worker_captures_and_forwards_exact_stock_bytes':True,'missing_records_no_verified_observation_not_producer_absence':True,'cancel_original_key_replay':True,'suspension_stops_frozen_ready_admission':True,'killed_probe_original_30_second_lease_preserved':True,'probe_takeover_fence':2,'browser_qualified':not options.backend_only,'inference_performed':False,'scanner_engine_started':False,'business_acceptance':'unknown','full_journeys_qualified':False};(raw/'arrival-result.json').write_text(json.dumps(result,indent=2)+'\n');state='passed'
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
 manifest={'schema_version':1,'state':state if unchanged and not cleanup and not output_failure else 'failed','failure':failure,'output_closure_failure':output_failure,'output_artifacts_verified':output_files,'cleanup_failures':cleanup,'observed_at':datetime.now(timezone.utc).isoformat(),'postgres_container_id':pg,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_sha256':initial,'sources_unchanged_during_run':unchanged,'changed_source_paths':[p for p in set(initial)|set(final) if initial.get(p)!=final.get(p)],'binary_sha256':sha(binary) if binary.exists() else None,'private_reference':str(private.relative_to(root)),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'isolated_database_removed':created and not cleanup,'inference_performed':False,'scanner_engine_started':False,'full_journeys_qualified':False,'backend_only':options.backend_only,'limits':['Selected assisted same-host scheduled collection component; broader batches/routing/connectors, business receipts, independent adoption and full J03 remain open.','No browser qualification in backend-only mode; selected browser states do not establish complete operator qualification.','No business acceptance or exactly-once downstream business effect.','F026 full aggregate owner-deferred; model/scanner/shared Docker lifecycle untouched.']};(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(str(raw/'manifest.json'),flush=True)
 if failure:print(failure,flush=True)
 if output_failure:print(output_failure,flush=True)
if manifest['state']!='passed':raise SystemExit(1)
