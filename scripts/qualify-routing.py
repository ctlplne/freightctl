#!/usr/bin/env python3
"""Approved bounded routing over real collected files and independent stock SFTP receivers.

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
parser=argparse.ArgumentParser();parser.add_argument('--postgres-container-id',required=True);options=parser.parse_args()
assert re.fullmatch(r'[0-9a-f]{64}',options.postgres_container_id),'use the exact task-owned PostgreSQL container ID'
run='routing-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
binary=private/'freightctl';database='freightctl_'+run.replace('-','_');created=False;servers={};logs={};steps=[];cleanup=[];state='failed';failure=None;started=time.monotonic()
output_proof=NativeEvidence(raw,steps)
reserve_step=output_proof.reserve
env=dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
pg=options.postgres_container_id
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 return {p:sha(root/p) for p in sorted(set(paths)) if p and (Path(p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p.startswith('web/tests/fixtures/') or p in ('go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'))}
initial=sources();(root/'.private/routing-native-current').write_text(str(raw)+'\n')
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
 entry=servers.pop(name,None)
 if entry is None:return
 p,out,err,args,began=entry
 if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
 try:code=p.wait(timeout=5)
 except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);code=p.wait(timeout=5)
 finally:out.close();err.close()
 steps.append({'name':name,'command':list(map(str,args)),'exit_code':code,'expected_exit_code':code,'duration_seconds':round(time.monotonic()-began,3),'stdout_sha256':sha(raw/(name+'.stdout')),'stderr_sha256':sha(raw/(name+'.stderr'))})
 assert code in (0,-signal.SIGTERM), 'task service did not stop cleanly: '+name

def start(name,args,number):
 assert name not in servers
 reserve_step(name)
 out=(raw/(name+'.stdout')).open('xb');err=(raw/(name+'.stderr')).open('xb');p=subprocess.Popen(list(map(str,args)),stdout=out,stderr=err,env=env,start_new_session=True)
 servers[name]=(p,out,err,args,time.monotonic())
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  assert p.poll() is None,name+' exited'
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
 https_args=[binary,'serve','--dsn-file',runtime,'--storage',storage,'--listen',f'127.0.0.1:{http_port}','--cert',cert,'--key',key,'--max-file-bytes',str(4<<20)];start('https-initial',https_args,http_port)
 def post(label,route,body=None,expected=200,key=None,who=None,method='POST'):
  out=raw/(label+'.json');args=['curl','--silent','--show-error','--cacert',cert,'--max-time','30','--header','@'+str(who or header),'--request',method,'--output',out,'--write-out','%{http_code}']
  if key:args+=['--header','Idempotency-Key: '+key]
  if body is not None:p=private/(label+'.request');p.write_bytes(body if isinstance(body,bytes) else json.dumps(body).encode());args+=['--header','Content-Type: application/json','--data-binary','@'+str(p)]
  code=int(command(label,[*args,url+prefix+route]).decode());steps[-1].update(http_status=code,expected_status=expected,response_sha256=sha(out));assert code==expected,(label,code,expected);return json.loads(out.read_bytes())
 for name in ['source-host','receiver-host','audit-host','source-client','receiver-client','audit-client']:command('ssh-key-'+name,['ssh-keygen','-q','-t','ed25519','-N','','-f',private/name])
 user=command('native-os-sftp-account',['id','-un']).decode().strip();assert re.fullmatch(r'[A-Za-z0-9_.-]+',user) # Stock OS fixture account, never Git identity.
 producer=private/'outbox';inbox=private/'inbox';audit_inbox=private/'audit-inbox';producer.mkdir(mode=0o700);inbox.mkdir(mode=0o700);audit_inbox.mkdir(mode=0o700);source_port=port();audit_port=port()
 def receiver(name,number,directory,readonly):
  (private/(name+'.authorized_keys')).write_bytes((private/(name+'-client.pub')).read_bytes());config=private/(name+'.conf');config.write_text(f'''Port {number}
ListenAddress 127.0.0.1
HostKey {private/(name+'-host')}
PidFile {private/(name+'.pid')}
AuthorizedKeysFile {private/(name+'.authorized_keys')}
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
 source_known=receiver('source',source_port,producer,True);destination_known=receiver('receiver',receiver_port,inbox,False);audit_known=receiver('audit',audit_port,audit_inbox,False)
 def contacts(name):return (raw/(name+'.stderr')).read_text().count('Accepted publickey for ')
 def stock(label,number,known,text,client,expected=0):
  batch=private/(label+'.batch');batch.write_text(text);return command(label,['sftp','-F','/dev/null','-P',str(number),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/(client+'-client'),'-b',batch,user+'@127.0.0.1'],expected=expected)
 def register(label,number,directory,host):
  return invoke(label+'-register','connection-register','--request-file',write(label+'-connection',{'expected_version':0,'address':f'127.0.0.1:{number}','user':user,'directory':str(directory),'host_public_file':str(private/(host+'-host.pub')),'key_file':str(private/(host+'-client')),'key_public_file':str(private/(host+'-client.pub'))}),'--idempotency-key',label+'-register',token=owner)['resource']
 source_connection=register('source',source_port,producer,'source');destination=register('destination',receiver_port,inbox,'receiver');audit_destination=register('audit-destination',audit_port,audit_inbox,'audit');post('create-incoming-folder','/namespace/commands',{'operation':'mkdir','path':'/incoming'},key='incoming')
 payloads={'north-settlement.csv':b'account,amount\n0001,42.00\n','south-settlement.csv':b'account,amount\n0002,13.00\n','unmatched.csv':b'account,amount\n0003,17.00\n'}
 for name,data in payloads.items():(producer/name).write_bytes(data)
 producer_manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in payloads.items()]}
 (producer/'settlement.ready.json').write_text(json.dumps(producer_manifest))
 probe=private/'readonly-probe.csv';probe.write_bytes(b'not permitted\n');stock('stock-source-refuses-write',source_port,source_known,f'put {probe} {producer}/forbidden.csv\n','source',expected=1);assert not (producer/'forbidden.csv').exists()
 source_definition={'kind':'sftp.collect','connection':ref(source_connection),'manifest':'settlement.ready.json','target_directory':'/incoming','completion_contract':'immutable-files-sha256-manifest-v1','max_files':4,'max_file_bytes':4<<20,'max_total_bytes':8<<20}
 catalog=[{'id':name,'kind':'sftp.deliver','connection':ref(destination if name=='north' else audit_destination),'filename':name+'.csv'} for name in ['north','south','audit']]
 program={'nodes':[{'kind':'if','when':{'op':'glob','field':'source.name','text':'north-*.csv'},'then':[{'kind':'for_each','variable':'recipient','steps':['north','audit'],'body':[{'kind':'deliver','step_variable':'recipient'}]}],'else':[{'kind':'if','when':{'op':'glob','field':'source.name','text':'south-*.csv'},'then':[{'kind':'deliver','step':'south'}],'else':[{'kind':'keep_local','reason':'unmatched_source_file'}]}]}]}
 definition={'schema_version':2,'name':'Approved settlement routing','steps':catalog,'source':source_definition,'program':program}
 before_peers=tuple(contacts(name) for name in ['source','receiver','audit'])
 preview=post('workflow-program-preview','/workflows/validate',{'definition':definition});assert preview['definition']==definition and len(preview['effects'])==3 and not preview['external_contact']
 workflow=post('workflow-program-draft','/workflows/drafts',{'expected_version':0,'definition':definition},key='routing-workflow')['resource'];workflow=post('workflow-program-approve','/workflows/'+workflow['id']+'/1/approve',decision(workflow),key='routing-approval')['resource']
 assert before_peers==tuple(contacts(name) for name in ['source','receiver','audit'])
 policy_request={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':32},{'name':'amount','type':'decimal','required':True,'max_bytes':32,'precision':12,'scale':2}],'max_bytes':1048576,'max_rows':100,'max_record_bytes':1024,'timeout_seconds':10}}
 policy=post('required-csv-policy','/intake-policy',policy_request,key='csv-policy')['resource']
 post('independent-dispatch-policy','/outbound-dispatch-policy',{'expected_revision':0,'mode':'independent'},key='independent-dispatch')
 selection={'workflow':ref(workflow),'timeout_seconds':300,'expected_authority_revision':1}
 collection_preview=post('collection-preview','/workflow-collections/preview',selection)
 request={'selection':selection,'definition_hash':collection_preview['definition_hash']}
 queued=post('collection-start','/workflow-collections',request,key='routing-collection')['resource']
 job=post('collection-queued-state','/workflow-collections/'+queued['id'],method='GET')['job']
 work_request={'definition_hash':job['definition_hash']}
 invoke('stock-source-collection','workflow-collection-work','--collection-id',job['id'],'--request-file',write('capture-request',work_request),'--idempotency-key','capture-original',token=owner)
 held=post('whole-batch-held','/workflow-collections/'+job['id'],method='GET');assert held['job']['captured'] and len(held['inputs'])==3 and all(s['state']=='held_or_unavailable' for s in held['local_states']) and all(i['run_id'] is None for i in held['inputs'])
 captured_peers=tuple(contacts(name) for name in ['source','receiver','audit']);assert captured_peers[1:]==before_peers[1:]
 for index,item in enumerate(held['inputs']):
  post('held-preview-refused-'+str(index),'/workflow-runs/preview',{'workflow':ref(workflow),'file_id':item['file_id']},expected=409)
  invoke('csv-parser-'+str(index),'check-run','--file-id',item['file_id'],'--idempotency-key','parse-'+str(index),token=owner)
  check=post('csv-proof-'+str(index),'/checks/'+item['file_id'],method='GET')['check'];assert check['state']=='passed' and check['policy_hash']==policy['definition_hash'] and check['report']['sha256']==item['sha256']
  release={'sha256':item['sha256'],'policy_hash':check['policy_hash'],'report_hash':check['report_hash'],'expected_revision':check['revision']}
  post('explicit-file-release-'+str(index),'/checks/'+item['file_id']+'/release',release,key='release-'+str(index))
  if index<2:
   post('partial-batch-cannot-route-'+str(index),'/workflow-collections/'+job['id']+'/refresh',decision(held['job']),key='partial-batch-'+str(index))
   partial=post('partial-batch-no-runs-'+str(index),'/workflow-collections/'+job['id'],method='GET');assert all(i['run_id'] is None for i in partial['inputs'])
 assert captured_peers==tuple(contacts(name) for name in ['source','receiver','audit'])
 # Once accepted, later routing reads only the original captured manifest/facts.
 (producer/'north-settlement.csv').rename(producer/'retired-north.csv');(producer/'settlement.ready.json').unlink()
 original_plans={};preview_counts=recorded_sql('preview-write-counts-before',"SELECT (SELECT count(*) FROM workflow_runs)||','||(SELECT count(*) FROM delivery_intents)||','||(SELECT count(*) FROM events)||','||(SELECT count(*) FROM workflow_receipts)")
 expected={'north-settlement.csv':['north','audit'],'south-settlement.csv':['south'],'unmatched.csv':[]}
 for index,item in enumerate(held['inputs']):
  x={'workflow':ref(workflow),'file_id':item['file_id']};p=post('exact-input-preview-'+str(index),'/workflow-runs/preview',x)
  q=invoke('cli-exact-input-preview-'+str(index),'workflow-run-preview','--request-file',write('preview-'+str(index),x),token=owner)
  assert p==q and not p['external_contact'] and [e['step_id'] for e in p['potential_effects']]==['north','south','audit'] and [e['step_id'] for e in p['selected_effects']]==expected[item['source_name']]
  plan=p['execution_plan'];facts=plan['facts']['source'];assert facts=={'collection_id':job['id'],'manifest_hash':held['job']['manifest_hash'],'name':item['source_name'],'batch_id':producer_manifest['batch_id'],'file_count':3,'index':index}
  assert plan['selected_steps']==expected[item['source_name']] and (plan.get('local_reason')=='unmatched_source_file')==(not expected[item['source_name']]);original_plans[item['id']]=(plan,p['execution_plan_hash'])
 assert recorded_sql('preview-write-counts-after',"SELECT (SELECT count(*) FROM workflow_runs)||','||(SELECT count(*) FROM delivery_intents)||','||(SELECT count(*) FROM events)||','||(SELECT count(*) FROM workflow_receipts)")==preview_counts
 post('queue-selected-plans','/workflow-collections/'+job['id']+'/refresh',decision(held['job']),key='routing-original-key')
 post('queue-original-key-replay','/workflow-collections/'+job['id']+'/refresh',decision(held['job']),key='routing-original-key')
 routed=post('selected-plans-persisted','/workflow-collections/'+job['id'],method='GET');assert all(i['run_id'] for i in routed['inputs'])
 assert recorded_sql('exact-selected-intent-count',"SELECT count(*) FROM delivery_intents")=='3'
 assert captured_peers==tuple(contacts(name) for name in ['source','receiver','audit'])
 stop('https-initial');start('https-restarted',https_args,http_port)
 reviewer=invoke('independent-reviewer-identity','identity',token=viewer)['actor_id'];received_paths={'receiver':set(),'audit':set()};verified_outputs=0
 for file_index,item in enumerate(routed['inputs']):
  status=post('frozen-plan-after-restart-'+str(file_index),'/workflow-runs/'+item['run_id'],method='GET');plan,plan_hash=original_plans[item['id']]
  assert status['run']['execution_plan']==plan and status['run']['execution_plan_hash']==plan_hash and [s['id'] for s in status['steps']]==expected[item['source_name']]
  post('foreign-actor-private-run-'+str(file_index),'/workflow-runs/'+item['run_id'],method='GET',expected=404,who=other_header)
  if not status['steps']:
   assert status['observed_state']=='kept_local';post('local-outcome-has-no-work','/workflow-runs/'+item['run_id']+'/work',key='local-work-refused',expected=409);continue
  for step_index,step in enumerate(status['steps']):
   label=f'file-{file_index}-step-{step_index}';intent=step['delivery_id'];peer='receiver' if step['id']=='north' else 'audit';current_contacts=tuple(contacts(n) for n in ['receiver','audit'])
   denied=post(label+'-independent-approval-required','/workflow-runs/'+item['run_id']+'/work',key=label+'-work',expected=409);assert denied['error']=='dispatch_approval_required' and current_contacts==tuple(contacts(n) for n in ['receiver','audit'])
   effect=post(label+'-delivery','/outbound-deliveries/'+intent,method='GET');assert effect['attempts']==0 and not effect['current_approval']
   choice={'delivery_id':intent,'reviewer_id':reviewer,**decision(effect)};review_preview=post(label+'-review-preview','/outbound-dispatch-reviews/preview',choice)
   review=post(label+'-review-proposal','/outbound-dispatch-reviews',{'selection':choice,'definition_hash':review_preview['definition_hash']},key=label+'-review')['resource']['review']
   post(label+'-named-approval','/outbound-dispatch-reviews/'+review['id']+'/approve',decision(review),key=label+'-approve',who=viewer_header)
   sent=invoke(label+'-stock-delivery','workflow-work','--run-id',item['run_id'],'--idempotency-key',label+'-work',token=owner)
   after_contacts=tuple(contacts(n) for n in ['receiver','audit']);other_index=1 if peer=='receiver' else 0;assert after_contacts[other_index]==current_contacts[other_index] and after_contacts[1-other_index]>current_contacts[1-other_index]
   replay=post(label+'-original-key-observation','/workflow-runs/'+item['run_id']+'/work',key=label+'-work');assert replay['replayed'] and replay['dispatch']==sent['dispatch'] and replay['status']==sent['status'] and tuple(contacts(n) for n in ['receiver','audit'])==after_contacts
   target=(inbox if peer=='receiver' else audit_inbox)/(intent+'-'+step['id']+'.csv');received=private/(label+'-received.csv');stock(label+'-independent-retrieval',receiver_port if peer=='receiver' else audit_port,destination_known if peer=='receiver' else audit_known,f'get {target} {received}\n',peer)
   assert received.read_bytes()==payloads[item['source_name']];received_paths[peer].add(target.name);verified_outputs+=1
  complete=post('complete-run-'+str(file_index),'/workflow-runs/'+item['run_id'],method='GET');assert complete['observed_state']=='succeeded' and complete['run']['execution_plan']==plan
 assert contacts('source')==captured_peers[0]
 assert {p.name for p in inbox.iterdir()}==received_paths['receiver'] and {p.name for p in audit_inbox.iterdir()}==received_paths['audit']
 # Browser phases use the same immutable workflow, original-key commands and
 # ordinary file/step approvals. Source acceptance and CSV release use the CLI.
 node=command('node-executable',['which','node']).decode().strip()
 post('browser-target-folder','/namespace/commands',{'operation':'mkdir','path':'/browser-routing'},key='browser-target')
 browser_payloads={'north-browser.csv':b'account,amount\n0061,31.00\n','south-browser.csv':b'account,amount\n0062,32.00\n','unmatched-browser.csv':b'account,amount\n0063,33.00\n'}
 for name,data in browser_payloads.items():(producer/name).write_bytes(data)
 browser_manifest={'schema_version':1,'batch_id':str(uuid.uuid4()),'files':[{'name':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in browser_payloads.items()]}
 (producer/'browser.ready.json').write_text(json.dumps(browser_manifest))
 browser_phases=[]
 def browser(phase,**values):
  directory=raw/('browser-'+phase);directory.mkdir(mode=0o700)
  cfg={'root':str(root),'private':str(private),'url':url,'certificate':str(cert),'token':str(owner),'tenant':tenant,'partner':partner,'raw':str(directory),'routing_only':True,'routing_phase':phase,'peer_logs':[str(raw/(name+'.stderr')) for name in ['source','receiver','audit']],'source':source_connection,'destination':destination,'audit_destination':audit_destination,'expected_program':program,**values}
  command('native-browser-'+phase,[node,'scripts/onboarding-exchange-browser.mjs',write('browser-'+phase,cfg)],timeout=180);browser_phases.append(phase)
  return json.loads((directory/'routing-browser-result.json').read_text())
 created_ui=browser('create')
 browser_job=post('browser-original-queued-job','/workflow-collections/'+created_ui['job']['id'],method='GET')['job']
 invoke('browser-source-byte-capture','workflow-collection-work','--collection-id',browser_job['id'],'--request-file',write('browser-capture-request',{'definition_hash':browser_job['definition_hash']}),'--idempotency-key','browser-capture',token=owner)
 browser_held=post('browser-original-captured-files','/workflow-collections/'+browser_job['id'],method='GET')
 for index,item in enumerate(browser_held['inputs']):
  invoke('browser-csv-check-'+str(index),'check-run','--file-id',item['file_id'],'--idempotency-key','browser-parse-'+str(index),token=owner)
  check=post('browser-csv-proof-'+str(index),'/checks/'+item['file_id'],method='GET')['check'];assert check['state']=='passed' and check['report']['sha256']==item['sha256']
  post('browser-explicit-file-release-'+str(index),'/checks/'+item['file_id']+'/release',{'sha256':item['sha256'],'policy_hash':check['policy_hash'],'report_hash':check['report_hash'],'expected_revision':check['revision']},key='browser-release-'+str(index))
 browser_expected={'north-browser.csv':['north','audit'],'south-browser.csv':['south'],'unmatched-browser.csv':[]}
 routed_ui=browser('route',job=browser_job,expected=browser_expected)
 browser_outputs=0
 for file_index,status in enumerate(routed_ui['runs']):
  item=next(i for i in routed_ui['view']['inputs'] if i['run_id']==status['run']['id'])
  for step_index,step in enumerate(status['steps']):
   label=f'browser-file-{file_index}-step-{step_index}'
   effect=post(label+'-original-delivery','/outbound-deliveries/'+step['delivery_id'],method='GET');choice={'delivery_id':step['delivery_id'],'reviewer_id':reviewer,**decision(effect)}
   preview=post(label+'-consent-preview','/outbound-dispatch-reviews/preview',choice);review=post(label+'-consent-proposal','/outbound-dispatch-reviews',{'selection':choice,'definition_hash':preview['definition_hash']},key=label+'-consent')['resource']['review']
   post(label+'-independent-approval','/outbound-dispatch-reviews/'+review['id']+'/approve',decision(review),key=label+'-approve',who=viewer_header)
   completed_ui=browser(f'send-{file_index}-{step_index}',job=browser_job,target_file_id=item['file_id'],target_step=step['id'],audit_send=browser_outputs==0)
   assert completed_ui['runs'][0]['steps'][step_index]['state']=='succeeded'
   peer='receiver' if step['id']=='north' else 'audit';target=(inbox if peer=='receiver' else audit_inbox)/(step['delivery_id']+'-browser-'+step['id']+'.csv');received=private/(f'browser-received-{file_index}-{step_index}.csv')
   stock(f'browser-stock-retrieval-{file_index}-{step_index}',receiver_port if peer=='receiver' else audit_port,destination_known if peer=='receiver' else audit_known,f'get {target} {received}\n',peer)
   assert received.read_bytes()==browser_payloads[item['source_name']];browser_outputs+=1
 assert browser_outputs==3
 result={'state':'passed','scope':'selected assisted same-host approved routing and ordinary intake/dispatch; full J03 remains open','files':3,'selected_delivery_intents':3,'verified_stock_outputs':verified_outputs,'explicit_local_outcomes':1,'distinct_receiver_host_and_client_identities':2,'whole_sibling_intake_before_routing':True,'independent_approval_per_selected_file_and_step':True,'metadata_previews_create_no_events_receipts_runs_or_intents':True,'api_cli_preview_agree':True,'original_manifest_facts_survive_source_name_change_and_manifest_removal':True,'execution_plan_survives_application_restart':True,'original_dispatch_key_replay_makes_no_new_contact':True,'foreign_actor_run_privacy':True,'local_outcome_creates_no_receiver_receipt':True,'sources_not_recontacted_after_capture':True,'unexpected_receiver_files':0,'browser_qualified':True,'browser_phases':browser_phases,'browser_verified_stock_outputs':browser_outputs,'full_journeys_qualified':False,'inference_performed':False,'scanner_engine_started':False}
 with (raw/'routing-result.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 state='passed'
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
 manifest={'schema_version':1,'state':state if unchanged and not cleanup and not output_failure else 'failed','failure':failure,'output_closure_failure':output_failure,'output_artifacts_verified':output_files,'cleanup_failures':cleanup,'observed_at':datetime.now(timezone.utc).isoformat(),'postgres_container_id':pg,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_sha256':initial,'sources_unchanged_during_run':unchanged,'changed_source_paths':[p for p in set(initial)|set(final) if initial.get(p)!=final.get(p)],'binary_sha256':sha(binary) if binary.exists() else None,'private_reference':str(private.relative_to(root)),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'isolated_database_removed':created and not cleanup,'inference_performed':False,'scanner_engine_started':False,'full_journeys_qualified':False,'browser_qualified':state=='passed','limits':['Selected assisted same-host routing, real PostgreSQL, stock SFTP source and two distinct stock SFTP receiver identities; no full J03 or production/native-platform qualification.','Browser selected structured editing, approval, preview, routing, local outcome and sends are exercised; CLI accepts/releases source bytes. Revoked authority, ambiguous receipt reconciliation, broader batch/routing/connectors and business acceptance remain open.','F026 final aggregate remains owner-deferred; no models, scanner, push, publication, external deployment or shared Docker lifecycle.']}
 with (raw/'manifest.json').open('x') as f:json.dump(manifest,f,indent=2);f.write('\n')
 print(str(raw/'manifest.json'),flush=True)
 if failure:print(failure,flush=True)
 if output_failure:print(output_failure,flush=True)
if manifest['state']!='passed':raise SystemExit(1)
