#!/usr/bin/env python3
"""Durable calendar admission, native worker recovery and independent SFTP receipts.

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
run='schedules-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700);raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
binary=private/'freightctl';database='freightctl_'+run.replace('-','_');created=False;servers={};logs={};steps=[];cleanup=[];state='failed';failure=None;started=time.monotonic()
output_proof=NativeEvidence(raw,steps)
reserve_step=output_proof.reserve
env=dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',NODE_OPTIONS='--max-old-space-size=192',PLAYWRIGHT_BROWSERS_PATH=str(root/'.cache/freightctl-playwright'))
pg=options.postgres_container_id
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 return {p:sha(root/p) for p in sorted(set(paths)) if p and (Path(p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p.startswith('web/tests/fixtures/') or p in ('go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'))}
initial=sources();(root/'.private/schedule-runtime-current').write_text(str(raw)+'\n')
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
def start_worker(label,schedule,execute=True,polls=120):
 reserve_step(label);args=cli_args('workflow-schedule-worker','--schedule-id',schedule['id'],'--version',schedule['version'],'--schedule-poll','1s','--max-polls',polls,*(['--execute'] if execute else []),token=owner)
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
 owner=identity('owner');viewer=identity('viewer','inspect,workflow_approve');header=headers('owner',owner);viewer_header=headers('viewer',viewer)
 cert,key=private/'cert.pem',private/'key.pem';command('certificate',[binary,'dev-cert','--cert',cert,'--key',key]);http_port,receiver_port=port(),port();url='https://127.0.0.1:'+str(http_port);prefix=f'/v1/tenants/{tenant}/partners/{partner}'
 start('https',[binary,'serve','--dsn-file',runtime,'--storage',storage,'--listen',f'127.0.0.1:{http_port}','--cert',cert,'--key',key,'--max-file-bytes',str(4<<20)],http_port)
 def post(label,route,body=None,expected=200,key=None,who=None,method='POST'):
  out=raw/(label+'.json');args=['curl','--silent','--show-error','--cacert',cert,'--max-time','30','--header','@'+str(who or header),'--request',method,'--output',out,'--write-out','%{http_code}']
  if key:args+=['--header','Idempotency-Key: '+key]
  if body is not None:p=private/(label+'.request');p.write_bytes(body if isinstance(body,bytes) else json.dumps(body).encode());args+=['--header','Content-Type: application/json','--data-binary','@'+str(p)]
  code=int(command(label,[*args,url+prefix+route]).decode());steps[-1].update(http_status=code,expected_status=expected,response_sha256=sha(out));assert code==expected,(label,code,expected);return json.loads(out.read_bytes())
 for name in ['host','client']:command('ssh-key-'+name,['ssh-keygen','-q','-t','ed25519','-N','','-f',private/name])
 (private/'authorized_keys').write_bytes((private/'client.pub').read_bytes());user=command('native-os-receiver-account',['id','-un']).decode().strip();assert re.fullmatch(r'[A-Za-z0-9_.-]+',user) # OS fixture account, never Git identity.
 inbox=private/'inbox';inbox.mkdir(mode=0o700)
 ssh_config=f'''Port {receiver_port}
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
'''
 send_conf=private/'sshd-send.conf';send_conf.write_text(ssh_config);read_conf=private/'sshd-observe.conf';read_conf.write_text(ssh_config.replace('ForceCommand internal-sftp -d','ForceCommand internal-sftp -R -d'));start('receiver',['/usr/sbin/sshd','-D','-e','-f',send_conf],receiver_port)
 known=private/'known_hosts';known.write_text(f'[127.0.0.1]:{receiver_port} '+(private/'host.pub').read_text());contacts=lambda:(raw/'receiver.log').read_text().count('Accepted publickey for ')
 connection=invoke('register-receiver','connection-register','--request-file',write('connection',{'expected_version':0,'address':f'127.0.0.1:{receiver_port}','user':user,'directory':str(inbox),'host_public_file':str(private/'host.pub'),'key_file':str(private/'client'),'key_public_file':str(private/'client.pub')}),'--idempotency-key','connection',token=owner)['resource']
 definition={'schema_version':1,'name':'Scheduled settlement','steps':[{'id':label,'kind':'sftp.deliver','connection':ref(connection),'filename':label+'.csv'} for label in ['first','second']]}
 workflow=post('workflow-draft','/workflows/drafts',{'expected_version':0,'definition':definition},key='workflow')['resource'];workflow=post('workflow-approve','/workflows/'+workflow['id']+'/1/approve',decision(workflow),key='workflow-approve')['resource']
 post('create-incoming-folder','/namespace/commands',{'operation':'mkdir','path':'/incoming'},key='incoming')
 def accept(label,filename):
  data=(b'account,amount,case\n0001,42.00,'+label.encode()+b'\n')*64;payload=private/(label+'.csv');payload.write_bytes(data);out=raw/(label+'-accept.json');code=int(command(label+'-accept',['curl','--silent','--show-error','--cacert',cert,'--max-time','20','--header','@'+str(header),'--header','Idempotency-Key: '+label+'-accept','--header','X-File-Size: '+str(len(data)),'--header','X-Content-SHA256: '+sha(payload),'--data-binary','@'+str(payload),'--output',out,'--write-out','%{http_code}',url+prefix+'/files']).decode());steps[-1].update(http_status=code,expected_status=201,response_sha256=sha(out));assert code==201;file=json.loads(out.read_bytes())['file'];assert file['sha256']==sha(payload);post(label+'-publish','/namespace/commands',{'operation':'publish','path':'/incoming/'+filename,'file_id':file['id']},key=label+'-publish');return file,data
 def receive(label,status,data):
  for index,step in enumerate(status['steps']):
   assert step['state']=='succeeded';target=inbox/(step['delivery_id']+'-'+definition['steps'][index]['filename']);out=private/(label+'-'+str(index)+'-received.csv');batch=private/(label+'-'+str(index)+'.batch');batch.write_text(f'get {target} {out}\n');command(label+'-'+str(index)+'-stock-sftp',['sftp','-F','/dev/null','-P',str(receiver_port),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(known),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'client','-b',batch,user+'@127.0.0.1']);assert out.read_bytes()==data and target.read_bytes()==data
 alpha,alpha_data=accept('alpha','settlement-a.csv');base=int(time.time())+12
 selection={'name':'Native scheduled settlements','workflow':ref(workflow),'source':{'directory':'/incoming','filename_pattern':'settlement-*.csv','recursive':False},'calendar':{'time_zone':'UTC','starts_at':utc(base),'ends_at':utc(base+120),'local_times':[utc(base+x)[11:19] for x in [0,8,12,16,50,55]],'weekdays':[0,1,2,3,4,5,6],'holidays':[],'gap_policy':'skip','fold_policy':'both'},'missed_run_policy':'all','max_catch_up':4,'max_active_runs':1,'max_files_per_occurrence':1,'execution_deadline_seconds':120,'late_start_grace_seconds':30,'expected_authority_revision':1}
 probe=json.loads(json.dumps(selection));probe['calendar'].update(time_zone='America/New_York',starts_at='2024-11-03T00:00:00Z',ends_at='2024-11-04T00:00:00Z',local_times=['01:30:00'])
 node=command('node-executable',['which','node']).decode().strip()
 def browser(phase,**values):
  directory=raw/('browser-'+phase);directory.mkdir(mode=0o700);cfg={'root':str(root),'private':str(private),'url':url,'certificate':str(cert),'token':str(owner),'tenant':tenant,'partner':partner,'raw':str(directory),'schedules_only':True,'schedule_phase':phase,'receiver_log':str(raw/'receiver.log'),'selection':selection,'calendar_probe':probe,**values};command('native-browser-'+phase,[node,'scripts/onboarding-exchange-browser.mjs',write('browser-'+phase,cfg)],timeout=180);return json.loads((directory/'schedule-browser-result.json').read_text())
 created_ui=browser('create');schedule=created_ui['schedule'];assert schedule['state']=='active'
 post('viewer-schedule-private','/workflow-schedules/'+schedule['id']+'/1',who=viewer_header,method='GET',expected=404);assert post('viewer-private-list','/workflow-schedules',who=viewer_header,method='GET')['schedules']==[]
 invoke('schedule-cli-exact-status','workflow-schedule-status','--schedule-id',schedule['id'],'--version','1',token=owner)
 stage_fault='freightctl_schedule_stage_'+uuid.uuid4().hex
 recorded_sql('install-original-publication-barrier',f"CREATE FUNCTION {stage_fault}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='publishing' AND NEW.attempts=1 THEN PERFORM pg_sleep(8);END IF;RETURN NEW;END $$;CREATE TRIGGER {stage_fault} BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION {stage_fault}()")
 first_worker=start_worker('first-worker-killed-before-publication',schedule);wait_sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep' AND query LIKE 'UPDATE delivery_intents%')",timeout=30)
 initial_status=post('first-worker-staging-status','/workflow-runs/'+sql("SELECT run_id FROM workflow_schedule_inputs WHERE file_id='"+alpha['id']+"'"),method='GET');first_run=initial_status['run']['id'];first_delivery=initial_status['steps'][0]['delivery_id'];partial=inbox/('.freightctl-'+first_delivery+'-1.partial');assert partial.read_bytes()==alpha_data and not (inbox/(first_delivery+'-first.csv')).exists();assert first_worker.poll() is None
 finish_worker('first-worker-killed-before-publication',expected=-signal.SIGKILL,kill=True);recorded_sql('drop-original-publication-barrier',f'DROP TRIGGER {stage_fault} ON delivery_intents;DROP FUNCTION {stage_fault}()');retained=invoke('retained-original-lease','delivery-status','--delivery-id',first_delivery,token=owner);assert retained['state']=='staging' and retained['attempts']==1 and retained['fence']==1
 beta,beta_data=accept('beta','settlement-b.csv');projection_fault='freightctl_schedule_projection_'+uuid.uuid4().hex
 recorded_sql('install-run-projection-failure',f"CREATE FUNCTION {projection_fault}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.file_id='{beta['id']}' AND NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned schedule projection failure';END IF;RETURN NEW;END $$;CREATE TRIGGER {projection_fault} BEFORE UPDATE ON workflow_runs FOR EACH ROW EXECUTE FUNCTION {projection_fault}()")
 replacement=start_worker('replacement-worker-projection-fault',schedule);assert replacement.poll() is None
 def api_schedule(label,pattern,deadline=30,due=None):
  stem=label.lower().replace(' ','-');when=due if due is not None else int(time.time())+2;x=json.loads(json.dumps(selection));x['name']=label;x['source']['filename_pattern']=pattern;x['execution_deadline_seconds']=deadline;x['late_start_grace_seconds']=min(deadline,1);x['calendar'].update(starts_at=utc(when),ends_at=utc(when+60),local_times=[utc(when)[11:19]]);p=post(stem+'-preview','/workflow-schedules/preview',x);s=post(stem+'-draft','/workflow-schedules/drafts',{'expected_version':0,'selection':x,'definition_hash':p['definition_hash']},key=stem+'-draft')['resource']['schedule'];s=post(stem+'-activate','/workflow-schedules/'+s['id']+'/1/activate',decision(s),key=stem+'-activate')['resource']['schedule'];return s,when
 uncertain,uncertain_data=accept('uncertain','uncertain.csv');u,when=api_schedule('Uncertain receipt','uncertain.csv',3);wait_sql('SELECT clock_timestamp()>='+sql_string(utc(when))+'::timestamptz');u_tick=post('uncertain-queue','/workflow-schedules/'+u['id']+'/1/tick',{'limit':1},key='uncertain-queue')['resource'];u_run=u_tick['run_ids'][0];u_status=post('uncertain-queued-status','/workflow-runs/'+u_run,method='GET');u_delivery=u_status['steps'][0]['delivery_id'];receipt_fault='freightctl_schedule_receipt_'+uuid.uuid4().hex
 recorded_sql('install-real-published-receipt-failure',f"CREATE FUNCTION {receipt_fault}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='{u_delivery}' AND NEW.state='succeeded' THEN RAISE EXCEPTION 'task-owned scheduled receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER {receipt_fault} BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION {receipt_fault}()")
 invoke('real-uncertain-send','delivery-work','--delivery-id',u_delivery,token=owner,expected=1);recorded_sql('drop-real-published-receipt-failure',f'DROP TRIGGER {receipt_fault} ON delivery_intents;DROP FUNCTION {receipt_fault}()');published=invoke('real-uncertain-published-status','delivery-status','--delivery-id',u_delivery,token=owner);assert published['state']=='publishing' and published['attempts']==1;u_target=inbox/(u_delivery+'-first.csv');assert u_target.read_bytes()==uncertain_data
 before_events=sql("SELECT count(*) FROM events WHERE resource_id IN ('"+schedule['id']+"','"+first_run+"','"+first_delivery+"')");before_contacts=contacts();assert replacement.poll() is None;time.sleep(2);assert replacement.poll() is None and before_events==sql("SELECT count(*) FROM events WHERE resource_id IN ('"+schedule['id']+"','"+first_run+"','"+first_delivery+"')") and contacts()==before_contacts
 finish_worker('replacement-worker-projection-fault',expected=1,timeout=80);recorded_sql('drop-run-projection-failure',f'DROP TRIGGER {projection_fault} ON workflow_runs;DROP FUNCTION {projection_fault}()');first_done=post('resumed-first-run','/workflow-runs/'+first_run,method='GET');assert first_done['observed_state']=='succeeded';resumed=invoke('resumed-first-intent','delivery-status','--delivery-id',first_delivery,token=owner);assert resumed['attempts']==2 and resumed['fence']==2 and partial.read_bytes()==alpha_data;receive('alpha-exact',first_done,alpha_data)
 beta_run=sql("SELECT run_id FROM workflow_schedule_inputs WHERE file_id='"+beta['id']+"'");beta_done=post('beta-receipts-before-projection-repair','/workflow-runs/'+beta_run,method='GET');assert beta_done['observed_state']=='succeeded' and sql("SELECT state FROM workflow_runs WHERE run_id='"+beta_run+"'")!='succeeded';receive('beta-exact',beta_done,beta_data)
 before_contacts=contacts();start_worker('metadata-projection-repair-worker',schedule,polls=1);finish_worker('metadata-projection-repair-worker');assert sql("SELECT state FROM workflow_runs WHERE run_id='"+beta_run+"'")=='succeeded' and contacts()==before_contacts
 repaired=post('projection-repair-api-original-key','/workflow-runs/'+beta_run+'/refresh',key='schedule-project:'+beta_run);assert repaired['replayed'] and repaired['resource']['status']['observed_state']=='succeeded';assert invoke('projection-repair-cli-original-key','workflow-refresh','--run-id',beta_run,'--idempotency-key','schedule-project:'+beta_run,token=owner)['resource']==repaired['resource'] and contacts()==before_contacts
 post('drain-empty-catchup','/workflow-schedules/'+schedule['id']+'/1/tick',{'limit':4},key='drain-empty-catchup')
 wait_sql("SELECT lease_until<=clock_timestamp() FROM delivery_intents WHERE delivery_id='"+u_delivery+"'")
 invoke('expired-uncertain-sender-refused','delivery-work','--delivery-id',u_delivery,token=owner,expected=1);stop('receiver');start('receiver',['/usr/sbin/sshd','-D','-e','-f',read_conf],receiver_port);wire=sha(u_target);reconciled=invoke('expired-schedule-readonly-reconcile','delivery-reconcile','--delivery-id',u_delivery,token=owner);assert reconciled['state']=='succeeded' and reconciled['attempts']==1 and reconciled['fence']==published['fence'] and reconciled['observation']['reconciled'] and reconciled['observation']['business_acceptance']=='unknown' and sha(u_target)==wire
 readonly_status={'steps':[{'state':'succeeded','delivery_id':u_delivery}]};receive('uncertain-readonly-exact',readonly_status,uncertain_data);stop('receiver');start('receiver',['/usr/sbin/sshd','-D','-e','-f',send_conf],receiver_port)
 gamma,gamma_data=accept('gamma','settlement-c.csv');wait_sql('SELECT clock_timestamp()>='+sql_string(utc(base+50))+'::timestamptz',timeout=70);live=post('main-live-for-browser','/workflow-schedules/'+schedule['id']+'/1',method='GET')['schedule'];worked_ui=browser('work',schedule=live);gamma_run=worked_ui['tick']['run_ids'][0];gamma_done=post('gamma-browser-complete','/workflow-runs/'+gamma_run,method='GET');assert gamma_done['observed_state']=='succeeded' and gamma_done['run']['file_id']==gamma['id'];receive('gamma-exact',gamma_done,gamma_data);live=post('main-live-for-suspension','/workflow-schedules/'+schedule['id']+'/1',method='GET')['schedule'];browser('suspend',schedule=live)
 # A live transfer crosses its cutoff while SQL pauses publication. Its safe
 # failure journal must remain writable, without authorizing the final rename.
 cutoff_file,cutoff_data=accept('cutoff','cutoff.csv');cutoff,when=api_schedule('Live cutoff','cutoff.csv',2);wait_sql('SELECT clock_timestamp()>='+sql_string(utc(when))+'::timestamptz');cutoff_tick=post('live-cutoff-queue','/workflow-schedules/'+cutoff['id']+'/1/tick',{'limit':1},key='cutoff-queue')['resource'];cutoff_status=post('live-cutoff-status','/workflow-runs/'+cutoff_tick['run_ids'][0],method='GET');cutoff_delivery=cutoff_status['steps'][0]['delivery_id'];pause='freightctl_cutoff_pause_'+uuid.uuid4().hex
 recorded_sql('install-cutoff-publication-pause',f"CREATE FUNCTION {pause}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='{cutoff_delivery}' AND NEW.state='publishing' THEN PERFORM pg_sleep(3);END IF;RETURN NEW;END $$;CREATE TRIGGER {pause} BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION {pause}()")
 invoke('live-cutoff-worker','delivery-work','--delivery-id',cutoff_delivery,token=owner,expected=1);recorded_sql('drop-cutoff-publication-pause',f'DROP TRIGGER {pause} ON delivery_intents;DROP FUNCTION {pause}()');cutoff_result=invoke('live-cutoff-recorded-failure','delivery-status','--delivery-id',cutoff_delivery,token=owner);assert cutoff_result['state']=='retry' and cutoff_result['attempts']==1 and not (inbox/(cutoff_delivery+'-first.csv')).exists();before_contacts=contacts();invoke('live-cutoff-cannot-resend','delivery-work','--delivery-id',cutoff_delivery,token=owner,expected=1);assert contacts()==before_contacts
 # An expired due occurrence cannot acquire a file at all.
 expired,expired_data=accept('expired','expired.csv');expired_schedule,_=api_schedule('Expired occurrence','expired.csv',1,due=int(time.time())-5);expired_tick=post('expired-admission','/workflow-schedules/'+expired_schedule['id']+'/1/tick',{'limit':1},key='expired-admission')['resource'];assert expired_tick['occurrences'][0]['kind']=='missed' and not expired_tick['run_ids']
 # Global exact-file review remains cumulative with autonomous schedule approval.
 review_file,review_data=accept('review','review.csv');post('enable-independent-dispatch','/outbound-dispatch-policy',{'expected_revision':0,'mode':'independent'},key='independent-dispatch');review_schedule,when=api_schedule('Independent dispatch','review.csv',60);wait_sql('SELECT clock_timestamp()>='+sql_string(utc(when))+'::timestamptz');review_tick=post('review-required-admission','/workflow-schedules/'+review_schedule['id']+'/1/tick',{'limit':1},key='review-required-admission')['resource'];review_run=review_tick['run_ids'][0];before_contacts=contacts();start_worker('waiting-independent-review-worker',review_schedule,polls=2);finish_worker('waiting-independent-review-worker');held=post('review-held-no-attempt','/workflow-runs/'+review_run,method='GET');assert all(s['attempts']==0 for s in held['steps']) and contacts()==before_contacts;reviewer=invoke('reviewer-identity','identity',token=viewer)['actor_id']
 for index in range(2):
  status=post('review-step-'+str(index)+'-status','/workflow-runs/'+review_run,method='GET');delivery_id=status['steps'][index]['delivery_id'];v=post('review-step-'+str(index)+'-delivery','/outbound-deliveries/'+delivery_id,method='GET');x={'delivery_id':delivery_id,'reviewer_id':reviewer,**decision(v)};p=post('review-step-'+str(index)+'-preview','/outbound-dispatch-reviews/preview',x);review=post('review-step-'+str(index)+'-propose','/outbound-dispatch-reviews',{'selection':x,'definition_hash':p['definition_hash']},key='review-step-'+str(index))['resource']['review'];post('review-step-'+str(index)+'-approve','/outbound-dispatch-reviews/'+review['id']+'/approve',decision(review),key='review-step-'+str(index)+'-approve',who=viewer_header);start_worker('approved-step-'+str(index)+'-worker',review_schedule,polls=1);finish_worker('approved-step-'+str(index)+'-worker')
 reviewed=post('independently-approved-schedule-complete','/workflow-runs/'+review_run,method='GET');assert reviewed['observed_state']=='succeeded';receive('review-exact',reviewed,review_data)
 post('reviewer-original-source-denied','/files/'+review_file['id'],who=viewer_header,method='GET',expected=403);post('reviewer-original-schedule-denied','/workflow-schedules/'+review_schedule['id']+'/1',who=viewer_header,method='GET',expected=404)
 result={'state':'passed','ordered_steps':2,'original_worker_killed_before_publication':True,'original_publication_barrier_seconds':8,'original_lease_seconds':30,'staging_resume_attempts':resumed['attempts'],'staging_resume_fence':resumed['fence'],'old_partial_preserved':True,'repeated_distinct_inputs_claimed_once':True,'projection_failure_repaired_without_receiver_contact':True,'expired_schedule_readonly_receipt_under_stock_readonly_server':True,'read_only_reconciliation_business_acceptance':'unknown','browser_draft_activation_queue_ordered_steps_suspension_original_key_recovery':True,'live_cutoff_safe_failure_recorded_and_final_not_published':True,'expired_occurrence_consumed_no_input':True,'independent_dispatch_review_remains_cumulative':True,'independently_retrieved_sources':['alpha','beta','gamma','uncertain','review'],'full_journeys_qualified':False,'inference_performed':False,'scanner_engine_started':False}
 (raw/'schedule-result.json').write_text(json.dumps(result,indent=2)+'\n');state='passed'
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
 manifest={'schema_version':1,'state':state if unchanged and not cleanup and not output_failure else 'failed','failure':failure,'output_closure_failure':output_failure,'output_artifacts_verified':output_files,'cleanup_failures':cleanup,'observed_at':datetime.now(timezone.utc).isoformat(),'postgres_container_id':pg,'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_sha256':initial,'sources_unchanged_during_run':unchanged,'changed_source_paths':[p for p in set(initial)|set(final) if initial.get(p)!=final.get(p)],'binary_sha256':sha(binary) if binary.exists() else None,'private_reference':str(private.relative_to(root)),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'isolated_database_removed':created and not cleanup,'inference_performed':False,'scanner_engine_started':False,'full_journeys_qualified':False,'limits':['Assisted same-host selected outbound SFTP schedules; full J03, independent operators, collection, trigger breadth and production remain open.','Live real clock execution plus pure historical clock-change checks; no host-clock adjustment or live DST boundary claim.','No business acceptance, exactly-once downstream effect or directory power-loss durability claim.','No full core aggregate; F026 replay remains owner-deferred.','Only exact task PostgreSQL, loopback HTTPS/stock SFTP and bounded Go/Node; no model/scanner or shared Docker lifecycle operation.']}
 (raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(str(raw/'manifest.json'),flush=True)
 if failure:print(failure,flush=True)
 if output_failure:print(output_failure,flush=True)
if manifest['state']!='passed':raise SystemExit(1)
