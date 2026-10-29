"""Native re-check extension; invoked by the real retained intake journey.

Uses that journey's task-owned HTTPS, PostgreSQL, storage and stock clients.
No inference, scanner runtime or shared service lifecycle operation.
"""
from pathlib import Path
import hashlib,json,os,signal,stat,subprocess,time,uuid

def qualify_rechecks(c):
 root,private,raw=c['root'],c['private'],c['raw']
 post,get,invoke,write,sql,args=(c[k] for k in ('post','get','invoke','write','sql','args'))
 source=c['held'];tenant,partner=c['tenant'],c['partner'];storage=c['storage'];steps=c['steps']
 before=get('recheck-original-snapshot','/checks/'+source['id'])['check']
 options={'target_path':'/from-https.csv','signature_mode':'not_required','reason':'Re-check exact retained bytes under the reviewed current policy'}
 preview=post('recheck-preview-current-policy','/checks/'+source['id']+'/recheck-preview',options)
 assert preview['plan']['policy']['hash']==c['policy']['definition_hash']
 assert preview['previous_policy']['state']=='retired'
 route='/checks/'+source['id']+'/rechecks'
 post('recheck-reject-execution-field',route,dict(plan=preview['plan'],force_clean=True),400,key='bad-recheck')
 post('recheck-reject-foreign-source','/checks/'+str(uuid.uuid4())+'/rechecks',{'plan':preview['plan']},400,key='foreign-path')
 post('recheck-reject-foreign-actor','/checks/'+source['id']+'/recheck-preview',options,404,who=c['other_header'])
 post('recheck-reject-old-grants','/checks/'+source['id']+'/recheck-preview',options,403,who=c['old_header'])
 def propose(label):
  value=invoke(label,'check-recheck-propose','--file-id',source['id'],'--request-file',write(label,{'plan':preview['plan']}),'--idempotency-key',label)
  row=value['resource']['recheck']
  repeated=post(label+'-replay',route,{'plan':preview['plan']},key=label)
  assert repeated['replayed'] and repeated['resource']==value['resource']
  return row
 def approve(label,row):
  decision={'operation':'approve','definition_hash':row['definition_hash'],'expected_revision':row['revision']}
  value=post(label,'/rechecks/'+row['id']+'/decide',decision,key=label)
  repeated=post(label+'-lost-response-replay','/rechecks/'+row['id']+'/decide',decision,key=label)
  assert repeated['replayed'] and repeated['resource']==value['resource']
  return value['resource']['recheck']
 row=propose('recheck-native-propose')
 post('recheck-copy-needs-separate-approval','/rechecks/'+row['id']+'/copy',expected=409,key='unapproved')
 row=approve('recheck-native-approve',row)
 post('recheck-copy-refuses-body','/rechecks/'+row['id']+'/copy',{},400,key='body')
 # Kill the actual CLI while its exclusive 0600 partial object is observable.
 def name(fid):return storage/(tenant+'_'+partner+'_'+fid)
 def kill_copy(label,row,boundary):
  out=(raw/(label+'.stdout')).open('wb');err=(raw/(label+'.stderr')).open('wb')
  child=subprocess.Popen(args('check-recheck-copy','--recheck-id',row['id'],'--idempotency-key',label),stdout=out,stderr=err)
  c['children'].append(child);observed=None;start=time.monotonic()
  try:
   while child.poll() is None and time.monotonic()-start<15:
    for slot in row['definition']['staging_slots']:
     try:st=name(slot['file_id']).stat()
     except FileNotFoundError:continue
     if boundary(st):
      os.kill(child.pid,signal.SIGSTOP)
      observed={'file_id':slot['file_id'],'bytes':st.st_size,'mode':oct(stat.S_IMODE(st.st_mode))}
      os.kill(child.pid,signal.SIGKILL);child.wait(timeout=5);break
    if observed:break
    time.sleep(.002)
   assert observed is not None,'actual copy boundary was not observed'
   assert child.returncode==-signal.SIGKILL
   steps.append({'name':label,'worker_exit':child.returncode,'observed':observed})
   return observed
  finally:
   if child.poll() is None:child.kill();child.wait(timeout=5)
   out.close();err.close()
 partial=kill_copy('recheck-actual-kill-during-copy',row,lambda st:stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<source['size_bytes'])
 partial_hash=hashlib.sha256(name(partial['file_id']).read_bytes()).hexdigest()
 copied=invoke('recheck-original-key-after-kill','check-recheck-copy','--recheck-id',row['id'],'--idempotency-key','recheck-actual-kill-during-copy')
 child=copied['resource']['recheck']['new_file_id']
 assert child!=partial['file_id']
 assert hashlib.sha256(name(partial['file_id']).read_bytes()).hexdigest()==partial_hash
 repeated=post('recheck-copy-exact-receipt-replay','/rechecks/'+row['id']+'/copy',key='recheck-actual-kill-during-copy')
 assert repeated['replayed'] and repeated['resource']==copied['resource']
 get('recheck-child-is-held','/files/'+child,expected=409)
 assert get('recheck-child-fresh-attempt-budget','/checks/'+child)['check']['attempts']==0
 # Delay only this approved slot's SQL insert, after real chmod/file/dir sync.
 # The published ten-second statement timeout and all product budgets remain.
 orphan=approve('recheck-orphan-approve',propose('recheck-orphan-propose'))
 first=orphan['definition']['staging_slots'][0]['file_id']
 trigger='freightctl_test_recheck_'+uuid.uuid4().hex
 sql(f"CREATE FUNCTION {trigger}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}' AND NEW.file_id='{first}' THEN PERFORM pg_sleep(8); END IF;RETURN NEW;END $$;CREATE TRIGGER {trigger} BEFORE INSERT ON files FOR EACH ROW EXECUTE FUNCTION {trigger}()")
 try:
  synced=kill_copy('recheck-actual-kill-after-sync',orphan,lambda st:stat.S_IMODE(st.st_mode)==0o400 and st.st_size==source['size_bytes'])
  assert synced['file_id']==first
 finally:sql(f'DROP TRIGGER {trigger} ON files;DROP FUNCTION {trigger}()')
 assert sql(f"SELECT count(*) FROM files WHERE tenant_id='{tenant}' AND file_id='{first}'").strip()==b'0'
 recovered=invoke('recheck-adopt-approved-synced-object','check-recheck-copy','--recheck-id',orphan['id'],'--idempotency-key','recheck-actual-kill-after-sync')['resource']['recheck']
 assert recovered['new_file_id']==first
 assert get('recheck-source-evidence-still-identical','/checks/'+source['id'])['check']==before
 assert name(first).read_bytes()==c['data']
 # Original queued workflow remains bound to the retired original file.
 get('recheck-original-queued-workflow-policy-blocked','/workflow-runs/'+c['queued_recheck_run']['id'],expected=409)
 assert sql(f"SELECT file_id::text FROM workflow_runs WHERE tenant_id='{tenant}' AND partner_id='{partner}' AND run_id='{c['queued_recheck_run']['id']}'").strip().decode()==source['id']
 post('recheck-does-not-redirect-original-job','/workflow-runs/'+c['queued_recheck_run']['id']+'/work',expected=409,key='do-not-redirect')
 # Browser review, real response loss, private history/reload and fresh checks.
 config={'root':str(root),'private':str(private),'raw':str(raw),'url':f"https://127.0.0.1:{c['http_port']}",'certificate':str(c['cert']),'tenant':tenant,'partner':partner,'token':str(c['owner']),'source':source['id'],'target':'/from-https.csv'}
 config_path=write('rechecks-browser-config',config)
 result=subprocess.run(['node','scripts/rechecks-browser.mjs',str(config_path)],capture_output=True,timeout=180)
 (raw/'rechecks-browser.stdout').write_bytes(result.stdout);(raw/'rechecks-browser.stderr').write_bytes(result.stderr)
 steps.append({'name':'rechecks-native-browser','exit_code':result.returncode,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()})
 assert result.returncode==0,'native browser re-check journey failed; inspect retained output'
 browser=json.loads((raw/'rechecks-browser.json').read_text())
 assert browser['state']=='passed'
 browser_child=browser['new_file_id']
 assert name(browser_child).read_bytes()==c['data']
 # Exact independent stock-curl retrieval follows the ordinary check/release.
 downloaded=raw/'recheck-released-bytes.out'
 command=c['command']
 command(['curl','--silent','--show-error','--fail','--cacert',str(c['cert']),'--header','@'+str(c['header']),'--output',str(downloaded),f"https://127.0.0.1:{c['http_port']}/v1/tenants/{tenant}/partners/{partner}/files/"+browser_child])
 assert downloaded.read_bytes()==c['data']
 steps.append({'name':'recheck-stock-curl-exact-released-bytes','size_bytes':downloaded.stat().st_size,'sha256':hashlib.sha256(downloaded.read_bytes()).hexdigest()})
 assert get('recheck-final-original-evidence','/checks/'+source['id'])['check']==before
