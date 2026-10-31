"""Real read-only receipt recovery after rotated trust; parent-owned peers only."""
import json, os, signal, subprocess, time
from pathlib import Path


def qualify_observations(c,h,prepared):
    post,invoke,write,command=(h[x] for x in ('post','invoke','write','command'))
    raw,private,inbox=c['raw'],c['private'],c['inbox']
    original=prepared['uncertain'];delivery=prepared['uncertain_id'];wire=prepared['uncertain_ciphertext'];final=inbox/(delivery+'-handoff-data.bin')
    selection={'source_run_id':original['run']['id'],'source_hash':original['dispatch']['definition_hash'],'probe_id':h['p']['id'],'file_id':h['child']['id'],'expected_authority_revision':2}
    before_events=c['sql']("SELECT count(*) FROM events WHERE resource_id IN ('"+original['run']['id']+"','"+delivery+"')")
    contacts=lambda:(raw/'receiver.log').read_text().count('Accepted publickey for ')
    files=lambda:{p.name:c['sha'](p) for p in sorted(inbox.iterdir())}
    before_contacts,before_files=contacts(),files()
    preview=post('observation-current-preview','/onboarding-observations/preview',selection)
    assert not preview['external_contact'] and not preview['resend_authorized'] and preview['definition']['wire']['sha256']==wire['sha256'] and preview['definition']['wire']['ciphertext']['object_id']==wire['object_id']
    assert preview['definition']['original_connection']['id']==h['connection_b']['id'] and preview['definition']['observer']['connection']['version']==2 and preview['definition']['source']['state']=='publishing'
    assert invoke('observation-cli-preview','partner-onboarding-observation-preview','--request-file',write('observation-selection',selection),token=h['owner'])==preview
    assert contacts()==before_contacts and files()==before_files
    browser_raw=raw/'observation-browser';browser_raw.mkdir(mode=0o700)
    cfg=dict(c['cfg'],raw=str(browser_raw),receiver_log=str(raw/'receiver.log'),plan=h['plan'],test_only=False,release_only=False,handoff_only=False,observation_only=True,observation_selection=selection,observation_hash=preview['definition_hash'],observation_path=str(final),observation_wire=preview['definition']['wire'],observer_host=h['connection_b']['host_fingerprint'],original_recipient=h['old_recipient']['fingerprint'],original_release=h['release'],observation_contacts_before=before_contacts,observation_files_before=before_files)
    command('native-browser-receipt-observation',[c['node'],'scripts/onboarding-exchange-browser.mjs',write('observation-browser',cfg)],timeout=180)
    browser=json.loads((browser_raw/'onboarding-observation-browser-result.json').read_text());assert browser['state']=='passed';observed=browser['observation']
    status=post('observation-original-outcome','/onboarding-production/'+original['run']['id'],method='GET')
    assert status['dispatch']==original['dispatch'] and status['status']['steps'][0]['state']=='publishing' and status['transport_outcome']['state']=='integrity_confirmed' and status['transport_outcome']['observation']['id']==observed['id'] and not status['current_bindings']
    assert status['transport_outcome']['observation']['result']['business_acceptance']=='unknown' and not status['transport_outcome']['observation']['result']['file_fsync_acknowledged']
    # Independent current SSH authentication retrieves the original ciphertext;
    # only the isolated receiver fixture uses its historical private recipient.
    received=private/'observation-original-received.pgp';batch=private/'observation-receive.batch';batch.write_text(f'get {final} {received}\n')
    command('observation-independent-stock-sftp',['sftp','-F','/dev/null','-P',str(c['receiver_port']),'-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+str(c['known']),'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',private/'handoff-client-b','-b',batch,c['user']+'@127.0.0.1']);assert c['sha'](received)==wire['sha256']
    plain=private/'observation-original-plaintext.csv';proof=command('observation-independent-original-decrypt',['python3','scripts/pgp-native-peer.py','--config',c['native_config'],'--metrics',raw/'observation-original-decryption.json','decrypt','--key',c['fixture']/'recipient-private.gpg','--cipher',received,'--output',plain]);assert plain.read_bytes()==c['data'] and b'GOODMDC' in proof and b'DECRYPTION_OKAY' in proof

    def approved(label):
        p=post(label+'-preview','/onboarding-observations/preview',selection)
        o=post(label+'-propose','/onboarding-observations',{'definition':p['definition']},key=label+'-propose')['resource']['observation']
        o=post(label+'-approve','/onboarding-observations/'+o['id']+'/approve',h['decision'](o),key=label+'-approve')['resource']['observation']
        return o
    def work(label,o,key=None):return post(label,'/onboarding-observations/'+o['id']+'/work',{'definition_hash':o['definition_hash']},key=key or label)
    negative=[]
    backup=private/'observation-original-final.backup';original_bytes=final.read_bytes();backup.write_bytes(original_bytes)
    for label in ['missing','changed','symlink']:
        o=approved('observation-'+label)
        try:
            final.unlink()
            if label=='changed':final.write_bytes(bytes([original_bytes[0]^1])+original_bytes[1:])
            elif label=='symlink':final.symlink_to(backup)
            result=work('observation-'+label+'-work',o);assert result['observation']['state']=='unconfirmed' and not result['observation']['result']['integrity_confirmed'] and not result['resend_authorized']
            before=contacts();replay=work('observation-'+label+'-work-replay',o,key='observation-'+label+'-work');assert replay['observation']==result['observation'] and not replay['contact_attempted'] and contacts()==before
            negative.append(label)
        finally:
            if final.is_symlink() or final.exists():final.unlink()
            final.write_bytes(original_bytes);final.chmod(0o600)
    assert files()==before_files

    lost=approved('observation-lost-worker')
    c['sql']("CREATE FUNCTION freightctl_observation_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.observation_id='"+lost['id']+"' AND NEW.state='succeeded' THEN PERFORM pg_sleep(8);END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_observation_barrier BEFORE UPDATE ON onboarding_observations FOR EACH ROW EXECUTE FUNCTION freightctl_observation_barrier()")
    args=[c['binary'],'partner-onboarding-observation-work','--dsn-file',c['runtime'],'--tenant',c['tenant'],'--partner',c['partner'],'--storage',c['storage'],'--token-file',h['owner'],'--onboarding-observation-id',lost['id'],'--request-file',write('observation-lost-worker-work',{'definition_hash':lost['definition_hash']}),'--idempotency-key','observation-killed-worker']
    c['reserve_step']('observation-killed-worker')
    out,err=raw/'observation-killed-worker.stdout',raw/'observation-killed-worker.stderr';started=time.monotonic()
    with out.open('wb') as stdout,err.open('wb') as stderr:
        child=subprocess.Popen(list(map(str,args)),stdout=stdout,stderr=stderr,env=c['env'],start_new_session=True);c['servers']['observation-worker']=child;deadline=time.monotonic()+12
        while c['sql']("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='freightctl' AND wait_event='PgSleep' AND query LIKE 'UPDATE onboarding_observations%')")!='t':
            assert child.poll() is None and time.monotonic()<deadline,'observation worker did not reach its exact result transaction boundary';time.sleep(.03)
        os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5);assert child.returncode==-signal.SIGKILL;c['servers'].pop('observation-worker')
    c['steps'].append({'name':'observation-killed-worker','command':list(map(str,args)),'exit_code':child.returncode,'expected_exit_code':-signal.SIGKILL,'duration_seconds':round(time.monotonic()-started,3),'stdout_sha256':c['sha'](out),'stderr_sha256':c['sha'](err)})
    c['sql']('DROP TRIGGER freightctl_observation_barrier ON onboarding_observations;DROP FUNCTION freightctl_observation_barrier()')
    current=post('observation-lost-worker-status','/onboarding-observations/'+lost['id'],method='GET');assert current['observation']['state']=='running'
    deadline=time.monotonic()+35
    while c['sql']("SELECT lease_until<=clock_timestamp() FROM onboarding_observations WHERE observation_id='"+lost['id']+"'")!='t':
        assert time.monotonic()<deadline,'original observation lease did not expire';time.sleep(.1)
    before=contacts();expired=post('observation-expired-worker-recovery','/onboarding-observations/'+lost['id']+'/work',{'definition_hash':lost['definition_hash']},key='observation-killed-worker');assert expired['observation']['state']=='expired' and not expired['contact_attempted'] and contacts()==before
    revoked=approved('observation-revoked-observer');post('observation-revoke-current-connection','/connections/'+h['connection_b']['id']+'/2/revoke',h['decision'](h['connection_b']),key='observation-revoke-current-connection')
    before=contacts();blocked=work('observation-revoked-work',revoked);assert blocked['observation']['state']=='blocked' and not blocked['contact_attempted'] and contacts()==before
    assert files()==before_files and c['sql']("SELECT count(*) FROM events WHERE resource_id IN ('"+original['run']['id']+"','"+delivery+"')")==before_events
    # Restart only this exact loopback application process; historical receipt
    # evidence remains readable even after the observing connection is revoked.
    c['stop']('https');c['start']('https',c['server_args'],c['http_port'])
    recovered=invoke('observation-cli-after-restart','partner-onboarding-observation-status','--onboarding-observation-id',observed['id'],token=h['owner']);assert recovered['observation']==observed and not recovered['resend_authorized']
    history=invoke('observation-cli-private-history','partner-onboarding-observation-list','--onboarding-id',h['plan']['id'],token=h['owner']);assert len(history['observations'])==6
    other_header=private/'observation-other.headers';other_header.write_bytes(b'Authorization: Bearer '+c['other'].read_bytes()+b'\n')
    post('observation-other-actor-refused','/onboarding-observations/'+observed['id'],method='GET',who=other_header,expected=404)
    final_status=post('observation-final-original-outcome','/onboarding-production/'+original['run']['id'],method='GET');assert final_status['transport_outcome']['observation']['id']==observed['id'] and final_status['status']['steps'][0]['state']=='publishing'
    (raw/'onboarding-observation-result.json').write_text(json.dumps({'state':'passed','original_run_id':original['run']['id'],'observation_id':observed['id'],'original_wire':preview['definition']['wire'],'source_events_unchanged':True,'receiver_files_and_bytes_unchanged':True,'original_execution_still_blocked':True,'strongest_receipt':'point-in-time exact original wire integrity','business_acceptance':'unknown','negative_remote_cases':negative,'actual_observer_worker_killed':True,'original_observer_lease_retained':True,'expired_replay_made_no_contact':True,'revoked_observer_made_no_contact':True,'restart_and_private_history':True,'inference_performed':False,'scanner_started':False},indent=2)+'\n')
