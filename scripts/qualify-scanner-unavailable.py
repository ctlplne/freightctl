#!/usr/bin/env python3
"""Real CLI/HTTPS outage gate only; no scanner engine or malware qualification."""
import hashlib
from datetime import datetime, timezone, timedelta
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid
from urllib.parse import urlencode

os.umask(0o077)
root = Path(__file__).resolve().parents[1]
os.chdir(root)
run_id = "scanner-unavailable-" + uuid.uuid4().hex
private = root / ".private" / run_id
private.mkdir(mode=0o700)
raw = root / "evidence/raw" / run_id
raw.mkdir(parents=True, mode=0o700)
binary = root / ".cache/freightctl"
started = time.monotonic()
steps = []
server = None
log = None
upload_client = None

def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, **kwargs)
    if result.returncode:
        # Commands contain only secret references; curl never runs verbose.
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {result.stderr.decode(errors='replace')[:1000]}")
    return result.stdout

def cli(*args):
    return command([str(binary), *args])

def stop():
    global server, log
    if server is not None:
        server.terminate()
        try:
            server.wait(timeout=8)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        server = None
    if log is not None:
        log.close()
        log = None

try:
    command(["sh", "scripts/go.sh", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/freightctl"])
    cli("init")
    cert, key = private / "localhost.crt", private / "localhost.key"
    cli("dev-cert", "--cert", str(cert), "--key", str(key))
    audit_key, audit_public = private / "audit.key", private / "audit.pub"
    cli("audit-keygen", "--audit-key-file", str(audit_key), "--audit-public-file", str(audit_public))
    tenant, partner = str(uuid.uuid4()), str(uuid.uuid4())
    other_tenant, other_partner = str(uuid.uuid4()), str(uuid.uuid4())
    identities = [(tenant, partner), (tenant, other_partner), (other_tenant, partner)]
    headers = []
    for index, (tid, pid) in enumerate(identities):
        token = private / f"identity-{index}.token"
        cli("token", "--token-file", str(token))
        cli("enroll", "--tenant", tid, "--partner", pid, "--token-file", str(token))
        header = private / f"identity-{index}.headers"
        header.write_bytes(b"Authorization: Bearer " + token.read_bytes() + b"\n")
        headers.append(header)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"https://127.0.0.1:{port}"
    api = base + f"/v1/tenants/{tenant}/partners/{partner}"
    storage = private / "custody"
    def start():
        global server, log
        log = (raw / "server.log").open("ab")
        server = subprocess.Popen([str(binary), "serve", "--listen", f"127.0.0.1:{port}", "--storage", str(storage), "--cert", str(cert), "--key", str(key), "--audit-key-file", str(audit_key)], stdout=log, stderr=log)
        for attempt in range(100):
            if server.poll() is not None:
                raise RuntimeError("server exited; inspect retained server.log")
            result = subprocess.run(["curl", "--silent", "--show-error", "--cacert", str(cert), "--max-time", "1", base + "/healthz"], capture_output=True)
            if result.returncode == 0:
                return
            time.sleep(0.05)
        raise RuntimeError("HTTPS health request failed: " + result.stderr.decode(errors="replace")[:1000])
    def curl(label, url, expected, identity=0, extra=()):
        output = raw / (label + ".out")
        args = ["curl", "--silent", "--show-error", "--cacert", str(cert), "--max-time", "15", "--output", str(output), "--write-out", "%{http_code}"]
        if identity is not None:
            args += ["--header", "@" + str(headers[identity])]
        args += list(extra) + [url]
        status = int(command(args).decode())
        if status != expected:
            raise RuntimeError(f"{label}: expected HTTP {expected}, got {status}; see {output.name}")
        steps.append({"name": label, "http_status": status, "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest()})
        return output
    start()
    # A task-owned strict configuration with an intentionally absent socket.
    # The expected version is synthetic metadata, never an observed engine.
    import tempfile
    from datetime import datetime,timezone,timedelta
    scan_dir=Path(tempfile.mkdtemp(prefix="freightctl-scan-offline-",dir="/private/tmp"))
    for name in ("db","tmp"):(scan_dir/name).mkdir(mode=0o700)
    scan_socket=scan_dir/'s';scan_config=scan_dir/'clamd.conf'
    scan_config.write_text(f"Foreground yes\nLocalSocket {scan_socket}\nLocalSocketMode 600\nDatabaseDirectory {scan_dir/'db'}\nTemporaryDirectory {scan_dir/'tmp'}\nMaxThreads 1\nMaxQueue 2\nStreamMaxLength 8388608\nMaxFileSize 8388608\nMaxScanSize 16777216\nMaxRecursion 4\nMaxFiles 100\nMaxScanTime 1000\nReadTimeout 2\nCommandReadTimeout 2\nSendBufTimeout 1000\nScanArchive yes\nAlertExceedsMax yes\nAlertEncrypted yes\nOfficialDatabaseOnly yes\nBytecode yes\nBytecodeSecurity TrustSigned\nConcurrentDatabaseReload no\nSelfCheck 0\nEnableVersionCommand yes\nEnableReloadCommand no\nEnableShutdownCommand no\nEnableStatsCommand no\n")
    now=datetime.now(timezone.utc)
    definition={'schema_version':1,'kind':'clamd-instream-v1','socket_reference':str(scan_socket),'configuration_reference':str(scan_config),'configuration_sha256':hashlib.sha256(scan_config.read_bytes()).hexdigest(),'expected_version':'ClamAV 1.5.4/30001/'+(now-timedelta(hours=1)).strftime('%a %b %d %H:%M:%S %Y'),'valid_until':(now+timedelta(hours=1)).isoformat(),'max_bytes':8<<20,'timeout_seconds':2,'max_result_age_seconds':600}
    request=private/'scanner.json';request.write_text(json.dumps({'expected_version':0,'definition':definition}))
    common=['--tenant',tenant,'--partner',partner,'--token-file',str(private/'identity-0.token'),'--storage',str(storage)]
    registered=json.loads(cli('scanner-register',*common,'--request-file',str(request),'--idempotency-key','scanner'))
    profile=registered['resource'];assert profile['state']=='active' and 'socket_reference' not in profile and 'configuration_reference' not in profile
    replay=json.loads(cli('scanner-register',*common,'--request-file',str(request),'--idempotency-key','scanner'));assert replay['replayed'] and replay['resource']==profile
    steps.append({'name':'original-scanner-register-and-replay','scanner_state':'active configuration; availability unverified'})
    view=json.loads(curl('sanitized-scanner-status',api+'/scanners/'+profile['id']+'/1',200).read_text());assert view==profile
    for index,(tid,pid) in enumerate(identities[1:],1):
        curl('foreign-scanner-'+str(index),base+f'/v1/tenants/{tid}/partners/{pid}/scanners/'+profile['id']+'/1',404,identity=index)
    curl('HTTP-cannot-enroll-local-files',api+'/scanners/'+profile['id']+'/1',405,extra=['--request','POST','--data-binary','@'+str(request)])
    policy={'expected_version':0,'definition':{'schema_version':1,'kind':'csv','columns':[{'name':'account','type':'text','required':True,'max_bytes':64},{'name':'amount','type':'decimal','required':True,'max_bytes':64,'precision':12,'scale':2},{'name':'day','type':'date','required':True,'max_bytes':10}],'max_bytes':8<<20,'max_rows':100000,'max_record_bytes':65536,'timeout_seconds':30,'scanner':{'id':profile['id'],'version':1,'hash':profile['definition_hash']}}}
    policy_file=private/'policy.json';policy_file.write_text(json.dumps(policy))
    p=json.loads(curl('required-scanner-policy',api+'/intake-policy',200,extra=['--header','Idempotency-Key: policy','--request','POST','--data-binary','@'+str(policy_file)]).read_text())['resource']
    data=b'account,amount,day\n0001,1.01,2026-10-29\n';digest=hashlib.sha256(data).hexdigest();payload=private/'source.csv';payload.write_bytes(data)
    accepted=json.loads(curl('durable-held-intake',api+'/namespace/file?'+urlencode({'path':'/pending.csv'}),201,extra=['--request','PUT','--header','Idempotency-Key: file','--header','X-File-Size: '+str(len(data)),'--header','X-Content-SHA256: '+digest,'--data-binary','@'+str(payload)]).read_text())['file'];fid=accepted['id']
    curl('absent-scanner-raw-bytes-denied',api+'/files/'+fid,409)
    curl('absent-scanner-path-unpublished',api+'/namespace/file?'+urlencode({'path':'/pending.csv'}),404)
    first=json.loads(curl('unavailable-scan-attempt',api+'/checks/'+fid+'/run',200,extra=['--request','POST','--header','Idempotency-Key: scan']).read_text())
    current=json.loads(curl('unavailable-verdict-is-not-clean',api+'/checks/'+fid,200).read_text())['check'];assert current['state']=='failed' and current['code']=='scanner_unavailable' and current['report_hash']==''
    repeated=json.loads(curl('unavailable-attempt-replay',api+'/checks/'+fid+'/run',200,extra=['--request','POST','--header','Idempotency-Key: scan']).read_text());assert repeated['replayed'] and repeated['resource']==first['resource']
    decision=private/'release.json';decision.write_text(json.dumps({'sha256':digest,'policy_hash':p['definition_hash'],'report_hash':'0'*64,'expected_revision':current['revision']}))
    curl('unknown-scan-cannot-release',api+'/checks/'+fid+'/release',409,extra=['--request','POST','--header','Idempotency-Key: release','--data-binary','@'+str(decision)])
    stop();start()
    retained=json.loads(curl('unknown-scan-survives-restart',api+'/checks/'+fid,200).read_text())['check'];assert retained==current
    revoke=private/'revoke.json';revoke.write_text(json.dumps({'definition_hash':profile['definition_hash'],'expected_revision':profile['revision']}))
    result=json.loads(curl('revoke-scanner-profile',api+'/scanners/'+profile['id']+'/1/revoke',200,extra=['--request','POST','--header','Idempotency-Key: revoke','--data-binary','@'+str(revoke)]).read_text())['resource'];assert result['state']=='revoked'
    curl('revoked-scanner-still-denies-bytes',api+'/files/'+fid,409)
    history=json.loads(curl('revoked-scan-context-visible',api+'/checks/'+fid,200).read_text());assert not history['current']
    state='passed';failure=None
except Exception as err:
    import traceback
    state='failed';failure=traceback.format_exc()
finally:
    stop()
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
sources=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py') or p in ('go.mod','go.sum'))]
manifest={'schema_version':1,'state':state,'failure':failure,'observed_at':datetime.now(timezone.utc).isoformat(),'starting_commit':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_files':sources,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'duration_seconds':round(time.monotonic()-started,3),'steps':steps,'scanner_engine_started':False,'standard_signature_database_loaded':False,'malware_detection_qualified':False,'inference_performed':False,'local_model_processes_started':0,'retained_private_configuration':str(scan_dir.relative_to('/private/tmp')) if 'scan_dir' in globals() else None,'limits':['Real PostgreSQL, CLI, HTTPS and stock curl establish only failure-closed behavior with an intentionally absent scanner socket.','The expected engine/version metadata is synthetic. No ClamAV detector, official signature corpus or clean/infected classification is qualified.','No ICAP, application malware coverage, retrospective re-scan/rebind, native production platform, adoption or complete business-file journey is qualified.']}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(root/'.private/scanner-unavailable-current').write_text(str(raw)+'\n');print(str(raw/'manifest.json'),flush=True)
if failure:print(failure,flush=True)
raise SystemExit(0 if state=='passed' else 1)
