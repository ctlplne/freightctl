#!/usr/bin/env python3
"""Retain native foundation checks and exact input hashes; no readiness inferred."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import time
import uuid
os.umask(0o077)
root=Path(__file__).resolve().parents[1]
os.chdir(root)
raw=root/'evidence/raw'/('foundation-'+uuid.uuid4().hex)
raw.mkdir(parents=True,mode=0o700)
def source_hashes():
    paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
    return {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in sorted(set(paths)) if p and ((root/p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p in ('go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'))}
starting_sources=source_hashes()
env=dict(os.environ,GOMAXPROCS='1',NODE_OPTIONS='--max-old-space-size=192')
commands=[
('records',['python3','scripts/check-records.py']),
('frontend-evidence-contract',['npm','--prefix','web','test']),
('frontend-typecheck',['npm','--prefix','web','run','typecheck']),
('browser-artifact-integrity',['npm','--prefix','web','run','check-built']),
('module-integrity',['sh','scripts/go.sh','mod','verify']),
('vet',['sh','scripts/go.sh','vet','-p','1','./...']),
('unit-race',['sh','scripts/go.sh','test','-p','1','-race','./...']),
('postgres-integration-race',['sh','scripts/integration.sh','-p','1','-race','-v']),
('virtual-path-fuzz',['sh','scripts/go.sh','test','./internal/vpath','-fuzz=FuzzCanonicalPath','-fuzztime=5s','-parallel=2']),
('sftp-packet-fuzz',['sh','scripts/go.sh','test','./internal/sftpd','-fuzz=FuzzInspectPacket','-fuzztime=5s','-parallel=2']),
('custody-name-fuzz',['sh','scripts/go.sh','test','./internal/custody','-fuzz=FuzzCustodyName','-fuzztime=5s','-parallel=2']),
('typed-workflow-fuzz',['sh','scripts/go.sh','test','./internal/workflow','-fuzz=FuzzTypedWorkflow','-fuzztime=5s','-parallel=2']),
('csv-contract-fuzz',['sh','scripts/go.sh','test','./internal/checks','-fuzz=FuzzCSVContract','-fuzztime=5s','-parallel=1']),
('scanner-record-fuzz',['sh','scripts/go.sh','test','./internal/scanner','-fuzz=FuzzClamdRecordAndVersion','-fuzztime=5s','-parallel=1']),
('openpgp-admission-fuzz',['sh','scripts/go.sh','test','./internal/crypto','-fuzz=FuzzPGPAdmission','-fuzztime=5s','-parallel=1']),
('untrusted-model-output-fuzz',['sh','scripts/go.sh','test','./internal/assistance','-fuzz=FuzzUntrustedModelOutput','-fuzztime=5s','-parallel=1']),
('first-run-enrollment',['python3','scripts/qualify-setup.py']),
('stock-curl-https',['python3','scripts/qualify-https.py']),
('stock-openssh-sftp',['python3','scripts/qualify-sftp.py']),
('durable-upload-resume',['python3','scripts/qualify-uploads.py']),
('durable-outbound-delivery',['python3','scripts/qualify-deliveries.py']),
('versioned-workflow-execution',['python3','scripts/qualify-workflows.py']),
('assistance-control-contract-no-inference',['python3','scripts/qualify-assistance.py']),
('held-intake-and-csv-checks',['python3','scripts/qualify-intake.py']),
('scanner-outage-controls-no-engine',['python3','scripts/qualify-scanner-unavailable.py']),
('native-browser-exchange',['python3','scripts/qualify-browser.py']),
('native-signed-browser-exchange',['python3','scripts/qualify-browser.py','--signed']),
('native-browser-worker-recovery',['python3','scripts/qualify-browser-recovery.py']),
('signed-intake-openpgp',['python3','scripts/qualify-pgp.py']),
('recipient-encrypted-delivery',['python3','scripts/qualify-encryption.py']),
]
if env.get('FREIGHTCTL_GNUPG_NATIVE_CONFIG'):
    commands.insert(1,('native-gnupg-peer-constraints',['python3','scripts/qualify-pgp-native.py']))
results=[]
for name,command in commands:
    start=time.monotonic()
    log=raw/(name+'.log')
    with log.open('wb') as output:
        result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,env=env)
    results.append({'name':name,'command':command,'exit_code':result.returncode,'duration_seconds':round(time.monotonic()-start,3),'native_output':str(log.relative_to(root)),'native_output_sha256':hashlib.sha256(log.read_bytes()).hexdigest()})
    print(name+': '+('passed' if result.returncode==0 else 'FAILED'),flush=True)
    if result.returncode:
        print(log.read_text()[-4000:],flush=True)
        break
sources=source_hashes()
changed_sources=sorted(p for p in set(starting_sources)|set(sources) if starting_sources.get(p)!=sources.get(p))
manifest={'schema_version':1,'started_from':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'source_sha256':sources,'sources_unchanged_during_run':not changed_sources,'changed_source_paths':changed_sources,'observed_at':datetime.now(timezone.utc).isoformat(),'results':results,'state':'passed' if len(results)==len(commands) and all(x['exit_code']==0 for x in results) and not changed_sources else 'failed'}
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(root/'.private/foundation-current').write_text(str(raw)+'\n')
print(str(raw/'manifest.json'),flush=True)
if manifest['state']!='passed':raise SystemExit(1)
