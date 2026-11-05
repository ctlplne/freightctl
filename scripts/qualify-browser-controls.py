#!/usr/bin/env python3
"""Retain complete browser gates plus current foundation controls, including red prerequisites."""
from ci_resources import environment as ci_environment
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,os,subprocess,time,uuid
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
p=argparse.ArgumentParser();p.add_argument('--pgp-fixture-reference',required=True);args=p.parse_args()
raw=root/'evidence/raw'/('browser-controls-'+uuid.uuid4().hex);raw.mkdir(parents=True,mode=0o700)
env=ci_environment(dict(os.environ,GOMAXPROCS='1',NODE_OPTIONS='--max-old-space-size=192'))
def sources():
 paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).decode().split('\0')
 special={'go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'}
 return[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()}for p in sorted(set(paths))if p and((root/p).suffix in('.go','.sql','.py','.sh','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml')or p in special)]
initial=sources();results=[]
commands=[('records',['python3','scripts/check-records.py']),('frontend-typecheck',['npm','--prefix','web','run','typecheck']),('exact-browser-artifacts',['npm','--prefix','web','run','check-built']),('dependency-audit',['npm','--prefix','web','--cache','.cache/freightctl-npm','--registry','https://registry.npmjs.org','audit','--json']),('foundation-controls-with-visible-prerequisite-failures',['python3','scripts/qualify-scanner-controls.py','--pgp-fixture-reference',args.pgp_fixture_reference]),('native-browser-exchange',['python3','scripts/qualify-browser.py'])]
for name,command in commands:
 start=time.monotonic();log=raw/(name+'.log')
 with log.open('wb')as out:r=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,env=env)
 results.append({'name':name,'command':command,'exit_code':r.returncode,'duration_seconds':round(time.monotonic()-start,3),'native_output':str(log.relative_to(root)),'native_output_sha256':hashlib.sha256(log.read_bytes()).hexdigest()})
 print(name+': '+('passed'if r.returncode==0 else'FAILED'),flush=True)
 # Continue independent gates; never normalize a required failure to success.
final=sources();m={'schema_version':1,'started_from':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'observed_at':datetime.now(timezone.utc).isoformat(),'source_files':final,'sources_unchanged_during_run':initial==final,'results':results,'state':'passed'if initial==final and all(r['exit_code']==0 for r in results)else'failed','foundation_controls_reference':Path('.private/scanner-controls-current').read_text().strip()+'/manifest.json','native_browser_reference':Path('.private/browser-current').read_text().strip()+'/manifest.json','inference_performed':False,'local_model_processes_started':0,'scanner_engine_started':False,'malware_detection_qualified':False,'full_journeys_qualified':False}
(raw/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');(root/'.private/browser-controls-current').write_text(str(raw)+'\n');print(str(raw/'manifest.json'),flush=True)
if m['state']!='passed':raise SystemExit(1)
