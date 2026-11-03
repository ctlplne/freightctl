#!/usr/bin/env python3
"""Reopen the original first-run journey; emit only fixed aggregate outcomes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
COMMANDS=('build','initialize-empty-database','save-first-run-plan','refuse-plan-overwrite','commit-first-run','recover-first-run-response','refuse-changed-plan','refuse-runtime-bootstrap','certificate','native-first-run-exchange','stock-curl-first-exchange','stock-curl-after-restart','replay-after-ordinary-work')
REFUSALS={'refuse-plan-overwrite','refuse-changed-plan','refuse-runtime-bootstrap'}
BROWSER=('setup-login-axe','workspace-file-refuses-invalid-ids-and-cannot-select-origin-or-credential','saved-setup-reference-and-first-admin-authenticate','fresh-first-admin-browser-durable-upload','setup-published-files-axe','fresh-first-admin-native-download-exact-bytes')
FILES={'raw/setup-result.json','raw/setup-login-axe.json','raw/setup-published-files-axe.json','fixture/source.csv','fixture/browser-received.csv','fixture/stock-curl-first-exchange.csv','fixture/stock-curl-after-restart.csv','fixture/setup.json','fixture/workspace.json'}
PAYLOAD=b'account,amount\n00000001,100.01\n00000002,200.02\n'


def read(root,path,bound=8<<20):
    relative=path.relative_to(root)
    if any(v in {'.','..'} for v in relative.parts):raise ValueError('unsafe first-run evidence path')
    if not path.resolve().is_relative_to(root.resolve()) or any((root/Path(*relative.parts[:i])).is_symlink() for i in range(1,len(relative.parts)+1)):raise ValueError('unsafe first-run evidence path')
    if not path.is_file() or path.stat().st_size>bound:raise ValueError('missing or oversized first-run evidence')
    return path.read_bytes()


def sha(data):return hashlib.sha256(data).hexdigest()


def source_paths(root):
    names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
    special={'go.mod','go.sum','web/package.json','web/package-lock.json','web/tsconfig.json','web/THIRD_PARTY_NOTICES.txt','internal/browser/assets/manifest.json'}
    return {p for p in names if p and (Path(p).suffix in ('.go','.sql','.sh','.py','.ts','.tsx','.js','.mjs','.css','.html','.yml','.yaml') or p in special)}


def summarize(root,path,commit,expected_sources):
    raw=read(root,path);m=json.loads(raw)
    run=path.parent.name
    if not re.fullmatch(r'setup-[0-9a-f]{32}',run) or path!=root/'evidence/raw'/run/'manifest.json':raise ValueError('wrong first-run evidence identity')
    if type(m.get('schema_version')) is not int or m.get('schema_version')!=1 or m.get('kind')!='native-first-run-browser' or m.get('state')!='passed' or m.get('starting_commit')!=commit:raise ValueError('first-run candidate or result differs')
    if m.get('system')!='Linux' or m.get('architecture')!='x86_64':raise ValueError('first-run native profile differs')
    if any(m.get(k) is not True for k in ('sources_unchanged_during_run','exact_fixture_database_removed')) or any(m.get(k) is not False for k in ('inference_performed','scanner_engine_started')) or m.get('cleanup_failures')!=[] or m.get('failure') is not None:raise ValueError('first-run scope or cleanup incomplete')
    fixture=root/'.private'/run
    if m.get('fixture_reference')!=str(fixture.relative_to(root)) or m.get('database')!='freightctl_'+run.replace('-','_'):raise ValueError('first-run fixture identity differs')
    sources=m.get('source_sha256')
    if not expected_sources or not isinstance(sources,dict) or set(sources)!=set(expected_sources):raise ValueError('first-run source closure differs')
    for name,digest in sources.items():
        if sha(read(root,root/name,16<<20))!=digest:raise ValueError('first-run source changed')
    if sha(read(root,fixture/'freightctl',64<<20))!=m.get('binary_sha256'):raise ValueError('first-run binary changed')
    steps=m.get('steps')
    if not isinstance(steps,list) or [s.get('name') for s in steps]!=list(COMMANDS):raise ValueError('first-run original command sequence differs')
    for step in steps:
        label=step['name'];expected=1 if label in REFUSALS else 0
        if type(step.get('exit_code')) is not int or type(step.get('expected_exit_code')) is not int or step['exit_code']!=expected or step['expected_exit_code']!=expected:raise ValueError('first-run original command failed')
        if step.get('native_output')!=str((path.parent/(label+'.log')).relative_to(root)) or sha(read(root,path.parent/(label+'.log')))!=step.get('native_output_sha256'):raise ValueError('first-run original command output changed')
    files=m.get('original_files_sha256')
    if not isinstance(files,dict) or set(files)!=FILES:raise ValueError('first-run original file closure differs')
    originals={}
    for name,digest in files.items():
        base,file=name.split('/',1);data=read(root,(path.parent if base=='raw' else fixture)/file)
        if sha(data)!=digest:raise ValueError('first-run original file changed')
        originals[name]=data
    for name in ('source.csv','browser-received.csv','stock-curl-first-exchange.csv','stock-curl-after-restart.csv'):
        if originals['fixture/'+name]!=PAYLOAD:raise ValueError('first-run exact bytes differ')
    def result(label):return json.loads(read(root,path.parent/(label+'.log')))
    first,replay,final=map(result,('commit-first-run','recover-first-run-response','replay-after-ordinary-work'))
    if first.get('replayed') is not False or replay.get('replayed') is not True or final!=replay or dict(first,replayed=True)!=replay or json.loads(originals['fixture/workspace.json'])!=replay:raise ValueError('first-run original receipt replay differs')
    plan=json.loads(originals['fixture/setup.json'])['request']
    for left,right in (('tenant_id','tenant_id'),('partner_id','partner_id'),('admin_id','actor_id'),('storage_id','storage_id')):
        if plan.get(left)!=first.get(right) or not re.fullmatch(r'[0-9a-f-]{36}',str(first.get(right,''))):raise ValueError('first-run plan and receipt differ')
    if fixture.stat().st_mode&0o077 or (fixture/'admin.token').stat().st_mode&0o077 or sha(read(root,fixture/'admin.token',1024))!=plan.get('credential_sha256'):raise ValueError('first-run credential proof differs')
    browser=json.loads(originals['raw/setup-result.json'])
    if browser.get('state')!='passed' or browser.get('stage')!='setup' or browser.get('runtime_errors')!=[] or browser.get('page_request_egress_origins')!=[] or browser.get('inference_performed') is not False or browser.get('scanner_engine_started') is not False:raise ValueError('first-run browser runtime failed')
    if [s.get('name') for s in browser.get('steps',[])]!=list(BROWSER):raise ValueError('first-run browser cases incomplete')
    if not re.fullmatch(r'[0-9]{1,4}(?:\.[0-9]{1,8}){2,3}',str(browser.get('browser_version',''))) or not re.fullmatch(r'v[0-9]{1,3}\.[0-9]{1,4}\.[0-9]{1,4}',str(browser.get('node',''))):raise ValueError('first-run native tool versions missing')
    for name in ('setup-login','setup-published-files'):
        audit=json.loads(originals['raw/'+name+'-axe.json'])
        if audit.get('violations')!=[] or type(audit.get('passes')) is not int or audit['passes']<=0:raise ValueError('first-run accessibility failed')
        if next(s for s in browser['steps'] if s['name']==name+'-axe').get('passes')!=audit['passes']:raise ValueError('first-run accessibility report differs')
    return {'state':'passed','source_commit':commit,'manifest_sha256':sha(raw),'system':'Linux','architecture':'x86_64','browser_version':browser['browser_version'],'node_version':browser['node'],'source_inputs':len(sources),'original_commands':len(steps),'browser_records':len(BROWSER),'accessibility_audits':2,'independent_exact_readbacks':3,'payload_bytes':len(PAYLOAD),'original_receipt_replays':2,'exact_fixture_database_removed':True,'inference_performed':False,'scanner_engine_started':False,'whole_journey_qualified':False,'scope':'assisted first enrollment,original receipt recovery,sandboxed browser exchange and stock curl readback after process restart;disconnected installation and independent adoption remain open'}


def diagnostics(root,path,commit):
    try:
        raw=read(root,path);m=json.loads(raw)
        if m.get('starting_commit')!=commit:return {}
        steps=[s for s in m.get('steps',[]) if s.get('name') in COMMANDS]
        result={'manifest_sha256':sha(raw),'recorded_commands':len(steps),'failed_commands':[{'name':s['name'],'exit_code':s['exit_code']} for s in steps if type(s.get('exit_code')) is int and s['exit_code']!=(1 if s['name'] in REFUSALS else 0)]}
        if steps:result['last_recorded_command']=steps[-1]['name']
        browser=next((s for s in steps if s['name']=='native-first-run-exchange'),None)
        if browser is not None:
            data=read(root,path.parent/'native-first-run-exchange.log')
            if sha(data)==browser.get('native_output_sha256'):
                result['browser_failure_locations']=sorted(set('browser-journey.mjs:'+a.decode()+':'+b.decode() for a,b in re.findall(rb'/scripts/browser-journey\.mjs:([0-9]{1,6}):([0-9]{1,6})',data)))[:16]
        return result
    except Exception:return {}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',required=True);args=parser.parse_args()
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip()
    try:
        value=summarize(ROOT,Path(args.manifest),commit,source_paths(ROOT));code=0
    except Exception:
        value={'state':'failed','source_commit':commit,'reason':'first-run journey or original evidence validation failed;inspect protected runner outputs',**diagnostics(ROOT,Path(args.manifest),commit)};code=1
    print(json.dumps(value));return code


if __name__=='__main__':raise SystemExit(main())
