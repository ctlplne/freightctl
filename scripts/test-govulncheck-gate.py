#!/usr/bin/env python3
"""Exercise the real pinned converter with synthetic reports, without scanning."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import uuid

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--tool',required=True);args=parser.parse_args()
    os.umask(0o077);private=ROOT/'.private'/('govulncheck-gate-'+uuid.uuid4().hex);private.mkdir(mode=0o700)
    tool=Path(args.tool).resolve(strict=True);database=private/'database';(database/'index').mkdir(parents=True)
    (database/'index/db.json').write_text('{"modified":"2026-01-01T00:00:00Z"}\n')
    (database/'index/modules.json').write_text('[]\n')
    env=dict(os.environ,GOMAXPROCS='1',GOMEMLIMIT='192MiB',GOTELEMETRY='off')
    config={'config':{'protocol_version':'v1.0.0','scanner_name':'govulncheck','scanner_version':'v1.9.0','go_version':'go1.26.10','scan_level':'symbol','scan_mode':'source'}}
    osv={'osv':{'id':'GO-9999-0001','modified':'2026-01-01T00:00:00Z','details':'Synthetic converter contract; not an application finding.','affected':[{'package':{'name':'example.invalid/stand-in','ecosystem':'Go'}}],'database_specific':{'url':'https://example.invalid/stand-in'}}}
    module={'module':'example.invalid/stand-in','version':'v1.0.0'}
    def report(frame):return ('\n'.join(json.dumps(v) for v in (config,osv,{'finding':{'osv':'GO-9999-0001','trace':[frame]}}))+'\n').encode()
    called=report(dict(module,package='example.invalid/stand-in',function='Called'))
    cases=[('tool-version',['-version'],b'',0),('legacy-json-called',['-json'],called,0),('text-called',[],called,3),('text-module-only',[],report(module),0),('text-clean',[],(json.dumps(config)+'\n').encode(),0),('text-truncated',[],b'{"finding":',1)]
    results=[]
    for name,flags,data,expected in cases:
        (private/(name+'.input')).write_bytes(data)
        out,err=private/(name+'.stdout'),private/(name+'.stderr')
        with out.open('xb') as stdout,err.open('xb') as stderr:
            result=subprocess.run([str(tool),'-mode=convert','-db='+database.as_uri(),*flags],input=data,stdout=stdout,stderr=stderr,env=env,timeout=15)
        row={'name':name,'exit_code':result.returncode,'expected_exit_code':expected}
        for ext in ('input','stdout','stderr'):
            path=private/(name+'.'+ext)
            if path.stat().st_size>2<<20:raise RuntimeError('converter contract output bound exceeded')
            row[ext+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        if name=='tool-version':
            if not re.search(rb'govulncheck@v1\.9\.0\b',out.read_bytes()):raise RuntimeError('actual converter version differs')
        results.append(row)
    state='passed' if all(r['exit_code']==r['expected_exit_code'] for r in results) else 'failed'
    manifest={'schema_version':1,'state':state,'kind':'actual-govulncheck-converter-contract','system':platform.system(),'architecture':platform.machine(),'binary_sha256':hashlib.sha256(tool.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'steps':results,'source_scan_performed':False,'inference_performed':False,'scanner_engine_started':False,'scope':'Synthetic JSON and actual pinned native converter exit behavior only;not a live vulnerability scan.'}
    path=private/'manifest.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'state':state,'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'converter_version':'v1.9.0','records':len(results),'exit_codes':{r['name']:r['exit_code'] for r in results},'source_scan_performed':False}))
    return 0 if state=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
