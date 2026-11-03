#!/usr/bin/env python3
"""Build a pinned independent receiver TLS variant on native GitHub Linux only."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tarfile
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
VERSION="3.5.9"
SHA256="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
URL="https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz"
FILES=("prefix/lib/libssl.so.3","prefix/lib/libcrypto.so.3","prefix/bin/openssl","prefix/include/openssl/configuration.h","prefix/LICENSE.txt")
RECIPES=("25-test_verify.t","80-test_ssl_new.t","90-test_sslapi.t")
HARNESS_FILES=("util/wrap.pl","util/shlib_wrap.sh","apps/openssl","test/sslapitest","test/ssl_test","test/fips_version_test","test/ssl_handshake_rtt_test")
STAGE=r'''
import json,pathlib,shutil,sys
source,prefix=map(pathlib.Path,sys.argv[1:])
files={'lib/libssl.so.3':'libssl.so.3','lib/libcrypto.so.3':'libcrypto.so.3','bin/openssl':'apps/openssl','include/openssl/configuration.h':'include/openssl/configuration.h','LICENSE.txt':'LICENSE.txt'}
for target,original in files.items():
 path=prefix/target;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 f=source/original
 if f.is_symlink() or not f.is_file():raise RuntimeError('receiver artifact is not a regular build output')
 shutil.copyfile(f,path);path.chmod(0o755 if target=='bin/openssl' else 0o644)
print(json.dumps({'staged_files':sorted(files),'scope':'private receiver runtime only'}))
'''


def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return h.hexdigest()


def diagnostics(source,private,steps):
    """Fixed categories from exact outputs; never echo upstream text or paths."""
    output=[]
    for step in steps:
        if step["name"] not in {"build","selected-upstream-tests"}:continue
        for ext in ("stdout","stderr"):
            path=private/(step["name"]+"."+ext)
            if path.is_symlink() or not path.is_file() or path.stat().st_size>64<<20:continue
            data=path.read_bytes()
            if hashlib.sha256(data).hexdigest()==step.get(ext+"_sha256"):output.append(data.decode(errors="replace"))
    text="\n".join(output)
    categories={"missing-file":"No such file or directory","missing-perl-module":"Can't locate ","shared-library-loader":"error while loading shared libraries","library-symbol-version":"version `OPENSSL_","tap-failure":"Failed test","tap-bailout":"Bailout called","signal":"Segmentation fault","make-target":"No rule to make target"}
    return {"harness_files":{name:bool((source/name).is_file() and not (source/name).is_symlink() and os.access(source/name,os.X_OK)) for name in HARNESS_FILES},"recipes_seen":[name for name in RECIPES if name in text],"not_ok_records":len(re.findall(r"^\s*not ok\s+[0-9]+\b",text,re.MULTILINE)),"categories":sorted(name for name,pattern in categories.items() if pattern in text)}


def main():
    if not __debug__ or os.environ.get("GITHUB_ACTIONS")!="true" or platform.system()!="Linux" or platform.machine() not in {"x86_64","aarch64"} or Path(os.environ.get("GITHUB_WORKSPACE",".")).resolve()!=ROOT:
        raise RuntimeError("receiver library build requires its native disposable GitHub runner")
    os.chdir(ROOT);os.umask(0o077)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    (ROOT/".cache").mkdir(mode=0o700,exist_ok=True);(ROOT/".private").mkdir(mode=0o700,exist_ok=True)
    base=ROOT/".cache/freightctl-openssl-3.5.9-no-ktls";base.mkdir(mode=0o700)
    private=ROOT/".private"/("ftps-library-"+uuid.uuid4().hex);private.mkdir(mode=0o700)
    prefix=base/"prefix";source=base/("openssl-"+VERSION)
    env=dict(os.environ,CC="/usr/bin/cc",CROSS_COMPILE="",MAKEFLAGS="",MFLAGS="",HARNESS_JOBS="1")
    steps=[];m={"schema_version":1,"kind":"native-receiver-openssl-no-ktls","state":"failed","version":VERSION,"source_url":URL,"source_sha256":SHA256,"architecture":platform.machine(),"configuration":["shared","no-ktls"],"inference_performed":False,"scanner_started":False,"postgres_started":False}
    def command(label,args,timeout,cwd=ROOT):
        out,err=private/(label+".stdout"),private/(label+".stderr")
        with out.open("xb") as stdout,err.open("xb") as stderr:
            child=subprocess.Popen(list(map(str,args)),cwd=cwd,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
            try:code=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(timeout=2)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=2)
                code="timeout"
            stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
        steps.append({"name":label,"exit_code":code,"stdout_sha256":digest(out),"stderr_sha256":digest(err)})
        if code!=0:raise RuntimeError(label+" failed")
        return out.read_text(errors="replace")
    phase="source-download"
    try:
        archive=base/"source.tar.gz"
        with urllib.request.urlopen(URL,timeout=30) as response,archive.open("xb") as out:
            total=0
            while b:=response.read(1<<20):
                total+=len(b)
                if total>64<<20:raise RuntimeError("library source bound exceeded")
                out.write(b)
            out.flush();os.fsync(out.fileno())
        phase="source-digest"
        if digest(archive)!=SHA256:raise RuntimeError("library source digest differs")
        phase="source-layout"
        with tarfile.open(archive,"r:gz") as tar:
            members=tar.getmembers()
            if len(members)>50000 or sum(v.size for v in members)>1<<30 or any(v.size>64<<20 or (v.name!="openssl-"+VERSION and not v.name.startswith("openssl-"+VERSION+"/")) for v in members):raise RuntimeError("library archive layout differs")
            tar.extractall(base,filter="data")
        phase="native-compiler"
        machine=command("native-compiler",["/usr/bin/cc","-dumpmachine"],10).strip()
        if not machine.startswith("aarch64-" if platform.machine()=="aarch64" else "x86_64-"):raise RuntimeError("compiler architecture differs")
        command("compiler-version",["/usr/bin/cc","--version"],10)
        phase="configure"
        command("configure",["perl","Configure","shared","no-ktls","--prefix="+str(prefix),"--libdir=lib"],60,source)
        phase="build"
        # OpenSSL's build_sw/build_tests include every test executable. Build
        # the exact tools needed by the same three complete original recipes.
        command("build",["make","-j1","build_generated","build_libs","build_modules","util/wrap.pl","util/shlib_wrap.sh","apps/openssl","test/sslapitest","test/ssl_test","test/fips_version_test","test/ssl_handshake_rtt_test","link-utils"],360,source)
        phase="selected-upstream-tests"
        output=command("selected-upstream-tests",["make","-j1","run_tests","TESTS=test_verify test_ssl_new test_sslapi","VERBOSE=1"],180,source)
        if "Result: PASS" not in output or any(name not in output for name in RECIPES):raise RuntimeError("selected native upstream recipes incomplete")
        m["upstream_skip_lines"]=len(re.findall(r"^.*#\s*(?:skip|SKIP)\b",output,re.MULTILINE))
        phase="install"
        command("install",["python3","-c",STAGE,source,prefix],60,source)
        env["LD_LIBRARY_PATH"]=str(prefix/"lib")
        phase="installed-version"
        version=command("installed-version",[prefix/"bin/openssl","version","-a"],10)
        if "OpenSSL "+VERSION not in version:raise RuntimeError("installed library version differs")
        phase="kernel-tls-header"
        header=(prefix/"include/openssl/configuration.h").read_text()
        if not re.search(r"^\s*#\s*define\s+OPENSSL_NO_KTLS\b",header,re.MULTILINE):raise RuntimeError("kernel TLS was not compiled out")
        m["files_sha256"]={name:digest(base/name) for name in FILES};m["state"]="passed"
    except Exception as error:m["failure"]=str(error);m["failure_stage"]=phase
    finally:
        m["diagnostics"]=diagnostics(source,private,steps)
        m["steps"]=steps;m["original_output_reference"]=str(private.relative_to(ROOT))
        path=base/"manifest.json"
        with path.open("x") as out:json.dump(m,out,indent=2);out.write("\n");out.flush();os.fsync(out.fileno())
        fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
    print(json.dumps({"state":m["state"],"profile":"openssl-3.5.9-no-ktls","architecture":platform.machine(),"manifest_sha256":digest(path),"source_sha256":SHA256,"upstream_skip_lines":m.get("upstream_skip_lines"),"failure_stage":m.get("failure_stage"),"failed_commands":[{"name":s["name"],"exit_code":s["exit_code"]} for s in steps if s["exit_code"]!=0],"diagnostics":m["diagnostics"],"scope":"native receiver dependency build and three selected upstream recipes;not protocol,system-library or FIPS qualification"}))
    return 0 if m["state"]=="passed" else 1


if __name__=="__main__":raise SystemExit(main())
