#!/usr/bin/env python3
"""Independently reopen a native FTPS-client/stock-receiver result; print counts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PAYLOAD=b"account,amount,day\n"+b"0001,1.01,2026-10-28\n"*10000
REQUIRED={"go-version","receiver-version","receiver-library-versions","build","token","certificate","create-exact-user","set-exact-password","own-exact-inbox","create-exact-pam","explicit-config-owner","implicit-config-owner","native-stock-receiver","independent-receiver-files","explicit-receiver","implicit-receiver","remove-exact-user","remove-exact-pam"}


def read(path,bound=4<<20):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>bound:raise ValueError("unsafe receiver evidence")
    return path.read_bytes()


def summarize(root,result,commit):
    h=json.loads(read(result,8192));ref=h.get("manifest_reference","")
    if not re.fullmatch(r"\.private/ftps-client-[0-9a-f]{32}/manifest\.json",ref):raise ValueError("receiver reference differs")
    path=root/ref
    if not path.resolve().is_relative_to((root/".private").resolve()):raise ValueError("receiver reference escapes private evidence")
    raw=read(path,8<<20);digest=hashlib.sha256(raw).hexdigest();m=json.loads(raw)
    if h.get("state")!="passed" or h.get("manifest_sha256")!=digest or m.get("state")!="passed" or m.get("kind")!="native-ftps-client-stock-receiver" or m.get("starting_commit")!=commit or m.get("architecture") not in {"x86_64","aarch64"}:raise ValueError("receiver candidate or result differs")
    for name in ("sources_unchanged","task_user_removed","task_pam_removed"):
        if m.get(name) is not True:raise ValueError("receiver cleanup or source identity incomplete")
    for name in ("inference_performed","scanner_started","postgres_started","domain_delivery_qualified","full_journeys_qualified"):
        if m.get(name) is not False:raise ValueError("receiver scope differs")
    if m.get("cleanup_failures")!=[] or m.get("native_pass_records")!=3:raise ValueError("receiver execution incomplete")
    steps=m.get("steps")
    if not isinstance(steps,list) or {s.get("name") for s in steps}!=REQUIRED or len(steps)!=len(REQUIRED):raise ValueError("receiver command closure differs")
    for s in steps:
        if type(s.get("exit_code")) is not int or s["exit_code"]!=0:raise ValueError("receiver command failed")
        for ext in ("stdout","stderr"):
            if hashlib.sha256(read(path.parent/(s["name"]+"."+ext),64<<20)).hexdigest()!=s.get(ext+"_sha256"):raise ValueError("receiver original output changed")
    native=read(path.parent/"native-stock-receiver.stdout").decode()
    expected={"TestNativeStockReceiver","TestNativeStockReceiver/explicit","TestNativeStockReceiver/implicit"}
    actual=re.findall(r"^\s*--- PASS: (\S+) \(",native,re.MULTILINE)
    if set(actual)!=expected or len(actual)!=3 or "--- FAIL:" in native or "--- SKIP:" in native:raise ValueError("receiver native cases missing or skipped")
    if b"version 3.0.5" not in read(path.parent/"receiver-version.stdout")+read(path.parent/"receiver-version.stderr"):raise ValueError("stock receiver version differs")
    observed=json.loads(read(path.parent/"independent-receiver-files.stdout"))
    expected_files={mode+"-"+suffix:{"size":len(b),"sha256":hashlib.sha256(b).hexdigest()} for mode in ("explicit","implicit") for suffix,b in (("final.csv",PAYLOAD),("resume.csv",PAYLOAD),("empty",b""))}
    if observed!=expected_files or m.get("receiver_files")!=observed:raise ValueError("independent stock receiver bytes differ")
    for mode in ("explicit","implicit"):
        config=dict(line.split("=",1) for line in read(path.parent/(mode+".conf")).decode().splitlines())
        for name,value in {"listen_address":"127.0.0.1","ssl_enable":"YES","force_local_logins_ssl":"YES","force_local_data_ssl":"YES","require_ssl_reuse":"YES","strict_ssl_read_eof":"YES","strict_ssl_write_shutdown":"YES","ssl_tlsv1_2":"NO","ssl_tlsv1_3":"YES","seccomp_sandbox":"YES","chroot_local_user":"YES","anonymous_enable":"NO","implicit_ssl":"YES" if mode=="implicit" else "NO"}.items():
            if config.get(name)!=value:raise ValueError("receiver security profile differs")
    sources=m.get("source_sha256")
    if not isinstance(sources,dict) or not 1<=len(sources)<=10000:raise ValueError("receiver source closure missing")
    for name,sha in sources.items():
        p=root/name
        if not p.resolve().is_relative_to(root.resolve()) or hashlib.sha256(read(p,16<<20)).hexdigest()!=sha:raise ValueError("receiver source identity changed")
    return {"state":"passed","source_commit":commit,"manifest_sha256":digest,"architecture":m["architecture"],"native_pass_records":3,"original_commands":len(steps),"source_inputs":len(sources),"independent_receiver_files":len(observed),"strict_tls13_reuse_and_shutdown":True,"task_user_removed":True,"task_pam_removed":True,"inference_performed":False,"scanner_started":False,"postgres_started":False,"domain_delivery_qualified":False,"scope":"actual stock vsftpd/OpenSSL/PAM transport component;governed delivery/collection integration and whole journeys remain open"}


def failure_diagnostics(root,result,commit):
    """Only fixed stages/codes from source-bound original failed evidence."""
    try:
        h=json.loads(read(result,8192));ref=h.get("manifest_reference","")
        if not re.fullmatch(r"\.private/ftps-client-[0-9a-f]{32}/manifest\.json",ref):return {}
        path=root/ref;raw=read(path,8<<20);m=json.loads(raw)
        if hashlib.sha256(raw).hexdigest()!=h.get("manifest_sha256") or m.get("starting_commit")!=commit:return {}
        failures=[s["name"] for s in m.get("steps",[]) if s.get("name") in REQUIRED and s.get("exit_code")!=0]
        result={"failed_commands":sorted(set(failures)),"manifest_sha256":h["manifest_sha256"]}
        if m.get("failure") in {"explicit receiver did not start","implicit receiver did not start"}:result["stage"]=m["failure"].split()[0]+"-receiver-start"
        native=read(path.parent/"native-stock-receiver.stdout").decode() if (path.parent/"native-stock-receiver.stdout").exists() else ""
        stages=re.findall(r"client_stock_test.go:\d+: stock (connection|store|size|independent readback|rename|renamed readback|prefix|resume|resumed integrity|zero-byte upload|zero-byte readback)\b",native)
        if stages:result["native_stages"]=sorted(set(stages))
        codes=re.findall(r"FTPS receiver status ([1-5][0-9]{2})\b",native)
        if codes:result["reply_codes"]=sorted(set(map(int,codes)))
        categories=[]
        patterns={"config-owner":"config file not owned by correct user","certificate-load":"SSL: cannot load RSA certificate","key-load":"SSL: cannot load RSA private key","cipher-list":"SSL: could not set cipher list","supervisor-child-exit":"receiver exited before cleanup","supervisor-preexec":"Exception occurred in preexec_fn","supervisor-resource-limit":"not allowed to raise maximum limit","supervisor-stdin":"receiver supervisor command differs","listener-bind":"could not bind listening IPv4 socket"}
        options={"ssl_tlsv1","ssl_tlsv1_1","ssl_tlsv1_2","ssl_tlsv1_3","ssl_sslv2","ssl_sslv3","seccomp_sandbox","strict_ssl_read_eof","strict_ssl_write_shutdown","require_ssl_reuse"}
        for mode in ("explicit","implicit"):
            for ext in ("stdout","stderr"):
                f=path.parent/(mode+"-receiver."+ext)
                if not f.exists():continue
                original=read(f).decode(errors="replace")
                categories.extend(mode+":"+label for label,text in patterns.items() if text in original)
                for option in re.findall(r"unrecognised variable in config file: ([a-z0-9_]+)",original):
                    categories.append(mode+":unsupported-option:"+(option if option in options else "other"))
        if categories:result["receiver_categories"]=sorted(set(categories))
        return result
    except Exception:return {}


def main():
    p=argparse.ArgumentParser();p.add_argument("--result",required=True);args=p.parse_args()
    try:
        commit=os.environ.get("GITHUB_SHA") or subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT).decode().strip()
        print(json.dumps(summarize(ROOT,Path(args.result),commit)));return 0
    except Exception:
        diagnostic=failure_diagnostics(ROOT,Path(args.result),locals().get("commit",""))
        print(json.dumps({"state":"failed","reason":"native FTPS client receiver qualification or original evidence validation failed;inspect protected outputs",**diagnostic}));return 1


if __name__=="__main__":raise SystemExit(main())
