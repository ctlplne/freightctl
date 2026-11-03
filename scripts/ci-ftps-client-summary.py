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
REQUIRED={"go-version","receiver-version","receiver-library-versions","build","token","certificate","create-exact-user","set-exact-password","own-exact-inbox","create-exact-pam","explicit-config-owner","implicit-config-owner","explicit-refuse-tls12","implicit-refuse-tls12","native-stock-receiver","independent-receiver-files","explicit-receiver","implicit-receiver","remove-exact-user","remove-exact-pam"}
REQUIRED.add('receiver-audit-logs')
OPENSSL_PROFILE=b"config_diagnostics=1\nopenssl_conf=freightctl_init\n[freightctl_init]\nssl_conf=freightctl_ssl\n[freightctl_ssl]\nsystem_default=freightctl_tls\n[freightctl_tls]\nMinProtocol=TLSv1.3\nMaxProtocol=TLSv1.3\nOptions=-KTLS\n"
LIBRARY_BASE=".cache/freightctl-openssl-3.5.9-no-ktls"
LIBRARY_SOURCE_SHA="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
LIBRARY_FILES={"prefix/lib/libssl.so.3","prefix/lib/libcrypto.so.3","prefix/bin/openssl","prefix/include/openssl/configuration.h","prefix/LICENSE.txt"}
LIBRARY_STEPS={"native-compiler","compiler-version","configure","build","selected-upstream-tests","install","installed-version"}
CUSTOM_COMMANDS={"selected-library-version","selected-library-linkage"}


def read(path,bound=4<<20):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>bound:raise ValueError("unsafe receiver evidence")
    return path.read_bytes()


def verify_library(root,architecture):
    base=root/LIBRARY_BASE
    if not base.resolve().is_relative_to(root.resolve()) or any(p.is_symlink() for p in (base,base/"prefix",base/"prefix/lib",base/"prefix/bin",base/"prefix/include",base/"prefix/include/openssl")):raise ValueError("receiver library path escapes its build")
    raw=read(base/"manifest.json");m=json.loads(raw)
    if m.get("state")!="passed" or m.get("kind")!="native-receiver-openssl-no-ktls" or m.get("version")!="3.5.9" or m.get("source_sha256")!=LIBRARY_SOURCE_SHA or m.get("source_url")!="https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz" or m.get("architecture")!=architecture or m.get("configuration")!=["shared","no-ktls"]:raise ValueError("receiver library build identity differs")
    for flag in ("inference_performed","scanner_started","postgres_started"):
        if m.get(flag) is not False:raise ValueError("receiver library scope differs")
    files=m.get("files_sha256",{})
    if set(files)!=LIBRARY_FILES:raise ValueError("receiver library artifact closure differs")
    for name,sha in files.items():
        if hashlib.sha256(read(base/name,64<<20)).hexdigest()!=sha:raise ValueError("receiver library artifact changed")
    if not re.search(rb"^\s*#\s*define\s+OPENSSL_NO_KTLS\b",read(base/"prefix/include/openssl/configuration.h"),re.MULTILINE):raise ValueError("receiver library kernel TLS profile differs")
    ref=m.get("original_output_reference","")
    if not re.fullmatch(r"\.private/ftps-library-[0-9a-f]{32}",ref):raise ValueError("receiver library output reference differs")
    directory=root/ref;steps=m.get("steps",[])
    if len(steps)!=len(LIBRARY_STEPS) or {s.get("name") for s in steps}!=LIBRARY_STEPS:raise ValueError("receiver library command closure differs")
    for s in steps:
        if type(s.get("exit_code")) is not int or s["exit_code"]!=0:raise ValueError("receiver library build or upstream recipe failed")
        for ext in ("stdout","stderr"):
            if hashlib.sha256(read(directory/(s["name"]+"."+ext),64<<20)).hexdigest()!=s.get(ext+"_sha256"):raise ValueError("receiver library original output changed")
    tests=read(directory/"selected-upstream-tests.stdout",64<<20).decode()
    if "Result: PASS" not in tests or any(name not in tests for name in ("25-test_verify.t","80-test_ssl_new.t","90-test_sslapi.t")):raise ValueError("receiver library selected upstream recipes incomplete")
    skips=len(re.findall(r"^.*#\s*(?:skip|SKIP)\b",tests,re.MULTILINE))
    if type(m.get("upstream_skip_lines")) is not int or m["upstream_skip_lines"]!=skips:raise ValueError("receiver library upstream skips differ")
    if "OpenSSL 3.5.9" not in read(directory/"installed-version.stdout").decode():raise ValueError("receiver library native version differs")
    machine=read(directory/"native-compiler.stdout").decode().strip()
    if not machine.startswith("aarch64-" if architecture=="aarch64" else "x86_64-"):raise ValueError("receiver library compiler architecture differs")
    return {"manifest_sha256":hashlib.sha256(raw).hexdigest(),"version":"3.5.9","source_sha256":LIBRARY_SOURCE_SHA,"selected_upstream_recipes":3,"upstream_skip_lines":skips,"kernel_tls_compiled_out":True}


def summarize(root,result,commit,library_profile="system"):
    h=json.loads(read(result,8192));ref=h.get("manifest_reference","")
    if not re.fullmatch(r"\.private/ftps-client-[0-9a-f]{32}/manifest\.json",ref):raise ValueError("receiver reference differs")
    path=root/ref
    if not path.resolve().is_relative_to((root/".private").resolve()):raise ValueError("receiver reference escapes private evidence")
    raw=read(path,8<<20);digest=hashlib.sha256(raw).hexdigest();m=json.loads(raw)
    if h.get("state")!="passed" or h.get("manifest_sha256")!=digest or m.get("state")!="passed" or m.get("kind")!="native-ftps-client-stock-receiver" or m.get("starting_commit")!=commit or m.get("architecture") not in {"x86_64","aarch64"}:raise ValueError("receiver candidate or result differs")
    if library_profile not in {"system","no-ktls"} or m.get("receiver_library_profile")!=library_profile:raise ValueError("receiver library profile differs")
    library=None
    if library_profile=="no-ktls":
        library=verify_library(root,m["architecture"])
        if m.get("receiver_library_manifest_sha256")!=library["manifest_sha256"]:raise ValueError("receiver library build binding differs")
    for name in ("sources_unchanged","task_user_removed","task_pam_removed"):
        if m.get(name) is not True:raise ValueError("receiver cleanup or source identity incomplete")
    for name in ("inference_performed","scanner_started","postgres_started","domain_delivery_qualified","full_journeys_qualified"):
        if m.get(name) is not False:raise ValueError("receiver scope differs")
    if m.get("receiver_traced") is not False:raise ValueError("traced receiver cannot qualify the normal profile")
    if m.get("cleanup_failures")!=[] or m.get("probe_failures")!=[] or m.get("native_pass_records")!=3:raise ValueError("receiver execution incomplete")
    steps=m.get("steps")
    required=REQUIRED|CUSTOM_COMMANDS if library_profile=="no-ktls" else REQUIRED
    if not isinstance(steps,list) or {s.get("name") for s in steps}!=required or len(steps)!=len(required):raise ValueError("receiver command closure differs")
    for s in steps:
        expected_code=1 if s["name"] in {"explicit-refuse-tls12","implicit-refuse-tls12"} else 0
        if type(s.get("exit_code")) is not int or s["exit_code"]!=expected_code:raise ValueError("receiver command failed")
        for ext in ("stdout","stderr"):
            if hashlib.sha256(read(path.parent/(s["name"]+"."+ext),64<<20)).hexdigest()!=s.get(ext+"_sha256"):raise ValueError("receiver original output changed")
    native=read(path.parent/"native-stock-receiver.stdout").decode()
    expected={"TestNativeStockReceiver","TestNativeStockReceiver/explicit","TestNativeStockReceiver/implicit"}
    actual=re.findall(r"^\s*--- PASS: (\S+) \(",native,re.MULTILINE)
    if set(actual)!=expected or len(actual)!=3 or "--- FAIL:" in native or "--- SKIP:" in native:raise ValueError("receiver native cases missing or skipped")
    if b"version 3.0.5" not in read(path.parent/"receiver-version.stdout")+read(path.parent/"receiver-version.stderr"):raise ValueError("stock receiver version differs")
    if library is not None:
        if b"OpenSSL 3.5.9" not in read(path.parent/"selected-library-version.stdout"):raise ValueError("actual receiver library version differs")
        linkage=read(path.parent/"selected-library-linkage.stdout").decode()
        for name in ("libssl.so.3","libcrypto.so.3"):
            if name+" => "+str(root/LIBRARY_BASE/"prefix/lib"/name) not in linkage:raise ValueError("actual receiver library linkage differs")
    observed=json.loads(read(path.parent/"independent-receiver-files.stdout"))
    expected_files={mode+"-"+suffix:{"size":len(b),"sha256":hashlib.sha256(b).hexdigest()} for mode in ("explicit","implicit") for suffix,b in (("final.csv",PAYLOAD),("resume.csv",PAYLOAD),("empty",b""))}
    if observed!=expected_files or m.get("receiver_files")!=observed:raise ValueError("independent stock receiver bytes differ")
    if read(path.parent/"openssl.conf")!=OPENSSL_PROFILE:raise ValueError("receiver OpenSSL TLS floor differs")
    for mode in ("explicit","implicit"):
        refusal=read(path.parent/(mode+"-refuse-tls12.stderr"))
        if b"alert protocol version" not in refusal or b"SSL alert number 70" not in refusal:raise ValueError("receiver original TLS1.2 refusal differs")
        config=dict(line.split("=",1) for line in read(path.parent/(mode+".conf")).decode().splitlines())
        for name,value in {"listen_address":"127.0.0.1","ssl_enable":"YES","force_local_logins_ssl":"YES","force_local_data_ssl":"YES","require_ssl_reuse":"YES","strict_ssl_read_eof":"YES","strict_ssl_write_shutdown":"YES","ssl_tlsv11":"NO","ssl_tlsv12":"NO","ssl_tlsv13":"YES","seccomp_sandbox":"YES","chroot_local_user":"YES","anonymous_enable":"NO","pasv_enable":"YES","port_enable":"NO","implicit_ssl":"YES" if mode=="implicit" else "NO"}.items():
            if config.get(name)!=value:raise ValueError("receiver security profile differs")
        for name,value in {'xferlog_enable':'YES','dual_log_enable':'NO','xferlog_std_format':'YES','log_ftp_protocol':'NO','xferlog_file':str(path.parent/(mode+'.xferlog'))}.items():
            if config.get(name)!=value:raise ValueError('receiver private auditing profile differs')
    logs=json.loads(read(path.parent/'receiver-audit-logs.stdout'));password=read(path.parent/'password',1024)
    if not password or set(logs)!={'explicit','implicit'} or m.get('receiver_audit_logs')!=logs:raise ValueError('receiver transfer audit closure differs')
    observations={}
    for mode in ('explicit','implicit'):
        log=path.parent/(mode+'.xferlog');body=read(log,1<<20)
        expected={'size_bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'line_records':len(body.splitlines())}
        if log.stat().st_mode&0o077 or logs[mode]!=expected or not 1<=expected['line_records']<=32 or password in body:raise ValueError('receiver transfer audit changed or exposed a credential')
        values=[]
        for line in read(path.parent/(mode+'-receiver.stdout')).splitlines():
            if line.startswith(b'{"freightctl_receiver_isolation":'):
                value=json.loads(line)
                if set(value)!={'freightctl_receiver_isolation'}:raise ValueError('receiver kernel witness differs')
                values.append(value['freightctl_receiver_isolation'])
        if len(values)!=1:raise ValueError('receiver kernel witness missing or duplicate')
        witness=values[0]
        if set(witness)!={'baseline_observed','native_filter_observations','maximum_added_filters'} or witness['baseline_observed'] is not True:raise ValueError('receiver kernel baseline missing')
        count,maximum=witness['native_filter_observations'],witness['maximum_added_filters']
        if type(count) is not int or type(maximum) is not int or not 0<=count<=50000 or not 0<=maximum<=128:raise ValueError('receiver kernel witness bounds differ')
        if m['architecture']=='x86_64' and (count<1 or maximum<1):raise ValueError('receiver native x86 filter not observed')
        if m['architecture']=='aarch64' and (count!=0 or maximum!=0):raise ValueError('unexpected ARM filter requires a reviewed native support profile')
        observations[mode]=count
    sources=m.get("source_sha256")
    if not isinstance(sources,dict) or not 1<=len(sources)<=10000:raise ValueError("receiver source closure missing")
    for name,sha in sources.items():
        p=root/name
        if not p.resolve().is_relative_to(root.resolve()) or hashlib.sha256(read(p,16<<20)).hexdigest()!=sha:raise ValueError("receiver source identity changed")
    return {"state":"passed","source_commit":commit,"manifest_sha256":digest,"architecture":m["architecture"],"receiver_library_profile":library_profile,"receiver_library":library,"native_pass_records":3,"original_commands":len(steps),"source_inputs":len(sources),"independent_receiver_files":len(observed),"strict_tls13_reuse_and_shutdown":True,"private_transfer_audit_records":{mode:logs[mode]['line_records'] for mode in logs},"receiver_native_seccomp":"added kernel filter observed" if m['architecture']=='x86_64' else "not implemented by selected ARM receiver","kernel_filter_observations":observations,"task_user_removed":True,"task_pam_removed":True,"inference_performed":False,"scanner_started":False,"postgres_started":False,"domain_delivery_qualified":False,"scope":"actual unmodified stock vsftpd/PAM with named TLS library profile;ARM native filter,governed delivery/collection and whole journeys remain unqualified"}


def failure_diagnostics(root,result,commit):
    """Only fixed stages/codes from source-bound original failed evidence."""
    try:
        h=json.loads(read(result,8192));ref=h.get("manifest_reference","")
        if not re.fullmatch(r"\.private/ftps-client-[0-9a-f]{32}/manifest\.json",ref):return {}
        path=root/ref;raw=read(path,8<<20);m=json.loads(raw)
        if hashlib.sha256(raw).hexdigest()!=h.get("manifest_sha256") or m.get("starting_commit")!=commit:return {}
        steps={s["name"]:s for s in m.get("steps",[]) if s.get("name") in REQUIRED|CUSTOM_COMMANDS}
        def original(name,ext):
            if name not in steps:return b""
            f=path.parent/(name+"."+ext)
            if not f.exists():return b""
            b=read(f,64<<20)
            return b if hashlib.sha256(b).hexdigest()==steps[name].get(ext+"_sha256") else b""
        failures=[s["name"] for s in m.get("steps",[]) if s.get("name") in REQUIRED|CUSTOM_COMMANDS and s.get("exit_code")!=(1 if s["name"] in {"explicit-refuse-tls12","implicit-refuse-tls12"} else 0)]
        result={"failed_commands":sorted(set(failures)),"manifest_sha256":h["manifest_sha256"]}
        if m.get("receiver_library_profile") in {"system","no-ktls"}:result["receiver_library_profile"]=m["receiver_library_profile"]
        if m.get("receiver_traced") is True:result["receiver_traced"]=True
        probes=m.get("probe_failures",[])
        if isinstance(probes,list):
            values=sorted({v for v in probes if isinstance(v,str) and v in {"explicit-refuse-tls12","implicit-refuse-tls12"}})
            if values:result["failed_tls_probes"]=values
        if m.get("failure") in {"explicit receiver did not start","implicit receiver did not start"}:result["stage"]=m["failure"].split()[0]+"-receiver-start"
        if m.get("failure") in {"explicit exact TLS1.2 refusal missing","implicit exact TLS1.2 refusal missing"}:result["stage"]=m["failure"].split()[0]+"-tls12-refusal"
        native=original("native-stock-receiver","stdout").decode(errors="replace")
        if "native-stock-receiver" in steps:
            result["observed_native_pass_records"]=len(re.findall(r"^\s*--- PASS: TestNativeStockReceiver(?:/(?:explicit|implicit))? \(",native,re.MULTILINE))
        stages=re.findall(r"client_stock_test.go:\d+: stock (receiver connection|connection|store|size|independent readback|rename|renamed readback|prefix|resume|resumed integrity|zero-byte upload|zero-byte readback)\b",native)
        if stages:result["native_stages"]=sorted(set(stages))
        codes=re.findall(r"FTPS receiver status ([1-5][0-9]{2})\b",native)
        if codes:result["reply_codes"]=sorted(set(map(int,codes)))
        phases=re.findall(r"FTPS connection phase (request|transport|greeting|auth-tls|control-tls|username|credential-reference|password|data-protection):",native)
        if phases:result["connection_phases"]=sorted(set(phases))
        fixed={"crypto-policy":"FTPS receiver identity, credential or channel policy failed","reply":"invalid or oversized FTPS receiver reply","native-timeout":"panic: test timed out","native-build":"[build failed]","protected-reference":"exact protected stock receiver reference required"}
        kinds=[name for name,text in fixed.items() if text in native]
        if kinds:result["native_categories"]=sorted(kinds)
        tls_patterns={"unexpected-eof":"unexpected eof while reading","no-protocols":"no protocols available","version-alert":"alert protocol version","connection-refused":"Connection refused","connection-reset":"errno=104","broken-pipe":"errno=32","starttls-refused":"Didn't find STARTTLS"}
        tls_categories=[]
        for mode in ("explicit","implicit"):
            text=original(mode+"-refuse-tls12","stderr").decode(errors="replace")
            tls_categories.extend(mode+":"+name for name,pattern in tls_patterns.items() if pattern in text)
        if tls_categories:result["tls_probe_categories"]=sorted(set(tls_categories))
        categories=[]
        patterns={"config-owner":"config file not owned by correct user","certificate-load":"SSL: cannot load RSA certificate","key-load":"SSL: cannot load RSA private key","cipher-list":"SSL: could not set cipher list","supervisor-child-exit":"receiver exited before cleanup","supervisor-preexec":"Exception occurred in preexec_fn","supervisor-resource-limit":"not allowed to raise maximum limit","supervisor-stdin":"receiver supervisor command differs","listener-bind":"could not bind listening IPv4 socket"}
        options={"ssl_tlsv1","ssl_tlsv1_1","ssl_tlsv1_2","ssl_tlsv1_3","ssl_sslv2","ssl_sslv3","seccomp_sandbox","strict_ssl_read_eof","strict_ssl_write_shutdown","require_ssl_reuse"}
        for mode in ("explicit","implicit"):
            for ext in ("stdout","stderr"):
                text=original(mode+"-receiver",ext).decode(errors="replace")
                categories.extend(mode+":"+label for label,pattern in patterns.items() if pattern in text)
                for option in re.findall(r"unrecognised variable in config file: ([a-z0-9_]+)",text):
                    categories.append(mode+":unsupported-option:"+(option if option in options else "other"))
        if categories:result["receiver_categories"]=sorted(set(categories))
        trace_syscalls={"newfstatat","statx","getdents64","readlinkat","getrandom","clock_gettime","clock_gettime64","futex","openat","openat2","prlimit64","setrlimit","mmap","mprotect","munmap","mremap","brk","rseq","clone","clone3","arch_prctl","rt_sigprocmask","rt_sigaction","rt_sigreturn","recvfrom","sendto","sendmsg","recvmsg","getsockopt","setsockopt","ioctl","fcntl","getpid","gettid","exit_group","epoll_pwait","epoll_wait","epoll_ctl","ppoll","poll","pselect6","socket","accept","accept4","bind","connect","listen","close","read","write","writev","readv","pread64","pwrite64","fsync","fchmod","fchown","chroot","capset","capget","setuid","setgid","setresuid","setresgid","setgroups","wait4","waitid","unshare","getuid","geteuid","getgid","getegid","umask"}
        trace_categories=[]
        for mode in ("explicit","implicit"):
            f=path.parent/(mode+"-receiver.trace")
            if not f.exists():continue
            b=read(f,16<<20)
            if hashlib.sha256(b).hexdigest()!=m.get("trace_sha256",{}).get(mode):continue
            text=b.decode(errors="replace")
            for signal in ("SIGSYS","SIGSEGV","SIGABRT"):
                if signal in text:trace_categories.append(mode+":"+signal)
            for name in re.findall(r"si_syscall=__NR_([a-z0-9_]{1,64})",text):
                trace_categories.append(mode+":syscall:"+(name if name in trace_syscalls else "other"))
            for number in re.findall(r"si_syscall=(0x[0-9a-f]{1,8}|[0-9]{1,8})\b",text):
                value=int(number,16 if number.startswith("0x") else 10)
                if value<4096:trace_categories.append(mode+":syscall-number:"+str(value))
            last={};socket_options={}
            for line in text.splitlines():
                match=re.match(r"\s*(?:\[pid\s+)?([0-9]{1,10})\]?\s+(?:\[\s*([0-9]{1,4})\]\s+)?",line)
                if not match:continue
                pid,number=match.groups()
                if number is not None and int(number)<4096 and (pid in last or len(last)<256):last[pid]=int(number)
                sock=re.search(r"\bsetsockopt\(([^()]*)\)",line)
                if sock and len(socket_options)<256:
                    args=[s.strip() for s in sock[1].split(",")]
                    if len(args)==5 and all(re.fullmatch(r"(?:0x[0-9a-f]{1,16}|[0-9]{1,10})",args[i]) for i in (1,2,4)):
                        values=[int(args[i],16 if args[i].startswith("0x") else 10) for i in (1,2,4)]
                        if values[0]<4096 and values[1]<4096 and values[2]<=256:socket_options[pid]=values
                if "killed by SIGSYS" in line and pid in last:
                    trace_categories.append(mode+":last-syscall-before-SIGSYS:"+str(last[pid]))
                    if pid in socket_options and last[pid] in {54,208}:
                        level,option,size=socket_options[pid]
                        trace_categories.append(mode+":last-setsockopt-before-SIGSYS:level="+str(level)+",option="+str(option)+",size="+str(size))
                exited=re.search(r"\bexit_group\((0x[0-9a-f]{1,8}|[0-9]{1,8})\)",line)
                if exited:
                    code=int(exited[1],16 if exited[1].startswith("0x") else 10)
                    if 0<code<=255:trace_categories.append(mode+":process-exit:"+str(code))
            for name,errno in re.findall(r"\b([a-z0-9_]{1,64})\([^\n]*\)\s*= -1 (EPERM|ENOMEM|EAGAIN|EACCES)\b",text):
                if name in trace_syscalls:trace_categories.append(mode+":"+name+":"+errno)
        if trace_categories:result["trace_categories"]=sorted(set(trace_categories))[:32]
        return result
    except Exception:return {}


def main():
    p=argparse.ArgumentParser();p.add_argument("--result",required=True);p.add_argument("--library-profile",choices=("system","no-ktls"),default="system");args=p.parse_args()
    try:
        commit=os.environ.get("GITHUB_SHA") or subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT).decode().strip()
        print(json.dumps(summarize(ROOT,Path(args.result),commit,args.library_profile)));return 0
    except Exception:
        diagnostic=failure_diagnostics(ROOT,Path(args.result),locals().get("commit",""))
        print(json.dumps({"state":"failed","reason":"native FTPS client receiver qualification or original evidence validation failed;inspect protected outputs",**diagnostic}));return 1


if __name__=="__main__":raise SystemExit(main())
