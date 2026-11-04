#!/usr/bin/env python3
"""Native stock vsftpd receiver qualification on disposable GitHub runners only.

Creates one exact PAM account/service and two loopback receivers. It never
installs/starts a global FTP daemon, uses retained PostgreSQL or runs inference.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import subprocess
import tempfile
import time
import uuid
import ftps_stock_metadata as stock_metadata

ROOT=Path(__file__).resolve().parents[1]
PAYLOAD=b"account,amount,day\n"+b"0001,1.01,2026-10-28\n"*10000
SUPERVISOR = r'''
import json,os,resource,select,signal,subprocess,sys
from scripts.ftps_receiver_witness import FilterWitness
def bounds():
 os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
 for kind,limit in [(resource.RLIMIT_AS,268435456),(resource.RLIMIT_CPU,60),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_FSIZE,16777216),(resource.RLIMIT_NPROC,64)]:resource.setrlimit(kind,(limit,limit))
# vsftpd writes version/startup diagnostics to descriptor0 before it accepts
# sockets. Keep its fd0 separate from the supervisor's read-only stop pipe.
os.environ['OPENSSL_CONF']=sys.argv[1]
if sys.argv[2]:os.environ['LD_LIBRARY_PATH']=sys.argv[2]
else:os.environ.pop('LD_LIBRARY_PATH',None)
witness=FilterWitness()
p=subprocess.Popen(sys.argv[3:],stdin=sys.stdout,start_new_session=True,preexec_fn=bounds)
signal.signal(signal.SIGTERM,lambda *_:sys.exit(1))
try:
 while p.poll() is None:
  witness.observe(p.pid)
  if select.select([sys.stdin.buffer],[],[],.05)[0]:
   if sys.stdin.buffer.readline(16)!=b'stop\n':raise RuntimeError('receiver supervisor command differs')
   break
 if p.poll() is not None:raise RuntimeError('receiver exited before cleanup')
finally:
 try:
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=2);raise RuntimeError('receiver forced cleanup')
 finally:print(json.dumps({'freightctl_receiver_isolation':witness.result()}),flush=True)
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receiver_directories():
    # chmod after creation is deliberate:the private077 umask must not make
    # approved non-owner traversal impossible. Only the payload inbox is0700.
    estate=Path(tempfile.mkdtemp(prefix="freightctl-ftps-receiver-"));estate.chmod(0o755)
    home=estate/"home";home.mkdir(mode=0o755);home.chmod(0o755)
    inbox=home/"inbox";inbox.mkdir(mode=0o700)
    empty=estate/"empty";empty.mkdir(mode=0o755);empty.chmod(0o755)
    return estate,home,inbox,empty


def main():
    if not __debug__ or os.environ.get("GITHUB_ACTIONS")!="true" or platform.system()!="Linux" or Path(os.environ.get("GITHUB_WORKSPACE",".")).resolve()!=ROOT:
        raise RuntimeError("stock receiver requires its disposable native GitHub runner")
    if platform.machine() not in {"x86_64","aarch64"}:raise RuntimeError("unsupported native receiver architecture")
    parser=argparse.ArgumentParser()
    parser.add_argument('--collection-metadata',action='store_true',help='also require exact bounded reads of independently published stock-peer metadata; no domain collection')
    args=parser.parse_args()
    os.chdir(ROOT);os.umask(0o077)
    private=ROOT/".private"/("ftps-client-"+uuid.uuid4().hex);private.mkdir(mode=0o700)
    estate,home,inbox,empty=receiver_directories()
    user="freightctl_ftp_"+uuid.uuid4().hex[:10]
    pam_name="freightctl_ftp_"+uuid.uuid4().hex[:12]
    pam=Path("/etc/pam.d")/pam_name
    receiver=ROOT/".cache/freightctl-vsftpd-3.0.5/root/usr/sbin/vsftpd"
    binary=private/"freightctl"
    steps=[];processes={};cleanup=[];probe_failures=[];created_user=False;created_pam=False;audit_paths={}
    env=dict(os.environ,GOMAXPROCS="1",GOMEMLIMIT="192MiB")
    traced=os.environ.get("FREIGHTCTL_FTPS_TRACE")=="1"
    library_profile=os.environ.get("FREIGHTCTL_FTPS_LIBRARY","system")
    if library_profile not in {"system","no-ktls"}:raise RuntimeError("unknown receiver library profile")
    library_base=ROOT/".cache/freightctl-openssl-3.5.9-no-ktls"
    library_dir=library_base/"prefix/lib" if library_profile=="no-ktls" else None
    names=sorted(set(subprocess.check_output(["git","ls-files","--cached","--others","--exclude-standard","-z"]).decode().split("\0"))-{ "" })
    sources={n:digest(ROOT/n) for n in names}
    manifest={"schema_version":1,"kind":"native-ftps-client-stock-receiver","state":"failed","starting_commit":subprocess.check_output(["git","rev-parse","HEAD"]).decode().strip(),"architecture":platform.machine(),"source_sha256":sources,"receiver_traced":traced,"inference_performed":False,"scanner_started":False,"postgres_started":False,"domain_delivery_qualified":False,"full_journeys_qualified":False}
    manifest["receiver_library_profile"]=library_profile
    manifest['collection_metadata_requested']=args.collection_metadata

    def command(label,argv,timeout=60,input_bytes=None,expected_code=0):
        out,err=private/(label+".stdout"),private/(label+".stderr")
        with out.open("xb") as stdout,err.open("xb") as stderr:
            try:r=subprocess.run(list(map(str,argv)),input=input_bytes,stdout=stdout,stderr=stderr,env=env,timeout=timeout);code=r.returncode
            except subprocess.TimeoutExpired:code="timeout"
            stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
        steps.append({"name":label,"exit_code":code,"stdout_sha256":digest(out),"stderr_sha256":digest(err)})
        if code!=expected_code:raise RuntimeError(label+" failed;protected original output retained")
        return out.read_bytes()
    def stop(label):
        process,out,err=processes.pop(label)
        if process.poll() is None:process.stdin.write(b"stop\n");process.stdin.flush()
        try:code=process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo","kill","-KILL","--","-"+str(process.pid)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);process.wait(timeout=5);code="forced";cleanup.append(label+" forced cleanup")
        out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno());out.close();err.close()
        process.stdin.close()
        if code!=0:cleanup.append(label+" unexpected stop")
        steps.append({"name":label,"exit_code":code,"stdout_sha256":digest(private/(label+".stdout")),"stderr_sha256":digest(private/(label+".stderr"))})
    try:
        if subprocess.run(["id","-u",user],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0 or pam.exists():raise RuntimeError("task account or PAM service collision")
        command("go-version",["sh","scripts/go.sh","version"])
        command("receiver-version",["sh","-c",'exec "$1" -v 0>&1',"freightctl-receiver-version",receiver])
        command("receiver-library-versions",["dpkg-query","--show","--showformat=${Package} ${Version} ${Architecture}\n","libssl3t64","libpam0g","libwrap0"])
        if library_dir is not None:
            library_manifest=json.loads((library_base/"manifest.json").read_text())
            if library_manifest.get("state")!="passed" or library_manifest.get("source_sha256")!="603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a":raise RuntimeError("receiver TLS build incomplete")
            manifest["receiver_library_manifest_sha256"]=digest(library_base/"manifest.json")
            command("selected-library-version",["env","LD_LIBRARY_PATH="+str(library_dir),library_base/"prefix/bin/openssl","version","-a"])
            command("selected-library-linkage",["env","LD_LIBRARY_PATH="+str(library_dir),"ldd",receiver])
        command("build",["sh","scripts/go.sh","build","-p","1","-trimpath","-buildvcs=false","-o",binary,"./cmd/freightctl"],180)
        manifest["binary_sha256"]=digest(binary);manifest["receiver_sha256"]=digest(receiver)
        token,cert,key=private/"password",private/"cert.pem",private/"key.pem"
        command("token",[binary,"token","--token-file",token]);command("certificate",[binary,"dev-cert","--cert",cert,"--key",key])
        command("create-exact-user",["sudo","useradd","--no-create-home","--home-dir",home,"--shell","/usr/sbin/nologin",user]);created_user=True
        command("set-exact-password",["sudo","chpasswd"],input_bytes=user.encode()+b":"+token.read_bytes()+b"\n")
        command("own-exact-inbox",["sudo","chown",user+":"+user,inbox])
        if args.collection_metadata:
            command('seed-source-metadata',['sudo','python3','-c',stock_metadata.SEED,inbox,user])
        pam_source=private/"pam.conf";pam_source.write_text("auth required pam_unix.so\naccount required pam_unix.so\n")
        command("create-exact-pam",["sudo","install","--mode=0600",pam_source,pam]);created_pam=True
        users=private/"allowed-users";users.write_text(user+"\n")
        openssl=private/"openssl.conf"
        openssl.write_text("config_diagnostics=1\nopenssl_conf=freightctl_init\n[freightctl_init]\nssl_conf=freightctl_ssl\n[freightctl_ssl]\nsystem_default=freightctl_tls\n[freightctl_tls]\nMinProtocol=TLSv1.3\nMaxProtocol=TLSv1.3\nOptions=-KTLS\n")
        references={}
        for implicit in (False,True):
            mode="implicit" if implicit else "explicit"
            with socket.socket() as probe:probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
            config={"listen":"YES","listen_ipv6":"NO","listen_address":"127.0.0.1","listen_port":str(port),"background":"NO","anonymous_enable":"NO","local_enable":"YES","write_enable":"YES","chroot_local_user":"YES","allow_writeable_chroot":"NO","local_root":str(home),"secure_chroot_dir":str(empty),"pam_service_name":pam_name,"userlist_enable":"YES","userlist_deny":"NO","userlist_file":str(users),"ssl_enable":"YES","ssl_tlsv1":"NO","ssl_tlsv11":"NO","ssl_tlsv12":"NO","ssl_tlsv13":"YES","ssl_sslv2":"NO","ssl_sslv3":"NO","ssl_request_cert":"NO","force_local_logins_ssl":"YES","force_local_data_ssl":"YES","require_ssl_reuse":"YES","strict_ssl_read_eof":"YES","strict_ssl_write_shutdown":"YES","rsa_cert_file":str(cert),"rsa_private_key_file":str(key),"implicit_ssl":"YES" if implicit else "NO","pasv_enable":"YES","port_enable":"NO","pasv_address":"127.0.0.1","pasv_min_port":"40000","pasv_max_port":"40100","max_clients":"4","max_per_ip":"4","idle_session_timeout":"30","data_connection_timeout":"15","accept_timeout":"5","connect_timeout":"5","local_umask":"077","file_open_mode":"0600","seccomp_sandbox":"YES","log_ftp_protocol":"NO"}
            # Stock transfer auditing also selects the daemon's existing
            # getrandom allowance. Retain its filter and strong OS entropy.
            audit_paths[mode]=private/(mode+'.xferlog')
            config.update(xferlog_enable='YES',dual_log_enable='NO',xferlog_std_format='YES',xferlog_file=str(audit_paths[mode]))
            # The actual parser uses ssl_tlsv11/12/13 (without a second
            # underscore). Keep the independent OpenSSL floor and alert probes.
            path=private/(mode+".conf");path.write_text("".join(k+"="+v+"\n" for k,v in config.items()))
            # vsftpd requires the launching uid to own its config. The containing
            # private directory stays0700;0644 lets the independent reporter read.
            path.chmod(0o644)
            command(mode+"-config-owner",["sudo","chown","root:root",path])
            out,err=(private/(mode+"-receiver.stdout")).open("xb"),(private/(mode+"-receiver.stderr")).open("xb")
            argv=["sudo","python3","-c",SUPERVISOR,openssl,str(library_dir) if library_dir is not None else "",receiver,path]
            if traced:
                trace=private/(mode+"-receiver.trace");trace.touch(mode=0o600,exist_ok=False)
                # Trace raw numeric syscall arguments (pointers,not decoded
                # buffers/strings),so a seccomp-killed call is not filtered out.
                argv=["sudo","python3","-c",SUPERVISOR,openssl,str(library_dir) if library_dir is not None else "","strace","-f","-n","-e","raw=all","-o",trace,receiver,path]
            process=subprocess.Popen(list(map(str,argv)),stdin=subprocess.PIPE,stdout=out,stderr=err,env=env,start_new_session=True);processes[mode+"-receiver"]=(process,out,err)
            deadline=time.monotonic()+10
            while True:
                if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError(mode+" receiver did not start")
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2):break
                except OSError:time.sleep(.05)
            references[mode]={"address":"127.0.0.1:"+str(port),"server_name":"localhost","mode":mode,"user":user,"ca_reference":str(cert),"ca_sha256":digest(cert),"password_reference":str(token),"password_sha256":digest(token)}
            probe=["openssl","s_client","-connect","127.0.0.1:"+str(port),"-servername","localhost","-verify_hostname","localhost","-verify_return_error","-CAfile",cert,"-tls1_2","-brief"]
            if not implicit:probe.extend(["-starttls","ftp"])
            label=mode+"-refuse-tls12"
            try:
                command(label,probe,timeout=10,input_bytes=b"",expected_code=1)
                refusal=(private/(label+".stderr")).read_bytes()
                if b"alert protocol version" not in refusal or b"SSL alert number 70" not in refusal:probe_failures.append(label)
            except RuntimeError:probe_failures.append(label)
            # Keep the failed probe red while observing independent client and
            # receiver byte gates. Passing transfers cannot erase this failure.
        if args.collection_metadata:references['collection_metadata']=True
        reference=private/"receiver.json";reference.write_text(json.dumps(references));env["FREIGHTCTL_FTPS_RECEIVER_FILE"]=str(reference)
        native=command("native-stock-receiver",["sh","scripts/go.sh","test","-p","1","-tags=ftpspeer","-race","-count=1","-timeout=120s","-v","-run","^TestNativeStockReceiver$","./internal/ftpsclient"],150).decode()
        passed=re.findall(r"^\s*--- PASS: (\S+) \(",native,re.MULTILINE)
        if set(passed)!={"TestNativeStockReceiver","TestNativeStockReceiver/explicit","TestNativeStockReceiver/implicit"} or len(passed)!=3 or "--- FAIL:" in native or "--- SKIP:" in native:raise RuntimeError("complete stock receiver profile did not execute")
        observer_code="import pathlib,hashlib,json,sys;p=pathlib.Path(sys.argv[1]);data=b'account,amount,day\\n'+b'0001,1.01,2026-10-28\\n'*10000;out={};\nfor mode in ('explicit','implicit'):\n for suffix in ('final.csv','resume.csv','empty'):\n  name=mode+'-'+suffix;b=(p/name).read_bytes();expected=b'' if suffix=='empty' else data;assert b==expected;out[name]={'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}\nprint(json.dumps(out))"
        observed=json.loads(command("independent-receiver-files",["sudo","python3","-c",observer_code,inbox]))
        if len(observed)!=6:raise RuntimeError("independent receiver file closure differs")
        if args.collection_metadata:
            command('independent-source-metadata',['sudo','python3','-c',stock_metadata.OBSERVE,inbox])
            manifest['collection_metadata']=stock_metadata.validate(private,stock_metadata.read_original)
        manifest["receiver_files"]=observed;manifest["native_pass_records"]=3;manifest["state"]="failed" if probe_failures else "passed"
    except Exception as error:
        manifest["failure"]=str(error)
    finally:
        for name in list(processes):
            try:stop(name)
            except Exception:cleanup.append(name+" cleanup failed")
        if len(audit_paths)==2:
            try:
                program="from pathlib import Path;import json,sys;from scripts.ftps_receiver_witness import seal_transfer_logs;print(json.dumps(seal_transfer_logs({'explicit':Path(sys.argv[3]),'implicit':Path(sys.argv[4])},int(sys.argv[1]),int(sys.argv[2]))))"
                manifest['receiver_audit_logs']=json.loads(command('receiver-audit-logs',['sudo','python3','-c',program,os.getuid(),os.getgid(),audit_paths['explicit'],audit_paths['implicit']]))
                if manifest['state']=='passed' and any(v['line_records']<1 for v in manifest['receiver_audit_logs'].values()):raise RuntimeError('receiver audit records missing')
            except Exception:cleanup.append('receiver audit log custody failed')
        if created_user:
            try:command("remove-exact-user",["sudo","userdel",user]);manifest["task_user_removed"]=True
            except Exception:cleanup.append("task user retained")
        if created_pam:
            try:command("remove-exact-pam",["sudo","rm","--",pam]);manifest["task_pam_removed"]=True
            except Exception:cleanup.append("task PAM retained")
        manifest["cleanup_failures"]=cleanup;manifest["probe_failures"]=probe_failures;manifest["sources_unchanged"]=all(digest(ROOT/n)==sha for n,sha in sources.items());manifest["steps"]=steps
        if traced:manifest["trace_sha256"]={mode:digest(private/(mode+"-receiver.trace")) for mode in ("explicit","implicit") if (private/(mode+"-receiver.trace")).exists()}
        if cleanup or not manifest["sources_unchanged"]:manifest["state"]="failed"
        if traced:manifest["state"]="diagnostic"
        path=private/"manifest.json"
        with path.open("x") as output:json.dump(manifest,output,indent=2);output.write("\n");output.flush();os.fsync(output.fileno())
        fd=os.open(private,os.O_RDONLY);os.fsync(fd);os.close(fd)
    print(json.dumps({"state":manifest["state"],"manifest_reference":str(path.relative_to(ROOT)),"manifest_sha256":digest(path)}))
    return 0 if manifest["state"]=="passed" else 1


if __name__=="__main__":raise SystemExit(main())
