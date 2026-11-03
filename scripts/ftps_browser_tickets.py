"""Browser-created FTPS tickets across an exact task-owned server process crash.

Original browser requests, responses, DOM readings, audits, CLI observations and
the independent TLS peer's bytes are reopened. Synthetic records do not qualify
runtime behavior; the native GitHub browser profile is required.
"""
import hashlib
import json
import re
import time
import uuid

import ftps_cli_governance as governance
import ftps_ticket_governance as tickets

require, read = governance.require, governance.read
AUDITS = ["ticket-prepared", "ticket-checkpoint", "ticket-restarted", "ticket-receipt", "ticket-release-review", "ticket-released"]
PHASES = ["checkpoint-committed", "server-restarted", "completion-committed", "ticket-held", "retrieval-verified"]
NODE_STATES = ["ticket-prepared", "ticket-checkpoint-inspected", "ticket-restart-inspected", "ticket-receipt-inspected", "ticket-release-committed", "passed"]
STAGES = {"prepare", "checkpoint", "restart", "receipt", "release", "finished"}
COMMANDS = ["owner-token", "foreign-token", "enroll", "foreign-enroll", "policy-register", "checkpoint", "completed", "released", "published", "crash", "restarted", "browser", "peer"]
RESPONSES = {"create-0":201, "create-1":200, "checkpoint":200, "restarted-list":200, "restarted":200,
             "foreign-list":200, "foreign-status":404, "completed-list":200, "completed":200,
             "held":200, "check-run":200, "checked":200, "release-0":200, "release-1":200}


def verify_http_outcome(label,status,body):
    require(label in RESPONSES and type(status) is int and status==RESPONSES[label], "browser ticket HTTP outcome differs")
    if label=="foreign-status":
        require(json.loads(body)=={"error":"not_found"}, "browser ticket foreign authority refusal differs")


def verify_saved_replay(first,second):
    a,b=first,second
    require(a[0].get("idempotency_key") and a[0].get("idempotency_key")==b[0].get("idempotency_key")
            and a[0].get("selection")==b[0].get("selection")
            and a[1].get("replayed") is False and b[1].get("replayed") is True
            and dict(a[1],replayed=True)==b[1], "browser ticket lost reply changed meaning or receipt")


def verify_visible_receipt(view,upload):
    expected={"state":upload["state"],"path":"/recovered.csv","expected_size":str(len(tickets.PAYLOAD)),"committed_offset":str(upload["committed_offset"]),"expected_sha256":tickets.SHA256,"sftp_path":"/.freightctl/uploads/"+upload["id"],"ftps_path":"/.freightctl/uploads/"+upload["id"]}
    if upload["state"]=="completed":expected.update(file_id=upload["file_id"],acceptance="Accepted and held for checks and release")
    require(view==expected, "browser ticket visible receipt differs")


def command_suffix(name):
    m = re.fullmatch(r"browser-ticket-(?:explicit|implicit)-(.+)", name)
    if m and (m[1] in COMMANDS or re.fullmatch(r"(?:checkpoint|completed)-poll-[0-4][0-9]", m[1])):
        return m[1]
    return None


def verify_outcome(name, code, stderr, stdout=b""):
    suffix = command_suffix(name)
    if suffix is None:
        return tickets.verify_outcome(name, code, stderr, stdout)
    require(type(code) is int and code == (-9 if suffix == "crash" else 0), "browser ticket command outcome differs")


def validate(private, mode, steps, inventory):
    prefix = "browser-ticket-" + mode + "-"
    directory = private / ("browser-ticket-" + mode)
    names = [s["name"][len(prefix):] for s in steps if s["name"].startswith(prefix)]
    require(len(names) == len(set(names)) and set(COMMANDS) <= set(names)
            and all(command_suffix(prefix+n) for n in names), "browser ticket command closure differs")
    require(isinstance(inventory,dict) and 1 <= len(inventory) <= 100
            and {p.name for p in directory.iterdir()} | {"download"} == set(inventory), "browser ticket file closure differs")
    for name, digest in inventory.items():
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",name), "browser ticket output name differs")
        path=private/(prefix+"download") if name=="download" else directory/name
        require(hashlib.sha256(read(path,4<<20)).hexdigest() == digest, "browser ticket original file changed")
    def output(name):
        return json.loads(read(private / (prefix+name+".stdout")))
    def load(name):
        return json.loads(read(directory/name))
    for step in steps:
        if step["name"].startswith(prefix):
            stdout,stderr=(read(private/(step["name"]+"."+ext)) for ext in ("stdout","stderr"))
            require(hashlib.sha256(stdout).hexdigest()==step["stdout_sha256"]
                    and hashlib.sha256(stderr).hexdigest()==step["stderr_sha256"], "browser ticket command output changed")
            verify_outcome(step["name"],step["exit_code"],stderr,stdout)
    report, cfg = load("result.json"), load("config.json")
    require(cfg == json.loads(read(private/(prefix+"browser.json"))), "browser ticket original configuration differs")
    require(report.get("state")=="passed" and not report.get("failure")
            and report.get("stage")=="finished" and report.get("runtime_errors")==[] and report.get("external_egress")==[]
            and report.get("inference_performed") is False and report.get("scanner_started") is False,
            "browser ticket runtime or scope differs")
    require(report.get("audits")==AUDITS and report.get("commands")==PHASES, "browser ticket operator phases differ")
    for name in AUDITS:
        audit=load(name+"-axe.json")
        require(audit.get("violations")==[] and type(audit.get("passes")) is int and audit["passes"]>0, "browser ticket accessibility differs")
    responses=report.get("responses")
    require(isinstance(responses,list) and [r.get("label") for r in responses]==list(RESPONSES), "browser ticket HTTP inventory differs")
    original={}
    for r in responses:
        label=r["label"]
        request=read(directory/(label+".request"))
        body=read(directory/(label+".response"))
        verify_http_outcome(label,r.get("status"),body)
        require(r.get("body")==body.decode()
                and r.get("selection")== (json.loads(request) if request else None), "browser ticket original HTTP result differs")
        headers=read(directory/(label+".headers")).decode()
        keys=re.findall(r"(?mi)^idempotency-key: ([^\r\n]+)$",headers)
        require(keys==([r["idempotency_key"]] if r.get("idempotency_key") else []), "browser ticket original operation key differs")
        original[label]=(r,json.loads(body))
    tenant,partner=cfg["owner"]["tenant"],cfg["owner"]["partner"]
    base=cfg["url"]+"/v1/tenants/"+tenant+"/partners/"+partner
    ident=report.get("upload_id")
    require(isinstance(ident,str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",ident), "browser ticket identity differs")
    created=original["create-0"][1]["upload"]
    require(created.get("id")==ident and created.get("path")=="/recovered.csv"
            and created.get("expected_size")==len(tickets.PAYLOAD) and created.get("expected_sha256")==tickets.SHA256
            and created.get("committed_offset")==0 and created.get("state")=="open"
            and created.get("sftp_path")==created.get("ftps_path")=="/.freightctl/uploads/"+ident,
            "browser ticket reviewed intent differs")
    def replay(first,second):
        verify_saved_replay(original[first],original[second])
    replay("create-0","create-1")
    require(original["create-0"][0].get("selection")=={"path":"/recovered.csv","expected_size":len(tickets.PAYLOAD),"expected_sha256":tickets.SHA256}, "browser ticket creation selection differs")
    checkpoint=output("checkpoint")
    require(checkpoint==original["checkpoint"][1]==original["restarted"][1]
            and checkpoint.get("id")==ident and checkpoint.get("committed_offset")==65536
            and checkpoint.get("chunk_count")==1 and checkpoint.get("state")=="open", "browser ticket crash changed checkpoint")
    for label in ("restarted-list","completed-list"):
        values=original[label][1].get("uploads",[])
        require(len(values)==1 and values[0].get("id")==ident, "browser ticket reload selected another upload")
    require(original["foreign-list"][1].get("uploads")==[] and original["foreign-status"][1]=={"error":"not_found"}, "browser ticket foreign authority refusal differs")
    completed=output("completed")
    require(completed==original["completed"][1] and completed.get("id")==ident
            and completed.get("state")=="completed" and completed.get("committed_offset")==len(tickets.PAYLOAD)
            and completed.get("acceptance")==tickets.ACCEPTANCE and completed.get("file_id")==report.get("accepted_file_id")
            and completed.get("file_id"), "browser ticket saved acceptance differs")
    file_id=completed["file_id"]
    for phase,target in (("checkpoint",checkpoint),("completed",completed)):
        polls=sorted(n for n in names if n.startswith(phase+"-poll-"))
        require(0<len(polls)<=50 and polls==[phase+"-poll-"+str(i).zfill(2) for i in range(len(polls))]
                and output(polls[-1])==target, "browser ticket poll closure differs")
    urls={"create-0":"/uploads","create-1":"/uploads","checkpoint":"/uploads/"+ident,"restarted":"/uploads/"+ident,"foreign-status":"/uploads/"+ident,"completed":"/uploads/"+ident,
          "restarted-list":"/uploads?limit=50&after=","foreign-list":"/uploads?limit=50&after=","completed-list":"/uploads?limit=50&after=",
          "held":"/checks/"+file_id,"check-run":"/checks/"+file_id+"/run","checked":"/checks/"+file_id,"release-0":"/checks/"+file_id+"/release","release-1":"/checks/"+file_id+"/release"}
    for label,(r,result) in original.items():
        require(r.get("url")==base+urls[label] and r.get("method")== ("POST" if label in {"create-0","create-1","check-run","release-0","release-1"} else "GET"), "browser ticket endpoint or method differs")
    policy=output("policy-register")["resource"]["definition_hash"]
    held,passed=original["held"][1]["check"],original["checked"][1]["check"]
    for check in (held,passed):
        require(check.get("file_id")==file_id and check.get("policy_hash")==policy
                and check["binding"]["file"].get("sha256")==tickets.SHA256
                and check["binding"]["file"].get("size_bytes")==len(tickets.PAYLOAD), "browser ticket check binding differs")
    require(held.get("state")=="held" and passed.get("state")=="passed" and passed.get("attempts")==1
            and passed.get("code")=="valid_csv" and re.fullmatch(r"[0-9a-f]{64}",passed.get("report_hash","")), "browser ticket exact validation differs")
    replay("release-0","release-1")
    selection=original["release-0"][0]["selection"]
    require(selection=={"sha256":tickets.SHA256,"policy_hash":policy,"report_hash":passed["report_hash"],"expected_revision":passed["revision"]}, "browser ticket release selection differs")
    released=original["release-1"][1]["resource"]
    require(released.get("file_id")==file_id and released.get("state")=="released"
            and released.get("revision")==passed["revision"]+1
            and output("released")["check"]["state"]=="released"
            and output("released")["check"]["file_id"]==file_id and output("published").get("file_id")==file_id,
            "browser ticket release receipt differs")
    for label,u in (("prepared",created),("checkpoint",checkpoint),("restarted",checkpoint),("receipt",completed)):
        view=load(label+"-view.json")
        verify_visible_receipt(view,u)
    require(report.get("mutations")==[{"method":"POST","url":base+"/uploads"}]*2, "browser ticket sent unapproved bytes or mutation")
    node=[json.loads(line) for line in read(private/(prefix+"browser.stdout"),16384).splitlines()]
    require([m.get("state") for m in node]==NODE_STATES and node[0].get("id")==ident, "browser ticket controller phases differ")
    peer=[json.loads(line) for line in read(private/(prefix+"peer.stdout"),16384).splitlines()]
    require([m.get("state") for m in peer]==tickets.STATES and peer[-1].get("case_count")==6
            and peer[-1].get("all_data_resumed") is True and peer[0].get("resumed") is True and peer[2].get("resumed") is True
            and read(private/(prefix+"peer.stderr"))==b"", "browser ticket independent wire phases differ")
    settings=json.loads(read(private/(prefix+"peer.json")))
    require(settings.get("username")==tenant+"/"+partner and settings.get("port")==cfg["port"]
            and settings.get("implicit")==cfg["implicit"] and settings.get("certificate")==cfg["certificate"]
            and settings.get("ticket")==created["ftps_path"]
            and settings.get("download_reference")==str(private/(prefix+"download"))
            and settings.get("password")==read(private/(prefix+"owner.token"),64).decode()
            and settings.get("foreign_password")==read(private/(prefix+"foreign.token"),64).decode(), "browser ticket peer binding differs")
    require(read(private/(prefix+"download"))==tickets.PAYLOAD, "browser ticket independently retrieved bytes differ")
    order=[s["name"] for s in steps]
    require(order.index(prefix+"checkpoint")<order.index(prefix+"crash")<order.index(prefix+"completed")<order.index(prefix+"released"), "browser ticket process crash order differs")
    return {"state":"passed","browser_ticket_cases":6,"controlled_sigkills":1,"strict_api_refusals":1,"accessibility_audits":len(AUDITS),"lost_response_replays":2,"original_https_responses":len(RESPONSES),"payload_bytes":len(tickets.PAYLOAD),"payload_sha256":tickets.SHA256}


def exercise(root,private,mode,port,http_port,cert,binary,env,steps,command,bounded_output,crash_restart):
    prefix="browser-ticket-"+mode+"-"
    directory=private/("browser-ticket-"+mode);directory.mkdir(mode=0o700)
    def run(name,argv):
        raw=command(prefix+name,argv,10)
        return json.loads(raw) if raw else None
    tenant,partner=str(uuid.uuid4()),str(uuid.uuid4())
    refs={name:private/(prefix+name+".token") for name in ("owner","foreign")}
    for name,ref in refs.items():
        run(name+"-token",[binary,"token","--token-file",ref])
        run("enroll" if name=="owner" else "foreign-enroll",[binary,"enroll","--admin-dsn-file",private/"pg-admin.dsn","--tenant",tenant,"--partner",partner,"--token-file",ref])
    base=["--dsn-file",private/"pg-runtime.dsn","--token-file",refs["owner"],"--tenant",tenant,"--partner",partner,"--storage",private/"custody"]
    policy={"schema_version":1,"kind":"csv","max_bytes":1<<20,"max_rows":20000,"max_record_bytes":128,"timeout_seconds":5,"columns":[{"name":"account","type":"text","required":True,"max_bytes":16},{"name":"amount","type":"decimal","required":True,"max_bytes":16,"precision":12,"scale":2},{"name":"day","type":"date","required":True,"max_bytes":10}]}
    ref=private/(prefix+"policy.json");ref.write_text(json.dumps({"definition":policy}))
    run("policy-register",[binary,"intake-policy-register",*base,"--request-file",ref,"--idempotency-key","policy"])
    source=private/(prefix+"source.csv");source.write_bytes(tickets.PAYLOAD)
    cfg={"root":str(root),"private":str(directory),"url":"https://127.0.0.1:"+str(http_port),"port":port,"implicit":mode=="implicit","certificate":str(cert),"source":str(source),**{name:{"tenant":tenant,"partner":partner,"token":str(path)} for name,path in refs.items()}}
    browser=governance.Peer(private,prefix+"browser",cfg,env,steps,bounded_output,argv=["node","scripts/ftps-ticket-browser.mjs"],phase_timeout=45)
    peer=None
    try:
        ident=browser.next("ticket-prepared").get("id")
        require(isinstance(ident,str) and re.fullmatch(r"[0-9a-f-]{36}",ident), "browser ticket prepared identity differs")
        status=[binary,"upload-status",*base,"--upload-id",ident]
        def poll(phase,predicate):
            deadline=time.monotonic()+8
            for i in range(50):
                value=run(phase+"-poll-"+str(i).zfill(2),status)
                if predicate(value):return
                require(time.monotonic()<deadline,"browser ticket progress deadline exceeded")
                time.sleep(.05)
            raise ValueError("browser ticket progress bound exceeded")
        settings={"scenario":"upload-ticket","port":port,"implicit":mode=="implicit","certificate":str(cert),"username":tenant+"/"+partner,"password":refs["owner"].read_text(),"foreign_password":refs["foreign"].read_text(),"ticket":"/.freightctl/uploads/"+ident,"download_reference":str(private/(prefix+"download"))}
        peer=governance.Peer(private,prefix+"peer",settings,env,steps,bounded_output)
        peer.next("ticket-checkpoint-open")
        poll("checkpoint",lambda v:v.get("committed_offset")==65536 and v.get("chunk_count")==1)
        run("checkpoint",status)
        browser.send("checkpoint-committed");browser.next("ticket-checkpoint-inspected")
        crash_restart();peer.send("interrupt-now");peer.next("ticket-interrupted")
        browser.send("server-restarted");browser.next("ticket-restart-inspected")
        peer.send("server-restarted");peer.next("ticket-data-finished")
        poll("completed",lambda v:v.get("state")=="completed")
        completed=run("completed",status)
        peer.send("discard-final-reply");peer.next("ticket-final-reply-unobserved")
        browser.send("completion-committed");browser.next("ticket-receipt-inspected")
        peer.send("receipt-inspected");peer.next("ticket-completed-held")
        browser.send("ticket-held");browser.next("ticket-release-committed")
        run("released",[binary,"check-status",*base,"--file-id",completed["file_id"]])
        run("published",[binary,"namespace-stat",*base,"--path","/recovered.csv"])
        peer.send("release-committed");peer.next("passed");peer.close(success=True)
        browser.send("retrieval-verified");browser.next("passed");browser.close(success=True)
    finally:
        if peer:peer.close()
        browser.close()
    inventory={p.name:hashlib.sha256(read(p,4<<20)).hexdigest() for p in directory.iterdir()}
    inventory["download"]=hashlib.sha256(read(private/(prefix+"download"))).hexdigest()
    return inventory
