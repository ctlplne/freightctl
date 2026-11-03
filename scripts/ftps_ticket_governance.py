"""Public CLI/HTTPS control of a real FTPS process-crash recovery.

The peer is a TLS client stand-in, not stock interoperability evidence. Original
command outputs, HTTP bodies and retrieved bytes are reopened by the reporter.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

import ftps_cli_governance as governance

PAYLOAD = b"account,amount,day\n" + b"0001,1.01,2026-10-28\n" * 10000
SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
ACCEPTANCE = "durable-held-pending-checks-and-release"
STATES = ["ticket-checkpoint-open", "ticket-interrupted", "ticket-data-finished",
          "ticket-final-reply-unobserved", "ticket-completed-held", "passed"]
COMMANDS = ["owner-token", "foreign-token", "enroll", "foreign-enroll", "policy-register",
            "create", "create-replay", "checkpoint", "checkpoint-api", "crash", "restarted",
            "after-restart", "after-restart-api", "foreign-refused", "foreign-api",
            "checkpoint-stat-refused", "completed", "completed-api", "receipt-api", "receipt-cli",
            "held", "held-stat-refused", "check-run", "checked", "release", "release-replay",
            "published-stat", "published-list", "peer"]
REFUSALS = {"foreign-refused": b"freightctl: not found\n",
            "checkpoint-stat-refused": b"freightctl: not found\n",
            "held-stat-refused": b"freightctl: not found\n"}
HTTP = {"checkpoint-api": 200, "after-restart-api": 200, "foreign-api": 404,
        "completed-api": 200, "receipt-api": 200}
require = governance.require
read = governance.read


def command_suffix(name):
    m = re.fullmatch(r"ticket-(?:explicit|implicit)-(.+)", name)
    if m and (m[1] in COMMANDS or re.fullmatch(r"(?:checkpoint|completed)-poll-[0-4][0-9]", m[1])):
        return m[1]
    return None


def verify_outcome(name, code, stderr, stdout=b""):
    suffix = command_suffix(name)
    if suffix is None:
        return governance.verify_outcome(name, code, stderr, stdout)
    expected = -9 if suffix == "crash" else 1 if suffix in REFUSALS else 0
    require(type(code) is int and code == expected, "ticket command outcome differs")
    if suffix in REFUSALS:
        require(stderr == REFUSALS[suffix] and stdout == b"", "ticket refusal category differs")
    if suffix in HTTP:
        require(stderr == b"" and stdout == str(HTTP[suffix]).encode(), "ticket HTTP status differs")


def validate(private, mode, steps, inventory):
    prefix = "ticket-" + mode + "-"
    names = [s["name"][len(prefix):] for s in steps if s["name"].startswith(prefix)]
    require(len(names) == len(set(names)) and set(COMMANDS) <= set(names)
            and all(command_suffix(prefix + n) for n in names), "ticket command closure missing")
    expected_files = {prefix + n + ".body" for n in HTTP} | {prefix + "download"}
    require(isinstance(inventory, dict) and set(inventory) == expected_files, "ticket output closure differs")
    for name, digest in inventory.items():
        require(hashlib.sha256(read(private / name)).hexdigest() == digest, "ticket original output changed")
    def output(name):
        return json.loads(read(private / (prefix + name + ".stdout")))
    def api(name):
        return json.loads(read(private / (prefix + name + ".body")))
    for step in steps:
        if step["name"].startswith(prefix):
            raw, err = (read(private / (step["name"] + "." + ext)) for ext in ("stdout", "stderr"))
            require(hashlib.sha256(raw).hexdigest() == step["stdout_sha256"]
                    and hashlib.sha256(err).hexdigest() == step["stderr_sha256"], "ticket command output changed")
            verify_outcome(step["name"], step["exit_code"], err, raw)
    created = output("create")
    ticket = created["upload"]
    ident = ticket["id"]
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", ident)
            and ticket.get("ftps_path") == "/.freightctl/uploads/" + ident
            and ticket.get("sftp_path") == ticket["ftps_path"]
            and ticket.get("path") == "/recovered.csv"
            and ticket.get("expected_size") == len(PAYLOAD) and ticket.get("expected_sha256") == SHA256
            and ticket.get("state") == "open" and ticket.get("committed_offset") == 0
            and ticket.get("chunk_count") == 0 and created.get("replayed") is False, "ticket creation contract differs")
    replay = output("create-replay")
    require(replay.get("replayed") is True and replay["upload"] == ticket, "ticket creation replay differs")
    checkpoint, restarted = output("checkpoint"), output("after-restart")
    require(checkpoint == restarted == api("checkpoint-api") == api("after-restart-api"), "process crash changed durable checkpoint")
    require(checkpoint.get("id") == ident and checkpoint.get("state") == "open"
            and checkpoint.get("committed_offset") == 65536 and checkpoint.get("chunk_count") == 1
            and not checkpoint.get("file_id") and checkpoint.get("expected_sha256") == SHA256, "ticket checkpoint differs")
    # Every poll is retained, bounded, contiguous and ends at its independently
    # inspected target. A success flag cannot hide an omitted final observation.
    for phase, target in (("checkpoint", checkpoint), ("completed", output("completed"))):
        polls = sorted(n for n in names if n.startswith(phase + "-poll-"))
        require(0 < len(polls) <= 50 and polls == [phase + "-poll-" + str(i).zfill(2) for i in range(len(polls))]
                and output(polls[-1]) == target, "ticket poll sequence differs")
    require(api("foreign-api") == {"error": "not_found"}, "foreign API refusal differs")
    completed = output("completed")
    require(completed == api("completed-api") and completed.get("id") == ident
            and completed.get("state") == "completed" and completed.get("committed_offset") == len(PAYLOAD)
            and completed.get("acceptance") == ACCEPTANCE and completed.get("file_id"), "ticket acceptance differs")
    receipt = api("receipt-api")
    require(receipt == output("receipt-cli") and receipt.get("replayed") is True
            and receipt.get("acceptance") == ACCEPTANCE and receipt["upload"] == completed
            and receipt["file"].get("id") == completed["file_id"]
            and receipt["file"].get("sha256") == SHA256
            and receipt["file"].get("size_bytes") == len(PAYLOAD), "lost reply did not recover the original receipt")
    held, checked = output("held")["check"], output("checked")["check"]
    policy = output("policy-register")["resource"]["definition_hash"]
    for c in (held, checked):
        require(c.get("file_id") == completed["file_id"] and c.get("policy_hash") == policy
                and c["binding"]["file"].get("sha256") == SHA256
                and c["binding"]["file"].get("size_bytes") == len(PAYLOAD), "ticket intake byte/policy binding differs")
    require(held.get("state") == "held" and checked.get("state") == "passed"
            and checked.get("attempts") == 1 and checked.get("code") == "valid_csv"
            and re.fullmatch(r"[0-9a-f]{64}", checked.get("report_hash", "")), "ticket validation differs")
    first, replay = output("release"), output("release-replay")
    require(first.get("replayed") is False and replay.get("replayed") is True
            and {k: v for k, v in first.items() if k != "replayed"} == {k: v for k, v in replay.items() if k != "replayed"}, "ticket release replay differs")
    published = output("published-stat")
    require(published.get("file_id") == completed["file_id"]
            and [e.get("file_id") for e in output("published-list").get("entries", [])] == [completed["file_id"]], "ticket recovery published another revision")
    messages = [json.loads(line) for line in read(private / (prefix + "peer.stdout"), 16 << 10).splitlines()]
    require([m.get("state") for m in messages] == STATES
            and messages[0].get("resumed") is True and messages[2].get("resumed") is True
            and messages[-1].get("case_count") == 6 and messages[-1].get("all_data_resumed") is True,
            "ticket wire phases differ")
    require(read(private / (prefix + "download")) == PAYLOAD, "ticket retrieved bytes differ")
    # The exact kill must occur after the live checkpoint, before restarted
    # observations. This is a process failure, never a power-loss/HA claim.
    order = [s["name"] for s in steps]
    require(order.index(prefix + "checkpoint-api") < order.index(prefix + "crash")
            < order.index(prefix + "after-restart") < order.index(prefix + "completed")
            < order.index(prefix + "receipt-api") < order.index(prefix + "release"), "ticket crash/recovery order differs")
    return {"state": "passed", "cases": 6, "process_sigkill": True, "public_cli_and_https": True,
            "payload_bytes": len(PAYLOAD), "payload_sha256": SHA256, "strict_cli_refusals": len(REFUSALS), "strict_api_refusals": 1}


def exercise(private, mode, port, http_port, cert, binary, env, steps, command, bounded_output, crash_restart):
    prefix = "ticket-" + mode + "-"
    def run(label, argv):
        raw = command(prefix + label, argv, 10)
        return json.loads(raw) if raw else None
    def request(label, value):
        ref = private / (prefix + label + ".json")
        with ref.open("x") as f:
            json.dump(value, f)
        return ref
    tenant, partner = str(uuid.uuid4()), str(uuid.uuid4())
    owner, foreign = (private / (prefix + n + ".token") for n in ("owner", "foreign"))
    for label, ref in (("owner", owner), ("foreign", foreign)):
        run(label + "-token", [binary, "token", "--token-file", ref])
        run("enroll" if label == "owner" else "foreign-enroll", [binary, "enroll", "--admin-dsn-file", private / "pg-admin.dsn", "--tenant", tenant, "--partner", partner, "--token-file", ref])
    base = ["--dsn-file", private / "pg-runtime.dsn", "--token-file", owner, "--tenant", tenant, "--partner", partner, "--storage", private / "custody"]
    configs = {}
    for name, token in (("owner", owner), ("foreign", foreign)):
        cfg = private / (prefix + name + ".curl")
        cfg.write_text("header = " + json.dumps("Authorization: Bearer " + token.read_text()) + "\ncacert = " + json.dumps(str(cert)) + '\nnoproxy = "*"\nconnect-timeout = 3\nmax-time = 8\nsilent\nshow-error\n')
        configs[name] = cfg
    policy = {"schema_version": 1, "kind": "csv", "max_bytes": 1 << 20, "max_rows": 20000, "max_record_bytes": 128, "timeout_seconds": 5,
              "columns": [{"name": "account", "type": "text", "required": True, "max_bytes": 16}, {"name": "amount", "type": "decimal", "required": True, "max_bytes": 16, "precision": 12, "scale": 2}, {"name": "day", "type": "date", "required": True, "max_bytes": 10}]}
    run("policy-register", [binary, "intake-policy-register", *base, "--request-file", request("policy", {"definition": policy}), "--idempotency-key", "policy"])
    create = [binary, "upload-create", *base, "--request-file", request("intent", {"path": "/recovered.csv", "expected_size": len(PAYLOAD), "expected_sha256": SHA256}), "--idempotency-key", "ticket"]
    upload = run("create", create)["upload"]
    run("create-replay", create)
    ident = upload["id"]
    status = [binary, "upload-status", *base, "--upload-id", ident]
    url = "https://127.0.0.1:" + str(http_port) + "/v1/tenants/" + tenant + "/partners/" + partner + "/uploads/" + ident
    body_files = []
    def api(label, who="owner", complete=False):
        body = private / (prefix + label + ".body")
        body_files.append(body)
        args = ["curl", "-q", "--config", configs[who], "--max-filesize", "65536", "--output", body, "--write-out", "%{http_code}"]
        if complete:
            args += ["--request", "POST", "--header", "Idempotency-Key: sftp-complete-" + ident]
        raw = command(prefix + label, [*args, url + ("/complete" if complete else "")], 10)
        with body.open("rb") as original:
            os.fsync(original.fileno())
        require(raw == str(HTTP[label]).encode(), "ticket HTTP status differs")
        return json.loads(read(body, 65536))
    def poll(phase, predicate):
        deadline = time.monotonic() + 8
        for i in range(50):
            value = run(phase + "-poll-" + str(i).zfill(2), status)
            if predicate(value):
                return
            require(time.monotonic() < deadline, "ticket progress deadline exceeded")
            time.sleep(.05)
        raise ValueError("ticket progress poll bound exceeded")
    settings = {"scenario": "upload-ticket", "port": port, "implicit": mode == "implicit", "certificate": str(cert),
                "username": tenant + "/" + partner, "password": owner.read_text(), "foreign_password": foreign.read_text(),
                "ticket": upload["ftps_path"], "download_reference": str(private / (prefix + "download"))}
    peer = governance.Peer(private, prefix + "peer", settings, env, steps, bounded_output)
    try:
        peer.next("ticket-checkpoint-open")
        poll("checkpoint", lambda v: v.get("committed_offset") == 65536 and v.get("chunk_count") == 1)
        run("checkpoint", status); api("checkpoint-api")
        crash_restart()  # Exact retained Popen only; peer's writer is still open.
        peer.send("interrupt-now"); peer.next("ticket-interrupted")
        run("after-restart", status); api("after-restart-api")
        run("foreign-refused", [*status, "--token-file", foreign]); api("foreign-api", "foreign")
        run("checkpoint-stat-refused", [binary, "namespace-stat", *base, "--path", "/recovered.csv"])
        peer.send("server-restarted"); peer.next("ticket-data-finished")
        poll("completed", lambda v: v.get("state") == "completed")
        completed = run("completed", status); api("completed-api")
        peer.send("discard-final-reply"); peer.next("ticket-final-reply-unobserved")
        api("receipt-api", complete=True)
        run("receipt-cli", [binary, "upload-complete", *base, "--upload-id", ident, "--idempotency-key", "sftp-complete-" + ident])
        peer.send("receipt-inspected"); peer.next("ticket-completed-held")
        check = ["--file-id", completed["file_id"]]
        run("held", [binary, "check-status", *base, *check])
        run("held-stat-refused", [binary, "namespace-stat", *base, "--path", "/recovered.csv"])
        run("check-run", [binary, "check-run", *base, *check, "--idempotency-key", "check"])
        checked = run("checked", [binary, "check-status", *base, *check])["check"]
        decision = {"sha256": checked["binding"]["file"]["sha256"], "policy_hash": checked["policy_hash"], "report_hash": checked["report_hash"], "expected_revision": checked["revision"]}
        release = [binary, "check-release", *base, *check, "--request-file", request("decision", decision), "--idempotency-key", "release"]
        run("release", release); run("release-replay", release)
        run("published-stat", [binary, "namespace-stat", *base, "--path", "/recovered.csv"])
        run("published-list", [binary, "namespace-list", *base, "--path", "/", "--path-limit", "100"])
        peer.send("release-committed"); peer.next("passed"); peer.close(success=True)
    finally:
        peer.close()
    files = body_files + [private / (prefix + "download")]
    inventory = {p.name: hashlib.sha256(read(p)).hexdigest() for p in files}
    return inventory
