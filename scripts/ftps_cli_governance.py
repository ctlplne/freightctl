"""Actual CLI changes coordinated with a TLS client stand-in, plus proof checks.

Only fixed task-owned commands run. Credentials stay in protected references.
The reporter reopens original outputs; a claimed case count is insufficient.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
import uuid

CASES = ["rotate-open-writer", "revoke-open-writer", "held-upload", "passed-still-unreleased", "exact-release", "policy-revoked-read"]
GOOD_CSV = b"account,amount,day\n0001,1.01,2026-10-28\n"
BAD_CSV = b"account,amount,day\n0001,invalid,2026-10-28\n"
COMMANDS = [
    "credential-owner-token", "credential-old-token", "credential-next-token", "credential-enroll",
    "credential-account-create", "credential-original-stat", "credential-other-partner-refused", "credential-page-zero-refused", "credential-page-overflow-refused", "credential-account-rotate", "credential-rotate-replay",
    "credential-old-identity-refused", "credential-rotated-identity", "credential-rotated-stat",
    "credential-page-one", "credential-page-two", "credential-account-revoke", "credential-revoke-replay",
    "credential-revoked-identity-refused", "credential-final-stat", "credential-final-account", "credential-peer",
    "intake-owner-token", "intake-enroll", "intake-policy-register", "intake-check-list", "intake-good-held",
    "intake-bad-held", "intake-held-list", "intake-held-stat-refused", "intake-good-run", "intake-bad-run",
    "intake-good-passed", "intake-bad-rejected", "intake-wrong-release-refused", "intake-bad-release-refused",
    "intake-good-release", "intake-release-replay", "intake-published-stat", "intake-bad-stat-refused",
    "intake-policy-status", "intake-policy-revoke", "intake-policy-replay", "intake-peer",
]
REFUSALS = {
    "credential-other-partner-refused": b"freightctl: unauthorized\n",
    "credential-page-zero-refused": b"freightctl: namespace page limit must be between 1 and 100\n",
    "credential-page-overflow-refused": b"freightctl: namespace page limit must be between 1 and 100\n",
    "credential-old-identity-refused": b"freightctl: unauthorized\n",
    "credential-revoked-identity-refused": b"freightctl: unauthorized\n",
    "intake-held-stat-refused": b"freightctl: not found\n",
    "intake-wrong-release-refused": b"freightctl: resource revision changed\n",
    "intake-bad-release-refused": b"freightctl: operation does not match the current resource state\n",
    "intake-bad-stat-refused": b"freightctl: not found\n",
}


def command_suffix(name):
    match = re.fullmatch(r"cli-(?:explicit|implicit)-gov-(.+)", name)
    return match[1] if match and match[1] in COMMANDS else None


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path, limit=1 << 20):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= limit, "unsafe governance output")
    return path.read_bytes()


def verify_outcome(name, code, stderr, stdout=b""):
    suffix = command_suffix(name)
    expected = 1 if suffix in REFUSALS else 0
    require(type(code) is int and code == expected, "CLI governance command outcome differs")
    if suffix in REFUSALS:
        require(stderr == REFUSALS[suffix] and stdout == b"", "CLI refusal category or empty result differs")


def validate_outputs(private, mode):
    """Check relationships in actual CLI receipts, read models and peer streams."""
    prefix = "cli-" + mode + "-gov-"
    def output(name):
        return json.loads(read(private / (prefix + name + ".stdout")))
    def replay(first, again):
        a, b = output(first), output(again)
        require(b.get("replayed") is True, "CLI replay did not recover a saved receipt")
        require({k: v for k, v in a.items() if k != "replayed"} == {k: v for k, v in b.items() if k != "replayed"}, "CLI replay changed the committed result")
    created = output("credential-account-create")["account"]
    rotated = output("credential-account-rotate")["account"]
    revoked = output("credential-account-revoke")["account"]
    require(created.get("id") == rotated.get("id") == revoked.get("id") and re.fullmatch(r"[0-9a-f-]{36}", created.get("id", "")), "CLI account identity changed")
    for account, revision, state in ((created, 1, "active"), (rotated, 2, "active"), (revoked, 3, "revoked")):
        require(account.get("revision") == account.get("authority_revision") == revision and account.get("state") == state and account.get("changed_event_id"), "CLI lifecycle revision/event differs")
    identity = output("credential-rotated-identity")
    require(identity.get("actor_id") == created["id"] and identity.get("authority_revision") == 2, "CLI rotated identity differs")
    # ObservedAt is query time; committed account identity/state must match.
    require({k: v for k, v in output("credential-final-account").items() if k != "observed_at"} == {k: v for k, v in revoked.items() if k != "observed_at"}, "CLI account read model differs")
    for first, again in (("credential-account-rotate", "credential-rotate-replay"), ("credential-account-revoke", "credential-revoke-replay"), ("intake-good-release", "intake-release-replay"), ("intake-policy-revoke", "intake-policy-replay")):
        replay(first, again)
    original = output("credential-original-stat")
    require(original.get("file_id") and original.get("revision", 0) >= 1, "CLI did not inspect an accepted revision")
    require(original == output("credential-rotated-stat") == output("credential-final-stat"), "invalidated writer changed the original CLI path view")
    one, two = output("credential-page-one"), output("credential-page-two")
    require(len(one.get("entries", [])) == len(two.get("entries", [])) == 1 and one.get("next") and not two.get("next"), "CLI namespace pagination differs")
    require({e["path"] for page in (one, two) for e in page["entries"]} == {"/guard.bin", "/rotated-accepted.bin"}, "CLI namespace page omitted or repeated a path")
    require(not output("intake-held-list").get("entries"), "CLI listed held uploads")
    checks = output("intake-check-list")["checks"]
    require(len(checks) == 2 and {c.get("path") for c in checks} == {"/good.csv", "/bad.csv"} and all(c.get("state") == "held" for c in checks), "CLI intake inventory differs")
    ids = {c["path"]: c["file_id"] for c in checks}
    for name, path, payload in (("intake-good-held", "/good.csv", GOOD_CSV), ("intake-bad-held", "/bad.csv", BAD_CSV)):
        held = output(name)["check"]
        require(held.get("state") == "held" and held.get("file_id") == ids[path] and held["binding"]["file"]["sha256"] == hashlib.sha256(payload).hexdigest(), "CLI hold was not bound to the uploaded revision")
    good, bad = output("intake-good-passed")["check"], output("intake-bad-rejected")["check"]
    require(good.get("file_id") == ids["/good.csv"] and good.get("state") == "passed" and good.get("attempts") == 1 and good.get("code") == "valid_csv" and re.fullmatch(r"[0-9a-f]{64}", good.get("report_hash", "")), "CLI good check did not pass")
    require(bad.get("file_id") == ids["/bad.csv"] and bad.get("state") == "rejected" and bad.get("attempts") == 1 and bad.get("code") == "invalid_cell" and not bad.get("report_hash"), "CLI rejected check gained a release proof")
    policy = output("intake-policy-register")["resource"]
    require(good.get("policy_hash") == bad.get("policy_hash") == policy.get("definition_hash"), "CLI checks used another policy")
    published = output("intake-published-stat")
    require(published.get("file_id") == ids["/good.csv"], "CLI published another immutable revision")
    require(output("intake-policy-revoke")["resource"].get("state") == "revoked", "CLI policy was not revoked")
    for name, states, count in (("credential-peer", ["writer-open-before-rotation", "writer-open-before-revocation", "passed"], 2), ("intake-peer", ["uploads-held", "passed-still-unreleased", "only-approved-revision-published", "passed"], 4)):
        messages = [json.loads(line) for line in read(private / (prefix + name + ".stdout"), 16 << 10).splitlines()]
        require([m.get("state") for m in messages] == states and messages[-1].get("case_count") == count and messages[-1].get("all_data_resumed") is True, "actual governance wire phases are missing")
        if name == "credential-peer":
            require(all(m.get("resumed") is True for m in messages[:-1]), "open writer did not resume its control")
    return {"state": "passed", "cases": CASES, "cli_commands": len(COMMANDS), "expected_refusals": len(REFUSALS)}


class Peer:
    def __init__(self, private, label, settings, env, steps, bounded_output):
        self.private, self.label, self.steps = private, label, steps
        ref = private / (label + ".json")
        with ref.open("x") as f:
            json.dump(settings, f)
        self.stdout = (private / (label + ".stdout")).open("xb")
        self.stderr = (private / (label + ".stderr")).open("xb")
        self.process = subprocess.Popen(["python3", "scripts/ftps-governance-probe.py", "--reference", str(ref)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, env=env, start_new_session=True, preexec_fn=bounded_output)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer, self.total, self.recorded = b"", 0, False

    def next(self, expected):
        deadline = time.monotonic() + 10
        while b"\n" not in self.buffer:
            require(time.monotonic() < deadline, "governance peer phase deadline exceeded")
            if not self.selector.select(max(0, deadline - time.monotonic())):
                continue
            chunk = os.read(self.process.stdout.fileno(), 4096)
            require(bool(chunk), "governance peer ended before its phase")
            self.total += len(chunk)
            require(self.total <= 16 << 10, "governance peer output exceeded bound")
            self.stdout.write(chunk)
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        require(len(line) <= 2048, "governance peer line exceeded bound")
        message = json.loads(line)
        require(message.get("state") == expected, "governance wire phase failed: " + expected)
        return message

    def send(self, action):
        self.process.stdin.write(json.dumps({"action": action}).encode() + b"\n")
        self.process.stdin.flush()

    def close(self, success=False):
        if self.recorded:
            return
        self.recorded = True
        if not success and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
            code = "forced"
        self.process.stdin.close()
        for _ in range(5):
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                break
            self.total += len(chunk)
            require(self.total <= 16 << 10, "governance peer output exceeded bound")
            self.stdout.write(chunk)
        self.selector.close()
        self.process.stdout.close()
        self.stdout.flush(); self.stderr.flush(); os.fsync(self.stdout.fileno()); os.fsync(self.stderr.fileno())
        self.stdout.close(); self.stderr.close()
        self.steps.append({"name": self.label, "exit_code": code, "stdout_sha256": hashlib.sha256((self.private / (self.label + ".stdout")).read_bytes()).hexdigest(), "stderr_sha256": hashlib.sha256((self.private / (self.label + ".stderr")).read_bytes()).hexdigest()})
        if success:
            require(code == 0, "governance peer did not finish normally")


def exercise(private, mode, port, cert, binary, env, steps, command, bounded_output):
    prefix = "cli-" + mode + "-gov-"
    peers = []
    def run(label, argv):
        raw = command(prefix + label, argv, 10)
        return json.loads(raw) if raw else None
    def request(label, data):
        path = private / (prefix + label + ".json")
        with path.open("x") as f:
            json.dump(data, f)
        return path
    def scope(kind):
        tenant, partner = str(uuid.uuid4()), str(uuid.uuid4())
        token = private / (prefix + kind + ".token")
        run(kind + "-owner-token", [binary, "token", "--token-file", token])
        run(kind + "-enroll", [binary, "enroll", "--admin-dsn-file", private / "pg-admin.dsn", "--tenant", tenant, "--partner", partner, "--token-file", token])
        args = ["--dsn-file", private / "pg-runtime.dsn", "--token-file", token, "--tenant", tenant, "--partner", partner, "--storage", private / "custody"]
        settings = {"port": port, "implicit": mode == "implicit", "certificate": str(cert), "username": tenant + "/" + partner, "password": token.read_text()}
        return token, args, settings
    try:
        owner, base, settings = scope("credential")
        old, new = private / (prefix + "old.token"), private / (prefix + "next.token")
        for label, path in (("credential-old-token", old), ("credential-next-token", new)):
            run(label, [binary, "token", "--token-file", path])
        account_id = str(uuid.uuid4())
        create = request("create", {"operation": "create", "account_id": account_id, "policy": {"label": "CLI FTPS writer", "permissions": ["read", "write", "list"], "namespace_root": "/"}})
        run("credential-account-create", [binary, "account-create", *base, "--request-file", create, "--idempotency-key", "create", "--new-token-file", old])
        peer = Peer(private, prefix + "credential-peer", dict(settings, scenario="credential-lifecycle", password=old.read_text(), next_password=new.read_text(), observer_password=owner.read_text()), env, steps, bounded_output)
        peers.append(peer)
        require(peer.next("writer-open-before-rotation").get("resumed") is True, "open writer data was not resumed")
        run("credential-original-stat", [binary, "namespace-stat", *base, "--path", "/guard.bin"])
        run("credential-other-partner-refused", [binary, "namespace-stat", *base, "--path", "/guard.bin", "--partner", str(uuid.uuid4())])
        for label, limit in (("credential-page-zero-refused", "0"), ("credential-page-overflow-refused", "101")):
            run(label, [binary, "namespace-list", *base, "--path", "/", "--path-limit", limit])
        rotate = request("rotate", {"operation": "rotate", "account_id": account_id, "expected_revision": 1})
        argv = [binary, "account-rotate", *base, "--request-file", rotate, "--idempotency-key", "rotate", "--new-token-file", new]
        run("credential-account-rotate", argv); run("credential-rotate-replay", argv)
        run("credential-old-identity-refused", [binary, "identity", *base, "--token-file", old])
        run("credential-rotated-identity", [binary, "identity", *base, "--token-file", new])
        peer.send("rotation-committed")
        require(peer.next("writer-open-before-revocation").get("resumed") is True, "rotated writer data was not resumed")
        run("credential-rotated-stat", [binary, "namespace-stat", *base, "--path", "/guard.bin"])
        page = run("credential-page-one", [binary, "namespace-list", *base, "--path", "/", "--path-limit", "1"])
        run("credential-page-two", [binary, "namespace-list", *base, "--path", "/", "--path-limit", "1", "--path-after", page["next"]])
        revoke = request("revoke", {"operation": "revoke", "account_id": account_id, "expected_revision": 2})
        argv = [binary, "account-revoke", *base, "--request-file", revoke, "--idempotency-key", "revoke"]
        run("credential-account-revoke", argv); run("credential-revoke-replay", argv)
        run("credential-revoked-identity-refused", [binary, "identity", *base, "--token-file", new])
        peer.send("revocation-committed"); peer.next("passed"); peer.close(success=True)
        run("credential-final-stat", [binary, "namespace-stat", *base, "--path", "/guard.bin"])
        run("credential-final-account", [binary, "account-status", *base, "--account-id", account_id])

        _, base, settings = scope("intake")
        policy = {"schema_version": 1, "kind": "csv", "max_bytes": 1024, "max_rows": 10, "max_record_bytes": 128, "timeout_seconds": 2, "columns": [{"name": "account", "type": "text", "required": True, "max_bytes": 16}, {"name": "amount", "type": "decimal", "required": True, "max_bytes": 16, "precision": 12, "scale": 2}, {"name": "day", "type": "date", "required": True, "max_bytes": 10}]}
        policy_ref = request("policy", {"definition": policy})
        run("intake-policy-register", [binary, "intake-policy-register", *base, "--request-file", policy_ref, "--idempotency-key", "policy"])
        peer = Peer(private, prefix + "intake-peer", dict(settings, scenario="intake"), env, steps, bounded_output)
        peers.append(peer); peer.next("uploads-held")
        page = run("intake-check-list", [binary, "check-list", *base, "--check-limit", "10"])
        ids = {c["path"]: c["file_id"] for c in page["checks"]}
        for name, path in (("good", "/good.csv"), ("bad", "/bad.csv")):
            run("intake-" + name + "-held", [binary, "check-status", *base, "--file-id", ids[path]])
        run("intake-held-list", [binary, "namespace-list", *base, "--path", "/", "--path-limit", "100"])
        run("intake-held-stat-refused", [binary, "namespace-stat", *base, "--path", "/good.csv"])
        for name, path in (("good", "/good.csv"), ("bad", "/bad.csv")):
            run("intake-" + name + "-run", [binary, "check-run", *base, "--file-id", ids[path], "--idempotency-key", "run-" + name])
        good = run("intake-good-passed", [binary, "check-status", *base, "--file-id", ids["/good.csv"]])["check"]
        bad = run("intake-bad-rejected", [binary, "check-status", *base, "--file-id", ids["/bad.csv"]])["check"]
        def decision(c):
            return {"sha256": c["binding"]["file"]["sha256"], "policy_hash": c["policy_hash"], "report_hash": c["report_hash"], "expected_revision": c["revision"]}
        d = decision(good)
        wrong = request("wrong-release", dict(d, sha256="0" * 64))
        run("intake-wrong-release-refused", [binary, "check-release", *base, "--file-id", good["file_id"], "--request-file", wrong, "--idempotency-key", "wrong-release"])
        wrong = request("bad-release", dict(decision(bad), report_hash=d["report_hash"]))
        run("intake-bad-release-refused", [binary, "check-release", *base, "--file-id", bad["file_id"], "--request-file", wrong, "--idempotency-key", "bad-release"])
        peer.send("checks-completed"); peer.next("passed-still-unreleased")
        release = request("release", d)
        argv = [binary, "check-release", *base, "--file-id", good["file_id"], "--request-file", release, "--idempotency-key", "release"]
        run("intake-good-release", argv); run("intake-release-replay", argv)
        peer.send("release-committed"); peer.next("only-approved-revision-published")
        run("intake-published-stat", [binary, "namespace-stat", *base, "--path", "/good.csv"])
        run("intake-bad-stat-refused", [binary, "namespace-stat", *base, "--path", "/bad.csv"])
        policy = run("intake-policy-status", [binary, "intake-policy-status", *base])
        revoke = request("policy-revoke", {"definition_hash": policy["definition_hash"], "expected_version": policy["version"], "expected_revision": policy["revision"]})
        argv = [binary, "intake-policy-revoke", *base, "--request-file", revoke, "--idempotency-key", "revoke-policy"]
        run("intake-policy-revoke", argv); run("intake-policy-replay", argv)
        peer.send("policy-revocation-committed"); peer.next("passed"); peer.close(success=True)
        return validate_outputs(private, mode)
    finally:
        for peer in peers:
            peer.close()
