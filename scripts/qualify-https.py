#!/usr/bin/env python3
"""Exercise a real freightctl process using stock curl, without logging credentials."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

os.umask(0o077)
root = Path(__file__).resolve().parents[1]
os.chdir(root)
run_id = "https-" + uuid.uuid4().hex
private = root / ".private" / run_id
private.mkdir(mode=0o700)
raw = root / "evidence/raw" / run_id
raw.mkdir(parents=True, mode=0o700)
binary = root / ".cache/freightctl"
started = time.monotonic()
steps = []
server = None
log = None

def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, **kwargs)
    if result.returncode:
        # Commands contain only secret references; curl never runs verbose.
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {result.stderr.decode(errors='replace')[:1000]}")
    return result.stdout

def cli(*args):
    return command([str(binary), *args])

def stop():
    global server, log
    if server is not None:
        server.terminate()
        try:
            server.wait(timeout=8)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        server = None
    if log is not None:
        log.close()
        log = None

try:
    command(["sh", "scripts/go.sh", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/freightctl"])
    cli("init")
    cert, key = private / "localhost.crt", private / "localhost.key"
    cli("dev-cert", "--cert", str(cert), "--key", str(key))
    tenant, partner = str(uuid.uuid4()), str(uuid.uuid4())
    other_tenant, other_partner = str(uuid.uuid4()), str(uuid.uuid4())
    identities = [(tenant, partner), (tenant, other_partner), (other_tenant, partner)]
    headers = []
    for index, (tid, pid) in enumerate(identities):
        token = private / f"identity-{index}.token"
        cli("token", "--token-file", str(token))
        cli("enroll", "--tenant", tid, "--partner", pid, "--token-file", str(token))
        header = private / f"identity-{index}.headers"
        header.write_bytes(b"Authorization: Bearer " + token.read_bytes() + b"\n")
        headers.append(header)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"https://127.0.0.1:{port}"
    api = base + f"/v1/tenants/{tenant}/partners/{partner}"
    storage = private / "custody"
    def start():
        global server, log
        log = (raw / "server.log").open("ab")
        server = subprocess.Popen([str(binary), "serve", "--listen", f"127.0.0.1:{port}", "--storage", str(storage), "--cert", str(cert), "--key", str(key)], stdout=log, stderr=log)
        for attempt in range(100):
            if server.poll() is not None:
                raise RuntimeError("server exited; inspect retained server.log")
            result = subprocess.run(["curl", "--silent", "--show-error", "--cacert", str(cert), "--max-time", "1", base + "/healthz"], capture_output=True)
            if result.returncode == 0:
                return
            time.sleep(0.05)
        raise RuntimeError("HTTPS health request failed: " + result.stderr.decode(errors="replace")[:1000])
    def curl(label, url, expected, identity=0, extra=()):
        output = raw / (label + ".out")
        args = ["curl", "--silent", "--show-error", "--cacert", str(cert), "--max-time", "15", "--output", str(output), "--write-out", "%{http_code}"]
        if identity is not None:
            args += ["--header", "@" + str(headers[identity])]
        args += list(extra) + [url]
        status = int(command(args).decode())
        if status != expected:
            raise RuntimeError(f"{label}: expected HTTP {expected}, got {status}; see {output.name}")
        steps.append({"name": label, "http_status": status, "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest()})
        return output
    start()
    payload = raw / "synthetic.payload"
    payload.write_bytes(b"synthetic settlement,000001,100.01\n" * 32768)
    data = payload.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    upload = ["--header", "Idempotency-Key: qualification-upload", "--header", f"X-File-Size: {len(data)}", "--header", "X-Content-SHA256: " + digest, "--data-binary", "@" + str(payload)]
    accepted = json.loads(curl("upload", api + "/files", 201, extra=upload).read_text())["file"]
    file_url = api + "/files/" + accepted["id"]
    assert accepted["sha256"] == digest and accepted["size_bytes"] == len(data)
    replay = json.loads(curl("replay", api + "/files", 200, extra=upload).read_text())
    assert replay["replayed"] and replay["file"] == accepted
    curl("changed-idempotency", api + "/files", 409, extra=["--header", "Idempotency-Key: qualification-upload", "--header", "X-File-Size: 1", "--header", "X-Content-SHA256: " + hashlib.sha256(b"x").hexdigest(), "--data-binary", "x"])
    downloaded = curl("download", file_url, 200)
    assert downloaded.read_bytes() == data
    ranged = curl("range", file_url, 206, extra=["--range", "7-63"])
    assert ranged.read_bytes() == data[7:64]
    curl("no-credential", file_url, 401, identity=None)
    curl("wrong-credential-scope", file_url, 401, identity=1)
    for index, (tid, pid) in enumerate(identities[1:], 1):
        other = base + f"/v1/tenants/{tid}/partners/{pid}"
        curl(f"foreign-file-{index}", other + "/files/" + accepted["id"], 404, identity=index)
        events = json.loads(curl(f"foreign-events-{index}", other + "/events", 200, identity=index).read_text())["events"]
        assert all(e["resource_id"] != accepted["id"] for e in events)
    curl("bad-digest", api + "/files", 422, extra=["--header", "Idempotency-Key: invalid-body", "--header", "X-File-Size: 1", "--header", "X-Content-SHA256: " + hashlib.sha256(b"y").hexdigest(), "--data-binary", "x"])
    events = json.loads(curl("events", api + "/events", 200).read_text())["events"]
    assert sum(e["kind"] == "FileAccepted" for e in events) == 1
    stop()
    start()
    assert curl("download-after-process-restart", file_url, 200).read_bytes() == data
    state = "passed"
    failure = None
except Exception as error:
    state = "failed"
    failure = str(error)
finally:
    stop()

source_paths = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]).decode().split("\0")
source_digests = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in sorted(set(source_paths)) if p and ((root / p).suffix in (".go", ".sql", ".sh", ".py") or p in ("go.mod", "go.sum"))}
manifest = {
    "schema_version": 1,
    "id": run_id,
    "state": state,
    "starting_commit": command(["git", "rev-parse", "HEAD"]).decode().strip(),
    "source_sha256": source_digests,
    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None,
    "environment": {"os": os.uname().sysname, "architecture": os.uname().machine, "go": command(["sh", "scripts/go.sh", "version"]).decode().strip(), "curl": command(["curl", "--version"]).decode().splitlines()[0], "postgres": "task-owned freightctl-postgres-v1; version recorded separately"},
    "elapsed_seconds": round(time.monotonic() - started, 3),
    "assistance": "Agent-operated synthetic service-account exchange; no independent human adoption claim",
    "steps": steps,
    "failure": failure,
    "raw_evidence_reference": str(raw.relative_to(root)),
    "private_fixture_reference": str(private.relative_to(root)),
    "limits": ["Single Mac and local PostgreSQL container", "Integrity-only policy; no antivirus, signatures or recipient business receipt", "No browser onboarding, resumable upload or SFTP qualification", "No HA, offline bundle, throughput or large-file acceptance claim"],
}
(raw / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"id": run_id, "state": state, "manifest": str(raw / "manifest.json"), "failure": failure}, indent=2))
if state != "passed":
    raise SystemExit(1)
