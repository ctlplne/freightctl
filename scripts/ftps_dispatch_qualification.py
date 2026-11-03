"""Public FTPS dispatch consent with real SQL/storage and a contact-only spy.

The spy cannot speak FTPS. It proves that metadata operations and refused work
make no receiver connection, not that a receiver accepts or persists bytes.
Reopen original CLI, HTTPS, DOM, accessibility and counter records before any
aggregate result can pass. Credentials and raw outputs stay task-private.
"""
import hashlib
import json
import os
import re
import socket
import threading
import uuid

import ftps_browser_tickets as previous
from ftps_cli_governance import read, require
from ftps_contract import CLI_PAYLOAD

PHASES = ("request", "approve", "withdraw")
COMMANDS = (
    "source-stat", "policy-status", "policy-set", "reviewer-token", "reviewer-create",
    "create", "create-replay", "queue", "work-before-consent", "status-before",
    "reviewer-original-denied", "reviewer-file-denied", "view-before",
    "browser-request", "view-after-request", "browser-approve", "view-approved",
    "status-approved", "reviewer-review-cli", "browser-withdraw", "work-after-withdraw",
    "status-withdrawn", "view-withdrawn", "owner-history", "reviewer-history",
)
REFUSALS = {
    "work-before-consent": b"freightctl: current outbound dispatch approval required\n",
    "work-after-withdraw": b"freightctl: current outbound dispatch approval required\n",
    "reviewer-original-denied": b"freightctl: permission denied\n",
}
SPY_KIND = "freightctl-ftps-contact-spy"


def command_suffix(name):
    match = re.fullmatch(r"cli-(?:explicit|implicit)-dispatch-(.+)", name)
    return match[1] if match and match[1] in COMMANDS else None


def verify_outcome(name, code, stderr, stdout=b""):
    suffix = command_suffix(name)
    if suffix is None:
        return previous.verify_outcome(name, code, stderr, stdout)
    require(type(code) is int and code == (1 if suffix in REFUSALS else 0), "dispatch CLI outcome differs")
    if suffix in REFUSALS:
        require(stderr == REFUSALS[suffix] and stdout == b"", "dispatch CLI refusal differs")


def check_counter(value, stopped):
    require(isinstance(value, dict) and set(value) == {
        "schema_version", "kind", "accepted_connections", "stopped", "budget_exhausted",
    }, "dispatch contact evidence shape differs")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == SPY_KIND and type(value["accepted_connections"]) is int
            and value["accepted_connections"] == 0 and value["stopped"] is stopped
            and value["budget_exhausted"] is False, "dispatch contacted receiver or spy did not stop")


class ContactSpy:
    """Own one ephemeral loopback socket; accept at most sixteen connections.

    Stop joins the only thread and drains the queued accepts before closing.
    This avoids a zero snapshot racing a pending connection in the socket queue.
    No probing connection is used to declare this listener ready.
    """
    def __init__(self, path):
        self.path = path
        self.listener = socket.socket()
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(16)
            self.listener.settimeout(.1)
            self.port = self.listener.getsockname()[1]
            self.done = threading.Event()
            self.error = None
            self.value = {"schema_version": 1, "kind": SPY_KIND, "accepted_connections": 0,
                          "stopped": False, "budget_exhausted": False}
            self.save()
            self.thread = threading.Thread(target=self.run, name="freightctl-ftps-contact-spy", daemon=True)
            self.thread.start()
        except Exception:
            self.listener.close()
            raise

    def save(self):
        temporary = self.path.with_suffix(".pending")
        with temporary.open("x") as output:
            json.dump(self.value, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.path)
        fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def accept(self):
        connection, _ = self.listener.accept()
        connection.close()
        self.value["accepted_connections"] += 1
        if self.value["accepted_connections"] >= 16:
            self.value["budget_exhausted"] = True
        self.save()

    def run(self):
        try:
            while not self.done.is_set() and not self.value["budget_exhausted"]:
                try:
                    self.accept()
                except socket.timeout:
                    pass
            self.listener.setblocking(False)
            while not self.value["budget_exhausted"]:
                try:
                    self.accept()
                except BlockingIOError:
                    break
            self.value["stopped"] = True
            self.save()
        except Exception as exc:
            self.error = exc
        finally:
            self.listener.close()

    def stop(self):
        self.done.set()
        self.thread.join(timeout=2)
        require(not self.thread.is_alive() and self.error is None, "dispatch contact spy cleanup failed")


def audit_names(phase):
    return ["dispatch-" + phase + "-" + suffix for suffix in (
        ("source", "disclosure", "history") if phase == "request"
        else ("reviewer", "confirmation", "decision-history")
    )]


def visible_terms(effect, source, delivery_id):
    ftps = effect["ftps"]
    return [delivery_id, source["id"], str(source["size_bytes"]), source["sha256"],
            effect["user"] + "@" + effect["address"], effect["final_path"],
            ("Explicit" if ftps["mode"] == "explicit" else "Implicit") + " TLS 1.3 required",
            ftps["server_name"], ftps["ca_sha256"], ftps["ca_reference_sha256"],
            ftps["password_reference_sha256"], ftps["staging_path"],
            ftps["receiver_contract"]["document_sha256"],
            "Certificate and credential checks run when sending starts.",
            "it does not verify those receiver promises.",
            "Rename may replace an existing final file.",
            "it does not acknowledge a receiver disk flush (fsync), power-loss persistence or business processing.",
            "a missing reply blocks automatic resend.", "Recovery only reads the exact final bytes"]


def validate(private, mode, steps, inventory):
    prefix = "cli-" + mode + "-dispatch-"
    directory = private / ("dispatch-" + mode)
    names = [s["name"][len(prefix):] for s in steps if s["name"].startswith(prefix)]
    require(len(names) == len(set(names)) and set(names) == set(COMMANDS), "dispatch command closure differs")
    actual = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file()}
    require(isinstance(inventory, dict) and 1 <= len(inventory) <= 100 and set(inventory) == actual,
            "dispatch private file closure differs")
    for name, digest in inventory.items():
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,200}", name)
                and all(part not in {".", ".."} for part in name.split("/")), "dispatch unsafe evidence name")
        path = directory / name
        require(not any(p.is_symlink() for p in (path, *path.parents))
                and path.stat().st_mode & 0o077 == 0
                and hashlib.sha256(read(path, 8 << 20)).hexdigest() == digest, "dispatch original file changed")
    def output(name):
        return json.loads(read(private / (prefix + name + ".stdout")))
    for step in steps:
        if step["name"].startswith(prefix):
            stdout, stderr = (read(private / (step["name"] + "." + ext), 8 << 20) for ext in ("stdout", "stderr"))
            require(hashlib.sha256(stdout).hexdigest() == step["stdout_sha256"]
                    and hashlib.sha256(stderr).hexdigest() == step["stderr_sha256"], "dispatch CLI original output changed")
            verify_outcome(step["name"], step["exit_code"], stderr, stdout)
    check_counter(json.loads(read(directory / "receiver.json")), True)
    original, replay, queued = (output(n) for n in ("create", "create-replay", "queue"))
    require(original.get("replayed") is False and replay == dict(original, replayed=True), "dispatch create replay differs")
    delivery = queued["delivery"]
    require(delivery["id"] == original["delivery"]["id"] and delivery["definition_hash"] == original["delivery"]["definition_hash"]
            and original["delivery"]["state"] == "draft" and delivery["state"] == "queued"
            and delivery["revision"] == original["delivery"]["revision"] + 1, "dispatch queue changed intent")
    for name in ("status-before", "status-approved", "status-withdrawn"):
        status = output(name)
        require(status == delivery and status["attempts"] == status["fence"] == 0
                and status["lease_owner"] == "" and status["lease_until"] is None, "dispatch refused work changed intent")
    definition = delivery["definition"]
    source = definition["source"]
    require(source["id"] == output("source-stat")["file_id"] and source["sha256"] == hashlib.sha256(CLI_PAYLOAD).hexdigest()
            and source["size_bytes"] == len(CLI_PAYLOAD), "dispatch source is not the stock accepted bytes")
    policy = output("policy-set")["resource"]["policy"]
    require(policy["mode"] == "independent" and policy["revision"] == output("policy-status")["revision"] + 1,
            "dispatch independent policy differs")
    reviewer = output("reviewer-create")["account"]
    require(reviewer["permissions"] == ["inspect", "workflow_approve"] and reviewer["namespace_root"] == "/"
            and reviewer["state"] == "active" and reviewer["authority_revision"] == 1, "dispatch reviewer privilege differs")
    require(read(private / (prefix + "reviewer-file-denied.stdout")) == b"403"
            and json.loads(read(directory / "reviewer-file.body")) == {"error": "permission_denied"}, "dispatch reviewer gained source access")
    before = output("view-before")
    effect = before["effect"]
    require(effect["protocol"] == "ftps" and effect["ftps"]["mode"] == mode
            and before["source"] == source and before["policy"] == before["current_policy"] == definition["dispatch_approval_policy"]
            and before["policy"] == {"revision": policy["revision"], "mode": "independent"}
            and before["current_approval"] is False and before["reviewable"] is True, "dispatch view does not bind intent")
    private_destination = definition["ftps"]["destination"]
    require(definition["schema_version"] == 2 and private_destination["mode"] == mode
            and definition == original["delivery"]["definition"]
            and effect == {"protocol": "ftps", "address": private_destination["address"], "user": private_destination["user"],
                "directory": definition["directory"], "filename": definition["filename"],
                "final_path": definition["directory"] + "/" + delivery["id"] + "-" + definition["filename"],
                "host_fingerprint": "", "key_fingerprint": "", "key_reference_sha256": "", "recipient_fingerprint": "",
                "ftps": {"mode": mode, "server_name": private_destination["server_name"], "ca_sha256": private_destination["ca_sha256"],
                    "ca_reference_sha256": hashlib.sha256(private_destination["ca_reference"].encode()).hexdigest(),
                    "password_reference_sha256": hashlib.sha256(private_destination["password_reference"].encode()).hexdigest(),
                    "staging_path": definition["ftps"]["staging_directory"] + "/.freightctl-" + delivery["id"] + ".partial",
                    "receiver_contract": definition["ftps"]["receiver_contract"]}}, "dispatch public effect changed approved destination")
    forbidden = [private_destination[k] for k in ("ca_reference", "password_reference", "password_sha256")]
    forbidden += [read(directory / "receiver-password").decode()]
    reviews = []
    for phase, expected_state in zip(PHASES, ("pending", "approved", "withdrawn")):
        phase_dir = directory / phase
        summary = json.loads(read(phase_dir / "onboarding-exchange-browser.json"))
        result = json.loads(read(phase_dir / "outbound-dispatch-browser-result.json"))
        require(summary.get("state") == result.get("state") == "passed" and not summary.get("failure")
                and summary.get("runtime_errors") == summary.get("external_egress") == []
                and summary.get("model_started") is False and summary.get("production_activated") is False,
                "dispatch actual browser did not pass")
        require(result.get("phase") == phase and result.get("receiver_contacts_unchanged") is True,
                "dispatch browser phase differs")
        for audit in audit_names(phase):
            report = json.loads(read(phase_dir / (audit + "-axe.json")))
            require(report.get("violations") == [] and type(report.get("passes")) is int and report["passes"] > 0,
                    "dispatch accessibility audit missing or failed")
        visible = read(phase_dir / "ftps-visible.txt").decode()
        normalized = " ".join(visible.split())
        require(all(term in normalized for term in visible_terms(effect, source, delivery["id"])), "dispatch rendered FTPS terms differ")
        responses = result["responses"]
        require(len(responses) == 2, "dispatch lost-response evidence missing")
        a, b = responses
        first, second = (json.loads(r["body"]) for r in responses)
        require(a["status"] == b["status"] == 200 and a["idempotency_key"] and a["idempotency_key"] == b["idempotency_key"]
                and a["selection"] == b["selection"] and first.get("replayed") is False
                and second == dict(first, replayed=True), "dispatch original-key receipt differs")
        for i, response in enumerate(responses):
            label = "browser-dispatch-" + phase + "-" + str(i)
            body = read(phase_dir / (label + ".json"))
            require(body.decode() == response["body"]
                    and json.loads(read(directory / (label + ".request"))) == response["selection"]
                    and ("idempotency-key: " + response["idempotency_key"] + "\n").encode() in read(directory / (label + ".headers")),
                    "dispatch actual HTTPS wire record differs")
            wire = [s for s in summary["steps"] if s["name"] == label + "-wire-response"]
            require(len(wire) == 1 and wire[0]["request_method"] == "POST" and wire[0]["response_status"] == 200
                    and wire[0]["response_sha256"] == hashlib.sha256(body).hexdigest(), "dispatch browser wire receipt differs")
        review = second["resource"]["review"]
        require(review == result["review"] and review["state"] == expected_state
                and review["delivery_id"] == delivery["id"] and review["reviewer_id"] == reviewer["id"], "dispatch review state differs")
        reviews.append(review)
        public_outputs = [visible, json.dumps(result), json.dumps(summary), json.dumps(output("view-" + {
            "request": "after-request", "approve": "approved", "withdraw": "withdrawn"}[phase]))]
        require(all(secret not in value for value in public_outputs for secret in forbidden), "dispatch delegated metadata exposes private reference or password proof")
    review = output("reviewer-review-cli")
    require(review["definition"]["schema_version"] == 2 and review["definition"]["effect"] == effect
            and review["definition"]["source"] == source and review["definition"]["delivery_hash"] == delivery["definition_hash"]
            and review["definition"]["delivery_revision"] == delivery["revision"] and review["definition"]["attempt_limit"] == 8,
            "dispatch delegated review differs from exact delivery")
    require([r["revision"] for r in reviews] == [1, 2, 3]
            and len({r["id"] for r in reviews}) == len({r["definition_hash"] for r in reviews}) == 1
            and {k:v for k,v in review.items() if k != "definition"} == reviews[1], "dispatch decision changed package")
    for name, consent in (("view-after-request", False), ("view-approved", True), ("view-withdrawn", False)):
        require(output(name) == dict(before, current_approval=consent), "dispatch consent read model differs")
    history = output("owner-history")
    require(len(history["reviews"]) == (1 if mode == "explicit" else 2)
            and [r for r in history["reviews"] if r["id"] == reviews[-1]["id"]] == [reviews[-1]]
            and all(r["state"] == "withdrawn" for r in history["reviews"]) and not history.get("next"), "dispatch author history differs")
    require(output("reviewer-history")["reviews"] == [reviews[-1]] and not output("reviewer-history").get("next"),
            "dispatch reviewer private history differs")
    return {"state": "passed", "mode": mode, "commands": len(COMMANDS), "strict_cli_refusals": len(REFUSALS),
            "strict_api_refusals": 1, "browser_phases": len(PHASES), "lost_response_replays": 3,
            "accessibility_audits": 9, "receiver_connections": 0, "attempts": 0, "fence": 0,
            "spy_stopped": True, "scope": "metadata consent and no-contact refusals; no FTPS wire or receiver persistence claim"}


def exercise(root, private, mode, http_port, cert, binary, tenant, partner, owner, steps, command):
    prefix = "cli-" + mode + "-dispatch-"
    directory = private / ("dispatch-" + mode)
    directory.mkdir(mode=0o700)
    def request(label, value):
        ref = directory / (label + ".json")
        with ref.open("x") as output:
            json.dump(value, output)
        return ref
    def invoke(label, operation, *args, who=owner):
        raw = command(prefix + label, [binary, operation, "--dsn-file", private / "pg-runtime.dsn",
            "--token-file", who, "--tenant", tenant, "--partner", partner,
            "--storage", private / "custody", *args], 20)
        return json.loads(raw) if raw else None
    source = invoke("source-stat", "namespace-stat", "--path", "/cli-" + mode + ".bin")
    policy = invoke("policy-status", "dispatch-policy-status")
    invoke("policy-set", "dispatch-policy-set", "--request-file", request("policy", {
        "expected_revision": policy["revision"], "mode": "independent"}), "--idempotency-key", prefix + "policy")
    reviewer_token = directory / "reviewer.token"
    command(prefix + "reviewer-token", [binary, "token", "--token-file", reviewer_token])
    reviewer = invoke("reviewer-create", "account-create", "--new-token-file", reviewer_token,
        "--request-file", request("reviewer", {"operation": "create", "account_id": str(uuid.uuid4()), "expected_revision": 0,
            "policy": {"label": "FTPS dispatch reviewer " + mode, "permissions": ["inspect", "workflow_approve"],
                       "namespace_root": "/", "expires_at": None}}), "--idempotency-key", prefix + "reviewer")["account"]
    password = directory / "receiver-password"
    password.write_bytes(os.urandom(32).hex().encode())
    spy = ContactSpy(directory / "receiver.json")
    try:
        ftps = {"destination": {"address": "127.0.0.1:" + str(spy.port), "server_name": "localhost", "mode": mode,
            "user": "freightctl-contact-only", "ca_reference": str(cert), "ca_sha256": hashlib.sha256(read(cert)).hexdigest(),
            "password_reference": str(password), "password_sha256": hashlib.sha256(read(password)).hexdigest()},
            "staging_directory": "/dispatch-stage-" + mode,
            "receiver_contract": {"schema_version": 1, "document_sha256": hashlib.sha256(b"synthetic contact-only contract; no receiver qualification").hexdigest(),
                "staging_visibility": "receiver-private", "rename": "may-replace", "duplicates": "receiver-deduplicates-delivery-id", "receipt": "exact-readback"}}
        ref = request("delivery", {"file_id": source["file_id"], "address": "", "user": "",
            "directory": "/dispatch-inbox-" + mode, "filename": "approved.bin", "host_public_file": "", "key_file": "", "key_public_file": "", "ftps": ftps})
        args = ("--request-file", ref, "--idempotency-key", prefix + "create")
        delivery = invoke("create", "delivery-create", *args)["delivery"]
        invoke("create-replay", "delivery-create", *args)
        delivery = invoke("queue", "delivery-approve", "--delivery-id", delivery["id"],
            "--definition-hash", delivery["definition_hash"], "--expected-revision", str(delivery["revision"]),
            "--idempotency-key", prefix + "queue")["delivery"]
        id_args = ("--delivery-id", delivery["id"])
        invoke("work-before-consent", "delivery-work", *id_args)
        invoke("status-before", "delivery-status", *id_args)
        invoke("reviewer-original-denied", "dispatch-delivery-status", *id_args, who=reviewer_token)
        headers = directory / "reviewer.headers"
        headers.write_bytes(b"Authorization: Bearer " + read(reviewer_token) + b"\n")
        command(prefix + "reviewer-file-denied", ["curl", "-q", "--silent", "--show-error", "--noproxy", "*", "--proto", "=https",
            "--cacert", cert, "--connect-timeout", "3", "--max-time", "8", "--max-filesize", "65536", "--header", "@" + str(headers),
            "--output", directory / "reviewer-file.body", "--write-out", "%{http_code}",
            "https://127.0.0.1:" + str(http_port) + "/v1/tenants/" + tenant + "/partners/" + partner + "/files/" + source["file_id"]])
        view = invoke("view-before", "dispatch-delivery-status", *id_args)
        def browser(phase, review=None):
            check_counter(json.loads(read(directory / "receiver.json")), False)
            raw = directory / phase
            raw.mkdir(mode=0o700)
            cfg = {"root": str(root), "private": str(directory), "raw": str(raw), "certificate": str(cert),
                "url": "https://127.0.0.1:" + str(http_port), "tenant": tenant, "partner": partner,
                "token": str(owner if phase == "request" else reviewer_token), "dispatch_approval_only": True,
                "dispatch_protocol": "ftps", "dispatch_phase": phase, "dispatch_delivery": {"id": delivery["id"]},
                "dispatch_review": {"id": review["id"]} if review else None,
                "dispatch_reviewer_id": reviewer["id"], "receiver_log": str(directory / "receiver.json"),
                "dispatch_expected": {"effect": view["effect"], "source": view["source"]}}
            command(prefix + "browser-" + phase, ["node", "scripts/onboarding-exchange-browser.mjs", request("browser-" + phase, cfg)], 150)
            check_counter(json.loads(read(directory / "receiver.json")), False)
            return json.loads(read(raw / "outbound-dispatch-browser-result.json"))["review"]
        pending = browser("request")
        invoke("view-after-request", "dispatch-delivery-status", *id_args)
        approved = browser("approve", pending)
        invoke("view-approved", "dispatch-delivery-status", *id_args)
        invoke("status-approved", "delivery-status", *id_args)
        invoke("reviewer-review-cli", "dispatch-review-status", "--dispatch-review-id", approved["id"], who=reviewer_token)
        browser("withdraw", approved)
        invoke("work-after-withdraw", "delivery-work", *id_args)
        invoke("status-withdrawn", "delivery-status", *id_args)
        invoke("view-withdrawn", "dispatch-delivery-status", *id_args)
        invoke("owner-history", "dispatch-review-list")
        invoke("reviewer-history", "dispatch-review-list", who=reviewer_token)
    finally:
        spy.stop()
    inventory = {str(p.relative_to(directory)): hashlib.sha256(read(p, 8 << 20)).hexdigest()
                 for p in sorted(directory.rglob("*")) if p.is_file()}
    return validate(private, mode, steps, inventory), inventory
