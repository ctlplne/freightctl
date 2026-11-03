"""Reopen original HTTPS receipts, browser audits and FTPS wire phase streams.

Only fixed safe counts reach CI logs. Credentials and original outputs stay
inside each ignored task directory; claimed case counters are insufficient.
"""
import hashlib
import json
import re
from pathlib import Path

from ftps_cli_governance import GOOD_CSV, BAD_CSV, read, require

AUDITS = ["credential-create-review", "credential-rotate-review", "intake-policy-editor", "intake-policy-register-review", "exact-ftps-release-review", "intake-policy-revoke-review", "intake-policy-revoked"]
PROOFS = ["browser-rotation-revocation-refuse-open-ftps-writers", "browser-ftps-hold-check-release-and-policy-revocation", "lost-accounts-commands-original-key", "lost-intake-policy-original-key", "lost-intake-policy-revoke-original-key", "rejected-ftps-file-release-api-refused"]
ACCESSIBILITY_RULES = set(json.loads((Path(__file__).resolve().parents[1] / "web/tests/fixtures/axe-rule-ids.json").read_text()))
PHASES = {"credential-sign-in", "credential-create", "credential-rotate", "credential-revoke", "intake-sign-in", "policy-register", "intake-list", "check-bad", "check-good", "bad-release-refusal", "release", "policy-revoke", "final-audit"}


EVIDENCE_FAILURES = frozenset({
    'browser FTPS wire proof differs',
    'browser accessibility proof differs',
    'browser account command count differs',
    'browser account transition differs',
    'browser check byte/policy binding differs',
    'browser command key differs',
    'browser credential proof differs',
    'browser did not complete',
    'browser did not inspect the actual FTPS check',
    'browser original HTTP outcome differs',
    'browser original output hash differs',
    'browser output closure differs',
    'browser output inventory differs',
    'browser peer endpoint or scope differs',
    'browser policy definition differs',
    'browser policy registration differs',
    'browser policy revocation differs',
    'browser refusal did not target the rejected immutable revision',
    'browser rejected-file release refusal differs',
    'browser release count differs',
    'browser release is not bound to the inspected bytes/report/revision',
    'browser release receipt differs',
    'browser request is not original selection',
    'browser response inventory differs',
    'browser response is not original output',
    'browser response labels repeat',
    'browser retry changed reviewed command',
    'browser retry changed saved receipt',
    'browser revoked another policy revision',
    'browser runtime or egress failure',
    'browser scope differs',
    'browser sent a raw credential',
    'browser wire label differs',
    'browser writer did not resume its control',
    'missing required browser evidence field',
    'required browser proof is missing',
    'unclassified browser evidence failure',
    'unsafe browser output reference',
})

def safe_failure(error):
    if type(error) is ValueError and str(error) in EVIDENCE_FAILURES:
        return str(error)
    if type(error) is KeyError:
        return "missing required browser evidence field"
    return "unclassified browser evidence failure"


def verify_http_outcome(label, status, body):
    require(re.fullmatch(r"(?:wire|loss)-[0-9]{1,3}|bad-release", label), "browser wire label differs")
    require(type(status) is int and status == (409 if label == "bad-release" else 200), "browser original HTTP outcome differs")
    if label == "bad-release":
        require(json.loads(body) == {"error":"operation_state_conflict"}, "browser rejected-file release refusal differs")


def verify_check_binding(check, policy_hash, payload):
    file = check.get("binding", {}).get("file", {})
    require(check.get("attempts") == 1 and check.get("policy_hash") == policy_hash and file.get("sha256") == hashlib.sha256(payload).hexdigest() and file.get("size_bytes") == len(payload), "browser check byte/policy binding differs")


def validate(directory, inventory=None):
    directory = Path(directory)
    if inventory is not None:
        require(isinstance(inventory, dict) and 1 <= len(inventory) <= 200, "browser output inventory differs")
        require({p.name for p in directory.iterdir()} == set(inventory), "browser output closure differs")
        for name, digest in inventory.items():
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name), "unsafe browser output reference")
            require(hashlib.sha256(read(directory / name, 4 << 20)).hexdigest() == digest, "browser original output hash differs")
    def load(name):
        return json.loads(read(directory / name))
    report = load("result.json")
    require(report.get("state") == "passed" and not report.get("failure"), "browser did not complete")
    require(report.get("runtime_errors") == [] and report.get("external_egress") == [], "browser runtime or egress failure")
    require(report.get("inference_performed") is False and report.get("scanner_started") is False, "browser scope differs")
    require(set(report.get("steps", [])) == set(PROOFS + [n + "-axe" for n in AUDITS]) and len(report["steps"]) == len(PROOFS) + len(AUDITS), "required browser proof is missing")
    for name in AUDITS:
        audit = load(name + "-axe.json")
        require(audit.get("violations") == [] and type(audit.get("passes")) is int and audit["passes"] > 0, "browser accessibility proof differs")
    cfg = load("config.json")
    responses = report.get("responses")
    require(isinstance(responses, list) and 12 <= len(responses) <= 40, "browser response inventory differs")
    requests = []
    negative = []
    for r in responses:
        label = r.get("label", "")
        verify_http_outcome(label, r.get("status"), r.get("body"))
        require(r.get("body") == read(directory / (label + ".response")).decode(), "browser response is not original output")
        body = read(directory / (label + ".request"))
        require(r.get("selection") == (json.loads(body) if body else None), "browser request is not original selection")
        header = read(directory / (label + ".headers")).decode()
        keys = re.findall(r"(?mi)^idempotency-key: ([^\r\n]+)$", header)
        require(keys == ([r["idempotency_key"]] if r.get("idempotency_key") else []), "browser command key differs")
        if label == "bad-release":
            require(json.loads(r["body"]) == {"error":"operation_state_conflict"} and r.get("idempotency_key") == "browser-bad-release" and r.get("method") == "POST", "browser rejected-file release refusal differs")
            negative.append(r)
        else:
            requests.append((r["selection"], json.loads(r["body"]), r.get("idempotency_key")))
    require(len({r["label"] for r in responses}) == len(responses), "browser response labels repeat")
    def commands(field):
        return [(s, r, k) for s, r, k in requests if isinstance(s, dict) and field in s]
    accounts = commands("account_id")
    require(len(accounts) == 4, "browser account command count differs")
    created, rotated, replay, revoked = accounts
    account_id = created[1]["account"]["id"]
    for (_, result, _), revision, state in ((created, 1, "active"), (rotated, 2, "active"), (replay, 2, "active"), (revoked, 3, "revoked")):
        a = result["account"]
        require(a.get("id") == account_id and a.get("revision") == a.get("authority_revision") == revision and a.get("state") == state and a.get("changed_event_id"), "browser account transition differs")
    for name, operation in (("old.token", created), ("next.token", rotated)):
        require(operation[0].get("credential_sha256") == hashlib.sha256(read(directory / name, 64)).hexdigest(), "browser credential proof differs")
        require(read(directory / name, 64) not in json.dumps(operation[0]).encode(), "browser sent a raw credential")
    def replayed(a, b):
        require(a[2] and a[2] == b[2] and a[0] == b[0], "browser retry changed reviewed command")
        require(a[1].get("replayed") is False and b[1].get("replayed") is True and dict(a[1], replayed=True) == b[1], "browser retry changed saved receipt")
    replayed(rotated, replay)
    policies = commands("definition")
    require(len(policies) == 2 and policies[0][0].get("expected_version") == 0, "browser policy registration differs")
    replayed(*policies)
    policy = policies[0][1]["resource"]
    require(policy.get("state") == "active" and policy.get("version") == policy.get("revision") == 1 and policy.get("definition") == policies[0][0]["definition"], "browser policy definition differs")
    revocations = commands("definition_hash")
    require(len(revocations) == 2, "browser policy revocation differs")
    replayed(*revocations)
    p = revocations[0][1]["resource"]
    require(revocations[0][0] == {"definition_hash": policy["definition_hash"], "expected_version":1, "expected_revision":1} and p.get("id") == policy["id"] and p.get("version") == 1 and p.get("revision") == 2 and p.get("state") == "revoked" and p.get("definition_hash") == policy["definition_hash"], "browser revoked another policy revision")
    views = [r["check"] for _, r, _ in requests if "check" in r]
    for path, payload, state in (("/good.csv", GOOD_CSV, "passed"), ("/bad.csv", BAD_CSV, "rejected")):
        matches = [v for v in views if v.get("state") == state and v.get("binding", {}).get("target", {}).get("path") == path]
        require(matches, "browser did not inspect the actual FTPS check")
        for v in matches:
            verify_check_binding(v, policy["definition_hash"], payload)
    releases = commands("report_hash")
    require(len(releases) == 1, "browser release count differs")
    selection, result, key = releases[0]
    good = next(v for v in views if v.get("state") == "passed")
    bad = next(v for v in views if v.get("state") == "rejected")
    require(len(negative) == 1 and negative[0]["selection"] == {"sha256":bad["binding"]["file"]["sha256"],"policy_hash":bad["policy_hash"],"report_hash":good["report_hash"],"expected_revision":bad["revision"]} and negative[0].get("url") == cfg["url"] + "/v1/tenants/" + cfg["intake"]["tenant"] + "/partners/" + cfg["intake"]["partner"] + "/checks/" + bad["file_id"] + "/release", "browser refusal did not target the rejected immutable revision")
    require(key and selection == {"sha256": good["binding"]["file"]["sha256"], "policy_hash":good["policy_hash"], "report_hash":good["report_hash"], "expected_revision":good["revision"]}, "browser release is not bound to the inspected bytes/report/revision")
    require(result["resource"].get("state") == "released" and result["resource"].get("file_id") == good["file_id"] and result["resource"].get("revision") == good["revision"] + 1, "browser release receipt differs")
    for name, phases, count in (("credential-peer", ["writer-open-before-rotation", "writer-open-before-revocation", "passed"], 2), ("intake-peer", ["uploads-held", "passed-still-unreleased", "only-approved-revision-published", "passed"], 4)):
        messages = [json.loads(line) for line in read(directory / (name + ".stdout"), 16384).splitlines()]
        require([m.get("state") for m in messages] == phases and messages[-1].get("case_count") == count and messages[-1].get("all_data_resumed") is True and read(directory / (name + ".stderr")) == b"", "browser FTPS wire proof differs")
        if name == "credential-peer":
            require(all(m.get("resumed") is True for m in messages[:-1]), "browser writer did not resume its control")
        settings = load(name + ".json")
        who = cfg["credential" if name == "credential-peer" else "intake"]
        require(settings.get("username") == who["tenant"] + "/" + who["partner"] and settings.get("port") == cfg["port"] and settings.get("implicit") is cfg["implicit"] and settings.get("certificate") == cfg["certificate"], "browser peer endpoint or scope differs")
    return {"state":"passed", "governance_cases":6, "strict_api_refusals":1, "accessibility_audits":len(AUDITS), "lost_response_replays":3, "original_https_responses":len(responses)}
