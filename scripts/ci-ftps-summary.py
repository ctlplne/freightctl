#!/usr/bin/env python3
"""Allowlist aggregate FTPS qualification outcomes; never print raw evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from ftps_contract import CLI_PAYLOAD, LFTP_CASES, LFTP_DOWNLOADS, LFTP_FAILURE_CODES, NATIVE_PARENT_TESTS, NATIVE_TESTS
import ftps_cli_governance as governance
import ftps_browser_evidence as browser_evidence
import ftps_ticket_governance as tickets
import ftps_browser_tickets as browser_tickets

ROOT = Path(__file__).resolve().parents[1]


def read(path, bound):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > bound:
        raise ValueError("unsafe or oversized FTPS evidence")
    return path.read_bytes()


def failure_diagnostics(root, result, commit):
    """Only fixed profile names/categories can leave failed protected evidence."""
    try:
        header = json.loads(read(result, 8192))
        ref = header.get("manifest_reference")
        if not isinstance(ref, str) or not re.fullmatch(r"\.private/ftps-[0-9a-f]{32}/manifest\.json", ref):
            return {}
        path = root / ref
        if not path.resolve().is_relative_to((root / ".private").resolve()):
            return {}
        raw = read(path, 8 << 20)
        manifest = json.loads(raw)
        if hashlib.sha256(raw).hexdigest() != header.get("manifest_sha256") or manifest.get("starting_commit") != commit or manifest.get("kind") != "stock-ftps-custody":
            return {}
        failed, categories, cli_failures, browser_failures = set(), set(), set(), []
        accessibility, ticket_browser_failures = [], []
        allowed = {"native-ftps-integration", "cli-explicit-lftp-probe", "cli-implicit-lftp-probe", "browser-explicit-operator", "browser-implicit-operator"}
        for step in manifest.get("steps", []):
            name = step.get("name")
            if name not in allowed and not governance.command_suffix(name or "") and not tickets.command_suffix(name or "") and not browser_tickets.command_suffix(name or ""):
                continue
            data = read(path.parent / (name + ".stdout"), 64 << 20)
            if hashlib.sha256(data).hexdigest() != step.get("stdout_sha256"):
                return {}
            if governance.command_suffix(name) or tickets.command_suffix(name) or browser_tickets.command_suffix(name):
                diagnostic = read(path.parent / (name + ".stderr"), 1 << 20)
                if hashlib.sha256(diagnostic).hexdigest() != step.get("stderr_sha256"):
                    return {}
                try:
                    browser_tickets.verify_outcome(name, step.get("exit_code"), diagnostic, data)
                except ValueError:
                    cli_failures.add(name)
            output = data.decode(errors="replace")
            failed.update(set(re.findall(r"^\s*--- FAIL: (TestFTPS\S+) \(", output, re.MULTILINE)) & NATIVE_TESTS)
            for line in output.splitlines():
                if "{" not in line:
                    continue
                try:
                    probe = json.loads(line[line.index("{"):])
                except ValueError:
                    continue
                if probe.get("state") == "failed" and probe.get("stage") in {"version", "transfers"} and probe.get("code") in LFTP_FAILURE_CODES:
                    categories.add((probe["stage"], probe["code"]))
                if browser_tickets.command_suffix(name)=="browser" and probe.get("state")=="failed" and probe.get("stage") in browser_tickets.STAGES:
                    ticket_browser_failures.append({"command":name,"stage":probe["stage"]})
                if name in {"browser-explicit-operator", "browser-implicit-operator"} and probe.get("state") == "failed" and probe.get("phase") in browser_evidence.PHASES and type(probe.get("line")) is int and 0 <= probe["line"] <= 10000:
                    browser_failures.append({"command":name,"phase":probe["phase"],"source_line":probe["line"]})
                if name in {"browser-explicit-operator", "browser-implicit-operator"} and probe.get("state") == "failed" and probe.get("audit") in browser_evidence.AUDITS:
                    ids = probe.get("accessibility_rule_ids")
                    if isinstance(ids,list) and 0 < len(ids) <= 100 and all(isinstance(i,str) and i in browser_evidence.ACCESSIBILITY_RULES for i in ids):
                        accessibility.append({"command":name,"audit":probe["audit"],"rule_ids":sorted(set(ids))})
        outcome = {"failed_native_tests": sorted(failed), "lftp_failures": [{"stage": s, "code": c} for s, c in sorted(categories)], "failed_cli_commands": sorted(cli_failures)}
        if browser_failures:
            outcome["browser_failures"] = browser_failures
        if accessibility:
            outcome["accessibility_failures"] = accessibility
        if ticket_browser_failures:
            outcome["browser_ticket_failures"] = ticket_browser_failures
        invariant = manifest.get("browser_evidence_failure")
        if isinstance(invariant,dict) and invariant.get("mode") in {"explicit","implicit"} and invariant.get("invariant") in browser_evidence.EVIDENCE_FAILURES:
            outcome["browser_evidence_failure"] = {"mode":invariant["mode"],"invariant":invariant["invariant"]}
        if manifest.get("browser_requested") is True:
            outcome["cleanup_observation"] = {key: manifest.get(key) is True for key in ("retained_metadata_and_roles_unchanged", "isolated_database_removed", "original_resource_state_restored")}
            failures = manifest.get("cleanup_failures")
            outcome["cleanup_observation"]["failure_count"] = len(failures) if isinstance(failures,list) else None
        return outcome
    except Exception:
        return {}


def summarize(root, result, commit, require_browser=False, require_tickets=False, require_browser_tickets=False):
    header = json.loads(read(result, 8192))
    ref = header.get("manifest_reference")
    if not isinstance(ref, str) or not re.fullmatch(r"\.private/ftps-[0-9a-f]{32}/manifest\.json", ref):
        raise ValueError("invalid FTPS manifest reference")
    path = root / ref
    if not path.resolve().is_relative_to((root / ".private").resolve()):
        raise ValueError("FTPS manifest escapes private evidence")
    raw = read(path, 8 << 20)
    digest = hashlib.sha256(raw).hexdigest()
    if header.get("manifest_sha256") != digest:
        raise ValueError("FTPS manifest checksum differs")
    manifest = json.loads(raw)
    if header.get("state") != "passed" or manifest.get("state") != "passed" or manifest.get("kind") != "stock-ftps-custody" or manifest.get("starting_commit") != commit:
        raise ValueError("FTPS qualification failed or belongs to another candidate")
    for key in ("stock_curl_qualified", "stock_lftp_qualified", "retained_metadata_and_roles_unchanged", "isolated_database_removed", "original_resource_state_restored", "sources_unchanged"):
        if manifest.get(key) is not True:
            raise ValueError("FTPS qualification or cleanup is incomplete")
    for key in ("native_client_only", "inference_performed", "scanner_engine_started", "full_foundation_aggregate_executed", "full_journeys_qualified"):
        if manifest.get(key) is not False:
            raise ValueError("FTPS evidence scope differs")
    if manifest.get("cleanup_failures") != [] or manifest.get("retained_before") != manifest.get("retained_after"):
        raise ValueError("FTPS cleanup or retained state differs")
    before = manifest.get("retained_before")
    if not isinstance(before, dict) or before.get("runtime_role_safe") is not True or len(before.get("migration_ledger", [])) != 35 or before.get("forced_rls_tables") != 63 or len(before.get("tables", [])) != 64:
        raise ValueError("FTPS PostgreSQL security profile differs")
    tests = manifest.get("native_tests")
    required = NATIVE_PARENT_TESTS
    if not isinstance(tests, dict) or tests.get("required") != required or tests.get("pass_records") != len(NATIVE_TESTS) or tests.get("failed_records") != 0 or tests.get("skipped_records") != 0:
        raise ValueError("required FTPS tests are missing or skipped")
    steps = manifest.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 1000 or len({s.get("name") for s in steps}) != len(steps):
        raise ValueError("invalid FTPS command inventory")
    names = {s.get("name") for s in steps}
    for name in ("native-ftps-integration", "stock-lftp-version", "cli-explicit-upload", "cli-explicit-download", "cli-implicit-upload", "cli-implicit-download", "cli-explicit-lftp-probe", "cli-implicit-lftp-probe", "drop-exact-test-database"):
        if name not in names:
            raise ValueError("required FTPS command is missing")
    for mode in ("explicit", "implicit"):
        if not {"cli-" + mode + "-gov-" + name for name in governance.COMMANDS} <= names:
            raise ValueError("public CLI governance command is missing")
    for step in steps:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", step.get("name", "")):
            raise ValueError("native FTPS command failed or is incomplete")
        for extension, field in (("stdout", "stdout_sha256"), ("stderr", "stderr_sha256")):
            data = read(path.parent / (step["name"] + "." + extension), 64 << 20)
            if hashlib.sha256(data).hexdigest() != step.get(field):
                raise ValueError("native FTPS output checksum differs")
        browser_tickets.verify_outcome(step["name"], step.get("exit_code"), read(path.parent / (step["name"] + ".stderr"), 64 << 20), read(path.parent / (step["name"] + ".stdout"), 64 << 20))
    for mode in ("explicit", "implicit"):
        governance.validate_outputs(path.parent, mode)
    native = read(path.parent / "native-ftps-integration.stdout", 64 << 20).decode()
    executed = re.findall(r"^\s*--- PASS: (TestFTPS\S+) \(", native, re.MULTILINE)
    if len(executed) != len(NATIVE_TESTS) or set(executed) != NATIVE_TESTS or "--- SKIP:" in native or "--- FAIL:" in native:
        raise ValueError("native FTPS output does not prove every required test")
    payload = CLI_PAYLOAD
    for name in ("cli-explicit-download", "cli-implicit-download"):
        if read(path.parent / (name + ".stdout"), 8192) != payload:
            raise ValueError("stock FTPS CLI bytes differ")
    for mode in ("explicit", "implicit"):
        report = json.loads(read(path.parent / ("cli-" + mode + "-lftp-probe.stdout"), 8192))
        if report.get("state") != "passed" or report.get("cases") != LFTP_CASES or report.get("stock_client_qualification") is not True or report.get("payload_bytes") != len(payload) or report.get("payload_sha256") != hashlib.sha256(payload).hexdigest():
            raise ValueError("stock lftp probe profile differs")
        for name in LFTP_DOWNLOADS:
            if read(path.parent / ("cli-" + mode + ".lftp") / name, 8192) != payload:
                raise ValueError("stock lftp CLI bytes differ")
    sources = manifest.get("source_sha256")
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 10000:
        raise ValueError("invalid FTPS source inventory")
    for name, expected in sources.items():
        p = root / name
        if not p.resolve().is_relative_to(root.resolve()) or hashlib.sha256(read(p, 16 << 20)).hexdigest() != expected:
            raise ValueError("FTPS source identity differs")
    if require_browser or require_browser_tickets or manifest.get("browser_requested"):
        if manifest.get("browser_requested") is not True:
            raise ValueError("required browser profile did not run")
        for mode in ("explicit", "implicit"):
            inventory = manifest.get("browser_output_sha256", {}).get(mode)
            if not isinstance(inventory, dict):
                raise ValueError("browser output closure missing")
            checked = browser_evidence.validate(path.parent / ("browser-" + mode), inventory)
            if manifest.get("browser_governance", {}).get(mode) != checked:
                raise ValueError("browser outcomes differ from original evidence")
    if require_tickets or manifest.get("tickets_requested"):
        if manifest.get("tickets_requested") is not True:
            raise ValueError("required public process-crash ticket profile did not run")
        for mode in ("explicit", "implicit"):
            checked = tickets.validate(path.parent, mode, steps, manifest.get("ticket_output_sha256", {}).get(mode))
            if manifest.get("ticket_governance", {}).get(mode) != checked:
                raise ValueError("ticket outcomes differ from original evidence")
    elif any(tickets.command_suffix(n) for n in names):
        raise ValueError("ticket commands require the complete ticket profile")
    if require_browser_tickets or manifest.get("browser_tickets_requested"):
        if manifest.get("browser_tickets_requested") is not True or manifest.get("browser_requested") is not True:
            raise ValueError("required browser ticket profile did not run")
        for mode in ("explicit", "implicit"):
            checked=browser_tickets.validate(path.parent,mode,steps,manifest.get("browser_ticket_output_sha256",{}).get(mode))
            if manifest.get("browser_ticket_governance",{}).get(mode)!=checked:
                raise ValueError("browser ticket outcomes differ from original evidence")
    elif any(browser_tickets.command_suffix(n) for n in names):
        raise ValueError("browser ticket commands require the complete profile")
    return {"state": "passed", "source_commit": commit, "manifest_sha256": digest,
            "stock_curl_qualified": True, "stock_lftp_qualified": True, "native_test_pass_records": len(NATIVE_TESTS), "source_inputs": len(sources),
            "public_cli_governance_cases": 2 * len(governance.CASES), "expected_cli_refusals": 2 * len(governance.REFUSALS),
            "native_commands": len(steps), "browser_qualified": manifest.get("browser_requested") is True,
            "browser_governance_cases": 12 if manifest.get("browser_requested") is True else 0,
            "strict_browser_api_refusals": 2 if manifest.get("browser_requested") is True else 0,
            "public_ticket_crash_cases": 12 if manifest.get("tickets_requested") is True else 0,
            "controlled_ftps_sigkills": 2 if manifest.get("tickets_requested") is True else 0,
            "strict_ticket_cli_refusals": 6 if manifest.get("tickets_requested") is True else 0,
            "strict_ticket_api_refusals": 2 if manifest.get("tickets_requested") is True else 0,
            "browser_ticket_cases": 12 if manifest.get("browser_tickets_requested") is True else 0,
            "browser_ticket_sigkills": 2 if manifest.get("browser_tickets_requested") is True else 0,
            "browser_ticket_api_refusals": 2 if manifest.get("browser_tickets_requested") is True else 0,
            "browser_ticket_accessibility_audits": 12 if manifest.get("browser_tickets_requested") is True else 0,
            "browser_ticket_lost_response_replays": 4 if manifest.get("browser_tickets_requested") is True else 0,
            "retained_metadata_and_roles_unchanged": True,
            "isolated_database_removed": True, "original_resource_state_restored": True,
            "inference_performed": False, "scanner_engine_started": False,
            "scope": "synthetic same-host FTPS receiving and authenticated retrieval; native stock curl/lftp plus TLS client stand-in; full journeys and proactive FTPS sending remain open"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", required=True)
    parser.add_argument("--require-browser", action="store_true")
    parser.add_argument("--require-tickets", action="store_true")
    parser.add_argument("--require-browser-tickets", action="store_true")
    args = parser.parse_args()
    commit = os.environ.get("GITHUB_SHA", "")
    try:
        commit = os.environ.get("GITHUB_SHA") or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        print(json.dumps(summarize(ROOT, Path(args.result), commit, args.require_browser, args.require_tickets, args.require_browser_tickets)))
        return 0
    except Exception:
        print(json.dumps({"state": "failed", "reason": "FTPS qualification or evidence validation failed; inspect protected outputs", **failure_diagnostics(ROOT, Path(args.result), commit)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
