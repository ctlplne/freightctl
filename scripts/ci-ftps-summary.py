#!/usr/bin/env python3
"""Allowlist aggregate FTPS qualification outcomes; never print raw evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def read(path, bound):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > bound:
        raise ValueError("unsafe or oversized FTPS evidence")
    return path.read_bytes()


def summarize(root, result, commit):
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
    for key in ("stock_curl_qualified", "retained_metadata_and_roles_unchanged", "isolated_database_removed", "original_resource_state_restored", "sources_unchanged"):
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
    required = ["TestFTPSNativeTLSClientProtocolAndInterruption", "TestFTPSStockCurlExplicitImplicitAndActiveCustody"]
    if not isinstance(tests, dict) or tests.get("required") != required or tests.get("pass_records") != 6 or tests.get("failed_records") != 0 or tests.get("skipped_records") != 0:
        raise ValueError("required FTPS tests are missing or skipped")
    steps = manifest.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 1000 or len({s.get("name") for s in steps}) != len(steps):
        raise ValueError("invalid FTPS command inventory")
    names = {s.get("name") for s in steps}
    for name in ("native-ftps-integration", "cli-explicit-upload", "cli-explicit-download", "cli-implicit-upload", "cli-implicit-download", "drop-exact-test-database"):
        if name not in names:
            raise ValueError("required FTPS command is missing")
    for step in steps:
        if type(step.get("exit_code")) is not int or step["exit_code"] != 0 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", step.get("name", "")):
            raise ValueError("native FTPS command failed or is incomplete")
        for extension, field in (("stdout", "stdout_sha256"), ("stderr", "stderr_sha256")):
            data = read(path.parent / (step["name"] + "." + extension), 64 << 20)
            if hashlib.sha256(data).hexdigest() != step.get(field):
                raise ValueError("native FTPS output checksum differs")
    native = read(path.parent / "native-ftps-integration.stdout", 64 << 20).decode()
    expected_tests = {name + suffix for name in required for suffix in ("", "/explicit", "/implicit")}
    executed = re.findall(r"^\s*--- PASS: (TestFTPS\S+) \(", native, re.MULTILINE)
    if len(executed) != 6 or set(executed) != expected_tests or "--- SKIP:" in native or "--- FAIL:" in native:
        raise ValueError("native FTPS output does not prove every required test")
    payload = b"exact FTPS CLI bytes\x00\r\n"
    for name in ("cli-explicit-download", "cli-implicit-download"):
        if read(path.parent / (name + ".stdout"), 8192) != payload:
            raise ValueError("stock FTPS CLI bytes differ")
    sources = manifest.get("source_sha256")
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 10000:
        raise ValueError("invalid FTPS source inventory")
    for name, expected in sources.items():
        p = root / name
        if not p.resolve().is_relative_to(root.resolve()) or hashlib.sha256(read(p, 16 << 20)).hexdigest() != expected:
            raise ValueError("FTPS source identity differs")
    return {"state": "passed", "source_commit": commit, "manifest_sha256": digest,
            "stock_curl_qualified": True, "native_test_pass_records": 6, "source_inputs": len(sources),
            "native_commands": len(steps), "retained_metadata_and_roles_unchanged": True,
            "isolated_database_removed": True, "original_resource_state_restored": True,
            "inference_performed": False, "scanner_engine_started": False,
            "scope": "synthetic same-host FTPS receiving and authenticated retrieval; native stock curl plus TLS client stand-in; full journeys and proactive FTPS sending remain open"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    try:
        commit = os.environ.get("GITHUB_SHA") or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        print(json.dumps(summarize(ROOT, Path(args.result), commit)))
        return 0
    except Exception:
        print(json.dumps({"state": "failed", "reason": "FTPS qualification or evidence validation failed; inspect protected outputs"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
