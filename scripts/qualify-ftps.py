#!/usr/bin/env python3
"""Real scoped PostgreSQL/storage FTPS tests and stock-curl CLI journeys.

Only the exact task-owned bounded PostgreSQL resource may start. Tests use a
fresh database. Retained metadata/roles are observed before and after; models,
scanners, shared Docker lifecycle and the deferred aggregate are never run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
from urllib.parse import parse_qsl, urlsplit, urlunsplit
import uuid

from ftps_contract import CLI_PAYLOAD, HOSTILE_CASE_COUNT, LFTP_CASES, LIMITED_PARENT_TESTS, NATIVE_PARENT_TESTS
import ftps_cli_governance as governance
import ftps_browser_evidence as browser_evidence

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("metadata", ROOT / "scripts/qualify-retained-metadata.py")
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def sources():
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    result = {}
    for name in sorted(set(names) - {""}):
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 << 20:
            raise RuntimeError("unsafe or oversized source input")
        result[name] = metadata.digest(path)
    return result


def main():
    if not __debug__:
        raise RuntimeError("qualification requires assertions; remove Python optimization")
    parser = argparse.ArgumentParser()
    parser.add_argument("--postgres-container-id", required=True)
    parser.add_argument("--native-client-only", action="store_true", help="exercise the native TLS1.3 client stand-in; stock curl stays unqualified")
    parser.add_argument("--browser", action="store_true", help="also qualify reviewed HTTPS browser governance against live FTPS writers and intake")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.postgres_container_id):
        raise RuntimeError("use the exact task-owned container ID")
    os.chdir(ROOT)
    os.umask(0o077)
    observer = metadata.Exercise(args.postgres_container_id, 35)
    # Reuse bounded native SQL observations, not the backup/upgrade journey.
    private = ROOT / ".private" / ("ftps-" + uuid.uuid4().hex)
    observer.private.rename(private)
    observer.private = private
    metadata.sync_directory(private.parent)
    database = "freightctl_ftps_" + uuid.uuid4().hex
    binary = private / "freightctl"
    manifest = {"schema_version": 1, "kind": "stock-ftps-custody", "state": "failed",
                "starting_commit": subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip(),
                "observed_at": datetime.now(timezone.utc).isoformat(), "fixture_reference": str(private.relative_to(ROOT)),
                "database": database, "postgres_container_id": args.postgres_container_id,
                "inference_performed": False, "scanner_engine_started": False,
                "full_foundation_aggregate_executed": False, "full_journeys_qualified": False}
    manifest["native_client_only"] = args.native_client_only
    manifest["browser_requested"] = args.browser
    manifest["stock_curl_qualified"] = False
    manifest["stock_lftp_qualified"] = False
    processes, created, started, originally_running = {}, False, False, None
    before = None
    cleanup = []
    env = dict(os.environ, GOMAXPROCS="1", GOMEMLIMIT="192MiB")

    def command(label, argv, timeout=60):
        # Passing secret values in argv is forbidden; callers use references.
        out = private / (label + ".stdout")
        err = private / (label + ".stderr")
        began = time.monotonic()
        with out.open("xb") as stdout, err.open("xb") as stderr:
            child = None
            try:
                if re.fullmatch(r"browser-(?:explicit|implicit)-operator", label):
                    child = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr, env=env, start_new_session=True, preexec_fn=metadata.bounded_output)
                    code = child.wait(timeout=timeout)
                else:
                    r = subprocess.run(list(map(str, argv)), stdout=stdout, stderr=stderr, env=env,
                                       timeout=timeout, preexec_fn=metadata.bounded_output)
                    code = r.returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
                if child is not None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=5)
            stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        metadata.sync_directory(private)
        observer.steps.append({"name": label, "exit_code": code, "seconds": round(time.monotonic() - began, 3),
                               "stdout_sha256": metadata.digest(out), "stderr_sha256": metadata.digest(err)})
        try:
            governance.verify_outcome(label, code, err.read_bytes(), out.read_bytes())
        except ValueError:
            raise RuntimeError(label + " failed; protected native output retained") from None
        return out.read_bytes()

    def stop(label):
        item = processes.pop(label, None)
        if item is None:
            return
        p, out, err = item
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
        try:
            code = p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=5)
            cleanup.append(label + " required forced process cleanup")
            code = "forced"
        out.flush(); err.flush(); os.fsync(out.fileno()); os.fsync(err.fileno()); out.close(); err.close()
        observer.steps.append({"name": label, "exit_code": code,
                               "stdout_sha256": metadata.digest(private / (label + ".stdout")),
                               "stderr_sha256": metadata.digest(private / (label + ".stderr"))})
        if code != 0:
            cleanup.append(label + " did not stop cleanly")

    initial = sources()
    manifest["source_sha256"] = initial
    try:
        resource = observer.inspect("resource-before")
        if (resource["Id"] != args.postgres_container_id
                or resource["Config"].get("Labels", {}).get("freightctl.workspace") != str(ROOT)
                or resource["HostConfig"]["Memory"] != 536870912
                or resource["HostConfig"]["NanoCpus"] != 1000000000
                or resource["HostConfig"]["PortBindings"].get("5432/tcp") != [{"HostIp": "127.0.0.1", "HostPort": "25432"}]):
            raise RuntimeError("PostgreSQL ownership, budget or loopback binding differs")
        originally_running = resource["State"]["Running"]
        manifest["postgres_originally_running"] = originally_running
        if not originally_running:
            observer.command("start-exact-postgres", ["docker", "start", args.postgres_container_id])
            started = True
        deadline = time.monotonic() + 30
        while subprocess.run(["docker", "exec", args.postgres_container_id, "pg_isready", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode:
            if time.monotonic() > deadline:
                raise RuntimeError("exact PostgreSQL resource did not become ready")
            time.sleep(.2)
        if observer.clients("other-clients-before"):
            raise RuntimeError("another client uses the retained resource")
        before = observer.snapshot("retained-before")
        manifest["retained_before"] = before
        observer.sql("create-exact-test-database", "CREATE DATABASE " + database + " TEMPLATE template0;")
        created = True
        for name in ("pg-admin.dsn", "pg-runtime.dsn"):
            ref = ROOT / ".private" / name
            if ref.is_symlink() or not ref.is_file() or ref.stat().st_mode & 0o077 or ref.stat().st_size > 4096:
                raise RuntimeError("unsafe database reference")
            uri = urlsplit(ref.read_text())
            if uri.hostname != "127.0.0.1" or uri.port != 25432 or uri.path != "/freightctl" or parse_qsl(uri.query) != [("sslmode", "disable")]:
                raise RuntimeError("database reference does not name the exact retained fixture")
            (private / name).write_text(urlunsplit(uri._replace(path="/" + database)))
        command("go-version", ["sh", "scripts/go.sh", "version"])
        command("build", ["sh", "scripts/go.sh", "build", "-p", "1", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/freightctl"], 120)
        manifest["binary_sha256"] = metadata.digest(binary)
        command("migrate-test-database", [binary, "init", "--admin-dsn-file", private / "pg-admin.dsn"])
        env.update(FREIGHTCTL_TEST_ADMIN_FILE=str(private / "pg-admin.dsn"), FREIGHTCTL_TEST_RUNTIME_FILE=str(private / "pg-runtime.dsn"))
        command("stock-curl-version", ["curl", "--version"])
        if not args.native_client_only:
            command("stock-lftp-version", ["lftp", "--version"])
        required = LIMITED_PARENT_TESTS if args.native_client_only else NATIVE_PARENT_TESTS
        selected = "^(" + "|".join(required) + ")$" if args.native_client_only else "^TestFTPS"
        test_output = command("native-ftps-integration", ["sh", "scripts/go.sh", "test", "-p", "1", "-tags=integration", "-race", "-count=1", "-timeout=120s", "-v", "-run", selected, "./internal/custody"], 150).decode()
        expected = {name + suffix for name in required for suffix in ("", "/explicit", "/implicit")}
        executed = re.findall(r"^\s*--- PASS: (TestFTPS\S+) \(", test_output, re.MULTILINE)
        if len(executed) != len(expected) or set(executed) != expected or "--- SKIP:" in test_output or "--- FAIL:" in test_output:
            raise RuntimeError("required native FTPS tests did not execute successfully")
        manifest["native_tests"] = {"required": required, "pass_records": test_output.count("--- PASS:"), "failed_records": 0, "skipped_records": 0}
        tenant, partner = str(uuid.uuid4()), str(uuid.uuid4())
        token, cert, key = private / "owner.token", private / "cert.pem", private / "key.pem"
        command("cli-token", [binary, "token", "--token-file", token])
        command("cli-enroll", [binary, "enroll", "--admin-dsn-file", private / "pg-admin.dsn", "--tenant", tenant, "--partner", partner, "--token-file", token])
        command("cli-cert", [binary, "dev-cert", "--cert", cert, "--key", key])
        if args.browser:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                http_port = probe.getsockname()[1]
            out, err = (private / "browser-https.stdout").open("xb"), (private / "browser-https.stderr").open("xb")
            p = subprocess.Popen(list(map(str, [binary, "serve", "--listen", "127.0.0.1:" + str(http_port), "--dsn-file", private / "pg-runtime.dsn", "--storage", private / "custody", "--cert", cert, "--key", key])), stdout=out, stderr=err, env=env, start_new_session=True)
            processes["browser-https"] = (p, out, err)
            deadline = time.monotonic() + 10
            while True:
                if p.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("browser HTTPS listener did not start")
                try:
                    with socket.create_connection(("127.0.0.1", http_port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.05)
        config = private / "curl.conf"
        config.write_text("user = " + json.dumps(tenant + "/" + partner + ":" + token.read_text()) + "\ncacert = " + json.dumps(str(cert)) + "\nssl-reqd\ntls-max = \"1.3\"\nnoproxy = \"*\"\nconnect-timeout = 3\nmax-time = 10\nsilent\nshow-error\n")
        payload = CLI_PAYLOAD
        source = private / "payload"
        source.write_bytes(payload)
        for implicit in (False, True):
            label = "cli-implicit" if implicit else "cli-explicit"
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            argv = [binary, "serve-ftps", "--listen", "127.0.0.1:" + str(port), "--dsn-file", private / "pg-runtime.dsn", "--storage", private / "custody", "--cert", cert, "--key", key, "--ftps-active"]
            if implicit:
                argv.append("--ftps-implicit")
            out, err = (private / (label + ".stdout")).open("xb"), (private / (label + ".stderr")).open("xb")
            p = subprocess.Popen(list(map(str, argv)), stdout=out, stderr=err, env=env, start_new_session=True)
            processes[label] = (p, out, err)
            deadline = time.monotonic() + 10
            while True:
                if p.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(label + " listener did not start")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.05)
            url = ("ftps" if implicit else "ftp") + "://127.0.0.1:" + str(port) + "/" + label + ".bin"
            if args.native_client_only:
                ref = private / (label + ".probe.json")
                ref.write_text(json.dumps({"port": port, "implicit": implicit, "certificate": str(cert), "username": tenant + "/" + partner, "password": token.read_text()}))
                report = json.loads(command(label + "-native-probe", ["python3", "scripts/ftps-probe.py", "--reference", ref]))
                if report["state"] != "passed" or report["case_count"] != HOSTILE_CASE_COUNT or not report["all_ordinary_data_resumed"]:
                    raise RuntimeError(label + " native probe incomplete")
            else:
                command(label + "-upload", ["curl", "-q", "--config", config, "--upload-file", source, url])
                downloaded = command(label + "-download", ["curl", "-q", "--config", config, url])
                if downloaded != payload:
                    raise RuntimeError(label + " changed opaque bytes")
                ref = private / (label + ".json")
                ref.write_text(json.dumps({"port": port, "implicit": implicit, "certificate": str(cert), "source": str(source), "username": tenant + "/" + partner, "password": token.read_text()}))
                report = json.loads(command(label + "-lftp-probe", ["python3", "scripts/lftp-probe.py", "--reference", ref]))
                if report.get("state") != "passed" or report.get("cases") != LFTP_CASES or report.get("stock_client_qualification") is not True:
                    raise RuntimeError(label + " stock lftp probe incomplete")
            manifest.setdefault("cli_governance", {})["implicit" if implicit else "explicit"] = governance.exercise(private, "implicit" if implicit else "explicit", port, cert, binary, env, observer.steps, command, metadata.bounded_output)
            if args.browser:
                mode = "implicit" if implicit else "explicit"
                directory = private / ("browser-" + mode)
                directory.mkdir(mode=0o700)
                cfg = {"root": str(ROOT), "private": str(directory), "url": "https://127.0.0.1:" + str(http_port), "certificate": str(cert), "port": port, "implicit": implicit}
                for kind in ("credential", "intake"):
                    who = {"tenant": str(uuid.uuid4()), "partner": str(uuid.uuid4()), "token": str(directory / (kind + ".token"))}
                    command("browser-" + mode + "-" + kind + "-token", [binary, "token", "--token-file", who["token"]])
                    command("browser-" + mode + "-" + kind + "-enroll", [binary, "enroll", "--admin-dsn-file", private / "pg-admin.dsn", "--tenant", who["tenant"], "--partner", who["partner"], "--token-file", who["token"]])
                    cfg[kind] = who
                ref = directory / "config.json"
                ref.write_text(json.dumps(cfg))
                command("browser-" + mode + "-operator", ["node", "scripts/ftps-operator-browser.mjs", ref], 240)
                manifest.setdefault("browser_governance", {})[mode] = browser_evidence.validate(directory)
                manifest.setdefault("browser_output_sha256", {})[mode] = {str(path.relative_to(directory)): metadata.digest(path) for path in sorted(directory.iterdir()) if path.is_file() and not path.is_symlink()}
            stop(label)
        if args.browser:
            stop("browser-https")
        manifest["state"] = "passed"
        manifest["stock_curl_qualified"] = not args.native_client_only
        manifest["stock_lftp_qualified"] = not args.native_client_only
    except Exception as exc:
        manifest["failure"] = str(exc)
    finally:
        for label in list(processes):
            try:
                stop(label)
            except Exception:
                cleanup.append(label + " process cleanup failed")
        if created:
            try:
                active = observer.sql("test-database-clients", "SELECT count(*) FROM pg_stat_activity WHERE datname='" + database + "' AND pid<>pg_backend_pid();")
                if active != "0":
                    raise RuntimeError("test clients remain")
                observer.sql("drop-exact-test-database", "DROP DATABASE " + database + ";")
                manifest["isolated_database_removed"] = True
            except Exception:
                cleanup.append("exact test database retained; no forced drop")
        if before is not None:
            try:
                after = observer.snapshot("retained-after")
                manifest["retained_after"] = after
                manifest["retained_metadata_and_roles_unchanged"] = before == after
                if before != after:
                    cleanup.append("retained metadata or role authority changed")
            except Exception:
                cleanup.append("retained preservation observation failed")
        if started:
            try:
                if observer.clients("other-clients-after"):
                    raise RuntimeError("clients remain; do not stop PostgreSQL")
                observer.command("stop-exact-postgres", ["docker", "stop", "--time", "10", args.postgres_container_id])
                manifest["original_stopped_state_restored"] = True
            except Exception:
                cleanup.append("PostgreSQL left available; original stopped state not restored")
        if originally_running is not None:
            try:
                final_resource = observer.inspect("resource-after")
                manifest["original_resource_state_restored"] = final_resource["State"]["Running"] == originally_running
                if not manifest["original_resource_state_restored"]:
                    cleanup.append("PostgreSQL running state differs")
            except Exception:
                cleanup.append("final exact resource observation failed")
        manifest["cleanup_failures"] = cleanup
        manifest["sources_unchanged"] = initial == sources()
        manifest["steps"] = observer.steps
        if cleanup or not manifest["sources_unchanged"]:
            manifest["state"] = "failed"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = private / "manifest.json"
        with path.open("x") as output:
            json.dump(manifest, output, indent=2); output.write("\n"); output.flush(); os.fsync(output.fileno())
        metadata.sync_directory(private)
    print(json.dumps({"state": manifest["state"], "manifest_reference": str(path.relative_to(ROOT)), "manifest_sha256": metadata.digest(path), "failure": manifest.get("failure"), "cleanup_failures": cleanup}))
    return 0 if manifest["state"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
