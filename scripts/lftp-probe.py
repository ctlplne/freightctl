#!/usr/bin/env python3
"""Run stock lftp through a protected command file against a loopback fixture.

Only this task's files are touched. No password in argv, shell, home rc, debug
output or public evidence. The stock client's TLS1.3 data-session binding is
enforced by the actual server; this script cannot relax that policy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess

from ftps_contract import LFTP_CASES, LFTP_DOWNLOADS


class ProbeFailure(RuntimeError):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


def quote(value):
    # lftp's command language expands double-quoted strings. Refuse controls
    # and escape its metacharacters rather than invoking a shell.
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("control character in probe input")
    return '"' + re.sub(r'([\\"$`])', r'\\\1', value) + '"'


def read(path, limit, private=False):
    st = path.lstat()
    if path.is_symlink() or not path.is_file() or not 0 < st.st_size <= limit or (private and st.st_mode & 0o077):
        raise ValueError("unsafe probe reference")
    return path.read_bytes()


def run(reference, settings):
    port = settings["port"]
    if type(port) is not int or not 1024 <= port <= 65535 or type(settings["implicit"]) is not bool:
        raise ValueError("invalid loopback probe target")
    if not re.fullmatch(r"[0-9a-f-]{36}/[0-9a-f-]{36}", settings["username"]) or not re.fullmatch(r"[0-9a-f]{64}", settings["password"]):
        raise ValueError("invalid scoped probe identity")
    cert = Path(settings["certificate"]).absolute()
    read(cert, 128 << 10)
    source = Path(settings["source"]).absolute()
    payload = read(source, 1 << 20, private=True)
    directory = reference.with_suffix(".lftp")
    directory.mkdir(mode=0o700)
    runtime = directory / "runtime"
    runtime.mkdir(mode=0o700)
    # Do not repurpose HOME or inherit proxy settings. --norc suppresses user
    # rc; all mutable lftp state is scoped by LFTP_HOME to this fresh directory.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C", "LFTP_HOME": str(runtime)}

    def command(label, argv):
        settings["stage"] = label
        out, err = directory / (label + ".stdout"), directory / (label + ".stderr")
        with out.open("xb") as stdout, err.open("xb") as stderr:
            try:
                def bound_output():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20, 4 << 20))
                result = subprocess.run(argv, cwd=runtime, env=env, stdout=stdout, stderr=stderr, timeout=20, preexec_fn=bound_output)
            finally:
                stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        if result.returncode != 0:
            diagnostic = err.read_bytes()[:4096].decode(errors="replace")
            lower = diagnostic.lower()
            code = "client-command-failed"
            if "certificate" in lower:
                code = "certificate-refused"
            elif "login failed" in lower or "530 " in lower:
                code = "authentication-refused"
            elif "gnutls" in lower or "tls" in lower:
                code = "tls-transfer-refused"
            raise ProbeFailure(code, "stock lftp failed: " + diagnostic)
        return out.read_bytes()

    version = command("version", ["lftp", "--version"]).decode()
    first_line = version.splitlines()[0] if version else ""
    if not first_line.lower().startswith("lftp") or not re.search(r"\bVersion\s+4\.9\.2\b", first_line) or "GnuTLS" not in version:
        raise ProbeFailure("client-profile-differs", "stock lftp4.9.2/GnuTLS profile differs")
    base = [
        "debug 0", "set cmd:fail-exit yes", "set cmd:move-background no",
        "set cmd:save-cwd-history no", "set bmk:save-passwords no",
        "set net:max-retries 1", "set net:timeout 3", "set net:reconnect-interval-base 1",
        'set ftp:proxy ""', 'set net:no-proxy "*"',
        "set ftp:ssl-force yes", "set ftp:ssl-auth TLS", "set ftp:ssl-protect-data yes",
        "set ftp:ssl-protect-list yes", "set ftp:ssl-use-ccc no",
        "set ssl:verify-certificate yes", "set ssl:check-hostname yes",
        'set ssl:priority "NORMAL:-VERS-ALL:+VERS-TLS1.3"',
        "set ssl:ca-file " + quote(str(cert)),
        "set ftp:passive-mode yes", "set ftp:prefer-epsv yes",
        "open -u " + quote(settings["username"] + "," + settings["password"]) + " " +
        quote(("ftps" if settings["implicit"] else "ftp") + "://127.0.0.1:" + str(port)),
    ]
    if settings.get("ticket") is not None:
        ticket = settings["ticket"]
        if not isinstance(ticket,str) or not re.fullmatch(r"/\.freightctl/uploads/[0-9a-f-]{36}",ticket) or settings.get("ticket_phase") not in {"resume","download"}:
            raise ValueError("invalid stock ticket probe")
        phase = settings["ticket_phase"]
        commands = base + (["put -c " + quote(str(source)) + " -o " + quote(ticket),
                            "mv " + quote(ticket) + " /stock-ticket.csv"] if phase == "resume" else
                           ["get /stock-ticket.csv -o " + quote(str(directory / "ticket.download"))]) + ["bye"]
        script = directory / "commands"
        with script.open("x") as stream:
            stream.write("\n".join(commands)+"\n");stream.flush();os.fsync(stream.fileno())
        command("transfers",["lftp","--norc","-f",str(script)])
        if phase == "download" and read(directory / "ticket.download",1 << 20,private=True) != payload:
            raise ProbeFailure("bytes-differ","stock ticket bytes differ")
        cases = ["ticket-prefix-resume","bound-completion-replay"] if phase == "resume" else ["released-ticket-bytes"]
        return {"state":"passed","client":"lftp4.9.2/GnuTLS","cases":cases,"case_count":len(cases),"payload_bytes":len(payload),"payload_sha256":hashlib.sha256(payload).hexdigest(),"stock_client_qualification":True}
    commands = base + [
        "put " + quote(str(source)) + " -o lftp.bin",
        "get lftp.bin -o " + quote(str(directory / "epsv.download")),
        "set ftp:prefer-epsv no",
        "get lftp.bin -o " + quote(str(directory / "pasv.download")),
        "set ftp:passive-mode no",
        "put " + quote(str(source)) + " -o active.bin",
        "get active.bin -o " + quote(str(directory / "active.download")),
        "set ftp:passive-mode yes", "set ftp:prefer-epsv yes", "cls -1",
        "mkdir lftp-inbox", "mv lftp.bin lftp-inbox/renamed.bin",
        "get lftp-inbox/renamed.bin -o " + quote(str(directory / "renamed.download")),
        "rm lftp-inbox/renamed.bin", "rmdir lftp-inbox", "rm active.bin", "bye",
    ]
    script = directory / "commands"
    with script.open("x") as stream:
        stream.write("\n".join(commands) + "\n")
        stream.flush(); os.fsync(stream.fileno())
    listing = command("transfers", ["lftp", "--norc", "-f", str(script)])
    if b"lftp.bin" not in listing or b"active.bin" not in listing:
        raise ProbeFailure("listing-differs", "stock lftp listing omitted published files")
    for name in LFTP_DOWNLOADS:
        if read(directory / name, 1 << 20, private=True) != payload:
            raise ProbeFailure("bytes-differ", "stock lftp changed opaque bytes")
    return {"state": "passed", "client": "lftp4.9.2/GnuTLS", "cases": LFTP_CASES,
            "case_count": len(LFTP_CASES), "payload_bytes": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "tls_profile": "TLS1.3-only; verified fixture CA and hostname; server-enforced per-control resumption",
            "stock_client_qualification": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    reference = Path(args.reference).absolute()
    settings = {}
    try:
        settings = json.loads(read(reference, 8192, private=True))
        report = run(reference, settings)
    except Exception as exc:
        reason = str(exc)
        for key in ("password", "username"):
            value = settings.get(key)
            if isinstance(value, str) and value:
                reason = reason.replace(value, "[redacted]")
        reason = re.sub(r"[0-9a-fA-F]{64}", "[redacted]", reason)[:512]
        code = exc.code if isinstance(exc, ProbeFailure) else "client-unavailable" if isinstance(exc, FileNotFoundError) else "client-deadline" if isinstance(exc, subprocess.TimeoutExpired) else "probe-failed"
        print(json.dumps({"state": "failed", "stage": settings.get("stage"), "code": code, "failure_class": type(exc).__name__, "reason": reason}))
        return 1
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
