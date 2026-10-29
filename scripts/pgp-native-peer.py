#!/usr/bin/env python3
"""Bounded, offline, task-owned native macOS GnuPG qualification peer.

This is test infrastructure, never a production private-key service. Native
execution must be selected explicitly with a protected acquisition manifest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_RSS = 128 << 20
MAX_SECONDS = 120
os.umask(0o077)


def protected(path):
    path = Path(path).resolve(strict=True)
    st = path.stat()
    if not path.is_file() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError("native peer configuration must be a private owner file")
    if st.st_size > 128 << 10:
        raise ValueError("native peer configuration is too large")
    return path


def configuration(path):
    path = protected(path)
    config = json.loads(path.read_text())
    if sys.platform != "darwin" or config["platform"] != "darwin/arm64":
        raise ValueError("this native peer profile requires macOS arm64")
    cache = (ROOT / ".cache/freightctl-gnupg-native").resolve()
    for entry in config["binaries"] + config["runtime_files"]:
        p = (ROOT / entry["path"]).resolve(strict=True)
        if not p.is_relative_to(cache) or hashlib.sha256(p.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("native peer runtime differs from its acquisition manifest")
    if not Path(config["binary_dir"]).resolve().is_relative_to(cache):
        raise ValueError("native peer executable must be in its task-owned cache")
    if any(not Path(p).resolve().is_relative_to(cache) for p in config["library_paths"]):
        raise ValueError("native peer libraries must be in their task-owned cache")
    return config


def terminate_group(pid):
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return


class Peer:
    def __init__(self, config, scratch):
        self.config, self.scratch = config, Path(scratch)
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                    "TMPDIR": str(self.scratch), "DYLD_LIBRARY_PATH": ":".join(config["library_paths"])}
        self.agents = {}

    def home(self, label):
        if label in self.agents:
            return self.scratch / label
        home = self.scratch / label
        home.mkdir(mode=0o700)
        (home / "common.conf").write_text("")  # Explicitly retain local keyrings, not keyboxd.
        log = (home / "agent.log").open("wb")
        args = [str(Path(self.config["binary_dir"]) / "gpg-agent"), "--homedir", str(home),
                "--daemon", "--no-detach", "--batch", "--disable-scdaemon", "--no-allow-external-cache"]
        agent = subprocess.Popen(args, env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        self.agents[label] = (agent, log)
        for _ in range(100):
            if (home / "S.gpg-agent").exists():
                return home
            if agent.poll() is not None:
                raise RuntimeError("native task agent failed: " + (home / "agent.log").read_text()[-2000:])
            time.sleep(0.02)
        raise RuntimeError("native task agent socket did not become ready")

    def gpg(self, label, *args):
        command = [str(Path(self.config["binary_dir"]) / "gpg"), "--no-options", "--homedir", str(self.home(label)),
                   "--no-autostart", "--no-auto-key-retrieve", "--auto-key-locate", "clear", "--no-tty",
                   "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *map(str, args)]
        r = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env=self.env, timeout=35)
        if len(r.stdout) + len(r.stderr) > 2 << 20:
            raise RuntimeError("native peer output exceeded its budget")
        if r.returncode:
            sys.stderr.buffer.write(r.stdout + r.stderr)
            raise RuntimeError("native GnuPG operation failed with status " + str(r.returncode))
        sys.stderr.buffer.write(r.stderr)
        return r.stdout

    def close(self):
        for agent, _ in self.agents.values():
            if agent.poll() is None:
                agent.terminate()
        for agent, log in self.agents.values():
            try:
                agent.wait(timeout=3)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait(timeout=3)
            log.close()

    def fingerprint(self, label):
        rows = self.gpg(label, "--with-colons", "--list-keys").decode().splitlines()
        return [row.split(":")[9] for row in rows if row.startswith("fpr:")]

    def prepare(self, work):
        work = Path(work)
        past, aged = str(int(time.time()) - 172800), str(int(time.time()) - 3600)
        (work / "gpg-version.txt").write_bytes(self.gpg("good", "--version"))
        (work / "packages.txt").write_text("\n".join(x["name"] + " " + x["bottle_tag"] + " sha256=" + x["bottle_sha256"] for x in self.config["dependencies"]) + "\n")
        self.gpg("good", "--faked-system-time", past, "--quick-generate-key", "freightctl synthetic signer", "ed25519", "cert,sign", "0")
        primary = self.fingerprint("good")[0]
        self.gpg("good", "--quick-add-key", primary, "ed25519", "sign", "0")
        subkey = self.fingerprint("good")[-1]
        (work / "good-fingerprint.txt").write_text(primary + "\n")
        (work / "subkey-fingerprint.txt").write_text(subkey + "\n")
        (work / "good-key-info.txt").write_bytes(self.gpg("good", "--with-colons", "--list-keys"))
        for armor, suffix in [(False, "gpg"), (True, "asc")]:
            self.gpg("good", *(["--armor"] if armor else []), "--output", work / ("good-public." + suffix), "--export", primary)
        for armor, name in [(False, "good.sig"), (True, "good.sig.asc")]:
            self.gpg("good", *(["--armor"] if armor else []), "--local-user", subkey + "!", "--digest-algo", "SHA256", "--output", work / name, "--detach-sign", work / "source.csv")
        self.gpg("good", "--faked-system-time", aged, "--local-user", primary + "!", "--digest-algo", "SHA256", "--output", work / "aged.sig", "--detach-sign", work / "source.csv")
        self.gpg("good", "--output", work / "private-rejection.gpg", "--export-secret-keys", primary)
        (work / "good-verification.txt").write_bytes(self.gpg("good", "--status-fd", "1", "--verify", work / "good.sig", work / "source.csv"))
        for label, algorithm, usage, expiration in [("other", "ed25519", "sign", "0"), ("rsa", "rsa3072", "sign", "0"), ("expired", "ed25519", "sign", "1d"), ("recipient", "ed25519", "cert", "1d"), ("recipient-rsa", "rsa3072", "cert", "1d")]:
            self.gpg(label, *(["--faked-system-time", past] if label in ("other", "expired") else []), "--quick-generate-key", "freightctl synthetic " + label, algorithm, usage, expiration)
            fingerprint = self.fingerprint(label)[0]
            (work / (label + "-fingerprint.txt")).write_text(fingerprint + "\n")
            if label.startswith("recipient"):
                self.gpg(label, "--quick-add-key", fingerprint, "cv25519" if label == "recipient" else "rsa3072", "encr", "1d")
                self.gpg(label, "--output", work / (label + "-private.gpg"), "--export-secret-keys", fingerprint)
            self.gpg(label, "--output", work / (label + "-public.gpg"), "--export", fingerprint)
            if label in ("other", "rsa"):
                self.gpg(label, "--local-user", fingerprint + "!", "--digest-algo", "SHA256", "--output", work / (label + ".sig"), "--detach-sign", work / "source.csv")
            if label == "rsa":
                self.gpg(label, "--local-user", fingerprint + "!", "--allow-weak-digest-algos", "--digest-algo", "SHA1", "--output", work / "weak.sig", "--detach-sign", work / "source.csv")
        rev = (self.scratch / "good/openpgp-revocs.d" / (primary + ".rev")).read_text().replace(":-----BEGIN", "-----BEGIN")
        rev = rev[rev.index("-----BEGIN PGP PUBLIC KEY BLOCK-----"):]
        rev = rev[:rev.index("-----END PGP PUBLIC KEY BLOCK-----") + len("-----END PGP PUBLIC KEY BLOCK-----")] + "\n"
        revocation = self.scratch / "revocation.asc"
        revocation.write_text(rev)
        self.gpg("good", "--import", revocation)
        self.gpg("good", "--output", work / "revoked-public.gpg", "--export", primary)


def worker(job):
    # A Go/Python caller can itself be killed on timeout. Its child watchdog
    # must not disappear with it and leave native processes running.
    if os.getpgrp() != os.getpid():
        raise ValueError("native worker requires its own controller-created process group")
    controller = int(job["controller_pid"])
    started = time.monotonic()

    def parent_guard():
        while True:
            if os.getppid() != controller or time.monotonic() - started > MAX_SECONDS + 10:
                os.killpg(os.getpid(), signal.SIGKILL)
                return
            time.sleep(0.1)

    threading.Thread(target=parent_guard, daemon=True).start()
    config = configuration(job["config"])
    peer = Peer(config, job["scratch"])
    try:
        if job["operation"] == "prepare":
            peer.prepare(job["work"])
        elif job["operation"] == "watchdog-probe":
            # Keep an ordinary interpreter alive so a deliberately tiny test
            # budget exercises termination without allocating a large payload.
            time.sleep(2)
        elif job["operation"] == "parent-death-probe":
            home = peer.home("parent-death")
            # --daemon may fork even with --no-detach. Ask the actual server,
            # rather than mistaking its short-lived launcher for the agent.
            info = subprocess.check_output([str(Path(config["binary_dir"]) / "gpg-connect-agent"), "--homedir", str(home),
                                            "--no-autostart", "GETINFO pid", "/bye"], env=peer.env, timeout=5)
            agent_pid = int(next(line[2:] for line in info.decode().splitlines() if line.startswith("D ")))
            (peer.scratch / "parent-death-ready.json").write_text(json.dumps({"agent_pid": agent_pid}))
            time.sleep(2)
        elif job["operation"] in ("verify", "decrypt"):
            peer.gpg("recipient", "--import", job["key"])
            if job["operation"] == "verify":
                sys.stdout.buffer.write(peer.gpg("recipient", "--status-fd", "1", "--verify", job["signature"], job["source"]))
            else:
                # GnuPG can leave plaintext even when it exits with BADMDC.
                # Keep its output private until both exit and authenticated
                # status succeed; only then publish a new receiver artifact.
                plain = peer.scratch / "plain.csv"
                proof = peer.gpg("recipient", "--status-fd", "1", "--output", plain, "--decrypt", job["cipher"])
                status = proof.splitlines()
                if b"[GNUPG:] DECRYPTION_OKAY" not in status or b"[GNUPG:] GOODMDC" not in status:
                    raise RuntimeError("native peer did not confirm authenticated MDC decryption")
                target = Path(job["output"])
                stage = Path(str(target) + ".part")
                created = False
                try:
                    with plain.open("rb") as source, stage.open("xb") as out:
                        created = True
                        shutil.copyfileobj(source, out, length=64 << 10)
                        out.flush()
                        os.fsync(out.fileno())
                    os.link(stage, target, follow_symlinks=False)
                finally:
                    if created:
                        stage.unlink()
                sys.stdout.buffer.write(proof)
        elif job["operation"] == "probe":
            failures = []
            cases = [("external_network", lambda: socket.create_connection(("127.0.0.1", job["probe_port"]), timeout=1)),
                     ("unlisted_private_read", lambda: Path(job["probe_read"]).read_bytes()),
                     ("unlisted_private_write", lambda: Path(job["probe_write"]).write_bytes(b"denied"))]
            if job.get("probe_alias"):
                cases.append(("unlisted_private_read_through_data_volume", lambda: Path(job["probe_alias"]).read_bytes()))
            if job.get("probe_signal_pid"):
                cases.append(("signal_outside_own_sandbox", lambda: os.kill(job["probe_signal_pid"], signal.SIGCONT)))
            for name, action in cases:
                try:
                    value = action()
                    if hasattr(value, "close"):
                        value.close()
                except PermissionError:
                    failures.append(name)
            if len(failures) != len(cases):
                raise RuntimeError("native peer sandbox boundary failed: " + repr(failures))
            print(json.dumps({"denied": failures}))
        else:
            raise ValueError("unknown native peer operation")
    finally:
        peer.close()


def run(job, max_rss=MAX_RSS):
    """Watch aggregate worker-family RSS; this is sampled enforcement, not cgroup isolation."""
    job["config"] = str(protected(job["config"]))
    job["metrics"] = str(Path(job["metrics"]).resolve())
    job["controller_pid"] = os.getpid()
    config = configuration(job["config"])
    with tempfile.TemporaryDirectory(prefix="freightctl-gpg-", dir="/private/tmp") as scratch:
        job["scratch"] = scratch
        reads = {str(Path(job["config"]).resolve()), str(Path(__file__).resolve()), scratch, str(ROOT / ".cache/freightctl-gnupg-native")}
        writes = {scratch}
        for key in ("work", "key", "signature", "source", "cipher", "output"):
            if job.get(key):
                p = Path(job[key]).resolve(strict=key != "output")
                job[key] = str(p)
                reads.add(str(p))
                if key == "work":
                    writes.add(str(p))
                elif key == "output":
                    writes.add(str(p))
                    # The adapter copies only authenticated plaintext here.
                    # GnuPG's own temporary output stays inside private scratch.
                    reads.add(str(p) + ".part")
                    writes.add(str(p) + ".part")
        q = json.dumps
        policy = '(version 1)(deny default)(allow process*)(allow sysctl-read)(allow mach-lookup)(allow ipc-posix*)(allow file-read-metadata)'
        policy += '(allow signal (target same-sandbox))'
        # The macOS loader reads the root directory itself before Python starts.
        # This literal permits no descendant file; unlisted private reads remain denied.
        policy += '(allow file-read* (literal "/")(subpath "/System/Library")(subpath "/System/Cryptexes")(subpath "/System/Volumes/Preboot/Cryptexes")(subpath "/usr")(subpath "/opt/homebrew")(subpath "/private/etc")(subpath "/private/var/db/timezone")(subpath "/dev")' + ''.join('(subpath ' + q(p) + ')' for p in sorted(reads)) + ')'
        policy += '(allow file-write* (literal "/dev/null")' + ''.join('(subpath ' + q(p) + ')' for p in sorted(writes)) + ')'
        policy += '(allow network* (local unix-socket (subpath ' + q(scratch) + '))(remote unix-socket (subpath ' + q(scratch) + ')))'
        request = Path(scratch) / "job.json"
        request.write_text(json.dumps(job))
        outpath, errpath = Path(scratch) / "stdout", Path(scratch) / "stderr"
        command = ["/usr/bin/sandbox-exec", "-p", policy, sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--worker", str(request)]
        started, peak, reason = time.monotonic(), 0, None
        cleanup_empty = False
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": scratch}
        with outpath.open("wb") as out, errpath.open("wb") as err:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env, start_new_session=True)
            lifecycle = {"controller_pid": os.getpid(), "child_process_group": process.pid, "scratch": scratch,
                         "operation": job["operation"], "config_sha256": hashlib.sha256(Path(job["config"]).read_bytes()).hexdigest()}
            lifecycle_path = Path(job["metrics"]).with_suffix(".lifecycle.json")
            lifecycle_path.write_text(json.dumps(lifecycle, indent=2) + "\n")
            try:
                while True:
                    rows = subprocess.check_output(["/bin/ps", "-axo", "pgid=,rss="]).decode().splitlines()
                    rss = sum(int(row.split()[1]) * 1024 for row in rows if len(row.split()) == 2 and int(row.split()[0]) == process.pid)
                    peak = max(peak, rss)
                    if rss > max_rss:
                        reason = "native peer process-family RSS exceeded its budget"
                    elif time.monotonic() - started > MAX_SECONDS:
                        reason = "native peer exceeded its wall-clock budget"
                    elif outpath.stat().st_size + errpath.stat().st_size > 4 << 20:
                        reason = "native peer output exceeded its budget"
                    if reason or process.poll() is not None:
                        break
                    time.sleep(0.1)
            finally:
                terminate_group(process.pid)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
                for _ in range(30):
                    groups = subprocess.check_output(["/bin/ps", "-axo", "pgid="]).decode().split()
                    if str(process.pid) not in groups:
                        cleanup_empty = True
                        break
                    time.sleep(0.1)
                if not cleanup_empty:
                    os.killpg(process.pid, signal.SIGKILL)
                    reason = reason or "native peer left live process-group members"
        sys.stdout.buffer.write(outpath.read_bytes())
        sys.stderr.buffer.write(errpath.read_bytes())
        metrics = {"state": "passed" if process.returncode == 0 and reason is None and cleanup_empty else "failed", "exit_code": process.returncode, "failure": reason,
                   "operation": job["operation"], "version": config["version"], "native_platform": "darwin/arm64", "duration_seconds": round(time.monotonic() - started, 3),
                   "rss_budget_bytes": max_rss, "sampled_process_family_peak_rss_bytes": peak, "rss_sampling_seconds": 0.1,
                   "resource_limits": "Sampled aggregate child process-group RSS watchdog and wall/output limits. Serial work; no kernel RSS or CPU quota claim.",
                   "sandbox": "Default deny; only explicit fixture/output/scratch writes and selected runtime reads; only scratch Unix sockets, no IP networking.",
                   "config_sha256": hashlib.sha256(Path(job["config"]).read_bytes()).hexdigest(), "local_model_processes_started": 0}
        metrics["child_process_group"] = process.pid
        metrics["cleanup_process_group_empty"] = cleanup_empty
        Path(job["metrics"]).write_text(json.dumps(metrics, indent=2) + "\n")
        if metrics["state"] != "passed":
            raise RuntimeError(reason or "native GnuPG peer failed")
        return metrics


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(json.loads(Path(sys.argv[2]).read_text()))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--metrics", required=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("prepare").add_argument("--work", required=True)
    verify = sub.add_parser("verify")
    for key in ("key", "signature", "source"):
        verify.add_argument("--" + key, required=True)
    decrypt = sub.add_parser("decrypt")
    for key in ("key", "cipher", "output"):
        decrypt.add_argument("--" + key, required=True)
    probe = sub.add_parser("probe")
    probe.add_argument("--probe-read", required=True)
    probe.add_argument("--probe-write", required=True)
    probe.add_argument("--probe-port", required=True, type=int)
    probe.add_argument("--probe-alias")
    probe.add_argument("--probe-signal-pid", type=int)
    run(vars(parser.parse_args()))


if __name__ == "__main__":
    main()
