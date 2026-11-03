#!/usr/bin/env python3
"""TLS client stand-in coordinated with actual governed PostgreSQL commands.

The Go integration test sends fixed phase commands over stdin. Credentials
arrive only through a protected reference. No model or scanner is involved.
"""
import argparse
import ftplib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import ssl
import sys

spec = importlib.util.spec_from_file_location("ftps_probe", Path(__file__).with_name("ftps-probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def emit(state, **fields):
    print(json.dumps({"state": state, **fields}), flush=True)


def phase(expected):
    line = sys.stdin.buffer.readline(1025)
    if len(line) > 1024 or not line.endswith(b"\n") or json.loads(line) != {"action": expected}:
        raise ValueError("unexpected governance phase")


def download(client, name):
    result = bytearray()
    def collect(data):
        if len(result) + len(data) > 1 << 20:
            raise ValueError("governance download exceeds bound")
        result.extend(data)
    client.retrbinary("RETR " + name, collect)
    return bytes(result)


def unavailable(client, name):
    try:
        download(client, name)
    except ftplib.error_perm as error:
        assert str(error).startswith("550"), "unexpected unavailable-file category"
    else:
        raise AssertionError("held, quarantined or revoked bytes were downloadable")


def run(settings, reference=None):
    context = ssl.create_default_context(cafile=settings["certificate"])
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    observed = []

    def client(password):
        config = dict(settings, password=password)
        c = probe.BoundFTP(config, context)
        observed.append(c)
        return c.open_control()

    def rejected_login(password):
        c = probe.BoundFTP(dict(settings, password=password), context)
        observed.append(c)
        c.open_control(authenticate=False)
        try:
            c.login(settings["username"], password)
        except ftplib.error_perm as error:
            assert str(error).startswith("530"), "unexpected credential refusal category"
        else:
            raise AssertionError("obsolete credential authenticated")
        finally:
            c.close()

    def begin_overwrite(c):
        c.voidcmd("TYPE I")
        data = c.transfercmd("STOR guard.bin")
        assert data.session_reused, "open writer data did not resume its control"
        data.sendall(b"unaccepted replacement prefix\x00\r\n")
        return data

    def finish_refused(c, data):
        # Attempt a clean TLS completion. No raw EOF is injected: that would
        # exercise the transport guard instead of current credential authority.
        try:
            data.sendall(b"replacement tail")
            data.unwrap().close()
        except (OSError, ssl.SSLError):
            pass  # Authority cancellation may already have closed this data.
        finally:
            data.close()
        try:
            c.voidresp()
        except (ftplib.error_perm, ftplib.error_temp, EOFError, OSError):
            pass
        else:
            raise AssertionError("invalidated open writer received a success reply")
        c.close()

    try:
        if settings["scenario"] == "credential-lifecycle":
            baseline = b"accepted before credential changes\x00\r\n"
            old = client(settings["password"])
            old.storbinary("STOR guard.bin", io.BytesIO(baseline))
            assert download(old, "guard.bin") == baseline, "baseline bytes differ"
            data = begin_overwrite(old)
            emit("writer-open-before-rotation", resumed=True)
            phase("rotation-committed")
            finish_refused(old, data)
            rejected_login(settings["password"])
            rotated = client(settings["next_password"])
            assert download(rotated, "guard.bin") == baseline, "rotation replaced accepted bytes"
            rotated.storbinary("STOR rotated-accepted.bin", io.BytesIO(baseline))
            assert download(rotated, "rotated-accepted.bin") == baseline, "rotated credential could not complete a new transfer"
            data = begin_overwrite(rotated)
            emit("writer-open-before-revocation", resumed=True)
            phase("revocation-committed")
            finish_refused(rotated, data)
            rejected_login(settings["next_password"])
            observer = client(settings["observer_password"])
            assert download(observer, "guard.bin") == baseline, "revocation replaced accepted bytes"
            observer.quit()
            count = 2
        elif settings["scenario"] == "upload-ticket":
            payload = b"account,amount,day\n" + b"0001,1.01,2026-10-28\n" * 10000
            ticket = settings["ticket"]
            assert re.fullmatch(r"/\.freightctl/uploads/[0-9a-f-]{36}", ticket)
            c = client(settings["password"])
            c.voidcmd("TYPE I")
            assert c.size(ticket) == 0, "new ticket did not expose zero durable progress"
            c.voidcmd("TYPE A")
            try:
                c.transfercmd("STOR " + ticket)
            except ftplib.error_perm as error:
                assert str(error).startswith("550")
            else:
                raise AssertionError("ticket accepted ASCII conversion")
            c.voidcmd("TYPE I")
            data = c.transfercmd("STOR " + ticket)
            assert data.session_reused
            data.sendall(payload[:65536 + 97])
            emit("ticket-checkpoint-open", resumed=True)
            phase("interrupt-now")
            data.close()  # Deliberate unclean EOF; only durable checkpoints survive.
            c.close()
            emit("ticket-interrupted")
            phase("server-restarted")
            foreign = client(settings["foreign_password"])
            try:
                foreign.size(ticket)
            except ftplib.error_perm as error:
                assert str(error).startswith("550")
            else:
                raise AssertionError("another actor saw ticket progress")
            try:
                foreign.transfercmd("STOR " + ticket)
            except ftplib.error_perm as error:
                assert str(error).startswith("550")
            else:
                raise AssertionError("another actor opened the ticket writer")
            foreign.close()
            c = client(settings["password"])
            c.voidcmd("TYPE I")
            assert c.size(ticket) == 65536, "unacknowledged tail changed durable progress"
            unavailable(c, ticket)
            unavailable(c, "recovered.csv")
            try:
                c.transfercmd("STOR " + ticket, rest=65535)
            except ftplib.error_perm as error:
                assert str(error).startswith("550")
            else:
                raise AssertionError("wrong restart offset opened a ticket writer")
            data = c.transfercmd("STOR " + ticket, rest=65536)
            assert data.session_reused
            data.sendall(payload[65536:])
            data.unwrap().close()
            emit("ticket-data-finished", resumed=True)
            phase("discard-final-reply")
            c.close()  # Intentionally never consume the final 226 response.
            emit("ticket-final-reply-unobserved")
            phase("receipt-inspected")
            c = client(settings["password"])
            c.voidcmd("TYPE I")
            assert c.size(ticket) == len(payload)
            unavailable(c, ticket)
            unavailable(c, "recovered.csv")
            try:
                c.rename(ticket, "/wrong-destination.csv")
            except ftplib.error_perm as error:
                assert str(error).startswith("550")
            else:
                raise AssertionError("ticket completion changed its bound destination")
            c.rename(ticket, "/recovered.csv")
            unavailable(c, "recovered.csv")
            emit("ticket-completed-held")
            phase("release-committed")
            retrieved = download(c, "recovered.csv")
            assert retrieved == payload
            if "download_reference" in settings:
                target = Path(settings["download_reference"])
                assert target.parent.resolve() == reference.parent.resolve() and not target.exists()
                with target.open("xb") as output:
                    output.write(retrieved)
                    output.flush()
                    os.fsync(output.fileno())
            unavailable(c, ticket)
            c.quit()
            count = 6
        elif settings["scenario"] == "intake":
            good = b"account,amount,day\n0001,1.01,2026-10-28\n"
            bad = b"account,amount,day\n0001,invalid,2026-10-28\n"
            c = client(settings["password"])
            c.storbinary("STOR good.csv", io.BytesIO(good))
            c.storbinary("STOR bad.csv", io.BytesIO(bad))
            assert not {"good.csv", "bad.csv"} & set(c.nlst()), "held path was listed"
            unavailable(c, "good.csv")
            unavailable(c, "bad.csv")
            emit("uploads-held")
            phase("checks-completed")
            unavailable(c, "good.csv")
            unavailable(c, "bad.csv")
            emit("passed-still-unreleased")
            phase("release-committed")
            assert download(c, "good.csv") == good, "released immutable bytes differ"
            unavailable(c, "bad.csv")
            names = set(c.nlst())
            assert "good.csv" in names and "bad.csv" not in names, "release/quarantine listing differs"
            emit("only-approved-revision-published")
            phase("policy-revocation-committed")
            unavailable(c, "good.csv")
            unavailable(c, "bad.csv")
            c.quit()
            count = 4
        else:
            raise ValueError("unknown governance scenario")
        ordinary = [resumed for c in observed for resumed in c.resumed]
        assert ordinary and all(ordinary), "governance data did not resume its control"
        emit("passed", case_count=count, all_data_resumed=True)
    finally:
        for c in observed:
            c.close()


def main():
    if not __debug__:
        emit("failed", failure_class="UnsafeOptimization", reason="Python assertions are required for protocol qualification")
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True)
    args = parser.parse_args()
    settings = {}
    try:
        p = Path(args.reference)
        st = p.lstat()
        if p.is_symlink() or not p.is_file() or st.st_mode & 0o077 or not 0 < st.st_size <= 8192:
            raise ValueError("unsafe governance reference")
        settings = json.loads(p.read_text())
        if type(settings["port"]) is not int or not 1024 <= settings["port"] <= 65535 or type(settings["implicit"]) is not bool:
            raise ValueError("invalid loopback governance target")
        run(settings, p)
    except Exception as exc:
        reason = str(exc)
        for key in ("password", "next_password", "observer_password", "foreign_password", "username"):
            value = settings.get(key)
            if isinstance(value, str) and value:
                reason = reason.replace(value, "[redacted]")
        reason = re.sub(r"[0-9a-fA-F]{64}", "[redacted]", reason)[:512]
        emit("failed", failure_class=type(exc).__name__, reason=reason)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
