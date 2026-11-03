#!/usr/bin/env python3
"""Bounded native TLS1.3 FTP client/hostile-client stand-in, not stock-client proof.

Credentials arrive through one protected reference and never enter output. The
standard-library FTP client only adds explicit control-session TLS resumption.
"""
import argparse
import ftplib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import ssl


class BoundFTP(ftplib.FTP_TLS):
    def __init__(self, settings, context):
        super().__init__(context=context, timeout=4)
        self.settings = settings
        self.epsv = True
        self.resumed = []
        self.data_session = None
        self.extended_active = False

    def putcmd(self, line):
        # Only the verb enters diagnostics; USER/PASS arguments never do.
        self.settings["last_command"] = line.split(" ", 1)[0].upper()
        return super().putcmd(line)

    def open_control(self):
        self.host = "127.0.0.1"
        port = self.settings["port"]
        if self.settings["implicit"]:
            raw = socket.create_connection((self.host, port), timeout=4)
            self.sock = self.context.wrap_socket(raw, server_hostname=self.host)
            self.af = self.sock.family
            self.file = self.sock.makefile("r", encoding=self.encoding)
            self.welcome = self.getresp()
        else:
            self.connect(self.host, port)
            self.auth()
        assert self.sock.version() == "TLSv1.3", "control TLS version differs"
        self.login(self.settings["username"], self.settings["password"])
        self.prot_p()
        assert self.sock.session.has_ticket, "control did not issue a TLS ticket"
        return self

    def makepasv(self):
        if self.epsv:
            return ftplib.parse229(self.sendcmd("EPSV"), self.sock.getpeername())
        return super().makepasv()

    def sendport(self, host, port):
        if self.extended_active:
            return self.voidcmd("EPRT #1#" + host + "#" + str(port) + "#")
        return super().sendport(host, port)

    def ntransfercmd(self, command, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, command, rest)
        if self._prot_p:
            session = self.sock.session if self.data_session is None else self.data_session
            try:
                conn = self.context.wrap_socket(conn, server_hostname=self.host, session=None if session is False else session)
            except Exception:
                conn.close()
                raise
            self.resumed.append(conn.session_reused)
            assert conn.version() == "TLSv1.3", "data TLS version differs"
        return conn, size


def run(settings):
    context = ssl.create_default_context(cafile=settings["certificate"])
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    observed = []
    cases = []

    def client():
        c = BoundFTP(settings, context).open_control()
        observed.append(c)
        return c

    def download(c, name):
        data = bytearray()
        def append(chunk):
            if len(data) + len(chunk) > 1 << 20:
                raise RuntimeError("probe download bound exceeded")
            data.extend(chunk)
        c.retrbinary("RETR " + name, append)
        return bytes(data)

    def refuse(c, command, code):
        try:
            c.sendcmd(command)
        except ftplib.error_perm as error:
            assert str(error).startswith(str(code)), "wrong refusal category"
        else:
            raise AssertionError("unsafe command accepted")

    try:
        c = client()
        payload = b"opaque\x00FTPS\r\nbytes\n" * 1024
        c.storbinary("STOR wire.bin", io.BytesIO(payload))
        assert download(c, "wire.bin") == payload, "EPSV bytes differ"
        cases.append("epsv-exact-bytes")
        c.epsv = False
        assert download(c, "wire.bin") == payload, "PASV bytes differ"
        cases.append("pasv-exact-bytes")
        c.set_pasv(False)
        assert download(c, "wire.bin") == payload, "active bytes differ"
        c.extended_active = True
        assert download(c, "wire.bin") == payload, "EPRT bytes differ"
        c.extended_active = False
        c.storbinary("STOR active.bin", io.BytesIO(payload))
        c.set_pasv(True)
        assert download(c, "active.bin") == payload, "active upload differs"
        cases.append("active-exact-bytes")
        c.storbinary("APPE wire.bin", io.BytesIO(b"tail"))
        payload += b"tail"
        assert download(c, "wire.bin") == payload, "append differs"
        c.storbinary("STOR wire.bin", io.BytesIO(b"restart"), rest=len(payload))
        payload += b"restart"
        assert download(c, "wire.bin") == payload, "REST differs"
        cases.append("append-and-rest")
        c.mkd("inbox")
        c.rename("wire.bin", "guard.bin")
        c.rmd("inbox")
        c.delete("active.bin")
        assert "guard.bin" in c.nlst(), "namespace output differs"
        cases.append("namespace-commands")
        # TYPE A is also needed by ordinary directory clients. Exercise its
        # real text conversion; TYPE I above still preserves every file byte.
        c.storlines("STOR lines.txt", io.BytesIO(b"alpha\nbeta\r\n"))
        lines = []
        c.retrlines("RETR lines.txt", lines.append)
        assert lines == ["alpha", "beta"], "ASCII logical lines differ"
        c.delete("lines.txt")
        cases.append("ascii-logical-lines")
        refuse(c, "PROT C", 534)
        refuse(c, "TYPE E", 504)
        refuse(c, "PBSZ 1", 501)
        refuse(c, "AUTH TLS", 504)
        refuse(c, "EPRT |1|127.0.0.2|2000|", 501)
        refuse(c, "EPRT |1|127.0.0.1|22|", 501)
        refuse(c, "PORT 127,000,0,1,8,0", 501)
        cases.append("no-downgrade-unsupported-type-or-bounce")
        c.quit()

        for attack in ("missing-ticket", "foreign-ticket", "unnotified-eof", "control-disconnect", "abort"):
            a = client()
            b = None
            if attack == "missing-ticket":
                a.data_session = False
            elif attack == "foreign-ticket":
                b = client()
                a.data_session = b.sock.session
            data = None
            refused = False
            try:
                data = a.transfercmd("STOR guard.bin")
                data.sendall(b"short unaccepted replacement")
                if attack == "control-disconnect":
                    a.close()
                    # Observe server cancellation before sending any data EOF;
                    # an idle timeout must not masquerade as control cancellation.
                    data.settimeout(1.5)
                    try:
                        assert data.recv(1) == b"", "closed control left a live data stream"
                    except socket.timeout:
                        raise AssertionError("control cancellation exceeded its deadline")
                elif attack == "abort":
                    a.putcmd("ABOR")
                    try:
                        a.getresp()
                    except ftplib.error_temp:
                        pass
                    try:
                        data.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass
                elif attack in ("missing-ticket", "foreign-ticket"):
                    # A clean TLS end prevents the EOF safeguard from hiding a
                    # broken channel-binding check.
                    data.unwrap().close()
                # No TLS unwrap/close_notify: EOF is an error, not acceptance.
                data.close()
                if attack not in ("control-disconnect", "abort"):
                    try:
                        a.voidresp()
                    except (ftplib.error_perm, ftplib.error_temp, EOFError, OSError):
                        refused = True
                    assert refused, "incomplete or foreign data was acknowledged"
            except (ssl.SSLError, ftplib.error_perm, ftplib.error_temp, EOFError, OSError):
                refused = True
            finally:
                if data is not None:
                    data.close()
                a.close()
                if b is not None:
                    b.close()
            # A fresh authenticated channel observes the committed old revision.
            check = client()
            assert download(check, "guard.bin") == payload, "failed transfer replaced accepted bytes"
            check.quit()
            cases.append(attack + "-preserves-old-revision")
        # Missing/foreign-ticket probes can finish their client-side handshake
        # before Go's refusal arrives. Only ordinary data channels count here.
        ordinary = [r for c in observed if c.data_session is None for r in c.resumed]
        assert ordinary and all(ordinary), "ordinary data did not resume its control session"
        # Only this fresh fixture's path is removed. Immutable accepted file
        # revisions/events remain in PostgreSQL and custody. The next transport
        # profile can repeat the same non-overwriting rename journey.
        cleanup = client()
        cleanup.delete("guard.bin")
        cleanup.quit()
        return {"state": "passed", "client": "Python stdlib TLS1.3 FTP stand-in with explicit session reuse",
                "cases": cases, "case_count": len(cases), "ordinary_resumed_data_channels": len(ordinary),
                "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_bytes": len(payload),
                "all_ordinary_data_resumed": True, "stock_client_qualification": False}
    finally:
        for c in observed:
            c.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True)
    args = parser.parse_args()
    path = Path(args.reference)
    st = path.lstat()
    if path.is_symlink() or not path.is_file() or st.st_mode & 0o077 or st.st_size > 8192:
        raise RuntimeError("unsafe probe reference")
    settings = json.loads(path.read_text())
    if type(settings["port"]) is not int or not 1024 <= settings["port"] <= 65535 or type(settings["implicit"]) is not bool:
        raise RuntimeError("invalid loopback probe target")
    try:
        result = run(settings)
    except Exception as exc:
        reason = str(exc).replace(settings["password"], "[redacted]").replace(settings["username"], "[identity]")[:512]
        print(json.dumps({"state": "failed", "failure_class": type(exc).__name__, "last_command": settings.get("last_command"), "reason": reason}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
