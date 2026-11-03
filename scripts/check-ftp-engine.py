#!/usr/bin/env python3
"""Verify the pinned FTP engine source/patch inventory; not runtime proof."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "third_party/ftpserverlib"
CHANGED = {"driver.go", "server.go", "transfer_pasv.go", "client_handler.go", "transfer_active.go", "handle_misc.go", "driver_test.go"}
ADDED = {"freightctl_active_test.go", "freightctl_passive_test.go", "freightctl_tls_fixture_test.go"}


def verify(directory=DIRECTORY):
    data = json.loads((directory / "UPSTREAM.json").read_text())
    if (data.get("module") != "github.com/fclairamb/ftpserverlib" or data.get("version") != "v0.32.7"
            or data.get("commit") != "a4adf0322c6c4f72e027f5106eeb918d5086f58f"):
        raise ValueError("FTP upstream identity differs")
    entries = data["files"]
    if not isinstance(entries, list) or len(entries) != 35:
        raise ValueError("FTP upstream inventory differs")
    names, changed = set(), set()
    for row in entries:
        name = row["path"]
        if name in names or not re.fullmatch(r"[a-z_]+\.go|go\.(mod|sum)|license\.txt", name):
            raise ValueError("unsafe or duplicate FTP upstream path")
        names.add(name)
        for key in ("upstream_sha256", "local_sha256"):
            if not re.fullmatch(r"[a-f0-9]{64}", row[key]):
                raise ValueError("invalid FTP source hash")
        if row["upstream_sha256"] != row["local_sha256"]:
            changed.add(name)
        path = directory / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["local_sha256"]:
            raise ValueError("FTP source bytes differ")
    if changed != CHANGED:
        raise ValueError("FTP patch scope differs")
    added = data["added_files"]
    if len(added) != len(ADDED) or {row["path"] for row in added} != ADDED:
        raise ValueError("FTP additional test inventory differs")
    for row in added:
        path = directory / row["path"]
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError("FTP patch test bytes differ")
    if {p.name for p in directory.iterdir()} != names | ADDED | {"UPSTREAM.json", "FREIGHTCTL.md"}:
        raise ValueError("unrecorded FTP dependency input")
    print("Pinned FTP engine:35 upstream files,7 modified files,3 added tests; MIT license preserved. No runtime claim inferred.")


if __name__ == "__main__":
    verify()
