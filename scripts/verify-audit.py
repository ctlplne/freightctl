#!/usr/bin/env python3
"""Verify a signed snapshot with stock OpenSSL and an independently trusted public key."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument("--export", required=True)
parser.add_argument("--trusted-key", required=True)
parser.add_argument("--tenant", required=True)
parser.add_argument("--partner", required=True)
parser.add_argument("--openssl", default="openssl")
args = parser.parse_args()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result

def native(*arguments):
    result = subprocess.run([args.openssl, *arguments], capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError("OpenSSL verification or public-key parsing failed")
    return result.stdout

try:
    path = Path(args.export)
    if not path.is_file() or path.stat().st_size > 24 << 20:
        raise ValueError("export exceeds the verifier input bound")
    trusted = Path(args.trusted_key)
    if not trusted.is_file() or trusted.stat().st_size > 4096:
        raise ValueError("trusted public-key file exceeds its input bound")
    envelope = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    if set(envelope) != {"format", "payload_base64", "signature_base64", "public_key_pem", "key_sha256_der"} or envelope["format"] != "freightctl-audit-snapshot-v1":
        raise ValueError("unknown export envelope")
    payload = base64.b64decode(envelope["payload_base64"], validate=True)
    signature = base64.b64decode(envelope["signature_base64"], validate=True)
    if len(payload) > 16 << 20 or len(signature) != 64 or len(envelope["public_key_pem"]) > 4096:
        raise ValueError("payload, signature or public key violates the format bound")
    trusted_der = native("pkey", "-pubin", "-in", str(trusted), "-outform", "DER")
    description = native("pkey", "-pubin", "-in", str(trusted), "-text_pub", "-noout")
    if description.splitlines()[0] != b"ED25519 Public-Key:":
        raise ValueError("snapshot format requires an Ed25519 verification identity")
    if hashlib.sha256(trusted_der).hexdigest() != envelope["key_sha256_der"]:
        raise ValueError("export signing identity differs from the independently trusted key")
    with tempfile.TemporaryDirectory(prefix="freightctl-audit-verify-") as temporary:
        directory = Path(temporary)
        (directory / "payload").write_bytes(payload)
        (directory / "signature").write_bytes(signature)
        (directory / "embedded-public.pem").write_text(envelope["public_key_pem"])
        embedded_der = native("pkey", "-pubin", "-in", str(directory / "embedded-public.pem"), "-outform", "DER")
        if embedded_der != trusted_der:
            raise ValueError("embedded identity differs from the trusted key")
        native("pkeyutl", "-verify", "-pubin", "-inkey", str(trusted), "-rawin", "-in", str(directory / "payload"), "-sigfile", str(directory / "signature"))
    snapshot = json.loads(payload, object_pairs_hook=unique_object)
    if snapshot["format"] != envelope["format"] or snapshot["tenant_id"] != args.tenant or snapshot["partner_id"] != args.partner:
        raise ValueError("snapshot format or expected resource scope differs")
    if str(uuid.UUID(snapshot["id"])) != snapshot["id"]:
        raise ValueError("invalid snapshot identity")
    events = snapshot["events"]
    if not isinstance(events, list) or len(events) > 100000 or snapshot["event_count"] != len(events):
        raise ValueError("snapshot event count differs")
    seen = set()
    for event in events:
        for field in ("id", "actor_id", "resource_id"):
            if str(uuid.UUID(event[field])) != event[field]:
                raise ValueError("invalid event reference")
        if event["id"] in seen or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,127}", event["kind"]):
            raise ValueError("duplicate or invalid event")
        seen.add(event["id"])
    print(json.dumps({"verified": True, "snapshot_id": snapshot["id"], "tenant_id": args.tenant, "partner_id": args.partner, "event_count": len(events), "payload_sha256": hashlib.sha256(payload).hexdigest(), "key_sha256_der": envelope["key_sha256_der"], "openssl": native("version").decode().strip(), "boundary": "Authenticates this scoped snapshot against the supplied trust key. Does not prove database history before export, protected retention, or receiver consumption."}, indent=2))
except Exception as error:
    print(json.dumps({"verified": False, "error": str(error)}))
    raise SystemExit(1)
