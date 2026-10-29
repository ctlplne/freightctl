#!/usr/bin/env python3
"""Reject broken qualification references and evidence-free success claims."""
import json
import hashlib
import re
from pathlib import Path

VERIFIED = {"verified locally", "externally qualified"}
COMMON_CASES = {"C-SCOPE", "C-DURABLE", "C-RETRY", "C-AUTHORITY",
                "C-BOUNDS", "C-RECEIPT", "C-PEER", "C-SURFACES"}


def artifact_evidence(root, entries, label):
    assert isinstance(entries, list) and entries, (label, "missing artifacts")
    for entry in entries:
        assert isinstance(entry, dict), label
        assert isinstance(entry.get("reference"), str), label
        assert re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")), label
        path = (root / entry["reference"]).resolve()
        assert path.is_relative_to(root.resolve()) and path.is_file(), label
        with path.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == entry["sha256"], label


def validate(records, root):
    if not __debug__:
        raise RuntimeError("Qualification checks require assertions; remove Python -O/PYTHONOPTIMIZE")
    sources = {s["id"]: s for s in records["sources"]["sources"]}
    assert len(sources) == len(records["sources"]["sources"]), "duplicate source"
    journeys = {j["id"] for j in records["journeys"]["journeys"]}
    states = set(records["parity"]["states"])
    rows = {}
    for row in records["parity"]["rows"]:
        assert row["id"] not in rows, row["id"]
        rows[row["id"]] = row
        assert row["state"] in states, row["id"]
        assert row["competitor"]["source_id"] in sources, row["id"]
        assert row["acceptance_journey"] in journeys, row["id"]
        for field in ("customer_job", "freightctl_behavior", "surfaces",
                      "implementation_owner", "dependencies", "native_clients_or_peers"):
            assert row[field], (row["id"], field)
        if row["state"] in VERIFIED:
            assert row["evidence"], row["id"]
        if row["state"] == "blocked":
            assert row["qualification_blockers"], row["id"]
        if row["state"] == "owner-approved exclusion":
            assert row.get("owner_authorization"), row["id"]
    for journey in records["journeys"]["journeys"]:
        if journey["state"] in VERIFIED:
            assert journey["candidate"] and journey["artifact_digests"]
            assert journey["evidence"] and journey["steps"] and journey["environment"]
    assert len(journeys) == 12

    register = records["protocol-profiles"]
    assert register["schema_version"] == 1, "unsupported protocol-contract schema"
    assert register["baseline_version"] == records["parity"]["baseline_version"] == records["sources"]["baseline_version"]
    cases = register["cases"]
    assert COMMON_CASES <= cases.keys(), "missing common acceptance cases"
    assert all(c.get("description") and c.get("source") for c in cases.values())
    required_rows = {r for r in rows if r.startswith(("P-AS1-", "P-AS2-", "P-AS3-", "P-AS4-", "P-OFTP2-", "P-PESIT-"))}
    profiles, mapped = set(), set()
    for profile in register["profiles"]:
        ident = profile["id"]
        assert ident not in profiles, ident
        profiles.add(ident)
        spec = profile["specification"]
        assert spec["selection"] in ("pinned", "open"), ident
        assert spec["target"] and profile["required_roles"] and profile["parity_rows"], ident
        if spec["selection"] == "pinned":
            assert spec["source_ids"], ident
        for source in spec["source_ids"]:
            assert source in sources and sources[source]["observation_kind"].startswith("Specification only"), (ident, source)
        prerequisites = profile["prerequisites"]
        assert {p["id"] for p in prerequisites} == {"security", "bounds", "peer", "conformance"}, ident
        assert len(prerequisites) == 4, ident
        for prerequisite in prerequisites:
            assert prerequisite["state"] in ("open", "resolved"), ident
            assert prerequisite["requirement"], ident
            if prerequisite["state"] == "resolved":
                artifact_evidence(root, prerequisite["evidence"], (ident, prerequisite["id"]))
        assert set(profile["qualification"]) <= profile["parity_rows"].keys(), ident
        for row_id, contract in profile["parity_rows"].items():
            assert row_id in required_rows and row_id not in mapped, row_id
            mapped.add(row_id)
            row = rows[row_id]
            assert row.get("protocol_profile") == ident, row_id
            required_cases = contract["required_cases"]
            assert len(required_cases) == len(set(required_cases)), row_id
            assert COMMON_CASES <= set(required_cases) <= cases.keys(), row_id
            assert contract["required_roles"] and set(contract["required_roles"]) <= set(profile["required_roles"]), row_id
            if row_id in {"P-AS2-SEND", "P-AS2-RECEIVE", "P-AS2-ROLLOVER"}:
                assert "AS2-RETRY" in required_cases, row_id
            if row_id.startswith("P-AS4-"):
                assert {"AS4-ROLES", "AS4-RECEIPTS", "AS4-SECURITY", "AS4-RECOVERY"} <= set(required_cases), row_id
                roles = {"push-initiator", "pull-responder"} if row_id.endswith("SEND") else {"push-responder", "pull-initiator"}
                assert roles <= set(contract["required_roles"]), row_id
            if row["state"] in VERIFIED:
                assert spec["selection"] == "pinned" and all(p["state"] == "resolved" for p in prerequisites), row_id
                qualification = profile["qualification"].get(row_id, {})
                assert re.fullmatch(r"[0-9a-f]{40}", qualification.get("candidate", "")), row_id
                assert qualification.get("environment") and qualification.get("steps"), row_id
                assert qualification.get("peer", {}).get("independently_implemented") is True, row_id
                assert qualification["peer"].get("version"), row_id
                assert re.fullmatch(r"[0-9a-f]{64}", qualification["peer"].get("artifact_sha256", "")), row_id
                assert set(contract["required_roles"]) <= set(qualification.get("observed_roles", [])), row_id
                results = qualification.get("cases", {})
                assert set(required_cases) <= results.keys(), row_id
                for case in required_cases:
                    assert results[case]["state"] == "passed", (row_id, case)
                    artifact_evidence(root, results[case]["evidence"], (row_id, case))
    assert mapped == required_rows, ("unmapped protocol rows", required_rows - mapped)
    assert all("protocol_profile" not in row or ident in mapped for ident, row in rows.items()), "unexpected protocol mapping"
    return len(rows), len(journeys), len(profiles)


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    base = root / "docs/qualification"
    records = {p.stem: json.loads(p.read_text()) for p in base.glob("*.json")}
    rows, journeys, profiles = validate(records, root)
    print(f"Record references valid: {rows} parity rows, {journeys} journeys and {profiles} protocol contracts. No runtime claim inferred.")
