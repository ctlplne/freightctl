#!/usr/bin/env python3
"""Reject broken qualification references and evidence-free success claims."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
base = root / "docs/qualification"
records = {p.stem: json.loads(p.read_text()) for p in base.glob("*.json")}
sources = {s["id"] for s in records["sources"]["sources"]}
journeys = {j["id"] for j in records["journeys"]["journeys"]}
states = set(records["parity"]["states"])
seen = set()
for row in records["parity"]["rows"]:
    assert row["id"] not in seen, row["id"]
    seen.add(row["id"])
    assert row["state"] in states, row["id"]
    assert row["competitor"]["source_id"] in sources, row["id"]
    assert row["acceptance_journey"] in journeys, row["id"]
    for field in ("customer_job", "freightctl_behavior", "surfaces",
                  "implementation_owner", "dependencies", "native_clients_or_peers"):
        assert row[field], (row["id"], field)
    if row["state"] in ("verified locally", "externally qualified"):
        assert row["evidence"], row["id"]
    if row["state"] == "blocked":
        assert row["qualification_blockers"], row["id"]
    if row["state"] == "owner-approved exclusion":
        assert row.get("owner_authorization"), row["id"]
for journey in records["journeys"]["journeys"]:
    if journey["state"] in ("verified locally", "externally qualified"):
        assert journey["candidate"] and journey["artifact_digests"]
        assert journey["evidence"] and journey["steps"] and journey["environment"]
assert len(journeys) == 12
print(f"Record references valid: {len(seen)} parity rows and {len(journeys)} journeys. No runtime claim inferred.")
