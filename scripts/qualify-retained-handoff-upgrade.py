#!/usr/bin/env python3
"""Rehearse the exact retained schema33 -> 35 metadata upgrade before applying it.

The default changes only the restored task-owned database. --apply-retained
additionally upgrades the retained fixture after every rehearsal comparison.
Payloads, keys, active executions and clean-host recovery remain separate gates.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
from urllib.parse import parse_qsl, urlsplit, urlunsplit

spec = importlib.util.spec_from_file_location("retained_metadata", Path(__file__).with_name("qualify-retained-metadata.py"))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)

SOURCE_SCHEMA, TARGET_SCHEMA = 33, 35
NEW_TABLE = "workflow_collection_handoffs"
CHANGED_FUNCTIONS = {"freightctl_program_run_facts", "freightctl_run_guard", "freightctl_collection_run_complete",
                     "freightctl_collected_run_status", "freightctl_collected_run_current"}
ADDED_FUNCTIONS = {"freightctl_collection_handoff_definition", "freightctl_collection_handoff_wire",
                   "freightctl_collection_handoff_matches", "freightctl_collection_handoff_guard",
                   "freightctl_collection_handoff_projection_complete", "freightctl_collection_handoff_cancellation_complete",
                   "freightctl_collection_handoff_run_matches", "freightctl_collected_run_status_v33"}
ADDED_TRIGGERS = {(NEW_TABLE, "collection_handoff_guard"), ("events", "collection_handoff_projection_complete"),
                  ("workflow_runs", "collection_handoff_cancelled_run"), ("delivery_intents", "collection_handoff_cancelled_delivery")}
ADDED_CONSTRAINTS = {key for key in ADDED_TRIGGERS if key[0] != NEW_TABLE}


def read_protected(path, limit):
    """Refuse replacement/symlink/broad permissions without displaying values."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or not 0 < before.st_size <= limit:
        raise ValueError("upgrade references must be bounded protected regular files")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        actual = os.fstat(stream.fileno())
        if (actual.st_dev, actual.st_ino, actual.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError("upgrade reference changed during inspection")
        value = stream.read(limit + 1)
    if len(value) != before.st_size:
        raise ValueError("upgrade reference length changed")
    return value


def retained_dsn(value):
    dsn = urlsplit(value.decode().strip())
    if (dsn.scheme != "postgres" or dsn.username != "postgres" or dsn.hostname != "127.0.0.1"
            or dsn.port != 25432 or dsn.path != "/freightctl" or dsn.fragment
            or parse_qsl(dsn.query, keep_blank_values=True, strict_parsing=True) != [("sslmode", "disable")]):
        raise ValueError("upgrade requires the exact retained loopback administrative reference")
    return dsn


def compare_rows(original, upgraded):
    if (len(original["migration_ledger"]) != SOURCE_SCHEMA or len(upgraded["migration_ledger"]) != TARGET_SCHEMA
            or upgraded["migration_ledger"][:SOURCE_SCHEMA] != original["migration_ledger"]
            or upgraded["role_authority_sha256"] != original["role_authority_sha256"]
            or upgraded["sequences"] != original["sequences"] or upgraded["forced_rls_tables"] != original["forced_rls_tables"] + 1):
        raise RuntimeError("upgrade changed historical migration, role authority, sequence or RLS state")
    old = {r["table"]: r for r in original["tables"]}
    new = {r["table"]: r for r in upgraded["tables"]}
    if set(new) != set(old) | {NEW_TABLE} or new[NEW_TABLE]["rows"] != 0:
        raise RuntimeError("upgrade invented handoffs or unexpected metadata tables")
    for name, row in old.items():
        if name != "freightctl_schema" and new[name] != row:
            raise RuntimeError("upgrade changed existing rows: " + name)


def compare_catalog(original, upgraded):
    old_relations = {r[0]: r for r in original["relations"]}
    new_relations = {r[0]: r for r in upgraded["relations"]}
    new_indexes = {r[1] for r in upgraded["indexes"] if r[0] == NEW_TABLE}
    expected_indexes = {"collection_handoff_pending", "collection_handoff_successor", "collection_handoff_history", "collection_handoff_input"}
    if (set(new_relations) != set(old_relations) | {NEW_TABLE} | new_indexes
            or len(new_indexes) != 6 or not expected_indexes <= new_indexes
            or any(new_relations.get(name) != row for name, row in old_relations.items())
            or new_relations[NEW_TABLE][1:4] != ["r", True, True]):
        raise RuntimeError("upgrade changed existing relation ownership/grants/RLS or omitted handoff indexes")
    for key in ("columns", "indexes", "policies"):
        retained = [row for row in upgraded[key] if row[0] in old_relations]
        if retained != original[key]:
            raise RuntimeError("upgrade changed existing " + key)
    old_constraints = {(r[0], r[1]): r for r in original["constraints"]}
    old_relation_constraints = {(r[0], r[1]): r for r in upgraded["constraints"] if r[0] in old_relations}
    if (set(old_relation_constraints) != set(old_constraints) | ADDED_CONSTRAINTS
            or any(old_relation_constraints.get(k) != row for k, row in old_constraints.items())
            or any(old_relation_constraints[k][2] != "TRIGGER DEFERRABLE INITIALLY DEFERRED" for k in ADDED_CONSTRAINTS)):
        raise RuntimeError("upgrade changed existing constraints or the exact new deferred handoff guards")
    for key in ("schemas", "default_grants"):
        if original[key] != upgraded[key]:
            raise RuntimeError("upgrade changed existing schema/default grants")
    old_triggers = {(r[0], r[1]): r for r in original["triggers"]}
    new_triggers = {(r[0], r[1]): r for r in upgraded["triggers"]}
    if set(new_triggers) != set(old_triggers) | ADDED_TRIGGERS or any(new_triggers.get(k) != r for k, r in old_triggers.items()):
        raise RuntimeError("upgrade changed existing triggers or introduced unexpected trigger authority")
    old_functions = {(r[0], r[1]): r for r in original["functions"]}
    new_functions = {(r[0], r[1]): r for r in upgraded["functions"]}
    added = set(new_functions) - set(old_functions)
    if not set(old_functions) <= set(new_functions) or len(added) != len(ADDED_FUNCTIONS) or {k[0] for k in added} != ADDED_FUNCTIONS:
        raise RuntimeError("upgrade changed the expected function inventory")
    for key, row in old_functions.items():
        actual = new_functions[key]
        if actual[3:] != row[3:] or (key[0] not in CHANGED_FUNCTIONS and actual != row):
            raise RuntimeError("upgrade changed unrelated functions or historical function grants: " + key[0])
    previous = next(r for k, r in old_functions.items() if k[0] == "freightctl_collected_run_status")
    renamed = next(r for k, r in new_functions.items() if k[0] == "freightctl_collected_run_status_v33")
    if (renamed[1] != previous[1] or renamed[3:] != previous[3:]
            or renamed[2].replace("FUNCTION public.freightctl_collected_run_status_v33(", "FUNCTION public.freightctl_collected_run_status(", 1) != previous[2]):
        raise RuntimeError("renamed schema33 run guard does not preserve its original body and grants")


class Upgrade(metadata.Exercise):
    def __init__(self, container_id, binary, apply_retained=False):
        super().__init__(container_id, SOURCE_SCHEMA)
        source = binary.absolute()
        info = source.lstat()
        if (not source.resolve().is_relative_to(metadata.ROOT / ".cache") or not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o022 or not 0 < info.st_size <= 128 << 20):
            raise ValueError("upgrade requires a bounded task-owned binary under .cache")
        # Freeze this exact binary inside the mode0700 evidence directory.
        self.binary = self.private / "freightctl-upgrade"
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as old, self.binary.open("xb") as new:
            current = os.fstat(old.fileno())
            if (current.st_dev, current.st_ino, current.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise ValueError("upgrade binary changed during inspection")
            size = 0
            while block := old.read(65536):
                size += len(block)
                if size > info.st_size:
                    raise ValueError("upgrade binary grew during snapshot")
                new.write(block)
            if size != info.st_size:
                raise ValueError("upgrade binary length changed during snapshot")
            new.flush()
            os.fchmod(new.fileno(), 0o500)
            os.fsync(new.fileno())
        metadata.sync_directory(self.private)
        self.apply_retained = apply_retained
        self.manifest.update(kind="retained-schema33-to35-handoff-upgrade", source_schema=SOURCE_SCHEMA,
                             target_schema=TARGET_SCHEMA, apply_retained_requested=apply_retained,
                             retained_migration_outcome="not_attempted",
                             upgrade_script_sha256=metadata.digest(Path(__file__)), binary_sha256=metadata.digest(self.binary))

    def run(self):
        version = self.command("inspect-frozen-binary-schema", [str(self.binary), "schema-version"])
        if json.loads(version.read_text()) != {"schema_version": TARGET_SCHEMA}:
            raise RuntimeError("this exact schema33-to35 rehearsal requires a schema35 binary")
        admin = metadata.ROOT / ".private/pg-admin.dsn"
        password = metadata.ROOT / ".private/pg-runtime-password"
        dsn = retained_dsn(read_protected(admin, 8192))
        read_protected(password, 4096)
        refs = {p: metadata.digest(p) for p in (admin, password)}
        # The exact protected backup, sync and successful restore precede every
        # init. The restore remains available for rehearsal until exact cleanup.
        super().run()
        self.manifest["state"] = "failed"
        self.manifest["backup_restore_left_retained_unchanged"] = self.manifest.pop("retained_database_unchanged")
        original, restored = self.manifest["before"], self.manifest["restored"]
        clone_ref = self.private / "restored-admin.dsn"
        with clone_ref.open("xb") as stream:
            stream.write(urlunsplit(dsn._replace(path="/" + self.restore_name)).encode())
            stream.flush()
            os.fsync(stream.fileno())
        clone_ref.chmod(0o600)
        metadata.sync_directory(self.private)
        init = [str(self.binary), "init", "--admin-dsn-file", str(clone_ref), "--runtime-password-file", str(password)]
        self.command("rehearse-ordinary-init", init, timeout=60)
        rehearsed = self.snapshot("rehearsed", self.restore_name)
        compare_rows(restored, rehearsed)
        compare_catalog(json.loads((self.private / "restored-catalog.stdout").read_text()),
                        json.loads((self.private / "rehearsed-catalog.stdout").read_text()))
        self.command("rehearse-init-replay", init, timeout=60)
        if self.snapshot("rehearsed-replay", self.restore_name) != rehearsed:
            raise RuntimeError("rehearsal init replay changed metadata")
        before = self.snapshot("retained-before-apply")
        if before != original or any(metadata.digest(p) != value for p, value in refs.items()):
            raise RuntimeError("retained state or protected references changed during rehearsal")
        self.manifest.update(rehearsal=rehearsed, rehearsal_passed=True, rehearsal_init_replay_unchanged=True,
                             retained_database_unchanged_during_rehearsal=True)
        if self.apply_retained:
            if self.clients("active-clients-before-retained-apply"):
                raise RuntimeError("other clients appeared; preserve their environment")
            init = [str(self.binary), "init", "--admin-dsn-file", str(admin), "--runtime-password-file", str(password)]
            # An uncertain client response must remain visible as a possible
            # migration. Never restore/drop retained data automatically.
            self.manifest["retained_migration_attempted"] = True
            self.manifest["retained_migration_outcome"] = "unknown"
            self.manifest["retained_schema_migrated"] = None
            self.command("retained-ordinary-init", init, timeout=60)
            self.manifest["retained_schema_migrated"] = True
            self.manifest["retained_migration_outcome"] = "applied"
            applied = self.snapshot("applied")
            compare_rows(original, applied)
            compare_catalog(json.loads((self.private / "original-before-catalog.stdout").read_text()),
                            json.loads((self.private / "applied-catalog.stdout").read_text()))
            self.command("retained-init-replay", init, timeout=60)
            if self.snapshot("applied-replay") != applied:
                raise RuntimeError("retained init replay changed metadata")
            self.manifest.update(applied=applied, historical_rows_grants_roles_sequences_preserved=True,
                                 retained_init_replay_unchanged=True)
        else:
            self.manifest["retained_database_unchanged"] = True
        self.manifest.update(state="passed", finished_at=datetime.now(timezone.utc).isoformat(),
                             active_or_queued_execution_upgrade_qualified=False,
                             payload_key_or_clean_host_recovery_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--apply-retained", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    exercise = Upgrade(args.container_id, args.binary, args.apply_retained)
    try:
        exercise.run()
    except Exception as error:
        exercise.manifest.update(state="failed", failure=str(error))
    finally:
        exercise.cleanup()
    exercise.manifest["steps"] = exercise.steps
    path = metadata.save_manifest(exercise)
    print(json.dumps({"state": exercise.manifest["state"], "manifest": str(path.relative_to(metadata.ROOT)),
                      "manifest_sha256": metadata.digest(path), "failure": exercise.manifest.get("failure"),
                      "retained_schema_migrated": exercise.manifest["retained_schema_migrated"],
                      "cleanup_failures": exercise.manifest.get("cleanup_failures", [])}), flush=True)
    return 0 if exercise.manifest["state"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
