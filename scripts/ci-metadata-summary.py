#!/usr/bin/env python3
"""One explicit metadata CI profile, with a bounded public result allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILE = {"schema": 36, "metadata_tables": 64, "forced_rls_tables": 63}
BOUND = 8 << 20


class EvidenceError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def verify_binary(binary):
    version = subprocess.check_output([str(binary.resolve(strict=True)), "schema-version"], timeout=15)
    require(json.loads(version) == {"schema_version": PROFILE["schema"]}, "binary_schema_differs_from_explicit_ci_profile")


def summarize(result, manifest, data):
    require(isinstance(result, dict) and isinstance(manifest, dict), "metadata_evidence_shape_invalid")
    require(hashlib.sha256(data).hexdigest() == result.get("manifest_sha256"), "metadata_manifest_hash_mismatch")
    require(result.get("state") == manifest.get("state") == "passed", "metadata_exercise_failed")
    for name in ("restored_metadata_matches", "retained_database_unchanged", "original_stopped_state_restored", "exact_restore_database_removed"):
        require(manifest.get(name) is True, "metadata_verification_or_cleanup_incomplete")
    require(manifest.get("inference_performed") is False and manifest.get("scanner_engine_started") is False, "unexpected_model_or_scanner_activity")
    backup = manifest.get("backup")
    require(isinstance(backup, dict) and backup.get("file_and_directory_synced") is True, "metadata_backup_sync_missing")
    before, restored = manifest.get("before", {}), manifest.get("restored", {})
    require(isinstance(before, dict) and isinstance(restored, dict), "metadata_snapshot_missing")
    require(before.get("runtime_role_safe") is True and restored.get("runtime_role_safe") is True, "metadata_runtime_role_unsafe")
    ledger = before.get("migration_ledger")
    source = ROOT / "internal/store"
    migrations = [source / "schema.sql"] + sorted(source.glob("[0-9][0-9][0-9]_*.sql"))
    expected = [{"version": i + 1, "digest": hashlib.sha256(p.read_bytes()).hexdigest()} for i, p in enumerate(migrations)]
    require(len(expected) == PROFILE["schema"] and ledger == expected and ledger == restored.get("migration_ledger"), "metadata_schema_profile_mismatch")
    tables = before.get("tables")
    require(isinstance(tables, list) and len(tables) == PROFILE["metadata_tables"] and tables == restored.get("tables"), "metadata_table_profile_or_restore_mismatch")
    require(before.get("forced_rls_tables") == restored.get("forced_rls_tables") == PROFILE["forced_rls_tables"], "metadata_rls_profile_mismatch")
    authority = before.get("role_authority_sha256")
    require(isinstance(authority, str) and re.fullmatch(r"[a-f0-9]{64}", authority)
            and authority == restored.get("role_authority_sha256")
            and isinstance(before.get("sequences"), list) and before["sequences"] == restored.get("sequences"), "metadata_authority_or_sequence_mismatch")
    require(all(isinstance(row, dict) and type(row.get("rows")) is int and row["rows"] >= 0 for row in tables), "metadata_row_count_invalid")
    steps = manifest.get("steps")
    require(isinstance(steps, list) and 1 <= len(steps) <= 10000
            and all(isinstance(step, dict) and type(step.get("exit_code")) is int and step["exit_code"] == 0 for step in steps), "metadata_native_step_failed_or_missing")
    return {"state": "passed", "manifest_sha256": result["manifest_sha256"], **PROFILE,
            "restored_rows": sum(row["rows"] for row in tables), "exact_restore_database_removed": True,
            "original_stopped_state_restored": True, "inference_performed": False, "scanner_engine_started": False,
            "scope": "synthetic first-run metadata; same-cluster restore; payload/key/clean-host recovery unqualified"}


def read_bounded(path):
    require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= BOUND, "metadata_evidence_path_or_size_invalid")
    with path.open("rb") as stream:
        data = stream.read(BOUND + 1)
    require(len(data) <= BOUND, "metadata_evidence_size_changed")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--print-schema-version", action="store_true")
    group.add_argument("--check-binary", type=Path)
    group.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        if args.print_schema_version:
            print(PROFILE["schema"])
        elif args.check_binary:
            verify_binary(args.check_binary)
        else:
            result = json.loads(read_bounded(args.result))
            require(isinstance(result, dict), "metadata_result_shape_invalid")
            reference = result.get("manifest")
            require(isinstance(reference, str) and re.fullmatch(r"\.private/retained-metadata-[a-f0-9]{32}/manifest\.json", reference), "metadata_manifest_reference_invalid")
            path = ROOT / reference
            require(path.resolve().is_relative_to(ROOT / ".private"), "metadata_manifest_reference_escapes")
            data = read_bounded(path)
            print(json.dumps(summarize(result, json.loads(data), data)))
        return 0
    except EvidenceError as error:
        print(json.dumps({"state": "failed", "reason": str(error), "scope": "metadata qualification failed; raw database records and diagnostics remain private"}))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(json.dumps({"state": "failed", "reason": "metadata_evidence_or_binary_unreadable", "scope": "metadata qualification failed; raw database records and diagnostics remain private"}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
