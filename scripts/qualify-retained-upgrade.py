#!/usr/bin/env python3
"""Verify the retained schema-32 to schema-33 administrative upgrade after a proven backup."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

spec = importlib.util.spec_from_file_location("retained_metadata", Path(__file__).with_name("qualify-retained-metadata.py"))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class Upgrade(metadata.Exercise):
    def __init__(self, container_id, binary):
        super().__init__(container_id, 32)
        self.binary = binary.resolve(strict=True)
        if not self.binary.is_relative_to(metadata.ROOT / ".cache") or not self.binary.is_file():
            raise ValueError("upgrade requires the separately built task-owned binary under .cache")
        self.manifest["upgrade_script_sha256"] = metadata.digest(Path(__file__))
        self.manifest["binary_sha256"] = metadata.digest(self.binary)

    def run(self):
        references = [metadata.ROOT / ".private/pg-admin.dsn", metadata.ROOT / ".private/pg-runtime-password"]
        for reference in references:
            if reference.is_symlink() or not stat.S_ISREG(reference.lstat().st_mode) or reference.stat().st_mode & 0o077:
                raise RuntimeError("upgrade references must be protected regular files")
        dsn = urlsplit(references[0].read_text())
        if dsn.scheme != "postgres" or dsn.hostname != "127.0.0.1" or dsn.port != 25432 or dsn.path != "/freightctl":
            raise RuntimeError("administrative reference does not select the retained loopback fixture")
        # The original restore exercise must pass before any retained SQL mutation.
        super().run()
        self.manifest["state"] = "failed"
        self.manifest["retained_database_unchanged_before_migration"] = self.manifest.pop("retained_database_unchanged")
        original = self.manifest["before"]
        original_catalog = json.loads((self.private / "original-before-catalog.stdout").read_text())
        if self.clients("active-clients-before-upgrade"):
            raise RuntimeError("other clients appeared; defer the retained upgrade")
        self.command("ordinary-administrative-init", [str(self.binary), "init", "--admin-dsn-file", str(references[0]),
                     "--runtime-password-file", str(references[1])], timeout=60)
        self.manifest["retained_schema_migrated"] = True
        # 033 adds one nullable run column. Compare every pre-existing field, and
        # independently require the new column to remain NULL for all old runs.
        upgraded = self.snapshot("upgraded", exclude_columns={"workflow_runs": ["routing_authorization_id"]})
        self.manifest["upgraded"] = upgraded
        if (len(upgraded["migration_ledger"]) != 33
                or upgraded["migration_ledger"][:32] != original["migration_ledger"]
                or upgraded["forced_rls_tables"] != 62
                or upgraded["role_authority_sha256"] != original["role_authority_sha256"]
                or upgraded["sequences"] != original["sequences"]):
            raise RuntimeError("upgrade changed the historical ledger, role authority or sequence state")
        old_rows = {row["table"]: row for row in original["tables"]}
        new_rows = {row["table"]: row for row in upgraded["tables"]}
        if set(new_rows) != set(old_rows) | {"workflow_collection_routing"} or new_rows["workflow_collection_routing"]["rows"] != 0:
            raise RuntimeError("upgrade created unexpected metadata or routing decisions")
        for table, old in old_rows.items():
            if table != "freightctl_schema" and new_rows[table] != old:
                raise RuntimeError("upgrade changed historical rows: " + table)
        if self.sql("old-runs-have-no-invented-routing", "SELECT count(*) FROM workflow_runs WHERE routing_authorization_id IS NOT NULL;") != "0":
            raise RuntimeError("upgrade attached invented routing decisions to retained runs")
        current_catalog = json.loads((self.private / "upgraded-catalog.stdout").read_text())
        old_relations = {row[0]: row for row in original_catalog["relations"]}
        new_relations = {row[0]: row for row in current_catalog["relations"]}
        if any(new_relations.get(name) != row for name, row in old_relations.items()):
            raise RuntimeError("upgrade changed existing ownership, grants or row-security enablement")
        for key in ("schemas", "default_grants", "policies"):
            old = original_catalog[key] or []
            new = current_catalog[key] or []
            if key == "policies":
                new = [row for row in new if row[0] != "workflow_collection_routing"]
            if old != new:
                raise RuntimeError("upgrade changed existing grants or policies")
        init = [str(self.binary), "init", "--admin-dsn-file", str(references[0]), "--runtime-password-file", str(references[1])]
        self.command("ordinary-init-replay", init, timeout=60)
        replay = self.snapshot("replayed", exclude_columns={"workflow_runs": ["routing_authorization_id"]})
        if replay != upgraded:
            raise RuntimeError("ordinary init replay changed the upgraded database")
        self.manifest.update({"state": "passed", "retained_schema_migrated": True,
                              "historical_table_rows_preserved": True, "historical_grants_and_authority_preserved": True,
                              "ordinary_init_replay_unchanged": True,
                              "historical_run_projection_excludes": ["routing_authorization_id"],
                              "new_routing_references_all_null": True, "finished_at": datetime.now(timezone.utc).isoformat(),
                              "active_or_queued_execution_upgrade_qualified": False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    exercise = Upgrade(args.container_id, args.binary)
    try:
        exercise.run()
    except Exception as error:
        exercise.manifest["failure"] = str(error)
        exercise.manifest["state"] = "failed"
    finally:
        exercise.cleanup()
    exercise.manifest["steps"] = exercise.steps
    path = metadata.save_manifest(exercise)
    print(json.dumps({"state": exercise.manifest["state"], "manifest": str(path.relative_to(metadata.ROOT)),
                      "manifest_sha256": metadata.digest(path), "failure": exercise.manifest.get("failure"),
                      "cleanup_failures": exercise.manifest.get("cleanup_failures", [])}))
    return 0 if exercise.manifest["state"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
