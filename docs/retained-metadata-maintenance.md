# Retained development metadata restore

Before migrating the retained development estate, run a metadata backup and restore exercise. A backup file alone proves only that the export command returned. The exercise restores that file into a new database and compares the recovered records and security configuration with the original.

This command is deliberately limited to this repository's stopped development PostgreSQL container. It is not an installation backup service or a production restore procedure. It does not copy payload stores, private keys, global roles or configuration references to a clean host. It does not qualify recovery timing, queued-work recovery, disconnected installation or full J11.

Inspect the exact container first:

```sh
docker inspect --format '{{.Id}} {{.Name}} {{.State.Running}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}' freightctl-postgres-v1
```

Use the full ID from that observation, and select the known retained schema checkpoint explicitly:

```sh
python3 scripts/qualify-retained-metadata.py --container-id FULL_INSPECTED_CONTAINER_ID --expected-schema 32
```

The script requires the matching repository label, original stopped state, exact loopback binding and existing 512 MiB/one-CPU limit. It starts only that resource; it never starts Docker itself, a scanner or a model. If another database client is present, maintenance stops. A client appearing during cleanup causes the script to leave PostgreSQL running and report failure rather than stop that client's resource.

The exercise saves a PostgreSQL custom-format dump under a new mode-0700 `.private/retained-metadata-*` directory. The dump and diagnostics are mode 0600. It flushes each file and its containing directory to storage before continuing; the final manifest is also written exclusively and flushed. This uses the host filesystem's `fsync` contract, without a power-loss or redundant-storage claim. A child output limit caps each native output at 512 MiB; database size, SQL result size, statement duration and command duration are also bounded. No dump, role-password verifier, credential record or raw diagnostic is public evidence. Keep the entire directory private and preserve the manifest and backup after a failure.

It restores through `pg_restore --single-transaction --exit-on-error` into one fresh database whose name contains a newly generated identity. No ownership or grant stripping is requested. It compares every original public table's row count and deterministic digest, migration checksums, forced row security, columns, constraints, indexes, triggers, function definitions, ownership, grants, policies, sequence state and existing cluster-role authority. Version 1 is `schema.sql`; subsequent files begin at `002_`.

PostgreSQL can reparse a dumped policy into a different parenthesis layout. The observer does not remove parentheses or simplify SQL. If only policy text differs, it reparses the original expression using PostgreSQL inside the isolated restored database, compares the resulting policy exactly with the actual restored predicate, and rolls back the temporary change. A changed predicate, role, command, grant or data digest still fails. The private manifest retains both catalog hashes and the parser comparison.

Finally, the exercise compares the original database again, removes only its created restore database and returns the exact PostgreSQL resource to stopped when no other clients are present. It never forces a database drop or terminates other connections. A pass does not apply migrations. Run any upgrade as a separate ordinary administrative operation after reviewing the backup and native migration evidence.

For the specifically qualified 32→33 transition, `qualify-retained-upgrade.py --container-id FULL_INSPECTED_CONTAINER_ID --binary .cache/TASK_OWNED_BINARY` repeats the backup/restore gate, then invokes that separately built binary's ordinary `init` with the protected administrative references. It verifies every old table field, existing grants and credential authority, the old checksum ledger and sequence state. The new nullable `workflow_runs.routing_authorization_id` is excluded only from the historical row projection and independently required to remain NULL on every old run. The new routing table must be empty. A second ordinary `init` must change nothing. This maintenance exercise does not establish execution through an active upgrade or a supported downgrade.

`freightctl schema-version` reports the binary's bundled migration target without opening a database. The recorded 32→33 utility now checks that result before starting PostgreSQL and refuses a newer or unidentified binary. A current schema-34 binary needs a separately verified 33→34 maintenance plan; do not use the historical wrapper to apply it. The retained estate remains at schema 33 during the new handoff implementation tests.

The resource-substitution, evidence-permission, checksum and policy-comparison refusal tests run locally with `python3 scripts/test-retained-metadata.py` and in GitHub's source checks. The retained private estate stays on its actual host. The native Linux workflow also prepares separate x86_64 and ARM restore jobs using synthetic first-run enrollment and real PostgreSQL. Their results remain pending until actual execution; they cannot replace verification of this retained estate.

The PostgreSQL manuals describe the [single-database export boundary](https://www.postgresql.org/docs/16/app-pgdump.html) and [transactional restore behavior](https://www.postgresql.org/docs/16/app-pgrestore.html). Full backup/restore, payload and key consistency, a clean host, reference RPO/RTO and active or queued upgrades remain mandatory GOAL.md work.
