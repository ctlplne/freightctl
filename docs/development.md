# Local custody development

This is an assisted development profile, not a production installer. It needs Docker, Python 3, stock curl and Go; `scripts/go.sh` selects Go 1.26.10 and keeps downloads/build caches in ignored `.cache/`. Initial dependency acquisition needs internet access. It does not claim a disconnected installation bundle.

Run at the repository root on local main:

```sh
python3 scripts/dev-db.py
sh scripts/go.sh run ./cmd/freightctl init
sh scripts/go.sh test ./...
sh scripts/integration.sh -race
python3 scripts/qualify-https.py
```

The database helper creates or reuses only `freightctl-postgres-v1`, its named volume, and loopback port 25432. It checks the workspace label before reusing a container. Do not remove that volume or credentials to fix a test. PostgreSQL superuser and runtime passwords are separate files in mode-0700 `.private/`, with mode 0600 on each credential. Plain database transport is restricted to this loopback development fixture; production database transport and deployment qualification remain open.

`init` applies checksum-tracked schema migrations with the protected admin connection reference. Runtime service connections use `freightctl_runtime`: it cannot own tables, bypass row policies, modify the journal or administer roles. Each request selects a tenant and partner inside a transaction and authenticates a credential within that scope. Changing URL identifiers does not grant permission. Direct SQL tests deliberately try to break these boundaries.

The HTTPS qualification command builds a real binary, creates synthetic scoped identities and a short-lived loopback certificate, runs stock curl with explicit certificate trust, and compares downloaded bytes independently in Python. It tests repeat/conflicting requests, ranges, isolation, bad digests and process restart. Credentials are passed through protected header files, never command-line token strings. It stops only its own server process. It retains private fixtures and native outputs in ignored directories and writes a safe manifest of hashes, results and limits.

For an interactive development service, create credentials without printing them:

```sh
sh scripts/go.sh run ./cmd/freightctl token --token-file .private/partner.token
sh scripts/go.sh run ./cmd/freightctl enroll --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222 --token-file .private/partner.token
sh scripts/go.sh run ./cmd/freightctl dev-cert
sh scripts/go.sh run ./cmd/freightctl serve
```

Token and certificate commands refuse to overwrite existing files. Enrollment currently requires an explicit administrator command; a repeated enrollment is rejected. Idempotent enrollment and the full first-admin/partner UI remain required work.

An upload uses `POST /v1/tenants/{tenant}/partners/{partner}/files`, a scoped bearer token, `Idempotency-Key`, `X-File-Size`, and a lowercase hex `X-Content-SHA256`. The request contains bytes directly. The same key, length, digest and policy returns the original accepted file; changed meaning returns 409. The response means bytes and directory were synced and metadata committed on this local persistence profile. It does not mean malware scanned, independently signed, delivered to a partner, or imported by a business system.

`GET .../files/{id}` verifies the exact stored revision before streaming and supports HTTP ranges. `GET .../events` returns the most recent 100 scoped events. A download-authorized event records permission to begin retrieval; it does not prove the recipient consumed the complete file. Event pagination and independently verifiable audit export remain open.

Default file admission is 64 MiB, configured with `--max-file-bytes` up to the current engineering limit of 1 GiB. `--max-stored-bytes` defaults to 1 GiB across the single storage root, including retained orphans. Initial admission serializes staging using PostgreSQL and caps root entries at 10,000 to bound directory accounting. These are operational development limits, not edition limits or performance claims; scalable reservations, configurable entry quotas and tenant fairness remain open. Incomplete staging is removed on ordinary errors. A crash or uncertain SQL commit may retain bytes. They count against capacity and cannot be downloaded without accepted metadata; a safe reconciliation tool is still required.

The custody root must be private (0700) before opening an existing directory. The service refuses broad permissions instead of silently changing them. Stored revisions are sealed 0400 and use generated identities, not client filesystem paths. A host administrator can still change storage; local integrity checks detect changed bytes but cannot protect against a malicious host controlling the service.

Inspect custody after an interruption through the same scoped service:

```sh
sh scripts/go.sh run ./cmd/freightctl reconcile --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222 --token-file .private/partner.token
```

`GET .../custody/reconcile` produces the same read-only report over HTTPS. It distinguishes verified revisions, missing bytes, changed bytes, unsafe entries and bytes without an accepted SQL record. Unknown names are represented by a digest instead of echoed into diagnostics. A report never deletes or adopts data. An unreferenced object may be partial, fully staged, or the result of an uncertain commit; an operator must not treat it as a ready-to-send file.

Reconciliation authenticates before inventory, waits on the same staging lock, and rechecks authority before returning. An active staging operation therefore cannot be mistaken for an orphan. The operation has a ten-second deadline, a 10,000-entry inventory bound, a 200-entry response bound with explicit truncation, and a configured hash budget (`--reconcile-max-bytes`, default 64 MiB, bounded by custody quota). Failed integrity checks consume the attempt budget too. `not_checked_budget` means unknown, never healthy. Counts cover the bounded inventory even when detailed entries are truncated. `consistent` describes this scoped snapshot only; it is not transfer readiness or an HA/storage durability guarantee. The current global staging lock can delay uploads while a reconciliation runs; scalable reservations and separate operational capacity remain open.

The stock-curl harness also kills its own server during a rate-limited upload, observes an actual partial staging object, restarts, checks that reconciliation reports it, confirms download still returns 404, and retries the request into a new accepted revision. It preserves the old unreferenced object and its quota cost. Crashes after syncing but before committing SQL, ambiguous commit outcomes, automatic cleanup and approved recovery are separate open gates.

`python3 scripts/check-records.py` validates qualification bookkeeping. No test is silently skipped when integration credentials are absent. A passing foundation exercise does not close any of GOAL.md's complete journeys.
