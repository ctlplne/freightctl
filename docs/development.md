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

`GET .../files/{id}` verifies the exact stored revision before streaming and supports HTTP ranges. `GET .../events` returns the most recent 100 scoped events. A download-authorized event records permission to begin retrieval; it does not prove the recipient consumed the complete file. Event pagination and whole-estate export remain open; the bounded signed export below is implemented.

Default file admission is 64 MiB, configured with `--max-file-bytes` up to the current engineering limit of 1 GiB. `--max-stored-bytes` defaults to 1 GiB across the single storage root, including retained orphans. Initial admission serializes staging using PostgreSQL and caps root entries at 10,000 to bound directory accounting. These are operational development limits, not edition limits or performance claims; scalable reservations, configurable entry quotas and tenant fairness remain open. Incomplete staging is removed on ordinary errors. A crash or uncertain SQL commit may retain bytes. They count against capacity and cannot be downloaded without accepted metadata; the read-only reconciliation tool below observes them without adopting or deleting them.

The custody root must be private (0700) before opening an existing directory. The service refuses broad permissions instead of silently changing them. Stored revisions are sealed 0400 and use generated identities, not client filesystem paths. A host administrator can still change storage; local integrity checks detect changed bytes but cannot protect against a malicious host controlling the service.

Inspect custody after an interruption through the same scoped service:

```sh
sh scripts/go.sh run ./cmd/freightctl reconcile --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222 --token-file .private/partner.token
```

`GET .../custody/reconcile` produces the same read-only report over HTTPS. It distinguishes verified revisions, missing bytes, changed bytes, unsafe entries and bytes without an accepted SQL record. Unknown names are represented by a digest instead of echoed into diagnostics. A report never deletes or adopts data. An unreferenced object may be partial, fully staged, or the result of an uncertain commit; an operator must not treat it as a ready-to-send file.

Reconciliation authenticates before inventory, waits on the same staging lock, and rechecks authority before returning. An active staging operation therefore cannot be mistaken for an orphan. The operation has a ten-second deadline, a 10,000-entry inventory bound, a 200-entry response bound with explicit truncation, and a configured hash budget (`--reconcile-max-bytes`, default 64 MiB, bounded by custody quota). Failed integrity checks consume the attempt budget too. `not_checked_budget` means unknown, never healthy. Counts cover the bounded inventory even when detailed entries are truncated. `consistent` describes this scoped snapshot only; it is not transfer readiness or an HA/storage durability guarantee. The current global staging lock can delay uploads while a reconciliation runs; scalable reservations and separate operational capacity remain open.

The stock-curl harness also kills its own server during a rate-limited upload, observes an actual partial staging object, restarts, checks that reconciliation reports it, confirms download still returns 404, and retries the request into a new accepted revision. It preserves the old unreferenced object and its quota cost. Crashes after syncing but before committing SQL, ambiguous commit outcomes, automatic cleanup and approved recovery are separate open gates.

`python3 scripts/check-records.py` validates qualification bookkeeping. No test is silently skipped when integration credentials are absent. A passing foundation exercise does not close any of GOAL.md's complete journeys.

## Signed audit snapshots

Create a dedicated audit identity explicitly; this does not upload a key or publish a verification key:

```sh
sh scripts/go.sh run ./cmd/freightctl audit-keygen --audit-key-file .private/audit-signing.key --audit-public-file .private/audit-signing.pub
sh scripts/go.sh run ./cmd/freightctl audit-export --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222 --token-file .private/partner.token --audit-key-file .private/audit-signing.key --output .private/audit-export.json
python3 scripts/verify-audit.py --export .private/audit-export.json --trusted-key .private/audit-signing.pub --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222
```

Start the server with `--audit-key-file .private/audit-signing.key` to enable `GET .../audit/export`. Without a configured identity the export fails; ordinary journaled custody does not depend on this optional export-signing configuration. Direct cryptographic operations stay in `internal/crypto`. The format uses Ed25519, PKCS8 private-key references and a SHA-256 fingerprint of the public SubjectPublicKeyInfo DER. This is an algorithm and format choice, not a FIPS or external key-custody certification.

The signed payload is base64 encoded so JSON presentation cannot change its exact bytes. It records tenant, partner, snapshot identity and database transaction time, deterministic event count, actors, resources and original event data from one repeatable-read view. The current journal is metadata; it does not contain file contents or credential values. The verifier requires an independently trusted public key and the expected tenant/partner. An embedded key is only a hint: trusting a key supplied by an unknown artifact would let an attacker sign a replacement with their own identity.

Export rechecks live authority after capturing the snapshot and before returning it. It commits `AuditSnapshotPrepared`, bound to the exact payload digest, event count and signing identity, before releasing the artifact. A failed journal write or revoked credential returns no artifact. Preparation does not prove receipt, retrieval or business acceptance. The CLI stages and syncs a complete mode-0400 artifact, then uses an atomic hard link to publish a new output without overwriting. Unsupported filesystems fail explicitly. Key generation also refuses existing paths; an error can leave a newly created private identity that must be preserved and inspected, rather than silently replaced.

Default export budgets are 10,000 events and 8 MiB before base64 encoding. Administrator flags `--audit-max-events` and `--audit-max-bytes` can select up to 100,000 events and 16 MiB within this implementation's bounded in-memory profile. Reaching a budget fails the export; it never presents a truncated snapshot as complete. API signing has one admission slot and a ten-second deadline. Larger asynchronous/segmented exports, long-term protected retention, key rotation, external key services, native platform custody and whole-estate portability remain required work.

The signature detects changes after signing. It does not prove a database superuser did not alter history before the snapshot, stop a compromised host from using its local key, or protect an artifact somebody deletes. Independent retention and stronger key custody are separate open gates. Secret-file reads use bounded buffers with best-effort memory locking and clearing; parsed library objects and process-dump protections still have platform limits to qualify.

Migration 3 bounds journal kind and payload sizes in SQL, while the application applies a tighter append budget. Every scoped operation locks the domain relations and checks their forced row policies before authentication. A concurrent policy change waits for that transaction; a disabled policy causes the running store to fail closed. These checks protect the tested application boundary. PostgreSQL superusers and host administrators remain trusted deployment authorities.

## Virtual folders and scoped accounts

Client folder names are records in PostgreSQL. A name such as `/inbox/payroll.csv` points to an immutable custody file ID; it is never passed to the host filesystem. Create a different file revision to replace contents. Renaming a folder changes the index and appends events while leaving those bytes intact. Removal creates a tombstone; accepted bytes and publication history remain retained. Approved recovery and retention policies are still required.

Enrollment supports `--permissions read,list` and `--namespace-root /inbox`. This mounts the existing partner folder `/inbox` as the account's `/`. Existing identities retain their previous grants. New development administrators receive the nineteen grants listed below; explicitly select the minimum permissions for a restricted account. The development bootstrap is still an administrator operation. Identity creation/rotation through a delegated operator UI remains open.

| Permission | Effect |
| --- | --- |
| `read` | Read an authorized immutable file revision. |
| `write` | Create folders and publish new contents at an authorized path. |
| `list` | Inspect names and metadata under the mounted root. |
| `manage_paths` | Rename, remove, or change supported mode/time attributes. |
| `inspect` | Run custody reconciliation; the current global report also requires root `/`. |
| `audit_read` | Read scoped events and signed snapshots; these global views also require root `/`. |
| `admin` | Bypass owner/group mode bits within the mounted namespace. Other operation grants and the mount still apply. |
| `pgp_manage` | Register/revoke exact partner public signer versions; admin and root mount also required. |
| `connections_manage` | Review and approve the initial local outbound connection definition, together with admin authority. |
| `deliver` | Inspect and execute this actor's approved outbound intent, together with source read authority. |
| `workflow_manage` | Create and compare typed draft workflow versions using this actor's registered connection references. |
| `workflow_approve` | Approve or revoke an exact workflow definition and state revision. |
| `workflow_execute` | Create/dispatch/cancel authorized frozen runs; read and deliver grants remain separate. |
| `ai_manage` | Register/revoke exact administrator-selected assistance profiles; admin grant also required. |
| `ai_use` | Prepare/read authorized assistance contexts and request bounded generation when enabled. |
| `ai_disclose` | Approve the exact context hash/state for disclosure; does not approve workflows. |
| `intake_manage` | Register/revoke the partner intake policy; root admin authority also required. |
| `check_run` | Validate this actor’s held immutable revision under the current bound policy; read also required. |
| `check_release` | Approve exact passing bytes/policy/report for publication; read/write also required. |

Virtual modes use owner bits for the creating actor and group bits for other authorized actors in the same partner. They do not create host users or POSIX groups. Tenant/partner SQL policies still isolate a mode-0777 file. Setstat requires owner or admin authority; replacement requires write authority, parent search/write bits and the expected path revision. Current authority is checked again before commit. A changed account policy increments its authority revision, invalidating an in-flight operation that used the old policy.

`GET .../identity` and the `identity` CLI command return current grants, authority revision and the future SSH username. They return a digest of the mount policy rather than exposing a hidden parent prefix. The current SSH key lifecycle and loopback SFTP commands are described in [the SFTP profile](protocols/sftp.md).

Namespace HTTPS routes use the same bearer token and tenant/partner URL prefix as custody:

| Route | Contract |
| --- | --- |
| `POST .../namespace/commands` | Strict JSON command, `Idempotency-Key`; mkdir, publish, rename, remove, rmdir, setstat. |
| `GET .../namespace/stat?path=...` | Inspect one virtual entry and its current revision. |
| `GET .../namespace/entries?path=...&limit=100&after=...` | Keyset page of immediate children; maximum 1,000 per page. |
| `PUT .../namespace/file?path=...` | Same size/digest/key upload contract; `If-Match-Revision` required to replace an existing file. |
| `GET .../namespace/file?path=...` | Verified immutable contents, with HTTP ranges. |

URL-encode query values. Paths are case-sensitive NFC Unicode, absolute within the mounted root, at most 1,024 bytes after combining mount and name, and at most 255 bytes per component. Traversal components, repeated/trailing separators, controls, backslashes, drive syntax, trailing dots/spaces and Windows device names are rejected. Names do not become host paths on any platform. This naming policy does not establish native Windows qualification.

A command JSON file can be submitted through `namespace --request-file .private/command.json --idempotency-key stable-operation-id` with tenant, partner and token references. For example, `{"operation":"mkdir","path":"/inbox","mode":504}` creates a mode-0770 folder. Mutations of existing entries require `expected_revision` from stat. Rename replacement additionally requires `replace` and the target's `target_revision`. A retry returns the original actor-scoped receipt; changed meaning returns 409. Independent file and folder operations may use different keys. Unicode and timestamp normalization happen before retry hashing.

The active-entry default is 10,000 per partner (`--namespace-max-entries`); one subtree move is bounded to 1,000 entries, command JSON to 16 KiB and path-command duration to ten seconds. No sparse writes, links, mounts onto host directories, arbitrary ownership assignment, recursive unbounded mutation or automatic deletion is offered. Larger estates and configurable reservations remain open.

Direct `GET .../files/{id}` follows the same mount and current mode checks. For non-admin identities an archived revision is readable only through a live permitted namespace entry; unlisted IDs cannot escape the mount. Root admins can inspect retained custody. A root non-admin can access its own never-published raw upload; publishing it brings it under the namespace rules. Mounted identities cannot create raw unbound uploads. Global event/export/reconciliation views fail rather than leaking names outside a mount.

Migration 4 adds namespace projections/history/command receipts, actor-scoped upload keys, account policy revisions and the future SSH public-key registry. Checksummed migrations 1–3 remain unchanged. The SFTP adapter uses these same namespace rules. Its loopback server, transfer-close behavior and stock OpenSSH exercise are documented in [the SFTP profile](protocols/sftp.md); the first outbound intent profile is described separately below. Broader adapters, enterprise peers and ordinary-operator resume qualification remain open.

`python3 scripts/qualify-foundation.py` retains native module, vet, unit/race, PostgreSQL/race, bounded name/path fuzzing, stock-curl, OpenSSH SFTP/scp and independent OpenSSL outputs with exact source hashes. This is a repeatable foundation check, not a release or complete-journey qualification.

## Durable upload tickets

[Resumable upload tickets](protocols/resumable-uploads.md) describe the shared HTTPS/CLI/SFTP flow, exact progress receipts, storage binding, completion and limits. Migrations 5–6 add immutable checkpoints, actor-private command receipts and a persistent storage reference. The namespace reserves `.freightctl` for protocol controls. Existing source, credentials and accepted bytes remain retained; no orphan is adopted automatically.

## Outbound delivery and uncertain receipts

[Approved outbound SFTP intents](protocols/outbound-sftp.md) describe local draft/approval commands, pinned receiver trust, immutable source binding, database leases/fences, no-overwrite publication and read-only reconciliation. Migration 7 adds two actor-private domain relations and outbound grants without granting them to existing accounts. The native delivery exercise is included in the foundation runner. Typed workflows, API/browser approval and full product qualification remain open.

## Versioned workflow execution

[Workflows and connections](workflows.md) document shared CLI/HTTPS typed validation, offline preview, draft/diff/approval, immutable registered connection versions, atomic run/intent creation, ordered dispatch and cancellation. Migration 8 adds five actor-private journal-backed relations and explicit workflow grants; existing account grants remain unchanged. Replays keep their selected step even after restart. The current executor has no model dependency; private AI, broader tasks, scheduling and full journeys remain open.

## Assistance without local inference

[Assistance controls](assistance.md) describe explicit context preparation/review, disclosure approval, a default-disabled bounded endpoint client, evidence validation and draft-only adoption. Migration 9 adds three actor-private journal-backed tables and three explicit grants; existing accounts keep their grants. Model runtime starts/loads/warmups/evaluations remain disallowed on this shared machine. The native contract responder is a tiny JSON fixture, not inference or an AI profile qualification.

## Held intake and exact CSV contracts

[Intake checks](intake.md) document durable held acceptance, bounded actor-private discovery, exact CSV validation and a separate release approval. Migration 10 adds four journal-backed relations and three explicit grants; old account grants stay unchanged. New accepted revisions under a configured policy cannot be downloaded, published or dispatched before release. Existing integrity-only revisions retain their original scope. Stock-client and delayed-worker evidence is separate from malware, business-receipt and complete-journey qualification.

## Detached OpenPGP verification

[The OpenPGP profile](openpgp.md) documents explicit public signer enrollment, actor-bound signature artifacts, exact verification/release and current revocation/expiry gates. Migration 11 adds two forced-RLS journal-backed relations and the explicit `pgp_manage` grant. The in-process backend is pinned behind `internal/crypto`; GnuPG is used only for independent synthetic peer qualification. Full integration/foundation checks require the locally built, labeled `freightctl-pgp-peer:2.4.9-r1` image described in that profile. Fixture execution has no network and is capped at 128 MiB/one CPU. No model runtime is started. Encryption, malware scanning and full customer journeys remain open.
