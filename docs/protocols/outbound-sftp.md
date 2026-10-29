# Approved outbound SFTP intents

This is a local development profile. It sends one accepted immutable file to a separately running SFTP receiver and records the evidence it can actually observe. It has no workflow scheduler, browser approval screen or receiver business acknowledgment yet. [Versioned workflows](../workflows.md) add registered connection references and ordered approved runs. Full product and protocol parity remain open.

## Draft, review and approval

Use a root-mounted service identity with `read`, `deliver`, `connections_manage` and `admin`. Migration 7 adds the two outbound grants. Newly provisioned development administrators receive all eighteen grants; existing identities keep their exact previous grants. `admin` alone does not grant delivery. This initial operator path uses local CLI files. HTTP clients cannot submit private-key file references.

Create a bounded JSON request such as:

```json
{
  "file_id": "REPLACE_WITH_ACCEPTED_FILE_UUID",
  "address": "127.0.0.1:2222",
  "user": "receiver",
  "directory": "/inbox",
  "filename": "settlement.csv",
  "host_public_file": ".private/receiver-host.pub",
  "key_file": ".private/outbound-client.key",
  "key_public_file": ".private/outbound-client.pub"
}
```

The numeric destination must be loopback in this profile. The directory must already exist and use the canonical path syntax; filename is one ASCII component of at most 128 characters. Host trust comes from the separately trusted public-key file. No trust-on-first-use, DNS, system SSH configuration, SSH agent, password, shell command or forwarding is used. The private key must be a protected regular file with mode 0600 or stricter. Only its absolute reference and public fingerprint enter the definition and journal.

Run `delivery-create` with tenant, partner, token and storage references, `--request-file .private/delivery.json`, and a stable `--idempotency-key`. The result contains a draft ID, exact `definition_hash` and state `revision`. Its typed definition freezes the accepted file ID, byte count, SHA-256, policy and acceptance event; storage UUID; actor authority revision and mount; receiver address, username, host wire and key fingerprint/reference; directory and logical filename. Creating or reviewing a draft does not contact the receiver.

Review that result. Call `delivery-approve --delivery-id ID --definition-hash HASH --expected-revision REVISION --idempotency-key APPROVAL_KEY` with the same identity selectors. A changed hash or revision fails. A retried command returns its original actor-private receipt. Reusing a command key for different meaning fails. `delivery-cancel` uses the same preconditions and accepts draft, queued, retry or ambiguous intents. Cancellation of an ambiguous intent does not undo a possible remote effect. Active staging/publication cancellation needs further work; current account revocation is checked by the worker.

`delivery-status --delivery-id ID` reports current state. Drafts, state and receipts are private to their actor as well as tenant and partner. Current source access and frozen authority are rechecked, including on receipt replay. A policy revision change freezes that intent; audited rebinding and delegated recovery remain required.

## What one worker does

Call `delivery-work --delivery-id ID` with the same identity and storage references. One call attempts one approved intent. Inspect the returned `state`: a successful command can report `retry`, `blocked` or `ambiguous`, and those do not mean delivery succeeded.

1. PostgreSQL records a 30-second lease, a random worker owner and a growing fence number. The fence is a numbered attempt ticket: a worker with an old ticket cannot update or authorize the current attempt. Leases renew every five seconds. The database clock decides expiry.
2. The worker verifies the local storage identity and exact source bytes before connecting. It rechecks current actor permissions, frozen authority, source access, storage identity and lease before each bounded data write/read and before publication.
3. It opens a new hidden `.freightctl-ID-FENCE.partial` file exclusively, writes at most the approved size in 32 KiB pieces, checks its sent digest, obtains `fsync@openssh.com` acknowledgment, closes it and reads it back to check the whole digest. Directory ancestors must be directories without symlinks.
4. It commits `publishing` locally **before** making the final remote name visible. The required `hardlink@openssh.com` extension atomically creates `ID-settlement.csv` without replacing an existing name. The unique ID belongs to the reviewed intent. It reads and hashes that final file before recording success. Removing the temporary link cannot remove the final link; a failed removal leaves the temporary file retained.

The receiver must cooperate: ignore hidden staging names, support the two required extensions and protect the approved directory from adversarial changes. SFTP cannot pin every remote directory descriptor or prevent a malicious receiver from changing bytes after observation. The publication mechanism follows OpenSSH's [hardlink extension](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) and [server implementation](https://github.com/openssh/openssh-portable/blob/master/sftp-server.c); it does not use an overwrite-capable rename.

The receipt says `remote_file_integrity_observed`, records the final path, exact hash/size and pinned host identity, and reports business acceptance as `unknown`. A remote file-sync acknowledgment does not establish directory-entry survival after power loss, protected retention, or successful import into a business system. The receiver contract must supply those stronger promises before freightctl can claim them.

## Failure and recovery

| Observed state | Next action |
| --- | --- |
| `draft` | Review the frozen definition and explicitly approve it. |
| `queued` | Invoke the bounded worker. |
| `staging` with a live lease | Let that worker finish; a competing worker cannot claim it. |
| `staging` after lease expiry | A new worker can claim a new fence and a separate temporary filename. The abandoned temporary file is retained. |
| `retry` | Resolve the reported stage/connection failure, wait until `next_at`, then invoke the worker. No final publication was authorized for that failed stage. |
| `publishing` after lease expiry | A worker records `ambiguous`; it sends no replacement bytes. |
| `ambiguous` | Use `delivery-reconcile` for a bounded read-only observation. A matching reserved final path/hash produces an observed receipt. A missing, unreadable or different file retains ambiguity. The receiver might already have consumed or moved it. |
| `blocked` | Resolve the source, collision or exhausted attempt budget; this profile requires a new reviewed intent rather than silently changing the old one. |
| `succeeded` | Inspect the observed receipt and obtain any separately required business acknowledgment. Running the worker again cannot resend it. |

Reconciliation requires the management grants and current authority. It does not create, write, rename or remove any remote file. Its recovered receipt explicitly does not claim that this observation obtained a file-sync acknowledgment. Observation failure is journaled without turning missing evidence into a successful transfer. Reconciliation may hold its own intent row during a bounded read; other actors remain isolated.

Fencing protects PostgreSQL transitions. The remote SFTP server does not understand that database fence. A worker can lose its database connection immediately before a remote operation completes; no transaction can atomically commit both systems. The committed publication phase, reserved no-overwrite name and conservative ambiguous state are the recovery boundary. This profile makes no exactly-once business-effect promise.

## Bounds and local evidence

The initial engineering profile permits two outbound streams per database across processes, enforced with retained PostgreSQL session locks, and 128 open intents per actor. Each intent has at most eight attempts; retry delay grows to 64 seconds. A worker has a 90-second absolute deadline, five-second connection timeout and fifteen-second SSH inactivity limit. Reconciliation has a twenty-second deadline. Frames are capped at 256 KiB before allocation, with sequential SFTP data requests. File size uses `--max-file-bytes`, default 64 MiB and current ceiling 1 GiB. These limits protect the initial implementation; configurable scheduling, fair reservations and large-file performance remain required.

`python3 scripts/qualify-deliveries.py` runs real PostgreSQL, stock curl, two worker processes, a separate stock OpenSSH daemon and an independent stock SFTP retrieval. It tests draft/approval and actor denial, changed host trust, traversal/symlink denial, destination collision, storage mismatch, corrupt source, authority revocation, an actual worker kill before publication, expired-stage recovery, and failure of the final local database update after the receiver has the exact file. Real expiry precedes recovery. The injected fault triggers select only the fixture's generated tenant/intent, add failure rather than relax checks, and are removed in `finally`. Keys and raw output stay ignored. The evidence uses synthetic 2 MiB files on the same macOS machine; no external partner or independent human operator is qualified.

The first [versioned workflow path](../workflows.md) supplies connection revisions/revocation and ordered SFTP steps through CLI/HTTPS. Remaining work includes live rotation/rebinding, broader workflow tasks, browser parity, active cancellation and approved rebinding, unattended queue scheduling, receiver receipt contracts, remote staging retention/cleanup and quotas, production network policy, broader peers/platforms, stronger key custody, large files and multi-host qualification.
