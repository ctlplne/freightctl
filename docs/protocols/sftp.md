# SFTP development profile

The server receives and retrieves files over SFTP v3 using stock OpenSSH. SSH proves possession of an enrolled private key and encrypts the connection. A successful file CLOSE means the new revision's bytes and directory were synced and its PostgreSQL acceptance transaction committed. With a configured [intake policy](../intake.md), the revision is held and no destination path is published until checks and separate release approval; `check-list` finds that actor's pending SFTP uploads. The integrity-only profile publishes its path in the acceptance transaction. WRITE replies acknowledge staged packets; they do not acknowledge durable acceptance. A download-authorized event records permission to start retrieval, not consumption or downstream business acceptance.

This is an assisted loopback development profile. No externally accessible deployment, outbound SFTP connector, complete customer journey, throughput result or enterprise interoperability is qualified by these tests. Payload policy remains integrity-only; malware scanning, file signatures and delivery workflows remain open.

## Setup and trust

Create a host identity separately from a user's identity. Keep the host private file protected; give clients its public key through a trusted route. Do not replace a changed host key automatically.

```sh
sh scripts/go.sh run ./cmd/freightctl ssh-host-keygen --ssh-host-key-file .private/ssh-host.key --ssh-public-file .private/ssh-host.pub
sh scripts/go.sh run ./cmd/freightctl ssh-key-enroll --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222 --token-file .private/partner.token --ssh-public-file .private/user.pub
sh scripts/go.sh run ./cmd/freightctl identity --tenant 11111111-1111-4111-8111-111111111111 --partner 22222222-2222-4222-8222-222222222222 --token-file .private/partner.token
sh scripts/go.sh run ./cmd/freightctl serve-sftp
```

The account must already exist through enrollment described in development.md. Use `ssh-keygen` or the client's ordinary key tooling to create the user key; only its public reference is registered. Enrollment/revocation requires the protected local admin database reference and the target account's token reference. It does not expose a remote account-management API. The returned key UUID is used by `ssh-key-revoke --ssh-key-id ...` with the same account references. Enrollment retries return the original receipt; revoked keys cannot be resurrected by a retry. Token access remains independent of revoking one public key.

The SSH username is the `ssh_username` value from identity, formatted as tenant UUID, partner UUID and actor UUID separated by dots. These selectors do not grant access. The database verifies the exact active registered public wire key; SSH verifies the signature proving its private-key possession before starting the subsystem. Each operation uses the same grants, mounted root, mode checks and authority revision as CLI/HTTPS. Changing the account policy invalidates the session's frozen authority revision. Revoked keys stop new operations and active readers/writers; data already retrieved cannot be recalled.

The initial host key is Ed25519. User keys allow Ed25519, P-256 and RSA 3072–8192; certificate identities and password authentication are unsupported. Key exchange, ciphers, MACs and public-key signatures use pinned x/crypto/ssh's SupportedAlgorithms, excluding its insecure algorithm list. Client trust is explicit known_hosts validation. Parsed signer objects have Go/library memory-custody limits; no FIPS, HSM or complete-zeroization claim is made.

## Operations and boundaries

| Operation | Behavior |
| --- | --- |
| Put, get, ranges | Staged immutable writes; exact stored digest verification before downloads, then current authorization on each bounded read. |
| Create/truncate/overwrite | A separate generated custody object; existing contents are retained under their old immutable ID. |
| Nontruncating write, append | Copy a verified old revision, then apply bounded writes to a new revision. Serialized frames preserve append order. |
| `reput` | Verified for a previously committed prefix. Use an explicit [upload ticket](resumable-uploads.md) to resume an interrupted, unaccepted transfer. |
| List/stat/lstat/realpath | Logical names/modes/times only, confined to the mounted virtual root; bounded pages and current authority checks. |
| Mkdir, rename, remove, rmdir | Same journaled namespace commands and revision checks as HTTPS; removal retains accepted bytes/history. |
| POSIX rename extension | Explicit replacement binds the current target revision. This is the only advertised extension. |
| Mode/time attributes | Stored virtual attributes. Ownership changes and extended attributes fail. Open-revision FSETSTAT can shrink to an existing length; standalone truncate/zero expansion remains unsupported. |
| Read/write combined handle | Explicitly unsupported; ordinary separate read-only and write-only handles work. |
| Links, host paths, statvfs, fsync | Explicitly unsupported. No partial durability guarantee is invented for an unsupported extension. |
| Shell/exec/forwarding/agent | Denied. Modern scp's SFTP upload/download is tested; legacy `scp -O` requires exec and is denied. |

Names never become host filesystem paths. Safe `.` and `..` navigation is resolved inside the virtual root; attempts to climb above it are rejected before the protocol library cleans the path. NFC and combined mount/name/component bounds still apply. Paths are case-sensitive. No host user/group identity is exposed or created; the virtual owner is an actor, and group mode bits apply only to authorized accounts within that partner.

An open writer holds partner namespace and storage admission locks. It reserves one maximum-sized revision conservatively, stages under a generated object ID and tracks bounded received extents. CLOSE fails if packets left gaps. A transport disconnect calls TransferError before cleanup Close, preventing cleanup from accepting even a completely transmitted but unclosed object. Ordinary failed staging is removed; a process crash may leave an unreferenced object. Sealed bytes are retained if SQL commit is uncertain. Reconciliation observes these states without adopting or deleting bytes.

The server cannot make an ambiguous CLOSE exactly once across reconnects without a receiver/request contract. A repeated put can create a new immutable revision. File revisions, events and path command receipts identify what committed; business-level duplicate prevention belongs in the required delivery/workflow contract.

## Budgets

| Resource | Initial profile |
| --- | --- |
| Connections | 16 by default, `--ssh-max-connections`; valid 1–1024. |
| Absolute connection lifetime | Five minutes, `--ssh-session-limit`; at most one hour in this profile. |
| Inactivity | Thirty seconds, `--ssh-idle-limit`, within the absolute lifetime. |
| SSH authentication | Five-second handshake, at most three authentication attempts. |
| SFTP packet | At most 256 KiB, checked before body allocation; 100,000 packets per session. |
| In-flight requests | One frame at a time, with bounded library worker channels. |
| Handles | Eight per session, including directories. |
| Open writers | Two by default, `--ssh-max-writers`; valid 1–4 within the eight-connection database pool. |
| Writer extents | At most 1,024 merged ranges; missing ranges fail CLOSE. |
| File/storage | Same configured limits as HTTPS; 64 MiB default file, 1 GiB current engineering ceiling, 1 GiB default custody quota. |
| Namespace | 10,000 active partner entries by default; one subtree move at most 1,000 entries. |

These are explicit engineering budgets. Larger-file, scalable reservation, tenant-fairness, multi-host and performance gates remain required. The global storage lock can delay unrelated admissions; this is not the final scheduler design.

## Native verification

`python3 scripts/qualify-sftp.py` builds a real binary and uses stock ssh-keygen, sftp, modern scp and curl against the retained PostgreSQL fixture. It pins host trust, compares receiver bytes independently, crosses the HTTPS/SFTP namespace, tests tenant/partner/mount denial, denies wrong keys/changed hosts/shell/forwarding/links/legacy SCP, checks malformed frames and handle limits, revokes a key during a rate-limited upload, kills its exact server process during staging, observes the orphan, restarts and retries into a different revision. Private keys and raw output remain ignored. No independent human adoption or third-party enterprise peer is inferred.

A modern scp regression exposed early SSH channel closure: the file arrived but the client received no exit status and failed. The transport now owns final status and normal channel close. A live-revocation regression exposed a failed upload lingering while its client drained buffered packets; invalid current authority now closes the transfer session promptly. Both original journeys are rerun without extending their time budgets.

The final native probe negotiated `mlkem768x25519-sha256`, an Ed25519 host key and `chacha20-poly1305@openssh.com`, with no compression and a clean SSH exit status. This observes one stock-client/profile combination, not every permitted algorithm or enterprise client. Complete denied-login/session-end audit retention, host-key rotation and delegated key administration remain required work. The pinned SFTP library is BSD-2-Clause and kr/fs is BSD-3-Clause; a complete distributable attribution bundle remains a release gate.

Resumable tickets add a reserved private control path. Their stat size is the committed checkpoint offset, while get is denied; completed bytes appear only at the approved ordinary destination after any configured intake checks and release. Bound-target control rename explicitly completes an already checkpointed ticket. See the [ticket contract](resumable-uploads.md) for resume and completion semantics.

Legacy SCP remains disabled in this default profile. The separate explicit
`--legacy-scp` option selects the [legacy regular-file contract](scp-legacy.md);
it never enables a shell or changes modern scp's SFTP path. Its native outcome
is separately owed;older default-denial evidence does not qualify this option.

The first local sender is documented in [approved outbound SFTP intents](outbound-sftp.md). It requires explicit approval, file-sync and atomic hardlink extensions, and handles uncertain publication through read-only reconciliation. This narrow profile does not qualify every outbound SFTP role or receiver.
