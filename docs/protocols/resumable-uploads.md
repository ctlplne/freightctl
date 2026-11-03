# Resumable upload tickets

A ticket lets an authorized sender continue a large file after interruption. It fixes the destination, expected length and SHA-256 before receiving bytes. The receiver seals bounded chunks and records their exact contiguous offset in PostgreSQL. The final path stays unavailable until complete-file verification and publication commit. A chunk receipt is durable progress; it is not file acceptance, malware clearance or business delivery.

The current profile uses the existing protected service token or enrolled SSH identity, with the same tenant, partner, actor, mount policy and write permission. Tickets are private to their creating actor, even when another actor has a full-root admin grant. Key rotation can use a newly enrolled key for the same actor; revocation stops the old key. Account-policy changes invalidate the ticket's frozen authority. Folder permissions and parent identity/revision are checked again before more writes. Recovery/reapproval after policy or parent changes is still required work; the server does not silently move the destination.

## HTTPS and CLI

Use the existing `/v1/tenants/{tenant}/partners/{partner}` prefix and bearer-token header:

| Request | Meaning |
| --- | --- |
| `POST .../uploads` | Create a ticket from strict bounded JSON and an Idempotency-Key. |
| `GET .../uploads/{id}` | Read current owned state and committed_offset. |
| `PATCH .../uploads/{id}` | Append one chunk with Upload-Offset, X-File-Size, X-Content-SHA256 and Idempotency-Key. |
| `POST .../uploads/{id}/complete` | Assemble and durably accept; configured intake policy holds publication. Empty body and Idempotency-Key required. |
| `POST .../uploads/{id}/abort` | Stop an open ticket; no accepted-file deletion or automatic byte cleanup. |

Creation JSON uses `path`, `expected_size`, `expected_sha256` and optional `expected_revision`, `mode`, `modified_at`. Replacing an existing file requires its exact current revision. The server also pins the parent identity/revision. Unknown fields and trailing commands are rejected. Normal paths cannot use the reserved `.freightctl` component.

A PATCH succeeds only at the exact recorded offset. Its chunk digest and length must match the actual body. Chunks are 64 KiB–8 MiB, except that the final remaining piece may be smaller. A repeated key/meaning returns the original receipt without appending again; a changed body, offset or operation under that key fails. Read status to find current progress rather than assuming an old replay receipt is current.

The corresponding CLI commands are `upload-create`, `upload-status`, `upload-append`, `upload-complete` and `upload-abort`. Use the same tenant/partner/token references as identity/namespace commands, `--storage` for the configured store and `--idempotency-key` for each mutation. Creation reads `--request-file`; append reads a bounded regular `--chunk-file` at `--upload-offset`; other commands use `--upload-id`. No token values are printed. Creation can initialize a new private store; read-only status cannot create or replace a missing store identity.

Storage has a persistent UUID marker. A ticket cannot resume on another directory merely because both processes use the same database. Use the same initialized store on restart. Invalid markers are preserved and rejected, not overwritten. Metadata-only abort remains possible when storage is unavailable. Existing experimental unbound tickets cannot be guessed into a new store.

## Browser transfer-client tickets

The browser can prepare the same immutable receiving job without sending bytes. Choose the source and destination under **Uploads**, then **Prepare transfer ticket**. It displays the returned SFTP/FTPS paths and the exact expected digest/length. **Refresh upload status** reads durable progress or the saved accepted file ID after a lost reply. Reload discovers the same owned ticket. These browser controls use the same scoped upload API; [F067](../qualification/evidence/F067-ftps-browser-tickets.json) records their passing actual native Linux x86 Chrome/process-crash replay in both FTPS modes, with exact original output closure and independent bytes. Broader browser/platform and whole-journey qualification remain open.

## Stock SFTP

Creation returns a private protocol path such as `/.freightctl/uploads/<upload-id>`. It is a receiving job, not an ordinary published file. Use stock sftp with explicit host-key trust and your enrolled identity:

```text
reput local-file /.freightctl/uploads/<upload-id>
```

For a new zero-offset ticket, ordinary `put` also works. After interruption, `reput` obtains the stored checkpoint offset and sends the suffix. SFTP WRITE replies can cover an in-memory tail; only the recorded offset claims checkpoint durability. The default checkpoint is 1 MiB, configured with `--upload-checkpoint-bytes` between 64 KiB and 8 MiB. Disconnect drops an uncommitted tail while preserving sealed, committed pieces. Normal SFTP filenames keep their previous behavior; resume is opt-in through a ticket.

A successful CLOSE verifies and durably accepts the whole file. Under a configured [intake policy](../intake.md), completion creates a held revision; validation and separate release approval precede publication. The response’s acceptance field distinguishes that from the integrity-only profile. If all bytes were checkpointed but completion did not commit, use `upload-complete`, the HTTPS completion action, or this bound-destination SFTP completion command:

```text
rename /.freightctl/uploads/<upload-id> /the-ticket-destination
```

That control-path rename can finalize only the destination already fixed by the ticket. It cannot retarget it; repeated completion returns the same accepted revision. Ordinary namespace renames keep their existing permissions and revision rules. OpenSSH's client sets APPEND for reput and refuses reput when remote size is already equal/larger, which is why completion is a separate explicit action in that case. See the [OpenSSH client source](https://raw.githubusercontent.com/openssh/openssh-portable/master/sftp-client.c).

Ticket stat reports recorded progress. Ticket get/download is denied before and after completion; retrieve the accepted destination through its ordinary path. Directory enumeration, arbitrary truncation/reset, preservation attributes on the ticket, read/write handles and destination changes are unsupported. Final permissions/time come from the approved creation intent. A mismatched complete-file hash rejects publication; do not bypass it to force a resume.

## Explicit and implicit FTPS

Create the same ticket through HTTPS or the CLI, then use its `ftps_path`. New status/creation responses return this alongside `sftp_path`; historical saved receipts keep their original fields. The reserved path is `/.freightctl/uploads/<upload-id>` in both protocols. It names the actor-owned upload, not a host file or a published partner folder.

Use binary mode (`TYPE I`, or the engine's equivalent binary type). Ticket writers refuse ASCII conversion. `SIZE`/metadata reads report only the PostgreSQL committed offset, not a buffered tail. Resume `STOR` with `REST` at exactly that offset, or use `APPE` to append at the receiver's committed end. A truncated restart, a different offset, another actor or changed authority is refused. Ordinary filenames retain their existing transfer semantics.

For stock lftp, [the documented `put -c` command](https://lftp.yar.ru/lftp-man.html) continues an upload. The native Linux qualification uses:

```text
put -c original.csv -o /.freightctl/uploads/<upload-id>
mv /.freightctl/uploads/<upload-id> /the-ticket-destination
```

The second command can complete or recover only the destination fixed by the ticket. It cannot retarget the upload. The completion key is shared with the existing SFTP writer, so retrying completion recovers the same accepted file revision. An ordinary namespace rename still follows its normal permissions and revision rules.

A clean data completion and successful final reply mean that full length/digest verification and durable acceptance completed. Configured intake checks still hold the file until separate release. If the final reply is lost, read `upload-status`/HTTPS status and inspect its state, file ID and acceptance. A full `SIZE` alone is not file acceptance: all chunks can be durable while final verification is still incomplete. Use the bound completion rename or the ordinary API/CLI completion action when necessary.

Ticket download is refused before and after completion, and the control directories cannot be enumerated. Retrieve only the approved ordinary destination. Failed data transfer drops an uncommitted tail, keeps committed checkpoints and cannot publish a partial file. Set `--upload-checkpoint-bytes` on `serve-ftps` to choose the durable checkpoint size, between 64 KiB and 8 MiB; the default is 1 MiB. Bytes sent after the last committed checkpoint must be sent again after a crash.

The selected native ARM stand-in journey passes both FTPS modes with real PostgreSQL/storage. At `8e01a30`, stock lftp4.9.2/GnuTLS resume, bound completion and independently matched retrieval pass on native GitHub Linux ARM/x86 in both listener modes ([F064](../qualification/evidence/F064-ftps-upload-tickets.json)). [F065](../qualification/evidence/F065-ftps-public-crash-recovery.json) separately drives real CLI/HTTPS controls across an actual task-owned FTPS process SIGKILL/restart. It recovers the unchanged checkpoint and original completion receipt, then checks/releases and independently retrieves the exact bytes. The public CLI wiring defect found by that test is repaired. Both new native Linux ARM/x86 profiles pass at `23cb5c5`: 21 native FTPS records and 194 original commands each, including 12 public crash cases. Browser ticket journeys, power-loss, multi-host, database and broader recovery remain open.

## Bounds and evidence

This engineering profile has a 1 GiB file ceiling, 4,096 chunks per upload, 128 open tickets per actor, existing file/storage quotas, one-frame SFTP admission, eight handles/session and bounded writers/time. These are operational development budgets, not edition limits. Assembly temporarily needs another full-file allocation on disk. Chunks remain retained and charged after completion, abort or rejection. Configurable larger estates, 100 GiB/1 TiB gates, cleanup/recovery, storage compaction, fairness, distributed backends and endurance remain open.

`python3 scripts/qualify-uploads.py` uses real PostgreSQL, stock curl and OpenSSH. It verifies private checkpoint receipts, exact retries, wrong offsets/digests, foreign actors, raw-chunk download denial, wrong-store rejection, a killed SFTP server, restart of both protocol services, CLI status and stock reput, independently matched final bytes, complete-prefix recovery, bound-destination denial, replay, CLI creation and abort. The broader foundation command also runs real database/storage isolation, conflict/corruption/revocation tests, race checks, bounded fuzzing and the previous HTTPS/SFTP journeys. No complete customer journey or enterprise qualification is inferred.
