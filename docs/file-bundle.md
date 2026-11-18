# Export and verify selected file revisions

Use `freightctl bundle-export` to take exact file revisions out of a
workspace. The command uses the same read permissions, namespace checks,
and intake release checks as an ordinary download. Select immutable
revision IDs, which identify particular bytes even if a path changes.
A protected request file has this shape:

```json
{"file_ids":["33333333-3333-4333-8333-333333333333"]}
```

```sh
umask 077
freightctl bundle-export --tenant "$TENANT" --partner "$PARTNER" \
  --request-file .private/file-revisions.json \
  --output .private/file-revisions.tar
freightctl bundle-verify --input .private/file-revisions.tar
```

Use the ordinary `--dsn-file`, `--token-file` and `--storage` selectors
for a workspace outside the local defaults. Choose a new archive name in
a private directory. One export can hold 1–64 unique revisions and up to
1 GiB of payload. If any selection is unavailable, the entire export fails.
The command stages the archive privately, checks current authority again
and records the prepared manifest and archive hashes in PostgreSQL. It
seals and syncs the file before linking it to the output name without
overwriting. The event records preparation. A local file or directory-sync
error can leave a verified file whose durable publication still needs
inspection.

## Inspect and recover with ordinary tools

The uncompressed USTAR archive starts with `manifest.json`. Its
`freightctl-portable-files-v1` manifest records the source tenant and
partner, followed by ordered revision IDs, byte lengths, and SHA-256
hashes. Each payload is a regular `files/<revision-id>` member. Use the
archive hash from the original export receipt to identify an expected
copy independently. Offline verification checks the format and every
payload, including the archive framing.

```sh
umask 077
mkdir -m 700 .private/recovered-revisions
tar -tf .private/file-revisions.tar
tar -xf .private/file-revisions.tar -C .private/recovered-revisions
```

Extract into a fresh private directory after verification. Upload recovered
bytes using ordinary destination credentials and intake policy. The
destination issues its own file revision IDs. Keep the source manifest
and the destination acceptance receipts together to trace the move.

## Recover a revision with an audit link

`bundle-restore` uses the same destination intake as an ordinary upload.
Its protected request file supplies `archive_sha256` from the original
export receipt, `source_revision_id` from the manifest, and a new
`destination_path` chosen by the destination operator. The command
checks the whole archive against the trusted digest before taking the
selected member to intake.

```sh
freightctl bundle-restore --tenant "$DEST_TENANT" --partner "$DEST_PARTNER" \
  --input .private/file-revisions.tar \
  --request-file .private/recovery-selection.json \
  --idempotency-key recover-selected-revision
```

The receipt gives the new revision ID, the original revision and archive
references, and the destination acceptance status. PostgreSQL commits the
source link in the same transaction as receipt and acceptance. Use the
same key and selection after a lost reply. Reusing that key with different
source evidence or a different destination path is a conflict. A new key
still requires a new path. Destination policies can hold restored bytes
for checks and separate release. Whole-workspace configuration, partner
policies, full receipt history and complete exit remain open.

## Export an exact workflow revision

Record the workflow ID, version and definition hash from ordinary workflow
status. Export under the same account that can read that revision.

```sh
umask 077
freightctl workflow-export --tenant "$TENANT" --partner "$PARTNER" \
  --workflow-id "$WORKFLOW_ID" --version "$VERSION" \
  --definition-hash "$DEFINITION_SHA256" \
  --output .private/portable-workflow.json
jq '.draft' .private/portable-workflow.json > .private/workflow-draft.json
```

The `freightctl-portable-workflow-v1` file contains the source reference,
observed state, an ordinary new draft request, and exact dependency
references. These can include connection revisions, public encryption
keys and processing policies. Inspect the new draft and rebind its
references to authorized destination revisions when moving between
workspaces. Then submit it through ordinary `workflow-draft`. The
destination creates a separate draft that needs its own approval. The
export checksum appears in the CLI receipt and the scoped preparation
event. Calendars, connection definitions and policy contents have
separate lifecycle and portability work.
