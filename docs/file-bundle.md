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
event. Export connection and producer-bound output policy revisions
separately. Intake policy recovery remains open.

## Export a schedule and compare its clock rules

```sh
umask 077
freightctl workflow-schedule-export --tenant "$TENANT" --partner "$PARTNER" \
  --schedule-id "$SCHEDULE_ID" --version "$VERSION" \
  --definition-hash "$DEFINITION_SHA256" \
  --output .private/portable-schedule.json
jq '.destination_preview_selection' .private/portable-schedule.json \
  > .private/schedule-selection.json
```

Use the exact schedule ID, version and definition hash from ordinary
schedule status. The `freightctl-portable-schedule-v1` file preserves
the source's frozen calendar, including the UTC offset intervals that
determined its run times. The destination selection carries the
calendar rules and workflow reference with an unset authority revision.
Supply the intended destination workflow, source selection and current
authority revision. Run ordinary schedule preview and compare its
calendar to `source_frozen_calendar`, especially across clock changes.
The destination assigns a new schedule identity on draft, with its own
approval and activation lifecycle.

## Export a connection and enroll its destination credentials

Use the connection ID, version and definition hash from the source
registry. Keep those values when recording workflow dependencies so
you can export the saved revision even after a source key is retired.

```sh
umask 077
freightctl connection-export --tenant "$TENANT" --partner "$PARTNER" \
  --connection-id "$CONNECTION_ID" --version "$VERSION" \
  --definition-hash "$DEFINITION_SHA256" \
  --output .private/portable-connection.json
jq '.destination_registration' .private/portable-connection.json \
  > .private/connection-registration.json
```

The `freightctl-portable-connection-v1` file includes the source revision,
observed state, peer settings and the fields the destination operator
must fill in. SFTP carries the public host and client fingerprints for
comparison. FTPS and WebDAV keep the public CA pin. The template omits
source credential paths and password or token hashes.

Confirm the intended peer, fill in `required_bindings` with destination
credentials or approved root references, and use ordinary
`connection-register` under destination administrator authority.
Compare the recorded source trust pin with the newly registered peer
pin. Use the resulting connection ID, version and definition hash when
rebinding a workflow. The new registration has its own credential and
revocation lifecycle.

## Export a producer-bound output policy

Use the exact ID, version and definition hash from
`processing-output-policy-status`. Run the export as a workspace
administrator with intake management permission.

```sh
umask 077
freightctl processing-output-policy-export --tenant "$TENANT" --partner "$PARTNER" \
  --output-policy-id "$POLICY_ID" --version "$VERSION" \
  --definition-hash "$DEFINITION_SHA256" \
  --output .private/portable-output-policy.json
jq '.destination_registration' .private/portable-output-policy.json \
  > .private/output-policy-registration.json
```

The `freightctl-portable-output-policy-v1` file records the exact checks,
the observed source state and the source producer binding. Review a
historical or revoked source under the destination's current policy.
Set `producer_id` to an authorized destination account. Preserve any
signature and scanner requirements and rebind their exact references
to authorized destination revisions. Use ordinary
`processing-output-policy-register` with the reviewed request. The
destination registry checks the producer and those dependencies and
returns a new policy reference you can use when rebinding a workflow.
An output policy governs that producer's workflow output. The partner
has a separate intake policy for uploads.
