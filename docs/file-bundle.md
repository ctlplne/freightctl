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
event. Export each referenced connection, intake policy and
producer-bound output policy revision separately.

For a processing workflow, compare the restored intake definition hash
with the workflow's source policy hash. Set the draft's output policy
reference to the newly registered producer policy. Run a known sample
after destination approval. Check that the output is held, release it
through the destination's ordinary controls, and compare the released
bytes to the original output.

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

## Export a partner's intake policy revision

Record the ID, version and definition hash returned by
`intake-policy-status` or an earlier registration receipt. A workspace
administrator with intake management permission can export that exact
revision after a replacement or revocation.

```sh
umask 077
freightctl intake-policy-export --tenant "$TENANT" --partner "$PARTNER" \
  --intake-policy-id "$POLICY_ID" --version "$VERSION" \
  --definition-hash "$DEFINITION_SHA256" \
  --output .private/portable-intake-policy.json
jq '.destination_registration' .private/portable-intake-policy.json \
  > .private/intake-policy-registration.json
```

The `freightctl-portable-intake-policy-v1` file preserves the reviewable
checks and source state. In the template, `expected_version` starts at
`-1` so ordinary registration refuses it. Check the destination's
current intake policy. Set the field to its observed version, or to
`0` after confirming there is no policy. Rebind any required signature
key and scanner to approved destination revisions and review the effect
on new uploads. Apply the reviewed request with `intake-policy-register`.
New uploads use the resulting destination policy and remain held until
they pass its checks and an authorized operator releases them.

## Export an enrolled tenant partner mapping

A tenant directory administrator can export one registered partner.
Get the partner ID and original registration event ID from
`partner-list`. Use the operator's control partner in `--partner`
and the selected entry in `--target-partner-id`.

```sh
umask 077
freightctl partner-export --tenant "$TENANT" --partner "$CONTROL_PARTNER" \
  --target-partner-id "$TARGET_PARTNER" --partner-registration-event-id "$EVENT_ID" \
  --output .private/portable-partner.json
jq '.destination_registration' .private/portable-partner.json \
  > .private/partner-registration.json
```

The `freightctl-portable-partner-v1` file records the original registration
and initial permissions for review. Its template carries the two display
labels. Pick destination partner and administrator IDs, review the
initial permissions, and fill in both current authority revisions from
the destination's `partner-list`. Run ordinary `partner-create` with the
reviewed request and a freshly generated protected `--new-token-file`.
Keep the source event and new registration receipt together for mapping
later workflow and connection references. Bootstrap entries without an
ordinary registration event and later account changes need separate
recovery.

## Preserve an original namespace command receipt

Keep the original protected request file and its idempotency key. The
same participant can export the historical result with its current
receipt permissions, even after a later move or deletion.

```sh
umask 077
freightctl namespace-receipt-export --tenant "$TENANT" --partner "$PARTNER" \
  --request-file .private/original-command.json --idempotency-key "$ORIGINAL_KEY" \
  --output .private/portable-namespace-receipt.json
shasum -a 256 .private/portable-namespace-receipt.json
jq '.receipt' .private/portable-namespace-receipt.json
```

Compare the file's SHA-256 to the original export response. The
`freightctl-portable-namespace-receipt-v1` file identifies the source
workspace, actor and completion event, and records the original command
result. Keep the event reference with the relevant signed audit export
for independent verification. A reader can inspect the JSON offline.
The historical receipt describes what committed at that time. Consult
ordinary status for current paths or availability.

## Preserve a delivery's recorded receiver observation

Take the delivery ID, definition hash and exact completed revision from
`delivery-status`. Use the original participant with current permission
to read the delivery and its source file.

```sh
umask 077
freightctl delivery-receipt-export --tenant "$TENANT" --partner "$PARTNER" \
  --delivery-id "$DELIVERY_ID" --definition-hash "$DEFINITION_SHA256" \
  --expected-revision "$REVISION" --output .private/delivery-receipt.json
shasum -a 256 .private/delivery-receipt.json
jq '.observation' .private/delivery-receipt.json
```

Compare the SHA-256 with the export response. The
`freightctl-portable-delivery-receipt-v1` record links the exact local
file revision, completed delivery event and receiver readback
observation. The export reads PostgreSQL and works after a receiver
goes offline. It keeps the protocol's original integrity and durability
fields, including any unknown business acceptance. Preserve the source
completion event with its signed audit export. Confirm business
acceptance separately with the receiver's business system.

## Export a workflow run's committed history

Take the run ID, workflow hash and run revision from
`workflow-run-status`. Put those values in a protected request file.
The first page starts after revision zero.

```json
{
  "run_id": "33333333-3333-4333-8333-333333333333",
  "workflow_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "through_revision": 5,
  "after_revision": 0,
  "limit": 64
}
```

```sh
umask 077
freightctl workflow-run-history-export --tenant "$TENANT" --partner "$PARTNER" \
  --request-file .private/run-history-request.json --output .private/run-history-page-1.json
shasum -a 256 .private/run-history-page-1.json
jq '.transitions' .private/run-history-page-1.json
```

The `freightctl-portable-workflow-run-history-v1` page contains committed
transitions in increasing revision order. Keep the source identifiers
and `through_revision` fixed. When a page includes `next_after_revision`,
set `after_revision` to that value and choose a new output file. Keep
each page's export checksum and event IDs. A request with a gap,
different workflow hash or uncommitted upper revision fails. Use the
ordinary status command for live observations. For processing runs,
use the same source custody root required by status.

## Export an OpenPGP verification or encryption public key

A workspace administrator with OpenPGP management permission can export
an exact public key revision. Get the key ID, version and definition hash
from `pgp-key-status`.

```sh
umask 077
freightctl pgp-key-export --tenant "$TENANT" --partner "$PARTNER" \
  --pgp-key-id "$KEY_ID" --version "$VERSION" \
  --definition-hash "$DEFINITION_SHA256" --output .private/public-key.json
jq -r '.destination_registration.public_key' .private/public-key.json |
  openssl base64 -d -A > .private/public-key.gpg
shasum -a 256 .private/public-key.gpg
```

Compare the packet checksum with `public_key_sha256` and verify the
fingerprint independently. The archive records the key purpose,
expiration and source lifecycle state. Review whether the destination
should trust it, including any source retirement or revocation. Extract
`destination_registration` into a protected request, set its
`expected_version` explicitly, and submit it through `pgp-key-register`.
Use zero for a new key family. Registration checks the key's current
validity and purpose. Rebind intake policies and encryption workflows
to the new key ID, version and definition hash. Private key custody stays
with the signing or receiving system.

## Compare an encrypted workflow before cutover

For a test delivery, use different source and destination receiving
directories so each run has its own observable effect. Bundle the exact
source file revision. Export its workflow, connection, and OpenPGP
recipient. On the destination, restore the file against the bundle's
pinned checksum, enroll a fresh SFTP client key, and review the
recipient public key. Rebind the workflow to the newly registered
connection and recipient before approving it.

Retrieve each test ciphertext with stock SFTP. Use the receiving
system's own GnuPG keyring to authenticate and decrypt the ciphertexts
into a private directory, then compare both plaintexts to the selected
source bytes. Keep the destination delivery observation and a signed
audit export. Their event IDs connect the restored revision and its
lineage to the workflow, the recorded receiver readback, and the
protected delivery receipt.

## Export an account's namespace and permission policy

An account manager can export an account revision using its ID and the
revision from `account-status` or a saved command receipt. Use the original
manager for historical revisions. A current account can also be exported
from its ordinary status projection.

```sh
umask 077
freightctl account-export --tenant "$TENANT" --partner "$PARTNER" \
  --account-id "$ACCOUNT_ID" --expected-revision "$REVISION" \
  --output .private/account-policy.json
jq '.destination_registration' .private/account-policy.json \
  > .private/account-registration.json
```

The export records the source namespace, permissions, expiration, and
revocation at that revision. Review the destination namespace and
permission list explicitly. Fill in those fields and the new account
ID. Keep or review the original expiration, and use a freshly generated
token with `account-create --new-token-file`. Verify the new account
can access its intended path and fails outside that scope. Credential
values and their hashes stay with the source.

## Preserve evidence of an artifact exchange

Get the exchange ID and request hash from the ordinary authorized
`exchange-trace` result. Use `incoming` for the recipient view or
`outgoing` for the sender view. Put those exact values in a protected
request file with fields `exchange_id`, `direction`, and `request_hash`.

```sh
umask 077
freightctl exchange-trace-export --tenant "$TENANT" --partner "$PARTNER" \
  --request-file .private/exchange-evidence-request.json \
  --output .private/exchange-evidence.json
shasum -a 256 .private/exchange-evidence.json
jq '.evidence' .private/exchange-evidence.json
```

Compare the checksum with the export response. The
`freightctl-portable-exchange-evidence-v1` document preserves the
actor's authorized event references and the metadata state observed at
`checked_at`. A sender can retain its cancellation evidence after
recipient retrieval closes. Use a signed audit export to verify the
event IDs. Retrieval, receiver persistence and business processing
stay unknown in this availability evidence.
