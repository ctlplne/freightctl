# Enroll another partner

The tenant directory enrolls a partner and its first administrator through the browser, REST API or CLI. Tenant directory authority is a separate approval bound to one current credential revision. An ordinary partner administrator has its reviewed account/file grants inside that partner. Existing accounts receive no tenant authority during migration.

This is enrollment, not the complete partner onboarding/production-activation workflow. Contacts, requirements, onboarding checklists, invitations/providers, delegated trust review, environment promotion, suspension and full operator adoption remain required work. New partner accounts can use their enabled protocol grants and configured intake policies immediately; review those grants deliberately.

## Authorize the tenant operator

For a new installation, explicitly include `--tenant-administration` in the reviewed `setup-plan` command described in [first-run enrollment](first-run.md). The protected plan records that decision. Setup commits its authority event and receipt with the initial enrollment. Without that flag, first-run creates the same partner administrator as before. Existing version-1 plans without the optional field keep their original command meaning.

For an existing account, use the separately protected deployment-admin reference. The following examples use an installed `freightctl`; development can substitute `sh scripts/go.sh run ./cmd/freightctl`. Set `umask 077` before saving private request/result files. Obtain the exact actor and credential authority revision with ordinary `identity`:

```sh
freightctl identity --tenant TENANT_UUID --partner CONTROL_PARTNER_UUID \
  --token-file .private/operator.token
freightctl tenant-admin-status --tenant TENANT_UUID --partner CONTROL_PARTNER_UUID \
  --account-id ACTOR_UUID --admin-dsn-file .private/pg-admin.dsn
```

A missing status means no previous grant. For a new grant, prepare protected JSON with the selected actor, its current credential revision and `expected_revision: 0`. For an existing grant, use the exact revision returned by status. Example shape, with reviewed values substituted:

```json
{
  "operation": "grant",
  "actor_id": "ACTOR_UUID",
  "expected_revision": 0,
  "expected_authority_revision": 1
}
```

```sh
freightctl tenant-admin-grant --tenant TENANT_UUID --partner CONTROL_PARTNER_UUID \
  --request-file .private/tenant-grant.json --idempotency-key UNIQUE_REVIEW_KEY \
  --admin-dsn-file .private/pg-admin.dsn
```

Granting requires an active account with root `/`, `admin` and `accounts_manage`. The grant names its exact credential authority revision. The server role cannot grant itself this capability. Status/grant/revoke use deployment maintenance; never supply that admin connection to the serving process. The mutation records the database maintenance role, exact decision, resulting membership and retry receipt.

## Browser enrollment

Sign in as the authorized operator and open **Partners**. Review the directory, enter the new partner and administrator names, and choose the first administrator’s grants. They must include `admin` and `accounts_manage` and fit within the operator’s own grants. This does not grant the new administrator tenant directory authority.

Choose **Review partner enrollment**. The review freezes the partner/admin IDs, names, credential fingerprint, grants, credential revision and tenant-grant revision. Download the generated credential into a protected location and acknowledge that it is saved before applying. Only the credential fingerprint crosses the enrollment API; the credential value stays in the downloaded file and the browser’s temporary buffer.

A successful enrollment records both scoped enrollment events and one command receipt in a single PostgreSQL transaction. Download the partner workspace JSON, sign out, import that file’s IDs and select the new credential. Test an allowed transfer with harmless data and independently compare downloaded bytes. Configure required intake/signature/scanner and workflow policies before business exchange. Integrity-only acceptance is not a malware, signature or downstream business acknowledgment.

If a response is lost, keep the review open and retry it. The same decision and operation key return the original receipt. A definitive refusal requires canceling, refreshing current state and a new review. Cancel does not undo an enrollment that already committed. A matching historical receipt reports what was enrolled; current account status still controls access.

The directory currently shows initial enrollment metadata. An earlier partner without a registration record is labeled **Earlier enrollment**, with its ID and unavailable metadata shown explicitly. Initial administrator grants/names are enrollment evidence; later account changes are read through that partner’s ordinary Accounts workspace.

## API and CLI

Use the controlling account’s authenticated scope:

- `GET /v1/tenants/{tenant}/partners/{control}/partner-directory?limit=50&after=UUID` returns at most 100 entries and the current `authority_revision` and `tenant_administration_revision`.
- `POST` to that same path accepts a bounded strict `PartnerCommand` and `Idempotency-Key`. Cookie requests require the normal same-origin CSRF proof.
- `partner-list --partner-limit 50 --partner-after UUID` returns the same directory.
- `partner-create --request-file REF --new-token-file REF --idempotency-key KEY` uses the same typed service. With `--new-token-file`, omit `credential_sha256` from the JSON; the CLI reads the protected 64-character token and supplies only its digest. Otherwise provide its exact digest.

All ordinary CLI operations also take tenant, controlling partner, runtime DSN and token references. The command body is:

```json
{
  "partner_id": "NEW_PARTNER_UUID",
  "admin_id": "NEW_ADMIN_UUID",
  "label": "Payroll partner",
  "admin_label": "Payroll administrator",
  "credential_sha256": "LOWERCASE_SHA256",
  "permissions": ["accounts_manage", "admin", "list", "read", "write"],
  "expected_authority_revision": 1,
  "expected_tenant_revision": 1
}
```

Read both expected revisions from the current directory response. Names must be nonempty NFC text, at most 128 UTF-8 bytes, without leading/trailing spaces or control characters. IDs are lowercase UUIDs. Changed command meaning conflicts with an existing key. A stale review cannot enroll a new partner, even after the operator is reauthorized. Current authority can retrieve a matching historical receipt without executing another enrollment.

## Revoke and reauthorize

Prepare `operation: "revoke"`, the actor, the current membership revision and its recorded authority revision, then run `tenant-admin-revoke` with the same maintenance flags and a new reviewed key. Revocation immediately refuses directory/enrollment calls, including requests from cached browser views. Retrying an earlier grant key returns that old receipt and does not reactivate authority.

Credential rotation, expiry, revocation or security-policy changes invalidate a grant’s credential binding. After a deliberate rotation, use status to read the stored grant revision and `identity` to read the new credential authority revision, then make an explicit new grant. File/account permissions and tenant directory authority remain separately checked. Directory authority alone cannot authenticate into another partner or read its files.

`scripts/qualify-partners.py` exercises real PostgreSQL/storage, native Chromium, protected credential download, response-loss replay, stale/cached/rotated authority refusal and independent stock curl retrieval after restart. Its evidence is assisted same-host enrollment/transfer qualification. Independent adoption, complete onboarding, production environments, disconnected packaging and enterprise qualification remain open.
