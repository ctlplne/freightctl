# Received artifact copy

`received-artifact-copy-v1` copies exact received bytes into a new file owned by
the authenticated recipient. It is a new write, not an implicit forwarding grant.
The original receive view remains revocable. A completed owned copy has its own
custody identity, intake checks and subsequent permissions.

`POST /v1/tenants/{tenant}/partners/{partner}/exchange-copies` takes an ordinary
authenticated request, stable `Idempotency-Key` and strict16KiB JSON:

```json
{
  "exchange_id": "original receive-view UUID",
  "request_hash": "exact original offer SHA256",
  "artifact": {
    "file_revision_id": "original immutable UUID",
    "size_bytes": 8,
    "sha256": "exact content SHA256",
    "acceptance_policy": "original acceptance policy"
  },
  "virtual_path": "/new-owned-file.dat"
}
```

The service checks the current recipient, endpoint revision, sender authority,
expiry, closure, available exact source and disk identity. Separate current write
permission and writable destination ancestors are required. The path is relative
to the authenticated root; it must be new. Mode is0600, with no overwrite option.
Bytes stay inside ordinary durable storage and are independently hashed during
staging. Reads and final commit recheck authority. New intake checks apply to the
new identity; previous source verdicts or approvals are never copied.

The immutable acceptance event records exact source provenance atomically with
the file, idempotency record and applicable intake/namespace events. SQL checks
bind it to the exact current receive view and accepted result. The original-key
receipt can be recovered after the view closes, under current owned-file receipt
permission. Recovery does not reopen the source. Changed meaning refuses.

Results describe original durable acceptance, not current availability. They
expose no storage identity, host path, credentials or new destination authority.
Receiver persistence and business processing remain unknown. A later send or
workflow execution requires its own permission and approval. Returned provenance
uses the acting participant's receipt authority; ordinary privileged audit/export
rules still apply. Downstream evidence does not traverse the parent without
separate authorization.

The CLI uses the same service with `freightctl exchange-copy -request-file
<protected-json> -idempotency-key <stable-key>`, ordinary protected database and
credential references, and the existing storage/file/namespace quota settings.
The request file is a bounded0600 regular file. A CLI success is the same original
custody receipt; it does not claim remote receiver persistence.

The API/CLI and append-only schema45 acceptance guard are implemented. No new
metadata table is added; all existing tenant/partner RLS boundaries remain. The
retained database is not migrated by this work. MCP `copy_received_artifact`
delegates to this same service with metadata only.

The browser's Receive artifacts workspace provides explicit source/new-path
review and submission. It keeps the original request/key through an uncertain
response and exports private recovery hints. Import binds the exact HTTPS origin,
tenant/partner/actor,authority revision and root digest, rejects ambiguous or
unknown controls, and sends no request before explicit review/submission. Hints
grant no authority. Submitting retries the original operation and may create the
copy if it never committed; the server rechecks every new-copy permission. A
known accepted file identity is pinned on later retry. Historical acceptance
never claims current availability or receiver processing. Changing account,
session,root or authority hides old state and refuses stale callbacks.

Original native Chrome proof retains24 existing accessibility states and adds
four:copy review,uncertain response,imported hints and recovered receipt. Separate
read-only and write-capable participants,real committed-response loss,reload,
foreign-owner hint refusal,exact-key recovery,independent HTTPS bytes and exact
SQL cardinality are prepared. All actual native copy outcomes remain owed.

Native PostgreSQL, served HTTPS, byte, refusal, recovery and intake outcomes must
be proved on actual runners. This contract alone qualifies none of them.
