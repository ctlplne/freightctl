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
workflow execution requires its own permission and approval. Parent provenance
is private to the actor performing this operation; downstream evidence must not
traverse it without separate authorization.

The CLI uses the same service with `freightctl exchange-copy -request-file
<protected-json> -idempotency-key <stable-key>`, ordinary protected database and
credential references, and the existing storage/file/namespace quota settings.
The request file is a bounded0600 regular file. A CLI success is the same original
custody receipt; it does not claim remote receiver persistence.

The API/CLI and append-only schema45 acceptance guard are implemented. No new
metadata table is added; all existing tenant/partner RLS boundaries remain. The
retained database is not migrated by this work. MCP `copy_received_artifact`
delegates to this same service with metadata only. Browser convenience controls
remain implementation work; all native copy outcomes remain owed.

Native PostgreSQL, served HTTPS, byte, refusal, recovery and intake outcomes must
be proved on actual runners. This contract alone qualifies none of them.
