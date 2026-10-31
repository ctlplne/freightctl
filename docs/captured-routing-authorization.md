# Review new routing for a captured batch

F041 is in progress. Selected backend contracts pass against real PostgreSQL, and the independent browser validation layer passes its data contracts. Browser controls, retained-database upgrade and stock-source/receiver qualification are still pending. F040 remains the last completed routing increment.

When an original program cannot decide what to do with captured files, editing its workflow must not silently change that job. A routing authorization is a separate record: it names an already approved schema-2 revision in the same workflow family and pins the exact plan fingerprint for each input owned by the original job. The original producer manifest, source facts, job definition, deadline and earlier input claims stay unchanged.

The target must use the same source configuration. The original source approval, current account authority, intake releases, exact published paths and any original calendar occurrence remain required. Every newly owned input must still have no run, including a local outcome. Once a run exists, this mechanism cannot reinterpret that batch. It grants no permission to extend a deadline, repair revoked source authority, change recipients through a request body or resend inputs owned by an earlier job.

A proposal changes no execution choices. Approval requires `workflow_approve` and binds the exact definition fingerprint and current proposal revision. Its definition includes the prior effective routing decision and revision; an intervening revocation or approval makes an older review stale. A proposed record can be withdrawn. Revoking an approved record blocks unfinished admission and execution; the system does not silently restore the original program. Before any input has a run, using another revision again requires another explicit authorization.

Ordinary collection refresh admits the reviewed plans through the existing run and delivery-intent engine. Each run retains its routing authorization ID and immutable plan. Sending still requires current permissions, the exact approved recipient connections and keys, whole-sibling intake and independent dispatch consent for each selected file and step. A local outcome creates no delivery intent. Approval itself contacts no peer and reserves no send capacity.

## API operations

Let `base` be `/v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing`. All operations remain private to the original actor under tenant and partner isolation.

| Method and suffix | Request and result |
| --- | --- |
| `POST base/preview` | A selection produces the immutable definition and its fingerprint. No durable writes or external contact. |
| `POST base/inputs/{input}/preview` | The same selection returns one complete plan with potential and selected recipients. Compare its fingerprint with that input's authorization binding. |
| `POST base/proposals` | The selection plus its reviewed `definition_hash` creates one pending proposal. Requires an idempotency key. |
| `GET base?after={version}&limit={count}` | Private version-ordered history; page size is 1–100. |
| `GET base/{routing}` | Original definition and current record state/revision. |
| `POST base/{routing}/approve` | Approve the exact fingerprint and `expected_revision`, with an idempotency key. |
| `POST base/{routing}/revoke` | Revoke an approved record using its current fingerprint/revision and an idempotency key. |
| `POST base/{routing}/withdraw` | Withdraw a pending proposal using its current fingerprint/revision and an idempotency key. |

The selection contains `collection: {definition_hash, expected_revision}`, `workflow: {id, version, hash}` and `expected_authority_revision`. It contains no caller-supplied facts, plans, deadlines or recipient overrides. The proposal wraps it as `{selection, definition_hash}`. Plans are reviewed one input at a time; a 64-input authorization contains fingerprints rather than an aggregate of potentially large plans.

## CLI operations

The matching commands use the normal protected token/database/storage references and bounded JSON `--request-file`:

| Command | Extra references |
| --- | --- |
| `workflow-collection-routing-preview` | `--collection-id` |
| `workflow-collection-routing-input-preview` | `--collection-id`, `--collection-input-id` |
| `workflow-collection-routing-propose` | `--collection-id`, original `--idempotency-key` |
| `workflow-collection-routing-status` | `--collection-id`, `--routing-id` |
| `workflow-collection-routing-list` | `--collection-id`, optional version `--collection-after` and `--collection-limit` |
| `workflow-collection-routing-approve` | `--collection-id`, `--routing-id`, original `--idempotency-key` |
| `workflow-collection-routing-revoke` | The same exact record/key references |
| `workflow-collection-routing-withdraw` | The same exact record/key references |

Preview, proposal and approval check the existing storage identity without reading payload bytes. Withdrawal and revocation remain metadata controls and can work after the original execution cutoff. Keep the same idempotency key and identical request when recovering a lost response; a different key is a new command.

## Remaining qualification

Migration 033 executes in temporary fixture databases; it has not been applied to retained storage. Seven new PostgreSQL cases prove selected blocked-batch repair, forged-binding and missing-lineage refusal, revocation without fallback, actor/partner/tenant privacy, protected-journal versus ordinary-feed/audit redaction, workflow revocation, withdrawal, original-key receipts and stale prior-decision refusal. Go and SQL agree on exact wire fingerprints for send/local examples and 64 bindings. The 133 workflow tests and two fuzz harnesses, 17 API tests, three migration/isolation/fencing regressions, 95 frontend data contracts and TypeScript checking pass. These tests do not establish stock-source collection, receiver delivery or a complete browser journey for this feature.

The browser validation layer independently recomputes each input's choices from the original manifest, verifies all bound input/file identities and preserves private receipt identity. Its controls and run inspection are still unwired. Finish browser review of all plans, actual response loss, restart/reload, scheduled capture, partial capacity, concurrency, intake/key/source/calendar changes, separate dispatch consent, retained upgrade and stock receivers under [the implementation contract](architecture/0015-captured-routing-authorization.md). [The progress record](qualification/evidence/F041-captured-routing-authorization.json) preserves the tested source epochs and exact remaining scope.

The owner-deferred aggregate replay remains pending. No inference or scanner qualification is part of this increment. The full product goal, whole parity rows and full journeys remain open.
