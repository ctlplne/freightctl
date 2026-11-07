# Independent processing workflow review

Profile `independent-processing-workflow-review-v1` gives one named reviewer
access to one explicitly disclosed schema3 task definition. It grants no file,
configuration-store, worker, release, delivery or administrator access. Existing
actor-private workflow, run, projection and receipt policies remain intact.

The creator needs `workflow_manage`. The distinct reviewer needs `inspect` and
`workflow_approve`. The review fixes both actor IDs, authority revisions and root
digests; the exact workflow ID/version/hash and draft revision; the complete
normalized definition; and an expiry within30 days. It includes no source file,
storage reference, credential or host path. The task's target is a logical path
within the executor's namespace. This explicitly discloses its name, reason,
column rules and policy references to that reviewer.

The reviewer approves or rejects the exact review hash/revision. Approval alone
does not activate a task. Its creator separately adopts an approved review while
the original draft and both participants remain current. Adoption commits the
review marker, owned workflow approval, immutable events and command receipt in
one transaction. The creator does not acquire a general approval permission.
The same actor may create and execute its task; this profile separates that actor
from its reviewer, without claiming a separate third-party author delegation.

The adopted marker is permanent. Withdrawal, expiry or participant revocation
blocks new runs and direct projection start/work/publication; it cannot fall back
to ordinary self-approval. Current status can report a changed processing binding.
Original command receipts remain historical. Pending work can still be safely
cancelled; active leases retain their existing fencing rules. Existing artifacts
remain in custody. A different task revision requires a new review.

Execution still needs ordinary `read`, `write`, `check_run` and
`workflow_execute`, the exact owned checked input and current output policy.
Review is for a reusable definition, not a grant to arbitrary input bytes.
Every output remains held for fresh checks and separate release. No onward
permission, delivery intent or business-processing promise follows.

The API under `/v1/tenants/{tenant}/partners/{partner}` exposes:

| Operation | Route |
| --- | --- |
| Request review | `POST /processing-reviews` |
| List own/named reviews | `GET /processing-reviews?limit=25&after=UUID` |
| Inspect disclosed definition | `GET /processing-reviews/{review}` |
| Decide or adopt | `POST /processing-reviews/{review}/approve`, `/reject`, `/withdraw`, `/adopt` |

Request JSON contains `workflow:{id,version,hash}`, `expected_revision`,
`reviewer_id` and `expires_at` (UTC, microsecond precision). Decisions contain
`definition_hash` and `expected_revision`. Every mutation requires its stable
`Idempotency-Key`; cookie requests also require ordinary CSRF protection. Unknown
fields and caller-supplied identities/permissions/approval assertions refuse.

Mutation `resource` values are compact original review summaries. Adoption adds
an exact workflow approval summary. They contain no duplicated definition and
are not current status. Use the separate GET for current authorized inspection.
JSON object key order is not business meaning: stored JSONB is normalized through
the typed workflow before the complete review hash is checked. Lists contain at
most100 summaries; admission allows128 unexpired pending/approved reviews per
creator. An expired open review can be explicitly withdrawn before replacement.

CLI commands are `processing-review-request`, `processing-review-list`,
`processing-review-status`, `processing-review-approve`,
`processing-review-reject`, `processing-review-withdraw` and
`processing-review-adopt`. They use ordinary `-dsn-file`, `-token-file`, `-tenant`,
`-partner`, protected `-request-file`, `-idempotency-key` and
`-processing-review-id` references; pagination uses `-processing-review-after` and
`-processing-review-limit`.
The [OpenAPI contract](../api/processing-reviews.openapi.json) defines wire shapes.
The browser's Record processing page exposes the same explicit disclosure,
named review, separate adoption and withdrawal. Its confirmation shows the actual
task rules and original expected revision. A compact saved request binds origin,
tenant/partner/actor, authority revision and root digest; it carries no credential
and imports for review before explicit submission. An uncertain command retains
its exact key. Original receipt status remains separate from current inspection.
Scope/session changes reject in-flight responses. No MCP approval tool is
introduced.

F175 records focused missing-behavior red and contract/static green. Real
PostgreSQL confinement, independent decisions, withdrawal/direct-worker refusal,
revocation, rollback and served verified-HTTPS/CLI cases are prepared and compiled
only. Neither a stand-in nor compilation qualifies these runtime claims. Schema54
adds one forced-RLS relation; current fresh-CI inventory is75 metadata/74 forced
RLS tables. Historical profiles and the retained schema35 database are unchanged.

F177 adds six focused browser contracts plus the affected processing checks and
an independent Go/Python/browser canonical review fixture. Actual Chrome proof
is prepared for two separately authenticated roles, stock-curl committed reply
loss, saved request import, explicit adoption, withdrawal, recovery of an older
approval receipt while current state remains withdrawn, six WCAG audits and
exact persisted event/owned-receipt counts. It performs no file processing and
does not replace F175/F173's separate native byte/held-output/release profiles.
Tagged compilation and stand-ins are not native qualification; those runtime
outcomes, originals and actual final-source proof remain owed.
