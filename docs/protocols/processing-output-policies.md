# Producer-bound processing output contracts

Profile `producer-processing-output-policy-v1` registers a checking contract for
one producer. A contract describes bytes; it grants no file, execution, release
or forwarding permission. The default ingress policy continues to describe new
incoming files. Registering a JSON output contract therefore leaves a CSV input
policy in place. A registry without a default policy does not configure ingress.

This increment implements **registration only**. Existing processing/check/release
guards do not consume these contracts. An output contract cannot yet replace the
ordinary active policy in a processing task. Producer-bound generated acceptance,
fresh checking and separate release remain owed; no repeat CSV-to-JSON processing
outcome is claimed here.

A root administrator with `admin` and `intake_manage` names an existing producer
with `read`, `write`, `check_run` and `workflow_execute`. The database resolves its
actor, tenant, partner, authority revision and namespace digest. Callers cannot
supply that authority snapshot. Each immutable policy ID/version/hash has one
immutable producer binding and journal event. Policy, binding and command receipt
commit together. Changing producer or rules creates a new version and retires the
previous output version. It does not advance, retire or replace the default policy.

Current root policy administrators and the exact current producer can inspect
the contract. Other actors cannot discover it, even with its ID. Producer
revocation or a changed authority/root invalidates that producer's observation;
the administrator can still inspect and revoke the contract. Registration grants
no administration to the producer. Revocation names the exact hash, version and
revision. Definitions, producer bindings and original receipts remain immutable.

Routes under `/v1/tenants/{tenant}/partners/{partner}`:

| Operation | Route |
| --- | --- |
| Register a new contract/version | `POST /processing-output-policies` |
| List active visible contracts | `GET /processing-output-policies?limit=25&after=UUID` |
| Inspect an exact version | `GET /processing-output-policies/{policy}/{version}` |
| Revoke an exact version | `POST /processing-output-policies/{policy}/{version}/revoke` |

Register JSON contains `producer_id`, `expected_version` and the ordinary typed
intake `definition`. A new family uses `expected_version:0` and no `policy_id`.
Updates name `policy_id` and its latest version. Revoke JSON contains
`definition_hash`, `expected_version` and `expected_revision`. Mutations require
an `Idempotency-Key`; browser cookies require the ordinary CSRF token. Strict
decoding rejects unknown fields and bodies above32 KiB. Pages default to25 and
allow at most100 summaries. Definitions use existing parser/security bounds.

Mutations return `{resource,replayed}` containing the original contract receipt.
`observation` explicitly says current state was not checked. GET separately
reports `producer_binding_current_at_observation`; this does not assert scanner,
key, file or execution readiness. `ingress_changed` is false and `usage` is
`contract-registration-only`. Lists contain policy and producer references,
format and column count, not full rules or paths. No MCP approval tool is added.

CLI commands are `processing-output-policy-register`,
`processing-output-policy-list`, `processing-output-policy-status` and
`processing-output-policy-revoke`. They use protected `-dsn-file`, `-token-file`,
`-request-file`, ordinary tenant/partner/key flags, `-output-policy-id`, `-version`,
`-output-policy-after` and `-output-policy-limit`. The [OpenAPI fragment](../api/processing-output-policies.openapi.json)
describes these routes. It is an increment, not full product qualification.

Schema55 adds one forced-RLS relation and separates policy version/state lanes.
Five latest database guards preserve all existing clauses while selecting only
the legacy default states. Historical migrations and retained schema35 are
unchanged. Fresh-CI target inventory is76 metadata/75 forced-RLS tables. F181
records focused contract/security checks and prepared real PostgreSQL, HTTPS
and CLI cases. Compilation selects zero native cases. Runtime qualification,
processing consumption and final-source acceptance remain owed.
