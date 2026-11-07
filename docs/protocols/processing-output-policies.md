# Producer-bound processing output contracts

Profile `producer-processing-output-policy-v1` registers a checking contract for
one producer. A contract describes bytes; it grants no file, execution, release
or forwarding permission. The default ingress policy continues to describe new
incoming files. Registering a JSON output contract therefore leaves a CSV input
policy in place. A registry without a default policy does not configure ingress.

F181 implements registration; F183 adds exact contract selection for typed task
draft/approval metadata and catalog observations. The selector accepts the active
default or one exact current output contract owned by this producer. A root
administrator cannot select another producer's contract merely because it can
inspect it. Stale versions, changed authority/root and revoked contracts refuse;
catalog policy currency remains separate from historical task approval.

F185 implements producer-bound task review and generated acceptance, fresh
checking, separate release and current-policy availability. The backend path is
implemented; its prepared native cases remain unqualified. A passing stand-in
does not establish a repeated CSV-to-JSON runtime outcome.

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
`producer-workflow-output-contract`. This describes the contract's purpose,
not a claim that any bytes were processed. Lists contain policy and producer references,
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
and CLI cases. Compilation selects zero native cases.

The F185 task path uses `producer-record-projection-v1`, plan/intent schema3 and
generated-acceptance schema6. The full producer binding is inside the immutable
plan hash. Existing root/scoped plans retain their old wire hashes and semantics.
Only a bound approved typed workflow can create this producer intent; direct
projection proposals cannot acquire the new profile. Every slot, lease, current
source proof, mapping and security control remains checked before acceptance.
The output check names the exact immutable generated acceptance and selected
policy. A normal upload cannot select an output-only contract by changing a
file policy string. Transformed bytes remain held; checks and release are new
commands. Prior signatures cannot cover changed bytes.

Schema56 adds a forced-RLS status read model: only policy reference/hash, state,
format and required-protection flags. Before a release, only the administrator
or producer can see it. A release makes these status facts visible within the
ordinary tenant/partner scope; private column rules remain private. Download
guards use the release, active status and current key/scanner proofs. Namespace,
file-read, receiving, forwarding and delivery permissions remain separate.
No security-definer reader or broad output-definition disclosure is introduced.

Public audit feeds and signed exports redact producer bindings, output rules,
projection definitions and original keys to the protected journal payload's exact
digest. Redaction does not mutate that journal. Focused regressions retain the
original producer-binding and nested work-receipt disclosures before the fix.

Fresh-CI inventory now targets77 metadata/76 forced-RLS tables. Retained35 stays
unchanged. Prepared PostgreSQL cases cover repeated CSV input, fresh held JSON
checks, explicit release, revocation and public-status/audit privacy. The served
HTTPS profile retains the original default-policy case and adds the producer
case. Browser validation recognizes the pinned producer profile and refuses
identity/root/authority/reference substitution. Runtime, native browser/stock CLI,
protected output, final-source and full acceptance qualification remain owed.
Output-to-input composition, scheduling and third-party author delegation remain
separate outstanding product work.

F187 adds browser discovery and explicit selection of this producer's current
CSV/JSON output contract. Choosing it clears the old review, fetches the exact
source/output metadata, and binds the current session identity, authority and
namespace digest. Stale/other-producer contracts cannot be substituted, even by
a root administrator. The default policy remains an explicit separate choice.
Contract registration itself remains available through administrator API/CLI;
a browser registration editor is still owed.

`GET /checks/{file}/processing-contracts` retains its default v1 response. Supply
all three `output_policy_id`, `output_policy_version` and `output_policy_hash`
query fields exactly once for `record-processing-contracts-v2`. Unknown,
incomplete, duplicate and oversized query shapes refuse. V2 includes the current
producer binding and exact output policy; it loads no bytes and records no event.
The [OpenAPI fragment](../api/processing-contract-selection.openapi.json) defines
both shapes. Receiving metadata grants no effect permission.

CLI `check-processing-contracts -file-id UUID -storage DIR` uses the default.
Add a protected `-request-file` containing `{id,version,hash}` to select the exact
producer contract. It uses ordinary protected DSN/token/tenant/partner references.
MCP Catalog38/`exchange-tools-v16` adds the optional closed `output_policy`
reference to `freightctl.processing_contracts`; it remains read-only and creates
no approval or run. Actual stock-SDK proof is prepared with receiving disabled.

F187 records focused source/binding/query/browser/schema red-to-green proof.
Actual PostgreSQL, verified HTTPS, public CLI dispatch, stock MCP client and
Chrome selection/recovery/processing/release remain prepared and compiled only.
The original Chrome profile retains all five audits; the separate producer
profile adds a sixth selection audit. No local Chrome or PostgreSQL runs. All
native outcomes and final-source acceptance remain owed.
