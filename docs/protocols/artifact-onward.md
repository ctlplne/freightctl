# Reviewed artifact onward delivery

`ordered-workflow-onward-v1` connects an owned,available artifact to an already
approved schema1 ordered sending workflow. Its steps reference registered SFTP or
FTPS connections. It accepts no arbitrary URL,host path,recipient,script,new
credential or approval flag. It does not adopt collection inputs or schema2
routing programs. Those bridges and complete AX-J02 qualification remain owed.

The caller needs the ordinary workflow service's root namespace profile plus
`workflow_execute`,read and deliver. The workflow must already be approved for
that actor's current authority;this interface cannot draft,approve or register
connections. Receiving an artifact view adds none of those permissions or ordinary
source access. A result derived outside freightctl needs its own permitted upload
and immutable identity before it can be used as an onward source. Correlation is
not proof of content derivation;complete cross-hop lineage remains work.

Under `/v1/tenants/{tenant}/partners/{partner}`:

| POST | Input | Meaning |
| --- | --- | --- |
| `onward/previews` | `OnwardRequest` | Read current source,policy,approved workflow and registered connection metadata. No run,intent,reservation or peer contact. |
| `onward/runs` | `{request,review_hash}` plus original `Idempotency-Key` | Compare the exact review inside the same transaction that records the ordinary run,intents and private command receipt. No peer contact. |
| `onward/receipts` | `{start:{request,review_hash},receipt_key}` | Recover only an already recorded exact reviewed-start receipt. Never creates or adopts a run. |
| `onward/status` | `{start,receipt_key,run_id}` | Inspect only that exact previously accepted reviewed run;no transfer. |
| `onward/work` | `{start,receipt_key,run_id}` plus stable `Idempotency-Key` | Work one ordinary pending intent. May perform the approved remote writes. |

The [OpenAPI subset](../api/artifact-onward.openapi.json) pins these five paths;
full external schema conformance remains owed.

An `OnwardRequest` contains `schema_version:1`,
`profile:ordered-workflow-onward-v1`,a workflow `{id,version,hash}` and artifact
`{file_revision_id,size_bytes,sha256,acceptance_policy}`. Normal strict workflow
JSON decoding rejects unknown fields,aliases and trailing data. Preparation's
SHA256 binds those exact values,tenant,partner,actor,authority revision,namespace
root digest,workflow approval revision and storage identity digest. It is a
consistency fingerprint,not an authorization credential or digital signature.
The server repeats actual permission and policy checks at staging and work.

The approval row is locked through staging. The recorded command receipt retains
its exact profile,review hash and workflow approval revision alongside the normal
run. Later lookup reconstructs the fingerprint from that immutable evidence.
A changed binding refuses before intents are staged. Preparation only advises on
available capacity;actual admission still reserves capacity transactionally.
Storage identity is checked during preparation;complete physical-byte and transfer
checks retain their ordinary worker meaning. No preparation response promises
physical-byte verification,remote acceptance or future availability.

An identical start key/body recovers the original accepted run without waking a
worker. Changed meaning under that key conflicts. Current original actor/authority
and source-receipt permission still guard disclosure. A subsequent workflow
revocation,policy hold or smaller new-file admission allowance does not turn an
old acceptance fact into a new action. New runs and actual work independently
refuse stale authority,holds and revoked configuration. A credential rotation
cannot adopt an old private command receipt.

The CLI commands are `onward-preview`, `onward-start` and `onward-receipt`,using
ordinary protected runtime-DSN/account/storage references and `-request-file`.
New onward request references must be protected bounded regular files;values are
cleared after decoding. Start uses `-idempotency-key`. Existing `workflow-work`,
status and recovery commands operate on ordinary runs with unchanged policy,
leases,fencing,receipt and ambiguity rules. Ordinary API/browser session mutations
retain current same-origin CSRF protection.

The MCP profile now exposes17tools. Its additional `freightctl.prepare_onward`,
`start_onward`, `onward_status` and `work_onward` separate review,staging,inspection
and one bounded work step. Status/work require the original typed `start`,its
`receipt_key` and exact `run_id`;work also needs its stable `request_key`. The
receipt lookup proves this run came from the narrower reviewed profile. It cannot
adopt a generic,collection or routing run. The work key fixes one ordinary pending
intent;repeating it cannot advance to the next step.

Only work can contact a registered peer. Its annotations conservatively disclose
external and potentially destructive writes,according to the approved adapter's
contract. It supplies no arbitrary network tool or stronger exclusive-publication
promise. HTTP cancellation and existing10second tool deadlines can leave remote
outcomes uncertain. Inspect actual state/receipts before recovery;do not infer
that a lost response means nothing happened.

MCP returns source integrity,workflow references,run/delivery IDs,states and receipt
hashes. It omits storage identity,namespace paths,private step labels,transport
references,raw observations and parsed contents. Historical acceptance says
`recorded-run-and-intents-only` with current state `not-checked`;current status is
a separate read. Receiver persistence and business processing remain `unknown`.
An ordinary authorized operator can inspect the full workflow/receipt through its
existing interfaces. Required independent approvals and current worker checks are
unchanged.

The browser's **Onward delivery** workspace is available to a root-namespace
participant with workflow_execute,read and deliver. Enter the exact available
file revision and approved workflow ID,version and hash. Review shows source
integrity and the ordered registered connection references. Confirm queue records
one ordinary run and intents without contacting a destination. The acceptance
receipt reconstructs the exact Go review fingerprint,including current original
participant,authority,root,approval revision and storage identity. It reports
historical queued acceptance separately from current state.

Save the recovery document before a consequential action. It contains no account
credential or transport secret;protect its private scope and metadata. Import
binds the exact HTTPS origin,actor,authority and root and contacts nothing. Saved
destination hints are untrusted. A fresh server preview must replace them and
match the original fingerprint before queueing or work is enabled. Original
receipt lookup and current observation remain separate read operations. A lost
response retains its original request/work key. Retrying a work key cannot move
to another step. A successful response allows the next explicit one-step action;
neither success nor a status label implies receiver business acceptance.

The ordinary HTTPS status/work paths and MCP share one receipt-bound adoption
helper. Their projection omits namespace/storage/transport references,raw step
observations and private labels. Current permissions,checks,approval,leases and
fencing are still enforced by the existing worker. No endpoint registration,
workflow approval,collection adoption or new forwarding grant is supplied here.

Prepared native proof covers zero-effect preparation,atomic run/intents/receipt,
exact-key replay,stale review,workflow revocation,policy holds,new-admission change,
wrong principal,credential rotation and legacy-run refusal. Actual HTTPS review/
start/lookup and a real native freightctl FTPS peer with independent byte readback
and contact counters are prepared. This own-product peer is not an independent
stock-receiver interoperability claim. Only focused pure tests and affected
compilation/vet/architecture checks have run locally. The original Chrome profile
is extended for a lost real queue response,reload/private receipt recovery,
tampered saved destination hints,current observation and revoked-work refusal,
with22accessibility states and exact SQL run/intent/receipt/zero-attempt counts.
Actual native/stock/client,UI,collection/cross-hop lineage,crash/restore and all final-source qualification
remain owed. Local inference and heavy runtimes stay off.

The separate [collected source review](artifact-collection-source.md) can identify
an already captured exact source under its own current source permissions. It
does not adopt the collection's existing run,routing plan,approval or permission.
Its artifact tuple can enter a new ordinary offer or this reviewed onward profile
only through the caller's separately authorized action.
