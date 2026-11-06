# Agent artifact upload metadata

The [OpenAPI subset](../api/artifact-ingress.openapi.json) pins the implemented
metadata contract. External schema/client conformance remains owed.

`ordinary-custody-upload-descriptor-v1` tells an authorized host client how to use
the existing verified custody upload. The host sends bytes outside MCP/model
context through ordinary authenticated HTTPS. No freightctl inference is needed.
Preparing metadata creates no file,grant,event,receipt,capacity reservation or
receive offer. It cannot choose a recipient or start execution.

Use `POST /v1/tenants/{tenant}/partners/{partner}/artifact-ingress/previews`,
the protected-reference CLI `exchange-ingress-descriptor -request-file`,or the
read-only MCP tool `freightctl.artifact_ingress_descriptor`. All accept exactly
`{size_bytes,sha256,request_key}` and share one ordinary service. The key is the
original upload's stable idempotency key. Unknown authority,body,host/path,address,
recipient and content arguments are refused. Existing strict control-body
bounds and configured artifact admission limits apply.

This initial profile is the existing unnamed-custody upload:current write
permission and the root virtual namespace `/` are required. This is a tenant/
partner namespace,not access to the operating-system filesystem. Confined
namespace and resumable-ticket uploads retain their existing separate interfaces;
this descriptor cannot invent a path for them. It supplies no administrator role.

The result gives only `POST`,a relative `/v1/.../files` route and the exact
`Content-Type: application/octet-stream`, `X-File-Size`, `X-Content-SHA256` and
`Idempotency-Key` headers. Resolve that path only against the client's already
configured verified freightctl HTTPS origin. Add the current ordinary credential
through protected transport configuration;cookie callers also need current
same-origin CSRF protection. No bearer token,CSRF value,credential reference,
external address or artifact contents are returned in the descriptor.

Its state is `metadata-only`,availability `not-checked`,and intake policy
`evaluated-by-upload-service`. Preparation repeats current write/root permission
and rolls back its read transaction. It makes no physical-storage,capacity or
future authority promise. The actual existing upload independently checks current
authority,body length and complete digest,storage admission and active intake
policy,then stages/syncs bytes and records ordinary acceptance/idempotency/events.
Preparing a descriptor is not an approval or an upload receipt.

Check the actual response's file revision,length,SHA256,policy and acceptance.
An intake-controlled response may mean durable-held-pending-checks-and-release;
an integrity-only response proves durable local integrity acceptance. Historical
acceptance does not prove current retrievability. Receiver persistence and
business processing remain unknown. Keep the original key/meaning after a lost
response;the existing upload transaction recovers its original accepted file.
Actual current permission and the upload contract still apply on retry.

After actual acceptance,a separately authorized sender can use ordinary exact
source review and an approved receive endpoint or onward workflow. Receiving,
uploading or an artifact's embedded text supplies no forwarding/execution right.
Model configuration/content disclosure policy remains a separate trusted host
decision;this interface has no inline-content mode.

The modern noncached scoped catalog has18tools. Prepared native proof extends
the original official-SDK/two-agent/exact-byte/reply journey with API/MCP descriptor
agreement,actual HTTPS upload and unrelated role refusal. The original CLI profile
and a real PG/stored-byte inventory case cover exact metadata,no new durable
effects and original-key upload replay. Focused pure guards/schema/architecture
checks and native compilation do not qualify those runtime outcomes. All actual
native,crash/restore,confined/resumable agent convenience and final-source/baseline/
AX gates remain owed. Local inference and heavy runtimes stay off.
