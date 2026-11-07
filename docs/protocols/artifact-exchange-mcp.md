# Governed agent exchange tools

The implemented endpoint is `POST /v1/tenants/{tenant}/partners/{partner}/mcp` over
verified HTTPS. It pins MCP **2026-07-28**, using the official Go SDK **v1.8.0**,
stateless Streamable HTTP and single JSON responses. This is the exchange-tool
profile, not a complete implementation of every AI requirement in GOAL.md.
Actual stock-client/native qualification remains owed.

An MCP client is a caller, not an identity provider. Configure the same ordinary
freightctl bearer credential used by the HTTPS API in the client's protected
transport configuration. Keep its value out of tool arguments, model context,
command lines and evidence. Tenant and partner come from the authenticated URL;
actor and permissions come from the current database credential. Arguments cannot
supply another actor, a tenant switch, an arbitrary URL, host path or approval.
Optional Trust Control integration remains unpinned; no provider API is assumed.

Every request carries `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, and, for
`tools/call`, `Mcp-Name` matching its tool name. Send `Content-Type:
application/json` and accept both `application/json` and `text/event-stream`.
The same version and client capabilities appear in `params._meta`. For example,
a tool-list body is:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"approved-exchange-caller","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}
```

Use a client supporting this pinned revision. Discovery is `server/discover`;
legacy initialization, session IDs, GET streams and DELETE sessions are not this
profile. The SDK validates version/header/body agreement. All discovery and tool
requests authenticate; cached descriptions cannot grant current permission.
Invalid origins refuse even with a bearer header. Cookie callers retain ordinary
same-origin CSRF protection. Tool-list results are private and immediately stale.

| Tool prefix `freightctl.` | Effect |
| --- | --- |
| `identity` | Inspect current scoped identity and grants. |
| `artifact_ingress_descriptor` | Review metadata for the existing ordinary custody upload route. Host sends exact bytes separately with ordinary authentication;preparation records no file,grant or receipt. |
| `exchange_source` | Review own authorized source revision metadata. |
| `collection_source` | Review one exact captured actor-private input and current ordinary source permission,with manifest/input correlation;no collection,offer or onward execution. |
| `exchange_endpoints`, `exchange_endpoint` | Read visible current endpoint heads. |
| `prepare_exchange` | Check an exact proposed request against current sender/source/endpoint/participant/policy/expiry/admission metadata. |
| `offer_exchange` | Commit the ordinary exact-byte offer and private idempotency receipt. Requires the exact canonical request hash and stable request key. |
| `incoming_exchanges`, `inspect_exchange` | Poll and inspect currently authorized incoming views; held rows stay opaque. |
| `retrieval_descriptor` | Return exact integrity metadata and a relative authenticated HTTPS download path, without artifact bytes. |
| `exchange_trace` | Read authorized custody/offer/closure records under an explicit incoming or outgoing selector;held incoming views stay opaque. |
| `validate_workflow`, `propose_workflow` | Validate a typed ordinary workflow or record an unapproved draft with its original operation key. Current workflow permissions and registered connection/source checks apply. |
| `artifact_upload_start`, `artifact_upload_status`, `artifact_upload_complete`, `artifact_upload_abort` | Create/recover a new confined virtual-file ticket,inspect committed progress or explicitly complete/abort through ordinary resumable custody. Host sends bytes outside MCP. |
| `outgoing_exchanges`, `exchange_receipt` | Inspect own original offer receipts and separately checked current state. Enumeration also needs list. |
| `close_exchange` | Record one exact sender cancellation or recipient decline using its original request hash and stable operation key. |
| `prepare_onward`, `start_onward` | Review an owned artifact/approved ordered workflow,then atomically record ordinary intents under the exact review. |
| `onward_status`, `work_onward` | Inspect or execute one ordinary step only with the original reviewed-start receipt and exact run binding. |

`validate_workflow` takes `request` in the ordinary `PreviewRequest` shape:
`definition` and optional `file_id`. `propose_workflow` takes the ordinary draft
`request`: `definition`, `expected_version`, optional `workflow_id`, plus the
stable outer `request_key`. The closed schemas preserve the typed source,
encryption-reference and finite program shapes; recursive conditions use the
ordinary quoted integer format, including `"0"`. Existing wire depth/token/body
bounds and domain normalization remain enforced. No shell, credentials, host key
paths, arbitrary connection address, approval or execution flag is accepted.
Typed filenames/directories retain their ordinary namespace/connection meaning.

Validation uses the same current workflow roles, registered connection versions
and optional ordinary file access as the API/CLI. It creates no durable objects,
contact or reservation and checks no physical bytes. Results contain the
normalized definition hash, schema/counts and requested authorized source identity;
names, filenames, remote addresses/directories, credential references and raw
effect descriptions are omitted. Hashes describe the plan, not approval.

Proposal requires ordinary root `workflow_manage`, records one immutable draft
revision and command receipt, and returns its identity/hash/revision. Separate
ordinary approval remains necessary before any run or onward intent. Exact-key
retries return the original draft with current state explicitly unchecked, even
when the database represents JSON keys in another order. Hash verification
normalizes the typed definition rather than hashing stored JSON formatting.
Changed meaning under the same key refuses. The original native official-client
profile now includes API/MCP hash/receipt parity, real PostgreSQL no-effect and
exact draft cardinality, role refusals, redaction and unapproved-onward refusal.
Those native outcomes remain owed. See
[F118](../qualification/evidence/F118-mcp-workflow-review-proposals.json).

`copy_received_artifact` takes a strict `request` matching
[received-artifact-copy-v1](received-artifact-copy.md) and `request_key`. It invokes
the same ordinary custody service as API/CLI. Current receive plus independent
write permission is required for a new private destination; bytes stay in custody,
are rehashed during staging, and get fresh intake checks. A received view does not
grant forwarding or execution. Original-key recovery returns the owned copy's
original acceptance without reopening a stale source view. Current availability,
receiver persistence and processing are not inferred. No content,overwrite,mode,
host path,actor,root,recipient or execution option enters this tool. The current
catalog has38 tools, implementation `exchange-tools-v16`; actual original
SDK/HTTPS proof remains owed.

Five scoped record-processing controls share the ordinary governed service:
`preview_record_projection`, `propose_record_projection`,
`inspect_record_projection`, `start_record_projection` and `work_record_projection`.
They require explicit workflow action rights, owned exact input and the actor's
namespace. Model results omit private paths, reasons, full definitions, staging
IDs and bytes. A review hash binds the complete private plan. There is no approval
or release tool; ordinary approval and fresh held-output checks/release remain
separate. The existing ten-second deadline is unchanged. The
[projection contract](record-projection.md) states the role, receipt and output
boundaries; stock-SDK/HTTPS/PostgreSQL runtime proof remains owed.

Six typed-workflow controls extend that catalog: `processing_contracts`,
`start_processing_workflow`, `inspect_processing_workflow`,
`work_processing_workflow`, `refresh_processing_workflow` and
`cancel_processing_workflow`. Contract discovery returns authorized source/output
schemas, exact policy revisions, source proof expiry and authority/root digests;
it reads no payload and creates no approval or run. Existing `validate_workflow`
and `propose_workflow` accept the closed schema3 records.project definition.
Start requires its separately approved exact workflow revision. These controls
use ordinary workflow permissions and services even when optional artifact
receiving is unconfigured; exchange operations retain their own receive gates.

Workflow results omit private paths, reasons, complete definitions, staging slots
and bytes. Original command receipts and historical work attempts remain separate
from current status. A completed task produces a held artifact, with no delivery
intent. Fresh ordinary checks and separately authorized release are required.
No approval, release or arbitrary execution tool is added. Focused contract and
redaction tests pass; the prepared stock-SDK verified-HTTPS/PostgreSQL case is
compiled only and remains owed.

`list_processing_workflows` discovers the actor's latest processing task versions
without names, reasons, paths or full rules in model output. Current approval and
output-policy facts remain separate; execution readiness is not checked. It uses
ordinary workflow scope and the [processing catalog contract](processing-workflow-catalog.md),
with no receive-adapter dependency, approval, file read or execution grant.

The four resumable controls use `ordinary-resumable-artifact-upload-v1` and the
existing upload service. Start takes `virtual_path`, `size_bytes`, `sha256` and
`request_key`; the path is relative to the authenticated account's virtual root.
It cannot name a host path, change roots, overwrite a file, set modes or supply
bytes. The service omits the replacement revision and fixes file mode0600. The
ordinary service therefore requires a new destination; it never replaces a file.
This is the same ordinary API/CLI create request. Status takes
`upload_id`; complete/abort also require their original stable `request_key`.
Every operation keeps the ordinary actor,root,authority revision and write checks.
No receiving privilege supplies upload authority.

The ticket is a durable checkpoint record, not accepted artifact bytes. The host
resolves `relative_append_path` only against its configured freightctl HTTPS
origin and sends authenticated `PATCH` chunks using the returned header names.
Each chunk needs an exact offset,length,SHA256 and stable chunk key. Existing64KiB
nonfinal minimum,8MiB maximum and4096-chunk bounds remain;new admission obeys the
configured file/storage limits. Complete independently checks the exact staged
bytes and current destination authority and intake policy. Configured checks can
keep a completed artifact held. Receiving,forwarding and execution need their own
permissions and operations.

Mutation replies say `observation: original-command-receipt` and `current_state:
not-checked`, including exact-key retries. A later status returns current ticket
metadata; it does not turn the old creation receipt into current progress.
`artifact_availability: not-checked`, receiver persistence and business processing
stay separate from ticket completion. Use ordinary source review before offering
an accepted revision. Uncertain calls must recover the original operation/key;
these tools do not silently retry under a new key or start autonomous workers.
Actual PostgreSQL/HTTPS/official-client confined byte continuation,replay,
independent download,foreign actor/overwrite/revocation refusal and durable
cardinality proofs are prepared,not qualified. See
[F116](../qualification/evidence/F116-mcp-resumable-artifact-ingress.json).

Preparation returns `state: metadata-review-only` and `storage_verification:
not-checked`. It writes no event, view, receipt or reservation, and returns no
exchange/event identity. It is not an approval or persistence promise. Actual
offering independently repeats live metadata authorization, verifies complete
physical bytes and commits the original service transaction. A changed request
hash refuses; identical-key retry recovers the original offer. A new request under
an old key conflicts. Do not interpret an uncertain tool response as no effect;
recover the same operation before deciding whether another action is safe.

The retrieval descriptor is metadata, not a bearer link. Resolve its relative path
only against the client's already configured freightctl HTTPS origin, authenticate
there again and independently verify full length and SHA256 before accepting a
complete artifact. Download rechecks live authority and holds. It creates no
inline model-content disclosure permission. A host choosing to give contents to a
model must have a separately configured disclosure policy and explicit content
approval; the current tool profile supplies no content-inlining mode. Never
forward a freightctl credential to a returned or artifact-suggested external URL.

Receiving supplies neither ordinary source access nor delivery/execution rights.
A reply needs its own authorized artifact, endpoint and sender grant. Correlation
with an old exchange adds no permission. Availability, retrieval, receiver
persistence and business processing remain separate facts; absent stronger
receiver evidence stays `unknown`.

Control envelopes are at most32KiB, depth16 and8192 inspected tokens. They refuse
batches, repeated/case-folded aliases, null values, lossy IDs, trailing data and
unknown argument fields. Ordinary16KiB request/24KiB endpoint/4KiB closure and
existing queue/read/admission controls keep their meanings. The shared API admits
at most eight concurrent requests; each tool runs under the originating HTTP
cancellation and a10second action deadline, inside a15second request deadline.
There is no tool loop,shell,database console,arbitrary filesystem/network tool,
model runtime or sampling callback. This interface starts no autonomous worker or
separate queue;onward intents use ordinary PostgreSQL coordination and explicit
workers.

Local proof covers strict wire/schema/authority-argument guards and compilation.
Prepared actual PostgreSQL proof checks preview creates no durable objects; the
original HTTPS fixture gains an official SDK client profile for polling, exact
same-key replay, wrong-scope/role refusals, independent HTTPS byte observation,
separately approved reply, cancellation and honest history. Native runtime,
actual socket-loss/process-death recovery and independent non-SDK conformance
remain owed. Additional partner/workflow/diagnostic/recovery tools beyond the
[reviewed onward profile](artifact-onward.md) and the remaining GOAL13/14 work remain open.

Protocol references: [versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
The pinned SDK's original licensing-transition notice is retained in
[third_party/mcp-go-sdk](../../third_party/mcp-go-sdk/UPSTREAM.json). Full final-source
SBOM, dependency security, redistribution and disconnected-bundle proof remain owed.


F191 implementation is Catalog38/`exchange-tools-v17`:the unchanged closed
`output_policy` reference may select v3 composed-source metadata. It names an
exact owned completed producer acceptance and does not inherit approval or
execution. A second task requires its own ordinary human approval;no approval
tool is added. Stock-client runtime proof with the receive adapter disabled is
prepared/compiled only. F187's original v16 evidence remains historical.
