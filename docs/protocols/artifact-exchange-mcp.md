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
| `exchange_source` | Review own authorized source revision metadata. |
| `exchange_endpoints`, `exchange_endpoint` | Read visible current endpoint heads. |
| `prepare_exchange` | Check an exact proposed request against current sender/source/endpoint/participant/policy/expiry/admission metadata. |
| `offer_exchange` | Commit the ordinary exact-byte offer and private idempotency receipt. Requires the exact canonical request hash and stable request key. |
| `incoming_exchanges`, `inspect_exchange` | Poll and inspect currently authorized incoming views; held rows stay opaque. |
| `retrieval_descriptor` | Return exact integrity metadata and a relative authenticated HTTPS download path, without artifact bytes. |
| `outgoing_exchanges`, `exchange_receipt` | Inspect own original offer receipts and separately checked current state. Enumeration also needs list. |
| `close_exchange` | Record one exact sender cancellation or recipient decline using its original request hash and stable operation key. |
| `prepare_onward`, `start_onward` | Review an owned artifact/approved ordered workflow,then atomically record ordinary intents under the exact review. |
| `onward_status`, `work_onward` | Inspect or execute one ordinary step only with the original reviewed-start receipt and exact run binding. |

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
