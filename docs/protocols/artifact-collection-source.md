# Collected artifact source review

The [OpenAPI subset](../api/artifact-collection-source.openapi.json) pins the
implemented response. External schema/client conformance is still owed.

`governed-collection-exchange-source-v1` connects an already captured governed
SFTP/FTPS input to ordinary artifact source review. It starts no source pull,
offer,run,transfer or worker. Receiving an artifact supplies no permission here.
The same current ordinary source/path/intake guards used by artifact sending
apply;collection metadata alone supplies no delivery or execution permission.

`GET /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/inputs/{input}/exchange-source`
requires the ordinary actor-private collection metadata role plus read and
deliver. Collection/input IDs are exact scoped UUIDs. In one transaction,the
service checks the complete captured manifest,ordered immutable input tuples,
input identity digests and accepted object/file bindings. It then independently
authorizes the selected current ordinary source and compares its revision,length
and SHA256 before returning metadata. The transaction rolls back without events,
receipts,intents or reservations. Physical bytes remain `not-checked` until the
ordinary offer/transfer service performs its own complete checks.

The response contains the exact artifact tuple/current intake policy and an
origin correlation:collection ID/definition hash,workflow reference,producer
batch/manifest hash,input ID/identity and first collection ID. Deduplication keeps
the original input/first-job identity. No source host,path,transport secret,
namespace/storage reference,private source name or inline bytes are returned.
This proves an exact captured-revision correlation when actually qualified;it
does not prove content derivation,receiver persistence or business processing.

An unfinished batch,held source,changed integrity tuple,unavailable namespace or
foreign actor cannot become a new sending source through this review. Stopping
or expiring an old collection does not recall already captured ordinary bytes.
Their new use still requires current source permissions and a separately
authorized offer or approved onward workflow. Existing collection routing and
run assignments are preserved;this interface cannot adopt or replay them.

The protected-reference CLI command is `workflow-collection-exchange-source`
with `--collection-id` and `--collection-input-id`. The read-only MCP tool is
`freightctl.collection_source` with those two IDs. It uses the same service and
has no actor,scope,address,approval,content or execution argument. The modern
catalog now has17tools;inference remains off.

For a published input,the browser's **Review collected artifact** action reads
this fresh source/correlation,checks it against the selected exact input,then
opens the ordinary Send artifacts form with a pinned ID,length and digest.
That form requires a fresh source check and an explicitly approved receive
endpoint before an offer can be confirmed. The navigation itself creates none.
Held,unpublished or incomplete input snapshots show no review action.

The first governed-source adapter pair is frozen as stock SFTP ready-manifest
collection -> this source review -> separately authorized custody HTTPS poll
offer. Original stock-source/API/CLI/modern-MCP/browser and real PG incomplete-
batch/private-input/no-effect profiles are extended. Focused pure checks and
native compilation do not qualify these runtime outcomes. Complete two-agent
onward/independent receiver,FTPS source pair,process-death/restore and all remaining
AX/baseline acceptance remain owed. No schema or retained environment change.
