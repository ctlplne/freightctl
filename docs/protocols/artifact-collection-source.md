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
catalog now has18tools;inference remains off.

For a published input,the browser's **Review collected artifact** action reads
this fresh source/correlation,checks it against the selected exact input,then
opens the ordinary Send artifacts form with a pinned ID,length and digest.
That form requires a fresh source check and an explicitly approved receive
endpoint before an offer can be confirmed. The navigation itself creates none.
Held,unpublished or incomplete input snapshots show no review action.

The governed-source profiles cover both SFTP and FTPS ready manifests. The
stock SFTP profile uses this source review and a separately authorized custody
HTTPS poll offer. Its full stock-source, API, MCP, browser and recovery proof
remains due.

The FTPS profile uses explicit AUTH TLS or implicit FTPS from a separately
provisioned freightctl producer. A collector reads the ready manifest and pins
each file's digest. The ordinary CLI reviews the captured, owner-only revision.
A separately enrolled recipient polls a pinned HTTPS view with stock curl and
checks the exact bytes. It may create a new owner-only custody copy through the
CLI under an explicit write grant. To send the copy onward, an operator must
provision the actor's pinned SFTP connection. The local replay removed the
temporary provisioning grants before the agent approved and executed its own
workflow. A stock OpenSSH receiver and stock SFTP client verify the output.
The receipt retains unknown business acceptance. [F503 replay](../qualification/evidence/F503-ftps-agent-stock-sftp.json)

The same journey now supports [operator provisioning](operator-connection-provisioning.md)
without granting the agent administrative or connection-management privileges.
The operator can withdraw the exact assigned route and stop queued work before
receiver contact.

Independent FTPS server interoperability, the native Linux matrix, the full
SFTP pair, additional actor and transport pairs, process-death recovery and
restore remain open.
