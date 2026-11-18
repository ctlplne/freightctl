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
derives the actor and scope from the caller's authenticated credential.
Inference stays off.

For a published input,the browser's **Review collected artifact** action reads
this fresh source/correlation,checks it against the selected exact input,then
opens the ordinary Send artifacts form with a pinned ID,length and digest.
That form requires a fresh source check and an explicitly approved receive
endpoint before an offer can be confirmed. The navigation itself creates none.
Held,unpublished or incomplete input snapshots show no review action.

The governed-source profiles cover both SFTP and FTPS ready manifests. In
the stock SFTP replay, a read-only OpenSSH producer served the ready manifest
and exact payload in one authenticated session. The agent received a separately
authorized HTTPS view and created a new custody copy. A second OpenSSH daemon
received the approved onward delivery. A stock SFTP write using the producer
credential was refused, and both producer files stayed unchanged.
[F516 replay](../qualification/evidence/F516-stock-sftp-source-agent-exchange.json)

Stock curl now drives that journey through the documented HTTPS routes. It
previews, queues and captures the collection, enrolls the receive endpoint,
offers the exact revision, creates the recipient-owned copy and opens the
approved onward run. The sender gets the same source metadata from HTTP and
the CLI. The agent recovers the HTTP copy receipt with the same key in the CLI
after its receive view closes. Reusing the copy key with a different path
fails. Withdrawing the assigned SFTP route blocks an already queued HTTPS work
request before it contacts the receiver. These assertions pass with stock SFTP
and with both FTPS producers. Native Linux and process-death recovery remain
open.
[F517 replay](../qualification/evidence/F517-stock-collection-https-exchange.json)

After capture and endpoint enrollment, an MCP caller can review the exact
source with `freightctl.collection_source`, prepare an offer with
`freightctl.prepare_exchange`, then submit it with `freightctl.offer_exchange`
using the returned request hash. The recipient calls
`freightctl.incoming_exchanges` and `freightctl.retrieval_descriptor`, fetches
bytes through the returned authenticated HTTPS path, and calls
`freightctl.copy_received_artifact` using its own write permission. A separate
grant, registered route and approved workflow are required for
`freightctl.prepare_onward`, `freightctl.start_onward` and
`freightctl.work_onward`. `freightctl.onward_status` checks the original run
receipt and current state. The local stock SDK replay verified each step
against real PostgreSQL, stock curl and separate OpenSSH peers. Native Linux
MCP proof and the full browser exchange remain due.
[F522 replay](../qualification/evidence/F522-stock-sftp-mcp-exchange.json)

If the stock SFTP collection worker dies after sealing the bytes and before
acceptance, keep the original collection ID, definition hash and work key.
Inspect the collection state and wait for the recorded worker lease to expire.
Run `workflow-collection-work` again with that same binding. The replacement
can verify and accept the sealed object from local storage. Review the captured
source by its original input ID, then obtain the separate offer and onward
approvals as usual. The local replay uses an actual killed worker and withdraws
both producer files before retrying. The replacement makes zero new producer
connections and publishes one original object.
[F523 replay](../qualification/evidence/F523-stock-sftp-collection-worker-death.json)

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

An independent replay replaced the producer with stock Alpine vsftpd 3.0.5-r3.
Both modes rejected TLS 1.2 and required resumed TLS 1.3 data sessions. Each
producer recorded one authenticated control session and two completed downloads
in order, first the ready manifest and then its file. The producer files were
unchanged after capture, retries and onward delivery. The standalone stock
listener then exited with status 139 in both witnessed runs.
[F509 replay](../qualification/evidence/F509-stock-ftps-producer-exchange.json)

The supervised profile runs BusyBox `inetd` as the listener. Each accepted
control socket starts a separate stock vsftpd process with `listen=NO`. The
same listener survived two full journeys in each TLS mode with no container
restarts. The standalone failure remains open.
[vsftpd configuration manual](https://security.appspot.com/vsftpd/vsftpd_conf.html) [F510 replay](../qualification/evidence/F510-supervised-stock-ftps-producer.json)

The replay harness builds a read-only loopback producer from pinned Alpine
packages and runs the full exchange twice per TLS mode. Use a task-owned
PostgreSQL fixture with the two protected references produced by
`scripts/dev-db.py`. The runner also needs Docker, stock OpenSSL, curl and
OpenSSH server and client tools. Run as an unprivileged user.

```sh
FREIGHTCTL_TEST_ADMIN_FILE="$PWD/.private/pg-admin.dsn" \
FREIGHTCTL_TEST_RUNTIME_FILE="$PWD/.private/pg-runtime.dsn" \
  python3 scripts/qualify-stock-ftps-producer.py
```

The harness reads the producer's own completion log and final file tree. It
prints a summary with artifact hashes and keeps raw logs in a private
workspace directory. The registered connection reads `/inbox` on the producer.
The collection definition uses `/` as its local custody directory.
[F513 harness evidence](../qualification/evidence/F513-native-stock-ftps-producer-harness.json)

The native Linux freightctl runtime matrix, additional actor and transport pairs,
process-death recovery and restore remain open.
