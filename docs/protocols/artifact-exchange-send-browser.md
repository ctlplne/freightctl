# Send an artifact in the browser

An account with read and deliver permission can choose **Send artifacts**. From
**Files**, **Send artifact** fills the exact file revision. A sender can also use
the immutable file ID in its own upload receipt. An incoming view is not a source
permission; a separately authorized reply needs its own readable source.

Use **Find approved recipients**, select an active endpoint and review its
recipient account. Only a current explicit sender binding appears as eligible.
Set an exact UTC expiry ending in Z, and optionally an earlier exchange ID for
reply correlation. The server enforces the configured lifetime and admission
limits. A correlation ID supplies no permission.

**Review artifact offer** reads source metadata and the current endpoint. Review
the complete source revision, length, SHA-256, acceptance policy, recipient,
endpoint revision and expiry. Source review uses the same ordinary file and
namespace authorization as offer creation. It neither reads payload bytes nor
reserves an endpoint. **Confirm artifact offer or recover result** commits through
the ordinary HTTPS offer API, which independently checks the exact stored bytes
and all live permissions/policy/participant/endpoint dependencies again.

The receipt binds the original request hash and journal event. It promises
availability under live checks, not retrieval, receiver persistence or business
processing. **Withdraw this artifact offer or recover result** records sender
cancellation through the same closure service used by API/CLI. It closes only
that view; previous copies cannot be recalled and other offers are unchanged.

An unconfirmed attempt keeps the original request and operation key for exact
retry. A withdrawal gets its own stable key. A timeout cannot prove failure.
The current review is kept only in memory: navigating away, reloading or changing
the account loses it. Keep the page open to recover an uncertain result. Durable
review export/import and outgoing history remain work; do not treat this UI as a
complete crash/recovery qualification. Canonical JSON integers must fit exactly
in the browser's safe integer range; API/CLI retain their explicit integer64
contract. No file is silently rounded.

The native GitHub Chrome profile prepares actual sender review/offer/withdrawal,
independent recipient404 after withdrawal, source and endpoint review, exact
existing byte retrieval, recipient decline and manager revocation. Eight
automated accessibility states are required. Local parser/adapter, type/build and
compilation results are stand-in/static proof only. Actual served browser and
complete AX qualification remain owed; local inference stays off.
