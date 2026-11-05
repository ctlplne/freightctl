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
**Save offer recovery file** preserves the exact request, approved endpoint
snapshot, source/account bindings and retry keys as compact JSON. Save it in a
protected location before leaving or reloading. After reconnecting to the same
HTTPS origin with the same account authority/root, choose **Saved offer recovery
file (optional)**. Import only fills an explicitly labeled saved review; it
contacts no endpoint, executes no action and confirms no result. Review it before
retrying. The server still checks ordinary authority and same-key request meaning.

The file's expected exchange ID is a selector, not proof of acceptance. A receipt
is displayed only after the actual server returns the matching canonical request
and expected ID. A saved withdrawal key can recover the original terminal receipt
after the offer receipt is recovered. Endpoint changes, expiry or holds do not
turn a historical publication receipt into new byte permission. Credentials or
scope that no longer match the original participant cannot adopt the review.

Recovery files are untrusted control input at most24KiB,depth8,tokens4096. The
parser rejects duplicate/case-folded/escaped field aliases, nulls, unknown fields,
unsafe or nonliteral integers, trailing input, foreign origins and mismatched
canonical hashes/bindings. The24KiB envelope covers saved metadata; artifact bytes
use the deployment's configured capacity. The format grants no authority or signature
claim. Outgoing history and complete process-death/restore qualification remain
work. Canonical JSON integers must fit exactly
in the browser's safe integer range; API/CLI retain their explicit integer64
contract. No file is silently rounded.

The native GitHub Chrome profile prepares actual sender review/offer/withdrawal,
independent recipient404 after withdrawal, source and endpoint review, exact
existing byte retrieval, recipient decline and manager revocation. Eight
automated accessibility states plus a saved-review state are required,for nine.
It saves the actual recovery download,reloads the page,imports without a POST,
and requires exact original offer/withdrawal keys,bodies and server receipts on
replay. PostgreSQL view/receipt/decision counts must not increase. Original
revocation proof checks a live grant immediately before revoking,so expiry cannot
produce a false pass. S004 leaves aggregate runtime to GitHub's platform lifetime;
individual API/DB/read/browser-interaction deadlines remain bounded.
Local parser/adapter, type/build and
compilation results are stand-in/static proof only. Actual served browser and
complete AX qualification remain owed; local inference stays off.
