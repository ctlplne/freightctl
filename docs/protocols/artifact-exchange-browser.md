# Receive artifacts in the browser

Connect with the ordinary workspace and account credential, then choose
**Receive artifacts**. This account needs read and list permission. Open the
approved endpoint ID from its registration receipt. The ID supplies a selector;
the server still decides whether this account may discover or retrieve anything.

The page shows only currently authorized receive views. **Inspect** refreshes one
view and displays its immutable revision, complete length, SHA-256, original
acceptance policy and expiry. A held view shows only its ID and fixed state.
**Download artifact** uses the ordinary browser attachment path. Payload bytes
are not buffered or executed by the application’s JavaScript. Compare complete
length and digest before treating interrupted output as a complete artifact.

**Next receive page** continues this polling cycle. **Check for new artifacts**
starts at the beginning, so an artifact with an earlier random ID cannot be lost
behind an old cursor. There is no background polling loop. Changing the endpoint
or workspace aborts pending reads and clears prior metadata. Changing authority,
policy or endpoint state can refuse the next read, including an already-open
download. Previously received bytes remain the recipient’s copy.

Availability at the last check, retrieval, receiver persistence and business
processing are separate facts. A received artifact grants no forwarding or
execution right. Use the ordinary API or CLI for a separately authorized reply;
browser sending, endpoint administration and outgoing history remain work.

The dedicated GitHub browser profile uses actual loopback HTTPS, PostgreSQL,
custody, ordinary participant cookies and sandboxed Chrome. It prepares exact
malicious-but-inert byte retrieval, unrelated-user metadata denial, actual manager
revocation, stale-screen removal and four automated accessibility states. Only
parser/client stand-ins, canonical Go/JavaScript bytes, syntax/build checks and
integration compilation have run locally. Actual served/browser and complete AX
qualification remain owed; automated accessibility does not replace manual WCAG
qualification. No local browser, database, scanner or inference runtime is started.
