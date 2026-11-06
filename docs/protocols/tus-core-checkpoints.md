# tus core checkpoint profile

`tus-core-checkpoint-v1` resumes an existing ordinary freightctl upload ticket
through the tus1.0 core wire protocol. Create the exact path/length/SHA256 ticket
with the existing API,CLI or agent tool first. This adapter never creates another
ticket or grants write permission from a URL. The configured origin plus
`/v1/tenants/{tenant}/partners/{partner}/tus/uploads/{upload}` identifies it.

The [tus1.0 specification](https://tus.io/protocols/resumable-upload) defines
version negotiation,HEAD offsets,PATCH offsets and method override. This profile
implements core resume only;no creation,checksum,expiration,termination,deferred
length or concatenation extension is advertised. In particular,advertising the
checksum extension would require SHA1 support;this profile keeps existing SHA256
custody instead. No generic tus extension compatibility is claimed.

Requests need current ordinary authentication and the original ticket's actor,
root and authority binding. Browser cookies retain same-origin/CSRF checks,
including method overrides. HEAD returns current offset/length with no-store;
PATCH requires the exact current offset and a bounded body;known-length and
chunked HTTP framing both retain that bound. The
existing64KiB nonfinal minimum,8MiB chunk maximum,4096-checkpoint and configured
file/storage allowances remain. The ordinary upload transaction checks strict
offsets under its lock before accepting any bytes. Conflict changes no checkpoint.

The adapter hashes its bounded received chunk and invokes the unchanged durable
checkpoint service. It does not claim a sender-declared per-chunk checksum.
The original whole-file SHA256 remains mandatory and is independently verified
by ordinary completion. Partial/request-body data never becomes an artifact.
Offset completion means durable checkpoints only. Explicit ordinary completion
and current intake checks still precede accepted/published artifact bytes.

Use tus-js-client4.3.1's documented
[`uploadUrl`](https://github.com/tus/tus-js-client/blob/v4.3.1/docs/api.md#uploadurl)
with the existing resource and a suitable `chunkSize`. Omit a creation endpoint;
the qualified client must fail instead of silently minting a new ticket. Stock
client version,package integrity,TLS verification and original/native byte,
response-loss,resume,offset,credential-expiry and revocation proofs remain owed.
The dedicated GitHub workflow executes the locked client on actual Linux ARM
and x86 with real PostgreSQL and verified loopback TLS. It drops an actual
committed response,requires HEAD recovery and tests both PATCH and stock method
override;ordinary completion and an independent HTTPS byte read follow. The
source commit,client/lock/result hashes bind its safe output. No native outcome
is established by local parser tests or compilation.
Expiry here is current credential authority;no independent upload-lifetime or
automatic cleanup claim is made. Receiving/uploading grants no forwarding or
execution authority. Inference stays off.
