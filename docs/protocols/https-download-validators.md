# HTTPS immutable download validators

`immutable-download-validator-v1` adds a strong revision validator to the
existing Go byte-range server. It covers ordinary file-ID downloads,namespace
path downloads and authorized exchange views. Existing range and multipart
handling stays in the standard HTTP implementation.

The strong ETag binds the immutable file UUID and whole-file SHA256. Even two
revisions with equal bytes have different tags. Clients can send the observed
tag in `If-Range` while resuming. A stale or weak validator results in the full
selected representation,never an unchecked continuation into another revision.
These are the [HTTP conditional range rules](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-range).
A mutable namespace path may select a newer revision;use its returned identity
and validator before appending bytes. Prefer an exact revision URL for recovery.

ETags grant no access and do not cache permission. Ordinary current tenant,
partner,actor,root,path/file/exchange,intake and verified-storage checks precede
all serving,including HEAD,conditional304,partial206 and range416. The actual
revision reader keeps live authorization checks on bounded reads. Every status
keeps no-store,including standard-server range errors. No raw filename or host
storage path enters the tag.

`X-Content-SHA256` always describes the whole immutable artifact,not a selected
range. Independently verify the final reconstructed file against that hash and
size. A partial connection or server acknowledgement cannot prove independent
receiver persistence or business processing. Receiving grants no execution or
forwarding permission.

Local focused HTTP tests prove validator/refusal behavior only. Actual PG/TLS,
cookie/bearer,namespace replacement,exchange closure,current revocation/intake,
stock-curl interrupted/resumed bytes and final-source/native profiles remain
owed until their original journeys run in the authorized environments.
