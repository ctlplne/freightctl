# Artifact receive views

A receive view gives one participant permission to retrieve one exact custody
revision. The server checks the sender, recipient, source permissions, endpoint,
current intake policy and storage identity before opening bytes and on every
bounded read. Registering an endpoint and publishing a view are separate actions.

This describes implemented API code. Actual native/served qualification is owed
in F081–F083. The [wire contract](../api/artifact-exchange.openapi.json) describes
these seven paths using [OpenAPI 3.1.0](https://spec.openapis.org/oas/v3.1.0.html).
It is a subset of the product API; independent schema validation remains owed.

## Configure and authenticate

`freightctl serve` enables the adapter by default with these deployment controls:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-exchange-enabled` | `true` | Setting false leaves ordinary custody routes available and makes exchange routes refuse. |
| `-exchange-max-lifetime` | `24h` | New-view lifetime limit, in positive whole seconds. |
| `-exchange-max-senders` | `16` | Explicit senders per endpoint; structural maximum 128 and 16 KiB definition bound apply. |
| `-exchange-max-open-views` | `128` | Unexpired views per sender, including unavailable views; maximum 10000. |
| `-exchange-max-endpoints` | `1000` | Registered endpoint IDs per partner, including revoked history; maximum 10000. |

These limits do not grant permissions. File, storage, request, TLS and browser
limits keep their existing meanings. An embedded custody service must supply
explicit `ExchangeSettings`; zero settings leave the adapter unavailable.

Use ordinary provisioned credentials through verified HTTPS. Bearer callers send
the actual credential, not its stored digest. Keep transport credentials in
protected references. Browser mutations use the existing secure session cookie,
exact same origin and CSRF token. An explicit bearer header never falls back to a
cookie identity. The optional Trust Control profile remains unpinned under X07;
these routes do not assume its API or credential format.

## Perform an exchange

All paths below start with `/v1/tenants/{tenant}/partners/{partner}`. Those
selectors must match the authenticated identity; they are not permission grants.

1. Obtain each participant's current bindings from `GET /identity`: tenant,
   partner, actor, authority revision and namespace-root digest. A participant
   can be a software agent, application, person or system.
   `GET /exchange-endpoints` lists currently visible heads; `GET
   /exchange-endpoints/{endpoint}` inspects one. Old visible journal versions do
   not become directory entries. These reads grant no exchange or byte access.
2. Accept the source through the existing file/upload/namespace interfaces.
   Required checks and release must pass for the exact revision. Receive views
   require the current intake policy. A changed policy can hold an existing view;
   recovery can require a newly checked revision and a new view.
   `GET exchange-sources/{file}` reviews its exact metadata with read/deliver,
   namespace and current intake authorization. It grants no publication or bytes;
   offer creation independently checks the same source path and exact storage.
3. A root account manager posts `exchange-endpoints/commands` with an exact
   recipient and allowed sender bindings. `create`, `replace` and `revoke` use
   expected revisions and an idempotency key. Registration returns the approved
   endpoint ID, revision and definition hash.
4. The sender posts `exchanges`, binding the exact file ID, length, SHA256 and
   original acceptance policy; approved endpoint reference; expiry; and
   `availability-only-v1` receipt. Read and delivery permission are both required.
   The original source path permission remains a live dependency of the view.
5. The recipient polls `exchange-endpoints/{endpoint}/incoming`, then inspects
   `exchanges/{exchange}` or retrieves `exchanges/{exchange}/file`. Poll pages have
   at most 100 entries. Finish a pagination cycle with `next`, then start each new
   cycle without a cursor. A cursor is not a permanent new-arrival checkpoint.
6. A reply is a new request, with separately authorized delivery and readable
   source bytes. `reply_to` links the original exchange; it grants no source,
   recipient, forwarding or execution right. Receiving a view does not add
   ordinary namespace/file access. Source access for any onward handoff needs its
   own authorization through existing permissions and publication controls.
7. `POST exchange-closures` withdraws one exact view. Its command is
   `{"schema_version":1,"exchange_id":"UUID","request_hash":"ORIGINAL_SHA256","operation":"cancel"}`
   for the sender, or `operation: "decline"` for the recipient. Use an original
   `Idempotency-Key`; the body is at most4096 bytes. The actor must still match
   its original participant binding, with the role's read/deliver or read/list
   permissions. A hold, expired offer or revoked endpoint does not prevent the
   unchanged participant from closing its own view. The API returns the exact
   decision's ID,state,canonical command hash,event ID and replay flag.

JSON bodies reject unknown fields, duplicate/case-folded aliases and nulls.
Endpoint commands are at most 24 KiB; offer requests are at most 16 KiB. Expiry
must identify an exact microsecond instant. Equivalent offsets and trailing
fractional zeroes normalize to UTC; precision that would be truncated refuses.

## Interpret outcomes

An offer returns 201 when its view and command receipt commit together. An
identical-key replay returns 200 with the original result. Changed meaning under
that key refuses. A historical receipt cannot reactivate a revoked view. Senders
recover publication receipts through their original submission key; the current
inspection route is recipient-only and does not provide outgoing history.

Discovery returns offered metadata only under current authority. Held entries
contain only a view ID and fixed state. A byte response identifies the immutable
revision and its full SHA256, including on a partial range response. A recipient
must verify complete length and digest before treating interrupted output as a
complete artifact. The download filename is the static `artifact`.

Reads remain at most 256 KiB and reauthorize within a 10 second deadline. Source
path restrictions, identity rotation/revocation, endpoint changes, policy holds
and storage changes refuse later reads. The recorded retrieval evidence means
only `read-authorized-only`. Availability, byte retrieval, receiver persistence
and business processing are distinct outcomes. No processing outcome is inferred
from a download or reply.

Cancellation/decline commits an immutable decision,event and actor-private retry
receipt in one transaction. Only the first terminal decision succeeds; a changed
command under its original key refuses. The original offer receipt survives and
cannot reopen bytes. Each bounded read holds a shared view lock; closing takes
the exclusive lock. An earlier authorized chunk may finish before closing commits;
no later chunk is authorized. Closed views disappear from live incoming lists and
return404 to recipient inspection/retrieval. Source bytes and other views remain
under their own permissions. Ordinary event feeds/audit exports retain the closure
event identity and exact payload digest, keeping its operation key and private
participant bindings in the protected journal.

API/CLI closure, offered-view browser decline,reviewed browser sending and
[sender history](artifact-exchange-outgoing.md) are implemented. Agent tools,
browser endpoint administration and the complete OpenAPI surface remain
implementation work. Actual stock-client,
independent-receiver, crash/recovery, capacity and AX profile proofs remain owed.
