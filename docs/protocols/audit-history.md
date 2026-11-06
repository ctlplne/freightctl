# Operator audit history

`event-metadata-history-v1` searches immutable recorded actions in the current
tenant/partner scope. The existing root `audit_read` permission is required,
including before returning results. This is privileged operator audit access;
ordinary read/receive permission grants none of it.

`POST /v1/tenants/{tenant}/partners/{partner}/audit/history/search` uses ordinary
authentication and strict8KiB JSON. Required `limit` is1–100. Optional exact
`actor_id`, `resource_id`, up to16 literal `kinds`, and UTC `from`/`until` filter
the search. Instants have at most six fractional digits; the time interval is
inclusive at `from`, exclusive at `until`. No raw payload, content, path, credential,
request key, arbitrary SQL or authority option is accepted.

Results contain event ID,actor ID,kind,resource ID and recorded UTC time only.
They show what the service recorded; they do not prove bytes, receiver persistence
or business processing. The existing signed snapshot export remains separate.

`next` is a bounded opaque keyset pointer ordered by recorded time then event ID.
It binds normalized filters and the authenticated tenant/partner/actor,authority
revision and root digest. It is not a capability or a durable notification cursor.
Every page reauthenticates. Pages are independent observations, not one fixed
snapshot; refresh starts again. Recorded time is not a promise of causal order or
a monotonic clock. Full repeatable evidence uses the existing snapshot export.

`freightctl audit-history -request-file <protected-json>` uses ordinary protected
credential/database references and the same service. The browser's Audit history
workspace is visible only under explicit root `audit_read`; administrator,read,
receive or write permission alone does not imply it. Search is explicit,with
actor,event-type,resource and UTC range fields plus next-page navigation.

The browser pins copied normalized filters,checks scope/reader/filter/time/order
and exact last-row cursor bindings,and rejects raw payload or unknown stronger
outcome fields. It verifies the same canonical cursor format as Go using a shared
fixture. Current actor,authority,root,permissions and session are checked before,
inside and after the request. Context change hides stale rows and aborts reads.

The native operator profile adds three search states to the existing28-state
artifact/copy journey:actor/event search,next page and exact file lookup. A
separately granted audit reader must see the two original sender acceptances and
the exact original file/event binding. Ordinary recipients have no history
control. All31 accessibility states and actual PG/Chrome outcomes remain owed.

Use actual PostgreSQL and served public-interface proofs for native claims.
Parsing,source presence and compilation do not qualify operator outcomes.
