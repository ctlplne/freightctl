# Sent artifact history

Choose **Sent artifacts** with an account that has read,deliver and list permission.
**Check sent artifacts** starts a fresh page cycle; **Next sent page** continues
that cycle. **Inspect sent** rereads one record under current authorization.

The history combines an immutable offer receipt with a current metadata check.
Only the original sender with its original still-current authority/root binding
and current source-file permission can see the record. Receiving a view, managing
accounts or knowing its ID does not grant sender-history access. Credential/root
rebinding or source path/mode loss hides affected records and their cursors.
An admission setting for new endpoint definitions does not hide or revoke an
unchanged stored definition. New definitions still obey that setting; head
replacement/revocation, current participant stamps, source permission, policy and
expiry still govern every use. Stored definitions retain their original strict
structure, hash and size checks.
Enumerating pages additionally requires `list`; inspecting a known own exchange
ID uses read/deliver plus its original binding and current source authorization.

States describe metadata at the server's `checked_at` instant:

| State | Meaning |
| --- | --- |
| `offered` | Current metadata checks allow the original view. Physical bytes and live authority are checked again on retrieval. |
| `held` | Current source checks or intake policy withhold this view. |
| `unavailable` | The original endpoint or participant dependencies no longer make the view current. No replacement recipient or private failure details are disclosed. |
| `expired` | Its original expiry is at or before the server check. |
| `canceled` | The sender recorded an immutable withdrawal; its exact decision event is shown. |
| `declined` | The recipient recorded an immutable decline; its exact decision event is shown. |

Terminal decisions remain facts after expiry or policy changes. Original request,
source revision/length/digest/policy, recipient, endpoint revision/hash and offer
event remain historical facts. The current source permission is checked before
disclosure even when the original endpoint is revoked. Retrieval, receiver
persistence and business processing remain `unknown`; this custody-poll adapter
does not infer them from an offer, notification, read authorization or reply.
No storage identity, private operation key, current replacement endpoint or
artifact content is returned. History reads do not create retrieval events.

Under `/v1/tenants/{tenant}/partners/{partner}`, `GET outgoing-exchanges` accepts
optional `after` and `limit` (1–100); `GET outgoing-exchanges/{exchange}` inspects
one record. Current principal/source filters run before choosing IDs and cursors.
Every selected row, including the extra pagination row, is checked under the
view/endpoint/namespace locks before returning a page. A race refuses the whole
affected page. Tenant/partner, sender, scope, canonical request, decision binding,
exact UTC microsecond expiry and explicit unknown outcomes are checked by the UI.

The CLI uses `exchange-outgoing` with optional `--exchange-after` and
`--exchange-limit`, or `exchange-outgoing-inspect --exchange-id UUID`, through
the same store services. Use ordinary protected account/runtime-DSN references;
no custody storage reference is needed for metadata. These reads do not grant
retrieval or forwarding permission.

Focused handler/domain/client checks and static/native compilation are local
proof only. Real PostgreSQL pagination/role/scope/mode/authority/hold/closure and
admission-change cases, original HTTPS/CLI profiles and eleven-state actual Chrome
proof are prepared. Runtime qualification and all affected original journeys
remain owed. No local PostgreSQL, browser, scanner or inference runtime is started.
Append-only migration44 adds a tenant/partner/sender/UUID seek index for the page
query. It changes no historical row,grant,event,receipt or forced-RLS table.
Fresh/native upgrade/restore and query-plan/capacity proof remain owed; adding the
source migration does not upgrade the retained database.
