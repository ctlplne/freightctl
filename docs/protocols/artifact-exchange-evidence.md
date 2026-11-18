# Authorized exchange evidence

The frozen `authorized-exchange-evidence-v1` read profile groups existing custody,
offer and terminal-decision records. It creates no event,receipt,grant,reservation,
run or intent and reads no artifact bytes. It is a view of recorded facts,not an
independent tamper-evidence or receiver-processing contract.

The ordinary authenticated API takes `POST exchange-traces/previews` under the
existing tenant/partner prefix. Cookie callers retain ordinary same-origin/CSRF
checks. The bounded control body requires `exchange_id` and `direction`, where
direction is `incoming` or `outgoing`. `profile` is optional. The matching CLI is `exchange-trace
-request-file` and the agent tool is `freightctl.exchange_trace`;both delegate to
the same read service and ordinary current identity.

Incoming evidence requires the existing incoming-view authorization. A held
opaque view stays opaque: no artifact,source event,offer time or reply link is
disclosed. Revoked,expired,closed,wrong-scope and unrelated views keep ordinary
refusals. Outgoing evidence requires the existing original sender-receipt checks;
an authorized sender can inspect its historical offer and terminal decision even
when the recipient can no longer retrieve it. Direction is an explicit selector,
never a permission fallback.

Detailed results bind tenant,partner,exchange,request hash and exact artifact.
They expose only the authorized source acceptance event/time,offer event/time
and optional recorded closure event/time. Each timestamp is the recorded database
value;the sequence expresses causal links,not a monotonic-clock guarantee.
`reply_to` is an already visible reply reference with no traversal. Names,paths,transport secrets,raw event payloads
and unrelated participants' receipts are excluded.

Set `profile` to `authorized-exchange-evidence-v2` in the API body, CLI request
file or agent tool arguments to request record projection lineage. The same
selector works in the CLI evidence export request. Omitting `profile` selects
frozen v1.

V2 adds `record_projection` when the original sender also owns the completed
projection under the same authority revision and namespace root and can
currently read its exact input through ordinary file permissions. The output
acceptance links to that projection's private slot, and the reviewed input
tuple links to the original input acceptance event. V2 can return that input
tuple, the projection ID and definition hash, and the completion event and
time. If the input is held, outside current access, or no verified edge is
available, the field is absent. Incoming evidence never discloses this edge.
Each trace covers one direct input revision. Definition contents, check reports,
paths and storage references stay private.

Select `authorized-exchange-evidence-v3` to include the exact
`recipient-sha256-report-v1` receipt once the recipient has committed one. The
browser's **Read recorded evidence** action selects v3. The same profile works
in the API preview, native CLI, explicit CLI export and MCP tool. V3 retains the
v2 sender lineage rule. A recipient needs the live receive grant, and the
original sender can inspect the receipt in authorized history after closure.
Held incoming views stay opaque.

The nested report binds the same exchange, request hash and artifact. It carries
the eligible read authorization ID and the report's own event and time. The
report records the recipient's statement about length and SHA-256. Receiver
persistence and business processing stay unknown.

Current metadata state and its observation time stay separate from immutable
records. Physical storage verification is `not-checked`;retrieval,receiver
persistence and business processing remain `unknown`. Receiving or reading this
evidence supplies no forwarding,execution,source-read or stronger receipt right.
Original shared-service/native proofs and every full AX profile remain required.
