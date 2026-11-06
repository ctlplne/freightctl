# Authorized exchange evidence

The frozen `authorized-exchange-evidence-v1` read profile groups existing custody,
offer and terminal-decision records. It creates no event,receipt,grant,reservation,
run or intent and reads no artifact bytes. It is a view of recorded facts,not an
independent tamper-evidence or receiver-processing contract.

The ordinary authenticated API takes `POST exchange-traces/previews` under the
existing tenant/partner prefix. Cookie callers retain ordinary same-origin/CSRF
checks. The bounded strict control body has only `exchange_id` and `direction`,
where direction is `incoming` or `outgoing`. The matching CLI is `exchange-trace
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
`reply_to` is only an already visible reply reference;this read does not follow
it or assert byte derivation. Names,paths,transport secrets,raw event payloads
and unrelated participants' receipts are excluded.

Current metadata state and its observation time stay separate from immutable
records. Physical storage verification is `not-checked`;retrieval,receiver
persistence and business processing remain `unknown`. Receiving or reading this
evidence supplies no forwarding,execution,source-read or stronger receipt right.
Original shared-service/native proofs and every full AX profile remain required.
