import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";

export interface ExchangeRequest {
  schema_version: 1;
  artifact: {
    file_revision_id: string;
    size_bytes: number;
    sha256: string;
    acceptance_policy: string;
  };
  endpoint: { id: string; revision: number; hash: string };
  expires_at: string;
  receipt: "availability-only-v1";
  reply_to?: string;
}
export interface ArtifactExchange {
  id: string;
  sender_actor_id: string;
  recipient_actor_id: string;
  request: ExchangeRequest;
  request_hash: string;
  event_id: string;
}
export type IncomingExchange =
  | { id: string; state: "held" }
  | { id: string; state: "offered"; exchange: ArtifactExchange };
export interface ExchangeIdentity {
  tenant: string;
  partner: string;
  actor: string;
}
export interface IncomingContext extends ExchangeIdentity {
  endpoint?: string;
  id?: string;
}
export interface PageContext extends ExchangeIdentity {
  endpoint: string;
  after: string;
  limit: number;
}
export interface IncomingPage {
  exchanges: IncomingExchange[];
  next: string;
}

function refuse(): never {
  throw new ApiError("invalid_server_response", 502);
}
function fields(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    refuse();
  return o;
}
function identifier(value: unknown): string {
  if (typeof value !== "string" || !uuid(value)) refuse();
  return value;
}
function hash(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) refuse();
  return value;
}
function integer(value: unknown, minimum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum
  )
    refuse();
  return value;
}
function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string") refuse();
  const match =
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,6}))?Z$/.exec(value);
  if (!match || match[2]?.endsWith("0")) refuse();
  const base = match[1]!;
  const time = Date.parse(base + "Z");
  if (
    !Number.isFinite(time) ||
    new Date(time).toISOString().slice(0, 19) !== base
  )
    refuse();
  return value;
}
export function asExchangeRequest(value: unknown): ExchangeRequest {
  const o = fields(
    value,
    ["schema_version", "artifact", "endpoint", "expires_at", "receipt"],
    ["reply_to"],
  );
  const a = fields(o.artifact, [
    "file_revision_id",
    "size_bytes",
    "sha256",
    "acceptance_policy",
  ]);
  const e = fields(o.endpoint, ["id", "revision", "hash"]);
  if (
    o.schema_version !== 1 ||
    o.receipt !== "availability-only-v1" ||
    typeof a.acceptance_policy !== "string" ||
    !/^(?:integrity-only-v1|intake-csv-v1:[0-9a-f]{64})$/.test(
      a.acceptance_policy,
    )
  )
    refuse();
  return {
    schema_version: 1,
    artifact: {
      file_revision_id: identifier(a.file_revision_id),
      size_bytes: integer(a.size_bytes, 0),
      sha256: hash(a.sha256),
      acceptance_policy: a.acceptance_policy,
    },
    endpoint: {
      id: identifier(e.id),
      revision: integer(e.revision, 1),
      hash: hash(e.hash),
    },
    expires_at: canonicalTimestamp(o.expires_at),
    receipt: "availability-only-v1",
    ...(o.reply_to !== undefined ? { reply_to: identifier(o.reply_to) } : {}),
  };
}
export function exchangeRequestBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(asExchangeRequest(value)));
}
export function exchangeRequestHash(value: unknown): string {
  return digestBytes(exchangeRequestBytes(value));
}
export function asIncomingView(
  value: unknown,
  context: IncomingContext,
): IncomingExchange {
  identifier(context.tenant);
  identifier(context.partner);
  identifier(context.actor);
  const o = fields(value, ["id", "state"], ["exchange"]);
  const id = identifier(o.id);
  if (context.id !== undefined && context.id !== id) refuse();
  if (o.state === "held") {
    if (Object.hasOwn(o, "exchange")) refuse();
    return { id, state: "held" };
  }
  if (o.state !== "offered") refuse();
  const e = fields(o.exchange, [
    "id",
    "sender_actor_id",
    "recipient_actor_id",
    "request",
    "request_hash",
    "event_id",
  ]);
  const request = asExchangeRequest(e.request);
  const recipient = identifier(e.recipient_actor_id);
  if (
    identifier(e.id) !== id ||
    recipient !== context.actor ||
    hash(e.request_hash) !== exchangeRequestHash(request) ||
    (context.endpoint !== undefined && request.endpoint.id !== context.endpoint)
  )
    refuse();
  return {
    id,
    state: "offered",
    exchange: {
      id,
      sender_actor_id: identifier(e.sender_actor_id),
      recipient_actor_id: recipient,
      request,
      request_hash: hash(e.request_hash),
      event_id: identifier(e.event_id),
    },
  };
}
export function asIncomingPage(
  value: unknown,
  context: PageContext,
): IncomingPage {
  identifier(context.endpoint);
  if (context.after !== "") identifier(context.after);
  if (
    !Number.isInteger(context.limit) ||
    context.limit < 1 ||
    context.limit > 100
  )
    refuse();
  const o = fields(value, ["exchanges"], ["next"]);
  if (!Array.isArray(o.exchanges) || o.exchanges.length > context.limit)
    refuse();
  const rows = o.exchanges.map((v) => asIncomingView(v, context));
  if (
    rows.some(
      (r, i) => r.id <= context.after || (i > 0 && r.id <= rows[i - 1]!.id),
    )
  )
    refuse();
  const next = Object.hasOwn(o, "next") ? identifier(o.next) : "";
  if (next && (rows.length !== context.limit || next !== rows.at(-1)?.id))
    refuse();
  return { exchanges: rows, next };
}
