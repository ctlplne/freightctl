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

export interface ExchangeClosureCommand {
  schema_version: 1;
  exchange_id: string;
  request_hash: string;
  operation: "cancel" | "decline";
}
export interface ExchangeClosureResult {
  exchange_id: string;
  state: "canceled" | "declined";
  command_hash: string;
  event_id: string;
  replayed: boolean;
}
export function exchangeClosureBytes(value: unknown): Uint8Array {
  const o = fields(value, [
    "schema_version",
    "exchange_id",
    "request_hash",
    "operation",
  ]);
  if (
    o.schema_version !== 1 ||
    (o.operation !== "cancel" && o.operation !== "decline")
  )
    refuse();
  return new TextEncoder().encode(
    JSON.stringify({
      schema_version: 1,
      exchange_id: identifier(o.exchange_id),
      request_hash: hash(o.request_hash),
      operation: o.operation,
    }),
  );
}
export function asExchangeClosureResult(
  value: unknown,
  command: ExchangeClosureCommand,
): ExchangeClosureResult {
  const expected = digestBytes(exchangeClosureBytes(command));
  const state = command.operation === "cancel" ? "canceled" : "declined";
  const o = fields(value, [
    "exchange_id",
    "state",
    "command_hash",
    "event_id",
    "replayed",
  ]);
  if (
    identifier(o.exchange_id) !== command.exchange_id ||
    hash(o.command_hash) !== expected ||
    o.state !== state ||
    typeof o.replayed !== "boolean"
  )
    refuse();
  return {
    exchange_id: command.exchange_id,
    state,
    command_hash: expected,
    event_id: identifier(o.event_id),
    replayed: o.replayed,
  };
}

export interface ExchangeBinding {
  tenant_id: string;
  partner_id: string;
  actor_id: string;
  authority_revision: number;
  root_policy_digest: string;
}
export interface EndpointDefinition {
  schema_version: 1;
  profile: "custody-https-poll-v1";
  recipient: ExchangeBinding;
  senders: ExchangeBinding[];
}
export interface EndpointRecord {
  id: string;
  revision: number;
  definition: EndpointDefinition;
  definition_hash: string;
  state: "active" | "revoked";
  recorded_by: string;
  event_id: string;
}
export interface DirectoryContext extends ExchangeIdentity {
  authority_revision: number;
  root_policy_digest: string;
  manager: boolean;
  can_receive: boolean;
  can_send: boolean;
}
export interface EndpointPage {
  endpoints: EndpointRecord[];
  next: string;
}

function binding(value: unknown, context: ExchangeIdentity): ExchangeBinding {
  const o = fields(value, [
    "tenant_id",
    "partner_id",
    "actor_id",
    "authority_revision",
    "root_policy_digest",
  ]);
  const result = {
    tenant_id: identifier(o.tenant_id),
    partner_id: identifier(o.partner_id),
    actor_id: identifier(o.actor_id),
    authority_revision: integer(o.authority_revision, 1),
    root_policy_digest: hash(o.root_policy_digest),
  };
  if (
    result.tenant_id !== context.tenant ||
    result.partner_id !== context.partner
  )
    refuse();
  return result;
}
export function asEndpointDefinition(
  value: unknown,
  context: ExchangeIdentity,
): EndpointDefinition {
  const o = fields(value, [
    "schema_version",
    "profile",
    "recipient",
    "senders",
  ]);
  if (
    o.schema_version !== 1 ||
    o.profile !== "custody-https-poll-v1" ||
    !Array.isArray(o.senders) ||
    o.senders.length < 1 ||
    o.senders.length > 128
  )
    refuse();
  const senders = o.senders.map((v) => binding(v, context));
  if (senders.some((s, i) => i > 0 && s.actor_id <= senders[i - 1]!.actor_id))
    refuse();
  return {
    schema_version: 1,
    profile: "custody-https-poll-v1",
    recipient: binding(o.recipient, context),
    senders,
  };
}
export function endpointDefinitionHash(
  value: unknown,
  context: ExchangeIdentity,
): string {
  return digestBytes(
    new TextEncoder().encode(
      JSON.stringify(asEndpointDefinition(value, context)),
    ),
  );
}
export function bindingIsCurrent(
  value: ExchangeBinding,
  context: DirectoryContext,
): boolean {
  return (
    value.tenant_id === context.tenant &&
    value.partner_id === context.partner &&
    value.actor_id === context.actor &&
    value.authority_revision === context.authority_revision &&
    value.root_policy_digest === context.root_policy_digest
  );
}
export function asEndpointRecord(
  value: unknown,
  context: DirectoryContext,
  expectedID?: string,
): EndpointRecord {
  const o = fields(value, [
    "id",
    "revision",
    "definition",
    "definition_hash",
    "state",
    "recorded_by",
    "event_id",
  ]);
  const id = identifier(o.id),
    definition = asEndpointDefinition(o.definition, context);
  if (
    (expectedID !== undefined && id !== expectedID) ||
    (o.state !== "active" && o.state !== "revoked") ||
    hash(o.definition_hash) !== endpointDefinitionHash(definition, context)
  )
    refuse();
  if (
    !context.manager &&
    !(context.can_receive && bindingIsCurrent(definition.recipient, context)) &&
    !(
      context.can_send &&
      definition.senders.some((s) => bindingIsCurrent(s, context))
    )
  )
    refuse();
  return {
    id,
    revision: integer(o.revision, 1),
    definition,
    definition_hash: hash(o.definition_hash),
    state: o.state,
    recorded_by: identifier(o.recorded_by),
    event_id: identifier(o.event_id),
  };
}
export function asEndpointPage(
  value: unknown,
  context: DirectoryContext,
  after: string,
  limit: number,
): EndpointPage {
  if (after !== "") identifier(after);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) refuse();
  const o = fields(value, ["endpoints"], ["next"]);
  if (!Array.isArray(o.endpoints) || o.endpoints.length > limit) refuse();
  const endpoints = o.endpoints.map((v) => asEndpointRecord(v, context));
  if (
    endpoints.some(
      (e, i) => e.id <= after || (i > 0 && e.id <= endpoints[i - 1]!.id),
    )
  )
    refuse();
  const next = Object.hasOwn(o, "next") ? identifier(o.next) : "";
  if (next && (endpoints.length !== limit || next !== endpoints.at(-1)?.id))
    refuse();
  return { endpoints, next };
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
