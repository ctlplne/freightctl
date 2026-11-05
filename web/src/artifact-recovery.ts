import { ApiError, object, uuid } from "./types";
import {
  asEndpointRecord,
  asExchangeRequest,
  bindingIsCurrent,
  exchangeRequestHash,
  type DirectoryContext,
  type EndpointRecord,
  type ExchangeRequest,
  type ExchangeBinding,
} from "./artifact-exchanges-types";

export const offerRecoveryMaximum = 24 * 1024;
export interface OfferReviewInput {
  request: ExchangeRequest;
  endpoint: EndpointRecord;
  key: string;
  expected_exchange_id?: string;
  withdrawal_key?: string;
}
export interface OfferRecovery {
  schema_version: 1;
  profile: "freightctl-offer-recovery-v1";
  server_origin: string;
  participant: ExchangeBinding;
  request_key: string;
  request: ExchangeRequest;
  request_hash: string;
  endpoint: EndpointRecord;
  expected_exchange_id?: string;
  withdrawal_key?: string;
}
function refuse(): never {
  throw new ApiError("invalid_exchange_recovery", 400);
}
function key(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(value))
    refuse();
  return value;
}
function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    refuse();
  return o;
}
function participant(context: DirectoryContext): ExchangeBinding {
  return {
    tenant_id: context.tenant,
    partner_id: context.partner,
    actor_id: context.actor,
    authority_revision: context.authority_revision,
    root_policy_digest: context.root_policy_digest,
  };
}
function normalize(
  value: unknown,
  context: DirectoryContext,
  origin: string,
): OfferRecovery {
  const url = new URL(origin);
  if (
    origin.length > 2048 ||
    url.protocol !== "https:" ||
    url.origin !== origin
  )
    refuse();
  const o = exact(
    value,
    [
      "schema_version",
      "profile",
      "server_origin",
      "participant",
      "request_key",
      "request",
      "request_hash",
      "endpoint",
    ],
    ["expected_exchange_id", "withdrawal_key"],
  );
  if (
    o.schema_version !== 1 ||
    o.profile !== "freightctl-offer-recovery-v1" ||
    o.server_origin !== origin ||
    !context.can_send
  )
    refuse();
  const expected = participant(context),
    p = exact(o.participant, Object.keys(expected));
  if (Object.entries(expected).some(([name, value]) => p[name] !== value))
    refuse();
  const endpoint = asEndpointRecord(o.endpoint, context);
  if (
    endpoint.state !== "active" ||
    !endpoint.definition.senders.some((s) => bindingIsCurrent(s, context))
  )
    refuse();
  const request = asExchangeRequest(o.request);
  if (
    request.endpoint.id !== endpoint.id ||
    request.endpoint.revision !== endpoint.revision ||
    request.endpoint.hash !== endpoint.definition_hash ||
    o.request_hash !== exchangeRequestHash(request)
  )
    refuse();
  const result: OfferRecovery = {
    schema_version: 1,
    profile: "freightctl-offer-recovery-v1",
    server_origin: origin,
    participant: expected,
    request_key: key(o.request_key),
    request,
    request_hash: exchangeRequestHash(request),
    endpoint,
  };
  if (Object.hasOwn(o, "expected_exchange_id")) {
    if (
      typeof o.expected_exchange_id !== "string" ||
      !uuid(o.expected_exchange_id)
    )
      refuse();
    result.expected_exchange_id = o.expected_exchange_id;
  }
  if (Object.hasOwn(o, "withdrawal_key")) {
    if (!result.expected_exchange_id) refuse();
    result.withdrawal_key = key(o.withdrawal_key);
  }
  return result;
}

// Validate syntax before JSON.parse can erase repeated fields or round a
// number. Control-file bounds protect the browser, not artifact/build sizes.
function strictJSON(text: string): unknown {
  if (
    typeof text !== "string" ||
    new TextEncoder().encode(text).length > offerRecoveryMaximum ||
    text.length === 0
  )
    refuse();
  let at = 0,
    tokens = 0;
  const ws = () => {
    while (at < text.length && /[\t\n\r ]/.test(text[at]!)) at++;
  };
  const consume = () => {
    if (++tokens > 4096) refuse();
  };
  function string(): string {
    consume();
    if (text[at] !== '"') refuse();
    const begin = at++;
    while (at < text.length) {
      const c = text[at]!;
      if (c === '"') {
        at++;
        return JSON.parse(text.slice(begin, at)) as string;
      }
      if (c.charCodeAt(0) < 32) refuse();
      at += c === "\\" ? 2 : 1;
    }
    return refuse();
  }
  function value(depth: number): void {
    ws();
    consume();
    if (depth > 8) refuse();
    const c = text[at];
    if (c === "{") {
      at++;
      ws();
      const seen = new Set<string>();
      if (text[at] === "}") {
        at++;
        return;
      }
      for (;;) {
        ws();
        const name = string().toLowerCase();
        if (seen.has(name)) refuse();
        seen.add(name);
        ws();
        if (text[at++] !== ":") refuse();
        value(depth + 1);
        ws();
        if (text[at] === "}") {
          at++;
          return;
        }
        if (text[at++] !== ",") refuse();
      }
    }
    if (c === "[") {
      at++;
      ws();
      if (text[at] === "]") {
        at++;
        return;
      }
      for (;;) {
        value(depth + 1);
        ws();
        if (text[at] === "]") {
          at++;
          return;
        }
        if (text[at++] !== ",") refuse();
      }
    }
    if (c === '"') {
      string();
      return;
    }
    if (text.startsWith("true", at)) {
      at += 4;
      return;
    }
    if (text.startsWith("false", at)) {
      at += 5;
      return;
    }
    const match = /^(?:0|[1-9][0-9]*)/.exec(text.slice(at));
    if (!match || !Number.isSafeInteger(Number(match[0]))) refuse();
    at += match[0].length;
  }
  value(1);
  ws();
  if (at !== text.length) refuse();
  return JSON.parse(text) as unknown;
}

export function decodeOfferRecovery(
  text: string,
  context: DirectoryContext,
  origin: string,
): OfferRecovery {
  try {
    return normalize(strictJSON(text), context, origin);
  } catch {
    return refuse();
  }
}
export function encodeOfferRecovery(
  review: OfferReviewInput,
  context: DirectoryContext,
  origin: string,
): Uint8Array {
  try {
    const normalized = normalize(
      {
        schema_version: 1,
        profile: "freightctl-offer-recovery-v1",
        server_origin: origin,
        participant: participant(context),
        request_key: review.key,
        request: review.request,
        request_hash: exchangeRequestHash(review.request),
        endpoint: review.endpoint,
        ...(review.expected_exchange_id
          ? { expected_exchange_id: review.expected_exchange_id }
          : {}),
        ...(review.withdrawal_key
          ? { withdrawal_key: review.withdrawal_key }
          : {}),
      },
      context,
      origin,
    );
    const bytes = new TextEncoder().encode(JSON.stringify(normalized));
    if (bytes.length > offerRecoveryMaximum) refuse();
    return bytes;
  } catch {
    return refuse();
  }
}
