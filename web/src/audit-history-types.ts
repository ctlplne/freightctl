import { ApiError, object, uuid, type Session } from "./types";
import { digestBytes } from "./crypto";
import { strictRecoveryJSON } from "./artifact-recovery";

type Reader = Session["identity"];
export function auditHistorySessionStamp(s: Session | null): string {
  return s
    ? JSON.stringify([
        s.identity.tenant_id,
        s.identity.partner_id,
        s.identity.actor_id,
        s.identity.authority_revision,
        s.identity.root_policy_digest,
        s.identity.permissions,
        s.session.id,
      ])
    : "";
}
export interface AuditHistoryRequest {
  actor_id?: string;
  resource_id?: string;
  kinds?: string[];
  from?: string;
  until?: string;
  after?: string;
  limit: number;
}
export interface AuditHistoryEvent {
  event_id: string;
  actor_id: string;
  kind: string;
  resource_id: string;
  recorded_at: string;
}
export interface AuditHistoryPage {
  profile: "event-metadata-history-v1";
  tenant_id: string;
  partner_id: string;
  reader_actor_id: string;
  observed_at: string;
  observation: "independent-page-observation";
  payloads: "omitted";
  events: AuditHistoryEvent[];
  next?: string;
}
function bad(): never {
  throw new ApiError("invalid_audit_history", 400);
}
function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
}
function identifier(v: unknown): string {
  if (typeof v !== "string" || !uuid(v)) bad();
  return v;
}
export function auditHistoryAllowed(c: Reader): boolean {
  return (
    c.permissions.includes("audit_read") &&
    c.root_policy_digest === digestBytes(new TextEncoder().encode("/"))
  );
}
function instant(v: unknown): string {
  if (
    typeof v !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(v) ||
    v.startsWith("0000")
  )
    bad();
  const d = new Date(v);
  if (
    !Number.isFinite(d.getTime()) ||
    d.toISOString().slice(0, 19) !== v.slice(0, 19)
  )
    bad();
  const fraction = v[19] === "." ? v.slice(20, -1).replace(/0+$/, "") : "";
  return v.slice(0, 19) + (fraction ? "." + fraction : "") + "Z";
}
function instantKey(v: string): string {
  const s = instant(v);
  return (
    s.slice(0, 19) + "." + (s[19] === "." ? s.slice(20, -1) : "").padEnd(6, "0")
  );
}
export function normalizeAuditHistory(value: unknown): AuditHistoryRequest {
  const o = exact(
    value,
    ["limit"],
    ["actor_id", "resource_id", "kinds", "from", "until", "after"],
  );
  if (
    !Number.isSafeInteger(o.limit) ||
    (o.limit as number) < 1 ||
    (o.limit as number) > 100
  )
    bad();
  const r: AuditHistoryRequest = { limit: o.limit as number };
  for (const k of ["actor_id", "resource_id"] as const)
    if (o[k] !== undefined && o[k] !== "") r[k] = identifier(o[k]);
  if (o.kinds !== undefined) {
    if (
      !Array.isArray(o.kinds) ||
      o.kinds.length > 16 ||
      o.kinds.some(
        (v) =>
          typeof v !== "string" || !/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/.test(v),
      )
    )
      bad();
    const kinds = [...new Set(o.kinds as string[])].sort();
    if (kinds.length) r.kinds = kinds;
  }
  for (const k of ["from", "until"] as const)
    if (o[k] !== undefined && o[k] !== "") r[k] = instant(o[k]);
  if (r.from && r.until && instantKey(r.from) >= instantKey(r.until)) bad();
  if (o.after !== undefined && o.after !== "") {
    if (typeof o.after !== "string") bad();
    cursor(o.after);
    r.after = o.after;
  }
  if (new TextEncoder().encode(JSON.stringify(r)).length > 8192) bad();
  return r;
}
function cursor(value: string): { at: string; id: string; binding: string } {
  try {
    if (value.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(value)) bad();
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    if (
      binary.length > 768 ||
      btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "") !== value
    )
      bad();
    const o = exact(strictRecoveryJSON(binary), ["at", "id", "binding"]);
    if (typeof o.binding !== "string" || !/^[0-9a-f]{64}$/.test(o.binding))
      bad();
    return { at: instant(o.at), id: identifier(o.id), binding: o.binding };
  } catch {
    return bad();
  }
}
export function auditHistoryBinding(
  c: Reader,
  request: AuditHistoryRequest,
): string {
  const r = normalizeAuditHistory(request),
    search = {
      ...(r.actor_id ? { actor_id: r.actor_id } : {}),
      ...(r.resource_id ? { resource_id: r.resource_id } : {}),
      ...(r.kinds ? { kinds: r.kinds } : {}),
      ...(r.from ? { from: r.from } : {}),
      ...(r.until ? { until: r.until } : {}),
      limit: 0,
    };
  return digestBytes(
    new TextEncoder().encode(
      JSON.stringify({
        Tenant: c.tenant_id,
        Partner: c.partner_id,
        Actor: c.actor_id,
        Root: c.root_policy_digest,
        Authority: c.authority_revision,
        Search: search,
      }),
    ),
  );
}
export function validateHistoryCursor(c: Reader, r: AuditHistoryRequest) {
  if (r.after && cursor(r.after).binding !== auditHistoryBinding(c, r))
    throw new ApiError("context_changed", 409);
}
export function asAuditHistoryPage(
  value: unknown,
  c: Reader,
  input: AuditHistoryRequest,
): AuditHistoryPage {
  try {
    const r = normalizeAuditHistory(input),
      o = exact(
        value,
        [
          "profile",
          "tenant_id",
          "partner_id",
          "reader_actor_id",
          "observed_at",
          "observation",
          "payloads",
          "events",
        ],
        ["next"],
      );
    if (
      o.profile !== "event-metadata-history-v1" ||
      o.tenant_id !== c.tenant_id ||
      o.partner_id !== c.partner_id ||
      o.reader_actor_id !== c.actor_id ||
      o.observation !== "independent-page-observation" ||
      o.payloads !== "omitted" ||
      !Array.isArray(o.events) ||
      o.events.length > r.limit
    )
      bad();
    const events: AuditHistoryEvent[] = [],
      seen = new Set<string>();
    let previous = r.after ? cursor(r.after) : null;
    for (const value of o.events) {
      const e = exact(value, [
        "event_id",
        "actor_id",
        "kind",
        "resource_id",
        "recorded_at",
      ]);
      if (
        typeof e.kind !== "string" ||
        !e.kind ||
        new TextEncoder().encode(e.kind).length > 128
      )
        bad();
      const event = {
        event_id: identifier(e.event_id),
        actor_id: identifier(e.actor_id),
        kind: e.kind,
        resource_id: identifier(e.resource_id),
        recorded_at: instant(e.recorded_at),
      };
      const at = instantKey(event.recorded_at);
      if (
        seen.has(event.event_id) ||
        (r.actor_id && event.actor_id !== r.actor_id) ||
        (r.resource_id && event.resource_id !== r.resource_id) ||
        (r.kinds && !r.kinds.includes(event.kind)) ||
        (r.from && at < instantKey(r.from)) ||
        (r.until && at >= instantKey(r.until)) ||
        (previous &&
          (at < instantKey(previous.at) ||
            (at === instantKey(previous.at) && event.event_id <= previous.id)))
      )
        bad();
      seen.add(event.event_id);
      events.push(event);
      previous = { at: event.recorded_at, id: event.event_id, binding: "" };
    }
    let next: string | undefined;
    if (o.next !== undefined) {
      if (typeof o.next !== "string" || events.length !== r.limit || !previous)
        bad();
      const after = cursor(o.next);
      if (
        after.binding !== auditHistoryBinding(c, r) ||
        after.id !== previous.id ||
        instantKey(after.at) !== instantKey(previous.at)
      )
        bad();
      next = o.next;
    }
    return {
      profile: "event-metadata-history-v1",
      tenant_id: c.tenant_id,
      partner_id: c.partner_id,
      reader_actor_id: c.actor_id,
      observed_at: instant(o.observed_at),
      observation: "independent-page-observation",
      payloads: "omitted",
      events,
      ...(next ? { next } : {}),
    };
  } catch {
    throw new ApiError("invalid_server_response", 502);
  }
}
