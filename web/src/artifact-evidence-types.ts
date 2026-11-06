import { ApiError, object, uuid } from "./types";
import {
  asExchangeArtifact,
  type ExchangeArtifact,
} from "./artifact-exchanges-types";

export type EvidenceDirection = "incoming" | "outgoing";
export interface EvidenceExpectation {
  request_hash: string;
  artifact: ExchangeArtifact;
  expires_at: string;
}
export interface ExchangeEvidence {
  profile: "authorized-exchange-evidence-v1";
  tenant_id: string;
  partner_id: string;
  exchange_id: string;
  direction: EvidenceDirection;
  current_metadata_state:
    "offered" | "held" | "unavailable" | "expired" | "canceled" | "declined";
  checked_at: string;
  details: "opaque" | "authorized-records";
  request_hash?: string;
  artifact?: ExchangeArtifact;
  reply_reference_only?: string;
  recorded_events: {
    kind:
      | "custody-acceptance"
      | "availability-offer"
      | "view-canceled"
      | "view-declined";
    event_id: string;
    resource_id: string;
    recorded_at: string;
  }[];
  storage_verification: "not-checked";
  retrieval: "unknown";
  receiver_persistence: "unknown";
  business_processing: "unknown";
}
function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}
function identifier(value: unknown): string {
  if (typeof value !== "string" || !uuid(value)) bad();
  return value;
}
const digest = (v: unknown): v is string =>
  typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
function keys(o: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(o).some((k) => !allowed.includes(k))) bad();
}
function instant(v: unknown): string {
  if (
    typeof v !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(v)
  )
    bad();
  const d = new Date(v);
  if (
    !Number.isFinite(d.getTime()) ||
    d.toISOString().slice(0, 19) !== v.slice(0, 19)
  )
    bad();
  return v;
}
function instantKey(v: string): string {
  const s = instant(v);
  return (
    s.slice(0, 19) + "." + (s[19] === "." ? s.slice(20, -1) : "").padEnd(6, "0")
  );
}
export function evidenceExpectation(
  value: EvidenceExpectation,
): EvidenceExpectation {
  if (!digest(value.request_hash)) bad();
  return {
    request_hash: value.request_hash,
    artifact: asExchangeArtifact(value.artifact),
    expires_at: instant(value.expires_at),
  };
}
export function asExchangeEvidence(
  value: unknown,
  scope: { tenant: string; partner: string },
  id: string,
  direction: EvidenceDirection,
  expected?: EvidenceExpectation,
): ExchangeEvidence {
  const o = object(value);
  keys(o, [
    "profile",
    "tenant_id",
    "partner_id",
    "exchange_id",
    "direction",
    "current_metadata_state",
    "checked_at",
    "details",
    "request_hash",
    "artifact",
    "reply_reference_only",
    "recorded_events",
    "storage_verification",
    "retrieval",
    "receiver_persistence",
    "business_processing",
  ]);
  if (
    o.profile !== "authorized-exchange-evidence-v1" ||
    o.tenant_id !== scope.tenant ||
    o.partner_id !== scope.partner ||
    o.exchange_id !== id ||
    !uuid(id) ||
    o.direction !== direction ||
    !["incoming", "outgoing"].includes(direction) ||
    o.storage_verification !== "not-checked" ||
    o.retrieval !== "unknown" ||
    o.receiver_persistence !== "unknown" ||
    o.business_processing !== "unknown" ||
    !Array.isArray(o.recorded_events)
  )
    bad();
  const state = o.current_metadata_state;
  if (
    typeof state !== "string" ||
    !(
      direction === "incoming"
        ? ["offered", "held"]
        : ["offered", "held", "unavailable", "expired", "canceled", "declined"]
    ).includes(state)
  )
    bad();
  const result: ExchangeEvidence = {
    profile: "authorized-exchange-evidence-v1",
    tenant_id: scope.tenant,
    partner_id: scope.partner,
    exchange_id: id,
    direction,
    current_metadata_state: state as ExchangeEvidence["current_metadata_state"],
    checked_at: instant(o.checked_at),
    details: "opaque",
    recorded_events: [],
    storage_verification: "not-checked",
    retrieval: "unknown",
    receiver_persistence: "unknown",
    business_processing: "unknown",
  };
  if (expected) {
    const expired =
      instantKey(expected.expires_at) <= instantKey(result.checked_at);
    if (
      direction === "incoming"
        ? expired
        : !["canceled", "declined"].includes(state) &&
          (state === "expired") !== expired
    )
      bad();
  }
  if (direction === "incoming" && state === "held") {
    if (
      o.details !== "opaque" ||
      o.recorded_events.length !== 0 ||
      ["artifact", "request_hash", "reply_reference_only"].some((k) =>
        Object.hasOwn(o, k),
      )
    )
      bad();
    return result;
  }
  if (o.details !== "authorized-records" || !digest(o.request_hash)) bad();
  const artifact = asExchangeArtifact(o.artifact);
  if (
    expected &&
    (o.request_hash !== expected.request_hash ||
      artifact.file_revision_id !== expected.artifact.file_revision_id ||
      artifact.size_bytes !== expected.artifact.size_bytes ||
      artifact.sha256 !== expected.artifact.sha256 ||
      artifact.acceptance_policy !== expected.artifact.acceptance_policy)
  )
    bad();
  const kinds = [
    "custody-acceptance",
    "availability-offer",
    ...(state === "canceled"
      ? ["view-canceled"]
      : state === "declined"
        ? ["view-declined"]
        : []),
  ];
  if (o.recorded_events.length !== kinds.length) bad();
  const events = o.recorded_events.map((value, i) => {
    const e = object(value);
    keys(e, ["kind", "event_id", "resource_id", "recorded_at"]);
    const eventId = identifier(e.event_id),
      resourceId = identifier(e.resource_id);
    if (
      e.kind !== kinds[i] ||
      resourceId !== (i === 0 ? artifact.file_revision_id : id)
    )
      bad();
    return {
      kind: e.kind as ExchangeEvidence["recorded_events"][number]["kind"],
      event_id: eventId,
      resource_id: resourceId,
      recorded_at: instant(e.recorded_at),
    };
  });
  if (new Set(events.map((e) => e.event_id)).size !== events.length) bad();
  result.details = "authorized-records";
  result.request_hash = o.request_hash;
  result.artifact = artifact;
  result.recorded_events = events;
  if (Object.hasOwn(o, "reply_reference_only")) {
    result.reply_reference_only = identifier(o.reply_reference_only);
  }
  return result;
}
