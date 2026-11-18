import { ApiError, object, uuid } from "./types";
import {
  asExchangeArtifact,
  type ExchangeArtifact,
} from "./artifact-exchanges-types";

export type EvidenceDirection = "incoming" | "outgoing";
export const evidenceV1 = "authorized-exchange-evidence-v1";
export const evidenceV2 = "authorized-exchange-evidence-v2";
export const evidenceV3 = "authorized-exchange-evidence-v3";
export const evidenceV4 = "authorized-exchange-evidence-v4";
export type EvidenceProfile =
  typeof evidenceV1 | typeof evidenceV2 | typeof evidenceV3 | typeof evidenceV4;
export interface EvidenceExpectation {
  request_hash: string;
  artifact: ExchangeArtifact;
  expires_at: string;
}
interface RecordProjectionLineage {
  projection_id: string;
  definition_hash: string;
  source_artifact: ExchangeArtifact;
  source_accepted_event_id: string;
  completed_event_id: string;
  completed_at: string;
}
interface ReceivedCopyLineage {
  source: {
    exchange_id: string;
    request_hash: string;
    artifact: ExchangeArtifact;
  };
  source_accepted_event_id: string;
  source_offer_event_id: string;
}
export interface ExchangeEvidence {
  profile: EvidenceProfile;
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
  record_projection?: RecordProjectionLineage;
  received_copy?: ReceivedCopyLineage;
  integrity_report?: ExchangeIntegrityReport;
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

export interface ExchangeIntegrityCommand {
  schema_version: 1;
  exchange_id: string;
  request_hash: string;
  read_authorization_event_id: string;
  file_revision_id: string;
  size_bytes: number;
  sha256: string;
}

export function asExchangeIntegrityCommand(
  value: unknown,
  id: string,
  expected: EvidenceExpectation,
): ExchangeIntegrityCommand {
  const o = object(value);
  keys(o, [
    "schema_version",
    "exchange_id",
    "request_hash",
    "read_authorization_event_id",
    "file_revision_id",
    "size_bytes",
    "sha256",
  ]);
  const a = expected.artifact;
  if (
    o.schema_version !== 1 ||
    o.exchange_id !== id ||
    o.request_hash !== expected.request_hash ||
    o.file_revision_id !== a.file_revision_id ||
    o.size_bytes !== a.size_bytes ||
    o.sha256 !== a.sha256
  )
    bad();
  return {
    schema_version: 1,
    exchange_id: id,
    request_hash: expected.request_hash,
    read_authorization_event_id: identifier(o.read_authorization_event_id),
    file_revision_id: a.file_revision_id,
    size_bytes: a.size_bytes,
    sha256: a.sha256,
  };
}

export function asExchangeIntegrityReport(
  value: unknown,
  id: string,
  expected: Pick<EvidenceExpectation, "request_hash" | "artifact">,
  read?: string,
) {
  const o = object(value);
  keys(o, [
    "profile",
    "exchange_id",
    "request_hash",
    "artifact",
    "read_authorization_event_id",
    "observation",
    "event_id",
    "recorded_at",
    "receiver_persistence",
    "business_processing",
  ]);
  const artifact = asExchangeArtifact(
    o.artifact,
    expected.artifact.file_revision_id,
  );
  const authorization = identifier(o.read_authorization_event_id);
  const event = identifier(o.event_id);
  if (
    o.profile !== "recipient-sha256-report-v1" ||
    o.exchange_id !== id ||
    o.request_hash !== expected.request_hash ||
    artifact.size_bytes !== expected.artifact.size_bytes ||
    artifact.sha256 !== expected.artifact.sha256 ||
    artifact.acceptance_policy !== expected.artifact.acceptance_policy ||
    event === authorization ||
    (read !== undefined && authorization !== read) ||
    o.observation !== "recipient-reported-sha256-and-length-match" ||
    o.receiver_persistence !== "unknown" ||
    o.business_processing !== "unknown"
  )
    bad();
  return { event, recordedAt: instant(o.recorded_at) };
}

export type ExchangeIntegrityReport = ReturnType<
  typeof asExchangeIntegrityReport
>;

export function asExchangeEvidence(
  value: unknown,
  scope: { tenant: string; partner: string },
  id: string,
  direction: EvidenceDirection,
  expected?: EvidenceExpectation,
  profile: EvidenceProfile = evidenceV1,
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
    "record_projection",
    "received_copy",
    "integrity_report",
    "storage_verification",
    "retrieval",
    "receiver_persistence",
    "business_processing",
  ]);
  if (
    o.profile !== profile ||
    ![evidenceV1, evidenceV2, evidenceV3, evidenceV4].includes(profile) ||
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
  const hasLineage = Object.hasOwn(o, "record_projection");
  if (hasLineage && (profile === evidenceV1 || direction !== "outgoing")) bad();
  const hasCopy = Object.hasOwn(o, "received_copy");
  if (
    hasCopy &&
    (profile !== evidenceV4 || direction !== "outgoing" || hasLineage)
  )
    bad();
  const hasReport = Object.hasOwn(o, "integrity_report");
  if (hasReport && profile !== evidenceV3 && profile !== evidenceV4) bad();
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
    profile,
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
      hasReport ||
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
  if (hasLineage) {
    const lineage = object(o.record_projection);
    keys(lineage, [
      "projection_id",
      "definition_hash",
      "source_artifact",
      "source_accepted_event_id",
      "completed_event_id",
      "completed_at",
    ]);
    const source = asExchangeArtifact(lineage.source_artifact);
    const sourceEvent = identifier(lineage.source_accepted_event_id);
    const completedEvent = identifier(lineage.completed_event_id);
    if (
      !digest(lineage.definition_hash) ||
      source.file_revision_id === artifact.file_revision_id ||
      sourceEvent === completedEvent ||
      events.some(
        (e) => e.event_id === sourceEvent || e.event_id === completedEvent,
      )
    )
      bad();
    result.record_projection = {
      projection_id: identifier(lineage.projection_id),
      definition_hash: lineage.definition_hash,
      source_artifact: source,
      source_accepted_event_id: sourceEvent,
      completed_event_id: completedEvent,
      completed_at: instant(lineage.completed_at),
    };
  }
  if (hasReport) {
    const report = asExchangeIntegrityReport(o.integrity_report, id, {
      request_hash: o.request_hash,
      artifact,
    });
    if (events.some((event) => event.event_id === report.event)) bad();
    result.integrity_report = report;
  }
  if (hasCopy) {
    const copy = object(o.received_copy);
    keys(copy, ["source", "source_accepted_event_id", "source_offer_event_id"]);
    const source = object(copy.source);
    keys(source, ["exchange_id", "request_hash", "artifact"]);
    const original = asExchangeArtifact(source.artifact);
    const parent = identifier(source.exchange_id);
    const accepted = identifier(copy.source_accepted_event_id);
    const offer = identifier(copy.source_offer_event_id);
    if (
      !digest(source.request_hash) ||
      parent === id ||
      original.file_revision_id === artifact.file_revision_id ||
      original.sha256 !== artifact.sha256 ||
      original.size_bytes !== artifact.size_bytes ||
      accepted === offer ||
      events.some((e) => e.event_id === accepted || e.event_id === offer)
    )
      bad();
    result.received_copy = {
      source: {
        exchange_id: parent,
        request_hash: source.request_hash,
        artifact: original,
      },
      source_accepted_event_id: accepted,
      source_offer_event_id: offer,
    };
  }
  return result;
}
