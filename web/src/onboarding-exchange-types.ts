import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import type { ProbeReference } from "./onboarding-probes-types";

export interface ExchangeSelection {
  plan: ProbeReference;
  requirement_id: string;
  probe_id: string;
  run_id: string;
  step_id: string;
  expected_authority_revision: number;
}
interface Resource {
  id: string;
  revision: number;
  hash: string;
}
export interface ExchangeSnapshot {
  schema_version: 1;
  selection: ExchangeSelection;
  probe: Resource;
  probe_completed_at: string | null;
  connection: ProbeReference;
  workflow: ProbeReference;
  workflow_revision: number;
  run_revision: number;
  delivery: Resource;
  file: {
    id: string;
    size_bytes: number;
    sha256: string;
    policy: string;
    accepted_event_id: string;
  };
  receipt_hash: string;
  transfer_sha256: string;
  transfer_bytes: number;
  required_receipt: "transport" | "integrity" | "business";
  observed_receipt: "none" | "integrity";
  file_fsync_acknowledged: boolean;
  reconciled: boolean;
}
export interface ExchangeReview {
  snapshot: ExchangeSnapshot;
  snapshot_hash: string;
  observed_at: string;
  ready_for_approval_review: boolean;
  reason:
    | "recorded_evidence_matches"
    | "business_receipt_missing"
    | "probe_not_succeeded"
    | "exchange_not_succeeded";
  business_acceptance: "unknown";
  production_active: false;
  external_contact: false;
}
const invalid = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
function text(
  o: Record<string, unknown>,
  key: string,
  max: number,
  empty = false,
): string {
  const s = o[key];
  if (
    typeof s !== "string" ||
    (!empty && !s) ||
    new TextEncoder().encode(s).length > max ||
    /[\u0000-\u001f\u007f-\u009f]/.test(s) ||
    /[\ud800-\udfff]/u.test(s)
  )
    invalid();
  return s as string;
}
function id(o: Record<string, unknown>, key: string): string {
  const s = text(o, key, 36);
  if (!uuid(s)) invalid();
  return s;
}
function hash(o: Record<string, unknown>, key: string): string {
  const s = text(o, key, 64);
  if (!/^[a-f0-9]{64}$/.test(s)) invalid();
  return s;
}
function integer(o: Record<string, unknown>, key: string, min = 1): number {
  const n = o[key];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min) invalid();
  return n as number;
}
function bool(o: Record<string, unknown>, key: string): boolean {
  if (typeof o[key] !== "boolean") invalid();
  return o[key] as boolean;
}
function time(o: Record<string, unknown>, key: string): string {
  const s = text(o, key, 64);
  if (!/^\d{4}-\d{2}-\d{2}T.*Z$/.test(s) || !Number.isFinite(Date.parse(s)))
    invalid();
  return s;
}
function ref(v: unknown): ProbeReference {
  const o = object(v),
    version = integer(o, "version");
  if (version > 2147483647) invalid();
  return { id: id(o, "id"), version, hash: hash(o, "hash") };
}
function resource(v: unknown): Resource {
  const o = object(v);
  return {
    id: id(o, "id"),
    revision: integer(o, "revision"),
    hash: hash(o, "hash"),
  };
}
function selection(v: unknown): ExchangeSelection {
  const o = object(v),
    step = text(o, "step_id", 64);
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(step)) invalid();
  return {
    plan: ref(o.plan),
    requirement_id: id(o, "requirement_id"),
    probe_id: id(o, "probe_id"),
    run_id: id(o, "run_id"),
    step_id: step,
    expected_authority_revision: integer(o, "expected_authority_revision"),
  };
}
export function exchangeSnapshotHash(snapshot: ExchangeSnapshot): string {
  // Go's canonical typed JSON escapes these code points. Preserve exact field
  // order and timestamp spelling; do not hash an arbitrary server JSON object.
  const encoded = JSON.stringify(snapshot).replace(
    /[<>&\u2028\u2029]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  const bytes = new TextEncoder().encode(encoded);
  try {
    return digestBytes(bytes);
  } finally {
    bytes.fill(0);
  }
}
export function asExchangeReview(
  value: unknown,
  expected: ExchangeSelection,
): ExchangeReview {
  const o = object(value),
    s = object(o.snapshot),
    file = object(s.file);
  if (s.schema_version !== 1) invalid();
  const required = text(s, "required_receipt", 16),
    observed = text(s, "observed_receipt", 16);
  if (
    !["transport", "integrity", "business"].includes(required) ||
    !["none", "integrity"].includes(observed)
  )
    invalid();
  const snapshot: ExchangeSnapshot = {
    schema_version: 1,
    selection: selection(s.selection),
    probe: resource(s.probe),
    probe_completed_at:
      s.probe_completed_at === null ? null : time(s, "probe_completed_at"),
    connection: ref(s.connection),
    workflow: ref(s.workflow),
    workflow_revision: integer(s, "workflow_revision"),
    run_revision: integer(s, "run_revision"),
    delivery: resource(s.delivery),
    file: {
      id: id(file, "id"),
      size_bytes: integer(file, "size_bytes", 0),
      sha256: hash(file, "sha256"),
      policy: text(file, "policy", 256),
      accepted_event_id: id(file, "accepted_event_id"),
    },
    receipt_hash: hash(s, "receipt_hash"),
    transfer_sha256: text(s, "transfer_sha256", 64, true),
    transfer_bytes: integer(s, "transfer_bytes", 0),
    required_receipt: required as ExchangeSnapshot["required_receipt"],
    observed_receipt: observed as ExchangeSnapshot["observed_receipt"],
    file_fsync_acknowledged: bool(s, "file_fsync_acknowledged"),
    reconciled: bool(s, "reconciled"),
  };
  const reason = text(o, "reason", 64),
    ready = bool(o, "ready_for_approval_review");
  if (
    ![
      "recorded_evidence_matches",
      "business_receipt_missing",
      "probe_not_succeeded",
      "exchange_not_succeeded",
    ].includes(reason) ||
    o.business_acceptance !== "unknown" ||
    o.production_active !== false ||
    o.external_contact !== false
  )
    invalid();
  if (
    JSON.stringify(snapshot.selection) !==
      JSON.stringify(selection(expected)) ||
    snapshot.probe.id !== expected.probe_id ||
    snapshot.probe.revision > 3 ||
    hash(o, "snapshot_hash") !== exchangeSnapshotHash(snapshot)
  )
    invalid();
  if (observed === "integrity") {
    if (
      !/^[a-f0-9]{64}$/.test(snapshot.transfer_sha256) ||
      !snapshot.probe_completed_at ||
      snapshot.file_fsync_acknowledged === snapshot.reconciled
    )
      invalid();
    const mustBlock = required === "business";
    if (
      ready === mustBlock ||
      reason !==
        (mustBlock ? "business_receipt_missing" : "recorded_evidence_matches")
    )
      invalid();
  } else if (
    ready ||
    !["probe_not_succeeded", "exchange_not_succeeded"].includes(reason) ||
    snapshot.transfer_sha256 ||
    snapshot.transfer_bytes ||
    snapshot.file_fsync_acknowledged ||
    snapshot.reconciled
  )
    invalid();
  return {
    snapshot,
    snapshot_hash: hash(o, "snapshot_hash"),
    observed_at: time(o, "observed_at"),
    ready_for_approval_review: ready,
    reason: reason as ExchangeReview["reason"],
    business_acceptance: "unknown",
    production_active: false,
    external_contact: false,
  };
}
