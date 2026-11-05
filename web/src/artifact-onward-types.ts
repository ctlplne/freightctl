import { ApiError, object, uuid, type Session } from "./types";
import {
  asExchangeArtifact,
  type ExchangeArtifact,
} from "./artifact-exchanges-types";
import { digestBytes } from "./crypto";
import { strictRecoveryJSON } from "./artifact-recovery";

export const onwardProfile = "ordered-workflow-onward-v1";
export interface OnwardReference {
  id: string;
  version: number;
  hash: string;
}
export interface OnwardRequest {
  schema_version: 1;
  profile: typeof onwardProfile;
  workflow: OnwardReference;
  artifact: ExchangeArtifact;
}
export interface OnwardStart {
  request: OnwardRequest;
  review_hash: string;
}
export interface OnwardReview extends OnwardStart {
  effects: {
    ordinal: number;
    protocol: "sftp" | "ftps";
    connection: OnwardReference;
  }[];
  state: "review-only";
  external_contact: false;
  receiver_persistence: "unknown";
  business_processing: "unknown";
}
export interface OnwardAcceptance {
  run_id: string;
  accepted_run_state: "queued";
  current_state: "not-checked";
  replayed: boolean;
}
export interface OnwardObservation {
  run_id: string;
  workflow: OnwardReference;
  artifact: ExchangeArtifact;
  observed_state: string;
  reason_sha256: string;
  receiver_persistence: "unknown";
  business_processing: "unknown";
  steps: {
    ordinal: number;
    delivery_id: string;
    state: string;
    observation_sha256: string;
  }[];
  replayed?: boolean;
  selected_delivery_id?: string;
}
export interface OnwardRecovery {
  schema_version: 1;
  profile: "freightctl-onward-recovery-v1";
  server_origin: string;
  participant: {
    tenant_id: string;
    partner_id: string;
    actor_id: string;
    authority_revision: number;
    root_policy_digest: string;
  };
  review: OnwardReview;
  request_key: string;
  expected_run_id?: string;
  work_key?: string;
}
function refuse(): never {
  throw new ApiError("invalid_onward_contract", 400);
}
function exact(v: unknown, required: string[], optional: string[] = []) {
  const o = object(v);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    refuse();
  return o;
}
function id(v: unknown): string {
  if (typeof v !== "string" || !uuid(v)) refuse();
  return v;
}
function hash(v: unknown): string {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) refuse();
  return v;
}
function integer(
  v: unknown,
  min: number,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max)
    refuse();
  return v;
}
function ref(v: unknown): OnwardReference {
  const o = exact(v, ["id", "version", "hash"]);
  return {
    id: id(o.id),
    version: integer(o.version, 1, 2147483647),
    hash: hash(o.hash),
  };
}
const same = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
const digest = (v: string) => digestBytes(new TextEncoder().encode(v));
export function asOnwardRequest(v: unknown): OnwardRequest {
  const o = exact(v, ["schema_version", "profile", "workflow", "artifact"]);
  if (o.schema_version !== 1 || o.profile !== onwardProfile) refuse();
  return {
    schema_version: 1,
    profile: onwardProfile,
    workflow: ref(o.workflow),
    artifact: asExchangeArtifact(o.artifact),
  };
}
export function asOnwardStart(v: unknown): OnwardStart {
  const o = exact(v, ["request", "review_hash"]);
  return {
    request: asOnwardRequest(o.request),
    review_hash: hash(o.review_hash),
  };
}
export function asOnwardReview(
  v: unknown,
  expected?: OnwardRequest,
): OnwardReview {
  const o = exact(v, [
    "request",
    "review_hash",
    "effects",
    "state",
    "external_contact",
    "receiver_persistence",
    "business_processing",
  ]);
  const request = asOnwardRequest(o.request);
  if (
    (expected && !same(request, asOnwardRequest(expected))) ||
    o.state !== "review-only" ||
    o.external_contact !== false ||
    o.receiver_persistence !== "unknown" ||
    o.business_processing !== "unknown" ||
    !Array.isArray(o.effects) ||
    o.effects.length < 1 ||
    o.effects.length > 16
  )
    refuse();
  const effects = o.effects.map((v, i) => {
    const e = exact(v, ["ordinal", "protocol", "connection"]);
    if (e.ordinal !== i + 1 || (e.protocol !== "sftp" && e.protocol !== "ftps"))
      refuse();
    return {
      ordinal: i + 1,
      protocol: e.protocol as "sftp" | "ftps",
      connection: ref(e.connection),
    };
  });
  return {
    request,
    review_hash: hash(o.review_hash),
    effects,
    state: "review-only",
    external_contact: false,
    receiver_persistence: "unknown",
    business_processing: "unknown",
  };
}
export function asOnwardAcceptance(
  v: unknown,
  original: OnwardStart,
  session: Session,
  expectedID?: string,
): OnwardAcceptance {
  const start = asOnwardStart(original),
    o = exact(v, ["resource", "replayed"]),
    r = object(o.resource),
    s = object(r.source),
    who = session.identity;
  const source = asExchangeArtifact({
    file_revision_id: s.id,
    size_bytes: s.size_bytes,
    sha256: s.sha256,
    acceptance_policy: s.policy,
  });
  const workflow = ref({
    id: r.workflow_id,
    version: r.workflow_version,
    hash: r.workflow_hash,
  });
  if (
    typeof o.replayed !== "boolean" ||
    r.onward_profile !== onwardProfile ||
    r.onward_review_hash !== start.review_hash ||
    r.file_id !== source.file_revision_id ||
    !same(source, start.request.artifact) ||
    !same(workflow, start.request.workflow) ||
    r.namespace_root !== "/" ||
    r.authority_revision !== who.authority_revision ||
    r.state !== "queued" ||
    r.revision !== 1 ||
    r.reason !== "awaiting_worker" ||
    r.execution_plan !== undefined ||
    r.routing_authorization_id !== undefined
  )
    refuse();
  const runID = id(r.id);
  if (expectedID && runID !== expectedID) refuse();
  // Reconstruct the server's exact review fingerprint from the immutable receipt.
  // The fingerprint proves consistency, never authority or receiver acceptance.
  const binding = {
    request: start.request,
    tenant_id: who.tenant_id,
    partner_id: who.partner_id,
    actor_id: who.actor_id,
    authority_revision: integer(r.authority_revision, 1),
    root_policy_digest: digest("/"),
    workflow_revision: integer(r.onward_workflow_revision, 1),
    storage_identity_digest: digest(id(r.storage_id)),
  };
  if (
    who.root_policy_digest !== binding.root_policy_digest ||
    digest(JSON.stringify(binding)) !== start.review_hash
  )
    refuse();
  return {
    run_id: runID,
    accepted_run_state: "queued",
    current_state: "not-checked",
    replayed: o.replayed,
  };
}
export function asOnwardObservation(
  v: unknown,
  original: OnwardStart,
  runID: string,
  work = false,
): OnwardObservation {
  const o = exact(
      v,
      [
        "run_id",
        "workflow",
        "artifact",
        "observed_state",
        "reason_sha256",
        "receiver_persistence",
        "business_processing",
        "steps",
      ],
      work ? ["replayed", "selected_delivery_id"] : [],
    ),
    start = asOnwardStart(original);
  const workflow = ref(o.workflow),
    artifact = asExchangeArtifact(o.artifact);
  if (
    id(o.run_id) !== id(runID) ||
    !same(workflow, start.request.workflow) ||
    !same(artifact, start.request.artifact) ||
    !["queued", "running", "attention", "succeeded", "cancelled"].includes(
      String(o.observed_state),
    ) ||
    o.receiver_persistence !== "unknown" ||
    o.business_processing !== "unknown" ||
    !Array.isArray(o.steps) ||
    o.steps.length < 1 ||
    o.steps.length > 16
  )
    refuse();
  const seen = new Set<string>();
  const steps = o.steps.map((v, i) => {
    const e = exact(v, [
        "ordinal",
        "delivery_id",
        "state",
        "observation_sha256",
      ]),
      delivery = id(e.delivery_id);
    if (
      e.ordinal !== i + 1 ||
      seen.has(delivery) ||
      ![
        "queued",
        "staging",
        "publishing",
        "retry",
        "blocked",
        "ambiguous",
        "succeeded",
        "cancelled",
      ].includes(String(e.state))
    )
      refuse();
    seen.add(delivery);
    return {
      ordinal: i + 1,
      delivery_id: delivery,
      state: String(e.state),
      observation_sha256: hash(e.observation_sha256),
    };
  });
  const result: OnwardObservation = {
    run_id: runID,
    workflow,
    artifact,
    observed_state: String(o.observed_state),
    reason_sha256: hash(o.reason_sha256),
    receiver_persistence: "unknown",
    business_processing: "unknown",
    steps,
  };
  if (work) {
    if (
      typeof o.replayed !== "boolean" ||
      !seen.has(id(o.selected_delivery_id))
    )
      refuse();
    result.replayed = o.replayed;
    result.selected_delivery_id = String(o.selected_delivery_id);
  }
  return result;
}
export function asOnwardRecovery(
  v: unknown,
  session: Session,
  origin: string,
): OnwardRecovery {
  const o = exact(
      v,
      [
        "schema_version",
        "profile",
        "server_origin",
        "participant",
        "review",
        "request_key",
      ],
      ["expected_run_id", "work_key"],
    ),
    i = session.identity;
  const url = new URL(origin);
  if (
    url.protocol !== "https:" ||
    url.origin !== origin ||
    origin.length > 2048 ||
    o.schema_version !== 1 ||
    o.profile !== "freightctl-onward-recovery-v1" ||
    o.server_origin !== origin
  )
    refuse();
  const p = exact(o.participant, [
      "tenant_id",
      "partner_id",
      "actor_id",
      "authority_revision",
      "root_policy_digest",
    ]),
    participant = {
      tenant_id: id(p.tenant_id),
      partner_id: id(p.partner_id),
      actor_id: id(p.actor_id),
      authority_revision: integer(p.authority_revision, 1),
      root_policy_digest: hash(p.root_policy_digest),
    };
  if (
    !same(participant, {
      tenant_id: i.tenant_id,
      partner_id: i.partner_id,
      actor_id: i.actor_id,
      authority_revision: i.authority_revision,
      root_policy_digest: i.root_policy_digest,
    })
  )
    refuse();
  const result: OnwardRecovery = {
    schema_version: 1,
    profile: "freightctl-onward-recovery-v1",
    server_origin: origin,
    participant,
    review: asOnwardReview(o.review),
    request_key: id(o.request_key),
  };
  if (o.expected_run_id !== undefined)
    result.expected_run_id = id(o.expected_run_id);
  if (o.work_key !== undefined) {
    if (!result.expected_run_id) refuse();
    result.work_key = id(o.work_key);
  }
  return result;
}
export function readOnwardRecovery(
  text: string,
  session: Session,
  origin: string,
): OnwardRecovery {
  try {
    return asOnwardRecovery(strictRecoveryJSON(text), session, origin);
  } catch {
    return refuse();
  }
}
