import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  canonicalWorkflowBytes,
  type Reference,
  type ScheduleEffect,
} from "./schedules-types";
import {
  asCollectionConfiguration,
  effectsForWorkflow,
  workflowProgramShape,
  type CollectionView,
  type WorkflowConfiguration,
} from "./collections-types";
import {
  asExecutionPlan,
  asRoutingFacts,
  programFingerprint,
  type ExecutionPlan,
} from "./programs-types";

export type HandoffState = "proposed" | "approved" | "cancelled" | "completed";
export interface CollectionHandoffSelection {
  input_id: string;
  source_run_id: string;
  workflow: Reference;
  expected_authority_revision: number;
}
export interface CollectionHandoffDefinition {
  schema_version: 1;
  profile: "untouched-collected-handoff-v1";
  collection: { id: string; revision: number; definition_hash: string };
  input_id: string;
  source_run: {
    id: string;
    revision: number;
    plan_hash: string;
    workflow: Reference;
    routing_authorization_id?: string;
  };
  intents: {
    id: string;
    revision: number;
    definition_hash: string;
    step_id: string;
    ordinal: number;
  }[];
  workflow: Reference;
  plan: ExecutionPlan;
  plan_hash: string;
  authority_revision: number;
  storage_id: string;
  namespace_root: "/";
}
export type HandoffEffect = ScheduleEffect & {
  user: string;
  key_fingerprint: string;
};
export interface CollectionHandoffReview {
  source_workflow: WorkflowConfiguration;
  source_plan: ExecutionPlan;
  source_effects: HandoffEffect[];
  workflow: WorkflowConfiguration;
  effects: HandoffEffect[];
}
export interface CollectionHandoffPreview extends CollectionHandoffReview {
  definition: CollectionHandoffDefinition;
  definition_hash: string;
  external_contact: false;
  approval_required: true;
}
export interface HandoffSummary {
  id: string;
  job_id: string;
  input_id: string;
  source_run_id: string;
  planned_run_id: string;
  definition_hash: string;
  state: HandoffState;
  revision: number;
  approval_authority: number;
}
export interface CollectionHandoffRecord extends HandoffSummary {
  definition: CollectionHandoffDefinition;
}
export interface CollectionHandoffView extends CollectionHandoffReview {
  handoff: CollectionHandoffRecord;
  current_bindings: boolean;
  binding_reason: "current" | "binding_changed" | "cancelled" | "completed";
}
const bad = (): never => {
  throw new ApiError("invalid_collection_handoff", 502);
};
const keys = (
  o: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) => {
  if (
    required.some((k) => !(k in o)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
};
const integer = (
  o: Record<string, unknown>,
  k: string,
  min = 1,
  max = Number.MAX_SAFE_INTEGER,
): number => {
  const n = o[k];
  if (!Number.isSafeInteger(n) || (n as number) < min || (n as number) > max)
    bad();
  return n as number;
};
const id = (o: Record<string, unknown>, k: string): string => {
  if (typeof o[k] !== "string" || !uuid(o[k] as string)) bad();
  return o[k] as string;
};
const hash = (o: Record<string, unknown>, k: string): string => {
  if (typeof o[k] !== "string" || !/^[a-f0-9]{64}$/.test(o[k] as string)) bad();
  return o[k] as string;
};
const text = (o: Record<string, unknown>, k: string, max = 128): string => {
  const s = o[k];
  if (
    typeof s !== "string" ||
    !s.length ||
    new TextEncoder().encode(s).length > max ||
    /\p{Cc}/u.test(s) ||
    s.normalize("NFC") !== s
  )
    bad();
  return s as string;
};
const list = (v: unknown, max: number, min = 0): unknown[] => {
  if (!Array.isArray(v) || v.length < min || v.length > max) bad();
  return v as unknown[];
};
const equal = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
const reviewKeys = [
  "source_workflow",
  "source_plan",
  "source_effects",
  "workflow",
  "effects",
];
export const collectionHandoffHash = (d: CollectionHandoffDefinition) =>
  digestBytes(canonicalWorkflowBytes(d));

function reference(v: unknown): Reference {
  const o = object(v);
  keys(o, ["id", "version", "hash"]);
  return {
    id: id(o, "id"),
    version: integer(o, "version", 1, 2147483647),
    hash: hash(o, "hash"),
  };
}

function effects(v: unknown, w: WorkflowConfiguration): HandoffEffect[] {
  const raw = list(v, 16).map(object);
  for (const o of raw) {
    keys(
      o,
      [
        "step_id",
        "connection",
        "address",
        "directory",
        "final_name_pattern",
        "host_fingerprint",
        "user",
        "key_fingerprint",
      ],
      [
        "encryption",
        "recipient_fingerprint",
        "encryption_fingerprint",
        ...(o.protocol === "ftps" ? ["protocol", "ftps"] : []),
      ],
    );
    reference(o.connection);
    if (o.encryption !== undefined) {
      const e = object(o.encryption);
      keys(e, ["key", "profile"]);
      reference(e.key);
    } else if (
      o.recipient_fingerprint !== undefined ||
      o.encryption_fingerprint !== undefined
    )
      bad();
  }
  const base = effectsForWorkflow(
    raw.map(({ user, key_fingerprint: _key, ...effect }) =>
      effect.protocol === "ftps" ? { ...effect, user } : effect,
    ),
    w.definition,
  );
  return base.map((effect, index) => {
    const o = raw[index]!;
    const user = text(o, "user", effect.protocol === "ftps" ? 256 : 128);
    let key = "";
    if (effect.protocol === "ftps") {
      if (o.key_fingerprint !== "" || user !== effect.user) bad();
    } else {
      key = text(o, "key_fingerprint", 100);
      if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(key)) bad();
    }
    return { ...effect, user, key_fingerprint: key };
  });
}

function reviewAndDefinition(
  o: Record<string, unknown>,
  raw: unknown,
  view: CollectionView,
): CollectionHandoffReview & { definition: CollectionHandoffDefinition } {
  const v = object(raw);
  keys(v, [
    "schema_version",
    "profile",
    "collection",
    "input_id",
    "source_run",
    "intents",
    "workflow",
    "plan",
    "plan_hash",
    "authority_revision",
    "storage_id",
    "namespace_root",
  ]);
  const j = object(v.collection),
    r = object(v.source_run);
  keys(j, ["id", "revision", "definition_hash"]);
  keys(
    r,
    ["id", "revision", "plan_hash", "workflow"],
    ["routing_authorization_id"],
  );
  const before = asCollectionConfiguration(
    o.source_workflow,
    reference(r.workflow),
  );
  const after = asCollectionConfiguration(o.workflow, reference(v.workflow));
  const inputID = id(v, "input_id"),
    input = view.inputs.find((i) => i.id === inputID);
  const job = view.job,
    sourceFacts = asRoutingFacts(
      object(o.source_plan).facts,
      before.definition.source,
    );
  if (
    !input ||
    !input.run_id ||
    input.state !== "queued" ||
    input.first_job_id !== job.id ||
    !job.captured ||
    !job.manifest ||
    !job.manifest_hash ||
    !sourceFacts.source
  )
    bad();
  const index = job.manifest!.files.findIndex(
    (f) =>
      f.name === input!.source_name &&
      f.sha256 === input!.sha256 &&
      f.size_bytes === input!.size_bytes,
  );
  if (
    index < 0 ||
    sourceFacts.file.id !== input!.file_id ||
    sourceFacts.file.size_bytes !== input!.size_bytes ||
    sourceFacts.file.sha256 !== input!.sha256
  )
    bad();
  const facts = {
    file: sourceFacts.file,
    source: {
      collection_id: job.id,
      manifest_hash: job.manifest_hash!,
      name: input!.source_name,
      batch_id: job.manifest!.batch_id,
      file_count: job.manifest!.files.length,
      index,
    },
  };
  const sourcePlan = asExecutionPlan(
    o.source_plan,
    workflowProgramShape(before.definition),
    facts,
  );
  const plan = asExecutionPlan(
    v.plan,
    workflowProgramShape(after.definition),
    facts,
  );
  const d: CollectionHandoffDefinition = {
    schema_version: 1,
    profile: "untouched-collected-handoff-v1",
    collection: {
      id: id(j, "id"),
      revision: integer(j, "revision"),
      definition_hash: hash(j, "definition_hash"),
    },
    input_id: inputID,
    source_run: {
      id: id(r, "id"),
      revision: integer(r, "revision"),
      plan_hash: hash(r, "plan_hash"),
      workflow: reference(r.workflow),
      ...(r.routing_authorization_id !== undefined
        ? { routing_authorization_id: id(r, "routing_authorization_id") }
        : {}),
    },
    intents: list(v.intents, 16, 1).map((value) => {
      const i = object(value);
      keys(i, ["id", "revision", "definition_hash", "step_id", "ordinal"]);
      const step = text(i, "step_id", 64);
      if (!/^[a-z][a-z0-9_-]{0,63}$/.test(step)) bad();
      return {
        id: id(i, "id"),
        revision: integer(i, "revision"),
        definition_hash: hash(i, "definition_hash"),
        step_id: step,
        ordinal: integer(i, "ordinal", 1, 16),
      };
    }),
    workflow: reference(v.workflow),
    plan,
    plan_hash: hash(v, "plan_hash"),
    authority_revision: integer(v, "authority_revision"),
    storage_id: id(v, "storage_id"),
    namespace_root: "/",
  };
  if (
    v.schema_version !== 1 ||
    v.profile !== d.profile ||
    v.namespace_root !== "/" ||
    d.collection.id !== job.id ||
    d.collection.definition_hash !== job.definition_hash ||
    d.collection.revision > job.revision ||
    d.authority_revision !== job.definition.authority_revision ||
    d.storage_id !== job.definition.storage_id ||
    before.id !== job.workflow_id ||
    after.id !== job.workflow_id ||
    equal(d.source_run.workflow, d.workflow) ||
    !["approved", "revoked"].includes(before.state) ||
    !["approved", "revoked"].includes(after.state) ||
    !equal(before.definition.source, job.definition.source) ||
    !equal(after.definition.source, job.definition.source) ||
    programFingerprint(sourcePlan) !== d.source_run.plan_hash ||
    programFingerprint(plan) !== d.plan_hash ||
    d.intents.length !== sourcePlan.selected_steps.length ||
    new Set(d.intents.map((i) => i.id)).size !== d.intents.length ||
    d.intents.some(
      (i, index) =>
        i.ordinal !== index + 1 ||
        i.step_id !== sourcePlan.selected_steps[index],
    ) ||
    canonicalWorkflowBytes(d).length > 32768
  )
    bad();
  return {
    definition: d,
    source_workflow: before,
    source_plan: sourcePlan,
    source_effects: effects(o.source_effects, before),
    workflow: after,
    effects: effects(o.effects, after),
  };
}

function summary(v: unknown, view: CollectionView): HandoffSummary {
  const o = object(v);
  keys(o, [
    "id",
    "job_id",
    "input_id",
    "source_run_id",
    "planned_run_id",
    "definition",
    "definition_hash",
    "state",
    "revision",
    "approval_authority",
  ]);
  const state = text(o, "state", 16) as HandoffState;
  const result = {
    id: id(o, "id"),
    job_id: id(o, "job_id"),
    input_id: id(o, "input_id"),
    source_run_id: id(o, "source_run_id"),
    planned_run_id: id(o, "planned_run_id"),
    definition_hash: hash(o, "definition_hash"),
    state,
    revision: integer(o, "revision"),
    approval_authority: integer(o, "approval_authority", 0),
  };
  if (
    !["proposed", "approved", "cancelled", "completed"].includes(state) ||
    result.job_id !== view.job.id ||
    result.source_run_id === result.planned_run_id ||
    !view.inputs.some(
      (i) =>
        i.id === result.input_id && i.first_job_id === view.job.id && i.run_id,
    ) ||
    (state === "proposed" &&
      (result.revision !== 1 || result.approval_authority !== 0)) ||
    (state === "approved" &&
      (result.revision !== 2 || result.approval_authority < 1)) ||
    (state === "completed" &&
      (result.revision !== 3 || result.approval_authority < 1)) ||
    (state === "cancelled" &&
      !(
        (result.revision === 2 && result.approval_authority === 0) ||
        (result.revision === 3 && result.approval_authority > 0)
      ))
  )
    bad();
  return result;
}
function record(
  v: unknown,
  view: CollectionView,
  d: CollectionHandoffDefinition,
): CollectionHandoffRecord {
  const s = summary(v, view);
  if (
    s.input_id !== d.input_id ||
    s.source_run_id !== d.source_run.id ||
    s.definition_hash !== collectionHandoffHash(d) ||
    (s.approval_authority && s.approval_authority !== d.authority_revision)
  )
    bad();
  return { ...s, definition: d };
}
export function handoffSelection(
  d: CollectionHandoffDefinition,
): CollectionHandoffSelection {
  return {
    input_id: d.input_id,
    source_run_id: d.source_run.id,
    workflow: d.workflow,
    expected_authority_revision: d.authority_revision,
  };
}
export function asCollectionHandoffPreview(
  v: unknown,
  view: CollectionView,
  selection: CollectionHandoffSelection,
): CollectionHandoffPreview {
  const o = object(v);
  keys(o, [
    ...reviewKeys,
    "definition",
    "definition_hash",
    "external_contact",
    "approval_required",
  ]);
  const review = reviewAndDefinition(o, o.definition, view),
    hashValue = hash(o, "definition_hash");
  if (
    !equal(handoffSelection(review.definition), selection) ||
    collectionHandoffHash(review.definition) !== hashValue ||
    o.external_contact !== false ||
    o.approval_required !== true ||
    review.workflow.state !== "approved" ||
    review.workflow.approval_authority !== selection.expected_authority_revision
  )
    bad();
  return {
    ...review,
    definition_hash: hashValue,
    external_contact: false,
    approval_required: true,
  };
}
export function asCollectionHandoffView(
  v: unknown,
  view: CollectionView,
  expectedID: string,
): CollectionHandoffView {
  const o = object(v);
  keys(o, [...reviewKeys, "handoff", "current_bindings", "binding_reason"]);
  const review = reviewAndDefinition(o, object(o.handoff).definition, view),
    h = record(o.handoff, view, review.definition);
  const current = o.current_bindings,
    reason = text(o, "binding_reason", 24);
  if (
    h.id !== expectedID ||
    typeof current !== "boolean" ||
    (h.state === "completed" || h.state === "cancelled"
      ? current || reason !== h.state
      : reason !== (current ? "current" : "binding_changed")) ||
    (current &&
      (review.workflow.state !== "approved" ||
        !view.current_authority ||
        review.workflow.approval_authority !== h.definition.authority_revision))
  )
    bad();
  const { definition: _definition, ...metadata } = review;
  return {
    ...metadata,
    handoff: h,
    current_bindings: current as boolean,
    binding_reason: reason as CollectionHandoffView["binding_reason"],
  };
}
export function asCollectionHandoffResult(
  v: unknown,
  view: CollectionView,
  review: CollectionHandoffReview,
  expected: {
    hash: string;
    state: HandoffState;
    revision: number;
    id?: string;
  },
): {
  resource: {
    kind: "workflow_collection_handoff";
    handoff: CollectionHandoffRecord;
  };
  replayed: boolean;
} {
  const o = object(v);
  keys(o, ["resource", "replayed"]);
  const resource = object(o.resource);
  keys(resource, ["kind", "handoff"]);
  const d = reviewAndDefinition(
    review as unknown as Record<string, unknown>,
    object(resource.handoff).definition,
    view,
  ).definition;
  const h = record(resource.handoff, view, d);
  if (
    typeof o.replayed !== "boolean" ||
    resource.kind !== "workflow_collection_handoff" ||
    h.definition_hash !== expected.hash ||
    h.state !== expected.state ||
    h.revision !== expected.revision ||
    (expected.id && h.id !== expected.id)
  )
    bad();
  return {
    resource: { kind: "workflow_collection_handoff", handoff: h },
    replayed: o.replayed as boolean,
  };
}
export function asCollectionHandoffHistory(
  v: unknown,
  view: CollectionView,
  after = "",
  limit = 20,
): { handoffs: HandoffSummary[]; next?: string } {
  const o = object(v);
  keys(o, ["handoffs"], ["next"]);
  const handoffs = list(o.handoffs, limit).map((v) => summary(v, view));
  if (
    handoffs.some(
      (h, index) => h.id <= (index ? handoffs[index - 1]!.id : after),
    )
  )
    bad();
  const next = o.next === undefined ? undefined : id(o, "next");
  if (next && (handoffs.length !== limit || next !== handoffs.at(-1)!.id))
    bad();
  return { handoffs, ...(next ? { next } : {}) };
}
