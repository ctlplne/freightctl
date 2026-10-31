import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  canonicalWorkflowBytes,
  asWorkflowReference,
  asWorkflowEffect,
  type ScheduleEffect,
  type Reference,
} from "./schedules-types";
import {
  asCollectionJob,
  asCollectionConfiguration,
  effectsForWorkflow,
  workflowProgramShape,
  type CollectionView,
  type WorkflowConfiguration,
  type CollectionRunPreview,
} from "./collections-types";
import {
  asRoutingFacts,
  asExecutionPlan,
  programFingerprint,
} from "./programs-types";

export interface RoutingDecisionReference {
  id: string;
  version: number;
  definition_hash: string;
  revision: number;
}
export interface CapturedRoutingDefinition {
  schema_version: 1;
  collection: { id: string; revision: number; definition_hash: string };
  original_workflow: Reference;
  workflow: Reference;
  manifest_hash: string;
  authority_revision: number;
  storage_id: string;
  namespace_root: "/";
  inputs: { input_id: string; file_id: string; plan_hash: string }[];
  previous?: RoutingDecisionReference;
}
export interface CapturedRoutingSelection {
  collection: { definition_hash: string; expected_revision: number };
  workflow: Reference;
  expected_authority_revision: number;
}
export type CapturedRoutingState =
  "proposed" | "approved" | "revoked" | "withdrawn";
export interface CapturedRoutingRecord {
  id: string;
  job_id: string;
  version: number;
  definition: CapturedRoutingDefinition;
  definition_hash: string;
  state: CapturedRoutingState;
  revision: number;
  approval_authority: number;
}
export interface CapturedRoutingPreview {
  definition: CapturedRoutingDefinition;
  definition_hash: string;
  external_contact: false;
  approval_required: true;
}

export interface CapturedRoutingMetadata {
  authorization: CapturedRoutingRecord | null;
  workflow?: WorkflowConfiguration;
  effects: ScheduleEffect[];
  current_authority: boolean;
  proposal?: CapturedRoutingRecord;
}

export function asCapturedRoutingMetadata(
  v: unknown,
  view: CollectionView,
  expectedID?: string,
): CapturedRoutingMetadata {
  const o = object(v);
  keys(
    o,
    ["authorization", "effects", "current_authority"],
    ["workflow", "proposal"],
  );
  if (typeof o.current_authority !== "boolean") bad();
  const proposal =
    o.proposal === undefined
      ? undefined
      : asCapturedRoutingRecord(o.proposal, view);
  if (proposal && proposal.state !== "proposed") bad();
  if (o.authorization === null) {
    if (
      expectedID ||
      o.workflow !== undefined ||
      list(o.effects, 0).length ||
      o.current_authority
    )
      bad();
    return {
      authorization: null,
      effects: [],
      current_authority: false,
      ...(proposal ? { proposal } : {}),
    };
  }
  const authorization = asCapturedRoutingRecord(
      o.authorization,
      view,
      expectedID,
    ),
    workflow = asCollectionConfiguration(
      o.workflow,
      authorization.definition.workflow,
    );
  asCapturedRoutingDefinition(authorization.definition, view, workflow);
  const effects = effectsForWorkflow(o.effects, workflow.definition);
  if (
    proposal &&
    (proposal.id === authorization.id ||
      proposal.version <= authorization.version)
  )
    bad();
  if (
    o.current_authority &&
    (!view.current_authority ||
      authorization.state !== "approved" ||
      workflow.state !== "approved" ||
      workflow.approval_authority !==
        authorization.definition.authority_revision)
  )
    bad();
  return {
    authorization,
    workflow,
    effects,
    current_authority: o.current_authority as boolean,
    ...(proposal ? { proposal } : {}),
  };
}
const bad = (): never => {
  throw new ApiError("invalid_captured_routing", 502);
};
function keys(
  o: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) {
  if (
    required.some((k) => !(k in o)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
}
function integer(
  o: Record<string, unknown>,
  k: string,
  min = 1,
  max = Number.MAX_SAFE_INTEGER,
): number {
  const v = o[k];
  if (!Number.isSafeInteger(v) || (v as number) < min || (v as number) > max)
    bad();
  return v as number;
}
function id(o: Record<string, unknown>, k: string): string {
  if (typeof o[k] !== "string" || !uuid(o[k] as string)) bad();
  return o[k] as string;
}
function hash(o: Record<string, unknown>, k: string): string {
  if (typeof o[k] !== "string" || !/^[0-9a-f]{64}$/.test(o[k] as string)) bad();
  return o[k] as string;
}
function list(v: unknown, max: number, min = 0): unknown[] {
  if (!Array.isArray(v) || v.length < min || v.length > max) bad();
  return v as unknown[];
}
function reference(v: unknown): Reference {
  const o = object(v);
  keys(o, ["id", "version", "hash"]);
  const r = asWorkflowReference(o);
  if (r.version > 2147483647) bad();
  return r;
}
const equal = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
function previous(v: unknown): RoutingDecisionReference {
  const o = object(v);
  keys(o, ["id", "version", "definition_hash", "revision"]);
  return {
    id: id(o, "id"),
    version: integer(o, "version", 1, 2147483647),
    definition_hash: hash(o, "definition_hash"),
    revision: integer(o, "revision"),
  };
}
export const capturedRoutingHash = (d: CapturedRoutingDefinition): string =>
  digestBytes(canonicalWorkflowBytes(d));

export function asCapturedRoutingDefinition(
  v: unknown,
  view?: CollectionView,
  target?: WorkflowConfiguration,
): CapturedRoutingDefinition {
  const o = object(v);
  keys(
    o,
    [
      "schema_version",
      "collection",
      "original_workflow",
      "workflow",
      "manifest_hash",
      "authority_revision",
      "storage_id",
      "namespace_root",
      "inputs",
    ],
    ["previous"],
  );
  const j = object(o.collection);
  keys(j, ["id", "revision", "definition_hash"]);
  if (o.schema_version !== 1 || o.namespace_root !== "/") bad();
  const d: CapturedRoutingDefinition = {
    schema_version: 1,
    collection: {
      id: id(j, "id"),
      revision: integer(j, "revision"),
      definition_hash: hash(j, "definition_hash"),
    },
    original_workflow: reference(o.original_workflow),
    workflow: reference(o.workflow),
    manifest_hash: hash(o, "manifest_hash"),
    authority_revision: integer(o, "authority_revision"),
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    inputs: list(o.inputs, 64, 1).map((v) => {
      const i = object(v);
      keys(i, ["input_id", "file_id", "plan_hash"]);
      return {
        input_id: id(i, "input_id"),
        file_id: id(i, "file_id"),
        plan_hash: hash(i, "plan_hash"),
      };
    }),
    ...(o.previous !== undefined ? { previous: previous(o.previous) } : {}),
  };
  if (
    d.original_workflow.id !== d.workflow.id ||
    new Set(d.inputs.map((i) => i.input_id)).size !== d.inputs.length ||
    new Set(d.inputs.map((i) => i.file_id)).size !== d.inputs.length ||
    canonicalWorkflowBytes(d).length > 24576
  )
    bad();
  if (view) {
    const job = asCollectionJob(view.job),
      owned = view.inputs.filter((i) => i.first_job_id === job.id);
    if (
      !job.captured ||
      !job.manifest_hash ||
      d.collection.id !== job.id ||
      d.collection.definition_hash !== job.definition_hash ||
      d.collection.revision > job.revision ||
      !equal(d.original_workflow, job.definition.workflow) ||
      d.manifest_hash !== job.manifest_hash ||
      d.authority_revision !== job.definition.authority_revision ||
      d.storage_id !== job.definition.storage_id ||
      d.namespace_root !== job.definition.namespace_root ||
      owned.length !== d.inputs.length
    )
      bad();
    d.inputs.forEach((b, index) => {
      const input = owned[index]!;
      if (b.input_id !== input.id || b.file_id !== input.file_id) bad();
    });
  }
  if (target) {
    const wf = asCollectionConfiguration(target, d.workflow);
    if (
      wf.definition.schema_version !== 2 ||
      (view && !equal(wf.definition.source, view.job.definition.source))
    )
      bad();
  }
  return d;
}

export function asCapturedRoutingRecord(
  v: unknown,
  view?: CollectionView,
  expectedID?: string,
): CapturedRoutingRecord {
  const o = object(v);
  keys(o, [
    "id",
    "job_id",
    "version",
    "definition",
    "definition_hash",
    "state",
    "revision",
    "approval_authority",
  ]);
  if (
    !["proposed", "approved", "revoked", "withdrawn"].includes(
      o.state as string,
    )
  )
    bad();
  const r: CapturedRoutingRecord = {
    id: id(o, "id"),
    job_id: id(o, "job_id"),
    version: integer(o, "version", 1, 2147483647),
    definition: asCapturedRoutingDefinition(o.definition, view),
    definition_hash: hash(o, "definition_hash"),
    state: o.state as CapturedRoutingState,
    revision: integer(o, "revision"),
    approval_authority: integer(o, "approval_authority", 0),
  };
  const revisions = { proposed: 1, approved: 2, revoked: 3, withdrawn: 2 };
  if (
    (expectedID && r.id !== expectedID) ||
    r.job_id !== r.definition.collection.id ||
    capturedRoutingHash(r.definition) !== r.definition_hash ||
    r.revision !== revisions[r.state] ||
    r.approval_authority !==
      (["approved", "revoked"].includes(r.state)
        ? r.definition.authority_revision
        : 0) ||
    (r.definition.previous &&
      (r.definition.previous.version >= r.version ||
        r.definition.previous.id === r.id))
  )
    bad();
  return r;
}

export function asCapturedRoutingPreview(
  v: unknown,
  view: CollectionView,
  selection: CapturedRoutingSelection,
  target: WorkflowConfiguration,
  prior: CapturedRoutingRecord | null,
): CapturedRoutingPreview {
  const o = object(v);
  keys(o, [
    "definition",
    "definition_hash",
    "external_contact",
    "approval_required",
  ]);
  const d = asCapturedRoutingDefinition(o.definition, view, target),
    fingerprint = hash(o, "definition_hash");
  const priorRecord = prior ? asCapturedRoutingRecord(prior, view) : null;
  if (priorRecord && !["approved", "revoked"].includes(priorRecord.state))
    bad();
  const expectedPrior = priorRecord
    ? {
        id: priorRecord.id,
        version: priorRecord.version,
        definition_hash: priorRecord.definition_hash,
        revision: priorRecord.revision,
      }
    : undefined;
  if (
    o.external_contact !== false ||
    o.approval_required !== true ||
    fingerprint !== capturedRoutingHash(d) ||
    d.collection.revision !== view.job.revision ||
    d.collection.definition_hash !== selection.collection.definition_hash ||
    d.collection.revision !== selection.collection.expected_revision ||
    !equal(d.workflow, reference(selection.workflow)) ||
    d.authority_revision !== selection.expected_authority_revision ||
    !equal(d.previous, expectedPrior) ||
    !view.current_authority ||
    view.job.state !== "captured" ||
    target.state !== "approved" ||
    target.approval_authority !== d.authority_revision
  )
    bad();
  const owned = view.inputs.filter((i) => i.first_job_id === view.job.id);
  if (
    owned.some(
      (i) =>
        i.state !== "accepted" ||
        i.run_id !== null ||
        view.local_states.find((s) => s.input_id === i.id)?.state !==
          "published",
    )
  )
    bad();
  return {
    definition: d,
    definition_hash: fingerprint,
    external_contact: false,
    approval_required: true,
  };
}

export function asCapturedRoutingInputPreview(
  v: unknown,
  inputID: string,
  view: CollectionView,
  target: WorkflowConfiguration,
  authorization: CapturedRoutingDefinition,
): CollectionRunPreview {
  const d = asCapturedRoutingDefinition(authorization, view, target),
    input = view.inputs.find(
      (i) => i.id === inputID && i.first_job_id === view.job.id,
    ),
    binding = d.inputs.find((b) => b.input_id === inputID);
  if (!input || !binding || !input.file_id) bad();
  const o = object(v);
  keys(o, [
    "workflow",
    "source",
    "potential_effects",
    "selected_effects",
    "execution_plan",
    "execution_plan_hash",
    "external_contact",
  ]);
  const job = asCollectionJob(view.job),
    manifest = job.manifest;
  if (!manifest || !job.manifest_hash) bad();
  const index = manifest!.files.findIndex(
    (f) =>
      f.name === input!.source_name &&
      f.size_bytes === input!.size_bytes &&
      f.sha256 === input!.sha256,
  );
  const file = asRoutingFacts({ file: o.source }).file;
  if (
    index < 0 ||
    o.external_contact !== false ||
    !equal(reference(o.workflow), d.workflow) ||
    file.id !== input!.file_id ||
    file.size_bytes !== input!.size_bytes ||
    file.sha256 !== input!.sha256
  )
    bad();
  const facts = {
    file,
    source: {
      collection_id: job.id,
      manifest_hash: job.manifest_hash!,
      name: input!.source_name,
      batch_id: manifest!.batch_id,
      file_count: manifest!.files.length,
      index,
    },
  };
  const plan = asExecutionPlan(
      o.execution_plan,
      workflowProgramShape(target.definition),
      facts,
    ),
    fingerprint = hash(o, "execution_plan_hash"),
    potential = effectsForWorkflow(o.potential_effects, target.definition);
  // The approval's fingerprint and the browser's independent compilation must
  // both agree. A self-consistent replacement hash cannot change original facts.
  const selected = list(o.selected_effects, 16).map(asWorkflowEffect);
  if (
    programFingerprint(plan) !== fingerprint ||
    binding!.plan_hash !== fingerprint ||
    !equal(
      selected,
      plan.selected_steps.map((id) => potential.find((e) => e.step_id === id)),
    )
  )
    bad();
  return {
    workflow: d.workflow,
    source: file,
    potential_effects: potential,
    selected_effects: plan.selected_steps.map((id) =>
      potential.find((e) => e.step_id === id)!,
    ),
    execution_plan: plan,
    execution_plan_hash: fingerprint,
    external_contact: false,
  };
}

export function asCapturedRoutingResult(
  v: unknown,
  expected: {
    job: string;
    hash: string;
    state: CapturedRoutingState;
    revision: number;
    id?: string;
    version?: number;
  },
): {
  resource: {
    kind: "workflow_collection_routing";
    id: string;
    job_id: string;
    version: number;
    definition_hash: string;
    state: CapturedRoutingState;
    revision: number;
  };
  replayed: boolean;
} {
  const o = object(v);
  keys(o, ["resource", "replayed"]);
  const a = object(o.resource);
  keys(a, [
    "kind",
    "id",
    "job_id",
    "version",
    "definition_hash",
    "state",
    "revision",
  ]);
  const result = {
    kind: "workflow_collection_routing" as const,
    id: id(a, "id"),
    job_id: id(a, "job_id"),
    version: integer(a, "version", 1, 2147483647),
    definition_hash: hash(a, "definition_hash"),
    state: a.state as CapturedRoutingState,
    revision: integer(a, "revision"),
  };
  if (
    a.kind !== result.kind ||
    result.job_id !== expected.job ||
    result.definition_hash !== expected.hash ||
    result.state !== expected.state ||
    result.revision !== expected.revision ||
    (expected.id && result.id !== expected.id) ||
    (expected.version !== undefined && result.version !== expected.version) ||
    typeof o.replayed !== "boolean"
  )
    bad();
  return { resource: result, replayed: o.replayed as boolean };
}

export function asCapturedRoutingHistory(
  v: unknown,
  view: CollectionView,
  after = 0,
  limit = 20,
): { authorizations: CapturedRoutingRecord[]; next?: number } {
  const o = object(v);
  keys(o, ["authorizations"], ["next"]);
  if (
    !Number.isSafeInteger(after) ||
    after < 0 ||
    after > 2147483647 ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100
  )
    bad();
  const records = list(o.authorizations, limit).map((r) =>
    asCapturedRoutingRecord(r, view),
  );
  if (
    new Set(records.map((r) => r.id)).size !== records.length ||
    records.some((r, i) => r.version <= (i ? records[i - 1]!.version : after))
  )
    bad();
  const next =
    o.next !== undefined ? integer(o, "next", 1, 2147483647) : undefined;
  if (
    next !== undefined &&
    (records.length !== limit || next !== records[records.length - 1]!.version)
  )
    bad();
  return { authorizations: records, ...(next !== undefined ? { next } : {}) };
}
