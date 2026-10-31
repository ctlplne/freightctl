import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  asRecordedTest,
  asTestEffect,
  type RecordedTest,
  type TestDefinition,
  type TestEffect,
} from "./onboarding-tests-types";
import type { OnboardingPlan } from "./onboarding-types";
import type { ProbeReference } from "./onboarding-probes-types";
export interface ReleaseSelection {
  plan: ProbeReference;
  test_ids: string[];
  expected_authority_revision: number;
}
export interface ReleaseProof {
  requirement_id: string;
  test_id: string;
  test_hash: string;
  snapshot_hash: string;
  delivery_id: string;
  delivery_revision: number;
  receipt_hash: string;
}
export interface ReleaseDefinition {
  schema_version: 1;
  profile: "sftp-outbound-production-v1";
  plan: ProbeReference;
  authority_revision: number;
  storage_id: string;
  namespace_root: "/";
  proofs: ReleaseProof[];
}
export interface ReleaseSummary {
  id: string;
  plan: ProbeReference;
  author_id: string;
  definition_hash: string;
  state: "proposed" | "approved" | "active" | "suspended" | "revoked";
  revision: number;
  approved_revision: number;
  created_at: string;
  changed_event_id: string;
}
export interface ReleasePreview {
  definition: ReleaseDefinition;
  definition_hash: string;
  tests: RecordedTest[];
  external_contact: false;
  production_active: false;
}
export interface ReleaseView {
  release: ReleaseSummary & { definition: ReleaseDefinition };
  tests: RecordedTest[];
  current_bindings: boolean;
  binding_reason: "current" | "binding_changed";
  production_active: boolean;
}
export interface ProductionDefinition {
  schema_version: 1;
  release: { id: string; revision: number; hash: string };
  requirement_id: string;
  test_id: string;
  test_hash: string;
  workflow: ProbeReference;
  file: TestDefinition["file"];
  storage_id: string;
  namespace_root: "/";
  authority_revision: number;
  effect: TestEffect;
}
export interface ProductionPreview {
  definition: ProductionDefinition;
  definition_hash: string;
  external_contact: false;
}
function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}

function text(o: Record<string, unknown>, k: string, max: number): string {
  const v = o[k];
  if (
    typeof v !== "string" ||
    !v ||
    new TextEncoder().encode(v).length > max ||
    /[\u0000-\u001f\u007f-\u009f]/.test(v)
  )
    bad();
  return v as string;
}
function id(o: Record<string, unknown>, k: string): string {
  const s = text(o, k, 36);
  if (!uuid(s)) bad();
  return s;
}
function hash(o: Record<string, unknown>, k: string): string {
  const s = text(o, k, 64);
  if (!/^[a-f0-9]{64}$/.test(s)) bad();
  return s;
}
function num(o: Record<string, unknown>, k: string, min = 1): number {
  const n = o[k];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min) bad();
  return n as number;
}
function ref(v: unknown): ProbeReference {
  const o = object(v),
    version = num(o, "version");
  if (version > 2147483647) bad();
  return { id: id(o, "id"), version, hash: hash(o, "hash") };
}
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
export function releaseHash(
  d: ReleaseDefinition | ProductionDefinition,
): string {
  const bytes = new TextEncoder().encode(
    JSON.stringify(d).replace(
      /[<>&\u2028\u2029]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    ),
  );
  try {
    return digestBytes(bytes);
  } finally {
    bytes.fill(0);
  }
}
function definition(value: unknown, plan: OnboardingPlan): ReleaseDefinition {
  const o = object(value);
  if (
    o.schema_version !== 1 ||
    o.profile !== "sftp-outbound-production-v1" ||
    o.namespace_root !== "/" ||
    !Array.isArray(o.proofs) ||
    o.proofs.length !== plan.definition.requirements.length ||
    o.proofs.length < 1 ||
    o.proofs.length > 64
  )
    bad();
  const proofs = (o.proofs as unknown[]).map((v, i) => {
    const p = object(v),
      r = plan.definition.requirements[i];
    if (
      !r ||
      r.direction !== "send" ||
      r.protocol !== "sftp" ||
      r.required_receipt === "business" ||
      p.requirement_id !== r.id
    )
      bad();
    return {
      requirement_id: id(p, "requirement_id"),
      test_id: id(p, "test_id"),
      test_hash: hash(p, "test_hash"),
      snapshot_hash: hash(p, "snapshot_hash"),
      delivery_id: id(p, "delivery_id"),
      delivery_revision: num(p, "delivery_revision"),
      receipt_hash: hash(p, "receipt_hash"),
    };
  });
  if (
    new Set(proofs.map((p) => p.test_id)).size !== proofs.length ||
    new Set(proofs.map((p) => p.requirement_id)).size !== proofs.length
  )
    bad();
  const d: ReleaseDefinition = {
    schema_version: 1,
    profile: "sftp-outbound-production-v1",
    plan: ref(o.plan),
    authority_revision: num(o, "authority_revision"),
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    proofs,
  };
  if (
    !same(d.plan, {
      id: plan.id,
      version: plan.version,
      hash: plan.definition_hash,
    })
  )
    bad();
  return d;
}
function tests(
  value: unknown,
  d: ReleaseDefinition,
  author: string,
): RecordedTest[] {
  if (!Array.isArray(value) || value.length !== d.proofs.length) bad();
  return (value as unknown[]).map((v, i) => {
    const p = d.proofs[i];
    if (!p) bad();
    const t = asRecordedTest(v, author, { id: p.test_id, hash: p.test_hash });
    if (
      t.definition.requirement_id !== p.requirement_id ||
      !same(t.definition.plan, d.plan) ||
      t.definition.authority_revision !== d.authority_revision ||
      t.definition.storage_id !== d.storage_id ||
      t.definition.namespace_root !== d.namespace_root
    )
      bad();
    return t;
  });
}
export function asReleasePreview(
  value: unknown,
  plan: OnboardingPlan,
  selection: ReleaseSelection,
  author: string,
): ReleasePreview {
  const o = object(value),
    d = definition(o.definition, plan),
    h = hash(o, "definition_hash"),
    ts = tests(o.tests, d, author);
  if (
    h !== releaseHash(d) ||
    !same(d.plan, selection.plan) ||
    d.authority_revision !== selection.expected_authority_revision ||
    !same(
      [...d.proofs.map((p) => p.test_id)].sort(),
      [...selection.test_ids].sort(),
    ) ||
    o.external_contact !== false ||
    o.production_active !== false
  )
    bad();
  return {
    definition: d,
    definition_hash: h,
    tests: ts,
    external_contact: false,
    production_active: false,
  };
}
function summary(
  value: unknown,
  author: string,
  planID: string,
): ReleaseSummary {
  const o = object(value),
    state = text(o, "state", 16),
    revision = num(o, "revision"),
    approved = num(o, "approved_revision", 0),
    plan = ref(o.plan),
    created = text(o, "created_at", 64);
  if (
    !["proposed", "approved", "active", "suspended", "revoked"].includes(
      state,
    ) ||
    approved > revision ||
    !/^\d{4}-\d{2}-\d{2}T.*Z$/.test(created) ||
    !Number.isFinite(Date.parse(created)) ||
    plan.id !== planID ||
    o.author_id !== author
  )
    bad();
  if (
    (state === "proposed" && (revision !== 1 || approved !== 0)) ||
    (state === "approved" && (revision !== 2 || approved !== 2)) ||
    (["active", "suspended"].includes(state) &&
      (approved !== 2 || revision < 3)) ||
    (state === "revoked" && revision < 2)
  )
    bad();
  return {
    id: id(o, "id"),
    plan,
    author_id: author,
    definition_hash: hash(o, "definition_hash"),
    state: state as ReleaseSummary["state"],
    revision,
    approved_revision: approved,
    created_at: created,
    changed_event_id: id(o, "changed_event_id"),
  };
}
export function asReleaseView(
  value: unknown,
  plan: OnboardingPlan,
  author: string,
  expected: { id: string; definition_hash: string },
): ReleaseView {
  const o = object(value),
    r = summary(o.release, author, plan.id),
    d = definition(object(o.release).definition, plan),
    ts = tests(o.tests, d, author);
  if (
    r.id !== expected.id ||
    r.definition_hash !== expected.definition_hash ||
    r.definition_hash !== releaseHash(d) ||
    !same(r.plan, d.plan) ||
    typeof o.current_bindings !== "boolean" ||
    o.binding_reason !== (o.current_bindings ? "current" : "binding_changed") ||
    o.production_active !== (o.current_bindings && r.state === "active")
  )
    bad();
  return {
    release: { ...r, definition: d },
    tests: ts,
    current_bindings: o.current_bindings as boolean,
    binding_reason: o.binding_reason as ReleaseView["binding_reason"],
    production_active: o.production_active as boolean,
  };
}
export function asReleasePage(
  value: unknown,
  author: string,
  plan: string,
): { releases: ReleaseSummary[]; next?: string } {
  const o = object(value);
  if (!Array.isArray(o.releases) || o.releases.length > 100) bad();
  const releases = (o.releases as unknown[]).map((v) =>
    summary(v, author, plan),
  );
  if (new Set(releases.map((r) => r.id)).size !== releases.length) bad();
  return { releases, ...(o.next === undefined ? {} : { next: id(o, "next") }) };
}
export function asReleaseResult(
  value: unknown,
  author: string,
  plan: OnboardingPlan,
  hash0: string,
  state: string,
  id0?: string,
): ReleaseSummary {
  const o = object(value),
    resource = object(o.resource);
  if (typeof o.replayed !== "boolean" || resource.kind !== "onboarding_release")
    bad();
  const r = summary(resource.release, author, plan.id);
  if (r.definition_hash !== hash0 || r.state !== state || (id0 && r.id !== id0))
    bad();
  return r;
}
function productionDefinition(
  value: unknown,
  view: ReleaseView,
  requirement: string,
  fileID: string,
  historical = false,
): ProductionDefinition {
  const o = object(value),
    a = object(o.release),
    file = object(o.file),
    p = view.release.definition.proofs.find(
      (p) => p.requirement_id === requirement,
    ),
    t = view.tests.find((t) => t.id === p?.test_id);
  if (
    !p ||
    !t ||
    (!historical && !view.production_active) ||
    o.schema_version !== 1 ||
    a.id !== view.release.id ||
    (historical
      ? num(a, "revision") < 3 || num(a, "revision") > view.release.revision
      : a.revision !== view.release.revision) ||
    a.hash !== view.release.definition_hash ||
    o.requirement_id !== requirement ||
    o.test_id !== t.id ||
    o.test_hash !== t.definition_hash ||
    o.storage_id !== view.release.definition.storage_id ||
    o.namespace_root !== "/" ||
    o.authority_revision !== view.release.definition.authority_revision ||
    file.id !== fileID
  )
    bad();
  const effect = asTestEffect(o.effect),
    workflow = ref(o.workflow);
  if (
    !same(effect, t.definition.effect) ||
    !same(workflow, t.definition.workflow)
  )
    bad();
  return {
    schema_version: 1,
    release: {
      id: id(a, "id"),
      revision: num(a, "revision"),
      hash: hash(a, "hash"),
    },
    requirement_id: id(o, "requirement_id"),
    test_id: id(o, "test_id"),
    test_hash: hash(o, "test_hash"),
    workflow,
    file: {
      id: id(file, "id"),
      size_bytes: num(file, "size_bytes", 0),
      sha256: hash(file, "sha256"),
      policy: text(file, "policy", 256),
      accepted_event_id: id(file, "accepted_event_id"),
    },
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    authority_revision: num(o, "authority_revision"),
    effect,
  };
}
export function asProductionPreview(
  value: unknown,
  view: ReleaseView,
  requirement: string,
  fileID: string,
): ProductionPreview {
  const o = object(value),
    d = productionDefinition(o.definition, view, requirement, fileID),
    h = hash(o, "definition_hash");
  if (h !== releaseHash(d) || o.external_contact !== false) bad();
  return { definition: d, definition_hash: h, external_contact: false };
}
export function asProductionResult(
  value: unknown,
  author: string,
  view: ReleaseView,
  review: ProductionPreview,
): { id: string; hash: string } {
  const o = object(value),
    resource = object(o.resource),
    dispatch = object(resource.dispatch),
    run = object(resource.run),
    expected = review.definition;
  if (
    typeof o.replayed !== "boolean" ||
    resource.kind !== "onboarding_production" ||
    dispatch.author_id !== author
  )
    bad();
  const d = productionDefinition(
      dispatch.definition,
      view,
      expected.requirement_id,
      expected.file.id,
    ),
    h = hash(dispatch, "definition_hash");
  if (
    h !== review.definition_hash ||
    !same(d, expected) ||
    h !== releaseHash(d) ||
    dispatch.id !== run.id ||
    run.workflow_id !== d.workflow.id ||
    run.workflow_version !== d.workflow.version ||
    run.workflow_hash !== d.workflow.hash ||
    run.file_id !== d.file.id ||
    !Object.entries(d.file).every(([k, v]) => object(run.source)[k] === v) ||
    run.storage_id !== d.storage_id ||
    run.namespace_root !== d.namespace_root ||
    run.authority_revision !== d.authority_revision ||
    run.state !== "queued" ||
    run.revision !== 1
  )
    bad();
  id(dispatch, "created_event_id");
  return { id: id(dispatch, "id"), hash: h };
}

export interface ProductionSummary {
  id: string;
  release: { id: string; revision: number; hash: string };
  requirement_id: string;
  file_id: string;
  definition_hash: string;
}
export interface ProductionStatus {
  state: string;
  reason: string;
  current: boolean;
  definition: ProductionDefinition;
  steps: {
    id: string;
    delivery_id: string;
    state: string;
    attempts: number;
    code: string;
  }[];
}
export function asProductionPage(
  value: unknown,
  view: ReleaseView,
): { dispatches: ProductionSummary[]; next?: string } {
  const o = object(value);
  if (!Array.isArray(o.dispatches) || o.dispatches.length > 100) bad();
  const dispatches = (o.dispatches as unknown[]).map((v) => {
    const d = object(v),
      a = object(d.release);
    if (
      a.id !== view.release.id ||
      a.hash !== view.release.definition_hash ||
      num(a, "revision") < 3 ||
      num(a, "revision") > view.release.revision ||
      !view.release.definition.proofs.some(
        (p) => p.requirement_id === d.requirement_id,
      )
    )
      bad();
    return {
      id: id(d, "id"),
      release: {
        id: id(a, "id"),
        revision: num(a, "revision"),
        hash: hash(a, "hash"),
      },
      requirement_id: id(d, "requirement_id"),
      file_id: id(d, "file_id"),
      definition_hash: hash(d, "definition_hash"),
    };
  });
  if (new Set(dispatches.map((d) => d.id)).size !== dispatches.length) bad();
  return {
    dispatches,
    ...(o.next === undefined ? {} : { next: id(o, "next") }),
  };
}
export function asProductionStatus(
  value: unknown,
  view: ReleaseView,
  expected: { id: string; hash: string },
  author: string,
): ProductionStatus {
  const o = object(value),
    dispatch = object(o.dispatch),
    raw = object(dispatch.definition),
    d = productionDefinition(
      raw,
      view,
      id(raw, "requirement_id"),
      id(object(raw.file), "id"),
      true,
    ),
    status = object(o.status),
    run = object(status.run);
  if (
    dispatch.id !== expected.id ||
    dispatch.author_id !== author ||
    dispatch.definition_hash !== expected.hash ||
    releaseHash(d) !== expected.hash ||
    run.id !== expected.id ||
    run.workflow_id !== d.workflow.id ||
    run.workflow_version !== d.workflow.version ||
    run.workflow_hash !== d.workflow.hash ||
    run.file_id !== d.file.id ||
    !Object.entries(d.file).every(([k, v]) => object(run.source)[k] === v) ||
    run.storage_id !== d.storage_id ||
    run.namespace_root !== d.namespace_root ||
    run.authority_revision !== d.authority_revision ||
    !["queued", "running", "attention", "succeeded", "cancelled"].includes(
      String(run.state),
    ) ||
    !["queued", "running", "attention", "succeeded", "cancelled"].includes(
      String(status.observed_state),
    ) ||
    !Array.isArray(status.steps) ||
    status.steps.length !== 1 ||
    typeof o.current_bindings !== "boolean" ||
    (o.current_bindings === true &&
      (!view.production_active || d.release.revision !== view.release.revision))
  )
    bad();
  num(run, "revision");
  id(dispatch, "created_event_id");
  const test = view.tests.find((t) => t.id === d.test_id);
  if (!test) bad();
  const steps = (status.steps as unknown[]).map((v) => {
    const s = object(v),
      obs = object(s.observation);
    if (
      s.id !== test.definition.step_id ||
      ![
        "queued",
        "staging",
        "publishing",
        "retry",
        "blocked",
        "ambiguous",
        "cancelled",
        "succeeded",
      ].includes(String(s.state)) ||
      num(s, "attempts", 0) > 8
    )
      bad();
    return {
      id: text(s, "id", 64),
      delivery_id: id(s, "delivery_id"),
      state: text(s, "state", 24),
      attempts: num(s, "attempts", 0),
      code:
        Object.keys(obs).length === 0
          ? "no observation recorded"
          : text(obs, "code", 128),
    };
  });
  return {
    state: text(status, "observed_state", 24),
    reason: text(status, "observed_reason", 64),
    current: o.current_bindings as boolean,
    definition: d,
    steps,
  };
}
