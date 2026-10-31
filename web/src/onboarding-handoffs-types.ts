import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import { asTestEffect, type TestDefinition } from "./onboarding-tests-types";
import type { ProductionDefinition } from "./onboarding-releases-types";
import type { ProbeReference } from "./onboarding-probes-types";
export interface HandoffSelection {
  source_run_id: string;
  source_hash: string;
  target_release: { id: string; revision: number; hash: string };
  file_id: string;
}
export interface HandoffDefinition {
  schema_version: 1;
  profile: "untouched-production-handoff-v1";
  source: {
    dispatch: {
      id: string;
      author_id: string;
      definition: ProductionDefinition;
      definition_hash: string;
      created_event_id: string;
    };
    plan: ProbeReference;
    run_revision: number;
    delivery: { id: string; revision: number; hash: string };
    state: "queued";
    attempts: 0;
    fence: 0;
  };
  target: ProductionDefinition;
  target_hash: string;
  source_recheck_id: string;
}
export interface HandoffPreview {
  definition: HandoffDefinition;
  definition_hash: string;
  external_contact: false;
}
export interface HandoffSummary {
  id: string;
  author_id: string;
  source_run_id: string;
  target_release: { id: string; revision: number; hash: string };
  definition_hash: string;
  state: "proposed" | "approved" | "cancelled" | "completed";
  revision: number;
  replacement_run_id: string;
  created_at: string;
  changed_event_id: string;
}
export interface HandoffView {
  handoff: HandoffSummary & { definition: HandoffDefinition };
  current_bindings: boolean;
  binding_reason: "current" | "binding_changed" | "cancelled" | "completed";
  external_contact: false;
}
function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}
function text(
  o: Record<string, unknown>,
  k: string,
  n: number,
  empty = false,
): string {
  const s = o[k];
  if (
    typeof s !== "string" ||
    (!s && !empty) ||
    new TextEncoder().encode(s).length > n ||
    /[\u0000-\u001f\u007f-\u009f]/.test(s) ||
    /[\ud800-\udfff]/u.test(s)
  )
    bad();
  return s as string;
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
function activation(v: unknown): {
  id: string;
  revision: number;
  hash: string;
} {
  const o = object(v);
  return {
    id: id(o, "id"),
    revision: num(o, "revision"),
    hash: hash(o, "hash"),
  };
}
function file(v: unknown): TestDefinition["file"] {
  const o = object(v);
  return {
    id: id(o, "id"),
    size_bytes: num(o, "size_bytes", 0),
    sha256: hash(o, "sha256"),
    policy: text(o, "policy", 256),
    accepted_event_id: id(o, "accepted_event_id"),
  };
}
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
export function handoffHash(
  d: HandoffDefinition | ProductionDefinition,
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
function dispatch(value: unknown): ProductionDefinition {
  const o = object(value);
  if (o.schema_version !== 1 || o.namespace_root !== "/") bad();
  return {
    schema_version: 1,
    release: activation(o.release),
    requirement_id: id(o, "requirement_id"),
    test_id: id(o, "test_id"),
    test_hash: hash(o, "test_hash"),
    workflow: ref(o.workflow),
    file: file(o.file),
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    authority_revision: num(o, "authority_revision"),
    effect: asTestEffect(o.effect),
  };
}
export function asHandoffDefinition(
  value: unknown,
  author: string,
  planID: string,
): HandoffDefinition {
  const o = object(value),
    s = object(o.source),
    raw = object(s.dispatch),
    before = dispatch(raw.definition),
    target = dispatch(o.target),
    plan = ref(s.plan),
    recheck = text(o, "source_recheck_id", 36, true),
    a = before.effect,
    b = target.effect;
  if (
    o.schema_version !== 1 ||
    o.profile !== "untouched-production-handoff-v1" ||
    s.state !== "queued" ||
    s.attempts !== 0 ||
    s.fence !== 0 ||
    raw.author_id !== author ||
    plan.id !== planID ||
    raw.definition_hash !== handoffHash(before) ||
    o.target_hash !== handoffHash(target) ||
    before.requirement_id !== target.requirement_id ||
    before.workflow.id !== target.workflow.id ||
    before.storage_id !== target.storage_id ||
    before.namespace_root !== target.namespace_root ||
    before.file.sha256 !== target.file.sha256 ||
    before.file.size_bytes !== target.file.size_bytes ||
    a.address !== b.address ||
    a.user !== b.user ||
    a.directory !== b.directory ||
    a.filename !== b.filename ||
    Boolean(a.encryption) !== Boolean(b.encryption) ||
    a.encryption?.profile !== b.encryption?.profile ||
    (same(before.release, target.release) && same(before.file, target.file)) ||
    (before.file.id === target.file.id
      ? !same(before.file, target.file) || recheck !== ""
      : !uuid(recheck))
  )
    bad();
  return {
    schema_version: 1,
    profile: "untouched-production-handoff-v1",
    source: {
      dispatch: {
        id: id(raw, "id"),
        author_id: author,
        definition: before,
        definition_hash: hash(raw, "definition_hash"),
        created_event_id: id(raw, "created_event_id"),
      },
      plan,
      run_revision: num(s, "run_revision"),
      delivery: activation(s.delivery),
      state: "queued",
      attempts: 0,
      fence: 0,
    },
    target,
    target_hash: hash(o, "target_hash"),
    source_recheck_id: recheck,
  };
}
export function asHandoffPreview(
  value: unknown,
  selection: HandoffSelection,
  author: string,
  plan: string,
): HandoffPreview {
  const o = object(value),
    d = asHandoffDefinition(o.definition, author, plan),
    h = hash(o, "definition_hash");
  if (
    d.source.dispatch.id !== selection.source_run_id ||
    d.source.dispatch.definition_hash !== selection.source_hash ||
    !same(d.target.release, selection.target_release) ||
    d.target.file.id !== selection.file_id ||
    h !== handoffHash(d) ||
    o.external_contact !== false
  )
    bad();
  return { definition: d, definition_hash: h, external_contact: false };
}
function summary(value: unknown, author: string): HandoffSummary {
  const o = object(value),
    state = text(o, "state", 16),
    revision = num(o, "revision"),
    next = text(o, "replacement_run_id", 36, true),
    created = text(o, "created_at", 64);
  if (
    o.author_id !== author ||
    !["proposed", "approved", "cancelled", "completed"].includes(state) ||
    (state === "proposed" && revision !== 1) ||
    (state === "approved" && revision !== 2) ||
    (state === "completed" &&
      (revision !== 3 || !uuid(next) || next === o.source_run_id)) ||
    (state === "cancelled" && ![2, 3].includes(revision)) ||
    (state !== "completed" && next !== "") ||
    !/^\d{4}-\d{2}-\d{2}T.*Z$/.test(created) ||
    !Number.isFinite(Date.parse(created))
  )
    bad();
  return {
    id: id(o, "id"),
    author_id: author,
    source_run_id: id(o, "source_run_id"),
    target_release: activation(o.target_release),
    definition_hash: hash(o, "definition_hash"),
    state: state as HandoffSummary["state"],
    revision,
    replacement_run_id: next,
    created_at: created,
    changed_event_id: id(o, "changed_event_id"),
  };
}
export function asHandoffResult(
  value: unknown,
  author: string,
  expected: {
    hash: string;
    state: string;
    source: string;
    target: HandoffSelection["target_release"];
    id?: string;
  },
): HandoffSummary {
  const o = object(value),
    resource = object(o.resource);
  if (typeof o.replayed !== "boolean" || resource.kind !== "onboarding_handoff")
    bad();
  const h = summary(resource.handoff, author);
  if (
    h.definition_hash !== expected.hash ||
    h.state !== expected.state ||
    h.source_run_id !== expected.source ||
    !same(h.target_release, expected.target) ||
    (expected.id && h.id !== expected.id)
  )
    bad();
  return h;
}
export function asHandoffView(
  value: unknown,
  author: string,
  plan: string,
  expected: { id: string; hash: string },
): HandoffView {
  const o = object(value),
    h = summary(o.handoff, author),
    d = asHandoffDefinition(object(o.handoff).definition, author, plan);
  if (
    h.id !== expected.id ||
    h.definition_hash !== expected.hash ||
    h.definition_hash !== handoffHash(d) ||
    h.source_run_id !== d.source.dispatch.id ||
    !same(h.target_release, d.target.release) ||
    typeof o.current_bindings !== "boolean" ||
    o.external_contact !== false
  )
    bad();
  let reason: string;
  if (h.state === "completed" || h.state === "cancelled") {
    reason = h.state;
    if (o.current_bindings !== false) bad();
  } else reason = o.current_bindings ? "current" : "binding_changed";
  if (o.binding_reason !== reason) bad();
  return {
    handoff: { ...h, definition: d },
    current_bindings: o.current_bindings as boolean,
    binding_reason: reason as HandoffView["binding_reason"],
    external_contact: false,
  };
}
export function asHandoffPage(
  value: unknown,
  author: string,
): { handoffs: HandoffSummary[]; next?: string } {
  const o = object(value);
  if (!Array.isArray(o.handoffs) || o.handoffs.length > 100) bad();
  const handoffs = (o.handoffs as unknown[]).map((v) => summary(v, author));
  if (new Set(handoffs.map((h) => h.id)).size !== handoffs.length) bad();
  return { handoffs, ...(o.next === undefined ? {} : { next: id(o, "next") }) };
}
