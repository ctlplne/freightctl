import { ApiError, object, uuid } from "./types";
import {
  asReleaseDefinitionSnapshot,
  releaseHash,
  type ReleaseDefinition,
} from "./onboarding-releases-types";
import {
  asTestEffect,
  type TestDefinition,
  type TestEffect,
} from "./onboarding-tests-types";
import { digestBytes } from "./crypto";
export interface ApprovalPolicy {
  revision: number;
  mode: "author" | "independent";
  author_id?: string;
  event_id?: string;
}
export interface ApprovalSelection {
  release_id: string;
  definition_hash: string;
  expected_revision: number;
  reviewer_id: string;
}
export interface ApprovalDefinition {
  schema_version: 1;
  author_id: string;
  reviewer_id: string;
  reviewer_authority_revision: number;
  policy: { revision: number; mode: "independent" };
  release_id: string;
  release_revision: 1;
  release_hash: string;
  release: ReleaseDefinition;
  effects: {
    requirement_id: string;
    file: TestDefinition["file"];
    effect: TestEffect;
  }[];
}
export interface ApprovalSummary {
  id: string;
  author_id: string;
  reviewer_id: string;
  definition_hash: string;
  state: "pending" | "approved" | "rejected" | "withdrawn";
  revision: number;
  created_at: string;
  changed_event_id: string;
}
export interface ApprovalReview extends ApprovalSummary {
  definition: ApprovalDefinition;
}
export interface ApprovalPreview {
  definition: ApprovalDefinition;
  definition_hash: string;
  external_contact: false;
  grants_file_access: false;
}
function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}
function str(o: Record<string, unknown>, k: string, n = 128): string {
  const v = o[k];
  if (
    typeof v !== "string" ||
    !v ||
    new TextEncoder().encode(v).length > n ||
    /[\u0000-\u001f\u007f-\u009f]/.test(v)
  )
    bad();
  return v as string;
}
function id(o: Record<string, unknown>, k: string): string {
  const v = str(o, k, 36);
  if (!uuid(v)) bad();
  return v;
}
function hash(o: Record<string, unknown>, k: string): string {
  const v = str(o, k, 64);
  if (!/^[a-f0-9]{64}$/.test(v)) bad();
  return v;
}
function num(o: Record<string, unknown>, k: string, min = 1): number {
  const n = o[k];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min) bad();
  return n as number;
}
export function asApprovalPolicy(v: unknown): ApprovalPolicy {
  const o = object(v);
  if (o.mode !== "author" && o.mode !== "independent") bad();
  const revision = num(o, "revision", 0);
  if (revision === 0 && o.mode !== "author") bad();
  return {
    revision,
    mode: o.mode,
    ...(revision > 0
      ? { author_id: id(o, "author_id"), event_id: id(o, "event_id") }
      : {}),
  };
}
export function approvalHash(v: ApprovalDefinition): string {
  const b = new TextEncoder().encode(
    JSON.stringify(v).replace(
      /[<>&\u2028\u2029]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    ),
  );
  try {
    return digestBytes(b);
  } finally {
    b.fill(0);
  }
}
function definition(v: unknown): ApprovalDefinition {
  const o = object(v),
    p = object(o.policy),
    release = asReleaseDefinitionSnapshot(o.release);
  if (
    o.schema_version !== 1 ||
    o.release_revision !== 1 ||
    p.mode !== "independent" ||
    !Array.isArray(o.effects) ||
    o.effects.length !== release.proofs.length
  )
    bad();
  const policy = { revision: num(p, "revision"), mode: "independent" as const };
  if (
    JSON.stringify(release.approval_policy) !== JSON.stringify(policy) ||
    releaseHash(release) !== o.release_hash
  )
    bad();
  const effects = (o.effects as unknown[]).map((v, i) => {
    const e = object(v),
      f = object(e.file),
      proof = release.proofs[i];
    if (!proof || e.requirement_id !== proof.requirement_id) bad();
    return {
      requirement_id: id(e, "requirement_id"),
      file: {
        id: id(f, "id"),
        size_bytes: num(f, "size_bytes", 0),
        sha256: hash(f, "sha256"),
        policy: str(f, "policy", 256),
        accepted_event_id: id(f, "accepted_event_id"),
      },
      effect: asTestEffect(e.effect),
    };
  });
  const d: ApprovalDefinition = {
    schema_version: 1,
    author_id: id(o, "author_id"),
    reviewer_id: id(o, "reviewer_id"),
    reviewer_authority_revision: num(o, "reviewer_authority_revision"),
    policy,
    release_id: id(o, "release_id"),
    release_revision: 1,
    release_hash: hash(o, "release_hash"),
    release,
    effects,
  };
  if (d.author_id === d.reviewer_id) bad();
  return d;
}
export function asApprovalSummary(v: unknown, actor: string): ApprovalSummary {
  const o = object(v),
    state = str(o, "state", 16),
    revision = num(o, "revision"),
    author = id(o, "author_id"),
    reviewer = id(o, "reviewer_id"),
    created = str(o, "created_at", 64);
  if (
    !["pending", "approved", "rejected", "withdrawn"].includes(state) ||
    author === reviewer ||
    ![author, reviewer].includes(actor) ||
    !/^\d{4}-\d\d-\d\dT.*Z$/.test(created) ||
    !Number.isFinite(Date.parse(created)) ||
    (state === "pending"
      ? revision !== 1
      : state === "withdrawn"
        ? ![2, 3].includes(revision)
        : revision !== 2)
  )
    bad();
  return {
    id: id(o, "id"),
    author_id: author,
    reviewer_id: reviewer,
    definition_hash: hash(o, "definition_hash"),
    state: state as ApprovalSummary["state"],
    revision,
    created_at: created,
    changed_event_id: id(o, "changed_event_id"),
  };
}
export function asApprovalReview(
  v: unknown,
  actor: string,
  expected?: ApprovalSummary,
): ApprovalReview {
  const o = object(v),
    r = asApprovalSummary(o, actor),
    d = definition(o.definition);
  if (
    d.author_id !== r.author_id ||
    d.reviewer_id !== r.reviewer_id ||
    approvalHash(d) !== r.definition_hash ||
    (expected &&
      (r.id !== expected.id || r.definition_hash !== expected.definition_hash))
  )
    bad();
  return { ...r, definition: d };
}
export function asApprovalPreview(
  v: unknown,
  actor: string,
  selection: ApprovalSelection,
): ApprovalPreview {
  const o = object(v),
    d = definition(o.definition),
    h = hash(o, "definition_hash");
  if (
    d.author_id !== actor ||
    d.reviewer_id !== selection.reviewer_id ||
    d.release_id !== selection.release_id ||
    d.release_hash !== selection.definition_hash ||
    d.release_revision !== selection.expected_revision ||
    approvalHash(d) !== h ||
    o.external_contact !== false ||
    o.grants_file_access !== false
  )
    bad();
  return {
    definition: d,
    definition_hash: h,
    external_contact: false,
    grants_file_access: false,
  };
}
export function asApprovalPage(
  v: unknown,
  actor: string,
): { reviews: ApprovalSummary[]; next?: string } {
  const o = object(v);
  if (!Array.isArray(o.reviews) || o.reviews.length > 100) bad();
  const reviews = (o.reviews as unknown[]).map((x) =>
    asApprovalSummary(x, actor),
  );
  if (new Set(reviews.map((x) => x.id)).size !== reviews.length) bad();
  return { reviews, ...(o.next ? { next: id(o, "next") } : {}) };
}
export function asApprovalResult(
  v: unknown,
  actor: string,
  expected: { hash: string; id?: string; state: string; revision: number },
): ApprovalSummary {
  const o = object(object(v).resource);
  if (o.kind !== "onboarding_approval") bad();
  const r = asApprovalSummary(o.review, actor);
  if (
    r.definition_hash !== expected.hash ||
    (expected.id && r.id !== expected.id) ||
    r.state !== expected.state ||
    r.revision !== expected.revision
  )
    bad();
  return r;
}
export function asApprovalPolicyResult(
  v: unknown,
  expected: ApprovalPolicy,
  actor: string,
): ApprovalPolicy {
  const o = object(object(v).resource);
  if (o.kind !== "onboarding_approval_policy") bad();
  const p = asApprovalPolicy(o.policy);
  if (
    p.revision !== expected.revision + 1 ||
    p.mode !== expected.mode ||
    p.author_id !== actor
  )
    bad();
  return p;
}
