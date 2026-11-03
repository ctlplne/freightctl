import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  asApprovalPolicy,
  type ApprovalPolicy,
} from "./onboarding-approvals-types";
import {
  asTestEffect,
  type TestDefinition,
  type TestEffect,
} from "./onboarding-tests-types";
export type DispatchPolicy = ApprovalPolicy;
export interface PolicyBinding {
  revision: number;
  mode: "author" | "independent";
}
export interface WorkflowBinding {
  workflow_id: string;
  workflow_version: number;
  workflow_hash: string;
  run_id: string;
  step_id: string;
  connection_id: string;
  connection_version: number;
  connection_hash: string;
}
export interface DispatchEffect {
  protocol: "sftp" | "ftps";
  address: string;
  user: string;
  directory: string;
  filename: string;
  final_path: string;
  host_fingerprint: string;
  key_fingerprint: string;
  key_reference_sha256: string;
  encryption?: TestEffect["encryption"];
  recipient_fingerprint: string;
  workflow_binding?: WorkflowBinding;
  ftps?: FTPSReviewEffect;
}
export interface FTPSReviewEffect {
  mode: "explicit" | "implicit";
  server_name: string;
  ca_sha256: string;
  ca_reference_sha256: string;
  password_reference_sha256: string;
  staging_path: string;
  receiver_contract: {
    schema_version: 1;
    document_sha256: string;
    staging_visibility: "receiver-private";
    rename: "may-replace";
    duplicates: "receiver-deduplicates-delivery-id";
    receipt: "exact-readback";
  };
}
export interface DispatchSelection {
  delivery_id: string;
  definition_hash: string;
  expected_revision: number;
  reviewer_id: string;
}
export interface DispatchDefinition {
  schema_version: 1 | 2;
  author_id: string;
  authority_revision: number;
  reviewer_id: string;
  reviewer_authority_revision: number;
  policy: PolicyBinding;
  delivery_id: string;
  delivery_revision: number;
  delivery_hash: string;
  source: TestDefinition["file"];
  storage_id: string;
  namespace_root: "/";
  effect: DispatchEffect;
  attempt_limit: 8;
}
export interface DispatchPreview {
  definition: DispatchDefinition;
  definition_hash: string;
  external_contact: false;
  grants_file_access: false;
}
export interface DispatchSummary {
  id: string;
  author_id: string;
  reviewer_id: string;
  delivery_id: string;
  definition_hash: string;
  state: "pending" | "approved" | "rejected" | "withdrawn";
  revision: number;
  created_at: string;
  changed_event_id: string;
}
export interface DispatchReview extends DispatchSummary {
  definition: DispatchDefinition;
}
export interface DispatchView {
  id: string;
  definition_hash: string;
  state: string;
  revision: number;
  attempts: number;
  policy: PolicyBinding;
  current_policy: PolicyBinding;
  current_approval: boolean;
  reviewable: boolean;
  source: TestDefinition["file"];
  effect: DispatchEffect;
}
function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}
function text(o: Record<string, unknown>, k: string, max = 128): string {
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
  const v = text(o, k, 36);
  if (!uuid(v)) bad();
  return v;
}
function hash(o: Record<string, unknown>, k: string): string {
  const v = text(o, k, 64);
  if (!/^[a-f0-9]{64}$/.test(v)) bad();
  return v;
}
function num(o: Record<string, unknown>, k: string, min = 1): number {
  const n = o[k];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min) bad();
  return n as number;
}
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
export function asDispatchPolicy(v: unknown): DispatchPolicy {
  return asApprovalPolicy(v);
}
function binding(v: unknown): PolicyBinding {
  const o = object(v),
    revision = num(o, "revision", 0);
  if (
    (o.mode !== "author" && o.mode !== "independent") ||
    (revision === 0 && o.mode !== "author")
  )
    bad();
  return { revision, mode: o.mode };
}
function source(v: unknown): TestDefinition["file"] {
  const o = object(v);
  return {
    id: id(o, "id"),
    size_bytes: num(o, "size_bytes", 0),
    sha256: hash(o, "sha256"),
    policy: text(o, "policy", 256),
    accepted_event_id: id(o, "accepted_event_id"),
  };
}
function exact(o: Record<string, unknown>, keys: string[]) {
  if (!same(Object.keys(o).sort(), [...keys].sort())) bad();
}
function ftpsPath(o: Record<string, unknown>, key: string, max = 1024): string {
  const v = text(o, key, max);
  if (!v.startsWith("/") || v.normalize("NFC") !== v) bad();
  if (v !== "/")
    for (const part of v.slice(1).split("/"))
      if (
        !part ||
        part === "." ||
        part === ".." ||
        part === ".freightctl" ||
        new TextEncoder().encode(part).length > 255 ||
        /[\\:]|[. ]$/.test(part) ||
        /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)
      )
        bad();
  return v;
}
function ftpsEffect(
  o: Record<string, unknown>,
  deliveryID: string,
): DispatchEffect {
  exact(o, [
    "protocol",
    "address",
    "user",
    "directory",
    "filename",
    "final_path",
    "host_fingerprint",
    "key_fingerprint",
    "key_reference_sha256",
    "recipient_fingerprint",
    "ftps",
    ...(o.workflow_binding === undefined ? [] : ["workflow_binding"]),
  ]);
  const f = object(o.ftps),
    c = object(f.receiver_contract),
    directory = ftpsPath(o, "directory", 768),
    filename = text(o, "filename", 128),
    final = ftpsPath(o, "final_path"),
    stage = ftpsPath(f, "staging_path"),
    serverName = text(f, "server_name", 253);
  exact(f, [
    "mode",
    "server_name",
    "ca_sha256",
    "ca_reference_sha256",
    "password_reference_sha256",
    "staging_path",
    "receiver_contract",
  ]);
  exact(c, [
    "schema_version",
    "document_sha256",
    "staging_visibility",
    "rename",
    "duplicates",
    "receipt",
  ]);
  if (
    (f.mode !== "explicit" && f.mode !== "implicit") ||
    /[\/\\ ]/.test(serverName) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename) ||
    final !==
      `${directory === "/" ? "" : directory}/${deliveryID}-${filename}` ||
    !stage.endsWith(`/.freightctl-${deliveryID}.partial`) ||
    o.host_fingerprint !== "" ||
    o.key_fingerprint !== "" ||
    o.key_reference_sha256 !== "" ||
    o.recipient_fingerprint !== "" ||
    c.schema_version !== 1 ||
    c.staging_visibility !== "receiver-private" ||
    c.rename !== "may-replace" ||
    c.duplicates !== "receiver-deduplicates-delivery-id" ||
    c.receipt !== "exact-readback"
  )
    bad();
  const stagingDirectory = stage.slice(0, stage.lastIndexOf("/")) || "/";
  if (
    directory === "/" ||
    stagingDirectory === "/" ||
    new TextEncoder().encode(stagingDirectory).length > 768 ||
    directory === stagingDirectory ||
    directory.startsWith(stagingDirectory + "/") ||
    stagingDirectory.startsWith(directory + "/")
  )
    bad();
  return {
    protocol: "ftps",
    address: text(o, "address", 128),
    user: text(o, "user", 256),
    directory,
    filename,
    final_path: final,
    host_fingerprint: "",
    key_fingerprint: "",
    key_reference_sha256: "",
    recipient_fingerprint: "",
    ...(o.workflow_binding === undefined
      ? {}
      : { workflow_binding: asWorkflowBinding(o.workflow_binding) }),
    ftps: {
      mode: f.mode,
      server_name: serverName,
      ca_sha256: hash(f, "ca_sha256"),
      ca_reference_sha256: hash(f, "ca_reference_sha256"),
      password_reference_sha256: hash(f, "password_reference_sha256"),
      staging_path: stage,
      receiver_contract: {
        schema_version: 1,
        document_sha256: hash(c, "document_sha256"),
        staging_visibility: "receiver-private",
        rename: "may-replace",
        duplicates: "receiver-deduplicates-delivery-id",
        receipt: "exact-readback",
      },
    },
  };
}
function asWorkflowBinding(v: unknown): WorkflowBinding {
  const b = object(v),
    step = text(b, "step_id", 64);
  exact(b, [
    "workflow_id",
    "workflow_version",
    "workflow_hash",
    "run_id",
    "step_id",
    "connection_id",
    "connection_version",
    "connection_hash",
  ]);
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(step)) bad();
  return {
    workflow_id: id(b, "workflow_id"),
    workflow_version: num(b, "workflow_version"),
    workflow_hash: hash(b, "workflow_hash"),
    run_id: id(b, "run_id"),
    step_id: step,
    connection_id: id(b, "connection_id"),
    connection_version: num(b, "connection_version"),
    connection_hash: hash(b, "connection_hash"),
  };
}
function effect(v: unknown, deliveryID: string): DispatchEffect {
  const o = object(v);
  if (o.protocol === "ftps") return ftpsEffect(o, deliveryID);
  if (o.ftps !== undefined) bad();
  const base = asTestEffect(v),
    final = text(o, "final_path", 1280);
  if (
    o.protocol !== "sftp" ||
    !/^\/[\s\S]*$/.test(base.directory) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(base.filename) ||
    final !==
      (base.directory === "/" ? "" : base.directory) +
        "/" +
        deliveryID +
        "-" +
        base.filename
  )
    bad();
  let workflow: WorkflowBinding | undefined;
  if (o.workflow_binding !== undefined) {
    workflow = asWorkflowBinding(o.workflow_binding);
  }
  return {
    protocol: "sftp",
    address: base.address,
    user: base.user,
    directory: base.directory,
    filename: base.filename,
    final_path: final,
    host_fingerprint: base.host_fingerprint,
    key_fingerprint: base.key_fingerprint,
    key_reference_sha256: hash(o, "key_reference_sha256"),
    ...(base.encryption ? { encryption: base.encryption } : {}),
    recipient_fingerprint: base.recipient_fingerprint,
    ...(workflow ? { workflow_binding: workflow } : {}),
  };
}
export function dispatchHash(d: DispatchDefinition): string {
  const b = new TextEncoder().encode(
    JSON.stringify(d).replace(
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
export function asDispatchDefinition(v: unknown): DispatchDefinition {
  const o = object(v),
    policy = binding(o.policy),
    deliveryID = id(o, "delivery_id"),
    author = id(o, "author_id"),
    reviewer = id(o, "reviewer_id"),
    schema = o.schema_version,
    fx = effect(o.effect, deliveryID);
  if (
    (schema !== 1 && schema !== 2) ||
    (schema === 2) !== (fx.protocol === "ftps") ||
    o.namespace_root !== "/" ||
    o.attempt_limit !== 8 ||
    policy.mode !== "independent" ||
    policy.revision < 1 ||
    author === reviewer
  )
    bad();
  return {
    schema_version: schema,
    author_id: author,
    authority_revision: num(o, "authority_revision"),
    reviewer_id: reviewer,
    reviewer_authority_revision: num(o, "reviewer_authority_revision"),
    policy,
    delivery_id: deliveryID,
    delivery_revision: num(o, "delivery_revision"),
    delivery_hash: hash(o, "delivery_hash"),
    source: source(o.source),
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    effect: fx,
    attempt_limit: 8,
  };
}
export function asDispatchView(v: unknown, expected: string): DispatchView {
  const o = object(v),
    deliveryID = id(o, "id"),
    state = text(o, "state", 16),
    attempts = num(o, "attempts", 0),
    policy = binding(o.policy),
    current = binding(o.current_policy);
  if (
    deliveryID !== expected ||
    ![
      "draft",
      "queued",
      "staging",
      "publishing",
      "retry",
      "ambiguous",
      "blocked",
      "cancelled",
      "succeeded",
    ].includes(state) ||
    attempts > 8 ||
    typeof o.current_approval !== "boolean" ||
    typeof o.reviewable !== "boolean" ||
    (o.current_approval && !same(policy, current)) ||
    (o.reviewable &&
      (!["draft", "queued"].includes(state) ||
        attempts !== 0 ||
        policy.mode !== "independent" ||
        !same(policy, current)))
  )
    bad();
  return {
    id: deliveryID,
    definition_hash: hash(o, "definition_hash"),
    state,
    revision: num(o, "revision"),
    attempts,
    policy,
    current_policy: current,
    current_approval: o.current_approval,
    reviewable: o.reviewable,
    source: source(o.source),
    effect: effect(o.effect, deliveryID),
  };
}
export function asDispatchPreview(
  v: unknown,
  actor: string,
  authority: number,
  x: DispatchSelection,
  view: DispatchView,
): DispatchPreview {
  const o = object(v),
    d = asDispatchDefinition(o.definition),
    h = hash(o, "definition_hash");
  if (
    dispatchHash(d) !== h ||
    d.author_id !== actor ||
    d.authority_revision !== authority ||
    d.delivery_id !== x.delivery_id ||
    d.delivery_hash !== x.definition_hash ||
    d.delivery_revision !== x.expected_revision ||
    d.reviewer_id !== x.reviewer_id ||
    d.delivery_id !== view.id ||
    !same(d.source, view.source) ||
    !same(d.effect, view.effect) ||
    !same(d.policy, view.policy) ||
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
export function asDispatchSummary(v: unknown, actor: string): DispatchSummary {
  const o = object(v),
    author = id(o, "author_id"),
    reviewer = id(o, "reviewer_id"),
    state = text(o, "state", 16),
    revision = num(o, "revision"),
    created = text(o, "created_at", 64);
  if (
    author === reviewer ||
    ![author, reviewer].includes(actor) ||
    !["pending", "approved", "rejected", "withdrawn"].includes(state) ||
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
    delivery_id: id(o, "delivery_id"),
    definition_hash: hash(o, "definition_hash"),
    state: state as DispatchSummary["state"],
    revision,
    created_at: created,
    changed_event_id: id(o, "changed_event_id"),
  };
}
export function asDispatchReview(
  v: unknown,
  actor: string,
  expected: DispatchSummary,
): DispatchReview {
  const o = object(v),
    r = asDispatchSummary(o, actor),
    d = asDispatchDefinition(o.definition);
  if (
    r.id !== expected.id ||
    r.definition_hash !== expected.definition_hash ||
    d.delivery_id !== r.delivery_id ||
    d.author_id !== r.author_id ||
    d.reviewer_id !== r.reviewer_id ||
    dispatchHash(d) !== r.definition_hash
  )
    bad();
  return { ...r, definition: d };
}
export function asDispatchPage(
  v: unknown,
  actor: string,
): { reviews: DispatchSummary[]; next?: string } {
  const o = object(v);
  if (!Array.isArray(o.reviews) || o.reviews.length > 100) bad();
  const reviews = (o.reviews as unknown[]).map((v) =>
    asDispatchSummary(v, actor),
  );
  if (new Set(reviews.map((v) => v.id)).size !== reviews.length) bad();
  return { reviews, ...(o.next ? { next: id(o, "next") } : {}) };
}
export function asDispatchResult(
  v: unknown,
  actor: string,
  expected: {
    hash: string;
    id?: string;
    delivery: string;
    state: string;
    revision: number;
  },
): DispatchSummary {
  const o = object(object(v).resource);
  if (o.kind !== "outbound_dispatch_review") bad();
  const r = asDispatchSummary(o.review, actor);
  if (
    r.definition_hash !== expected.hash ||
    (expected.id && r.id !== expected.id) ||
    r.delivery_id !== expected.delivery ||
    r.state !== expected.state ||
    r.revision !== expected.revision
  )
    bad();
  return r;
}
export function asDispatchPolicyResult(
  v: unknown,
  expected: DispatchPolicy,
  actor: string,
): DispatchPolicy {
  const o = object(object(v).resource);
  if (o.kind !== "outbound_dispatch_policy") bad();
  const p = asDispatchPolicy(o.policy);
  if (
    p.revision !== expected.revision + 1 ||
    p.mode !== expected.mode ||
    p.author_id !== actor
  )
    bad();
  return p;
}
