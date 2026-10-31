import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  asProbeConnection,
  type ProbeReference,
  type ProbeConnection,
} from "./onboarding-probes-types";
export interface TestSelection {
  plan: ProbeReference;
  requirement_id: string;
  probe_id: string;
  workflow: ProbeReference;
  file_id: string;
  expected_authority_revision: number;
}
export interface TestEffect {
  address: string;
  user: string;
  directory: string;
  filename: string;
  host_fingerprint: string;
  key_fingerprint: string;
  encryption?: { key: ProbeReference; profile: string };
  recipient_fingerprint: string;
}
export interface TestDefinition {
  schema_version: 1;
  profile: "single-sftp-test-v1";
  plan: ProbeReference;
  requirement_id: string;
  probe: { id: string; revision: 3; hash: string };
  workflow: ProbeReference;
  workflow_revision: number;
  step_id: string;
  connection: ProbeReference;
  effect: TestEffect;
  file: {
    id: string;
    size_bytes: number;
    sha256: string;
    policy: string;
    accepted_event_id: string;
  };
  storage_id: string;
  namespace_root: "/";
  authority_revision: number;
  required_receipt: "transport" | "integrity" | "business";
}
export interface TestPreview {
  definition: TestDefinition;
  definition_hash: string;
  connection: ProbeConnection;
  filename: string;
  external_contact: false;
  production_active: false;
}
export interface RecordedTest {
  id: string;
  run_id: string;
  author_id: string;
  definition: TestDefinition;
  definition_hash: string;
  created_at: string;
  created_event_id: string;
}
export interface TestView {
  test: RecordedTest;
  current_bindings: boolean;
  binding_reason: string;
  production_active: false;
  status: {
    observed_state: string;
    observed_reason: string;
    steps: {
      id: string;
      delivery_id: string;
      state: string;
      attempts: number;
    }[];
  };
}
const bad = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
function text(
  o: Record<string, unknown>,
  k: string,
  n: number,
  empty = false,
): string {
  const v = o[k];
  if (
    typeof v !== "string" ||
    (!empty && !v) ||
    new TextEncoder().encode(v).length > n ||
    /[\u0000-\u001f\u007f-\u009f]/.test(v) ||
    /[\ud800-\udfff]/u.test(v)
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
function integer(o: Record<string, unknown>, k: string, min = 1): number {
  const n = o[k];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min) bad();
  return n as number;
}
function ref(value: unknown): ProbeReference {
  const o = object(value),
    version = integer(o, "version");
  if (version > 2147483647) bad();
  return { id: id(o, "id"), version, hash: hash(o, "hash") };
}
function bool(o: Record<string, unknown>, k: string): boolean {
  if (typeof o[k] !== "boolean") bad();
  return o[k] as boolean;
}
function time(o: Record<string, unknown>, k: string): string {
  const t = text(o, k, 64);
  if (!/^\d{4}-\d{2}-\d{2}T.*Z$/.test(t) || !Number.isFinite(Date.parse(t)))
    bad();
  return t;
}
export function asTestEffect(value: unknown): TestEffect {
  const o = object(value),
    recipient = text(o, "recipient_fingerprint", 64, true);
  let encryption: TestEffect["encryption"];
  if (o.encryption !== undefined) {
    const e = object(o.encryption),
      profile = text(e, "profile", 32);
    if (
      !["seipd-v1-aes256", "seipd-v2-aes256-ocb"].includes(profile) ||
      !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(recipient)
    )
      bad();
    encryption = { key: ref(e.key), profile };
  } else if (recipient) bad();
  return {
    address: text(o, "address", 128),
    user: text(o, "user", 64),
    directory: text(o, "directory", 1024),
    filename: text(o, "filename", 128),
    host_fingerprint: text(o, "host_fingerprint", 128),
    key_fingerprint: text(o, "key_fingerprint", 128),
    ...(encryption ? { encryption } : {}),
    recipient_fingerprint: recipient,
  };
}
export function asTestDefinition(value: unknown): TestDefinition {
  const o = object(value),
    p = object(o.probe),
    f = object(o.file),
    step = text(o, "step_id", 64),
    receipt = text(o, "required_receipt", 16);
  if (
    o.schema_version !== 1 ||
    o.profile !== "single-sftp-test-v1" ||
    o.namespace_root !== "/" ||
    p.revision !== 3 ||
    !/^[a-z][a-z0-9_]{0,63}$/.test(step) ||
    !["transport", "integrity", "business"].includes(receipt)
  )
    bad();
  return {
    schema_version: 1,
    profile: "single-sftp-test-v1",
    plan: ref(o.plan),
    requirement_id: id(o, "requirement_id"),
    probe: { id: id(p, "id"), revision: 3, hash: hash(p, "hash") },
    workflow: ref(o.workflow),
    workflow_revision: integer(o, "workflow_revision"),
    step_id: step,
    connection: ref(o.connection),
    effect: asTestEffect(o.effect),
    file: {
      id: id(f, "id"),
      size_bytes: integer(f, "size_bytes", 0),
      sha256: hash(f, "sha256"),
      policy: text(f, "policy", 256),
      accepted_event_id: id(f, "accepted_event_id"),
    },
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    authority_revision: integer(o, "authority_revision"),
    required_receipt: receipt as TestDefinition["required_receipt"],
  };
}
export function testDefinitionHash(value: TestDefinition): string {
  const encoded = JSON.stringify(asTestDefinition(value)).replace(
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
function selected(d: TestDefinition, r: TestSelection): boolean {
  return (
    JSON.stringify(d.plan) === JSON.stringify(r.plan) &&
    d.requirement_id === r.requirement_id &&
    d.probe.id === r.probe_id &&
    JSON.stringify(d.workflow) === JSON.stringify(r.workflow) &&
    d.file.id === r.file_id &&
    d.authority_revision === r.expected_authority_revision
  );
}
export function asTestPreview(value: unknown, r: TestSelection): TestPreview {
  const o = object(value),
    d = asTestDefinition(o.definition),
    h = hash(o, "definition_hash"),
    c = asProbeConnection(o.connection),
    filename = text(o, "filename", 128);
  if (
    !selected(d, r) ||
    h !== testDefinitionHash(d) ||
    c.id !== d.connection.id ||
    c.version !== d.connection.version ||
    c.hash !== d.connection.hash ||
    c.state !== "active" ||
    d.effect.address !== c.address ||
    d.effect.user !== c.user ||
    d.effect.directory !== c.directory ||
    d.effect.filename !== filename ||
    d.effect.host_fingerprint !== c.host_fingerprint ||
    d.effect.key_fingerprint !== c.key_fingerprint ||
    o.external_contact !== false ||
    o.production_active !== false ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename)
  )
    bad();
  return {
    definition: d,
    definition_hash: h,
    connection: c,
    filename,
    external_contact: false,
    production_active: false,
  };
}
export function asRecordedTest(
  value: unknown,
  author: string,
  expected?: { id?: string; hash?: string },
): RecordedTest {
  const o = object(value),
    d = asTestDefinition(o.definition),
    p: RecordedTest = {
      id: id(o, "id"),
      run_id: id(o, "run_id"),
      author_id: id(o, "author_id"),
      definition: d,
      definition_hash: hash(o, "definition_hash"),
      created_at: time(o, "created_at"),
      created_event_id: id(o, "created_event_id"),
    };
  if (
    p.id !== p.run_id ||
    p.author_id !== author ||
    p.definition_hash !== testDefinitionHash(d) ||
    (expected?.id && p.id !== expected.id) ||
    (expected?.hash && p.definition_hash !== expected.hash)
  )
    bad();
  return p;
}
export function asTestStart(
  value: unknown,
  author: string,
  review: TestPreview,
): RecordedTest {
  const o = object(value),
    result = object(o.resource);
  if (typeof o.replayed !== "boolean" || result.kind !== "onboarding_test")
    bad();
  const p = asRecordedTest(result.test, author, {
      hash: review.definition_hash,
    }),
    run = object(result.run),
    d = p.definition;
  if (
    JSON.stringify(d) !== JSON.stringify(review.definition) ||
    run.id !== p.run_id ||
    run.workflow_id !== d.workflow.id ||
    run.workflow_version !== d.workflow.version ||
    run.workflow_hash !== d.workflow.hash ||
    run.file_id !== d.file.id ||
    !sameSource(run.source, d.file) ||
    run.storage_id !== d.storage_id ||
    run.namespace_root !== d.namespace_root ||
    run.authority_revision !== d.authority_revision ||
    run.state !== "queued" ||
    run.revision !== 1
  )
    bad();
  return p;
}
function sameSource(value: unknown, expected: TestDefinition["file"]): boolean {
  const f = object(value);
  return Object.entries(expected).every(([k, v]) => f[k] === v);
}
export function asTestPage(
  value: unknown,
  author: string,
  plan: string,
): { tests: RecordedTest[]; next?: string } {
  const o = object(value);
  if (!Array.isArray(o.tests) || o.tests.length > 100) bad();
  const tests = (o.tests as unknown[]).map((v) => asRecordedTest(v, author));
  if (
    tests.some((t) => t.definition.plan.id !== plan) ||
    new Set(tests.map((t) => t.id)).size !== tests.length
  )
    bad();
  return { tests, ...(o.next === undefined ? {} : { next: id(o, "next") }) };
}
export function asTestView(
  value: unknown,
  author: string,
  expected: { id: string; hash: string },
): TestView {
  const o = object(value),
    p = asRecordedTest(o.test, author, expected),
    status = object(o.status),
    run = object(status.run),
    current = bool(o, "current_bindings"),
    reason = text(o, "binding_reason", 64),
    observed = text(status, "observed_state", 24);
  if (
    o.production_active !== false ||
    reason !== (current ? "current" : "binding_changed") ||
    run.id !== p.run_id ||
    run.workflow_id !== p.definition.workflow.id ||
    run.workflow_version !== p.definition.workflow.version ||
    run.workflow_hash !== p.definition.workflow.hash ||
    run.file_id !== p.definition.file.id ||
    !sameSource(run.source, p.definition.file) ||
    run.storage_id !== p.definition.storage_id ||
    run.namespace_root !== p.definition.namespace_root ||
    run.authority_revision !== p.definition.authority_revision ||
    !["queued", "running", "attention", "succeeded", "cancelled"].includes(
      String(run.state),
    ) ||
    integer(run, "revision") < 1 ||
    !Array.isArray(status.steps) ||
    status.steps.length !== 1 ||
    !["queued", "running", "attention", "succeeded", "cancelled"].includes(
      observed,
    )
  )
    bad();
  const steps = (status.steps as unknown[]).map((v) => {
    const s = object(v);
    return {
      id: text(s, "id", 64),
      delivery_id: id(s, "delivery_id"),
      state: text(s, "state", 24),
      attempts: integer(s, "attempts", 0),
    };
  });
  if (
    steps[0]?.id !== p.definition.step_id ||
    ![
      "queued",
      "staging",
      "publishing",
      "succeeded",
      "retry",
      "blocked",
      "ambiguous",
      "cancelled",
    ].includes(steps[0].state)
  )
    bad();
  return {
    test: p,
    current_bindings: current,
    binding_reason: reason,
    production_active: false,
    status: {
      observed_state: observed,
      observed_reason: text(status, "observed_reason", 64),
      steps,
    },
  };
}
