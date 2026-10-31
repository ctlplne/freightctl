import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  asWorkflowReference,
  asWorkflowEffect,
  canonicalWorkflowBytes,
  asScheduledRun,
  asScheduledWork,
  type Reference,
  type ScheduleEffect,
  type ScheduledRun,
} from "./schedules-types";

export const collectionContract = "immutable-files-sha256-manifest-v1";
export interface CollectionSource {
  kind: "sftp.collect";
  connection: Reference;
  manifest: string;
  target_directory: string;
  completion_contract: typeof collectionContract;
  max_files: number;
  max_file_bytes: number;
  max_total_bytes: number;
}
export interface WorkflowStep {
  id: string;
  kind: "sftp.deliver";
  connection: Reference;
  filename: string;
  encryption?: ScheduleEffect["encryption"];
}
export interface CollectionWorkflow {
  schema_version: 1;
  name: string;
  steps: WorkflowStep[];
  source: CollectionSource;
}
export interface WorkflowConfiguration {
  id: string;
  version: number;
  definition: CollectionWorkflow;
  definition_hash: string;
  state: "draft" | "approved" | "revoked";
  revision: number;
  approval_authority: number;
}
export interface CollectionConnection {
  id: string;
  version: number;
  definition_hash: string;
  state: "active" | "revoked";
  revision: number;
  address: string;
  user: string;
  directory: string;
  host_fingerprint: string;
  key_fingerprint: string;
}
export interface CollectionDefinition {
  schema_version: 1;
  workflow: Reference;
  source: CollectionSource;
  source_connection: CollectionConnection;
  source_identity: string;
  authority_revision: number;
  storage_id: string;
  namespace_root: "/";
  timeout_seconds: number;
  effects: ScheduleEffect[];
}
export interface CollectionSelection {
  workflow: Reference;
  timeout_seconds: number;
  expected_authority_revision: number;
}
export interface CollectionPreview {
  definition: CollectionDefinition;
  definition_hash: string;
  external_contact: false;
  approval_required: true;
}
export interface ProducerFile {
  name: string;
  size_bytes: number;
  sha256: string;
}
export interface ProducerManifest {
  schema_version: 1;
  batch_id: string;
  files: ProducerFile[];
}
export type CollectionState =
  | "queued"
  | "reading"
  | "retry"
  | "captured"
  | "attention"
  | "expired"
  | "cancelled";
export interface CollectionJob {
  id: string;
  workflow_id: string;
  workflow_version: number;
  workflow_hash: string;
  definition: CollectionDefinition;
  definition_hash: string;
  state: CollectionState;
  captured: boolean;
  revision: number;
  fence: number;
  attempts: number;
  lease_owner: string;
  lease_until: string | null;
  next_at: string;
  created_at: string;
  deadline_at: string;
  manifest: ProducerManifest | null;
  manifest_hash: string | null;
  reason: string;
}
export interface CollectionInput {
  id: string;
  first_job_id: string;
  workflow_id: string;
  source_identity: string;
  input_identity: string;
  source_name: string;
  size_bytes: number;
  sha256: string;
  target_path: string;
  object_id: string;
  state: "pending" | "accepted" | "queued";
  revision: number;
  capture_fence: number;
  capture_owner: string;
  file_id: string | null;
  run_id: string | null;
}
export interface CollectionView {
  job: CollectionJob;
  inputs: CollectionInput[];
  current_authority: boolean;
  observed_state: CollectionState;
  business_acceptance: "unknown";
  local_states: { input_id: string; state: string }[];
}
export interface CollectionAction {
  kind: "workflow_collection";
  id: string;
  definition_hash: string;
  state: CollectionState;
  revision: number;
}

const bad = (): never => {
  throw new ApiError("invalid_server_response", 502);
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
function str(
  o: Record<string, unknown>,
  k: string,
  max = 1024,
  empty = false,
): string {
  const v = o[k];
  if (
    typeof v !== "string" ||
    (!empty && !v.length) ||
    new TextEncoder().encode(v).length > max ||
    /\p{Cc}/u.test(v) ||
    v.normalize("NFC") !== v
  )
    bad();
  return v as string;
}
function num(
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
function bool(o: Record<string, unknown>, k: string): boolean {
  if (typeof o[k] !== "boolean") bad();
  return o[k] as boolean;
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
function array(v: unknown, max: number, min = 0): unknown[] {
  if (!Array.isArray(v) || v.length > max || v.length < min) bad();
  return v as unknown[];
}
function ref(v: unknown): Reference {
  const o = object(v);
  keys(o, ["id", "version", "hash"]);
  const r = asWorkflowReference(o);
  if (r.version > 2147483647) bad();
  return r;
}
const equal = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
const hashValue = (v: unknown) => digestBytes(canonicalWorkflowBytes(v));
function date(o: Record<string, unknown>, k: string): string {
  const v = str(o, k, 40);
  if (
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) ||
    !Number.isFinite(Date.parse(v)) ||
    new Date(v).toISOString().slice(0, 19) !== v.slice(0, 19)
  )
    bad();
  return v;
}
function path(v: string): string {
  if (
    !v.startsWith("/") ||
    new TextEncoder().encode(v).length > 1024 ||
    v.normalize("NFC") !== v
  )
    bad();
  if (v === "/") return v;
  for (const p of v.slice(1).split("/")) {
    const base = p.split(".")[0]!.toUpperCase();
    if (
      !p ||
      p === "." ||
      p === ".." ||
      p === ".freightctl" ||
      p.endsWith(".") ||
      p.endsWith(" ") ||
      /[\p{Cc}\\:]/u.test(p) ||
      new TextEncoder().encode(p).length > 255 ||
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(base)
    )
      bad();
  }
  return v;
}
const filename = (v: string): string => {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(v)) bad();
  return v;
};
const sshFingerprint = (v: string): string => {
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(v)) bad();
  return v;
};
const target = (directory: string, sha: string, name: string) =>
  path((directory === "/" ? "" : directory) + "/" + sha + "-" + name);

export function asCollectionSource(v: unknown): CollectionSource {
  const o = object(v);
  keys(o, [
    "kind",
    "connection",
    "manifest",
    "target_directory",
    "completion_contract",
    "max_files",
    "max_file_bytes",
    "max_total_bytes",
  ]);
  if (o.kind !== "sftp.collect" || o.completion_contract !== collectionContract)
    bad();
  const manifest = filename(str(o, "manifest", 128)),
    directory = path(str(o, "target_directory", 1024));
  if (!manifest.endsWith(".ready.json")) bad();
  target(directory, "a".repeat(64), "x".repeat(128));
  const maxFiles = num(o, "max_files", 1, 64),
    maxFile = num(o, "max_file_bytes", 1, 1073741824),
    maxTotal = num(o, "max_total_bytes", 1, maxFiles * maxFile);
  return {
    kind: "sftp.collect",
    connection: ref(o.connection),
    manifest,
    target_directory: directory,
    completion_contract: collectionContract,
    max_files: maxFiles,
    max_file_bytes: maxFile,
    max_total_bytes: maxTotal,
  };
}
export function asCollectionConnection(v: unknown): CollectionConnection {
  const o = object(v);
  keys(o, [
    "id",
    "version",
    "definition_hash",
    "state",
    "revision",
    "address",
    "user",
    "directory",
    "host_fingerprint",
    "key_fingerprint",
  ]);
  if (o.state !== "active" && o.state !== "revoked") bad();
  return {
    id: id(o, "id"),
    version: num(o, "version", 1, 2147483647),
    definition_hash: hash(o, "definition_hash"),
    state: o.state as CollectionConnection["state"],
    revision: num(o, "revision"),
    address: str(o, "address", 300),
    user: str(o, "user", 64),
    directory: path(str(o, "directory", 1024)),
    host_fingerprint: sshFingerprint(str(o, "host_fingerprint", 100)),
    key_fingerprint: sshFingerprint(str(o, "key_fingerprint", 100)),
  };
}
export function asCollectionConnections(v: unknown): {
  connections: CollectionConnection[];
  next?: string;
} {
  const o = object(v);
  keys(o, ["connections"], ["next"]);
  const connections = array(o.connections, 100).map(asCollectionConnection);
  if (
    connections.some((c) => c.state !== "active") ||
    new Set(connections.map((c) => c.id)).size !== connections.length
  )
    bad();
  return {
    connections,
    ...(o.next !== undefined ? { next: id(o, "next") } : {}),
  };
}
export function asCollectionWorkflow(v: unknown): CollectionWorkflow {
  const o = object(v);
  keys(o, ["schema_version", "name", "steps", "source"]);
  if (o.schema_version !== 1) bad();
  const steps = array(o.steps, 16).map((v) => {
    const s = object(v);
    keys(s, ["id", "kind", "connection", "filename"], ["encryption"]);
    const step = str(s, "id", 64);
    if (s.kind !== "sftp.deliver" || !/^[a-z][a-z0-9_]{0,63}$/.test(step))
      bad();
    let encryption: ScheduleEffect["encryption"];
    if (s.encryption !== undefined) {
      const e = object(s.encryption);
      keys(e, ["key", "profile"]);
      if (
        !["seipd-v1-aes256", "seipd-v2-aes256-ocb"].includes(
          e.profile as string,
        )
      )
        bad();
      encryption = { key: ref(e.key), profile: e.profile as string };
    }
    return {
      id: step,
      kind: "sftp.deliver" as const,
      connection: ref(s.connection),
      filename: filename(str(s, "filename", 128)),
      ...(encryption ? { encryption } : {}),
    };
  });
  if (new Set(steps.map((s) => s.id)).size !== steps.length) bad();
  const d: CollectionWorkflow = {
    schema_version: 1,
    name: str(o, "name", 256),
    steps,
    source: asCollectionSource(o.source),
  };
  if (canonicalWorkflowBytes(d).length > 24576) bad();
  return d;
}
export const collectionWorkflowHash = (d: CollectionWorkflow) => hashValue(d);
export function asCollectionConfiguration(
  v: unknown,
  expected?: Reference,
): WorkflowConfiguration {
  const o = object(v);
  keys(o, [
    "id",
    "version",
    "definition",
    "definition_hash",
    "state",
    "revision",
    "approval_authority",
  ]);
  const d = asCollectionWorkflow(o.definition),
    h = hash(o, "definition_hash"),
    state = str(o, "state", 20);
  if (
    h !== collectionWorkflowHash(d) ||
    !["draft", "approved", "revoked"].includes(state)
  )
    bad();
  const c: WorkflowConfiguration = {
    id: id(o, "id"),
    version: num(o, "version", 1, 2147483647),
    definition: d,
    definition_hash: h,
    state: state as WorkflowConfiguration["state"],
    revision: num(o, "revision"),
    approval_authority: num(o, "approval_authority", 0),
  };
  if (
    expected &&
    (c.id !== expected.id ||
      c.version !== expected.version ||
      c.definition_hash !== expected.hash)
  )
    bad();
  if ((state === "draft") !== (c.approval_authority === 0)) bad();
  return c;
}
export function asCollectionConfigurationResult(
  v: unknown,
  definition: CollectionWorkflow,
  state: WorkflowConfiguration["state"],
  expected?: Reference,
): WorkflowConfiguration {
  const o = object(v);
  keys(o, ["resource", "replayed"]);
  bool(o, "replayed");
  const c = asCollectionConfiguration(o.resource, expected);
  if (c.state !== state || !equal(c.definition, definition)) bad();
  return c;
}
export function asCollectionWorkflowPreview(
  v: unknown,
  expected: CollectionWorkflow,
) {
  const o = object(v);
  keys(o, [
    "definition",
    "definition_hash",
    "effects",
    "external_contact",
    "approval_required",
    "collection",
  ]);
  const d = asCollectionWorkflow(o.definition);
  if (
    !equal(d, expected) ||
    hash(o, "definition_hash") !== collectionWorkflowHash(d) ||
    o.external_contact !== false ||
    o.approval_required !== true
  )
    bad();
  const c = object(o.collection);
  keys(c, ["kind", "connection", "source"]);
  if (
    c.kind !== "sftp.collect" ||
    !equal(asCollectionSource(c.source), d.source)
  )
    bad();
  const connection = asCollectionConnection(c.connection);
  if (
    !equal(
      {
        id: connection.id,
        version: connection.version,
        hash: connection.definition_hash,
      },
      d.source.connection,
    ) ||
    connection.state !== "active"
  )
    bad();
  const effects = effectsForWorkflow(o.effects, d);
  return {
    definition: d,
    definition_hash: collectionWorkflowHash(d),
    effects,
    collection: { kind: "sftp.collect" as const, connection, source: d.source },
    external_contact: false as const,
    approval_required: true as const,
  };
}
function effectsForWorkflow(
  v: unknown,
  d: CollectionWorkflow,
): ScheduleEffect[] {
  const effects = array(v, 16).map(asWorkflowEffect);
  if (effects.length !== d.steps.length) bad();
  effects.forEach((e, i) => {
    const s = d.steps[i]!;
    if (
      e.step_id !== s.id ||
      !equal(e.connection, s.connection) ||
      e.final_name_pattern !== "<delivery UUID>-" + s.filename ||
      !equal(e.encryption, s.encryption)
    )
      bad();
    sshFingerprint(e.host_fingerprint);
  });
  return effects;
}
export function asCollectionDefinition(v: unknown): CollectionDefinition {
  const o = object(v);
  keys(o, [
    "schema_version",
    "workflow",
    "source",
    "source_connection",
    "source_identity",
    "authority_revision",
    "storage_id",
    "namespace_root",
    "timeout_seconds",
    "effects",
  ]);
  if (o.schema_version !== 1 || o.namespace_root !== "/") bad();
  const source = asCollectionSource(o.source),
    connection = asCollectionConnection(o.source_connection),
    identity = hash(o, "source_identity"),
    effects = array(o.effects, 16).map(asWorkflowEffect);
  if (
    connection.state !== "active" ||
    !equal(
      {
        id: connection.id,
        version: connection.version,
        hash: connection.definition_hash,
      },
      source.connection,
    ) ||
    identity !==
      digestBytes(
        new TextEncoder().encode(connection.id + ":" + connection.directory),
      ) ||
    new Set(effects.map((e) => e.step_id)).size !== effects.length
  )
    bad();
  const d: CollectionDefinition = {
    schema_version: 1,
    workflow: ref(o.workflow),
    source,
    source_connection: connection,
    source_identity: identity,
    authority_revision: num(o, "authority_revision"),
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    timeout_seconds: num(o, "timeout_seconds", 1, 3600),
    effects,
  };
  if (canonicalWorkflowBytes(d).length > 24576) bad();
  return d;
}
export const collectionHash = (d: CollectionDefinition) => hashValue(d);
export function asCollectionPreview(
  v: unknown,
  selection: CollectionSelection,
  authority: number,
  workflow?: WorkflowConfiguration,
): CollectionPreview {
  const o = object(v);
  keys(o, [
    "definition",
    "definition_hash",
    "external_contact",
    "approval_required",
  ]);
  const d = asCollectionDefinition(o.definition),
    h = hash(o, "definition_hash");
  if (
    h !== collectionHash(d) ||
    !equal(d.workflow, selection.workflow) ||
    d.timeout_seconds !== selection.timeout_seconds ||
    d.authority_revision !== authority ||
    authority !== selection.expected_authority_revision ||
    o.external_contact !== false ||
    o.approval_required !== true
  )
    bad();
  if (workflow) {
    if (
      !equal(d.source, workflow.definition.source) ||
      workflow.definition_hash !== d.workflow.hash
    )
      bad();
    effectsForWorkflow(d.effects, workflow.definition);
  }
  return {
    definition: d,
    definition_hash: h,
    external_contact: false,
    approval_required: true,
  };
}

function manifest(v: unknown, source: CollectionSource): ProducerManifest {
  const o = object(v);
  keys(o, ["schema_version", "batch_id", "files"]);
  if (o.schema_version !== 1) bad();
  const files = array(o.files, source.max_files, 1).map((v) => {
    const f = object(v);
    keys(f, ["name", "size_bytes", "sha256"]);
    const name = filename(str(f, "name", 128));
    if (name.endsWith(".ready.json")) bad();
    const file = {
      name,
      size_bytes: num(f, "size_bytes", 0, source.max_file_bytes),
      sha256: hash(f, "sha256"),
    };
    target(source.target_directory, file.sha256, name);
    return file;
  });
  if (
    new Set(files.map((f) => f.name)).size !== files.length ||
    files.reduce((sum, f) => sum + f.size_bytes, 0) > source.max_total_bytes
  )
    bad();
  return { schema_version: 1, batch_id: id(o, "batch_id"), files };
}
const states: CollectionState[] = [
  "queued",
  "reading",
  "retry",
  "captured",
  "attention",
  "expired",
  "cancelled",
];
function state(o: Record<string, unknown>, k: string): CollectionState {
  const s = str(o, k, 20);
  if (!states.includes(s as CollectionState)) bad();
  return s as CollectionState;
}
export function asCollectionJob(
  v: unknown,
  expectedID?: string,
): CollectionJob {
  const o = object(v);
  keys(o, [
    "id",
    "workflow_id",
    "workflow_version",
    "workflow_hash",
    "definition",
    "definition_hash",
    "state",
    "captured",
    "revision",
    "fence",
    "attempts",
    "lease_owner",
    "lease_until",
    "next_at",
    "created_at",
    "deadline_at",
    "manifest",
    "manifest_hash",
    "reason",
  ]);
  const d = asCollectionDefinition(o.definition),
    s = state(o, "state"),
    captured = bool(o, "captured"),
    h = hash(o, "definition_hash"),
    owner = str(o, "lease_owner", 36, true),
    until = o.lease_until === null ? null : date(o, "lease_until"),
    m = o.manifest === null ? null : manifest(o.manifest, d.source),
    mh = o.manifest_hash === null ? null : hash(o, "manifest_hash");
  const j: CollectionJob = {
    id: id(o, "id"),
    workflow_id: id(o, "workflow_id"),
    workflow_version: num(o, "workflow_version", 1, 2147483647),
    workflow_hash: hash(o, "workflow_hash"),
    definition: d,
    definition_hash: h,
    state: s,
    captured,
    revision: num(o, "revision"),
    fence: num(o, "fence", 0, 8),
    attempts: num(o, "attempts", 0, 8),
    lease_owner: owner,
    lease_until: until,
    next_at: date(o, "next_at"),
    created_at: date(o, "created_at"),
    deadline_at: date(o, "deadline_at"),
    manifest: m,
    manifest_hash: mh,
    reason: str(o, "reason", 64),
  };
  if (
    (expectedID && j.id !== expectedID) ||
    h !== collectionHash(d) ||
    j.workflow_id !== d.workflow.id ||
    j.workflow_version !== d.workflow.version ||
    j.workflow_hash !== d.workflow.hash ||
    j.fence !== j.attempts ||
    !/^[a-z_]{1,64}$/.test(j.reason) ||
    (m === null) !== (mh === null) ||
    (m !== null && hashValue(m) !== mh)
  )
    bad();
  if (
    Date.parse(j.deadline_at) - Date.parse(j.created_at) !==
      d.timeout_seconds * 1000 ||
    Date.parse(j.next_at) < Date.parse(j.created_at) ||
    Date.parse(j.next_at) > Date.parse(j.deadline_at)
  )
    bad();
  if (s === "reading") {
    if (
      !uuid(owner) ||
      until === null ||
      j.fence < 1 ||
      Date.parse(until) > Date.parse(j.deadline_at)
    )
      bad();
  } else if (owner !== "" || until !== null) bad();
  if (
    s === "queued" &&
    (j.revision !== 1 ||
      j.fence !== 0 ||
      j.manifest !== null ||
      captured ||
      j.next_at !== j.created_at)
  )
    bad();
  if (
    (s === "captured" && !captured) ||
    (captured && !["captured", "cancelled", "expired"].includes(s)) ||
    (captured && m === null)
  )
    bad();
  return j;
}
function input(v: unknown, j: CollectionJob): CollectionInput {
  const o = object(v);
  keys(o, [
    "id",
    "first_job_id",
    "workflow_id",
    "source_identity",
    "input_identity",
    "source_name",
    "size_bytes",
    "sha256",
    "target_path",
    "object_id",
    "state",
    "revision",
    "capture_fence",
    "capture_owner",
    "file_id",
    "run_id",
  ]);
  const s = str(o, "state", 16);
  if (!["pending", "accepted", "queued"].includes(s)) bad();
  const i: CollectionInput = {
    id: id(o, "id"),
    first_job_id: id(o, "first_job_id"),
    workflow_id: id(o, "workflow_id"),
    source_identity: hash(o, "source_identity"),
    input_identity: hash(o, "input_identity"),
    source_name: filename(str(o, "source_name", 128)),
    size_bytes: num(o, "size_bytes", 0, j.definition.source.max_file_bytes),
    sha256: hash(o, "sha256"),
    target_path: path(str(o, "target_path", 1024)),
    object_id: id(o, "object_id"),
    state: s as CollectionInput["state"],
    revision: num(o, "revision"),
    capture_fence: num(o, "capture_fence", 1, 8),
    capture_owner: id(o, "capture_owner"),
    file_id: o.file_id === null ? null : id(o, "file_id"),
    run_id: o.run_id === null ? null : id(o, "run_id"),
  };
  if (
    i.workflow_id !== j.workflow_id ||
    i.source_identity !== j.definition.source_identity ||
    i.input_identity !==
      digestBytes(
        new TextEncoder().encode(
          i.source_identity +
            ":" +
            i.source_name +
            ":" +
            i.size_bytes +
            ":" +
            i.sha256,
        ),
      ) ||
    (i.state === "pending") !== (i.file_id === null) ||
    (i.state === "queued") !== (i.run_id !== null) ||
    (i.file_id !== null && i.file_id !== i.object_id)
  )
    bad();
  if (
    i.first_job_id === j.id &&
    (i.target_path !==
      target(j.definition.source.target_directory, i.sha256, i.source_name) ||
      i.capture_fence > j.fence ||
      (j.state === "reading" &&
        i.capture_fence === j.fence &&
        i.capture_owner !== j.lease_owner))
  )
    bad();
  if (j.captured && i.state === "pending") bad();
  return i;
}
export function asCollectionView(
  v: unknown,
  expectedID: string,
  authority: number,
  expectedHash?: string,
): CollectionView {
  const o = object(v);
  keys(o, [
    "job",
    "inputs",
    "current_authority",
    "observed_state",
    "business_acceptance",
    "local_states",
  ]);
  const j = asCollectionJob(o.job, expectedID),
    inputs = array(o.inputs, 64).map((v) => input(v, j)),
    current = bool(o, "current_authority"),
    observed = state(o, "observed_state");
  if (
    (expectedHash && j.definition_hash !== expectedHash) ||
    o.business_acceptance !== "unknown" ||
    (current &&
      (j.definition.authority_revision !== authority ||
        ["cancelled", "expired"].includes(j.state))) ||
    observed !==
      (!current && !["cancelled", "expired"].includes(j.state)
        ? "attention"
        : j.state)
  )
    bad();
  if (
    inputs.length !== (j.manifest?.files.length ?? 0) ||
    new Set(inputs.map((i) => i.id)).size !== inputs.length ||
    new Set(inputs.map((i) => i.file_id).filter(Boolean)).size !==
      inputs.filter((i) => i.file_id !== null).length
  )
    bad();
  inputs.forEach((i, index) => {
    const f = j.manifest!.files[index]!;
    if (
      i.source_name !== f.name ||
      i.size_bytes !== f.size_bytes ||
      i.sha256 !== f.sha256
    )
      bad();
  });
  const local = array(o.local_states, 64).map((v, index) => {
    const l = object(v);
    keys(l, ["input_id", "state"]);
    const inputID = id(l, "input_id"),
      s = str(l, "state", 40),
      i = inputs[index];
    if (
      !i ||
      i.id !== inputID ||
      ![
        "pending",
        "awaiting_batch_capture",
        "held_or_unavailable",
        "unpublished_or_removed",
        "published",
      ].includes(s) ||
      (i.state === "pending" && s !== "pending") ||
      (s === "published" &&
        (i.file_id === null || (i.first_job_id === j.id && !j.captured))) ||
      (i.first_job_id === j.id &&
        i.file_id !== null &&
        !j.captured &&
        s !== "awaiting_batch_capture")
    )
      bad();
    return { input_id: inputID, state: s };
  });
  if (local.length !== inputs.length) bad();
  return {
    job: j,
    inputs,
    current_authority: current,
    observed_state: observed,
    business_acceptance: "unknown",
    local_states: local,
  };
}
export function asCollectionPage(v: unknown): {
  jobs: CollectionJob[];
  next?: string;
} {
  const o = object(v);
  keys(o, ["jobs"], ["next"]);
  const jobs = array(o.jobs, 100).map((v) => asCollectionJob(v));
  if (new Set(jobs.map((j) => j.id)).size !== jobs.length) bad();
  return { jobs, ...(o.next !== undefined ? { next: id(o, "next") } : {}) };
}
export function asCollectionResult(
  v: unknown,
  expected: {
    id?: string;
    hash: string;
    states: CollectionState[];
    revision?: number;
  },
): { resource: CollectionAction; replayed: boolean } {
  const o = object(v);
  keys(o, ["resource", "replayed"]);
  const r = object(o.resource);
  keys(r, ["kind", "id", "definition_hash", "state", "revision"]);
  const a: CollectionAction = {
    kind: "workflow_collection",
    id: id(r, "id"),
    definition_hash: hash(r, "definition_hash"),
    state: state(r, "state"),
    revision: num(r, "revision"),
  };
  if (
    r.kind !== "workflow_collection" ||
    (expected.id && a.id !== expected.id) ||
    a.definition_hash !== expected.hash ||
    !expected.states.includes(a.state) ||
    (expected.revision !== undefined && a.revision !== expected.revision)
  )
    bad();
  return { resource: a, replayed: bool(o, "replayed") };
}
function linked(i: CollectionInput): { file_id: string; run_id: string } {
  if (!i.file_id || !i.run_id) bad();
  return { file_id: i.file_id!, run_id: i.run_id! };
}
export function asCollectedRun(
  v: unknown,
  i: CollectionInput,
  d: CollectionDefinition,
): ScheduledRun {
  const r = asScheduledRun(v, linked(i), d);
  if (
    r.run.source.size_bytes !== i.size_bytes ||
    r.run.source.sha256 !== i.sha256 ||
    d.effects.length < 1
  )
    bad();
  return r;
}
export function asCollectedWork(
  v: unknown,
  i: CollectionInput,
  d: CollectionDefinition,
): ScheduledRun {
  const r = asScheduledWork(v, linked(i), d);
  if (
    r.run.source.size_bytes !== i.size_bytes ||
    r.run.source.sha256 !== i.sha256 ||
    d.effects.length < 1
  )
    bad();
  return r;
}
