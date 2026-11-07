import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import { asSSHUsername } from "./ssh-metadata";
import {
  asFTPSConnectionProof,
  type FTPSConnectionProof,
} from "./ftps-metadata";
import {
  asCollectionHandoffView,
  type CollectionHandoffView,
} from "./collection-handoffs-types";
import {
  asCapturedRoutingMetadata,
  asCapturedRoutingInputPreview,
  type CapturedRoutingMetadata,
} from "./collection-routing-types";
import {
  asProgram,
  asExecutionPlan,
  asRoutingFacts,
  compileProgram,
  programFingerprint,
  type Program,
  type ProgramShape,
  type RoutingSource,
  type ExecutionPlan,
  type RoutingFile,
} from "./programs-types";
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
export const scheduledCollectionContract =
  "immutable-files-sha256-scheduled-manifest-v1";
export interface CollectionSource {
  kind: "sftp.collect" | "ftps.collect" | "local.collect";
  connection: Reference;
  manifest: string;
  target_directory: string;
  completion_contract:
    typeof collectionContract | typeof scheduledCollectionContract;
  max_files: number;
  max_file_bytes: number;
  max_total_bytes: number;
}
export interface WorkflowStep {
  id: string;
  kind: "sftp.deliver" | "ftps.deliver";
  connection: Reference;
  filename: string;
  encryption?: ScheduleEffect["encryption"];
}
export interface WorkflowDefinition {
  schema_version: 1 | 2;
  name: string;
  steps: WorkflowStep[];
  source?: CollectionSource;
  program?: Program;
}
export interface CollectionWorkflow extends WorkflowDefinition {
  source: CollectionSource;
}
export interface AnyWorkflowConfiguration {
  id: string;
  version: number;
  definition: WorkflowDefinition;
  definition_hash: string;
  state: "draft" | "approved" | "revoked";
  revision: number;
  approval_authority: number;
}
export interface WorkflowConfiguration extends AnyWorkflowConfiguration {
  definition: CollectionWorkflow;
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
  protocol?: "ftps" | "local";
  ftps?: FTPSConnectionProof;
  local?: LocalCollectionProof;
}
export interface LocalCollectionProof {
  profile: "freightctl-local-collection-source-v1";
  root_reference_sha256: string;
  configuration_sha256: string;
  root_fingerprint: string;
  read_only: true;
}
export interface CollectionScheduleBinding {
  schedule: Reference;
  occurrence_id: string;
  due_at: string;
  arrival_deadline_at: string;
  deadline_at: string;
  manifest_name: string;
  manifest_hash: string;
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
  schedule?: CollectionScheduleBinding;
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
  replacements?: CollectionReplacement[];
}
export interface CollectionReplacement {
  input_id: string;
  job_id: string;
  original_run_id: string;
  current_run_id: string;
  handoff_id: string;
  source_run_id: string;
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
  if (
    (o.kind !== "sftp.collect" &&
      o.kind !== "ftps.collect" &&
      o.kind !== "local.collect") ||
    ![collectionContract, scheduledCollectionContract].includes(
      String(o.completion_contract),
    )
  )
    bad();
  const contract =
    o.completion_contract as CollectionSource["completion_contract"];
  const manifest = str(o, "manifest", 160),
    directory = path(str(o, "target_directory", 1024));
  const name =
    contract === scheduledCollectionContract
      ? manifest.replace("{due_utc}", "20060102T150405Z")
      : manifest;
  if (
    contract === scheduledCollectionContract &&
    manifest.split("{due_utc}").length !== 2
  )
    bad();
  filename(name);
  if (!manifest.endsWith(".ready.json")) bad();
  target(directory, "a".repeat(64), "x".repeat(128));
  const maxFiles = num(o, "max_files", 1, 64),
    maxFile = num(o, "max_file_bytes", 1, 1073741824),
    maxTotal = num(o, "max_total_bytes", 1, maxFiles * maxFile);
  return {
    kind: o.kind as CollectionSource["kind"],
    connection: ref(o.connection),
    manifest,
    target_directory: directory,
    completion_contract: contract,
    max_files: maxFiles,
    max_file_bytes: maxFile,
    max_total_bytes: maxTotal,
  };
}
function asLocalCollectionProof(v: unknown): LocalCollectionProof {
  const o = object(v);
  keys(o, [
    "profile",
    "root_reference_sha256",
    "configuration_sha256",
    "root_fingerprint",
    "read_only",
  ]);
  if (
    o.profile !== "freightctl-local-collection-source-v1" ||
    o.read_only !== true
  )
    bad();
  return {
    profile: "freightctl-local-collection-source-v1",
    root_reference_sha256: hash(o, "root_reference_sha256"),
    configuration_sha256: hash(o, "configuration_sha256"),
    root_fingerprint: hash(o, "root_fingerprint"),
    read_only: true,
  };
}
export function asCollectionConnection(v: unknown): CollectionConnection {
  const o = object(v);
  keys(
    o,
    [
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
    ],
    o.protocol === "ftps"
      ? ["protocol", "ftps"]
      : o.protocol === "local"
        ? ["protocol", "local"]
        : [],
  );
  if (o.state !== "active" && o.state !== "revoked") bad();
  const directory = path(str(o, "directory", 1024));
  if (
    o.protocol !== undefined &&
    o.protocol !== "ftps" &&
    o.protocol !== "local"
  )
    bad();
  if (
    o.protocol === "ftps" &&
    (o.host_fingerprint !== "" ||
      o.key_fingerprint !== "" ||
      o.ftps === undefined)
  )
    bad();
  if (
    o.protocol === "local" &&
    (o.address !== "" ||
      o.user !== "" ||
      directory !== "/" ||
      o.host_fingerprint !== "" ||
      o.key_fingerprint !== "" ||
      o.local === undefined)
  )
    bad();
  return {
    id: id(o, "id"),
    version: num(o, "version", 1, 2147483647),
    definition_hash: hash(o, "definition_hash"),
    state: o.state as CollectionConnection["state"],
    revision: num(o, "revision"),
    address: o.protocol === "local" ? "" : str(o, "address", 300),
    user:
      o.protocol === "local"
        ? ""
        : o.protocol === "ftps"
          ? str(o, "user", 256)
          : asSSHUsername(o.user),
    directory,
    host_fingerprint:
      o.protocol === "ftps" || o.protocol === "local"
        ? ""
        : sshFingerprint(str(o, "host_fingerprint", 100)),
    key_fingerprint:
      o.protocol === "ftps" || o.protocol === "local"
        ? ""
        : sshFingerprint(str(o, "key_fingerprint", 100)),
    ...(o.protocol === "ftps"
      ? {
          protocol: "ftps" as const,
          ftps: asFTPSConnectionProof(o.ftps, directory),
        }
      : o.protocol === "local"
        ? { protocol: "local" as const, local: asLocalCollectionProof(o.local) }
        : {}),
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
export function asWorkflowDefinition(v: unknown): WorkflowDefinition {
  const o = object(v);
  keys(o, ["schema_version", "name", "steps"], ["source", "program"]);
  if (o.schema_version !== 1 && o.schema_version !== 2) bad();
  if (o.schema_version === 1 && o.program !== undefined) bad();
  const steps = array(o.steps, 16).map((v) => {
    const s = object(v);
    keys(s, ["id", "kind", "connection", "filename"], ["encryption"]);
    const step = str(s, "id", 64);
    if (
      (s.kind !== "sftp.deliver" && s.kind !== "ftps.deliver") ||
      !/^[a-z][a-z0-9_]{0,63}$/.test(step)
    )
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
      kind: s.kind as WorkflowStep["kind"],
      connection: ref(s.connection),
      filename: filename(str(s, "filename", 128)),
      ...(encryption ? { encryption } : {}),
    };
  });
  if (new Set(steps.map((s) => s.id)).size !== steps.length) bad();
  const d: WorkflowDefinition = {
    schema_version: o.schema_version as 1 | 2,
    name: str(o, "name", 256),
    steps,
    ...(o.source === undefined ? {} : { source: asCollectionSource(o.source) }),
    ...(o.schema_version === 2
      ? {
          program: asProgram(
            o.program,
            steps.map((s) => s.id),
            o.source !== undefined,
          ),
        }
      : {}),
  };
  if (d.schema_version === 1 && !d.steps.length && !d.source) bad();
  if (canonicalWorkflowBytes(d).length > 24576) bad();
  return d;
}
export function asCollectionWorkflow(v: unknown): CollectionWorkflow {
  const d = asWorkflowDefinition(v);
  if (!d.source) bad();
  return { ...d, source: d.source! };
}
export const collectionWorkflowHash = (d: WorkflowDefinition) => hashValue(d);
export function asWorkflowConfiguration(
  v: unknown,
  expected?: Reference,
): AnyWorkflowConfiguration {
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
  const d = asWorkflowDefinition(o.definition),
    h = hash(o, "definition_hash"),
    state = str(o, "state", 20);
  if (
    h !== collectionWorkflowHash(d) ||
    !["draft", "approved", "revoked"].includes(state)
  )
    bad();
  const c: AnyWorkflowConfiguration = {
    id: id(o, "id"),
    version: num(o, "version", 1, 2147483647),
    definition: d,
    definition_hash: h,
    state: state as AnyWorkflowConfiguration["state"],
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
export function asCollectionConfiguration(
  v: unknown,
  expected?: Reference,
): WorkflowConfiguration {
  const c = asWorkflowConfiguration(v, expected);
  return { ...c, definition: asCollectionWorkflow(c.definition) };
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
    c.kind !== d.source.kind ||
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
    connection.state !== "active" ||
    (d.source.kind === "ftps.collect") !== (connection.protocol === "ftps") ||
    (d.source.kind === "local.collect") !== (connection.protocol === "local")
  )
    bad();
  const effects = effectsForWorkflow(o.effects, d);
  return {
    definition: d,
    definition_hash: collectionWorkflowHash(d),
    effects,
    collection: { kind: d.source.kind, connection, source: d.source },
    external_contact: false as const,
    approval_required: true as const,
  };
}
export function effectsForWorkflow(
  v: unknown,
  d: WorkflowDefinition,
): ScheduleEffect[] {
  const effects = array(v, 16).map(asWorkflowEffect);
  if (effects.length !== d.steps.length) bad();
  effects.forEach((e, i) => {
    const s = d.steps[i]!;
    if (
      e.step_id !== s.id ||
      !equal(e.connection, s.connection) ||
      e.final_name_pattern !== "<delivery UUID>-" + s.filename ||
      !equal(e.encryption, s.encryption) ||
      (s.kind === "ftps.deliver") !== (e.protocol === "ftps")
    )
      bad();
    if (e.protocol !== "ftps") sshFingerprint(e.host_fingerprint);
  });
  return effects;
}
export function dueManifestName(source: CollectionSource, due: string): string {
  const instant = new Date(due);
  if (
    source.completion_contract !== scheduledCollectionContract ||
    !Number.isFinite(instant.getTime()) ||
    instant.getUTCMilliseconds() !== 0
  )
    bad();
  const token = instant.toISOString().slice(0, 19).replace(/[-:]/g, "") + "Z";
  return filename(source.manifest.replace("{due_utc}", token));
}
export function asCollectionScheduleBinding(
  v: unknown,
  source: CollectionSource,
): CollectionScheduleBinding {
  const o = object(v);
  keys(o, [
    "schedule",
    "occurrence_id",
    "due_at",
    "arrival_deadline_at",
    "deadline_at",
    "manifest_name",
    "manifest_hash",
  ]);
  const b = {
    schedule: ref(o.schedule),
    occurrence_id: id(o, "occurrence_id"),
    due_at: date(o, "due_at"),
    arrival_deadline_at: date(o, "arrival_deadline_at"),
    deadline_at: date(o, "deadline_at"),
    manifest_name: str(o, "manifest_name", 128),
    manifest_hash: hash(o, "manifest_hash"),
  };
  if (
    b.manifest_name !== dueManifestName(source, b.due_at) ||
    Date.parse(b.arrival_deadline_at) <= Date.parse(b.due_at) ||
    Date.parse(b.deadline_at) <= Date.parse(b.arrival_deadline_at)
  )
    bad();
  return b;
}
export function asCollectionDefinition(v: unknown): CollectionDefinition {
  const o = object(v);
  keys(
    o,
    [
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
    ],
    ["schedule"],
  );
  if (o.schema_version !== 1 || o.namespace_root !== "/") bad();
  const source = asCollectionSource(o.source),
    connection = asCollectionConnection(o.source_connection),
    identity = hash(o, "source_identity"),
    effects = array(o.effects, 16).map(asWorkflowEffect);
  if (
    connection.state !== "active" ||
    (source.kind === "ftps.collect") !== (connection.protocol === "ftps") ||
    (source.kind === "local.collect") !== (connection.protocol === "local") ||
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
        new TextEncoder().encode(
          connection.local
            ? "local-root-v1:" +
                connection.id +
                ":" +
                connection.local.root_fingerprint
            : connection.id + ":" + connection.directory,
        ),
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
    timeout_seconds: num(
      o,
      "timeout_seconds",
      1,
      o.schedule === undefined ? 3600 : 604800,
    ),
    effects,
    ...(o.schedule === undefined
      ? {}
      : { schedule: asCollectionScheduleBinding(o.schedule, source) }),
  };
  if (
    (d.schedule !== undefined) !==
    (source.completion_contract === scheduledCollectionContract)
  )
    bad();
  if (
    d.schedule &&
    Date.parse(d.schedule.deadline_at) - Date.parse(d.schedule.due_at) !==
      d.timeout_seconds * 1000
  )
    bad();
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
    d.schedule !== undefined ||
    d.source.completion_contract !== collectionContract ||
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
    (d.schedule
      ? j.deadline_at !== d.schedule.deadline_at ||
        Date.parse(j.created_at) < Date.parse(d.schedule.due_at) ||
        Date.parse(j.created_at) >= Date.parse(j.deadline_at)
      : Date.parse(j.deadline_at) - Date.parse(j.created_at) !==
        d.timeout_seconds * 1000) ||
    (d.schedule && mh !== null && mh !== d.schedule.manifest_hash) ||
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
  keys(
    o,
    [
      "job",
      "inputs",
      "current_authority",
      "observed_state",
      "business_acceptance",
      "local_states",
    ],
    ["replacements"],
  );
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
  const replacements =
    o.replacements === undefined
      ? undefined
      : array(o.replacements, 64).map((v) => {
          const r = object(v);
          keys(r, [
            "input_id",
            "job_id",
            "original_run_id",
            "current_run_id",
            "handoff_id",
            "source_run_id",
          ]);
          const result: CollectionReplacement = {
            input_id: id(r, "input_id"),
            job_id: id(r, "job_id"),
            original_run_id: id(r, "original_run_id"),
            current_run_id: id(r, "current_run_id"),
            handoff_id: id(r, "handoff_id"),
            source_run_id: id(r, "source_run_id"),
          };
          const i = inputs.find((i) => i.id === result.input_id);
          if (
            !i ||
            !i.run_id ||
            i.state !== "queued" ||
            result.job_id !== i.first_job_id ||
            result.original_run_id !== i.run_id ||
            result.current_run_id === result.original_run_id ||
            result.current_run_id === result.source_run_id
          )
            bad();
          return result;
        });
  if (
    replacements &&
    ["input_id", "current_run_id", "handoff_id"].some(
      (key) =>
        new Set(replacements.map((r) => r[key as keyof CollectionReplacement]))
          .size !== replacements.length,
    )
  )
    bad();
  return {
    job: j,
    inputs,
    current_authority: current,
    observed_state: observed,
    business_acceptance: "unknown",
    local_states: local,
    ...(replacements ? { replacements } : {}),
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
export interface CollectionRunContext {
  workflow: AnyWorkflowConfiguration;
  job: CollectionJob;
  routing?: { view: CollectionView; metadata: CapturedRoutingMetadata };
  handoff?: { view: CollectionView; metadata: CollectionHandoffView };
}

function handoffExecution(
  context: CollectionRunContext,
  input: CollectionInput,
) {
  if (!context.handoff) return undefined;
  const { view } = context.handoff;
  const metadata = asCollectionHandoffView(
    context.handoff.metadata,
    view,
    context.handoff.metadata.handoff.id,
  );
  const r = view.replacements?.find((r) => r.input_id === input.id);
  if (
    metadata.handoff.state !== "completed" ||
    !r ||
    r.handoff_id !== metadata.handoff.id ||
    r.current_run_id !== metadata.handoff.planned_run_id ||
    r.original_run_id !== input.run_id ||
    context.job.id !== view.job.id ||
    context.job.definition_hash !== view.job.definition_hash
  )
    bad();
  return metadata;
}

function routingExecution(context: CollectionRunContext) {
  const r = context.routing;
  if (!r) return undefined;
  const metadata = asCapturedRoutingMetadata(r.metadata, r.view);
  if (
    !metadata.authorization ||
    !metadata.workflow ||
    r.view.job.id !== context.job.id ||
    r.view.job.definition_hash !== context.job.definition_hash ||
    r.view.job.manifest_hash !== context.job.manifest_hash
  )
    bad();
  return metadata as CapturedRoutingMetadata & {
    authorization: NonNullable<CapturedRoutingMetadata["authorization"]>;
    workflow: WorkflowConfiguration;
  };
}
export function workflowProgramShape(d: WorkflowDefinition): ProgramShape {
  if (d.schema_version !== 2 || !d.program) bad();
  return {
    schema_version: 2,
    steps: d.steps,
    ...(d.source ? { source: d.source } : {}),
    program: d.program!,
  };
}
export function compileCollectionProgram(
  d: CollectionWorkflow,
  facts: unknown,
): ExecutionPlan {
  return compileProgram(workflowProgramShape(asCollectionWorkflow(d)), facts);
}
function originalRoutingSource(
  i: CollectionInput,
  d: CollectionDefinition,
  context: CollectionRunContext,
): RoutingSource {
  const workflow = asCollectionConfiguration(context.workflow, d.workflow),
    job = context.job;
  if (
    !equal(workflow.definition.source, d.source) ||
    job.id !== i.first_job_id ||
    !job.captured ||
    job.workflow_id !== d.workflow.id ||
    job.workflow_version !== d.workflow.version ||
    job.workflow_hash !== d.workflow.hash ||
    i.workflow_id !== d.workflow.id ||
    !equal(job.definition, d) ||
    !job.manifest ||
    !job.manifest_hash
  )
    bad();
  effectsForWorkflow(d.effects, workflow.definition);
  const m = manifest(job.manifest, d.source),
    index = m.files.findIndex(
      (f) =>
        f.name === i.source_name &&
        f.sha256 === i.sha256 &&
        f.size_bytes === i.size_bytes,
    );
  if (index < 0 || hashValue(m) !== job.manifest_hash) bad();
  return {
    collection_id: job.id,
    manifest_hash: job.manifest_hash!,
    name: i.source_name,
    batch_id: m.batch_id,
    file_count: m.files.length,
    index,
  };
}
export interface CollectionRunPreview {
  workflow: Reference;
  source: RoutingFile;
  potential_effects: ScheduleEffect[];
  selected_effects: ScheduleEffect[];
  execution_plan?: ExecutionPlan;
  execution_plan_hash?: string;
  external_contact: false;
}
export function asCollectionRunPreview(
  v: unknown,
  i: CollectionInput,
  d: CollectionDefinition,
  context: CollectionRunContext,
): CollectionRunPreview {
  const routing = routingExecution(context);
  if (routing) {
    originalRoutingSource(i, d, context);
    const preview = asCapturedRoutingInputPreview(
      v,
      i.id,
      context.routing!.view,
      routing.workflow,
      routing.authorization.definition,
    );
    if (!equal(preview.potential_effects, routing.effects)) bad();
    return preview;
  }
  const o = object(v);
  keys(
    o,
    [
      "workflow",
      "source",
      "potential_effects",
      "selected_effects",
      "external_contact",
    ],
    ["execution_plan", "execution_plan_hash"],
  );
  const wf = asCollectionConfiguration(context.workflow, d.workflow),
    source = asRoutingFacts({ file: o.source }).file,
    expectedSource = originalRoutingSource(i, d, context),
    potential = effectsForWorkflow(o.potential_effects, wf.definition);
  if (
    !equal(ref(o.workflow), d.workflow) ||
    !equal(potential, d.effects) ||
    o.external_contact !== false ||
    source.id !== i.file_id ||
    source.sha256 !== i.sha256 ||
    source.size_bytes !== i.size_bytes
  )
    bad();
  let plan: ExecutionPlan | undefined, planHash: string | undefined;
  if (wf.definition.schema_version === 2) {
    plan = asExecutionPlan(
      o.execution_plan,
      workflowProgramShape(wf.definition),
      { file: source, source: expectedSource },
    );
    planHash = hash(o, "execution_plan_hash");
    if (programFingerprint(plan) !== planHash) bad();
  } else if (
    o.execution_plan !== undefined ||
    o.execution_plan_hash !== undefined
  )
    bad();
  const selected = array(o.selected_effects, 16).map(asWorkflowEffect),
    ids = plan?.selected_steps ?? wf.definition.steps.map((s) => s.id);
  if (
    !equal(
      selected,
      ids.map((id) => potential.find((e) => e.step_id === id)),
    )
  )
    bad();
  return {
    workflow: d.workflow,
    source,
    potential_effects: potential,
    selected_effects: selected,
    ...(plan ? { execution_plan: plan, execution_plan_hash: planHash! } : {}),
    external_contact: false,
  };
}
export function asCollectedRun(
  v: unknown,
  i: CollectionInput,
  d: CollectionDefinition,
  context?: CollectionRunContext,
): ScheduledRun {
  const source = context ? originalRoutingSource(i, d, context) : undefined;
  const handoff = context ? handoffExecution(context, i) : undefined;
  if (handoff) {
    const def = handoff.handoff.definition;
    const r = asScheduledRun(
      v,
      { file_id: i.file_id!, run_id: handoff.handoff.planned_run_id },
      {
        workflow: def.workflow,
        authority_revision: def.authority_revision,
        effects: handoff.effects,
      },
      handoff.workflow,
      source,
    );
    if (
      r.run.execution_plan_hash !== def.plan_hash ||
      !equal(r.run.execution_plan, def.plan)
    )
      bad();
    return r;
  }
  const routing = context ? routingExecution(context) : undefined;
  if (routing) {
    const r = asScheduledRun(
      v,
      linked(i),
      {
        workflow: routing.authorization.definition.workflow,
        authority_revision: routing.authorization.definition.authority_revision,
        effects: routing.effects,
      },
      routing.workflow,
      source,
      routing.authorization.id,
    );
    checkRoutingRun(r, i, routing);
    return r;
  }
  const r = asScheduledRun(v, linked(i), d, context?.workflow, source);
  if (
    r.run.source.size_bytes !== i.size_bytes ||
    r.run.source.sha256 !== i.sha256 ||
    (d.effects.length < 1 && !r.run.execution_plan)
  )
    bad();
  return r;
}
export function asCollectedWork(
  v: unknown,
  i: CollectionInput,
  d: CollectionDefinition,
  context?: CollectionRunContext,
): ScheduledRun {
  const source = context ? originalRoutingSource(i, d, context) : undefined;
  const handoff = context ? handoffExecution(context, i) : undefined;
  if (handoff) {
    const def = handoff.handoff.definition;
    const r = asScheduledWork(
      v,
      { file_id: i.file_id!, run_id: handoff.handoff.planned_run_id },
      {
        workflow: def.workflow,
        authority_revision: def.authority_revision,
        effects: handoff.effects,
      },
      handoff.workflow,
      source,
    );
    if (
      r.run.execution_plan_hash !== def.plan_hash ||
      !equal(r.run.execution_plan, def.plan)
    )
      bad();
    return r;
  }
  const routing = context ? routingExecution(context) : undefined;
  if (routing) {
    const r = asScheduledWork(
      v,
      linked(i),
      {
        workflow: routing.authorization.definition.workflow,
        authority_revision: routing.authorization.definition.authority_revision,
        effects: routing.effects,
      },
      routing.workflow,
      source,
      routing.authorization.id,
    );
    checkRoutingRun(r, i, routing);
    return r;
  }
  const r = asScheduledWork(v, linked(i), d, context?.workflow, source);
  if (
    r.run.source.size_bytes !== i.size_bytes ||
    r.run.source.sha256 !== i.sha256 ||
    (d.effects.length < 1 && !r.run.execution_plan)
  )
    bad();
  return r;
}

export { manifest as asProducerManifest };

function checkRoutingRun(
  run: ScheduledRun,
  input: CollectionInput,
  metadata: CapturedRoutingMetadata & {
    authorization: NonNullable<CapturedRoutingMetadata["authorization"]>;
  },
) {
  const binding = metadata.authorization.definition.inputs.find(
    (b) => b.input_id === input.id && b.file_id === input.file_id,
  );
  if (
    !binding ||
    binding.plan_hash !== run.run.execution_plan_hash ||
    run.run.source.sha256 !== input.sha256 ||
    run.run.source.size_bytes !== input.size_bytes
  )
    bad();
}

export interface WorkflowDifference {
  workflow_id: string;
  from_version: number;
  to_version: number;
  from_hash: string;
  to_hash: string;
  before: WorkflowDefinition;
  after: WorkflowDefinition;
  name_changed: boolean;
  order_changed: boolean;
  source_changed: boolean;
  program_changed: boolean;
  added_steps: string[];
  removed_steps: string[];
  changed_steps: string[];
}
export function asWorkflowDifference(
  v: unknown,
  current: AnyWorkflowConfiguration,
): WorkflowDifference {
  const o = object(v),
    configuration = asWorkflowConfiguration(current);
  keys(
    o,
    [
      "workflow_id",
      "from_version",
      "to_version",
      "from_hash",
      "to_hash",
      "before",
      "after",
      "name_changed",
      "order_changed",
      "added_steps",
      "removed_steps",
      "changed_steps",
    ],
    ["source_changed", "program_changed"],
  );
  const before = asWorkflowDefinition(o.before),
    after = asWorkflowDefinition(o.after),
    from = num(o, "from_version", 1, 2147483647),
    to = num(o, "to_version", 1, 2147483647),
    fromHash = hash(o, "from_hash"),
    toHash = hash(o, "to_hash");
  if (
    id(o, "workflow_id") !== configuration.id ||
    to !== configuration.version ||
    from !== to - 1 ||
    fromHash !== collectionWorkflowHash(before) ||
    toHash !== collectionWorkflowHash(after) ||
    toHash !== configuration.definition_hash ||
    !equal(after, configuration.definition)
  )
    bad();
  const oldSteps = new Map(before.steps.map((s) => [s.id, s])),
    newSteps = new Map(after.steps.map((s) => [s.id, s]));
  const added = after.steps.filter((s) => !oldSteps.has(s.id)).map((s) => s.id),
    removed = before.steps.filter((s) => !newSteps.has(s.id)).map((s) => s.id),
    changed = after.steps
      .filter((s) => oldSteps.has(s.id) && !equal(oldSteps.get(s.id), s))
      .map((s) => s.id);
  const flag = (k: string, expected: boolean) => {
    const actual = o[k] === undefined ? false : bool(o, k);
    if (actual !== expected) bad();
    return actual;
  };
  const names = (k: string, expected: string[]) => {
    const actual = array(o[k], 16).map((v) => {
      if (typeof v !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(v)) bad();
      return v as string;
    });
    if (!equal(actual, expected)) bad();
    return actual;
  };
  return {
    workflow_id: configuration.id,
    from_version: from,
    to_version: to,
    from_hash: fromHash,
    to_hash: toHash,
    before,
    after,
    name_changed: flag("name_changed", before.name !== after.name),
    order_changed: flag(
      "order_changed",
      !equal(
        before.steps.map((s) => s.id),
        after.steps.map((s) => s.id),
      ),
    ),
    source_changed: flag("source_changed", !equal(before.source, after.source)),
    program_changed: flag(
      "program_changed",
      !equal(before.program, after.program),
    ),
    added_steps: names("added_steps", added),
    removed_steps: names("removed_steps", removed),
    changed_steps: names("changed_steps", changed),
  };
}
