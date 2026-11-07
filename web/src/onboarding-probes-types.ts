import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import { asSSHUsername } from "./ssh-metadata";

export interface ProbeReference {
  id: string;
  version: number;
  hash: string;
}
export interface ProbeRequest {
  plan: ProbeReference;
  requirement_id: string;
  connection: ProbeReference;
  expected_authority_revision: number;
}
export interface ProbeDefinition {
  schema_version: 1;
  profile: "sftp-readonly-v1";
  plan: ProbeReference;
  requirement_id: string;
  connection: ProbeReference;
  authority_revision: number;
}
export interface Probe {
  id: string;
  author_id: string;
  definition: ProbeDefinition;
  definition_hash: string;
  state: "queued" | "running" | "succeeded" | "failed" | "blocked" | "expired";
  revision: number;
  worker_key: string;
  lease_owner: string;
  lease_until: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  observation: {
    code: string;
    ssh_identity_and_authentication: boolean;
    sftp_negotiated: boolean;
    required_extensions: boolean;
    directory_traversable: boolean;
  };
}
export interface ProbeConnection extends ProbeReference {
  definition_hash: string;
  state: string;
  revision: number;
  address: string;
  user: string;
  directory: string;
  host_fingerprint: string;
  key_fingerprint: string;
}
export interface ProbeView {
  probe: Probe;
  connection?: ProbeConnection;
  current_bindings: boolean;
  binding_reason: string;
  evidence_strength: "connectivity_only";
  file_exchange_performed: false;
  production_active: false;
}
const invalid = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
function text(
  o: Record<string, unknown>,
  k: string,
  max: number,
  empty = false,
): string {
  const v = o[k];
  if (
    typeof v !== "string" ||
    (!empty && !v.length) ||
    new TextEncoder().encode(v).length > max ||
    /[\u0000-\u001f\u007f-\u009f]/.test(v) ||
    /[\ud800-\udfff]/u.test(v)
  )
    invalid();
  return v as string;
}
function id(o: Record<string, unknown>, k: string): string {
  const v = text(o, k, 36);
  if (!uuid(v)) invalid();
  return v;
}
function integer(
  o: Record<string, unknown>,
  k: string,
  max = Number.MAX_SAFE_INTEGER,
): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 1 || v > max)
    invalid();
  return v as number;
}
function hash(o: Record<string, unknown>, k: string): string {
  const v = text(o, k, 64);
  if (!/^[a-f0-9]{64}$/.test(v)) invalid();
  return v;
}
function time(o: Record<string, unknown>, k: string): string | null {
  if (o[k] === null) return null;
  const v = text(o, k, 64);
  if (!Number.isFinite(Date.parse(v))) invalid();
  return v;
}
function ref(value: unknown): ProbeReference {
  const o = object(value);
  return {
    id: id(o, "id"),
    version: integer(o, "version", 2147483647),
    hash: hash(o, "hash"),
  };
}
function bool(o: Record<string, unknown>, k: string): boolean {
  if (typeof o[k] !== "boolean") invalid();
  return o[k] as boolean;
}
export function probeDefinition(request: ProbeRequest): ProbeDefinition {
  return {
    schema_version: 1,
    profile: "sftp-readonly-v1",
    plan: ref(request.plan),
    requirement_id: id(object(request), "requirement_id"),
    connection: ref(request.connection),
    authority_revision: integer(object(request), "expected_authority_revision"),
  };
}
function definition(value: unknown): ProbeDefinition {
  const o = object(value);
  if (o.schema_version !== 1 || o.profile !== "sftp-readonly-v1") invalid();
  return {
    schema_version: 1,
    profile: "sftp-readonly-v1",
    plan: ref(o.plan),
    requirement_id: id(o, "requirement_id"),
    connection: ref(o.connection),
    authority_revision: integer(o, "authority_revision"),
  };
}
export function probeFingerprint(d: ProbeDefinition): string {
  const bytes = new TextEncoder().encode(JSON.stringify(definition(d)));
  try {
    return digestBytes(bytes);
  } finally {
    bytes.fill(0);
  }
}
export function asProbeConnection(value: unknown): ProbeConnection {
  const o = object(value),
    h = hash(o, "definition_hash"),
    state = text(o, "state", 16);
  if (!["active", "revoked"].includes(state)) invalid();
  return {
    id: id(o, "id"),
    version: integer(o, "version", 2147483647),
    hash: h,
    definition_hash: h,
    state,
    revision: integer(o, "revision"),
    address: text(o, "address", 128),
    user: asSSHUsername(o.user),
    directory: text(o, "directory", 1024),
    host_fingerprint: text(o, "host_fingerprint", 128),
    key_fingerprint: text(o, "key_fingerprint", 128),
  };
}
export function asProbe(
  value: unknown,
  author: string,
  expected?: { id?: string; hash?: string; request?: ProbeRequest },
): Probe {
  const o = object(value),
    d = definition(o.definition),
    obs = object(o.observation);
  const state = text(o, "state", 16),
    owner = text(o, "lease_owner", 36, true),
    key = text(o, "worker_key", 128, true);
  if (
    ![
      "queued",
      "running",
      "succeeded",
      "failed",
      "blocked",
      "expired",
    ].includes(state) ||
    (owner && !uuid(owner)) ||
    (key && !/^[A-Za-z0-9._:-]{1,128}$/.test(key))
  )
    invalid();
  const p: Probe = {
    id: id(o, "id"),
    author_id: id(o, "author_id"),
    definition: d,
    definition_hash: hash(o, "definition_hash"),
    state: state as Probe["state"],
    revision: integer(o, "revision", 3),
    worker_key: key,
    lease_owner: owner,
    lease_until: time(o, "lease_until"),
    started_at: time(o, "started_at"),
    completed_at: time(o, "completed_at"),
    created_at: time(o, "created_at") ?? invalid(),
    observation: {
      code: text(obs, "code", 64),
      ssh_identity_and_authentication: bool(
        obs,
        "ssh_identity_and_authentication",
      ),
      sftp_negotiated: bool(obs, "sftp_negotiated"),
      required_extensions: bool(obs, "required_extensions"),
      directory_traversable: bool(obs, "directory_traversable"),
    },
  };
  if (
    p.author_id !== author ||
    p.definition_hash !== probeFingerprint(d) ||
    (expected?.id && p.id !== expected.id) ||
    (expected?.hash && p.definition_hash !== expected.hash) ||
    (expected?.request &&
      JSON.stringify(d) !== JSON.stringify(probeDefinition(expected.request)))
  )
    invalid();
  if (
    ![
      "awaiting_worker",
      "probing",
      "connectivity_verified",
      "connection_failed",
      "required_extensions_missing",
      "directory_unavailable",
      "binding_changed",
      "lease_expired",
      "probe_deadline_exceeded",
    ].includes(p.observation.code)
  )
    invalid();
  const checks = p.observation;
  const anyCheck =
    checks.ssh_identity_and_authentication ||
    checks.sftp_negotiated ||
    checks.required_extensions ||
    checks.directory_traversable;
  if (
    checks.ssh_identity_and_authentication !== checks.sftp_negotiated ||
    (checks.required_extensions && !checks.sftp_negotiated) ||
    (checks.directory_traversable && !checks.required_extensions) ||
    ([
      "awaiting_worker",
      "probing",
      "binding_changed",
      "lease_expired",
      "connection_failed",
    ].includes(checks.code) &&
      anyCheck)
  )
    invalid();
  const positive =
    p.observation.ssh_identity_and_authentication &&
    p.observation.sftp_negotiated &&
    p.observation.required_extensions &&
    p.observation.directory_traversable;
  if (
    (p.state === "succeeded" &&
      (!positive || p.observation.code !== "connectivity_verified")) ||
    (p.state !== "succeeded" && p.observation.code === "connectivity_verified")
  )
    invalid();
  if (
    p.state === "queued" &&
    (p.revision !== 1 ||
      key ||
      owner ||
      p.started_at !== null ||
      p.completed_at !== null ||
      p.lease_until !== null ||
      p.observation.code !== "awaiting_worker")
  )
    invalid();
  if (
    p.state === "running" &&
    (p.revision !== 2 ||
      !key ||
      !owner ||
      !p.started_at ||
      !p.lease_until ||
      p.completed_at !== null ||
      p.observation.code !== "probing")
  )
    invalid();
  if (
    !["queued", "running"].includes(p.state) &&
    (!key || p.completed_at === null)
  )
    invalid();
  return p;
}
export function asProbeStart(
  value: unknown,
  author: string,
  request: ProbeRequest,
): Probe {
  const o = object(value);
  if (typeof o.replayed !== "boolean") invalid();
  const p = asProbe(o.resource, author, { request });
  if (p.state !== "queued") invalid();
  return p;
}
export function asProbeView(
  value: unknown,
  author: string,
  expected?: { id?: string; hash?: string },
): ProbeView {
  const o = object(value),
    probe = asProbe(o.probe, author, expected),
    current = bool(o, "current_bindings"),
    reason = text(o, "binding_reason", 32);
  if (
    o.evidence_strength !== "connectivity_only" ||
    o.file_exchange_performed !== false ||
    o.production_active !== false ||
    reason !== (current ? "current" : "binding_changed")
  )
    invalid();
  const connection =
    o.connection === undefined ? undefined : asProbeConnection(o.connection);
  if (
    current &&
    (!connection ||
      connection.id !== probe.definition.connection.id ||
      connection.version !== probe.definition.connection.version ||
      connection.hash !== probe.definition.connection.hash ||
      connection.state !== "active")
  )
    invalid();
  return {
    probe,
    ...(connection ? { connection } : {}),
    current_bindings: current,
    binding_reason: reason,
    evidence_strength: "connectivity_only",
    file_exchange_performed: false,
    production_active: false,
  };
}
export function asProbePage(
  value: unknown,
  author: string,
  plan: string,
): { probes: Probe[]; next?: string } {
  const o = object(value);
  if (!Array.isArray(o.probes) || o.probes.length > 100) invalid();
  const probes = (o.probes as unknown[]).map((p) => asProbe(p, author));
  if (
    probes.some((p) => p.definition.plan.id !== plan) ||
    new Set(probes.map((p) => p.id)).size !== probes.length
  )
    invalid();
  return { probes, ...(o.next !== undefined ? { next: id(o, "next") } : {}) };
}
