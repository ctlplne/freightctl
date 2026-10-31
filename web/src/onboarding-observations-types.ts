import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import { asDispatchDefinition, handoffHash } from "./onboarding-handoffs-types";
import type { ProductionDefinition } from "./onboarding-releases-types";
import type { ProbeReference } from "./onboarding-probes-types";
export interface ObservationSelection {
  source_run_id: string;
  source_hash: string;
  probe_id: string;
  file_id: string;
  expected_authority_revision: number;
}
export interface ObservationDefinition {
  schema_version: 1;
  profile: "sftp-published-observation-v1";
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
    state: "publishing" | "ambiguous";
    attempts: number;
    fence: number;
  };
  original_connection: ProbeReference;
  authorized_file: ProductionDefinition["file"];
  source_recheck_id: string;
  probe: { id: string; revision: number; hash: string };
  observer: {
    schema_version: 1;
    profile: "sftp-readonly-v1";
    plan: ProbeReference;
    requirement_id: string;
    connection: ProbeReference;
    authority_revision: number;
  };
  effect: {
    address: string;
    user: string;
    directory: string;
    path: string;
    host_fingerprint: string;
    key_fingerprint: string;
  };
  wire: {
    sha256: string;
    size_bytes: number;
    ciphertext: {
      object_id: string;
      sha256: string;
      size_bytes: number;
    } | null;
  };
  required_receipt: "transport" | "integrity" | "business";
  storage_id: string;
  namespace_root: "/";
  authority_revision: number;
}
export interface ObservationPreview {
  definition: ObservationDefinition;
  definition_hash: string;
  external_contact: false;
  resend_authorized: false;
}
export interface ObservationResult {
  code: string;
  integrity_confirmed: boolean;
  sha256: string;
  size_bytes: number;
  file_fsync_acknowledged: false;
  reconciled: boolean;
  business_acceptance: "unknown";
  directory_power_loss_durability: "not established";
}
export interface ObservationSummary {
  id: string;
  author_id: string;
  source_run_id: string;
  definition_hash: string;
  state:
    | "proposed"
    | "approved"
    | "running"
    | "succeeded"
    | "unconfirmed"
    | "blocked"
    | "expired"
    | "cancelled";
  revision: number;
  worker_key: string;
  lease_owner: string;
  lease_until: string | null;
  started_at: string | null;
  completed_at: string | null;
  result: ObservationResult;
  created_at: string;
  changed_event_id: string;
}
export interface ObservationView {
  observation: ObservationSummary & { definition: ObservationDefinition };
  current_bindings: boolean;
  binding_reason: string;
  contact_attempted: boolean;
  resend_authorized: false;
  observed_at: string;
}
function bad(): never {
  throw new ApiError("invalid_server_response", 502);
}
function text(
  o: Record<string, unknown>,
  k: string,
  n = 128,
  empty = false,
): string {
  const v = o[k];
  if (
    typeof v !== "string" ||
    (!v && !empty) ||
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
function num(o: Record<string, unknown>, k: string, min = 1): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) bad();
  return v as number;
}
function ref(v: unknown): ProbeReference {
  const o = object(v),
    version = num(o, "version");
  if (version > 2147483647) bad();
  return { id: id(o, "id"), version, hash: hash(o, "hash") };
}
function revision(v: unknown): { id: string; revision: number; hash: string } {
  const o = object(v);
  return {
    id: id(o, "id"),
    revision: num(o, "revision"),
    hash: hash(o, "hash"),
  };
}
function file(v: unknown): ProductionDefinition["file"] {
  const o = object(v);
  return {
    id: id(o, "id"),
    size_bytes: num(o, "size_bytes", 0),
    sha256: hash(o, "sha256"),
    policy: text(o, "policy", 256),
    accepted_event_id: id(o, "accepted_event_id"),
  };
}
function date(
  o: Record<string, unknown>,
  k: string,
  nullable = false,
): string | null {
  if (o[k] === null && nullable) return null;
  const v = text(o, k, 64);
  if (!/^\d{4}-\d{2}-\d{2}T.*Z$/.test(v) || !Number.isFinite(Date.parse(v)))
    bad();
  return v;
}
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
function ticks(value: string): bigint {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(
    value,
  );
  if (!match) bad();
  const base = Date.parse(match[1] + "Z");
  if (
    !Number.isFinite(base) ||
    new Date(base).toISOString().slice(0, 19) !== match[1]
  )
    bad();
  return BigInt(base) * 1000000n + BigInt((match[2] ?? "").padEnd(9, "0"));
}
export function observationHash(
  d: ObservationDefinition | ObservationDefinition["observer"],
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
export function asObservationDefinition(
  value: unknown,
  author: string,
  planID: string,
): ObservationDefinition {
  const o = object(value),
    s = object(o.source),
    raw = object(s.dispatch),
    before = asDispatchDefinition(raw.definition),
    plan = ref(s.plan),
    delivery = revision(s.delivery),
    state = text(s, "state", 16),
    attempts = num(s, "attempts"),
    fence = num(s, "fence"),
    p = revision(o.probe),
    obs = object(o.observer),
    file0 = file(o.authorized_file),
    recheck = text(o, "source_recheck_id", 36, true),
    fx = object(o.effect),
    w = object(o.wire),
    required = text(o, "required_receipt", 16),
    authority = num(o, "authority_revision");
  const observer: ObservationDefinition["observer"] = {
    schema_version: 1,
    profile: "sftp-readonly-v1",
    plan: ref(obs.plan),
    requirement_id: id(obs, "requirement_id"),
    connection: ref(obs.connection),
    authority_revision: num(obs, "authority_revision"),
  };
  const effect = {
    address: text(fx, "address", 512),
    user: text(fx, "user", 128),
    directory: text(fx, "directory", 4096),
    path: text(fx, "path", 4352),
    host_fingerprint: text(fx, "host_fingerprint", 128),
    key_fingerprint: text(fx, "key_fingerprint", 128),
  };
  let ciphertext: ObservationDefinition["wire"]["ciphertext"] = null;
  const wireHash = hash(w, "sha256"),
    wireSize = num(w, "size_bytes", 0);
  if (w.ciphertext !== null) {
    const c = object(w.ciphertext);
    ciphertext = {
      object_id: id(c, "object_id"),
      sha256: hash(c, "sha256"),
      size_bytes: num(c, "size_bytes"),
    };
    if (
      !before.effect.encryption ||
      ciphertext.sha256 !== wireHash ||
      ciphertext.size_bytes !== wireSize ||
      wireSize >
        before.file.size_bytes +
          Math.floor(before.file.size_bytes / 128) +
          65536
    )
      bad();
  } else if (
    before.effect.encryption ||
    wireHash !== before.file.sha256 ||
    wireSize !== before.file.size_bytes
  )
    bad();
  if (
    o.schema_version !== 1 ||
    o.profile !== "sftp-published-observation-v1" ||
    raw.author_id !== author ||
    raw.definition_hash !== handoffHash(before) ||
    plan.id !== planID ||
    observer.plan.id !== planID ||
    obs.schema_version !== 1 ||
    obs.profile !== "sftp-readonly-v1" ||
    p.revision !== 3 ||
    p.hash !== observationHash(observer) ||
    observer.requirement_id !== before.requirement_id ||
    observer.connection.id !== ref(o.original_connection).id ||
    observer.authority_revision !== authority ||
    !["publishing", "ambiguous"].includes(state) ||
    attempts > 8 ||
    fence !== attempts ||
    delivery.revision < (state === "publishing" ? 4 : 5) ||
    file0.sha256 !== before.file.sha256 ||
    file0.size_bytes !== before.file.size_bytes ||
    (file0.id === before.file.id
      ? !same(file0, before.file) || recheck !== ""
      : !uuid(recheck)) ||
    effect.address !== before.effect.address ||
    effect.user !== before.effect.user ||
    effect.directory !== before.effect.directory ||
    effect.path !==
      before.effect.directory.replace(/\/$/, "") +
        "/" +
        delivery.id +
        "-" +
        before.effect.filename ||
    !effect.host_fingerprint.startsWith("SHA256:") ||
    !effect.key_fingerprint.startsWith("SHA256:") ||
    !["transport", "integrity", "business"].includes(required) ||
    o.storage_id !== before.storage_id ||
    o.namespace_root !== "/"
  )
    bad();
  return {
    schema_version: 1,
    profile: "sftp-published-observation-v1",
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
      delivery,
      state: state as "publishing" | "ambiguous",
      attempts,
      fence,
    },
    original_connection: ref(o.original_connection),
    authorized_file: file0,
    source_recheck_id: recheck,
    probe: p,
    observer,
    effect,
    wire: { sha256: wireHash, size_bytes: wireSize, ciphertext },
    required_receipt: required as ObservationDefinition["required_receipt"],
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    authority_revision: authority,
  };
}
export function asObservationPreview(
  value: unknown,
  selection: ObservationSelection,
  author: string,
  plan: string,
): ObservationPreview {
  const o = object(value),
    d = asObservationDefinition(o.definition, author, plan),
    h = hash(o, "definition_hash");
  if (
    d.source.dispatch.id !== selection.source_run_id ||
    d.source.dispatch.definition_hash !== selection.source_hash ||
    d.probe.id !== selection.probe_id ||
    d.authorized_file.id !== selection.file_id ||
    d.authority_revision !== selection.expected_authority_revision ||
    h !== observationHash(d) ||
    o.external_contact !== false ||
    o.resend_authorized !== false
  )
    bad();
  return {
    definition: d,
    definition_hash: h,
    external_contact: false,
    resend_authorized: false,
  };
}
export function asObservationSummary(
  value: unknown,
  author: string,
): ObservationSummary {
  const o = object(value),
    state = text(o, "state", 16),
    r = num(o, "revision"),
    key = text(o, "worker_key", 128, true),
    owner = text(o, "lease_owner", 36, true),
    lease = date(o, "lease_until", true),
    started = date(o, "started_at", true),
    completed = date(o, "completed_at", true),
    raw = object(o.result),
    success = state === "succeeded";
  const codes: Record<string, string> = {
    proposed: "awaiting_review",
    approved: "approved",
    running: "observing",
    succeeded: "remote_file_integrity_observed",
    unconfirmed: "remote_postcondition_not_confirmed",
    blocked: "binding_changed",
    expired: "lease_expired",
    cancelled: "cancelled",
  };
  if (
    !(state in codes) ||
    o.author_id !== author ||
    r > 4 ||
    (state === "proposed" && r !== 1) ||
    (state === "approved" && r !== 2) ||
    (state === "running" && r !== 3) ||
    (state === "cancelled" && ![2, 3].includes(r)) ||
    (["succeeded", "unconfirmed", "expired"].includes(state) && r !== 4) ||
    (state === "blocked" && ![3, 4].includes(r))
  )
    bad();
  const claimed = state === "running" || r === 4;
  if (
    claimed
      ? !uuid(owner) ||
        !started ||
        !lease ||
        ticks(lease) !== ticks(started) + 30000000000n ||
        !/^[A-Za-z0-9._:-]{1,128}$/.test(key)
      : owner !== "" ||
        lease !== null ||
        started !== null ||
        (state !== "blocked" && key !== "")
  )
    bad();
  if (
    state === "running" || state === "proposed" || state === "approved"
      ? completed !== null
      : completed === null
  )
    bad();
  if (
    claimed &&
    completed &&
    lease &&
    (state === "expired"
      ? ticks(completed) < ticks(lease)
      : ticks(completed) >= ticks(lease))
  )
    bad();
  if (
    raw.code !== codes[state] ||
    raw.integrity_confirmed !== success ||
    raw.reconciled !== success ||
    raw.file_fsync_acknowledged !== false ||
    raw.business_acceptance !== "unknown" ||
    raw.directory_power_loss_durability !== "not established"
  )
    bad();
  const sha = success ? hash(raw, "sha256") : text(raw, "sha256", 64, true),
    size = num(raw, "size_bytes", 0);
  if (!success && (sha !== "" || size !== 0)) bad();
  return {
    id: id(o, "id"),
    author_id: author,
    source_run_id: id(o, "source_run_id"),
    definition_hash: hash(o, "definition_hash"),
    state: state as ObservationSummary["state"],
    revision: r,
    worker_key: key,
    lease_owner: owner,
    lease_until: lease,
    started_at: started,
    completed_at: completed,
    result: {
      code: codes[state]!,
      integrity_confirmed: success,
      sha256: sha,
      size_bytes: size,
      file_fsync_acknowledged: false,
      reconciled: success,
      business_acceptance: "unknown",
      directory_power_loss_durability: "not established",
    },
    created_at: date(o, "created_at")!,
    changed_event_id: id(o, "changed_event_id"),
  };
}
export function asObservationReceipt(
  value: unknown,
  author: string,
  expected: { hash: string; state: string; source: string; id?: string },
): ObservationSummary {
  const o = object(value),
    r = object(o.resource),
    s = asObservationSummary(r.observation, author);
  if (
    typeof o.replayed !== "boolean" ||
    r.kind !== "onboarding_observation" ||
    s.definition_hash !== expected.hash ||
    s.state !== expected.state ||
    s.source_run_id !== expected.source ||
    (expected.id && s.id !== expected.id)
  )
    bad();
  return s;
}
export function asObservationView(
  value: unknown,
  author: string,
  plan: string,
  expected: { id: string; hash: string },
  allowContact = false,
): ObservationView {
  const o = object(value),
    s = asObservationSummary(o.observation, author),
    d = asObservationDefinition(object(o.observation).definition, author, plan),
    reason = text(o, "binding_reason", 32),
    terminal = !["proposed", "approved", "running"].includes(s.state);
  if (
    s.id !== expected.id ||
    s.definition_hash !== expected.hash ||
    s.definition_hash !== observationHash(d) ||
    s.source_run_id !== d.source.dispatch.id ||
    typeof o.current_bindings !== "boolean" ||
    typeof o.contact_attempted !== "boolean" ||
    (!allowContact && o.contact_attempted !== false) ||
    o.resend_authorized !== false ||
    (terminal
      ? o.current_bindings !== false || reason !== s.state
      : o.current_bindings
        ? reason !== "current"
        : reason !== "binding_changed") ||
    (s.result.integrity_confirmed &&
      (s.result.sha256 !== d.wire.sha256 ||
        s.result.size_bytes !== d.wire.size_bytes))
  )
    bad();
  return {
    observation: { ...s, definition: d },
    current_bindings: o.current_bindings as boolean,
    binding_reason: reason,
    contact_attempted: o.contact_attempted as boolean,
    resend_authorized: false,
    observed_at: date(o, "observed_at")!,
  };
}
export function asObservationPage(
  value: unknown,
  author: string,
): { observations: ObservationSummary[]; next?: string } {
  const o = object(value);
  if (!Array.isArray(o.observations) || o.observations.length > 100) bad();
  const observations = (o.observations as unknown[]).map((v) =>
    asObservationSummary(v, author),
  );
  if (new Set(observations.map((x) => x.id)).size !== observations.length)
    bad();
  return {
    observations,
    ...(o.next === undefined ? {} : { next: id(o, "next") }),
  };
}
