import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import { controlledArtifactPolicyHash } from "./artifact-policy";

type Obj = Record<string, unknown>;
export type RecheckMode = "not_required" | "reuse_exact" | "require_new";
export interface RecheckOptions {
  target_path: string;
  signature_mode: RecheckMode;
  reason: string;
}
export interface RecheckPlan extends Obj {
  source: Obj & {
    file: Obj & {
      id: string;
      sha256: string;
      size_bytes: number;
      policy: string;
    };
  };
  policy: { id: string; version: number; hash: string };
  namespace_root: string;
  authority_revision: number;
  storage_id: string;
  signature_mode: RecheckMode;
  reason: string;
  target?: Obj;
}
export interface RecheckDefinition {
  schema_version: 1;
  plan: RecheckPlan;
  staging_slots: { file_id: string; signature_object_id?: string }[];
}
export interface Recheck {
  id: string;
  source_file_id: string;
  definition: RecheckDefinition;
  definition_hash: string;
  state: "proposed" | "approved" | "cancelled" | "copied";
  revision: number;
  new_file_id: string;
  result: Obj;
}
export interface RecheckPreview {
  plan: RecheckPlan;
  previous_policy?: Obj;
  current_policy: Obj;
  effects: string;
}
export interface RecheckView {
  kind: "file_recheck";
  recheck: Recheck;
  current: boolean;
  code: string;
  previous_policy?: Obj;
  selected_policy?: Obj;
}
const bad = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
function keys(o: Obj, allowed: string[]) {
  if (Object.keys(o).some((k) => !allowed.includes(k))) bad();
}
function text(o: Obj, key: string, max = 4096, empty = false): string {
  const x = o[key];
  if (
    typeof x !== "string" ||
    (!empty && !x.length) ||
    new TextEncoder().encode(x).length > max ||
    /[\u0000-\u001f\u007f-\u009f]/.test(x) ||
    /[\ud800-\udfff]/u.test(x)
  )
    bad();
  return x as string;
}
function integer(
  o: Obj,
  k: string,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): number {
  const n = o[k];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max)
    bad();
  return n as number;
}
function id(o: Obj, k: string, empty = false) {
  const x = text(o, k, 36, empty);
  if (x !== "" || !empty) if (!uuid(x)) bad();
  return x;
}
function hash(o: Obj, k: string, empty = false) {
  const x = text(o, k, 64, empty);
  if (x !== "" || !empty) if (!/^[0-9a-f]{64}$/.test(x)) bad();
  return x;
}
function reference(value: unknown) {
  const o = object(value);
  keys(o, ["id", "version", "hash"]);
  return {
    id: id(o, "id"),
    version: integer(o, "version", 1, 2147483647),
    hash: hash(o, "hash"),
  };
}
function file(value: unknown) {
  const o = object(value);
  keys(o, ["id", "size_bytes", "sha256", "policy", "accepted_event_id"]);
  return {
    id: id(o, "id"),
    size_bytes: integer(o, "size_bytes", 0, 1 << 30),
    sha256: hash(o, "sha256"),
    policy: text(o, "policy", 128),
    accepted_event_id: id(o, "accepted_event_id"),
  };
}
function pathCommand(value: unknown) {
  const o = object(value);
  keys(o, [
    "operation",
    "path",
    "target",
    "file_id",
    "expected_revision",
    "replace",
    "target_revision",
    "mode",
    "modified_at",
  ]);
  const r: Obj = { operation: text(o, "operation", 32), path: text(o, "path") };
  if (o.target !== undefined) r.target = text(o, "target");
  if (o.file_id !== undefined) r.file_id = id(o, "file_id");
  if (o.expected_revision !== undefined)
    r.expected_revision = integer(o, "expected_revision", 1);
  if (o.replace !== undefined) {
    if (o.replace !== true) bad();
    r.replace = true;
  }
  if (o.target_revision !== undefined)
    r.target_revision = integer(o, "target_revision", 1);
  if (o.mode !== undefined) r.mode = integer(o, "mode", 0, 511);
  if (o.modified_at !== undefined) {
    const x = text(o, "modified_at", 40);
    if (!Number.isFinite(Date.parse(x))) bad();
    r.modified_at = x;
  }
  return r;
}
function binding(value: unknown) {
  const o = object(value);
  keys(o, [
    "file",
    "storage_id",
    "namespace_root",
    "authority_revision",
    "parent_id",
    "parent_revision",
    "target",
  ]);
  return {
    file: file(o.file),
    storage_id: id(o, "storage_id"),
    namespace_root: text(o, "namespace_root"),
    authority_revision: integer(o, "authority_revision", 1),
    parent_id: id(o, "parent_id", true),
    parent_revision: integer(o, "parent_revision"),
    target: o.target === null ? null : pathCommand(o.target),
  };
}
function signature(value: unknown) {
  const o = object(value);
  keys(o, [
    "file_id",
    "object_id",
    "storage_id",
    "size_bytes",
    "sha256",
    "data_sha256",
    "policy_hash",
    "key",
    "attached_event_id",
  ]);
  return {
    file_id: id(o, "file_id"),
    object_id: id(o, "object_id"),
    storage_id: id(o, "storage_id"),
    size_bytes: integer(o, "size_bytes", 1, 32768),
    sha256: hash(o, "sha256"),
    data_sha256: hash(o, "data_sha256"),
    policy_hash: hash(o, "policy_hash"),
    key: reference(o.key),
    ...(o.attached_event_id === undefined
      ? {}
      : { attached_event_id: id(o, "attached_event_id") }),
  };
}
export function parseRecheckPlan(
  value: unknown,
  expectedRoot = "/",
): RecheckPlan {
  const o = object(value);
  keys(o, [
    "source",
    "policy",
    "namespace_root",
    "authority_revision",
    "storage_id",
    "target",
    "signature_mode",
    "reason",
  ]);
  const s = object(o.source);
  keys(s, ["file", "check", "signature"]);
  const source: RecheckPlan["source"] = { file: file(s.file) };
  if (s.check !== undefined) {
    const c = object(s.check);
    keys(c, [
      "policy_id",
      "policy_version",
      "policy_hash",
      "state",
      "revision",
      "attempts",
      "code",
      "worker_id",
      "lease_until",
      "report_hash",
      "binding",
    ]);
    const state = text(c, "state", 16);
    if (
      !["held", "running", "passed", "rejected", "failed", "released"].includes(
        state,
      )
    )
      bad();
    if (
      c.lease_until !== undefined &&
      (!Number.isFinite(Date.parse(text(c, "lease_until", 40))) ||
        !String(c.lease_until).endsWith("Z"))
    )
      bad();
    source.check = {
      policy_id: id(c, "policy_id"),
      policy_version: integer(c, "policy_version", 1),
      policy_hash: hash(c, "policy_hash"),
      state,
      revision: integer(c, "revision", 1),
      attempts: integer(c, "attempts", 0, 3),
      code: text(c, "code", 64),
      ...(c.worker_id === undefined ? {} : { worker_id: id(c, "worker_id") }),
      ...(c.lease_until === undefined
        ? {}
        : { lease_until: text(c, "lease_until", 40) }),
      report_hash: hash(c, "report_hash", true),
      binding: binding(c.binding),
    };
  }
  if (s.signature !== undefined) source.signature = signature(s.signature);
  const mode = text(o, "signature_mode", 20) as RecheckMode;
  if (!["not_required", "reuse_exact", "require_new"].includes(mode)) bad();
  const plan: RecheckPlan = {
    source,
    policy: reference(o.policy),
    namespace_root: text(o, "namespace_root"),
    authority_revision: integer(o, "authority_revision", 1),
    storage_id: id(o, "storage_id"),
  } as RecheckPlan;
  if (o.target !== undefined) {
    const t = object(o.target);
    keys(t, [
      "command",
      "parent_id",
      "parent_revision",
      "entry_id",
      "entry_revision",
    ]);
    plan.target = {
      command: pathCommand(t.command),
      parent_id: id(t, "parent_id", true),
      parent_revision: integer(t, "parent_revision", 1),
      entry_id: id(t, "entry_id", true),
      entry_revision: integer(t, "entry_revision"),
    };
  }
  plan.signature_mode = mode;
  plan.reason = text(o, "reason", 1024);
  if (
    plan.reason.normalize("NFC") !== plan.reason ||
    plan.reason.trim() !== plan.reason ||
    new TextEncoder().encode(plan.reason).length < 3 ||
    [...plan.reason].length > 240
  )
    bad();
  if (plan.namespace_root !== expectedRoot) bad();
  if (source.check) {
    const b = object(object(source.check).binding);
    if (
      JSON.stringify(b.file) !== JSON.stringify(source.file) ||
      b.storage_id !== plan.storage_id ||
      b.namespace_root !== plan.namespace_root
    )
      bad();
  }
  if (source.signature) {
    const sig = object(source.signature);
    if (
      sig.file_id !== source.file.id ||
      sig.data_sha256 !== source.file.sha256 ||
      sig.storage_id !== plan.storage_id
    )
      bad();
  }
  if (mode === "reuse_exact" && !source.signature) bad();
  return plan;
}
export function goJSON(value: unknown): string {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
export function recheckFingerprint(definition: RecheckDefinition) {
  return digestBytes(new TextEncoder().encode(goJSON(definition)));
}
export function planFingerprint(plan: RecheckPlan) {
  return digestBytes(new TextEncoder().encode(goJSON(plan)));
}
export function parseRecheck(value: unknown): Recheck {
  const o = object(value);
  keys(o, [
    "id",
    "source_file_id",
    "definition",
    "definition_hash",
    "state",
    "revision",
    "new_file_id",
    "result",
  ]);
  const raw = object(o.definition);
  keys(raw, ["schema_version", "plan", "staging_slots"]);
  if (
    raw.schema_version !== 1 ||
    !Array.isArray(raw.staging_slots) ||
    raw.staging_slots.length !== 3
  )
    bad();
  const plan = parseRecheckPlan(raw.plan),
    slots = (raw.staging_slots as unknown[]).map((v: unknown) => {
      const s = object(v);
      keys(s, ["file_id", "signature_object_id"]);
      return {
        file_id: id(s, "file_id"),
        ...(s.signature_object_id === undefined
          ? {}
          : { signature_object_id: id(s, "signature_object_id") }),
      };
    });
  if (
    new Set(slots.map((s) => s.file_id)).size !== 3 ||
    new Set(
      slots.flatMap((s) => [
        s.file_id,
        ...(s.signature_object_id ? [s.signature_object_id] : []),
      ]),
    ).size !== (plan.signature_mode === "reuse_exact" ? 6 : 3) ||
    slots.some(
      (s) =>
        s.file_id === plan.source.file.id ||
        s.signature_object_id === plan.source.file.id ||
        (plan.source.signature !== undefined &&
          [s.file_id, s.signature_object_id].includes(
            String(object(plan.source.signature).object_id),
          )) ||
        (s.signature_object_id !== undefined) !==
          (plan.signature_mode === "reuse_exact"),
    )
  )
    bad();
  const definition: RecheckDefinition = {
      schema_version: 1,
      plan,
      staging_slots: slots,
    },
    definition_hash = hash(o, "definition_hash");
  if (recheckFingerprint(definition) !== definition_hash) bad();
  const state = text(o, "state", 16) as Recheck["state"];
  if (!["proposed", "approved", "cancelled", "copied"].includes(state)) bad();
  const r: Recheck = {
    id: id(o, "id"),
    source_file_id: id(o, "source_file_id"),
    definition,
    definition_hash,
    state,
    revision: integer(o, "revision", 1),
    new_file_id: id(o, "new_file_id", true),
    result: object(o.result),
  };
  if (
    r.source_file_id !== plan.source.file.id ||
    (state === "copied") !== !!r.new_file_id ||
    (state === "proposed" && r.revision !== 1) ||
    (state === "approved" && r.revision !== 2) ||
    (state === "copied" && r.revision !== 3) ||
    (state === "cancelled" && ![2, 3].includes(r.revision))
  )
    bad();
  if (state === "copied") {
    const result = r.result;
    keys(result, ["kind", "file", "acceptance", "signature"]);
    if (
      result.kind !== "file_recheck_copy" ||
      result.acceptance !== "durable-held-pending-checks-and-release"
    )
      bad();
    const f = file(result.file);
    if (
      f.id !== r.new_file_id ||
      f.sha256 !== plan.source.file.sha256 ||
      f.size_bytes !== plan.source.file.size_bytes ||
      controlledArtifactPolicyHash(f.policy) !== plan.policy.hash ||
      !slots.some((s) => s.file_id === f.id)
    )
      bad();
    if (plan.signature_mode === "reuse_exact") {
      const sig = signature(result.signature),
        source = signature(plan.source.signature),
        slot = slots.find((s) => s.file_id === f.id)!;
      if (
        sig.object_id !== slot.signature_object_id ||
        sig.file_id !== f.id ||
        sig.data_sha256 !== f.sha256 ||
        sig.policy_hash !== plan.policy.hash ||
        sig.storage_id !== plan.storage_id ||
        sig.sha256 !== source.sha256 ||
        sig.size_bytes !== source.size_bytes ||
        JSON.stringify(sig.key) !== JSON.stringify(source.key) ||
        !sig.attached_event_id
      )
        bad();
    } else if (result.signature !== undefined) bad();
  } else if (Object.keys(r.result).length) bad();
  return r;
}
function policyDefinition(value: unknown): Obj {
  const o = object(value);
  keys(o, [
    "schema_version",
    "kind",
    "columns",
    "max_bytes",
    "max_rows",
    "max_record_bytes",
    "timeout_seconds",
    "signature",
    "scanner",
  ]);
  if (
    o.schema_version !== 1 ||
    o.kind !== "csv" ||
    !Array.isArray(o.columns) ||
    !o.columns.length ||
    o.columns.length > 128
  )
    bad();
  const columns = (o.columns as unknown[]).map((v: unknown) => {
    const c = object(v);
    keys(c, ["name", "type", "required", "max_bytes", "precision", "scale"]);
    if (typeof c.required !== "boolean") bad();
    const r: Obj = {
      name: text(c, "name", 128),
      type: text(c, "type", 16),
      required: c.required,
      max_bytes: integer(c, "max_bytes", 1, 64 << 10),
    };
    if (c.precision !== undefined) r.precision = integer(c, "precision", 1, 38);
    if (c.scale !== undefined) r.scale = integer(c, "scale", 1, 38);
    return r;
  });
  const result: Obj = {
    schema_version: 1,
    kind: "csv",
    columns,
    max_bytes: integer(o, "max_bytes", 1, 1 << 30),
    max_rows: integer(o, "max_rows", 1),
    max_record_bytes: integer(o, "max_record_bytes", 1, 1 << 20),
    timeout_seconds: integer(o, "timeout_seconds", 1, 60),
  };
  if (o.signature !== undefined) {
    const sig = object(o.signature);
    keys(sig, ["key", "max_age_seconds"]);
    result.signature = {
      key: reference(sig.key),
      ...(sig.max_age_seconds === undefined
        ? {}
        : { max_age_seconds: integer(sig, "max_age_seconds", 1, 4294967295) }),
    };
  }
  if (o.scanner !== undefined) result.scanner = reference(o.scanner);
  return result;
}
function policy(
  value: unknown,
  expected: { id: string; version: number; hash: string },
): Obj {
  const o = object(value),
    r = reference(o.reference);
  if (
    JSON.stringify(r) !== JSON.stringify(expected) ||
    typeof o.state !== "string"
  )
    bad();
  keys(o, ["reference", "state", "definition"]);
  if (!["active", "retired", "revoked"].includes(String(o.state))) bad();
  const definition = policyDefinition(o.definition);
  if (digestBytes(new TextEncoder().encode(goJSON(definition))) !== r.hash)
    bad();
  return { ...o, definition };
}
export function parseRecheckPreview(value: unknown): RecheckPreview {
  const o = object(value),
    plan = parseRecheckPlan(o.plan),
    current = policy(o.current_policy, plan.policy);
  const definition = object(current.definition),
    requiresSignature = definition.signature !== undefined;
  if (
    (plan.source.check !== undefined) !== (o.previous_policy !== undefined) ||
    current.state !== "active"
  )
    bad();
  if (
    definition.kind !== "csv" ||
    definition.schema_version !== 1 ||
    requiresSignature !== (plan.signature_mode !== "not_required")
  )
    bad();
  if (
    plan.signature_mode === "reuse_exact" &&
    JSON.stringify(reference(object(definition.signature).key)) !==
      JSON.stringify(reference(object(plan.source.signature).key))
  )
    bad();
  return {
    plan,
    ...(o.previous_policy === undefined
      ? {}
      : {
          previous_policy: policy(o.previous_policy, {
            id: String(object(plan.source.check).policy_id),
            version: Number(object(plan.source.check).policy_version),
            hash: String(object(plan.source.check).policy_hash),
          }),
        }),
    current_policy: current,
    effects: text(o, "effects", 1024),
  };
}
export function parseRecheckView(value: unknown): RecheckView {
  const o = object(value);
  if (o.kind !== "file_recheck" || typeof o.current !== "boolean") bad();
  const recheck = parseRecheck(o.recheck),
    code = text(o, "code", 64),
    plan = recheck.definition.plan;
  if (
    (plan.source.check !== undefined) !== (o.previous_policy !== undefined) ||
    o.selected_policy === undefined
  )
    bad();
  if (
    o.current &&
    (!["proposed", "approved"].includes(recheck.state) || code !== "current")
  )
    bad();
  if (
    !o.current &&
    code !==
      (["copied", "cancelled"].includes(recheck.state)
        ? recheck.state
        : "historical_or_changed")
  )
    bad();
  return {
    kind: "file_recheck",
    recheck,
    current: o.current as boolean,
    code,
    ...(o.previous_policy === undefined
      ? {}
      : {
          previous_policy: policy(o.previous_policy, {
            id: String(object(plan.source.check).policy_id),
            version: Number(object(plan.source.check).policy_version),
            hash: String(object(plan.source.check).policy_hash),
          }),
        }),
    ...(o.selected_policy === undefined
      ? {}
      : {
          selected_policy: policy(
            o.selected_policy,
            recheck.definition.plan.policy,
          ),
        }),
  };
}
export function parseRecheckReceipt(value: unknown): Recheck {
  const o = object(value);
  if (typeof o.replayed !== "boolean") bad();
  const r = object(o.resource);
  if (r.kind !== "file_recheck") bad();
  return parseRecheck(r.recheck);
}
