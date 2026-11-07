import { ApiError, object, uuid, type Session } from "./types";
import { digestBytes } from "./crypto";
import { programBytes } from "./programs-types";
import {
  intakeDefinition,
  intakeHash,
  type IntakeDefinition,
} from "./intake-policy-types";
import {
  asExchangeArtifact,
  type ExchangeArtifact,
} from "./artifact-exchanges-types";
import { parseRecheckPlan } from "./rechecks-types";

type Obj = Record<string, unknown>;
export interface Reference {
  id: string;
  version: number;
  hash: string;
}
export interface Mapping {
  source: string;
  target: string;
  conversion: "identity" | "text" | "normalize_lf";
  missing: string;
  null: string;
  empty: string;
}
export interface Projection {
  schema_version: 1;
  kind: "record_projection";
  engine: "freightctl-record-projection-v1";
  source_policy_hash: string;
  output_kind: "csv" | "json_records";
  columns: Mapping[];
  max_bytes: number;
  max_record_bytes: number;
  max_rows: number;
  timeout_seconds: number;
}
export interface ProcessingDefinition {
  schema_version: 3;
  name: string;
  steps: [];
  processing: {
    id: string;
    kind: "records.project";
    definition: Projection;
    output_policy: Reference;
    target_path: string;
    reason: string;
  };
}
export interface Contracts {
  profile:
    | "record-processing-contracts-v1"
    | "record-processing-contracts-v2"
    | "record-processing-contracts-v3";
  output_binding?: ReturnType<typeof processingOutputBinding>;
  source_origin?: ReturnType<typeof processingSourceOrigin>;
  source: ExchangeArtifact;
  source_policy: {
    reference: Reference;
    state: string;
    definition: IntakeDefinition;
  };
  output_policy: {
    reference: Reference;
    state: string;
    definition: IntakeDefinition;
  };
  authority_revision: number;
  namespace_root_digest: string;
  source_proof_valid_until?: string;
  effects: string;
}
export interface Configuration {
  id: string;
  version: number;
  definition: ProcessingDefinition;
  definition_hash: string;
  state: "draft" | "approved" | "revoked";
  revision: number;
  approval_authority: number;
}
export interface ProcessingRun {
  id: string;
  workflow_id: string;
  workflow_version: number;
  workflow_hash: string;
  file_id: string;
  source: {
    id: string;
    size_bytes: number;
    sha256: string;
    policy: string;
    accepted_event_id: string;
  };
  storage_id: string;
  namespace_root: string;
  authority_revision: number;
  state: string;
  reason: string;
  revision: number;
}
export interface ProcessingObservation {
  projection_id: string;
  definition_hash: string;
  state: string;
  revision: number;
  attempts: number;
  output_file_id?: string;
  current: boolean;
  released: boolean;
}
export interface RunView {
  run: ProcessingRun;
  steps: [];
  observed_state: string;
  observed_reason: string;
  processing: ProcessingObservation;
}
export interface WorkView {
  status: RunView;
  replayed: boolean;
  history?: { state: string; attempts: number; output_file_id?: string };
}
export const processingHash = (value: unknown) =>
  digestBytes(programBytes(value));
const bad = (): never => {
  throw new ApiError("invalid_processing_contract", 502);
};
const exact = (value: unknown, required: string[], optional: string[] = []) => {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
};
const text = (value: unknown, max = 1024, empty = false): string => {
  if (
    typeof value !== "string" ||
    (!empty && !value) ||
    new TextEncoder().encode(value).length > max ||
    /[\p{Cc}\p{Cs}]/u.test(value)
  )
    bad();
  return value as string;
};
const integer = (
  value: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): number => {
  if (
    !Number.isSafeInteger(value) ||
    Number(value) < min ||
    Number(value) > max
  )
    bad();
  return value as number;
};
const identifier = (value: unknown) => {
  const s = text(value, 36);
  if (!uuid(s)) bad();
  return s;
};
const hash = (value: unknown) => {
  const s = text(value, 64);
  if (!/^[0-9a-f]{64}$/.test(s)) bad();
  return s;
};
const bool = (value: unknown): boolean => {
  if (typeof value !== "boolean") bad();
  return value as boolean;
};
const option = (value: unknown, values: string[], fallback = "") => {
  const s =
    value === undefined || value === "" ? fallback : text(value, 64, true);
  if (!values.includes(s)) bad();
  return s;
};
const trim = (s: string) =>
  s.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
export function processingPath(value: unknown, empty = true): string {
  const s = text(value, 1024, empty).normalize("NFC");
  if (empty && s === "") return s;
  if (!s.startsWith("/") || new TextEncoder().encode(s).length > 1024) bad();
  if (s === "/") return s;
  for (const part of s.slice(1).split("/")) {
    if (
      !part ||
      part === "." ||
      part === ".." ||
      part === ".freightctl" ||
      /[\\:]/.test(part) ||
      /[. ]$/.test(part) ||
      new TextEncoder().encode(part).length > 255 ||
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)
    )
      bad();
  }
  return s;
}
export function reference(value: unknown): Reference {
  const o = exact(value, ["id", "version", "hash"]);
  return {
    id: identifier(o.id),
    version: integer(o.version, 1, 2147483647),
    hash: hash(o.hash),
  };
}

// This is a bound review profile, not an approval or permission grant.
export function processingOutputBinding(
  value: unknown,
  selected: Reference,
  session: Session,
) {
  const b = exact(value, [
      "profile",
      "policy_id",
      "policy_version",
      "policy_hash",
      "publisher_id",
      "producer",
    ]),
    actor = exact(b.producer, [
      "tenant_id",
      "partner_id",
      "actor_id",
      "authority_revision",
      "root_policy_digest",
    ]),
    producer = {
      tenant_id: identifier(actor.tenant_id),
      partner_id: identifier(actor.partner_id),
      actor_id: identifier(actor.actor_id),
      authority_revision: integer(actor.authority_revision, 1),
      root_policy_digest: hash(actor.root_policy_digest),
    },
    ref = reference(selected),
    identity = session.identity;
  if (
    b.profile !== "producer-processing-output-policy-v1" ||
    b.policy_id !== ref.id ||
    b.policy_version !== ref.version ||
    b.policy_hash !== ref.hash ||
    producer.tenant_id !== identity.tenant_id ||
    producer.partner_id !== identity.partner_id ||
    producer.actor_id !== identity.actor_id ||
    producer.authority_revision !== identity.authority_revision ||
    producer.root_policy_digest !== identity.root_policy_digest
  )
    bad();
  return {
    profile: "producer-processing-output-policy-v1",
    policy_id: ref.id,
    policy_version: ref.version,
    policy_hash: ref.hash,
    publisher_id: identifier(b.publisher_id),
    producer,
  };
}

export function processingSourceOrigin(
  value: unknown,
  source: ExchangeArtifact,
  policy: Reference,
  session: Session,
  acceptedEvent?: unknown,
) {
  const o = exact(value, [
      "profile",
      "file",
      "projection_id",
      "projection_hash",
      "producer_binding",
    ]),
    f = exact(o.file, [
      "id",
      "size_bytes",
      "sha256",
      "policy",
      "accepted_event_id",
    ]),
    file = {
      id: identifier(f.id),
      size_bytes: integer(f.size_bytes),
      sha256: hash(f.sha256),
      policy: text(f.policy, 128),
      accepted_event_id: identifier(f.accepted_event_id),
    };
  if (
    o.profile !== "owned-produced-source-v1" ||
    file.id !== source.file_revision_id ||
    file.size_bytes !== source.size_bytes ||
    file.sha256 !== source.sha256 ||
    file.policy !== source.acceptance_policy ||
    !file.policy.endsWith(":" + policy.hash) ||
    (acceptedEvent !== undefined && file.accepted_event_id !== acceptedEvent)
  )
    bad();
  return {
    profile: "owned-produced-source-v1",
    file,
    projection_id: identifier(o.projection_id),
    projection_hash: hash(o.projection_hash),
    producer_binding: processingOutputBinding(
      o.producer_binding,
      policy,
      session,
    ),
  };
}

export function processingPlanProfile(
  value: unknown,
  context: ReturnType<typeof parseRecheckPlan>,
  session: Session,
): {
  schema_version: number;
  profile: string;
  output_binding?: ReturnType<typeof processingOutputBinding>;
  source_origin?: ReturnType<typeof processingSourceOrigin>;
} {
  const plan = object(value);
  if (
    plan.schema_version === 2 &&
    plan.profile === "scoped-record-projection-v1" &&
    plan.output_binding === undefined &&
    plan.source_origin === undefined
  )
    return { schema_version: 2, profile: "scoped-record-projection-v1" };
  const composed =
    plan.schema_version === 4 &&
    plan.profile === "composed-producer-record-projection-v1";
  if (
    (!composed &&
      (plan.schema_version !== 3 ||
        plan.profile !== "producer-record-projection-v1")) ||
    composed !== (plan.source_origin !== undefined)
  )
    bad();
  const binding = processingOutputBinding(
    plan.output_binding,
    reference(context.policy),
    session,
  );
  if (
    composed &&
    object(plan.projection).source_policy_hash !==
      reference(plan.source_policy).hash
  )
    bad();
  if (
    binding.producer.authority_revision !== context.authority_revision ||
    binding.producer.root_policy_digest !==
      digestBytes(new TextEncoder().encode(context.namespace_root))
  )
    bad();
  return {
    schema_version: composed ? 4 : 3,
    profile: composed
      ? "composed-producer-record-projection-v1"
      : "producer-record-projection-v1",
    output_binding: binding,
    ...(composed
      ? {
          source_origin: processingSourceOrigin(
            plan.source_origin,
            {
              file_revision_id: context.source.file.id,
              size_bytes: context.source.file.size_bytes,
              sha256: context.source.file.sha256,
              acceptance_policy: context.source.file.policy,
            },
            reference(plan.source_policy),
            session,
            context.source.file.accepted_event_id,
          ),
        }
      : {}),
  };
}
export function projection(value: unknown): Projection {
  const o = exact(value, [
    "schema_version",
    "kind",
    "engine",
    "source_policy_hash",
    "output_kind",
    "columns",
    "max_bytes",
    "max_record_bytes",
    "max_rows",
    "timeout_seconds",
  ]);
  if (
    o.schema_version !== 1 ||
    o.kind !== "record_projection" ||
    o.engine !== "freightctl-record-projection-v1" ||
    !Array.isArray(o.columns) ||
    o.columns.length < 1 ||
    o.columns.length > 128
  )
    bad();
  const seen = new Set<string>();
  const columns = (o.columns as unknown[]).map((v) => {
    const m = exact(
        v,
        ["source", "target"],
        ["conversion", "missing", "null", "empty"],
      ),
      source = text(m.source, 128),
      target = text(m.target, 128);
    if (trim(source) !== source || trim(target) !== target || seen.has(target))
      bad();
    seen.add(target);
    return {
      source,
      target,
      conversion: option(
        m.conversion,
        ["identity", "text", "normalize_lf"],
        "identity",
      ) as Mapping["conversion"],
      missing: option(
        m.missing,
        ["preserve", "empty", "null", "error"],
        "preserve",
      ),
      null: option(
        m.null,
        ["preserve", "empty", "missing", "error"],
        "preserve",
      ),
      empty: option(
        m.empty,
        ["preserve", "missing", "null", "error"],
        "preserve",
      ),
    };
  });
  return {
    schema_version: 1,
    kind: "record_projection",
    engine: "freightctl-record-projection-v1",
    source_policy_hash: hash(o.source_policy_hash),
    output_kind: option(o.output_kind, [
      "csv",
      "json_records",
    ]) as Projection["output_kind"],
    columns,
    max_bytes: integer(o.max_bytes, 1, 1073741824),
    max_record_bytes: integer(o.max_record_bytes, 64, 1048576),
    max_rows: integer(o.max_rows, 1, 1000000),
    timeout_seconds: integer(o.timeout_seconds, 1, 60),
  };
}
export function processingDefinition(value: unknown): ProcessingDefinition {
  const o = exact(value, ["schema_version", "name", "steps", "processing"]);
  if (o.schema_version !== 3 || !Array.isArray(o.steps) || o.steps.length !== 0)
    bad();
  const p = exact(o.processing, [
      "id",
      "kind",
      "definition",
      "output_policy",
      "target_path",
      "reason",
    ]),
    id = text(p.id, 64),
    reason = trim(text(p.reason, 1024).normalize("NFC")),
    target = processingPath(p.target_path);
  if (
    !/^[a-z][a-z0-9_]{0,63}$/.test(id) ||
    p.kind !== "records.project" ||
    new TextEncoder().encode(reason).length < 3 ||
    [...reason].length > 240 ||
    target === "/"
  )
    bad();
  return {
    schema_version: 3,
    name: text(o.name, 256).normalize("NFC"),
    steps: [],
    processing: {
      id,
      kind: "records.project",
      definition: projection(p.definition),
      output_policy: reference(p.output_policy),
      target_path: target,
      reason,
    },
  };
}
export function processingContracts(
  value: unknown,
  session?: Session,
): Contracts {
  const o = exact(
    value,
    [
      "profile",
      "source",
      "source_policy",
      "output_policy",
      "authority_revision",
      "namespace_root_digest",
      "effects",
    ],
    ["source_proof_valid_until", "output_binding", "source_origin"],
  );
  const composed = o.profile === "record-processing-contracts-v3";
  const selected = composed || o.profile === "record-processing-contracts-v2";
  if (
    (!selected && o.profile !== "record-processing-contracts-v1") ||
    selected !== (o.output_binding !== undefined) ||
    composed !== (o.source_origin !== undefined) ||
    (selected && !session)
  )
    bad();
  const policy = (v: unknown, source: boolean) => {
    const p = exact(v, ["reference", "state", "definition"]),
      ref = reference(p.reference),
      definition = intakeDefinition(p.definition),
      state = option(
        p.state,
        source
          ? composed
            ? ["output_active"]
            : ["active", "retired"]
          : selected
            ? ["output_active"]
            : ["active"],
      );
    if (intakeHash(definition) !== ref.hash) bad();
    return { reference: ref, state, definition };
  };
  const source = asExchangeArtifact(o.source),
    source_policy = policy(o.source_policy, true),
    output_policy = policy(o.output_policy, false);
  const prefix = {
    csv: "intake-csv-v1:",
    json_records: "intake-json-records-v1:",
    fixed_width: "intake-fixed-width-v1:",
    xml_records: "intake-xml-records-v1:",
    xlsx_records: "intake-xlsx-records-v1:",
  }[source_policy.definition.kind];
  if (source.acceptance_policy !== prefix + source_policy.reference.hash) bad();
  const result: Contracts = {
    profile: composed
      ? "record-processing-contracts-v3"
      : selected
        ? "record-processing-contracts-v2"
        : "record-processing-contracts-v1",
    source,
    source_policy,
    output_policy,
    authority_revision: integer(o.authority_revision, 1),
    namespace_root_digest: hash(o.namespace_root_digest),
    effects: text(o.effects, 1024),
  };
  if (selected) {
    result.output_binding = processingOutputBinding(
      o.output_binding,
      output_policy.reference,
      session!,
    );
    if (
      result.output_binding.producer.authority_revision !==
        result.authority_revision ||
      result.output_binding.producer.root_policy_digest !==
        result.namespace_root_digest
    )
      bad();
  }
  if (composed)
    result.source_origin = processingSourceOrigin(
      o.source_origin,
      source,
      source_policy.reference,
      session!,
    );
  if (o.source_proof_valid_until !== undefined) {
    const t = text(o.source_proof_valid_until, 40);
    if (!Number.isFinite(Date.parse(t))) bad();
    result.source_proof_valid_until = t;
  }
  return result;
}
export function processingConfiguration(value: unknown): Configuration {
  const o = exact(value, [
      "id",
      "version",
      "definition",
      "definition_hash",
      "state",
      "revision",
      "approval_authority",
    ]),
    definition = processingDefinition(o.definition),
    fingerprint = hash(o.definition_hash),
    state = option(o.state, [
      "draft",
      "approved",
      "revoked",
    ]) as Configuration["state"],
    authority = integer(o.approval_authority);
  if (
    processingHash(definition) !== fingerprint ||
    (state === "draft") !== (authority === 0)
  )
    bad();
  return {
    id: identifier(o.id),
    version: integer(o.version, 1),
    definition,
    definition_hash: fingerprint,
    state,
    revision: integer(o.revision, 1),
    approval_authority: authority,
  };
}
export const processingStamp = (session: Session | null) =>
  session
    ? JSON.stringify([
        session.identity.tenant_id,
        session.identity.partner_id,
        session.identity.actor_id,
        session.identity.authority_revision,
        session.identity.root_policy_digest,
        session.session.id,
      ])
    : "";
export const processingAllowed = (session: Session | null, action: string) => {
  const has = (g: string) => session?.identity.permissions.includes(g) ?? false;
  if (action === "manage") return has("workflow_manage");
  if (action === "approve") return has("workflow_approve");
  if (action === "configuration")
    return ["workflow_manage", "workflow_approve", "workflow_execute"].some(
      has,
    );
  return (
    ["read", "write", "check_run"].every(has) &&
    (action === "execute"
      ? has("workflow_execute")
      : ["workflow_manage", "workflow_approve", "workflow_execute"].some(has))
  );
};
export function processingRun(value: unknown, session: Session): ProcessingRun {
  const o = exact(value, [
      "id",
      "workflow_id",
      "workflow_version",
      "workflow_hash",
      "file_id",
      "source",
      "storage_id",
      "namespace_root",
      "authority_revision",
      "state",
      "reason",
      "revision",
    ]),
    s = exact(o.source, [
      "id",
      "size_bytes",
      "sha256",
      "policy",
      "accepted_event_id",
    ]);
  const source = {
      id: identifier(s.id),
      size_bytes: integer(s.size_bytes, 0, 1073741824),
      sha256: hash(s.sha256),
      policy: text(s.policy, 128),
      accepted_event_id: identifier(s.accepted_event_id),
    },
    root = processingPath(o.namespace_root, false),
    authority = integer(o.authority_revision, 1);
  if (
    source.id !== o.file_id ||
    digestBytes(new TextEncoder().encode(root)) !==
      session.identity.root_policy_digest ||
    authority !== session.identity.authority_revision
  )
    bad();
  asExchangeArtifact({
    file_revision_id: source.id,
    size_bytes: source.size_bytes,
    sha256: source.sha256,
    acceptance_policy: source.policy,
  });
  return {
    id: identifier(o.id),
    workflow_id: identifier(o.workflow_id),
    workflow_version: integer(o.workflow_version, 1),
    workflow_hash: hash(o.workflow_hash),
    file_id: identifier(o.file_id),
    source,
    storage_id: identifier(o.storage_id),
    namespace_root: root,
    authority_revision: authority,
    state: option(o.state, [
      "queued",
      "running",
      "attention",
      "succeeded",
      "cancelled",
    ]),
    reason: text(o.reason, 64),
    revision: integer(o.revision, 1),
  };
}
export function processingStatus(value: unknown, session: Session): RunView {
  const o = exact(value, [
    "run",
    "steps",
    "observed_state",
    "observed_reason",
    "processing",
  ]);
  if (!Array.isArray(o.steps) || o.steps.length) bad();
  const p = exact(
      o.processing,
      [
        "projection_id",
        "definition_hash",
        "state",
        "revision",
        "attempts",
        "current",
        "released",
      ],
      ["output_file_id"],
    ),
    state = option(p.state, [
      "approved",
      "running",
      "failed",
      "cancelled",
      "completed",
    ]),
    released = bool(p.released);
  const observation: ProcessingObservation = {
    projection_id: identifier(p.projection_id),
    definition_hash: hash(p.definition_hash),
    state,
    revision: integer(p.revision, 1),
    attempts: integer(p.attempts, 0, 3),
    ...(p.output_file_id === undefined
      ? {}
      : { output_file_id: identifier(p.output_file_id) }),
    current: bool(p.current),
    released,
  };
  if (
    (state === "completed") !== (observation.output_file_id !== undefined) ||
    (released && state !== "completed")
  )
    bad();
  const run = processingRun(o.run, session),
    observed_state = option(o.observed_state, [
      "queued",
      "running",
      "attention",
      "succeeded",
      "cancelled",
    ]),
    observed_reason = option(o.observed_reason, [
      "awaiting_worker",
      "processing_in_progress",
      "processing_failed",
      "processing_cancelled",
      "output_held",
      "transformed_output_released",
      "processing_binding_changed",
      "operator_cancelled",
    ]);
  if (
    (observed_state === "succeeded") !==
      (state === "completed" && released && run.state !== "cancelled") ||
    (observed_reason === "transformed_output_released") !==
      (observed_state === "succeeded")
  )
    bad();
  return {
    run,
    steps: [],
    observed_state,
    observed_reason,
    processing: observation,
  };
}
export function processingWork(value: unknown, session: Session): WorkView {
  const o = exact(
      value,
      ["dispatch", "replayed", "status"],
      ["processing_attempt"],
    ),
    status = processingStatus(o.status, session),
    d = exact(
      o.dispatch,
      [
        "run_id",
        "delivery_id",
        "step_id",
        "projection_id",
        "projection_hash",
        "projection_revision",
      ],
      ["observe_only"],
    );
  if (
    d.run_id !== status.run.id ||
    d.delivery_id !== "" ||
    d.projection_id !== status.processing.projection_id ||
    d.projection_hash !== status.processing.definition_hash ||
    integer(d.projection_revision, 1) > status.processing.revision
  )
    bad();
  const result: WorkView = { status, replayed: bool(o.replayed) };
  if (o.processing_attempt !== undefined) {
    const p = exact(o.processing_attempt, [
        "id",
        "source_file_id",
        "definition",
        "definition_hash",
        "state",
        "revision",
        "attempts",
        "worker_id",
        "lease_until",
        "new_file_id",
        "result",
      ]),
      definition = exact(p.definition, [
        "schema_version",
        "plan",
        "staging_slots",
        "workflow",
      ]),
      plan = exact(
        definition.plan,
        [
          "schema_version",
          "profile",
          "context",
          "source_policy",
          "projection",
          "output_contract_hash",
        ],
        ["source_proof_valid_until", "output_binding", "source_origin"],
      ),
      context = parseRecheckPlan(plan.context, status.run.namespace_root),
      mode = processingPlanProfile(plan, context, session),
      binding = exact(definition.workflow, [
        "workflow_id",
        "workflow_version",
        "workflow_hash",
        "run_id",
        "step_id",
      ]);
    if (
      definition.schema_version !== mode.schema_version ||
      context.authority_revision !== session.identity.authority_revision ||
      context.source.file.id !== status.run.file_id ||
      processingHash(context.source.file) !==
        processingHash(status.run.source) ||
      binding.run_id !== status.run.id ||
      binding.workflow_id !== status.run.workflow_id ||
      binding.workflow_version !== status.run.workflow_version ||
      binding.workflow_hash !== status.run.workflow_hash ||
      !Array.isArray(definition.staging_slots) ||
      definition.staging_slots.length !== 3
    )
      bad();
    const slots = (definition.staging_slots as unknown[]).map(identifier);
    if (new Set(slots).size !== 3 || slots.includes(status.run.file_id)) bad();
    const canonical = {
      schema_version: mode.schema_version,
      plan: {
        schema_version: mode.schema_version,
        profile: mode.profile,
        context,
        source_policy: reference(plan.source_policy),
        projection: projection(plan.projection),
        output_contract_hash: hash(plan.output_contract_hash),
        ...(plan.source_proof_valid_until === undefined
          ? {}
          : {
              source_proof_valid_until: text(plan.source_proof_valid_until, 40),
            }),
        ...(mode.output_binding === undefined
          ? {}
          : { output_binding: mode.output_binding }),
        ...(mode.source_origin === undefined
          ? {}
          : { source_origin: mode.source_origin }),
      },
      staging_slots: slots,
      workflow: {
        workflow_id: identifier(binding.workflow_id),
        workflow_version: integer(binding.workflow_version, 1),
        workflow_hash: hash(binding.workflow_hash),
        run_id: identifier(binding.run_id),
        step_id: text(binding.step_id, 64),
      },
    };
    if (
      p.id !== status.processing.projection_id ||
      p.definition_hash !== status.processing.definition_hash ||
      processingHash(canonical) !== p.definition_hash ||
      p.source_file_id !== status.run.file_id ||
      d.step_id !== binding.step_id
    )
      bad();
    const state = option(p.state, ["failed", "completed"]),
      attempts = integer(p.attempts, 1, 3);
    if (
      (state === "completed") !== (p.new_file_id !== "") ||
      attempts > status.processing.attempts
    )
      bad();
    result.history = {
      state,
      attempts,
      ...(state === "completed"
        ? { output_file_id: identifier(p.new_file_id) }
        : {}),
    };
  }
  return result;
}
