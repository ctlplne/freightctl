import { ApiError, object, uuid, type Session } from "./types";
import { Api } from "./api";
import { digestBytes } from "./crypto";
import {
  intakeDefinition,
  intakeHash,
  type IntakeDefinition,
} from "./intake-policy-types";
import {
  processingHash,
  processingStamp,
  reference,
  type Reference,
} from "./processing-types";

export type OutputPolicyMutation =
  | {
      kind: "register";
      key: string;
      body: {
        policy_id?: string;
        expected_version: number;
        producer_id: string;
        definition: IntakeDefinition;
      };
    }
  | { kind: "revoke"; key: string; policy: Reference; revision: number };

function bad(): never {
  throw new ApiError("invalid_output_policy_command", 400);
}
function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
}
function identifier(value: unknown): string {
  if (typeof value !== "string" || !uuid(value)) bad();
  return value;
}
function positive(value: unknown, zero = false): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < (zero ? 0 : 1)
  )
    bad();
  return value;
}
export function outputPolicyAllowed(session: Session): boolean {
  return (
    session.identity.permissions.includes("admin") &&
    session.identity.permissions.includes("intake_manage") &&
    session.identity.root_policy_digest ===
      digestBytes(new TextEncoder().encode("/"))
  );
}
function participant(session: Session) {
  if (!outputPolicyAllowed(session))
    throw new ApiError("output_policy_admin_required", 403);
  return {
    tenant_id: identifier(session.identity.tenant_id),
    partner_id: identifier(session.identity.partner_id),
    actor_id: identifier(session.identity.actor_id),
    authority_revision: positive(session.identity.authority_revision),
    root_policy_digest: session.identity.root_policy_digest,
  };
}
export function outputPolicyMutation(value: unknown): OutputPolicyMutation {
  const raw = object(value);
  if (typeof raw.key !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(raw.key))
    bad();
  if (raw.kind === "register") {
    const o = exact(raw, ["kind", "key", "body"]),
      body = exact(
        o.body,
        ["expected_version", "producer_id", "definition"],
        ["policy_id"],
      ),
      version = positive(body.expected_version, true);
    if ((version === 0) !== (body.policy_id === undefined)) bad();
    return {
      kind: "register",
      key: raw.key,
      body: {
        ...(body.policy_id === undefined
          ? {}
          : { policy_id: identifier(body.policy_id) }),
        expected_version: version,
        producer_id: identifier(body.producer_id),
        definition: intakeDefinition(body.definition),
      },
    };
  }
  if (raw.kind === "revoke") {
    const o = exact(raw, ["kind", "key", "policy", "revision"]);
    return {
      kind: "revoke",
      key: raw.key,
      policy: reference(o.policy),
      revision: positive(o.revision),
    };
  }
  return bad();
}
export function outputPolicyRecovery(
  command: OutputPolicyMutation,
  session: Session,
  origin: string,
) {
  if (new URL(origin).origin !== origin) bad();
  const request = outputPolicyMutation(command);
  return {
    profile: "producer-output-policy-command-v1",
    server_origin: origin,
    participant: participant(session),
    request,
    request_sha256: processingHash(request),
  };
}
export function parseOutputPolicyRecovery(
  raw: string,
  session: Session,
  origin: string,
): OutputPolicyMutation {
  if (new TextEncoder().encode(raw).length > 64 * 1024) bad();
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return bad();
  }
  const o = exact(value, [
      "profile",
      "server_origin",
      "participant",
      "request",
      "request_sha256",
    ]),
    stamp = exact(o.participant, [
      "tenant_id",
      "partner_id",
      "actor_id",
      "authority_revision",
      "root_policy_digest",
    ]),
    expected = participant(session),
    request = outputPolicyMutation(o.request);
  if (
    o.profile !== "producer-output-policy-command-v1" ||
    o.server_origin !== origin ||
    Object.entries(expected).some(([key, value]) => stamp[key] !== value) ||
    o.request_sha256 !== processingHash(request)
  )
    bad();
  return request;
}

export interface OutputPolicyRecord {
  profile: "producer-processing-output-policy-v1";
  policy: {
    id: string;
    version: number;
    definition: IntakeDefinition;
    definition_hash: string;
    state: "output_active" | "output_retired" | "output_revoked";
    revision: number;
    approval_authority: number;
  };
  binding: {
    profile: string;
    policy_id: string;
    policy_version: number;
    policy_hash: string;
    publisher_id: string;
    producer: {
      tenant_id: string;
      partner_id: string;
      actor_id: string;
      authority_revision: number;
      root_policy_digest: string;
    };
  };
  observation: string;
  ingress_changed: false;
  usage: string;
  producer_binding_current_at_observation?: boolean;
}
export interface OutputPolicyAdminPage {
  policies: {
    reference: Reference;
    producer_id: string;
    producer_current: boolean;
    kind: string;
    column_count: number;
  }[];
  next?: string;
}
function fingerprint(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) bad();
  return value;
}
function outputRecord(
  value: unknown,
  session: Session,
  current: boolean,
): OutputPolicyRecord {
  participant(session);
  const fields = [
    "profile",
    "policy",
    "binding",
    "observation",
    "ingress_changed",
    "usage",
  ];
  if (current) fields.push("producer_binding_current_at_observation");
  const o = exact(value, fields),
    p = exact(o.policy, [
      "id",
      "version",
      "definition",
      "definition_hash",
      "state",
      "revision",
      "approval_authority",
    ]),
    ref = reference({ id: p.id, version: p.version, hash: p.definition_hash }),
    definition = intakeDefinition(p.definition),
    b = exact(o.binding, [
      "profile",
      "policy_id",
      "policy_version",
      "policy_hash",
      "publisher_id",
      "producer",
    ]),
    rawProducer = exact(b.producer, [
      "tenant_id",
      "partner_id",
      "actor_id",
      "authority_revision",
      "root_policy_digest",
    ]),
    producer = {
      tenant_id: identifier(rawProducer.tenant_id),
      partner_id: identifier(rawProducer.partner_id),
      actor_id: identifier(rawProducer.actor_id),
      authority_revision: positive(rawProducer.authority_revision),
      root_policy_digest: fingerprint(rawProducer.root_policy_digest),
    };
  if (
    o.profile !== "producer-processing-output-policy-v1" ||
    b.profile !== o.profile ||
    b.policy_id !== ref.id ||
    b.policy_version !== ref.version ||
    b.policy_hash !== ref.hash ||
    intakeHash(definition) !== ref.hash ||
    p.approval_authority !== 0 ||
    !["output_active", "output_retired", "output_revoked"].includes(
      p.state as string,
    ) ||
    p.revision !== (p.state === "output_active" ? 1 : 2) ||
    producer.tenant_id !== session.identity.tenant_id ||
    producer.partner_id !== session.identity.partner_id ||
    o.ingress_changed !== false ||
    ![
      "contract-registration-only",
      "producer-workflow-output-contract",
    ].includes(o.usage as string) ||
    o.observation !==
      (current
        ? "current-contract-metadata-only"
        : "original-command-receipt;current-state-not-checked") ||
    (current && typeof o.producer_binding_current_at_observation !== "boolean")
  )
    bad();
  return {
    profile: "producer-processing-output-policy-v1",
    policy: {
      id: ref.id,
      version: ref.version,
      definition,
      definition_hash: ref.hash,
      state: p.state as OutputPolicyRecord["policy"]["state"],
      revision: p.revision as number,
      approval_authority: 0,
    },
    binding: {
      profile: "producer-processing-output-policy-v1",
      policy_id: ref.id,
      policy_version: ref.version,
      policy_hash: ref.hash,
      publisher_id: identifier(b.publisher_id),
      producer,
    },
    observation: o.observation as string,
    ingress_changed: false,
    usage: o.usage as string,
    ...(current
      ? {
          producer_binding_current_at_observation:
            o.producer_binding_current_at_observation as boolean,
        }
      : {}),
  };
}

export class OutputPolicyApi {
  private stamp: string;
  private prefix: string;
  constructor(private api: Api) {
    this.stamp = processingStamp(api.session);
    this.prefix = api.prefix;
    this.current();
  }
  private current(): Session {
    const s = this.api.session;
    if (!s) throw new ApiError("authentication_required", 401);
    participant(s);
    if (processingStamp(s) !== this.stamp)
      throw new ApiError("context_changed", 409);
    return s;
  }
  private async request<T>(
    path: string,
    options: RequestInit,
    decode: (value: unknown, session: Session) => T,
  ): Promise<T> {
    this.current();
    return this.api.request(this.prefix + path, options, (value) =>
      decode(value, this.current()),
    );
  }
  async list(after = ""): Promise<OutputPolicyAdminPage> {
    if (after) identifier(after);
    return this.request(
      "/processing-output-policies?limit=25" + (after ? "&after=" + after : ""),
      {},
      (value) => {
        const page = exact(value, ["profile", "policies"], ["next"]);
        if (
          page.profile !== "producer-processing-output-policy-v1" ||
          !Array.isArray(page.policies) ||
          page.policies.length > 25
        )
          bad();
        const rows: OutputPolicyAdminPage["policies"] = [],
          seen = new Set<string>();
        for (const value of page.policies) {
          const row = exact(value, [
              "id",
              "version",
              "definition_hash",
              "state",
              "revision",
              "producer_id",
              "producer_binding_current_at_observation",
              "kind",
              "column_count",
            ]),
            ref = reference({
              id: row.id,
              version: row.version,
              hash: row.definition_hash,
            });
          if (
            seen.has(ref.id) ||
            row.state !== "output_active" ||
            row.revision !== 1 ||
            typeof row.producer_binding_current_at_observation !== "boolean" ||
            ![
              "csv",
              "json_records",
              "fixed_width",
              "xml_records",
              "xlsx_records",
            ].includes(row.kind as string)
          )
            bad();
          seen.add(ref.id);
          const columns = positive(row.column_count);
          if (columns > 128) bad();
          rows.push({
            reference: ref,
            producer_id: identifier(row.producer_id),
            producer_current:
              row.producer_binding_current_at_observation as boolean,
            kind: row.kind as string,
            column_count: columns,
          });
        }
        return {
          policies: rows,
          ...(page.next === undefined ? {} : { next: identifier(page.next) }),
        };
      },
    );
  }
  async get(value: Reference): Promise<OutputPolicyRecord> {
    const ref = reference(value);
    return this.request(
      `/processing-output-policies/${ref.id}/${ref.version}`,
      {},
      (value, s) => {
        const record = outputRecord(value, s, true);
        if (
          record.policy.id !== ref.id ||
          record.policy.version !== ref.version ||
          record.policy.definition_hash !== ref.hash
        )
          bad();
        return record;
      },
    );
  }
  async mutate(
    value: OutputPolicyMutation,
  ): Promise<{ resource: OutputPolicyRecord; replayed: boolean }> {
    const command = outputPolicyMutation(value),
      body =
        command.kind === "register"
          ? command.body
          : {
              definition_hash: command.policy.hash,
              expected_version: command.policy.version,
              expected_revision: command.revision,
            },
      path =
        command.kind === "register"
          ? "/processing-output-policies"
          : `/processing-output-policies/${command.policy.id}/${command.policy.version}/revoke`;
    return this.request(
      path,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": command.key,
        },
        body: JSON.stringify(body),
      },
      (value, s) => {
        const result = exact(value, ["resource", "replayed"]),
          record = outputRecord(result.resource, s, false);
        if (typeof result.replayed !== "boolean") bad();
        if (command.kind === "register") {
          if (
            record.policy.state !== "output_active" ||
            record.policy.version !== command.body.expected_version + 1 ||
            (command.body.policy_id !== undefined &&
              record.policy.id !== command.body.policy_id) ||
            record.binding.producer.actor_id !== command.body.producer_id ||
            record.binding.publisher_id !== s.identity.actor_id ||
            record.policy.definition_hash !==
              intakeHash(command.body.definition)
          )
            bad();
        } else if (
          record.policy.state !== "output_revoked" ||
          record.policy.id !== command.policy.id ||
          record.policy.version !== command.policy.version ||
          record.policy.definition_hash !== command.policy.hash ||
          record.policy.revision !== command.revision + 1
        )
          bad();
        return { resource: record, replayed: result.replayed as boolean };
      },
    );
  }
}
