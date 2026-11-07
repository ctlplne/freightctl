import { Api } from "./api";
import { processingCatalog } from "./processing-catalog-types";
import { processingOutputCatalog } from "./processing-output-types";
import { ApiError, object, type Session } from "./types";
import { operationKey, digestBytes } from "./crypto";
import { parseRecheckPlan } from "./rechecks-types";
import {
  processingAllowed,
  processingStamp,
  processingContracts,
  processingDefinition,
  processingConfiguration,
  processingRun,
  processingStatus,
  processingWork,
  processingHash,
  processingPath,
  processingPlanProfile,
  projection,
  reference,
  type Configuration,
  type ProcessingDefinition,
  type ProcessingRun,
  type RunView,
  type WorkView,
  type Reference,
} from "./processing-types";

export type Mutation = {
  kind: "draft" | "approve" | "revoke" | "run" | "work" | "refresh" | "cancel";
  target?: { id: string; version?: number };
  body: Record<string, unknown>;
  key: string;
};
export type MutationResult = {
  replayed: boolean;
  configuration?: Configuration;
  run?: ProcessingRun;
  status?: RunView;
  work?: WorkView;
};
export function processingMutation(value: unknown): Mutation {
  const o = object(value);
  if (
    Object.keys(o).some(
      (k) => !["kind", "target", "body", "key"].includes(k),
    ) ||
    typeof o.key !== "string" ||
    !/^[A-Za-z0-9._:-]{1,128}$/.test(o.key)
  )
    throw new ApiError("invalid_processing_recovery", 400);
  const kind = o.kind as Mutation["kind"],
    body = object(o.body),
    keys = (allowed: string[]) => {
      if (Object.keys(body).some((k) => !allowed.includes(k)))
        throw new ApiError("invalid_processing_recovery", 400);
    };
  const validID = (v: unknown) =>
    reference({ id: v, version: 1, hash: "a".repeat(64) }).id;
  let target: Mutation["target"];
  if (o.target !== undefined) {
    const t = object(o.target);
    if (Object.keys(t).some((k) => !["id", "version"].includes(k)))
      throw new ApiError("invalid_processing_recovery", 400);
    target = {
      id: validID(t.id),
      ...(t.version === undefined
        ? {}
        : {
            version: reference({
              id: t.id,
              version: t.version,
              hash: "a".repeat(64),
            }).version,
          }),
    };
  }
  let normalized: Record<string, unknown>;
  switch (kind) {
    case "draft":
      keys(["workflow_id", "expected_version", "definition"]);
      if (
        target ||
        !Number.isSafeInteger(body.expected_version) ||
        Number(body.expected_version) < 0 ||
        (body.workflow_id === undefined) !== (body.expected_version === 0)
      )
        throw new ApiError("invalid_processing_recovery", 400);
      normalized = {
        ...(body.workflow_id === undefined
          ? {}
          : { workflow_id: validID(body.workflow_id) }),
        expected_version: body.expected_version,
        definition: processingDefinition(body.definition),
      };
      break;
    case "run":
      keys(["workflow", "file_id"]);
      if (target) throw new ApiError("invalid_processing_recovery", 400);
      normalized = {
        workflow: reference(body.workflow),
        file_id: validID(body.file_id),
      };
      break;
    case "approve":
    case "revoke":
    case "cancel":
      keys(["definition_hash", "expected_revision"]);
      if (
        !target ||
        (!target.version && kind !== "cancel") ||
        (target.version !== undefined && kind === "cancel") ||
        typeof body.definition_hash !== "string" ||
        !/^[0-9a-f]{64}$/.test(body.definition_hash) ||
        !Number.isSafeInteger(body.expected_revision) ||
        Number(body.expected_revision) < 1
      )
        throw new ApiError("invalid_processing_recovery", 400);
      normalized = {
        definition_hash: body.definition_hash,
        expected_revision: body.expected_revision,
      };
      break;
    case "work":
    case "refresh":
      keys([]);
      if (!target || target.version !== undefined)
        throw new ApiError("invalid_processing_recovery", 400);
      normalized = {};
      break;
    default:
      throw new ApiError("invalid_processing_recovery", 400);
  }
  return { kind, ...(target ? { target } : {}), body: normalized, key: o.key };
}
export const newProcessingMutation = (m: Omit<Mutation, "key">) =>
  processingMutation({ ...m, key: operationKey() });
const replayed = (o: Record<string, unknown>) => {
  if (typeof o.replayed !== "boolean")
    throw new ApiError("invalid_processing_contract", 502);
  return o.replayed;
};
export class ProcessingApi {
  private who: string;
  private prefix: string;
  constructor(private api: Api) {
    if (!api.session) throw new ApiError("unauthorized", 401);
    this.who = processingStamp(api.session);
    this.prefix = api.prefix;
  }
  private current(action = "inspect"): Session {
    if (processingStamp(this.api.session) !== this.who)
      throw new ApiError("context_changed", 409);
    if (!processingAllowed(this.api.session, action))
      throw new ApiError("permission_denied", 403);
    return this.api.session!;
  }
  private async request<T>(
    path: string,
    options: RequestInit,
    decode: (v: unknown, s: Session) => T,
    action = "inspect",
    timeout = 30000,
  ) {
    this.current(action);
    return this.api.request(
      this.prefix + path,
      options,
      (v) => {
        const s = this.current(action);
        return decode(v, s);
      },
      timeout,
    );
  }
  contracts(id: string, selected?: Reference) {
    const output = selected === undefined ? undefined : reference(selected);
    const query =
      output === undefined
        ? ""
        : `?output_policy_id=${output.id}&output_policy_version=${output.version}&output_policy_hash=${output.hash}`;
    return this.request(
      `/checks/${reference({ id, version: 1, hash: "a".repeat(64) }).id}/processing-contracts${query}`,
      {},
      (v, s) => {
        const c = processingContracts(v, s);
        if (
          c.source.file_revision_id !== id ||
          c.authority_revision !== s.identity.authority_revision ||
          c.namespace_root_digest !== s.identity.root_policy_digest
        )
          throw new ApiError("context_changed", 409);
        if (
          (output !== undefined) !== (c.output_binding !== undefined) ||
          (output !== undefined &&
            processingHash(c.output_policy.reference) !==
              processingHash(output))
        )
          throw new ApiError("invalid_processing_contract", 502);
        return c;
      },
    );
  }
  outputContracts(after = "") {
    if (after) reference({ id: after, version: 1, hash: "a".repeat(64) });
    return this.request(
      "/processing-output-policies?limit=25" + (after ? "&after=" + after : ""),
      {},
      (v, s) => processingOutputCatalog(v, s),
      "configuration",
    );
  }
  catalog(after = "") {
    if (after) reference({ id: after, version: 1, hash: "a".repeat(64) });
    return this.request(
      "/processing-workflows?limit=25" + (after ? "&after=" + after : ""),
      {},
      (v, s) => {
        const page = processingCatalog(v);
        if (
          page.workflows.length > 25 ||
          page.authority_revision !== s.identity.authority_revision ||
          page.namespace_root_digest !== s.identity.root_policy_digest
        )
          throw new ApiError("context_changed", 409);
        return page;
      },
      "configuration",
    );
  }
  configuration(id: string, version: number) {
    const ref = reference({ id, version, hash: "a".repeat(64) });
    return this.request(
      `/workflows/${ref.id}/${ref.version}`,
      {},
      (v) => {
        const c = processingConfiguration(v);
        if (c.id !== id || c.version !== version)
          throw new ApiError("invalid_processing_contract", 502);
        return c;
      },
      "configuration",
    );
  }
  review(definition: ProcessingDefinition, file: string) {
    const d = processingDefinition(definition),
      hash = processingHash(d);
    return this.request(
      "/workflows/validate",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ definition: d, file_id: file }),
      },
      (v, s) => {
        const o = object(v);
        const actual = processingDefinition(o.definition),
          source = object(o.source);
        if (
          processingHash(actual) !== hash ||
          o.definition_hash !== hash ||
          o.external_contact !== false ||
          o.approval_required !== true ||
          !Array.isArray(o.effects) ||
          o.effects.length !== 0 ||
          source.id !== file ||
          typeof source.policy !== "string" ||
          !source.policy.endsWith(
            ":" + d.processing.definition.source_policy_hash,
          ) ||
          !o.processing
        )
          throw new ApiError("invalid_processing_contract", 502);
        const plan = object(object(o.processing).plan),
          rawContext = object(plan.context),
          root = processingPath(rawContext.namespace_root, false);
        if (
          digestBytes(new TextEncoder().encode(root)) !==
          s.identity.root_policy_digest
        )
          throw new ApiError("context_changed", 409);
        const context = parseRecheckPlan(rawContext, root);
        processingPlanProfile(plan, context, s);
        if (
          context.authority_revision !== s.identity.authority_revision ||
          context.source.file.id !== source.id ||
          context.source.file.sha256 !== source.sha256 ||
          context.source.file.size_bytes !== source.size_bytes ||
          context.source.file.policy !== source.policy ||
          processingHash(reference(context.policy)) !==
            processingHash(d.processing.output_policy) ||
          processingHash(projection(plan.projection)) !==
            processingHash(d.processing.definition) ||
          context.reason !== d.processing.reason ||
          (context.target
            ? object(object(context.target).command).path
            : "") !== d.processing.target_path
        )
          throw new ApiError("invalid_processing_contract", 502);
        return { definition: actual, hash, source };
      },
      "inspect",
    );
  }
  status(id: string) {
    return this.request(
      `/workflow-runs/${reference({ id, version: 1, hash: "a".repeat(64) }).id}`,
      {},
      (v, s) => {
        const r = processingStatus(v, s);
        if (r.run.id !== id)
          throw new ApiError("invalid_processing_contract", 502);
        return r;
      },
    );
  }
  mutate(input: Mutation): Promise<MutationResult> {
    const m = processingMutation(input),
      action =
        m.kind === "draft"
          ? "manage"
          : ["approve", "revoke"].includes(m.kind)
            ? "approve"
            : "execute";
    const route =
      m.kind === "draft"
        ? "/workflows/drafts"
        : m.kind === "run"
          ? "/workflow-runs"
          : ["approve", "revoke"].includes(m.kind)
            ? `/workflows/${m.target!.id}/${m.target!.version}/${m.kind}`
            : `/workflow-runs/${m.target!.id}/${m.kind}`;
    return this.request(
      route,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": m.key,
        },
        ...(["work", "refresh"].includes(m.kind)
          ? {}
          : { body: JSON.stringify(m.body) }),
      },
      (v, s) => {
        const o = object(v);
        if (m.kind === "work") {
          const work = processingWork(v, s);
          if (work.status.run.id !== m.target!.id)
            throw new ApiError("invalid_processing_contract", 502);
          return { replayed: work.replayed, status: work.status, work };
        }
        const repeated = replayed(o);
        if (["draft", "approve", "revoke"].includes(m.kind)) {
          const c = processingConfiguration(o.resource);
          if (m.kind === "draft") {
            if (
              c.state !== "draft" ||
              c.revision !== 1 ||
              c.version !== Number(m.body.expected_version) + 1 ||
              (m.body.workflow_id !== undefined &&
                c.id !== m.body.workflow_id) ||
              c.definition_hash !== processingHash(m.body.definition)
            )
              throw new ApiError("invalid_processing_contract", 502);
          } else if (
            c.id !== m.target!.id ||
            c.version !== m.target!.version ||
            c.definition_hash !== m.body.definition_hash ||
            c.revision !== Number(m.body.expected_revision) + 1 ||
            c.state !== (m.kind === "approve" ? "approved" : "revoked")
          )
            throw new ApiError("invalid_processing_contract", 502);
          return { replayed: repeated, configuration: c };
        }
        if (m.kind === "run") {
          const r = processingRun(o.resource, s),
            ref = reference(m.body.workflow);
          if (
            r.workflow_id !== ref.id ||
            r.workflow_version !== ref.version ||
            r.workflow_hash !== ref.hash ||
            r.file_id !== m.body.file_id ||
            r.state !== "queued" ||
            r.revision !== 1
          )
            throw new ApiError("invalid_processing_contract", 502);
          return { replayed: repeated, run: r };
        }
        const resource =
          m.kind === "refresh" ? object(o.resource).status : o.resource;
        const status = processingStatus(resource, s);
        if (
          status.run.id !== m.target!.id ||
          (m.kind === "cancel" && status.run.state !== "cancelled")
        )
          throw new ApiError("invalid_processing_contract", 502);
        return { replayed: repeated, status };
      },
      action,
      m.kind === "work" ? 70000 : 30000,
    );
  }
}

function participant(session: Session) {
  const i = session.identity;
  return {
    tenant_id: i.tenant_id,
    partner_id: i.partner_id,
    actor_id: i.actor_id,
    authority_revision: i.authority_revision,
    root_policy_digest: i.root_policy_digest,
  };
}
export function processingRecovery(
  m: Mutation,
  session: Session,
  origin: string,
) {
  const request = processingMutation(m);
  return {
    schema_version: 1,
    profile: "freightctl-processing-recovery-v1",
    server_origin: origin,
    participant: participant(session),
    request,
    request_hash: processingHash(request),
  };
}
export function parseProcessingRecovery(
  text: string,
  session: Session,
  origin: string,
): Mutation {
  if (new TextEncoder().encode(text).length > 32 * 1024)
    throw new ApiError("invalid_processing_recovery", 400);
  const o = object(JSON.parse(text)),
    bound = object(o.participant),
    expected = participant(session);
  if (
    Object.keys(o).some(
      (k) =>
        ![
          "schema_version",
          "profile",
          "server_origin",
          "participant",
          "request",
          "request_hash",
        ].includes(k),
    ) ||
    o.schema_version !== 1 ||
    o.profile !== "freightctl-processing-recovery-v1" ||
    o.server_origin !== origin ||
    Object.keys(bound).length !== Object.keys(expected).length ||
    Object.entries(expected).some(([key, value]) => bound[key] !== value)
  )
    throw new ApiError("invalid_processing_recovery", 400);
  const request = processingMutation(o.request);
  if (processingHash(request) !== o.request_hash)
    throw new ApiError("invalid_processing_recovery", 400);
  return request;
}
