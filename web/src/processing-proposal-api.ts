import { Api } from "./api";
import { ApiError, object, uuid, type Session } from "./types";
import {
  processingDefinition,
  processingHash,
  processingStamp,
  reference,
  type ProcessingDefinition,
  type Reference,
} from "./processing-types";
import { reviewTime } from "./processing-review-api";

const profile = "processing-workflow-proposal-v1";
const bad = (): never => {
  throw new ApiError("invalid_processing_proposal", 502);
};
const exact = (v: unknown, required: string[], optional: string[] = []) => {
  const o = object(v);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
};
const id = (v: unknown): string => {
  if (typeof v !== "string" || !uuid(v)) bad();
  return v as string;
};
const hash = (v: unknown): string => {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) bad();
  return v as string;
};
const integer = (v: unknown): number => {
  if (!Number.isSafeInteger(v) || Number(v) < 1) bad();
  return v as number;
};
const micros = (s: string) =>
  BigInt(Date.parse(s.slice(0, 19) + "Z")) * 1000n +
  BigInt((s.match(/\.(\d+)Z$/)?.[1] ?? "").padEnd(6, "0"));
function participant(value: unknown) {
  const o = exact(value, [
    "tenant_id",
    "partner_id",
    "actor_id",
    "authority_revision",
    "root_policy_digest",
  ]);
  return {
    tenant_id: id(o.tenant_id),
    partner_id: id(o.partner_id),
    actor_id: id(o.actor_id),
    authority_revision: integer(o.authority_revision),
    root_policy_digest: hash(o.root_policy_digest),
  };
}
const sessionParticipant = (s: Session) =>
  participant({
    tenant_id: s.identity.tenant_id,
    partner_id: s.identity.partner_id,
    actor_id: s.identity.actor_id,
    authority_revision: s.identity.authority_revision,
    root_policy_digest: s.identity.root_policy_digest,
  });
type Participant = ReturnType<typeof participant>;
export type ProposalSummary = {
  id: string;
  author_id: string;
  executor_id: string;
  definition_hash: string;
  state: string;
  revision: number;
  expires_at: string;
  adopted_workflow?: Reference;
};
export type Proposal = {
  id: string;
  definition: {
    profile: string;
    author: Participant;
    executor: Participant;
    definition: ProcessingDefinition;
    workflow_definition_hash: string;
    expires_at: string;
  };
  definition_hash: string;
  state: string;
  revision: number;
  created_at: string;
  adopted_workflow?: Reference;
};
export type ProposalView = {
  profile: string;
  proposal: Proposal;
  participant_bindings_current_at_observation: boolean;
  expired_at_observation: boolean;
  effects: string;
};
export function proposalSummary(value: unknown): ProposalSummary {
  const o = exact(
    value,
    [
      "id",
      "author_id",
      "executor_id",
      "definition_hash",
      "state",
      "revision",
      "expires_at",
    ],
    ["adopted_workflow"],
  );
  const r: ProposalSummary = {
    id: id(o.id),
    author_id: id(o.author_id),
    executor_id: id(o.executor_id),
    definition_hash: hash(o.definition_hash),
    state: String(o.state),
    revision: integer(o.revision),
    expires_at: reviewTime(o.expires_at),
    ...(o.adopted_workflow === undefined
      ? {}
      : { adopted_workflow: reference(o.adopted_workflow) }),
  };
  if (
    r.author_id === r.executor_id ||
    !["pending", "adopted", "rejected", "withdrawn"].includes(r.state) ||
    r.revision !== (r.state === "pending" ? 1 : 2) ||
    (r.state === "adopted") !== (r.adopted_workflow !== undefined)
  )
    bad();
  return r;
}
export function processingProposal(value: unknown): ProposalView {
  const o = exact(value, [
    "profile",
    "proposal",
    "participant_bindings_current_at_observation",
    "expired_at_observation",
    "effects",
  ]);
  const p = exact(
    o.proposal,
    ["id", "definition", "definition_hash", "state", "revision", "created_at"],
    ["adopted_workflow"],
  );
  const d = exact(p.definition, [
    "profile",
    "author",
    "executor",
    "definition",
    "workflow_definition_hash",
    "expires_at",
  ]);
  const definition = {
    profile,
    author: participant(d.author),
    executor: participant(d.executor),
    definition: processingDefinition(d.definition),
    workflow_definition_hash: hash(d.workflow_definition_hash),
    expires_at: reviewTime(d.expires_at),
  };
  const summary = proposalSummary({
    id: p.id,
    author_id: definition.author.actor_id,
    executor_id: definition.executor.actor_id,
    definition_hash: p.definition_hash,
    state: p.state,
    revision: p.revision,
    expires_at: definition.expires_at,
    ...(p.adopted_workflow === undefined
      ? {}
      : { adopted_workflow: p.adopted_workflow }),
  });
  const proposal: Proposal = {
    id: summary.id,
    definition,
    definition_hash: summary.definition_hash,
    state: summary.state,
    revision: summary.revision,
    created_at: reviewTime(p.created_at),
    ...(summary.adopted_workflow
      ? { adopted_workflow: summary.adopted_workflow }
      : {}),
  };
  if (
    o.profile !== profile ||
    d.profile !== profile ||
    definition.author.tenant_id !== definition.executor.tenant_id ||
    definition.author.partner_id !== definition.executor.partner_id ||
    processingHash(definition.definition) !==
      definition.workflow_definition_hash ||
    processingHash(definition) !== proposal.definition_hash ||
    (proposal.adopted_workflow &&
      proposal.adopted_workflow.hash !== definition.workflow_definition_hash) ||
    micros(definition.expires_at) <= micros(proposal.created_at) ||
    micros(definition.expires_at) >
      micros(proposal.created_at) + 30n * 86400000000n ||
    typeof o.participant_bindings_current_at_observation !== "boolean" ||
    typeof o.expired_at_observation !== "boolean" ||
    typeof o.effects !== "string"
  )
    bad();
  return {
    profile,
    proposal,
    participant_bindings_current_at_observation:
      o.participant_bindings_current_at_observation as boolean,
    expired_at_observation: o.expired_at_observation as boolean,
    effects: o.effects as string,
  };
}
export type ProposalMutation = {
  kind: "submit" | "adopt" | "reject" | "withdraw";
  id?: string;
  body: Record<string, unknown>;
  key: string;
};
export function proposalMutation(value: unknown): ProposalMutation {
  const o = exact(value, ["kind", "body", "key"], ["id"]);
  if (typeof o.key !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(o.key))
    bad();
  if (o.kind === "submit") {
    if (o.id !== undefined) bad();
    const b = exact(o.body, ["executor_id", "definition", "expires_at"]),
      definition = processingDefinition(b.definition);
    if (new TextEncoder().encode(JSON.stringify(definition)).length > 24 * 1024)
      bad();
    return {
      kind: "submit",
      key: o.key as string,
      body: {
        executor_id: id(b.executor_id),
        definition,
        expires_at: reviewTime(b.expires_at),
      },
    };
  }
  if (!["adopt", "reject", "withdraw"].includes(o.kind as string)) bad();
  const b = exact(o.body, ["definition_hash", "expected_revision"]);
  return {
    kind: o.kind as ProposalMutation["kind"],
    id: id(o.id),
    key: o.key as string,
    body: {
      definition_hash: hash(b.definition_hash),
      expected_revision: integer(b.expected_revision),
    },
  };
}
export function proposalAllowed(
  s: Session | null | undefined,
  action = "inspect",
  v?: ProposalView,
): boolean {
  if (!s || !s.identity.permissions.includes("workflow_manage")) return false;
  if (action === "submit") return true;
  if (action === "inspect")
    return (
      !v ||
      [
        v.proposal.definition.author.actor_id,
        v.proposal.definition.executor.actor_id,
      ].includes(s.identity.actor_id)
    );
  if (!v) return false;
  const d = v.proposal.definition;
  if (action === "withdraw") return s.identity.actor_id === d.author.actor_id;
  if (action === "reject") return s.identity.actor_id === d.executor.actor_id;
  return (
    action === "adopt" &&
    s.identity.actor_id === d.executor.actor_id &&
    ["read", "write", "check_run", "workflow_execute"].every((p) =>
      s.identity.permissions.includes(p),
    )
  );
}
export function proposalRecovery(
  input: ProposalMutation,
  s: Session,
  origin: string,
) {
  const request = proposalMutation(input);
  return {
    schema_version: 1,
    profile: "freightctl-processing-proposal-recovery-v1",
    server_origin: origin,
    participant: sessionParticipant(s),
    request,
    request_hash: processingHash(request),
  };
}
export function parseProposalRecovery(
  text: string,
  s: Session,
  origin: string,
): ProposalMutation {
  if (new TextEncoder().encode(text).length > 32 * 1024) bad();
  const o = exact(JSON.parse(text), [
    "schema_version",
    "profile",
    "server_origin",
    "participant",
    "request",
    "request_hash",
  ]);
  const actual = participant(o.participant),
    expected = sessionParticipant(s),
    request = proposalMutation(o.request);
  if (
    o.schema_version !== 1 ||
    o.profile !== "freightctl-processing-proposal-recovery-v1" ||
    o.server_origin !== origin ||
    processingHash(actual) !== processingHash(expected) ||
    o.request_hash !== processingHash(request)
  )
    bad();
  return request;
}
export class ProcessingProposalApi {
  private who: string;
  private prefix: string;
  constructor(private api: Api) {
    if (!api.session) throw new ApiError("unauthorized", 401);
    this.who = processingStamp(api.session);
    this.prefix = api.prefix;
  }
  private current(action = "inspect", v?: ProposalView) {
    if (processingStamp(this.api.session) !== this.who)
      throw new ApiError("context_changed", 409);
    if (!proposalAllowed(this.api.session, action, v))
      throw new ApiError("permission_denied", 403);
    return this.api.session!;
  }
  private bound(v: ProposalView, s: Session) {
    const d = v.proposal.definition,
      p = s.identity.actor_id === d.author.actor_id ? d.author : d.executor;
    if (processingHash(p) !== processingHash(sessionParticipant(s)))
      throw new ApiError("context_changed", 409);
    return v;
  }
  get(proposalID: string) {
    this.current();
    return this.api.request(
      this.prefix + "/processing-proposals/" + id(proposalID),
      {},
      (value) => {
        const v = processingProposal(value);
        return this.bound(v, this.current("inspect", v));
      },
    );
  }
  list(after = "") {
    this.current();
    if (after) id(after);
    return this.api.request(
      this.prefix +
        "/processing-proposals?limit=25" +
        (after ? "&after=" + after : ""),
      {},
      (value) => {
        const s = this.current(),
          o = exact(value, ["proposals"], ["next"]);
        if (!Array.isArray(o.proposals) || o.proposals.length > 25) bad();
        const proposals = (o.proposals as unknown[]).map(proposalSummary),
          next = o.next === undefined ? "" : id(o.next),
          seen = new Set();
        for (const r of proposals) {
          if (
            seen.has(r.id) ||
            (r.author_id !== s.identity.actor_id &&
              r.executor_id !== s.identity.actor_id)
          )
            bad();
          seen.add(r.id);
        }
        if (next && proposals.at(-1)?.id !== next) bad();
        return { proposals, next };
      },
    );
  }
  mutate(input: ProposalMutation, view?: ProposalView) {
    const m = proposalMutation(input),
      s = this.current(m.kind, view);
    if (m.kind === "submit") {
      if (m.body.executor_id === s.identity.actor_id) bad();
    } else {
      if (!view) bad();
      this.bound(view!, s);
      if (
        m.id !== view!.proposal.id ||
        m.body.definition_hash !== view!.proposal.definition_hash
      )
        bad();
    }
    return this.api.request(
      this.prefix +
        "/processing-proposals" +
        (m.kind === "submit" ? "" : "/" + m.id + "/" + m.kind),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": m.key,
        },
        body: JSON.stringify(m.body),
      },
      (value) => {
        const current = this.current(m.kind, view),
          o = exact(value, ["resource", "replayed"]),
          r = exact(
            o.resource,
            ["profile", "observation", "proposal"],
            ["adopted_workflow"],
          ),
          summary = proposalSummary(r.proposal);
        if (
          typeof o.replayed !== "boolean" ||
          r.profile !== profile ||
          r.observation !== "original-command-receipt"
        )
          bad();
        if (m.kind === "submit") {
          if (
            summary.author_id !== current.identity.actor_id ||
            summary.executor_id !== m.body.executor_id ||
            summary.expires_at !== m.body.expires_at ||
            summary.state !== "pending" ||
            summary.revision !== 1 ||
            r.adopted_workflow !== undefined
          )
            bad();
        } else {
          const d = view!.proposal.definition;
          if (
            summary.id !== m.id ||
            summary.definition_hash !== m.body.definition_hash ||
            summary.revision !== Number(m.body.expected_revision) + 1 ||
            summary.state !==
              (
                {
                  adopt: "adopted",
                  reject: "rejected",
                  withdraw: "withdrawn",
                } as Record<string, string>
              )[m.kind] ||
            summary.author_id !== d.author.actor_id ||
            summary.executor_id !== d.executor.actor_id ||
            summary.expires_at !== d.expires_at
          )
            bad();
        }
        if (m.kind === "adopt") {
          const w = exact(r.adopted_workflow, [
              "id",
              "version",
              "definition_hash",
              "state",
              "revision",
              "approval_authority",
            ]),
            ref = summary.adopted_workflow!;
          if (
            ref.hash !== view!.proposal.definition.workflow_definition_hash ||
            w.id !== ref.id ||
            w.version !== ref.version ||
            w.definition_hash !== ref.hash ||
            w.state !== "draft" ||
            w.revision !== 1 ||
            w.approval_authority !== 0
          )
            bad();
        } else if (r.adopted_workflow !== undefined) bad();
        return { summary, replayed: o.replayed as boolean };
      },
    );
  }
}
