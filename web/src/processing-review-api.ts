import { Api } from "./api";
import { ApiError, object, uuid, type Session } from "./types";
import {
  processingDefinition,
  processingHash,
  processingStamp,
  reference,
  type ProcessingDefinition,
} from "./processing-types";

const bad = (): never => {
  throw new ApiError("invalid_processing_review", 502);
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
const number = (v: unknown, min = 1): number => {
  if (!Number.isSafeInteger(v) || Number(v) < min) bad();
  return v as number;
};
export function reviewTime(v: unknown): string {
  if (
    typeof v !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(v)
  )
    bad();
  const t = Date.parse(v as string);
  if (
    !Number.isFinite(t) ||
    new Date(t).toISOString().slice(0, 19) !== (v as string).slice(0, 19)
  )
    bad();
  return (v as string)
    .replace(/(\.\d*?[1-9])0+Z$/, "$1Z")
    .replace(/\.0+Z$/, "Z");
}
const micros = (value: string) =>
  BigInt(Date.parse(value.slice(0, 19) + "Z")) * 1000n +
  BigInt((value.match(/\.(\d+)Z$/)?.[1] ?? "").padEnd(6, "0"));
export type ReviewParticipant = {
  actor_id: string;
  authority_revision: number;
  namespace_root_digest: string;
};
export type ReviewDefinition = {
  profile: string;
  author: ReviewParticipant;
  reviewer: ReviewParticipant;
  workflow: { id: string; version: number; hash: string };
  workflow_revision: number;
  definition: ProcessingDefinition;
  expires_at: string;
};
export type Review = {
  id: string;
  definition: ReviewDefinition;
  definition_hash: string;
  state: string;
  revision: number;
  adopted_revision: number;
  created_at: string;
  changed_event_id: string;
};
export type ReviewSummary = {
  id: string;
  author_id: string;
  reviewer_id: string;
  workflow_id: string;
  workflow_version: number;
  definition_hash: string;
  state: string;
  revision: number;
  adopted_revision: number;
  expires_at: string;
};
function participant(v: unknown): ReviewParticipant {
  const o = exact(v, [
    "actor_id",
    "authority_revision",
    "namespace_root_digest",
  ]);
  return {
    actor_id: id(o.actor_id),
    authority_revision: number(o.authority_revision),
    namespace_root_digest: hash(o.namespace_root_digest),
  };
}
function state(v: unknown): string {
  if (
    !["pending", "approved", "rejected", "adopted", "withdrawn"].includes(
      v as string,
    )
  )
    bad();
  return v as string;
}
function adoption(o: {
  state: string;
  revision: number;
  adopted_revision: number;
}) {
  if (
    o.adopted_revision > o.revision ||
    (["pending", "approved", "rejected"].includes(o.state) &&
      o.adopted_revision !== 0) ||
    (o.state === "adopted" &&
      (o.adopted_revision < 1 || o.adopted_revision !== o.revision))
  )
    bad();
}
export function processingReview(value: unknown): Review {
  const o = exact(value, [
    "id",
    "definition",
    "definition_hash",
    "state",
    "revision",
    "adopted_revision",
    "created_at",
    "changed_event_id",
  ]);
  const d = exact(o.definition, [
    "profile",
    "author",
    "reviewer",
    "workflow",
    "workflow_revision",
    "definition",
    "expires_at",
  ]);
  const definition: ReviewDefinition = {
    profile: "independent-processing-workflow-review-v1",
    author: participant(d.author),
    reviewer: participant(d.reviewer),
    workflow: reference(d.workflow),
    workflow_revision: number(d.workflow_revision),
    definition: processingDefinition(d.definition),
    expires_at: reviewTime(d.expires_at),
  };
  if (
    d.profile !== definition.profile ||
    definition.author.actor_id === definition.reviewer.actor_id ||
    processingHash(definition.definition) !== definition.workflow.hash
  )
    bad();
  const row: Review = {
    id: id(o.id),
    definition,
    definition_hash: hash(o.definition_hash),
    state: state(o.state),
    revision: number(o.revision),
    adopted_revision: number(o.adopted_revision, 0),
    created_at: reviewTime(o.created_at),
    changed_event_id: id(o.changed_event_id),
  };
  adoption(row);
  if (
    processingHash(definition) !== row.definition_hash ||
    micros(definition.expires_at) <= micros(row.created_at) ||
    micros(definition.expires_at) > micros(row.created_at) + 30n * 86400000000n
  )
    bad();
  return row;
}
export function reviewSummary(value: unknown): ReviewSummary {
  const o = exact(value, [
    "id",
    "author_id",
    "reviewer_id",
    "workflow_id",
    "workflow_version",
    "definition_hash",
    "state",
    "revision",
    "adopted_revision",
    "expires_at",
  ]);
  const row: ReviewSummary = {
    id: id(o.id),
    author_id: id(o.author_id),
    reviewer_id: id(o.reviewer_id),
    workflow_id: id(o.workflow_id),
    workflow_version: number(o.workflow_version),
    definition_hash: hash(o.definition_hash),
    state: state(o.state),
    revision: number(o.revision),
    adopted_revision: number(o.adopted_revision, 0),
    expires_at: reviewTime(o.expires_at),
  };
  adoption(row);
  if (row.author_id === row.reviewer_id) bad();
  return row;
}
export type ReviewMutation = {
  kind: "request" | "approve" | "reject" | "withdraw" | "adopt";
  id?: string;
  body: Record<string, unknown>;
  key: string;
};
export function reviewMutation(value: unknown): ReviewMutation {
  const o = exact(value, ["kind", "body", "key"], ["id"]);
  if (typeof o.key !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(o.key))
    bad();
  if (o.kind === "request") {
    if (o.id !== undefined) bad();
    const b = exact(o.body, [
      "workflow",
      "expected_revision",
      "reviewer_id",
      "expires_at",
    ]);
    return {
      kind: "request",
      body: {
        workflow: reference(b.workflow),
        expected_revision: number(b.expected_revision),
        reviewer_id: id(b.reviewer_id),
        expires_at: reviewTime(b.expires_at),
      },
      key: o.key as string,
    };
  }
  if (!["approve", "reject", "withdraw", "adopt"].includes(o.kind as string))
    bad();
  const b = exact(o.body, ["definition_hash", "expected_revision"]);
  return {
    kind: o.kind as ReviewMutation["kind"],
    id: id(o.id),
    body: {
      definition_hash: hash(b.definition_hash),
      expected_revision: number(b.expected_revision),
    },
    key: o.key as string,
  };
}
export function reviewAllowed(
  s: Session | null | undefined,
  action = "inspect",
  r?: Review,
): boolean {
  if (!s) return false;
  const has = (p: string) => s.identity.permissions.includes(p),
    actor = s.identity.actor_id;
  if (action === "request") return has("workflow_manage");
  if (action === "inspect" && r)
    return (
      (actor === r.definition.author.actor_id &&
        (has("workflow_manage") ||
          has("workflow_execute") ||
          has("workflow_approve"))) ||
      (actor === r.definition.reviewer.actor_id &&
        has("inspect") &&
        has("workflow_approve"))
    );
  if (action === "inspect")
    return (
      has("workflow_manage") ||
      has("workflow_execute") ||
      has("workflow_approve")
    );
  if (!r) return false;
  if (action === "adopt")
    return actor === r.definition.author.actor_id && has("workflow_manage");
  const reviewer =
    actor === r.definition.reviewer.actor_id &&
    has("inspect") &&
    has("workflow_approve");
  if (action === "withdraw")
    return (
      reviewer ||
      (actor === r.definition.author.actor_id && has("workflow_manage"))
    );
  return (action === "approve" || action === "reject") && reviewer;
}
const sessionParticipant = (s: Session) => ({
  tenant_id: s.identity.tenant_id,
  partner_id: s.identity.partner_id,
  actor_id: s.identity.actor_id,
  authority_revision: s.identity.authority_revision,
  root_policy_digest: s.identity.root_policy_digest,
});
export function reviewRecovery(m: ReviewMutation, s: Session, origin: string) {
  const request = reviewMutation(m);
  return {
    schema_version: 1,
    profile: "freightctl-processing-review-recovery-v1",
    server_origin: origin,
    participant: sessionParticipant(s),
    request,
    request_hash: processingHash(request),
  };
}
export function parseReviewRecovery(
  text: string,
  s: Session,
  origin: string,
): ReviewMutation {
  if (new TextEncoder().encode(text).length > 32 * 1024) bad();
  const o = exact(JSON.parse(text), [
      "schema_version",
      "profile",
      "server_origin",
      "participant",
      "request",
      "request_hash",
    ]),
    expected = sessionParticipant(s),
    p = exact(o.participant, Object.keys(expected));
  if (
    o.schema_version !== 1 ||
    o.profile !== "freightctl-processing-review-recovery-v1" ||
    o.server_origin !== origin ||
    Object.entries(expected).some(([k, v]) => p[k] !== v)
  )
    bad();
  const request = reviewMutation(o.request);
  if (processingHash(request) !== o.request_hash) bad();
  return request;
}
export class ProcessingReviewApi {
  private who: string;
  private prefix: string;
  constructor(private api: Api) {
    if (!api.session) throw new ApiError("unauthorized", 401);
    this.who = processingStamp(api.session);
    this.prefix = api.prefix;
  }
  private current(action = "inspect", r?: Review) {
    if (processingStamp(this.api.session) !== this.who)
      throw new ApiError("context_changed", 409);
    if (!reviewAllowed(this.api.session, action, r))
      throw new ApiError("permission_denied", 403);
    return this.api.session!;
  }
  private bound(r: Review, s: Session) {
    const p =
      s.identity.actor_id === r.definition.author.actor_id
        ? r.definition.author
        : r.definition.reviewer;
    if (
      p.actor_id !== s.identity.actor_id ||
      p.authority_revision !== s.identity.authority_revision ||
      p.namespace_root_digest !== s.identity.root_policy_digest
    )
      throw new ApiError("context_changed", 409);
    return r;
  }
  get(reviewID: string) {
    this.current();
    return this.api.request(
      this.prefix + "/processing-reviews/" + id(reviewID),
      {},
      (v) => {
        const row = processingReview(v);
        return this.bound(row, this.current("inspect", row));
      },
    );
  }
  list(after = "") {
    this.current();
    if (after) id(after);
    return this.api.request(
      this.prefix +
        "/processing-reviews?limit=25" +
        (after ? "&after=" + after : ""),
      {},
      (v) => {
        const s = this.current(),
          o = exact(v, ["reviews"], ["next"]);
        if (!Array.isArray(o.reviews) || o.reviews.length > 25) bad();
        const reviews = (o.reviews as unknown[]).map(reviewSummary);
        if (
          reviews.some(
            (r) =>
              r.author_id !== s.identity.actor_id &&
              (r.reviewer_id !== s.identity.actor_id ||
                !s.identity.permissions.includes("inspect") ||
                !s.identity.permissions.includes("workflow_approve")),
          )
        )
          bad();
        return { reviews, next: o.next === undefined ? "" : id(o.next) };
      },
    );
  }
  mutate(input: ReviewMutation, review?: Review) {
    const m = reviewMutation(input),
      s = this.current(m.kind, review);
    if (review) {
      this.bound(review, s);
      if (
        m.id !== review.id ||
        m.body.definition_hash !== review.definition_hash
      )
        bad();
    }
    if (m.kind !== "request" && !review) bad();
    return this.api.request(
      this.prefix +
        "/processing-reviews" +
        (m.kind === "request" ? "" : "/" + m.id + "/" + m.kind),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": m.key,
        },
        body: JSON.stringify(m.body),
      },
      (v) => {
        const current = this.current(m.kind, review),
          o = exact(v, ["resource", "replayed"]);
        if (typeof o.replayed !== "boolean") bad();
        const adoption =
          m.kind === "adopt"
            ? exact(o.resource, ["review", "workflow"])
            : undefined;
        const summary = reviewSummary(adoption ? adoption.review : o.resource);
        if (m.kind === "request") {
          const w = reference(m.body.workflow);
          if (
            summary.author_id !== current.identity.actor_id ||
            summary.reviewer_id !== m.body.reviewer_id ||
            summary.workflow_id !== w.id ||
            summary.workflow_version !== w.version ||
            summary.state !== "pending" ||
            summary.revision !== 1 ||
            summary.adopted_revision !== 0 ||
            summary.expires_at !== m.body.expires_at
          )
            bad();
        } else {
          const r = review!,
            d = r.definition;
          if (
            summary.id !== m.id ||
            summary.definition_hash !== m.body.definition_hash ||
            summary.revision !== Number(m.body.expected_revision) + 1 ||
            summary.state !==
              (
                {
                  approve: "approved",
                  reject: "rejected",
                  withdraw: "withdrawn",
                  adopt: "adopted",
                } as Record<string, string>
              )[m.kind] ||
            summary.author_id !== d.author.actor_id ||
            summary.reviewer_id !== d.reviewer.actor_id ||
            summary.workflow_id !== d.workflow.id ||
            summary.workflow_version !== d.workflow.version ||
            summary.expires_at !== d.expires_at
          )
            bad();
          if (adoption) {
            const w = exact(adoption.workflow, [
              "id",
              "version",
              "definition_hash",
              "state",
              "revision",
              "approval_authority",
            ]);
            if (
              w.id !== d.workflow.id ||
              w.version !== d.workflow.version ||
              w.definition_hash !== d.workflow.hash ||
              w.state !== "approved" ||
              w.revision !== d.workflow_revision + 1 ||
              w.approval_authority !== d.author.authority_revision
            )
              bad();
          }
        }
        return { summary, replayed: o.replayed };
      },
    );
  }
}
