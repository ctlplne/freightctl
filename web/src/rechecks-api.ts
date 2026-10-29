import { Api } from "./api";
import { operationKey, digestBytes } from "./crypto";
import { ApiError, object, uuid } from "./types";
import {
  parseRecheck,
  parseRecheckPreview,
  parseRecheckReceipt,
  parseRecheckView,
  planFingerprint,
  type Recheck,
  type RecheckOptions,
  type RecheckPlan,
} from "./rechecks-types";

export class RechecksApi {
  private who: string;
  private prefix: string;
  constructor(private api: Api) {
    if (!api.session) throw new ApiError("unauthorized", 401);
    this.prefix = api.prefix;
    this.who = this.context();
  }
  private context() {
    const s = this.api.session;
    if (!s) return "";
    return JSON.stringify([
      s.identity.tenant_id,
      s.identity.partner_id,
      s.identity.actor_id,
      s.identity.authority_revision,
      s.session.id,
    ]);
  }
  private current() {
    if (this.context() !== this.who) throw new ApiError("context_changed", 409);
  }
  private key(op: string, row: Recheck) {
    return (
      "browser-recheck-" +
      op +
      "-" +
      digestBytes(
        new TextEncoder().encode(
          JSON.stringify([
            this.who,
            row.id,
            row.definition_hash,
            row.revision,
            op,
          ]),
        ),
      )
    );
  }
  preview(id: string, options: RecheckOptions) {
    this.current();
    return this.api.request(
      `${this.prefix}/checks/${id}/recheck-preview`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(options),
      },
      parseRecheckPreview,
    );
  }
  async list(id: string, after = "") {
    this.current();
    return this.api.request(
      `${this.prefix}/checks/${id}/rechecks?${new URLSearchParams({ limit: "20", after })}`,
      {},
      (v) => {
        const o = object(v);
        if (!Array.isArray(o.rechecks) || o.rechecks.length > 20)
          throw new ApiError("invalid_server_response", 502);
        const rows = o.rechecks.map(parseRecheck);
        if (
          rows.some(
            (r, i) =>
              r.source_file_id !== id ||
              r.id <= after ||
              (i > 0 && r.id <= rows[i - 1]!.id),
          )
        )
          throw new ApiError("invalid_server_response", 502);
        if (
          o.next !== undefined &&
          (!rows.length || o.next !== rows[rows.length - 1]!.id)
        )
          throw new ApiError("invalid_server_response", 502);
        if (
          o.next !== undefined &&
          (typeof o.next !== "string" || !uuid(o.next))
        )
          throw new ApiError("invalid_server_response", 502);
        return {
          rechecks: rows,
          next: typeof o.next === "string" ? o.next : "",
        };
      },
    );
  }
  get(id: string) {
    this.current();
    return this.api.request(`${this.prefix}/rechecks/${id}`, {}, (v) => {
      const view = parseRecheckView(v);
      if (view.recheck.id !== id)
        throw new ApiError("invalid_server_response", 502);
      return view;
    });
  }
  proposalKey(plan: RecheckPlan) {
    this.current();
    const scope = this.api.session!.identity,
      slot =
        "freightctl-recheck-intent:" +
        JSON.stringify([
          scope.tenant_id,
          scope.partner_id,
          scope.actor_id,
          plan.source.file.id,
        ]),
      fingerprint = planFingerprint(plan);
    try {
      const saved = JSON.parse(sessionStorage.getItem(slot) || "null");
      if (
        saved?.fingerprint === fingerprint &&
        typeof saved.key === "string" &&
        /^browser-recheck-propose-[0-9a-f-]{36}$/.test(saved.key)
      )
        return saved.key;
    } catch {
      /* Recover through private history when browser storage is unavailable. */
    }
    const key = "browser-recheck-propose-" + operationKey();
    try {
      sessionStorage.setItem(slot, JSON.stringify({ fingerprint, key }));
    } catch {
      /* No credential or plan content is stored. */
    }
    return key;
  }
  forgetProposal(plan: RecheckPlan) {
    const scope = this.api.session?.identity;
    if (scope)
      try {
        sessionStorage.removeItem(
          "freightctl-recheck-intent:" +
            JSON.stringify([
              scope.tenant_id,
              scope.partner_id,
              scope.actor_id,
              plan.source.file.id,
            ]),
        );
      } catch {
        /* Optional operation-key cache. */
      }
  }
  async propose(plan: RecheckPlan, key: string) {
    this.current();
    const r = await this.api.request(
      `${this.prefix}/checks/${plan.source.file.id}/rechecks`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({ plan }),
      },
      parseRecheckReceipt,
    );
    if (planFingerprint(r.definition.plan) !== planFingerprint(plan))
      throw new ApiError("invalid_server_response", 502);
    return r;
  }
  async decide(row: Recheck, operation: "approve" | "cancel") {
    this.current();
    const next = await this.api.request(
      `${this.prefix}/rechecks/${row.id}/decide`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": this.key(operation, row),
        },
        body: JSON.stringify({
          operation,
          definition_hash: row.definition_hash,
          expected_revision: row.revision,
        }),
      },
      parseRecheckReceipt,
    );
    this.match(row, next);
    if (
      next.state !== (operation === "approve" ? "approved" : "cancelled") ||
      next.revision !== row.revision + 1
    )
      throw new ApiError("invalid_server_response", 502);
    return next;
  }
  async copy(row: Recheck) {
    this.current();
    const next = await this.api.request(
      `${this.prefix}/rechecks/${row.id}/copy`,
      { method: "POST", headers: { "Idempotency-Key": this.key("copy", row) } },
      parseRecheckReceipt,
      90000,
    );
    this.match(row, next);
    if (next.state !== "copied")
      throw new ApiError("invalid_server_response", 502);
    return next;
  }
  private match(a: Recheck, b: Recheck) {
    if (
      a.id !== b.id ||
      a.source_file_id !== b.source_file_id ||
      a.definition_hash !== b.definition_hash
    )
      throw new ApiError("invalid_server_response", 502);
  }
}
