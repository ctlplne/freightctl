import { Api } from "./api";
import { ApiError, uuid } from "./types";
import {
  asIncomingPage,
  asIncomingView,
  type ExchangeIdentity,
  type IncomingExchange,
} from "./artifact-exchanges-types";

export class ExchangeReceiveApi {
  private identity: ExchangeIdentity;
  private prefix: string;
  private who: string;
  constructor(private api: Api) {
    const s = api.session;
    if (!s) throw new ApiError("unauthorized", 401);
    this.identity = {
      tenant: s.identity.tenant_id,
      partner: s.identity.partner_id,
      actor: s.identity.actor_id,
    };
    this.prefix = `/v1/tenants/${this.identity.tenant}/partners/${this.identity.partner}`;
    this.who = this.context();
  }
  private context(): string {
    const s = this.api.session;
    return s
      ? JSON.stringify([
          s.identity.tenant_id,
          s.identity.partner_id,
          s.identity.actor_id,
          s.identity.authority_revision,
          s.identity.root_policy_digest,
          s.session.id,
        ])
      : "";
  }
  private current() {
    if (this.context() !== this.who) throw new ApiError("context_changed", 409);
  }
  isCurrent(): boolean {
    return this.context() === this.who;
  }
  async incoming(endpoint: string, after = "", signal?: AbortSignal) {
    this.current();
    if (!uuid(endpoint) || (after !== "" && !uuid(after)))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchange-endpoints/${endpoint}/incoming?${new URLSearchParams({ limit: "20", after })}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asIncomingPage(value, {
          ...this.identity,
          endpoint,
          after,
          limit: 20,
        });
      },
    );
    this.current();
    return result;
  }
  async inspect(id: string, endpoint: string, signal?: AbortSignal) {
    this.current();
    if (!uuid(id) || !uuid(endpoint))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchanges/${id}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asIncomingView(value, { ...this.identity, id, endpoint });
      },
    );
    this.current();
    return result;
  }
  downloadPath(row: IncomingExchange): string {
    this.current();
    const validated = asIncomingView(row, this.identity);
    if (validated.state !== "offered") throw new ApiError("artifact_held", 409);
    // The browser's native attachment path streams bytes. No URL, name,
    // execution instruction or secret is taken from an artifact or its payload.
    return `${this.prefix}/exchanges/${validated.id}/file`;
  }
}
