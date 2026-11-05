import { Api } from "./api";
import { ApiError, uuid } from "./types";
import {
  asIncomingPage,
  asIncomingView,
  asEndpointPage,
  asEndpointRecord,
  asExchangeClosureResult,
  type ExchangeClosureCommand,
  bindingIsCurrent,
  type DirectoryContext,
  type EndpointRecord,
  type ExchangeIdentity,
  type IncomingExchange,
} from "./artifact-exchanges-types";

export class ExchangeReceiveApi {
  private identity: ExchangeIdentity;
  private prefix: string;
  private who: string;
  private directory: DirectoryContext;
  constructor(private api: Api) {
    const s = api.session;
    if (!s) throw new ApiError("unauthorized", 401);
    this.identity = {
      tenant: s.identity.tenant_id,
      partner: s.identity.partner_id,
      actor: s.identity.actor_id,
    };
    this.prefix = `/v1/tenants/${this.identity.tenant}/partners/${this.identity.partner}`;
    const permissions = s.identity.permissions;
    this.directory = {
      ...this.identity,
      authority_revision: s.identity.authority_revision,
      root_policy_digest: s.identity.root_policy_digest,
      manager:
        permissions.includes("admin") &&
        permissions.includes("accounts_manage"),
      can_receive: permissions.includes("read") && permissions.includes("list"),
      can_send: permissions.includes("read") && permissions.includes("deliver"),
    };
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
          s.identity.permissions,
        ])
      : "";
  }
  private current() {
    if (this.context() !== this.who) throw new ApiError("context_changed", 409);
  }
  isCurrent(): boolean {
    return this.context() === this.who;
  }
  async endpoints(after = "", signal?: AbortSignal) {
    this.current();
    if (after !== "" && !uuid(after))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchange-endpoints?${new URLSearchParams({ limit: "10", after })}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asEndpointPage(value, this.directory, after, 10);
      },
    );
    this.current();
    return result;
  }
  async endpoint(id: string, signal?: AbortSignal) {
    this.current();
    if (!uuid(id))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchange-endpoints/${id}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asEndpointRecord(value, this.directory, id);
      },
    );
    this.current();
    return result;
  }
  isReceiveEndpoint(record: EndpointRecord): boolean {
    this.current();
    const checked = asEndpointRecord(record, this.directory);
    return (
      checked.state === "active" &&
      this.directory.can_receive &&
      bindingIsCurrent(checked.definition.recipient, this.directory)
    );
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
  async decline(row: IncomingExchange, key: string, signal?: AbortSignal) {
    this.current();
    const validated = asIncomingView(row, this.identity);
    if (validated.state !== "offered" || !/^[A-Za-z0-9._:-]{1,128}$/.test(key))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const command: ExchangeClosureCommand = {
      schema_version: 1,
      exchange_id: validated.id,
      request_hash: validated.exchange.request_hash,
      operation: "decline",
    };
    const result = await this.api.request(
      `${this.prefix}/exchange-closures`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify(command),
        ...(signal ? { signal } : {}),
      },
      (value) => {
        this.current();
        return asExchangeClosureResult(value, command);
      },
    );
    this.current();
    return result;
  }
}
