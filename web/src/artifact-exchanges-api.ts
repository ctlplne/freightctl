import { Api } from "./api";
import { ApiError, asAccountPage, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  asExchangeEvidence,
  evidenceExpectation,
  type EvidenceDirection,
  type EvidenceExpectation,
} from "./artifact-evidence-types";
import {
  asCollectedExchangeSource,
  type CollectedSourceExpectation,
} from "./collection-exchange-source-types";
import {
  decodeOfferRecovery,
  encodeOfferRecovery,
  type OfferReviewInput,
} from "./artifact-recovery";
import {
  asIncomingPage,
  asIncomingView,
  asEndpointPage,
  asEndpointRecord,
  asExchangeClosureResult,
  asExchangeArtifact,
  asExchangeRequest,
  asExchangeOfferResult,
  asOutgoingExchange,
  asOutgoingPage,
  endpointCommandBytes,
  asEndpointCommandResult,
  type EndpointCommand,
  type ExchangeRequest,
  type ExchangeSourceExpectation,
  type ArtifactExchange,
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
  private canList: boolean;
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
    this.canList = permissions.includes("list");
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
  async evidence(
    id: string,
    direction: EvidenceDirection,
    expected?: EvidenceExpectation,
    signal?: AbortSignal,
  ) {
    const permitted = () => {
      this.current();
      if (!uuid(id) || !["incoming", "outgoing"].includes(direction))
        throw new ApiError("invalid_artifact_exchange_contract", 400);
      if (
        !(direction === "incoming"
          ? this.directory.can_receive
          : this.directory.can_send)
      )
        throw new ApiError("permission_denied", 403);
    };
    permitted();
    const pinned = expected ? evidenceExpectation(expected) : undefined;
    if (pinned && !/^[0-9a-f]{64}$/.test(pinned.request_hash))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchange-traces/previews`,
      {
        method: "POST",
        body: JSON.stringify({ exchange_id: id, direction }),
        ...(signal ? { signal } : {}),
      },
      (value) => {
        permitted();
        return asExchangeEvidence(value, this.identity, id, direction, pinned);
      },
    );
    permitted();
    return result;
  }
  recoveryBytes(origin: string, review: OfferReviewInput): Uint8Array {
    this.current();
    return encodeOfferRecovery(review, this.directory, origin);
  }
  readRecovery(origin: string, text: string) {
    this.current();
    return decodeOfferRecovery(text, this.directory, origin);
  }
  private requireEndpointManager() {
    this.current();
    if (
      !this.directory.manager ||
      this.directory.root_policy_digest !==
        digestBytes(new TextEncoder().encode("/"))
    )
      throw new ApiError("permission_denied", 403);
  }
  async endpointAccounts(after = "", signal?: AbortSignal) {
    this.requireEndpointManager();
    if (after !== "" && !uuid(after))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/accounts?${new URLSearchParams({ limit: "50", after })}`,
      signal ? { signal } : {},
      (value) => {
        this.requireEndpointManager();
        const page = asAccountPage(value);
        if (
          page.accounts.length > 50 ||
          page.accounts.some(
            (a, i) =>
              a.id <= after || (i > 0 && a.id <= page.accounts[i - 1]!.id),
          ) ||
          (page.next &&
            (page.accounts.length !== 50 ||
              page.next !== page.accounts.at(-1)?.id))
        )
          throw new ApiError("invalid_server_response", 502);
        return page;
      },
    );
    this.requireEndpointManager();
    return result;
  }
  async endpointCommand(
    command: EndpointCommand,
    key: string,
    previous?: EndpointRecord,
    signal?: AbortSignal,
  ) {
    this.requireEndpointManager();
    if (!uuid(key))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    // Copy the exact review before awaiting transport. Caller mutation cannot
    // change either the sent body or the receipt's expected meaning.
    const body = new TextDecoder().decode(
      endpointCommandBytes(command, this.directory),
    );
    const pinned = JSON.parse(body) as EndpointCommand;
    const base = previous
      ? asEndpointRecord(previous, this.directory)
      : undefined;
    if (
      pinned.operation === "revoke" &&
      (!base ||
        base.id !== pinned.endpoint_id ||
        base.revision !== pinned.expected_revision ||
        base.state !== "active")
    )
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchange-endpoints/commands`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body,
        ...(signal ? { signal } : {}),
      },
      (value) => {
        this.requireEndpointManager();
        return asEndpointCommandResult(value, pinned, this.directory, base);
      },
    );
    this.requireEndpointManager();
    return result;
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
  isSendEndpoint(record: EndpointRecord): boolean {
    this.current();
    const checked = asEndpointRecord(record, this.directory);
    return (
      checked.state === "active" &&
      this.directory.can_send &&
      checked.definition.senders.some((s) =>
        bindingIsCurrent(s, this.directory),
      )
    );
  }
  async source(
    id: string,
    signal?: AbortSignal,
    expected?: ExchangeSourceExpectation,
  ) {
    this.current();
    const pinned = expected
      ? {
          file_revision_id: expected.file_revision_id,
          size_bytes: expected.size_bytes,
          sha256: expected.sha256,
        }
      : undefined;
    if (!uuid(id))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchange-sources/${id}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        const source = asExchangeArtifact(value, id);
        if (
          pinned &&
          (pinned.file_revision_id !== id ||
            pinned.size_bytes !== source.size_bytes ||
            pinned.sha256 !== source.sha256)
        )
          throw new ApiError("revision_conflict", 409);
        return source;
      },
    );
    this.current();
    return result;
  }
  async collectedSource(
    expected: CollectedSourceExpectation,
    signal?: AbortSignal,
  ) {
    this.current();
    if (!this.directory.can_send) throw new ApiError("permission_denied", 403);
    const pinned = structuredClone(expected);
    if (!uuid(pinned.origin.collection_id) || !uuid(pinned.origin.input_id))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/workflow-collections/${pinned.origin.collection_id}/inputs/${pinned.origin.input_id}/exchange-source`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asCollectedExchangeSource(value, pinned);
      },
    );
    this.current();
    return result;
  }
  async outgoing(after = "", signal?: AbortSignal) {
    this.current();
    if (!this.directory.can_send || !this.canList)
      throw new ApiError("permission_denied", 403);
    if (after !== "" && !uuid(after))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/outgoing-exchanges?${new URLSearchParams({ limit: "20", after })}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asOutgoingPage(value, this.identity, after, 20);
      },
    );
    this.current();
    return result;
  }
  async outgoingExchange(id: string, signal?: AbortSignal) {
    this.current();
    if (!this.directory.can_send) throw new ApiError("permission_denied", 403);
    if (!uuid(id))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/outgoing-exchanges/${id}`,
      signal ? { signal } : {},
      (value) => {
        this.current();
        return asOutgoingExchange(value, this.identity, id);
      },
    );
    this.current();
    return result;
  }
  async offer(
    request: ExchangeRequest,
    endpoint: EndpointRecord,
    key: string,
    signal?: AbortSignal,
  ) {
    this.current();
    const normalized = asExchangeRequest(request);
    if (
      !this.isSendEndpoint(endpoint) ||
      normalized.endpoint.id !== endpoint.id ||
      normalized.endpoint.revision !== endpoint.revision ||
      normalized.endpoint.hash !== endpoint.definition_hash ||
      !/^[A-Za-z0-9._:-]{1,128}$/.test(key)
    )
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/exchanges`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify(normalized),
        ...(signal ? { signal } : {}),
      },
      (value) => {
        this.current();
        return asExchangeOfferResult(
          value,
          normalized,
          this.identity,
          endpoint.definition.recipient.actor_id,
        );
      },
    );
    this.current();
    return result;
  }
  async cancelOffer(
    exchange: ArtifactExchange,
    key: string,
    signal?: AbortSignal,
  ) {
    this.current();
    const checked = asExchangeOfferResult(
      { exchange, replayed: false },
      exchange.request,
      this.identity,
      exchange.recipient_actor_id,
    ).exchange;
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(key))
      throw new ApiError("invalid_artifact_exchange_contract", 400);
    const command: ExchangeClosureCommand = {
      schema_version: 1,
      exchange_id: checked.id,
      request_hash: checked.request_hash,
      operation: "cancel",
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
