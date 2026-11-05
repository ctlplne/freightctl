import { Api } from "./api";
import { ApiError, uuid, type Session } from "./types";
import { digestBytes } from "./crypto";
import {
  asOnwardRequest,
  asOnwardStart,
  asOnwardReview,
  asOnwardAcceptance,
  asOnwardObservation,
  asOnwardRecovery,
  readOnwardRecovery,
  type OnwardRequest,
  type OnwardReview,
  type OnwardStart,
  type OnwardRecovery,
} from "./artifact-onward-types";

export class ArtifactOnwardApi {
  private pinned: Session;
  private context: string;
  private prefix: string;
  constructor(private api: Api) {
    if (!api.session) throw new ApiError("unauthorized", 401);
    this.pinned = structuredClone(api.session);
    this.context = this.stamp();
    const i = this.pinned.identity;
    this.prefix = `/v1/tenants/${i.tenant_id}/partners/${i.partner_id}/onward`;
    this.current();
  }
  private stamp() {
    const s = this.api.session;
    return s ? JSON.stringify([s.identity, s.session.id]) : "";
  }
  private current() {
    if (this.context !== this.stamp())
      throw new ApiError("context_changed", 409);
    const i = this.pinned.identity;
    if (
      i.root_policy_digest !== digestBytes(new TextEncoder().encode("/")) ||
      !["workflow_execute", "read", "deliver"].every((p) =>
        i.permissions.includes(p),
      )
    )
      throw new ApiError("permission_denied", 403);
  }
  isCurrent() {
    return this.context === this.stamp();
  }
  private key(key: string) {
    if (!uuid(key)) throw new ApiError("invalid_onward_contract", 400);
  }
  private async post<T>(
    path: string,
    value: unknown,
    decode: (v: unknown) => T,
    key?: string,
    signal?: AbortSignal,
  ) {
    this.current();
    const body = JSON.stringify(value);
    if (new TextEncoder().encode(body).length > 32768)
      throw new ApiError("invalid_onward_contract", 400);
    const result = await this.api.request(
      `${this.prefix}/${path}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(key ? { "Idempotency-Key": key } : {}),
        },
        body,
        ...(signal ? { signal } : {}),
      },
      (v) => {
        this.current();
        return decode(v);
      },
    );
    this.current();
    return result;
  }
  async prepare(request: OnwardRequest, signal?: AbortSignal) {
    const pinned = asOnwardRequest(request);
    return this.post(
      "previews",
      pinned,
      (v) => asOnwardReview(v, pinned),
      undefined,
      signal,
    );
  }
  async refresh(saved: OnwardReview, signal?: AbortSignal) {
    const pinned = asOnwardReview(saved);
    const fresh = await this.prepare(pinned.request, signal);
    if (fresh.review_hash !== pinned.review_hash)
      throw new ApiError("context_changed", 409);
    return fresh;
  }
  async start(
    original: OnwardStart,
    key: string,
    expectedID?: string,
    signal?: AbortSignal,
  ) {
    this.key(key);
    const pinned = asOnwardStart(original);
    return this.post(
      "runs",
      pinned,
      (v) => asOnwardAcceptance(v, pinned, this.pinned, expectedID),
      key,
      signal,
    );
  }
  async receipt(
    original: OnwardStart,
    key: string,
    expectedID?: string,
    signal?: AbortSignal,
  ) {
    this.key(key);
    const pinned = asOnwardStart(original);
    const result = await this.post(
      "receipts",
      { start: pinned, receipt_key: key },
      (v) => asOnwardAcceptance(v, pinned, this.pinned, expectedID),
      undefined,
      signal,
    );
    if (!result.replayed) throw new ApiError("invalid_server_response", 502);
    return result;
  }
  async observe(
    original: OnwardStart,
    receiptKey: string,
    runID: string,
    signal?: AbortSignal,
  ) {
    this.key(receiptKey);
    this.key(runID);
    const pinned = asOnwardStart(original);
    return this.post(
      "status",
      { start: pinned, receipt_key: receiptKey, run_id: runID },
      (v) => asOnwardObservation(v, pinned, runID),
      undefined,
      signal,
    );
  }
  async work(
    original: OnwardStart,
    receiptKey: string,
    runID: string,
    workKey: string,
    signal?: AbortSignal,
  ) {
    this.key(receiptKey);
    this.key(runID);
    this.key(workKey);
    const pinned = asOnwardStart(original);
    return this.post(
      "work",
      { start: pinned, receipt_key: receiptKey, run_id: runID },
      (v) => asOnwardObservation(v, pinned, runID, true),
      workKey,
      signal,
    );
  }
  recovery(value: unknown, origin: string): OnwardRecovery {
    this.current();
    return asOnwardRecovery(value, this.pinned, origin);
  }
  readRecovery(text: string, origin: string): OnwardRecovery {
    this.current();
    return readOnwardRecovery(text, this.pinned, origin);
  }
}
