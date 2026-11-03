import { operationKey, digestBytes } from "./crypto";
import {
  ApiError,
  asSession,
  asUpload,
  asUploadPage,
  asUploadResult,
  asEntryPage,
  asCheckPage,
  asCheckView,
  object,
  uuid,
  type Session,
  type Upload,
  type UploadResult,
  type CheckView,
  type RecoveryDecision,
} from "./types";

export class Api {
  session: Session | null = null;
  private controllers = new Set<AbortController>();
  private loginAttempt: {
    tenant: string;
    partner: string;
    fingerprint: string;
    key: string;
  } | null = null;
  abortAll(): void {
    for (const c of this.controllers) c.abort();
    this.controllers.clear();
  }
  clear(): void {
    this.abortAll();
    this.session = null;
    this.loginAttempt = null;
  }
  get prefix(): string {
    if (!this.session) throw new ApiError("unauthorized", 401);
    return `/v1/tenants/${this.session.identity.tenant_id}/partners/${this.session.identity.partner_id}`;
  }
  async request<T>(
    path: string,
    options: RequestInit,
    decode: (value: unknown) => T,
    timeoutMs = 30000,
  ): Promise<T> {
    if (!path.startsWith("/v1/") || path.startsWith("//"))
      throw new ApiError("invalid_request", 400);
    const controller = new AbortController();
    this.controllers.add(controller);
    const abort = () => controller.abort();
    const external = options.signal;
    if (external?.aborted) controller.abort();
    else external?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, timeoutMs);
    try {
      const headers = new Headers(options.headers);
      if (
        options.method &&
        !["GET", "HEAD"].includes(options.method) &&
        this.session
      )
        headers.set("X-CSRF-Token", this.session.csrf_token);
      const response = await fetch(path, {
        ...options,
        headers,
        signal: controller.signal,
        credentials: "same-origin",
        redirect: "error",
        cache: "no-store",
      });
      // JSON responses are bounded separately from file downloads, which use
      // the native browser download path and never buffer payloads in JS.
      if (response.status === 204 && response.ok) return decode(null);
      const reader = response.body?.getReader();
      if (!reader) throw new ApiError("invalid_server_response", 502);
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      try {
        for (;;) {
          const item = await reader.read();
          if (item.done) break;
          bytes += item.value.byteLength;
          if (bytes > 262144)
            throw new ApiError("response_budget_exceeded", 502);
          chunks.push(item.value);
        }
      } finally {
        await reader.cancel();
        reader.releaseLock();
      }
      const all = new Uint8Array(bytes);
      let offset = 0;
      for (const c of chunks) {
        all.set(c, offset);
        offset += c.length;
      }
      let value: unknown;
      try {
        value = JSON.parse(new TextDecoder().decode(all)) as unknown;
      } catch {
        throw new ApiError("invalid_server_response", 502);
      } finally {
        all.fill(0);
        for (const c of chunks) c.fill(0);
      }
      if (!response.ok) {
        const code =
          typeof value === "object" &&
          value !== null &&
          "error" in value &&
          typeof value.error === "string" &&
          /^[a-z_]{1,80}$/.test(value.error)
            ? value.error
            : "operation_unavailable";
        throw new ApiError(code, response.status);
      }
      return decode(value);
    } catch (error) {
      if (controller.signal.aborted && !external?.aborted)
        throw new ApiError("connection_timeout", 503);
      throw error;
    } finally {
      clearTimeout(timer);
      external?.removeEventListener("abort", abort);
      this.controllers.delete(controller);
    }
  }
  async restore(signal?: AbortSignal): Promise<Session> {
    const s = await this.request(
      "/v1/browser/session",
      signal ? { signal } : {},
      asSession,
    );
    this.session = s;
    return s;
  }
  async login(
    tenant: string,
    partner: string,
    file: File,
    signal: AbortSignal,
  ): Promise<Session> {
    if (!uuid(tenant) || !uuid(partner) || file.size > 128 || file.size < 64)
      throw new ApiError("invalid_credential_file", 400);
    const bytes = new Uint8Array(await file.arrayBuffer());
    let token = "";
    try {
      let end = bytes.length;
      while (end > 0 && [10, 13, 32].includes(bytes[end - 1] ?? 0)) end--;
      if (
        end !== 64 ||
        !bytes
          .subarray(0, 64)
          .every((b) => (b >= 48 && b <= 57) || (b >= 97 && b <= 102))
      )
        throw new ApiError("invalid_credential_file", 400);
      const fingerprint = digestBytes(bytes.subarray(0, 64));
      if (
        !this.loginAttempt ||
        this.loginAttempt.tenant !== tenant ||
        this.loginAttempt.partner !== partner ||
        this.loginAttempt.fingerprint !== fingerprint
      )
        this.loginAttempt = {
          tenant,
          partner,
          fingerprint,
          key: operationKey(),
        };
      token = new TextDecoder().decode(bytes.subarray(0, 64));
      const s = await this.request(
        `/v1/tenants/${tenant}/partners/${partner}/browser-session`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Idempotency-Key": this.loginAttempt.key,
          },
          signal,
        },
        asSession,
      );
      if (s.session.state !== "active") throw new ApiError("unauthorized", 401);
      this.session = s;
      this.loginAttempt = null;
      return s;
    } finally {
      bytes.fill(0);
      token = "";
    }
  }
  async logout(): Promise<void> {
    await this.request(
      "/v1/browser/logout",
      { method: "POST", headers: { "Idempotency-Key": operationKey() } },
      () => undefined,
    );
    this.clear();
  }
  upload(id: string, signal?: AbortSignal): Promise<Upload> {
    return this.request(
      `${this.prefix}/uploads/${id}`,
      signal ? { signal } : {},
      (value) => asUpload(value, { id }),
    );
  }
  uploads(after = "", signal?: AbortSignal) {
    return this.request(
      `${this.prefix}/uploads?${new URLSearchParams({ limit: "50", after })}`,
      signal ? { signal } : {},
      asUploadPage,
    );
  }
  entries(path: string, after = "", signal?: AbortSignal) {
    return this.request(
      `${this.prefix}/namespace/entries?${new URLSearchParams({ path, limit: "100", after })}`,
      signal ? { signal } : {},
      asEntryPage,
    );
  }
  createUpload(
    path: string,
    size: number,
    sha256: string,
    key: string,
    signal: AbortSignal,
  ): Promise<UploadResult> {
    return this.request(
      `${this.prefix}/uploads`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({
          path: path.normalize("NFC"),
          expected_size: size,
          expected_sha256: sha256,
        }),
        signal,
      },
      (value) => {
        const result = asUploadResult(value);
        asUpload(result.upload, {
          path: path.normalize("NFC"),
          expected_size: size,
          expected_sha256: sha256,
        });
        return result;
      },
    );
  }
  append(
    upload: Upload,
    bytes: Uint8Array,
    hash: string,
    signal: AbortSignal,
  ): Promise<UploadResult> {
    return this.request(
      `${this.prefix}/uploads/${upload.id}`,
      {
        method: "PATCH",
        headers: {
          "Idempotency-Key": `browser-chunk-${upload.id}-${upload.committed_offset}`,
          "Upload-Offset": String(upload.committed_offset),
          "X-File-Size": String(bytes.length),
          "X-Content-SHA256": hash,
        },
        body: bytes.buffer as ArrayBuffer,
        signal,
      },
      asUploadResult,
    );
  }
  complete(id: string, signal: AbortSignal): Promise<UploadResult> {
    return this.request(
      `${this.prefix}/uploads/${id}/complete`,
      {
        method: "POST",
        headers: { "Idempotency-Key": `browser-complete-${id}` },
        signal,
      },
      asUploadResult,
    );
  }
  abortUpload(id: string): Promise<UploadResult> {
    return this.request(
      `${this.prefix}/uploads/${id}/abort`,
      { method: "POST", headers: { "Idempotency-Key": `browser-abort-${id}` } },
      asUploadResult,
    );
  }
  checks(after = "", signal?: AbortSignal) {
    return this.request(
      `${this.prefix}/checks?${new URLSearchParams({ limit: "50", after })}`,
      signal ? { signal } : {},
      asCheckPage,
    );
  }
  check(id: string, signal?: AbortSignal) {
    return this.request(
      `${this.prefix}/checks/${id}`,
      signal ? { signal } : {},
      asCheckView,
    );
  }
  private checkCommandKey(
    operation: "run" | "release",
    view: CheckView,
  ): string {
    if (!this.session) throw new ApiError("unauthorized", 401);
    const who = this.session.identity,
      c = view.check;
    // This is an operation identity, not a credential or authorization grant.
    // The same observed revision keeps the same identity after response loss;
    // a newly reviewed revision produces a different command identity.
    const meaning = new TextEncoder().encode(
      JSON.stringify([
        operation,
        who.tenant_id,
        who.partner_id,
        who.actor_id,
        c.file_id,
        c.revision,
        c.source_sha256,
        c.policy_hash,
        c.report_hash,
      ]),
    );
    return `browser-check-${operation}-${digestBytes(meaning)}`;
  }
  async runCheck(view: CheckView): Promise<CheckView> {
    const id = view.check.file_id,
      key = this.checkCommandKey("run", view);
    await this.request(
      `${this.prefix}/checks/${id}/run`,
      { method: "POST", headers: { "Idempotency-Key": key } },
      object,
      90000,
    );
    return this.check(id);
  }
  async recoverCheck(
    view: CheckView,
    decision: RecoveryDecision,
  ): Promise<CheckView> {
    if (!this.session) throw new ApiError("unauthorized", 401);
    const who = this.session.identity;
    const key =
      "browser-check-recover-" +
      digestBytes(
        new TextEncoder().encode(
          JSON.stringify([
            who.tenant_id,
            who.partner_id,
            who.actor_id,
            view.check.file_id,
            decision.expected_revision,
            decision.expected_worker_id,
            decision.expected_lease_until,
            decision.sha256,
            decision.policy_hash,
          ]),
        ),
      );
    await this.request(
      `${this.prefix}/checks/${view.check.file_id}/recover`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify(decision),
      },
      object,
      90000,
    );
    return this.check(view.check.file_id);
  }
  async release(view: CheckView): Promise<CheckView> {
    const key = this.checkCommandKey("release", view);
    const c = view.check;
    await this.request(
      `${this.prefix}/checks/${c.file_id}/release`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({
          sha256: c.source_sha256,
          policy_hash: c.policy_hash,
          report_hash: c.report_hash,
          expected_revision: c.revision,
        }),
      },
      object,
    );
    return this.check(c.file_id);
  }
  async attachSignature(view: CheckView, file: File): Promise<CheckView> {
    if (file.size < 1 || file.size > 32768)
      throw new ApiError("invalid_signature_file", 400);
    const data = new Uint8Array(await file.arrayBuffer());
    const c = view.check;
    try {
      await this.request(
        `${this.prefix}/checks/${c.file_id}/signature`,
        {
          method: "PUT",
          headers: {
            "Idempotency-Key": `browser-signature-${c.file_id}-${digestBytes(data)}`,
            "If-Check-Revision": String(c.revision),
            "X-Data-SHA256": c.source_sha256,
            "X-Policy-Hash": c.policy_hash,
          },
          body: data.buffer as ArrayBuffer,
        },
        object,
      );
      return this.check(c.file_id);
    } catch (error) {
      if (error instanceof ApiError && error.status === 400)
        throw new ApiError("invalid_signature_file", 400);
      throw error;
    } finally {
      data.fill(0);
    }
  }
}
