export interface Identity {
  tenant_id: string;
  partner_id: string;
  actor_id: string;
  permissions: string[];
  authority_revision: number;
  root_policy_digest: string;
  ssh_username: string;
}
export interface Session {
  identity: Identity;
  session: { id: string; expires_at: string; state: string };
  csrf_token: string;
  limits: {
    max_file_bytes: number;
    min_chunk_bytes: number;
    max_chunk_bytes: number;
    max_upload_chunks: number;
  };
}
export interface Upload {
  id: string;
  path: string;
  expected_size: number;
  expected_sha256: string;
  committed_offset: number;
  chunk_count: number;
  state: string;
  revision: number;
  file_id?: string;
  acceptance?: string;
}
export interface UploadPage {
  uploads: Upload[];
  next?: string;
  blocked_by_access_change: boolean;
}
export interface UploadResult {
  upload: Upload;
  file?: { id: string; sha256: string; size_bytes: number; policy: string };
  acceptance?: string;
}
export interface Entry {
  id: string;
  path: string;
  kind: string;
  size_bytes: number;
  revision: number;
  file_id?: string;
}
export interface EntryPage {
  entries: Entry[];
  next?: string;
}
export interface CheckSummary {
  file_id: string;
  state: string;
  revision: number;
  code: string;
  path: string;
}
export interface CheckPage {
  checks: CheckSummary[];
  next?: string;
}
export interface CheckView {
  current: boolean;
  signatureAttached: boolean;
  requirements: { signature: boolean; scanner: boolean } | null;
  check: {
    file_id: string;
    state: string;
    revision: number;
    attempts: number;
    code: string;
    policy_hash: string;
    report_hash: string;
    source_sha256: string;
    path: string;
    report: Record<string, unknown> | null;
  };
}

export class ApiError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
  ) {
    super(code);
  }
}
export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new ApiError("invalid_server_response", 502);
  return value as Record<string, unknown>;
}
function text(o: Record<string, unknown>, key: string, max = 1024): string {
  const value = o[key];
  if (typeof value !== "string" || value.length > max)
    throw new ApiError("invalid_server_response", 502);
  return value;
}
function number(o: Record<string, unknown>, key: string, max: number): number {
  const value = o[key];
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > max
  )
    throw new ApiError("invalid_server_response", 502);
  return value;
}
function array(
  o: Record<string, unknown>,
  key: string,
  max: number,
): unknown[] {
  const value = o[key];
  if (!Array.isArray(value) || value.length > max)
    throw new ApiError("invalid_server_response", 502);
  return value as unknown[];
}
function bool(o: Record<string, unknown>, key: string): boolean {
  const value = o[key];
  if (typeof value !== "boolean")
    throw new ApiError("invalid_server_response", 502);
  return value;
}
export function uuid(value: string): boolean {
  return /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value);
}
function id(o: Record<string, unknown>, key: string): string {
  const value = text(o, key, 36);
  if (!uuid(value)) throw new ApiError("invalid_server_response", 502);
  return value;
}
function hash(o: Record<string, unknown>, key: string): string {
  const value = text(o, key, 64);
  if (!/^[0-9a-f]{64}$/.test(value))
    throw new ApiError("invalid_server_response", 502);
  return value;
}
export function asSession(value: unknown): Session {
  const o = object(value),
    who = object(o.identity),
    limits = object(o.limits),
    session = object(o.session);
  const expires = text(session, "expires_at", 64);
  if (!Number.isFinite(Date.parse(expires)))
    throw new ApiError("invalid_server_response", 502);
  return {
    identity: {
      tenant_id: id(who, "tenant_id"),
      partner_id: id(who, "partner_id"),
      actor_id: id(who, "actor_id"),
      permissions: array(who, "permissions", 64).map((v) => {
        if (typeof v !== "string" || v.length > 64)
          throw new ApiError("invalid_server_response", 502);
        return v;
      }),
      authority_revision: number(
        who,
        "authority_revision",
        Number.MAX_SAFE_INTEGER,
      ),
      root_policy_digest: hash(who, "root_policy_digest"),
      ssh_username: text(who, "ssh_username", 128),
    },
    session: {
      id: id(session, "id"),
      expires_at: expires,
      state: text(session, "state", 16),
    },
    csrf_token: hash(o, "csrf_token"),
    limits: {
      max_file_bytes: number(limits, "max_file_bytes", 1073741824),
      min_chunk_bytes: number(limits, "min_chunk_bytes", 8388608),
      max_chunk_bytes: number(limits, "max_chunk_bytes", 8388608),
      max_upload_chunks: number(limits, "max_upload_chunks", 4096),
    },
  };
}
export function asUpload(value: unknown): Upload {
  const o = object(value);
  const size = number(o, "expected_size", 1073741824);
  const u: Upload = {
    id: id(o, "id"),
    path: text(o, "path"),
    expected_size: size,
    expected_sha256: hash(o, "expected_sha256"),
    committed_offset: number(o, "committed_offset", size),
    chunk_count: number(o, "chunk_count", 4096),
    state: text(o, "state", 32),
    revision: number(o, "revision", Number.MAX_SAFE_INTEGER),
  };
  if (o.file_id !== undefined && o.file_id !== "") u.file_id = id(o, "file_id");
  if (o.acceptance !== undefined) u.acceptance = text(o, "acceptance", 128);
  return u;
}
export function asUploadPage(value: unknown): UploadPage {
  const o = object(value);
  const page: UploadPage = {
    uploads: array(o, "uploads", 100).map(asUpload),
    blocked_by_access_change: bool(o, "blocked_by_access_change"),
  };
  if (o.next !== undefined) page.next = id(o, "next");
  return page;
}
export function asUploadResult(value: unknown): UploadResult {
  const o = object(value),
    result: UploadResult = { upload: asUpload(o.upload) };
  if (o.acceptance !== undefined)
    result.acceptance = text(o, "acceptance", 128);
  if (o.file !== undefined) {
    const f = object(o.file);
    result.file = {
      id: id(f, "id"),
      sha256: hash(f, "sha256"),
      size_bytes: number(f, "size_bytes", 1073741824),
      policy: text(f, "policy", 128),
    };
  }
  return result;
}
export function asEntryPage(value: unknown): EntryPage {
  const o = object(value);
  const page: EntryPage = {
    entries: array(o, "entries", 100).map((value) => {
      const e = object(value);
      const result: Entry = {
        id: id(e, "id"),
        path: text(e, "path"),
        kind: text(e, "kind", 16),
        size_bytes: number(e, "size_bytes", 1073741824),
        revision: number(e, "revision", Number.MAX_SAFE_INTEGER),
      };
      if (e.file_id !== undefined && e.file_id !== "")
        result.file_id = id(e, "file_id");
      return result;
    }),
  };
  if (o.next !== undefined) page.next = text(o, "next");
  return page;
}
export function asCheckPage(value: unknown): CheckPage {
  const o = object(value);
  const page: CheckPage = {
    checks: array(o, "checks", 100).map((value) => {
      const c = object(value);
      return {
        file_id: id(c, "file_id"),
        state: text(c, "state", 32),
        revision: number(c, "revision", Number.MAX_SAFE_INTEGER),
        code: text(c, "code", 128),
        path: c.path === undefined ? "" : text(c, "path"),
      };
    }),
  };
  if (o.next !== undefined) page.next = id(o, "next");
  return page;
}
export function asCheckView(value: unknown): CheckView {
  const o = object(value),
    c = object(o.check),
    b = object(c.binding),
    file = object(b.file);
  const target = b.target === null ? null : object(b.target);
  const reportHash = text(c, "report_hash", 64);
  if (reportHash !== "" && !/^[0-9a-f]{64}$/.test(reportHash))
    throw new ApiError("invalid_server_response", 502);
  const req = o.requirements === undefined ? null : object(o.requirements);
  return {
    current: bool(o, "current"),
    signatureAttached: o.signature !== undefined && o.signature !== null,
    requirements: req
      ? {
          signature: bool(req, "signature_required"),
          scanner: bool(req, "scanner_required"),
        }
      : null,
    check: {
      file_id: id(c, "file_id"),
      state: text(c, "state", 32),
      revision: number(c, "revision", Number.MAX_SAFE_INTEGER),
      attempts: number(c, "attempts", 3),
      code: text(c, "code", 128),
      policy_hash: hash(c, "policy_hash"),
      report_hash: reportHash,
      source_sha256: hash(file, "sha256"),
      path: target === null ? "" : text(target, "path"),
      report: c.report === null ? null : object(c.report),
    },
  };
}

export interface Account {
  id: string;
  label: string;
  permissions: string[];
  namespace_root: string;
  expires_at: string | null;
  revision: number;
  authority_revision: number;
  state: string;
  changed_event_id: string | null;
  observed_at: string;
}
export interface AccountCommand {
  operation: "create" | "update" | "rotate" | "revoke";
  account_id: string;
  expected_revision: number;
  credential_sha256?: string;
  policy?: Pick<
    Account,
    "label" | "permissions" | "namespace_root" | "expires_at"
  >;
}
export function asAccount(value: unknown): Account {
  const o = object(value);
  const state = text(o, "state", 16);
  const expiry = o.expires_at;
  const event = o.changed_event_id;
  const observed = text(o, "observed_at", 64);
  if (
    !["active", "expired", "revoked"].includes(state) ||
    !Number.isFinite(Date.parse(observed)) ||
    (expiry !== null &&
      (typeof expiry !== "string" || !Number.isFinite(Date.parse(expiry)))) ||
    (event !== null && (typeof event !== "string" || !uuid(event)))
  )
    throw new ApiError("invalid_server_response", 502);
  return {
    id: id(o, "id"),
    label: text(o, "label", 128),
    permissions: array(o, "permissions", 21).map((v) => {
      if (typeof v !== "string" || v.length > 64)
        throw new ApiError("invalid_server_response", 502);
      return v;
    }),
    namespace_root: text(o, "namespace_root", 4096),
    expires_at: expiry as string | null,
    revision: number(o, "revision", Number.MAX_SAFE_INTEGER),
    authority_revision: number(
      o,
      "authority_revision",
      Number.MAX_SAFE_INTEGER,
    ),
    state,
    changed_event_id: event as string | null,
    observed_at: observed,
  };
}
export function asAccountPage(value: unknown): {
  accounts: Account[];
  next?: string;
} {
  const o = object(value);
  return {
    accounts: array(o, "accounts", 100).map(asAccount),
    ...(o.next === undefined ? {} : { next: id(o, "next") }),
  };
}
