export interface Identity {
  tenant_administration: boolean;
  tenant_id: string;
  partner_id: string;
  actor_id: string;
  permissions: string[];
  authority_revision: number;
  root_policy_digest: string;
  ssh_username: string;
}

export interface PartnerCommand {
  expected_authority_revision: number;
  expected_tenant_revision: number;
  partner_id: string;
  admin_id: string;
  label: string;
  admin_label: string;
  credential_sha256: string;
  permissions: string[];
}
export interface Partner {
  id: string;
  label: string;
  admin_id?: string;
  admin_label?: string;
  namespace_root: string;
  permissions: string[];
  event_id?: string;
  registered_at: string | null;
}
export function asPartner(value: unknown): Partner {
  const o = object(value),
    permissions = array(o, "permissions", 21).map((v) => {
      if (typeof v !== "string" || v.length > 64)
        throw new ApiError("invalid_server_response", 502);
      return v;
    });
  const when = o.registered_at === null ? null : text(o, "registered_at", 64);
  if (when !== null && !Number.isFinite(Date.parse(when)))
    throw new ApiError("invalid_server_response", 502);
  const root = text(o, "namespace_root", 1);
  if (root !== "/") throw new ApiError("invalid_server_response", 502);
  return {
    id: id(o, "id"),
    label: text(o, "label", 128),
    namespace_root: root,
    permissions,
    registered_at: when,
    ...(o.admin_id !== undefined
      ? {
          admin_id: id(o, "admin_id"),
          admin_label: text(o, "admin_label", 128),
        }
      : {}),
    ...(o.event_id !== undefined ? { event_id: id(o, "event_id") } : {}),
  };
}
export function asPartnerPage(value: unknown): {
  partners: Partner[];
  authority_revision: number;
  tenant_administration_revision: number;
  next?: string;
} {
  const o = object(value);
  return {
    partners: array(o, "partners", 100).map(asPartner),
    authority_revision: number(
      o,
      "authority_revision",
      Number.MAX_SAFE_INTEGER,
    ),
    tenant_administration_revision: number(
      o,
      "tenant_administration_revision",
      Number.MAX_SAFE_INTEGER,
    ),
    ...(o.next !== undefined ? { next: id(o, "next") } : {}),
  };
}
export function asPartnerResult(
  value: unknown,
  command: PartnerCommand,
): Partner {
  const o = object(value),
    p = asPartner(o.partner);
  bool(o, "replayed");
  if (
    p.id !== command.partner_id ||
    p.admin_id !== command.admin_id ||
    p.label !== command.label ||
    p.admin_label !== command.admin_label ||
    !p.event_id ||
    !p.registered_at ||
    JSON.stringify(p.permissions) !== JSON.stringify(command.permissions)
  )
    throw new ApiError("invalid_server_response", 502);
  return p;
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
export interface SignatureEvidence {
  primary: string;
  signer: string;
  signatureSHA256: string;
  keyID: string;
  keyVersion: number;
  keyHash: string;
  createdAt: string;
  verifiedAt: string;
  validUntil: string | null;
  hashAlgorithm: string;
  signatureVersion: number;
}
export interface RecoveryDecision {
  expected_revision: number;
  expected_worker_id: string;
  expected_lease_until: string;
  sha256: string;
  policy_hash: string;
}
export interface CheckRecovery {
  observedAt: string;
  eligible: boolean;
  code:
    | "ready"
    | "lease_active"
    | "attempt_budget_exhausted"
    | "authority_or_policy_changed"
    | "permission_denied";
  decision: RecoveryDecision;
}
export interface CheckView {
  recovery: CheckRecovery | null;
  signatureProof: SignatureEvidence | null;
  validation: {
    engine: string;
    code: string;
    rows: number;
    bytes: number;
  } | null;
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
// A local workspace reference supplies selectors only. Never copy endpoints,
// credentials, permissions or commands from it into the authenticated client.
export function asWorkspaceReference(value: unknown): {
  tenant_id: string;
  partner_id: string;
} {
  const o = object(value);
  if (o.schema_version !== 1)
    throw new ApiError("invalid_workspace_reference", 400);
  return { tenant_id: id(o, "tenant_id"), partner_id: id(o, "partner_id") };
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
      tenant_administration:
        who.tenant_administration === undefined
          ? false
          : bool(who, "tenant_administration"),
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
// Compare server timestamp instants at PostgreSQL precision across UTC offsets.
// The browser clock never grants permission to replace a worker reservation.
function timestampInstant(value: string): bigint {
  const match =
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  if (!match?.[1] || !match[3])
    throw new ApiError("invalid_server_response", 502);
  const base = Date.parse(match[1] + "Z"),
    zone = match[3];
  if (
    !Number.isFinite(base) ||
    new Date(base).toISOString().slice(0, 19) !== match[1]
  )
    throw new ApiError("invalid_server_response", 502);
  let offset = 0;
  if (zone !== "Z") {
    const hours = Number(zone.slice(1, 3)),
      minutes = Number(zone.slice(4, 6));
    if (hours > 23 || minutes > 59)
      throw new ApiError("invalid_server_response", 502);
    offset = (hours * 60 + minutes) * (zone[0] === "-" ? -1 : 1);
  }
  return (
    BigInt(base - offset * 60000) * 1000000n +
    BigInt((match[2] ?? "").padEnd(9, "0"))
  );
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
  const rawReport = c.report === null ? null : object(c.report);
  // PostgreSQL stores {} before a check has produced its first report.
  const report =
    rawReport && reportHash === "" && Object.keys(rawReport).length === 0
      ? null
      : rawReport;
  const attached =
    o.signature === undefined || o.signature === null
      ? null
      : object(o.signature);
  const fileID = id(c, "file_id"),
    sourceSHA = hash(file, "sha256"),
    policySHA = hash(c, "policy_hash");
  let signatureProof: SignatureEvidence | null = null;
  let validation: CheckView["validation"] = null;
  const invalid = () => {
    throw new ApiError("invalid_server_response", 502);
  };
  const reference = (v: unknown) => {
    const k = object(v);
    const version = number(k, "version", Number.MAX_SAFE_INTEGER);
    if (version < 1) invalid();
    return { id: id(k, "id"), version, hash: hash(k, "hash") };
  };
  const sameReference = (
    a: ReturnType<typeof reference>,
    b: ReturnType<typeof reference>,
  ) => a.id === b.id && a.version === b.version && a.hash === b.hash;
  if (
    attached &&
    (id(attached, "file_id") !== fileID ||
      hash(attached, "data_sha256") !== sourceSHA ||
      hash(attached, "policy_hash") !== policySHA)
  )
    invalid();
  if (report) {
    if (
      id(report, "file_id") !== fileID ||
      hash(report, "sha256") !== sourceSHA ||
      hash(report, "policy_hash") !== policySHA
    )
      invalid();
    validation = {
      engine: text(report, "engine", 64),
      code: text(report, "code", 128),
      rows: number(report, "rows", Number.MAX_SAFE_INTEGER),
      bytes: number(report, "bytes_read", 1 << 30),
    };
    if (report.signature !== undefined && report.signature !== null) {
      if (!attached) invalid();
      const proof = object(report.signature),
        verified = object(proof.verification),
        key = reference(proof.key);
      const fingerprint = (field: string) => {
        const value = text(verified, field, 64);
        if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) invalid();
        return value;
      };
      const timestamp = (field: string) => {
        const value = text(verified, field, 64);
        if (!Number.isFinite(Date.parse(value))) invalid();
        return value;
      };
      const instant = (value: string): bigint => {
        const match =
          /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(
            value,
          );
        const seconds = match?.[1];
        if (!seconds) return invalid();
        const base = Date.parse(seconds + "Z");
        if (
          !Number.isFinite(base) ||
          new Date(base).toISOString().slice(0, 19) !== seconds
        )
          return invalid();
        return (
          BigInt(base) * 1000000n + BigInt((match?.[2] ?? "").padEnd(9, "0"))
        );
      };
      const created = timestamp("created_at"),
        at = timestamp("verified_at");
      const until =
        verified.valid_until === undefined ? null : timestamp("valid_until");
      const digest = hash(proof, "sha256"),
        algorithm = text(verified, "hash_algorithm", 16),
        version = number(verified, "signature_version", 6);
      if (
        !attached ||
        id(proof, "object_id") !== id(attached, "object_id") ||
        digest !== hash(attached, "sha256") ||
        digest !== hash(verified, "signature_sha256") ||
        !sameReference(key, reference(attached.key)) ||
        ![4, 6].includes(version) ||
        !["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"].includes(
          algorithm,
        ) ||
        instant(created) > instant(at) ||
        (until !== null && instant(until) <= instant(at))
      )
        invalid();
      signatureProof = {
        primary: fingerprint("primary_fingerprint"),
        signer: fingerprint("signer_fingerprint"),
        signatureSHA256: digest,
        keyID: key.id,
        keyVersion: key.version,
        keyHash: key.hash,
        createdAt: created,
        verifiedAt: at,
        validUntil: until,
        hashAlgorithm: algorithm,
        signatureVersion: version,
      };
    }
  }
  const state = text(c, "state", 32);
  if (
    ["passed", "released"].includes(state) &&
    (report === null ||
      reportHash === "" ||
      (req && bool(req, "signature_required") && signatureProof === null))
  )
    invalid();
  let recovery: CheckRecovery | null = null;
  if (o.recovery !== undefined && o.recovery !== null) {
    const r = object(o.recovery),
      d = object(r.decision);
    const observed = text(r, "observed_at", 64),
      until = text(d, "expected_lease_until", 64),
      rawUntil = text(c, "lease_until", 64);
    const observedInstant = timestampInstant(observed),
      untilInstant = timestampInstant(until);
    const decision: RecoveryDecision = {
      expected_revision: number(
        d,
        "expected_revision",
        Number.MAX_SAFE_INTEGER,
      ),
      expected_worker_id: id(d, "expected_worker_id"),
      expected_lease_until: until,
      sha256: hash(d, "sha256"),
      policy_hash: hash(d, "policy_hash"),
    };
    const code = text(r, "code", 64),
      eligible = bool(r, "eligible");
    if (
      ![
        "ready",
        "lease_active",
        "attempt_budget_exhausted",
        "authority_or_policy_changed",
        "permission_denied",
      ].includes(code) ||
      state !== "running" ||
      decision.expected_revision !==
        number(c, "revision", Number.MAX_SAFE_INTEGER) ||
      decision.expected_worker_id !== id(c, "worker_id") ||
      decision.sha256 !== sourceSHA ||
      decision.policy_hash !== policySHA ||
      untilInstant !== timestampInstant(rawUntil) ||
      eligible !== (code === "ready") ||
      (eligible &&
        (!bool(o, "current") ||
          number(c, "attempts", 3) >= 3 ||
          untilInstant > observedInstant)) ||
      (code === "lease_active" && untilInstant <= observedInstant)
    )
      invalid();
    recovery = {
      observedAt: observed,
      eligible,
      code: code as CheckRecovery["code"],
      decision,
    };
  }
  return {
    recovery,
    signatureProof,
    validation,
    current: bool(o, "current"),
    signatureAttached: attached !== null,
    requirements: req
      ? {
          signature: bool(req, "signature_required"),
          scanner: bool(req, "scanner_required"),
        }
      : null,
    check: {
      file_id: fileID,
      state,
      revision: number(c, "revision", Number.MAX_SAFE_INTEGER),
      attempts: number(c, "attempts", 3),
      code: text(c, "code", 128),
      policy_hash: policySHA,
      report_hash: reportHash,
      source_sha256: sourceSHA,
      path: target === null ? "" : text(target, "path"),
      report,
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
