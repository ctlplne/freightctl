import { ApiError, object, uuid } from "./types";
import { ftpsMetadataPath } from "./ftps-metadata";
import { strictRecoveryJSON } from "./artifact-recovery";
import {
  asExchangeArtifact,
  type ExchangeArtifact,
  type DirectoryContext,
} from "./artifact-exchanges-types";

export interface ReceivedCopyRequest {
  exchange_id: string;
  request_hash: string;
  artifact: ExchangeArtifact;
  virtual_path: string;
}
export interface CopyOperation {
  request: ReceivedCopyRequest;
  request_key: string;
  expected_artifact_id?: string;
}
export interface ReceivedCopyResult {
  profile: "received-artifact-copy-v1";
  source: Omit<ReceivedCopyRequest, "virtual_path">;
  artifact: ExchangeArtifact;
  event_id: string;
  acceptance:
    "durable-local-integrity-only" | "durable-held-pending-checks-and-release";
  replayed: boolean;
  observation: "original-command-receipt";
  current_state: "not-checked";
  receiver_persistence: "unknown";
  business_processing: "unknown";
}
function bad(): never {
  throw new ApiError("invalid_received_copy_contract", 400);
}
function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
}
const identifier = (v: unknown): string => {
  if (typeof v !== "string" || !uuid(v)) bad();
  return v;
};
export function copyKey(v: unknown): string {
  if (typeof v !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(v)) bad();
  return v;
}
export function asReceivedCopyRequest(value: unknown): ReceivedCopyRequest {
  const o = exact(value, [
    "exchange_id",
    "request_hash",
    "artifact",
    "virtual_path",
  ]);
  if (
    typeof o.request_hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(o.request_hash) ||
    typeof o.virtual_path !== "string" ||
    o.virtual_path === "/" ||
    /[\uD800-\uDFFF]/u.test(o.virtual_path)
  )
    bad();
  const result = {
    exchange_id: identifier(o.exchange_id),
    request_hash: o.request_hash,
    artifact: asExchangeArtifact(o.artifact),
    virtual_path: ftpsMetadataPath(o.virtual_path),
  };
  if (new TextEncoder().encode(JSON.stringify(result)).length > 16384) bad();
  return result;
}
export function asReceivedCopyResult(
  value: unknown,
  request: ReceivedCopyRequest,
  expectedID?: string,
): ReceivedCopyResult {
  const o = exact(value, [
      "profile",
      "source",
      "artifact",
      "event_id",
      "acceptance",
      "replayed",
      "observation",
      "current_state",
      "receiver_persistence",
      "business_processing",
    ]),
    source = exact(o.source, ["exchange_id", "request_hash", "artifact"]),
    artifact = asExchangeArtifact(o.artifact);
  const pinned = asReceivedCopyRequest(request);
  if (
    o.profile !== "received-artifact-copy-v1" ||
    source.exchange_id !== pinned.exchange_id ||
    source.request_hash !== pinned.request_hash ||
    JSON.stringify(asExchangeArtifact(source.artifact)) !==
      JSON.stringify(pinned.artifact) ||
    artifact.file_revision_id === pinned.artifact.file_revision_id ||
    (expectedID !== undefined &&
      artifact.file_revision_id !== identifier(expectedID)) ||
    artifact.size_bytes !== pinned.artifact.size_bytes ||
    artifact.sha256 !== pinned.artifact.sha256 ||
    typeof o.replayed !== "boolean" ||
    o.observation !== "original-command-receipt" ||
    o.current_state !== "not-checked" ||
    o.receiver_persistence !== "unknown" ||
    o.business_processing !== "unknown" ||
    o.acceptance !==
      (artifact.acceptance_policy.startsWith("intake-csv-v1:")
        ? "durable-held-pending-checks-and-release"
        : "durable-local-integrity-only")
  )
    bad();
  return {
    profile: "received-artifact-copy-v1",
    source: {
      exchange_id: pinned.exchange_id,
      request_hash: pinned.request_hash,
      artifact: pinned.artifact,
    },
    artifact,
    event_id: identifier(o.event_id),
    acceptance: artifact.acceptance_policy.startsWith("intake-csv-v1:")
      ? "durable-held-pending-checks-and-release"
      : "durable-local-integrity-only",
    replayed: o.replayed,
    observation: "original-command-receipt",
    current_state: "not-checked",
    receiver_persistence: "unknown",
    business_processing: "unknown",
  };
}
function binding(c: DirectoryContext) {
  return {
    tenant_id: c.tenant,
    partner_id: c.partner,
    actor_id: c.actor,
    authority_revision: c.authority_revision,
    root_policy_digest: c.root_policy_digest,
  };
}
function origin(v: string) {
  const u = new URL(v);
  if (u.protocol !== "https:" || u.origin !== v || v.length > 2048) bad();
  return v;
}
export function copyRecovery(
  value: CopyOperation,
  c: DirectoryContext,
  serverOrigin: string,
) {
  if (!c.can_receive) bad();
  return {
    schema_version: 1,
    profile: "freightctl-received-copy-recovery-v1",
    server_origin: origin(serverOrigin),
    participant: binding(c),
    request: asReceivedCopyRequest(value.request),
    request_key: copyKey(value.request_key),
    ...(value.expected_artifact_id !== undefined
      ? { expected_artifact_id: identifier(value.expected_artifact_id) }
      : {}),
  };
}
export function readCopyRecovery(
  text: string,
  c: DirectoryContext,
  serverOrigin: string,
): CopyOperation {
  const o = exact(
      strictRecoveryJSON(text),
      [
        "schema_version",
        "profile",
        "server_origin",
        "participant",
        "request",
        "request_key",
      ],
      ["expected_artifact_id"],
    ),
    p = exact(o.participant, Object.keys(binding(c)));
  if (
    !c.can_receive ||
    o.schema_version !== 1 ||
    o.profile !== "freightctl-received-copy-recovery-v1" ||
    o.server_origin !== origin(serverOrigin) ||
    Object.entries(binding(c)).some(([k, v]) => p[k] !== v)
  )
    bad();
  return {
    request: asReceivedCopyRequest(o.request),
    request_key: copyKey(o.request_key),
    ...(o.expected_artifact_id !== undefined
      ? { expected_artifact_id: identifier(o.expected_artifact_id) }
      : {}),
  };
}
