import { ApiError, object } from "./types";
import { asCollectionView, type CollectionView } from "./collections-types";
import {
  asExchangeArtifact,
  type ExchangeSourceExpectation,
} from "./artifact-exchanges-types";

export interface CollectedSourceExpectation {
  artifact: ExchangeSourceExpectation;
  origin: {
    collection_id: string;
    definition_hash: string;
    workflow: { id: string; version: number; hash: string };
    manifest_sha256: string;
    producer_batch_id: string;
    input_id: string;
    input_identity: string;
    first_collection_id: string;
  };
}
function refuse(): never {
  throw new ApiError("invalid_server_response", 502);
}
function exact(v: unknown, keys: string[]) {
  const o = object(v);
  if (
    keys.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !keys.includes(k))
  )
    refuse();
  return o;
}
export function collectedSourceExpectation(
  value: CollectionView,
  inputID: string,
  authority: number,
): CollectedSourceExpectation | null {
  const v = asCollectionView(
      value,
      value.job.id,
      authority,
      value.job.definition_hash,
    ),
    index = v.inputs.findIndex((i) => i.id === inputID),
    input = v.inputs[index];
  if (
    !input ||
    !v.job.captured ||
    !v.job.manifest ||
    !v.job.manifest_hash ||
    !input.file_id ||
    input.state === "pending" ||
    v.local_states[index]?.state !== "published"
  )
    return null;
  return {
    artifact: {
      file_revision_id: input.file_id,
      size_bytes: input.size_bytes,
      sha256: input.sha256,
    },
    origin: {
      collection_id: v.job.id,
      definition_hash: v.job.definition_hash,
      workflow: { ...v.job.definition.workflow },
      manifest_sha256: v.job.manifest_hash,
      producer_batch_id: v.job.manifest.batch_id,
      input_id: input.id,
      input_identity: input.input_identity,
      first_collection_id: input.first_job_id,
    },
  };
}
export function asCollectedExchangeSource(
  value: unknown,
  expected: CollectedSourceExpectation,
) {
  const o = exact(value, [
      "profile",
      "artifact",
      "origin",
      "state",
      "storage_verification",
    ]),
    r = exact(o.origin, [
      "collection_id",
      "definition_hash",
      "workflow",
      "manifest_sha256",
      "producer_batch_id",
      "input_id",
      "input_identity",
      "first_collection_id",
    ]);
  const w = exact(r.workflow, ["id", "version", "hash"]);
  const origin = {
    collection_id: r.collection_id,
    definition_hash: r.definition_hash,
    workflow: { id: w.id, version: w.version, hash: w.hash },
    manifest_sha256: r.manifest_sha256,
    producer_batch_id: r.producer_batch_id,
    input_id: r.input_id,
    input_identity: r.input_identity,
    first_collection_id: r.first_collection_id,
  };
  const artifact = asExchangeArtifact(
    o.artifact,
    expected.artifact.file_revision_id,
  );
  if (
    o.profile !== "governed-collection-exchange-source-v1" ||
    o.state !== "source-review-only" ||
    o.storage_verification !== "not-checked" ||
    JSON.stringify(origin) !== JSON.stringify(expected.origin) ||
    artifact.size_bytes !== expected.artifact.size_bytes ||
    artifact.sha256 !== expected.artifact.sha256
  )
    refuse();
  return {
    artifact,
    origin: structuredClone(expected.origin),
    profile: "governed-collection-exchange-source-v1" as const,
    state: "source-review-only" as const,
    storage_verification: "not-checked" as const,
  };
}
