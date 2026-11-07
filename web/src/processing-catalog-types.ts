import { ApiError, object, uuid } from "./types";
import { reference, type Reference } from "./processing-types";

export type ProcessingCatalogEntry = Reference & {
  name: string;
  state: string;
  revision: number;
  kind: "records.project";
  source_policy_hash: string;
  output_kind: string;
  column_count: number;
  output_policy: Reference;
  approval_current: boolean;
  output_policy_current: boolean;
};
export type ProcessingCatalog = {
  profile: "processing-workflow-catalog-v1";
  authority_revision: number;
  namespace_root_digest: string;
  workflows: ProcessingCatalogEntry[];
  next?: string;
};
const bad = (): never => {
  throw new ApiError("invalid_processing_catalog", 502);
};
function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value);
  if (
    required.some((k) => !Object.hasOwn(o, k)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
}
function positive(value: unknown) {
  if (!Number.isSafeInteger(value) || Number(value) < 1) bad();
  return value as number;
}
function digest(value: unknown) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) bad();
  return value as string;
}
export function processingCatalog(value: unknown): ProcessingCatalog {
  const o = exact(
    value,
    ["profile", "authority_revision", "namespace_root_digest", "workflows"],
    ["next"],
  );
  if (
    o.profile !== "processing-workflow-catalog-v1" ||
    !Array.isArray(o.workflows) ||
    o.workflows.length > 100
  )
    bad();
  const rows = (o.workflows as unknown[]).map((value) => {
    const r = exact(value, [
      "id",
      "version",
      "hash",
      "name",
      "state",
      "revision",
      "kind",
      "source_policy_hash",
      "output_kind",
      "column_count",
      "output_policy",
      "approval_current",
      "output_policy_current",
    ]);
    if (
      typeof r.name !== "string" ||
      r.name.normalize("NFC") !== r.name ||
      new TextEncoder().encode(r.name).length < 1 ||
      new TextEncoder().encode(r.name).length > 256 ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(r.name) ||
      !["draft", "approved", "revoked"].includes(r.state as string) ||
      r.kind !== "records.project" ||
      !["csv", "json_records"].includes(r.output_kind as string) ||
      typeof r.approval_current !== "boolean" ||
      typeof r.output_policy_current !== "boolean" ||
      (r.approval_current && r.state !== "approved")
    )
      bad();
    const row: ProcessingCatalogEntry = {
      ...reference({ id: r.id, version: r.version, hash: r.hash }),
      name: r.name as string,
      state: r.state as string,
      revision: positive(r.revision),
      kind: "records.project",
      source_policy_hash: digest(r.source_policy_hash),
      output_kind: r.output_kind as string,
      column_count: positive(r.column_count),
      output_policy: reference(r.output_policy),
      approval_current: r.approval_current as boolean,
      output_policy_current: r.output_policy_current as boolean,
    };
    if (row.column_count > 128) bad();
    return row;
  });
  for (let i = 1; i < rows.length; i++)
    if (rows[i - 1]!.id >= rows[i]!.id) bad();
  if (
    o.next !== undefined &&
    (typeof o.next !== "string" ||
      !uuid(o.next) ||
      rows.length === 0 ||
      rows.at(-1)!.id !== o.next)
  )
    bad();
  return {
    profile: "processing-workflow-catalog-v1",
    authority_revision: positive(o.authority_revision),
    namespace_root_digest: digest(o.namespace_root_digest),
    workflows: rows,
    ...(o.next === undefined ? {} : { next: o.next as string }),
  };
}
