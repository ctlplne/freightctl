import { ApiError, object, uuid, type Session } from "./types";
import { reference, type Reference } from "./processing-types";

export interface OutputContractCatalog {
  policies: {
    reference: Reference;
    kind: "csv" | "json_records";
    column_count: number;
  }[];
  next?: string;
}
function bad(): never {
  throw new ApiError("invalid_processing_output_catalog", 502);
}
function exact(value: unknown, required: string[], optional: string[] = []) {
  const o = object(value),
    keys = Object.keys(o);
  if (
    required.some((k) => !(k in o)) ||
    keys.some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
  return o;
}
export function processingOutputCatalog(
  value: unknown,
  session: Session,
): OutputContractCatalog {
  const p = exact(value, ["profile", "policies"], ["next"]);
  if (
    p.profile !== "producer-processing-output-policy-v1" ||
    !Array.isArray(p.policies) ||
    p.policies.length > 25
  )
    bad();
  const policies: OutputContractCatalog["policies"] = [],
    seen = new Set<string>();
  for (const value of p.policies) {
    const row = exact(value, [
        "id",
        "version",
        "definition_hash",
        "state",
        "revision",
        "producer_id",
        "producer_binding_current_at_observation",
        "kind",
        "column_count",
      ]),
      ref = reference({
        id: row.id,
        version: row.version,
        hash: row.definition_hash,
      });
    if (
      row.state !== "output_active" ||
      row.revision !== 1 ||
      typeof row.producer_id !== "string" ||
      !uuid(row.producer_id) ||
      typeof row.producer_binding_current_at_observation !== "boolean" ||
      typeof row.kind !== "string" ||
      ![
        "csv",
        "json_records",
        "fixed_width",
        "xml_records",
        "xlsx_records",
      ].includes(row.kind) ||
      !Number.isSafeInteger(row.column_count) ||
      (row.column_count as number) < 1 ||
      (row.column_count as number) > 128 ||
      seen.has(ref.id)
    )
      bad();
    seen.add(ref.id);
    if (
      row.producer_id === session.identity.actor_id &&
      row.producer_binding_current_at_observation &&
      (row.kind === "csv" || row.kind === "json_records")
    )
      policies.push({
        reference: ref,
        kind: row.kind,
        column_count: row.column_count as number,
      });
  }
  if (p.next !== undefined && (typeof p.next !== "string" || !uuid(p.next)))
    bad();
  return {
    policies,
    ...(p.next === undefined ? {} : { next: p.next as string }),
  };
}
