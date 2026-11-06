import { digestBytes } from "./crypto";
import { ApiError, object, uuid } from "./types";

export interface IntakeColumn {
  name: string;
  type: "text" | "integer" | "decimal" | "date";
  required: boolean;
  max_bytes: number;
  precision?: number;
  scale?: number;
}
interface Reference {
  id: string;
  version: number;
  hash: string;
}
interface IntakeDefinitionFields {
  columns: IntakeColumn[];
  max_bytes: number;
  max_rows: number;
  max_record_bytes: number;
  timeout_seconds: number;
  signature?: { key: Reference; max_age_seconds?: number };
  scanner?: Reference;
}
export type IntakeDefinition = IntakeDefinitionFields &
  (
    | { schema_version: 1; kind: "csv" }
    | { schema_version: 2; kind: "json_records" }
  );
export interface IntakePolicy {
  id: string;
  version: number;
  definition: IntakeDefinition;
  definition_hash: string;
  state: "active" | "revoked";
  revision: number;
}
const fail = (): never => {
  throw new ApiError("invalid_intake_policy", 400);
};
function integer(value: unknown, low: number, high: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < low ||
    value > high
  )
    return fail();
  return value;
}
function keys(o: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(o).some((key) => !allowed.includes(key))) fail();
}
function reference(value: unknown): Reference {
  const o = object(value);
  keys(o, ["id", "version", "hash"]);
  if (
    typeof o.id !== "string" ||
    !uuid(o.id) ||
    typeof o.hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(o.hash)
  )
    return fail();
  return {
    id: o.id,
    version: integer(o.version, 1, Number.MAX_SAFE_INTEGER),
    hash: o.hash,
  };
}
export function intakeDefinition(value: unknown): IntakeDefinition {
  const o = object(value);
  keys(o, [
    "schema_version",
    "kind",
    "columns",
    "max_bytes",
    "max_rows",
    "max_record_bytes",
    "timeout_seconds",
    "signature",
    "scanner",
  ]);
  if (
    !(
      (o.schema_version === 1 && o.kind === "csv") ||
      (o.schema_version === 2 && o.kind === "json_records")
    ) ||
    !Array.isArray(o.columns) ||
    o.columns.length < 1 ||
    o.columns.length > 128
  )
    return fail();
  const record = integer(o.max_record_bytes, 64, 1048576),
    names = new Set<string>();
  const columns = o.columns.map((value): IntakeColumn => {
    const c = object(value);
    keys(c, ["name", "type", "required", "max_bytes", "precision", "scale"]);
    if (
      typeof c.name !== "string" ||
      // Match Go strings.TrimSpace: ECMAScript trim also removes U+FEFF,
      // which is a valid literal CSV header character in a stored policy.
      /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/u.test(
        c.name,
      ) ||
      !c.name ||
      new TextEncoder().encode(c.name).length > 128 ||
      /[\p{Cc}\p{Cs}]/u.test(c.name) ||
      names.has(c.name) ||
      !["text", "integer", "decimal", "date"].includes(String(c.type)) ||
      typeof c.required !== "boolean"
    )
      return fail();
    names.add(c.name);
    const column: IntakeColumn = {
      name: c.name,
      type: c.type as IntakeColumn["type"],
      required: c.required,
      max_bytes: integer(c.max_bytes, 1, Math.min(record, 65536)),
    };
    const precision = integer(c.precision ?? 0, 0, 38),
      scale = integer(c.scale ?? 0, 0, 38);
    if (column.type === "decimal") {
      if (precision < 1 || scale > precision) return fail();
      column.precision = precision;
      if (scale) column.scale = scale;
    } else if (precision || scale) return fail();
    return column;
  });
  const result: IntakeDefinition = {
    ...(o.kind === "csv"
      ? { schema_version: 1 as const, kind: "csv" as const }
      : { schema_version: 2 as const, kind: "json_records" as const }),
    columns,
    max_bytes: integer(o.max_bytes, 1, 1073741824),
    max_rows: integer(o.max_rows, 1, 1000000),
    max_record_bytes: record,
    timeout_seconds: integer(o.timeout_seconds, 1, 60),
  };
  if (o.signature !== undefined) {
    const s = object(o.signature);
    keys(s, ["key", "max_age_seconds"]);
    result.signature = { key: reference(s.key) };
    const age = integer(s.max_age_seconds ?? 0, 0, 4294967295);
    if (age) result.signature.max_age_seconds = age;
  }
  if (o.scanner !== undefined) result.scanner = reference(o.scanner);
  if (new TextEncoder().encode(goJSON(result)).length > 12 * 1024)
    return fail();
  return result;
}
function goJSON(value: unknown): string {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
export function intakeHash(definition: IntakeDefinition): string {
  // Go's encoding/json escapes HTML and the two line separators. Field order
  // and omitted zero precision/scale match the actual CSV policy structure.
  const encoded = goJSON(intakeDefinition(definition));
  return digestBytes(new TextEncoder().encode(encoded));
}
export function asIntakePolicy(value: unknown): IntakePolicy | null {
  if (value === null) return null;
  try {
    const o = object(value),
      definition = intakeDefinition(o.definition);
    if (
      typeof o.id !== "string" ||
      !uuid(o.id) ||
      !["active", "revoked"].includes(String(o.state)) ||
      typeof o.definition_hash !== "string" ||
      intakeHash(definition) !== o.definition_hash
    )
      return fail();
    return {
      id: o.id,
      version: integer(o.version, 1, Number.MAX_SAFE_INTEGER),
      definition,
      definition_hash: o.definition_hash,
      state: o.state as IntakePolicy["state"],
      revision: integer(o.revision, 1, Number.MAX_SAFE_INTEGER),
    };
  } catch {
    throw new ApiError("invalid_server_response", 502);
  }
}
export function defaultIntakeDefinition(): IntakeDefinition {
  return {
    schema_version: 1,
    kind: "csv",
    columns: [
      { name: "account", type: "text", required: true, max_bytes: 64 },
      {
        name: "amount",
        type: "decimal",
        required: true,
        max_bytes: 64,
        precision: 12,
        scale: 2,
      },
      { name: "day", type: "date", required: true, max_bytes: 10 },
    ],
    max_bytes: 16777216,
    max_rows: 100000,
    max_record_bytes: 65536,
    timeout_seconds: 30,
  };
}
