import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
export interface Condition {
  op: string;
  field?: string;
  variable?: string;
  text?: string;
  number?: string;
  all?: Condition[];
  any?: Condition[];
  not?: Condition;
}
export interface ProgramNode {
  kind: "deliver" | "if" | "for_each" | "keep_local";
  step?: string;
  step_variable?: string;
  when?: Condition;
  then?: ProgramNode[];
  else?: ProgramNode[];
  variable?: string;
  steps?: string[];
  body?: ProgramNode[];
  reason?: string;
}
export interface Program {
  nodes: ProgramNode[];
}
export interface RoutingFile {
  id: string;
  size_bytes: number;
  sha256: string;
  policy: string;
  accepted_event_id: string;
}
export interface RoutingSource {
  collection_id: string;
  manifest_hash: string;
  name: string;
  batch_id: string;
  file_count: number;
  index: number;
}
export interface RoutingFacts {
  file: RoutingFile;
  source?: RoutingSource;
}
export interface ProgramDecision {
  path: string;
  kind: string;
  matched?: boolean;
  step?: string;
  variable?: string;
  steps?: string[];
  reason?: string;
}
export interface ExecutionPlan {
  schema_version: 1;
  facts: RoutingFacts;
  selected_steps: string[];
  decisions: ProgramDecision[];
  local_reason?: string;
}
export interface ProgramShape {
  schema_version: 2;
  steps: { id: string }[];
  source?: { max_files: number; max_file_bytes: number };
  program: Program;
}
const bad = (): never => {
  throw new ApiError("invalid_workflow_program", 502);
};
const keys = (
  o: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) => {
  if (
    required.some((k) => !(k in o)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
};
const text = (v: unknown, max = 128) => {
  if (
    typeof v !== "string" ||
    new TextEncoder().encode(v).length < 1 ||
    new TextEncoder().encode(v).length > max ||
    /\p{Cc}/u.test(v)
  )
    bad();
  return v as string;
};
const name = (v: unknown) => {
  const s = text(v, 64);
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(s)) bad();
  return s;
};
const id = (v: unknown) => {
  const s = text(v, 36);
  if (!uuid(s)) bad();
  return s;
};
const hash = (v: unknown) => {
  const s = text(v, 64);
  if (!/^[a-f0-9]{64}$/.test(s)) bad();
  return s;
};
const number = (v: unknown, min: number, max: number) => {
  if (!Number.isSafeInteger(v) || Number(v) < min || Number(v) > max) bad();
  return v as number;
};
const list = (v: unknown, max: number, min = 0) => {
  if (!Array.isArray(v) || v.length < min || v.length > max) bad();
  return v as unknown[];
};
const globPattern = /^[A-Za-z0-9._*?-]{1,128}$/;
const fieldKind = (v: string, source: boolean) =>
  ["file.id", "file.sha256", "file.policy"].includes(v)
    ? "text"
    : v === "file.size_bytes"
      ? "number"
      : source && ["source.name", "source.batch_id"].includes(v)
        ? "text"
        : source && ["source.file_count", "source.index"].includes(v)
          ? "number"
          : "";
export const programBytes = (v: unknown) =>
  new TextEncoder().encode(
    JSON.stringify(v).replace(
      /[<>&\u2028\u2029]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    ),
  );
export const programFingerprint = (v: unknown) => digestBytes(programBytes(v));
export function asProgram(
  v: unknown,
  catalog: string[],
  hasSource: boolean,
): Program {
  const o = object(v);
  keys(o, ["nodes"]);
  if (catalog.length > 16 || new Set(catalog).size !== catalog.length) bad();
  catalog.forEach(name);
  let nodes = 0,
    conditions = 0;
  function condition(
    v: unknown,
    vars: Set<string>,
    depth: number,
  ): [Condition, number] {
    const o = object(v),
      op = text(o.op);
    if (depth > 3 || ++conditions > 64) bad();
    if (["all", "any", "not"].includes(op)) {
      keys(o, ["op", op]);
      const raw = op === "not" ? [o.not] : list(o[op], 16, 1);
      let cost = 1;
      const values = raw.map((v) => {
        const [c, n] = condition(v, vars, depth + 1);
        cost += n;
        return c;
      });
      return [
        {
          op,
          ...(op === "all"
            ? { all: values }
            : op === "any"
              ? { any: values }
              : { not: values[0]! }),
        },
        cost,
      ];
    }
    keys(o, ["op"], ["field", "variable", "text", "number"]);
    if ((o.field === undefined) === (o.variable === undefined)) bad();
    const variable = o.variable === undefined ? undefined : name(o.variable),
      field = o.field === undefined ? undefined : text(o.field),
      kind = variable
        ? vars.has(variable)
          ? "text"
          : ""
        : fieldKind(field!, hasSource);
    if (!kind) bad();
    const base = {
      op,
      ...(field ? { field } : {}),
      ...(variable ? { variable } : {}),
    };
    if (kind === "number") {
      if (
        !["eq", "ne", "lt", "le", "gt", "ge"].includes(op) ||
        o.text !== undefined ||
        typeof o.number !== "string" ||
        !/^(0|[1-9][0-9]{0,18})$/.test(o.number) ||
        BigInt(o.number) > 9223372036854775807n
      )
        bad();
      return [{ ...base, number: o.number as string }, 1];
    }
    if (
      !["eq", "ne", "prefix", "suffix", "glob"].includes(op) ||
      o.number !== undefined
    )
      bad();
    const value = text(o.text);
    if (op === "glob" && !globPattern.test(value)) bad();
    if (
      field === "file.sha256" &&
      (!["eq", "ne"].includes(op) || !/^[a-f0-9]{64}$/.test(value))
    )
      bad();
    if (
      ["file.id", "source.batch_id"].includes(field ?? "") &&
      (!["eq", "ne"].includes(op) || !uuid(value))
    )
      bad();
    return [{ ...base, text: value }, 1];
  }
  function sequence(
    v: unknown,
    vars: Set<string>,
    depth: number,
  ): [ProgramNode[], number] {
    if (depth >= 4) bad();
    let cost = 0;
    const result = list(v, 64).map((v) => {
      if (++nodes > 64) bad();
      cost++;
      const o = object(v),
        kind = text(o.kind);
      let node: ProgramNode;
      switch (kind) {
        case "deliver": {
          keys(o, ["kind"], ["step", "step_variable"]);
          if ((o.step === undefined) === (o.step_variable === undefined)) bad();
          const step = o.step === undefined ? undefined : name(o.step),
            variable =
              o.step_variable === undefined ? undefined : name(o.step_variable);
          if (
            (step && !catalog.includes(step)) ||
            (variable && !vars.has(variable))
          )
            bad();
          node = {
            kind,
            ...(step ? { step } : {}),
            ...(variable ? { step_variable: variable } : {}),
          };
          break;
        }
        case "keep_local":
          keys(o, ["kind", "reason"]);
          node = { kind, reason: name(o.reason) };
          break;
        case "if": {
          keys(o, ["kind", "when", "then"], ["else"]);
          list(o.then, 64, 1);
          const [when, terms] = condition(o.when, vars, 0),
            [yes, a] = sequence(o.then, vars, depth + 1),
            [no, b] =
              o.else === undefined
                ? ([[], 0] as [ProgramNode[], number])
                : sequence(o.else, vars, depth + 1);
          cost += terms + a + b;
          node = { kind, when, then: yes, ...(no.length ? { else: no } : {}) };
          break;
        }
        case "for_each": {
          keys(o, ["kind", "variable", "steps", "body"]);
          const variable = name(o.variable),
            steps = list(o.steps, 16, 1).map(name);
          if (
            vars.has(variable) ||
            new Set(steps).size !== steps.length ||
            steps.some((s) => !catalog.includes(s))
          )
            bad();
          list(o.body, 64, 1);
          const [body, n] = sequence(
            o.body,
            new Set([...vars, variable]),
            depth + 1,
          );
          cost += steps.length * n;
          node = { kind, variable, steps, body };
          break;
        }
        default:
          return bad();
      }
      if (cost > 256) bad();
      return node;
    });
    return [result, cost];
  }
  list(o.nodes, 64, 1);
  const [parsed] = sequence(o.nodes, new Set(), 0);
  return { nodes: parsed };
}
export function asRoutingFacts(
  v: unknown,
  source?: ProgramShape["source"],
): RoutingFacts {
  const o = object(v);
  keys(o, ["file"], source ? ["source"] : []);
  const f = object(o.file);
  keys(f, ["id", "size_bytes", "sha256", "policy", "accepted_event_id"]);
  const file = {
    id: id(f.id),
    size_bytes: number(f.size_bytes, 0, 1073741824),
    sha256: hash(f.sha256),
    policy: text(f.policy),
    accepted_event_id: id(f.accepted_event_id),
  };
  if (!source) return { file };
  const s = object(o.source);
  keys(s, [
    "collection_id",
    "manifest_hash",
    "name",
    "batch_id",
    "file_count",
    "index",
  ]);
  const count = number(s.file_count, 1, source.max_files),
    filename = text(s.name);
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename) ||
    filename.endsWith(".ready.json") ||
    file.size_bytes > source.max_file_bytes
  )
    bad();
  return {
    file,
    source: {
      collection_id: id(s.collection_id),
      manifest_hash: hash(s.manifest_hash),
      name: filename,
      batch_id: id(s.batch_id),
      file_count: count,
      index: number(s.index, 0, count - 1),
    },
  };
}
export function compileProgram(d: ProgramShape, input: unknown): ExecutionPlan {
  if (d.schema_version !== 2) bad();
  const program = asProgram(
      d.program,
      d.steps.map((s) => s.id),
      d.source !== undefined,
    ),
    facts = asRoutingFacts(input, d.source);
  const plan: ExecutionPlan = {
    schema_version: 1,
    facts,
    selected_steps: [],
    decisions: [],
  };
  let visits = 0;
  const emitted = new Set<string>();
  const visit = () => {
    if (++visits > 256) bad();
  };
  function matches(c: Condition, vars: Map<string, string>): boolean {
    visit();
    if (c.op === "not") return !matches(c.not!, vars);
    if (c.op === "all") return c.all!.every((x) => matches(x, vars));
    if (c.op === "any") return c.any!.some((x) => matches(x, vars));
    let value: unknown;
    if (c.variable) {
      value = vars.get(c.variable);
      if (value === undefined) bad();
    } else {
      const [owner, key] = c.field!.split(".");
      const values = owner === "file" ? facts.file : facts.source;
      if (!values) bad();
      value = (values as unknown as Record<string, unknown>)[key!];
    }
    if (c.number !== undefined) {
      if (typeof value !== "number") bad();
      const a = BigInt(value as number),
        b = BigInt(c.number);
      switch (c.op) {
        case "eq":
          return a === b;
        case "ne":
          return a !== b;
        case "lt":
          return a < b;
        case "le":
          return a <= b;
        case "gt":
          return a > b;
        case "ge":
          return a >= b;
        default:
          return bad();
      }
    }
    if (typeof value !== "string") bad();
    const a = value as string,
      b = c.text!;
    switch (c.op) {
      case "eq":
        return a === b;
      case "ne":
        return a !== b;
      case "prefix":
        return a.startsWith(b);
      case "suffix":
        return a.endsWith(b);
      case "glob":
        return new RegExp(
          "^" +
            [...b]
              .map((c) =>
                c === "*" ? ".*" : c === "?" ? "." : c === "." ? "[.]" : c,
              )
              .join("") +
            "$",
        ).test(a);
      default:
        return bad();
    }
  }
  function execute(
    nodes: ProgramNode[],
    vars: Map<string, string>,
    prefix = "",
  ) {
    nodes.forEach((n, index) => {
      visit();
      const path = prefix + index;
      switch (n.kind) {
        case "deliver": {
          const step = n.step ?? vars.get(n.step_variable!);
          if (!step || emitted.has(step) || plan.local_reason) bad();
          emitted.add(step!);
          plan.selected_steps.push(step!);
          plan.decisions.push({ path, kind: n.kind, step: step! });
          break;
        }
        case "keep_local":
          if (plan.selected_steps.length || plan.local_reason) bad();
          plan.local_reason = n.reason!;
          plan.decisions.push({ path, kind: n.kind, reason: n.reason! });
          break;
        case "if": {
          const matched = matches(n.when!, vars);
          plan.decisions.push({ path, kind: n.kind, matched });
          execute(
            matched ? n.then! : (n.else ?? []),
            vars,
            path + (matched ? ".then." : ".else."),
          );
          break;
        }
        case "for_each":
          plan.decisions.push({
            path,
            kind: n.kind,
            variable: n.variable!,
            steps: [...n.steps!],
          });
          n.steps!.forEach((s, i) =>
            execute(
              n.body!,
              new Map([...vars, [n.variable!, s]]),
              path + "[" + i + "].body.",
            ),
          );
          break;
      }
    });
  }
  execute(program.nodes, new Map());
  if (
    (!plan.selected_steps.length && !plan.local_reason) ||
    (plan.selected_steps.length && plan.local_reason) ||
    programBytes(plan).length > 24576
  )
    bad();
  return plan;
}
export function asExecutionPlan(
  v: unknown,
  d: ProgramShape,
  expectedFacts?: RoutingFacts,
): ExecutionPlan {
  const o = object(v);
  keys(
    o,
    ["schema_version", "facts", "selected_steps", "decisions"],
    ["local_reason"],
  );
  if (o.schema_version !== 1) bad();
  const expected = compileProgram(d, o.facts);
  if (
    expectedFacts &&
    programFingerprint(expected.facts) !== programFingerprint(expectedFacts)
  )
    bad();
  const canonical = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(canonical)
      : v !== null && typeof v === "object"
        ? Object.fromEntries(
            Object.entries(v)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([k, v]) => [k, canonical(v)]),
          )
        : v;
  if (JSON.stringify(canonical(o)) !== JSON.stringify(canonical(expected)))
    bad();
  return expected;
}
