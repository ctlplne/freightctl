import {
  asCollectionSource,
  asCollectionConnection,
  scheduledCollectionContract,
  type CollectionSource,
  type CollectionConnection,
  asWorkflowConfiguration,
  effectsForWorkflow,
  workflowProgramShape,
  type AnyWorkflowConfiguration,
} from "./collections-types";
import {
  asExecutionPlan,
  programFingerprint,
  type ExecutionPlan,
  type RoutingSource,
} from "./programs-types";
import { ApiError, object, uuid } from "./types";
import {
  processingDefinition,
  type ProcessingDefinition,
} from "./processing-types";
import { digestBytes } from "./crypto";
import {
  asFTPSConnectionProof,
  type FTPSConnectionProof,
} from "./ftps-metadata";
export interface Reference {
  id: string;
  version: number;
  hash: string;
}
export interface CalendarSelection {
  time_zone: string;
  starts_at: string;
  ends_at: string;
  local_times: string[];
  weekdays: number[];
  holidays: string[];
  gap_policy: "skip";
  fold_policy: "first" | "second" | "both";
}
export interface OffsetRule {
  from: string;
  until: string;
  offset_seconds: number;
  abbreviation: string;
}
export interface CalendarDefinition extends CalendarSelection {
  offset_rules: OffsetRule[];
}
export interface CalendarOccurrence {
  at: string;
  local_time: string;
  offset_seconds: number;
  abbreviation: string;
}
export interface SourceSelection {
  directory: string;
  filename_pattern: string;
  recursive: boolean;
  kind?:
    | "sftp.collect"
    | "ftps.collect"
    | "local.collect"
    | "owned_released_records";
}
export interface ArrivalSelection {
  late_after_seconds: number;
  arrival_deadline_seconds: number;
  poll_interval_seconds: number;
}
export interface ScheduleCollection {
  source: CollectionSource;
  source_connection: CollectionConnection;
  arrival: ArrivalSelection;
}
export interface ScheduleSelection {
  name: string;
  workflow: Reference;
  source: SourceSelection;
  calendar: CalendarSelection;
  missed_run_policy: "skip" | "latest" | "all";
  max_catch_up: number;
  max_active_runs: number;
  max_files_per_occurrence: number;
  execution_deadline_seconds: number;
  late_start_grace_seconds: number;
  expected_authority_revision: number;
  arrival?: ArrivalSelection;
}
export interface ScheduleEffect {
  step_id: string;
  connection: Reference;
  address: string;
  directory: string;
  final_name_pattern: string;
  host_fingerprint: string;
  encryption?: { key: Reference; profile: string };
  recipient_fingerprint?: string;
  encryption_fingerprint?: string;
  protocol?: "ftps";
  user?: string;
  ftps?: FTPSConnectionProof;
}
export interface ScheduleDefinition {
  schema_version: 1 | 2;
  name: string;
  workflow: Reference;
  source: SourceSelection & { filename_regex: string };
  calendar: CalendarDefinition;
  missed_run_policy: ScheduleSelection["missed_run_policy"];
  max_catch_up: number;
  max_active_runs: number;
  max_files_per_occurrence: number;
  execution_deadline_seconds: number;
  late_start_grace_seconds: number;
  authority_revision: number;
  storage_id: string;
  namespace_root: "/";
  effects: ScheduleEffect[];
  collection?: ScheduleCollection;
  processing?: ScheduledProcessing;
}
export interface ScheduledProcessing {
  profile: "owned-record-processing-schedule-v1";
  task: ProcessingDefinition["processing"];
}
function scheduledProcessing(value: unknown): ScheduledProcessing {
  const o = object(value);
  if (
    o.profile !== "owned-record-processing-schedule-v1" ||
    Object.keys(o).sort().join(",") !== "profile,task"
  )
    bad();
  const definition = processingDefinition({
    schema_version: 3,
    name: "Scheduled processing task",
    steps: [],
    processing: o.task,
  });
  return {
    profile: "owned-record-processing-schedule-v1",
    task: definition.processing,
  };
}
export interface ScheduleSummary {
  id: string;
  version: number;
  name: string;
  definition_hash: string;
  state: "draft" | "active" | "suspended" | "revoked";
  revision: number;
  approval_authority: number;
  next_due: string | null;
  created_at: string;
  changed_event_id: string;
}
export interface SchedulePreview {
  definition: ScheduleDefinition;
  definition_hash: string;
  first_due: string | null;
  latest_due: string | null;
  upcoming: CalendarOccurrence[];
  effects: ScheduleEffect[];
  external_contact: false;
  approval_required: true;
}
export interface ScheduleView {
  schedule: ScheduleSummary & { definition: ScheduleDefinition };
  upcoming: CalendarOccurrence[];
  pending_runs: string[];
  pending_arrivals?: string[];
  active_runs: number;
  current_authority: boolean;
}
export interface Occurrence {
  id: string;
  schedule_id: string;
  schedule_version: number;
  due_at: string;
  deadline_at: string;
  kind: "queued" | "empty" | "missed" | "skipped" | "collection";
  skipped_until: string | null;
  input_count: number;
  event_id: string;
}
export interface OccurrenceView extends Occurrence {
  inputs: {
    schedule_id: string;
    schedule_version: number;
    occurrence_id: string;
    file_id: string;
    run_id: string;
    event_id: string;
  }[];
}
export interface ScheduleTick {
  kind: "workflow_schedule_tick";
  schedule: ScheduleSummary;
  occurrences: Occurrence[];
  run_ids: string[];
  reason: string;
  external_contact: false;
}
const bad = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
const str = (o: Record<string, unknown>, k: string, max = 256): string => {
  const v = o[k];
  if (
    typeof v !== "string" ||
    !v ||
    new TextEncoder().encode(v).length > max ||
    /[\u0000-\u001f\u007f]/.test(v)
  )
    bad();
  return v as string;
};
const num = (
  o: Record<string, unknown>,
  k: string,
  min = 1,
  max = Number.MAX_SAFE_INTEGER,
): number => {
  const n = o[k];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max)
    bad();
  return n as number;
};
const bool = (o: Record<string, unknown>, k: string): boolean => {
  if (typeof o[k] !== "boolean") bad();
  return o[k] as boolean;
};
const id = (o: Record<string, unknown>, k: string): string => {
  const v = str(o, k, 36);
  if (!uuid(v)) bad();
  return v;
};
const hash = (o: Record<string, unknown>, k: string): string => {
  const v = str(o, k, 64);
  if (!/^[a-f0-9]{64}$/.test(v)) bad();
  return v;
};
const same = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
const arr = (v: unknown, max: number): unknown[] => {
  if (!Array.isArray(v) || v.length > max) bad();
  return v as unknown[];
};
const date = (
  o: Record<string, unknown>,
  k: string,
  seconds = false,
): string => {
  const v = str(o, k, 40);
  if (
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) ||
    !Number.isFinite(Date.parse(v))
  )
    bad();
  if (new Date(v).toISOString().slice(0, 19) !== v.slice(0, 19)) bad();
  if (seconds && !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v)) bad();
  return v;
};
const nullableDate = (o: Record<string, unknown>, k: string): string | null =>
  o[k] === null ? null : date(o, k, true);
const canonicalPath = (v: string): string => {
  if (
    !v.startsWith("/") ||
    v.includes("\\") ||
    v.includes("//") ||
    (v !== "/" && v.endsWith("/")) ||
    v
      .split("/")
      .some((x) => x === "." || x === ".." || x.startsWith(".freightctl-"))
  )
    bad();
  return v;
};
function reference(v: unknown): Reference {
  const o = object(v);
  return { id: id(o, "id"), version: num(o, "version"), hash: hash(o, "hash") };
}
export function calendarSelection(v: unknown): CalendarSelection {
  const o = object(v),
    zone = str(o, "time_zone", 100),
    start = date(o, "starts_at", true),
    end = date(o, "ends_at", true),
    times = arr(o.local_times, 96).map((v) => {
      if (typeof v !== "string" || !/^([01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(v))
        bad();
      return v as string;
    }),
    weekdays = arr(o.weekdays, 7).map((v) => {
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 6)
        bad();
      return v as number;
    }),
    holidays = arr(o.holidays, 512).map((v) => {
      if (
        typeof v !== "string" ||
        !/^\d{4}-\d\d-\d\d$/.test(v) ||
        new Date(v + "T00:00:00Z").toISOString().slice(0, 10) !== v
      )
        bad();
      return v as string;
    });
  if (
    !/^[A-Za-z0-9_+/-]{1,100}$/.test(zone) ||
    zone === "Local" ||
    zone.startsWith("/") ||
    zone.includes("..") ||
    Date.parse(end) <= Date.parse(start) ||
    Date.parse(end) - Date.parse(start) > 5 * 366 * 86400000 ||
    !times.length ||
    !weekdays.length ||
    new Set(times).size !== times.length ||
    new Set(weekdays).size !== weekdays.length ||
    new Set(holidays).size !== holidays.length ||
    o.gap_policy !== "skip" ||
    !["first", "second", "both"].includes(String(o.fold_policy))
  )
    bad();
  return {
    time_zone: zone,
    starts_at: start,
    ends_at: end,
    local_times: times.sort(),
    weekdays: weekdays.sort((a, b) => a - b),
    holidays: holidays.sort(),
    gap_policy: "skip",
    fold_policy: o.fold_policy as CalendarSelection["fold_policy"],
  };
}
function calendar(v: unknown): CalendarDefinition {
  const o = object(v),
    c = calendarSelection(o),
    rules = arr(o.offset_rules, 64).map((v) => {
      const r = object(v);
      return {
        from: date(r, "from", true),
        until: date(r, "until", true),
        offset_seconds: num(r, "offset_seconds", -86400, 86400),
        abbreviation: str(r, "abbreviation", 32),
      };
    });
  if (
    !rules.length ||
    Date.parse(rules[0]!.from) !== Date.parse(c.starts_at) - 48 * 3600000 ||
    Date.parse(rules.at(-1)!.until) !== Date.parse(c.ends_at) + 48 * 3600000
  )
    bad();
  for (let i = 0; i < rules.length; i++) {
    const r = rules[i]!;
    if (
      Date.parse(r.until) <= Date.parse(r.from) ||
      (i > 0 && r.from !== rules[i - 1]!.until)
    )
      bad();
  }
  return { ...c, offset_rules: rules };
}
export function calendarContains(c: CalendarDefinition, at: string): boolean {
  const t = Date.parse(at);
  if (
    t < Date.parse(c.starts_at) ||
    t >= Date.parse(c.ends_at) ||
    t % 1000 !== 0
  )
    return false;
  const r = c.offset_rules.find(
    (r) => t >= Date.parse(r.from) && t < Date.parse(r.until),
  );
  if (!r) return false;
  const wall = t + r.offset_seconds * 1000,
    s = new Date(wall).toISOString(),
    clock = s.slice(11, 19),
    day = s.slice(0, 10);
  if (
    !c.local_times.includes(clock) ||
    !c.weekdays.includes(new Date(wall).getUTCDay()) ||
    c.holidays.includes(day)
  )
    return false;
  const candidates = c.offset_rules
    .map((r) => ({ r, t: wall - r.offset_seconds * 1000 }))
    .filter((x) => x.t >= Date.parse(x.r.from) && x.t < Date.parse(x.r.until))
    .map((x) => x.t)
    .sort((a, b) => a - b);
  return (
    candidates.includes(t) &&
    (c.fold_policy === "both" ||
      (c.fold_policy === "first"
        ? t === candidates[0]
        : t === candidates.at(-1)))
  );
}
function effect(v: unknown): ScheduleEffect {
  const o = object(v),
    step = str(o, "step_id", 64);
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(step)) bad();
  const ftps = o.protocol === "ftps";
  if (o.protocol !== undefined && !ftps) bad();
  if (ftps) {
    const expected = [
      "step_id",
      "connection",
      "address",
      "directory",
      "final_name_pattern",
      "host_fingerprint",
      "protocol",
      "user",
      "ftps",
      ...(o.encryption === undefined
        ? []
        : ["encryption", "recipient_fingerprint", "encryption_fingerprint"]),
    ];
    if (
      Object.keys(o).sort().join("\0") !== expected.sort().join("\0") ||
      o.host_fingerprint !== ""
    )
      bad();
  } else if (o.ftps !== undefined) bad();
  let encryption: ScheduleEffect["encryption"];
  if (o.encryption !== undefined) {
    const e = object(o.encryption),
      profile = str(e, "profile", 40);
    if (!["seipd-v1-aes256", "seipd-v2-aes256-ocb"].includes(profile)) bad();
    encryption = { key: reference(e.key), profile };
  }
  return {
    step_id: step,
    connection: reference(o.connection),
    address: str(o, "address", 300),
    directory: canonicalPath(str(o, "directory", 4096)),
    final_name_pattern: str(o, "final_name_pattern", 160),
    host_fingerprint: ftps ? "" : str(o, "host_fingerprint", 100),
    ...(encryption
      ? {
          encryption,
          recipient_fingerprint: str(o, "recipient_fingerprint", 100),
          encryption_fingerprint: str(o, "encryption_fingerprint", 100),
        }
      : {}),
    ...(ftps
      ? {
          protocol: "ftps" as const,
          user: str(o, "user", 256),
          ftps: asFTPSConnectionProof(
            o.ftps,
            canonicalPath(str(o, "directory", 4096)),
          ),
        }
      : {}),
  };
}
export function canonicalWorkflowBytes(d: unknown): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify(d).replace(
      /[<>&\u2028\u2029]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    ),
  );
}
export function scheduleHash(d: ScheduleDefinition): string {
  return digestBytes(canonicalWorkflowBytes(d));
}

export function asArrivalSelection(
  v: unknown,
  execution: number,
): ArrivalSelection {
  const o = object(v);
  if (Object.keys(o).length !== 3) bad();
  const a = {
    late_after_seconds: num(o, "late_after_seconds", 0, 604800),
    arrival_deadline_seconds: num(o, "arrival_deadline_seconds", 1, 604799),
    poll_interval_seconds: num(o, "poll_interval_seconds", 1, 3600),
  };
  if (
    a.arrival_deadline_seconds <= a.late_after_seconds ||
    a.arrival_deadline_seconds >= execution ||
    a.poll_interval_seconds > a.arrival_deadline_seconds ||
    Math.ceil(a.arrival_deadline_seconds / a.poll_interval_seconds) + 1 > 65536
  )
    bad();
  return a;
}
export function asScheduleDefinition(v: unknown): ScheduleDefinition {
  const o = object(v),
    processing = o.schema_version === 2,
    source = object(o.source),
    pattern = str(source, "filename_pattern", 160),
    remote =
      source.kind === "sftp.collect" ||
      source.kind === "ftps.collect" ||
      source.kind === "local.collect",
    regex = remote
      ? ""
      : "^" +
        pattern.replace(/[.*?]/g, (c) =>
          c === "." ? "[.]" : c === "*" ? ".*" : ".",
        ) +
        "$";
  if (
    (!processing && o.schema_version !== 1) ||
    processing !== (o.processing !== undefined) ||
    o.namespace_root !== "/" ||
    (remote
      ? source.recursive !== false
      : (processing
          ? source.kind !== "owned_released_records"
          : source.kind !== undefined) ||
        !/^[-A-Za-z0-9._*?]{1,128}$/.test(pattern)) ||
    source.filename_regex !== regex ||
    !["skip", "latest", "all"].includes(String(o.missed_run_policy))
  )
    bad();
  const effects = arr(o.effects, 16).map(effect);
  if (
    (!remote && !processing && !effects.length) ||
    (processing &&
      (remote || effects.length !== 0 || o.collection !== undefined)) ||
    new Set(effects.map((e) => e.step_id)).size !== effects.length
  )
    bad();
  for (const e of effects) {
    if (
      !/^<delivery UUID>-[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(
        e.final_name_pattern,
      )
    )
      bad();
  }
  const d: ScheduleDefinition = {
    schema_version: processing ? 2 : 1,
    name: str(o, "name"),
    workflow: reference(o.workflow),
    source: {
      directory: canonicalPath(str(source, "directory", 4096)),
      filename_pattern: pattern,
      recursive: bool(source, "recursive"),
      ...(processing
        ? { kind: "owned_released_records" as const }
        : remote
          ? {
              kind: source.kind as Exclude<
                CollectionSource["kind"],
                "webdav.collect"
              >,
            }
          : {}),
      filename_regex: regex,
    },
    calendar: calendar(o.calendar),
    missed_run_policy:
      o.missed_run_policy as ScheduleSelection["missed_run_policy"],
    max_catch_up: num(o, "max_catch_up", 1, 100),
    max_active_runs: num(o, "max_active_runs", 1, 64),
    max_files_per_occurrence: num(o, "max_files_per_occurrence", 1, 64),
    execution_deadline_seconds: num(o, "execution_deadline_seconds", 1, 604800),
    late_start_grace_seconds: num(o, "late_start_grace_seconds", 1, 3600),
    authority_revision: num(o, "authority_revision"),
    storage_id: id(o, "storage_id"),
    namespace_root: "/",
    effects,
  };
  if (remote) {
    const c = object(o.collection),
      input = asCollectionSource(c.source),
      connection = asCollectionConnection(c.source_connection),
      arrival = asArrivalSelection(c.arrival, d.execution_deadline_seconds);
    if (
      input.completion_contract !== scheduledCollectionContract ||
      input.kind !== d.source.kind ||
      (input.kind === "ftps.collect") !== (connection.protocol === "ftps") ||
      (input.kind === "local.collect") !== (connection.protocol === "local") ||
      input.manifest !== pattern ||
      input.target_directory !== d.source.directory ||
      input.max_files !== d.max_files_per_occurrence ||
      connection.state !== "active" ||
      !same(input.connection, {
        id: connection.id,
        version: connection.version,
        hash: connection.definition_hash,
      })
    )
      bad();
    d.collection = { source: input, source_connection: connection, arrival };
  } else if (o.collection !== undefined) bad();
  if (processing) d.processing = scheduledProcessing(o.processing);
  if (
    d.late_start_grace_seconds > d.execution_deadline_seconds ||
    canonicalWorkflowBytes(d).length > 24 * 1024
  )
    bad();
  return d;
}
function upcoming(v: unknown, c: CalendarDefinition): CalendarOccurrence[] {
  const list = arr(v, 12).map((v) => {
    const o = object(v),
      at = date(o, "at", true),
      r = c.offset_rules.find(
        (r) =>
          Date.parse(at) >= Date.parse(r.from) &&
          Date.parse(at) < Date.parse(r.until),
      );
    if (!r) return bad();
    if (
      !calendarContains(c, at) ||
      o.offset_seconds !== r.offset_seconds ||
      o.abbreviation !== r.abbreviation ||
      o.local_time !==
        new Date(Date.parse(at) + r.offset_seconds * 1000)
          .toISOString()
          .slice(0, 19)
    )
      bad();
    return {
      at,
      local_time: o.local_time as string,
      offset_seconds: r.offset_seconds,
      abbreviation: r.abbreviation,
    };
  });
  for (let i = 1; i < list.length; i++) {
    if (list[i]!.at <= list[i - 1]!.at) bad();
  }
  return list;
}
export function asSchedulePreview(
  v: unknown,
  selection: ScheduleSelection,
  authority: number,
): SchedulePreview {
  const o = object(v),
    d = asScheduleDefinition(o.definition),
    h = hash(o, "definition_hash"),
    normalized = {
      name: selection.name.normalize("NFC"),
      workflow: selection.workflow,
      source: selection.source,
      calendar: calendarSelection(selection.calendar),
      missed_run_policy: selection.missed_run_policy,
      max_catch_up: selection.max_catch_up,
      max_active_runs: selection.max_active_runs,
      max_files_per_occurrence: selection.max_files_per_occurrence,
      execution_deadline_seconds: selection.execution_deadline_seconds,
      late_start_grace_seconds: selection.late_start_grace_seconds,
      expected_authority_revision: selection.expected_authority_revision,
      ...(selection.arrival ? { arrival: selection.arrival } : {}),
    },
    actual = {
      name: d.name,
      workflow: d.workflow,
      source: {
        directory: d.source.directory,
        filename_pattern: d.source.filename_pattern,
        recursive: d.source.recursive,
        ...(d.source.kind ? { kind: d.source.kind } : {}),
      },
      calendar: calendarSelection(d.calendar),
      missed_run_policy: d.missed_run_policy,
      max_catch_up: d.max_catch_up,
      max_active_runs: d.max_active_runs,
      max_files_per_occurrence: d.max_files_per_occurrence,
      execution_deadline_seconds: d.execution_deadline_seconds,
      late_start_grace_seconds: d.late_start_grace_seconds,
      expected_authority_revision: d.authority_revision,
      ...(d.collection ? { arrival: d.collection.arrival } : {}),
    };
  if (
    scheduleHash(d) !== h ||
    !same(normalized, actual) ||
    d.authority_revision !== authority ||
    o.external_contact !== false ||
    o.approval_required !== true ||
    !same(arr(o.effects, 16).map(effect), d.effects)
  )
    bad();
  const first = nullableDate(o, "first_due"),
    latest = nullableDate(o, "latest_due");
  if (
    (first && !calendarContains(d.calendar, first)) ||
    (latest && !calendarContains(d.calendar, latest)) ||
    (first && latest && first > latest)
  )
    bad();
  return {
    definition: d,
    definition_hash: h,
    first_due: first,
    latest_due: latest,
    upcoming: upcoming(o.upcoming, d.calendar),
    effects: d.effects,
    external_contact: false,
    approval_required: true,
  };
}
export function asScheduleSummary(v: unknown): ScheduleSummary {
  const o = object(v);
  if (!["draft", "active", "suspended", "revoked"].includes(String(o.state)))
    bad();
  const s: ScheduleSummary = {
    id: id(o, "id"),
    version: num(o, "version"),
    name: str(o, "name"),
    definition_hash: hash(o, "definition_hash"),
    state: o.state as ScheduleSummary["state"],
    revision: num(o, "revision"),
    approval_authority: num(o, "approval_authority", 0),
    next_due: nullableDate(o, "next_due"),
    created_at: date(o, "created_at"),
    changed_event_id: id(o, "changed_event_id"),
  };
  if (
    (s.state === "draft" && s.approval_authority !== 0) ||
    (s.state === "active" && s.approval_authority === 0)
  )
    bad();
  return s;
}
export function asScheduleView(
  v: unknown,
  id0: string,
  version: number,
  authority: number,
): ScheduleView {
  const o = object(v),
    record = object(o.schedule),
    s = asScheduleSummary(record),
    d = asScheduleDefinition(record.definition),
    pending = arr(o.pending_runs, 64).map((v) => {
      if (typeof v !== "string" || !uuid(v)) bad();
      return v as string;
    });
  if (
    s.id !== id0 ||
    s.version !== version ||
    s.name !== d.name ||
    scheduleHash(d) !== s.definition_hash ||
    new Set(pending).size !== pending.length ||
    (s.next_due !== null && !calendarContains(d.calendar, s.next_due))
  )
    bad();
  const current = bool(o, "current_authority");
  if (
    current !==
    (s.state === "active" &&
      s.approval_authority === authority &&
      d.authority_revision === authority)
  )
    bad();
  return {
    schedule: { ...s, definition: d },
    upcoming: upcoming(o.upcoming, d.calendar),
    pending_runs: pending,
    active_runs: num(o, "active_runs", 0, 64),
    current_authority: current,
    ...(o.pending_arrivals === undefined
      ? {}
      : {
          pending_arrivals: (() => {
            const ids = arr(o.pending_arrivals, 64).map((v) => {
              if (typeof v !== "string" || !uuid(v)) bad();
              return v as string;
            });
            if (!d.collection || new Set(ids).size !== ids.length) bad();
            return ids;
          })(),
        }),
  };
}
export function asSchedulePage(v: unknown): {
  schedules: (ScheduleSummary & { active_version: number })[];
  next?: string;
} {
  const o = object(v),
    rows = arr(o.schedules, 100).map((v) => ({
      ...asScheduleSummary(v),
      active_version: num(object(v), "active_version", 0),
    }));
  if (new Set(rows.map((r) => r.id)).size !== rows.length) bad();
  const next = o.next === undefined ? undefined : id(o, "next");
  if (next && next !== rows.at(-1)?.id) bad();
  return { schedules: rows, ...(next ? { next } : {}) };
}
export function asScheduleResult(
  v: unknown,
  expected: {
    hash: string;
    id?: string;
    version: number;
    state: ScheduleSummary["state"];
    revision: number;
  },
): ScheduleSummary {
  const outer = object(v);
  bool(outer, "replayed");
  const r = object(outer.resource);
  if (r.kind !== "workflow_schedule") bad();
  const s = asScheduleSummary(r.schedule);
  if (
    s.definition_hash !== expected.hash ||
    (expected.id !== undefined && s.id !== expected.id) ||
    s.version !== expected.version ||
    s.state !== expected.state ||
    s.revision !== expected.revision
  )
    bad();
  return s;
}
export function asOccurrence(v: unknown, scheduleID?: string): Occurrence {
  const o = object(v),
    kind = str(o, "kind", 16);
  if (!["queued", "empty", "missed", "skipped", "collection"].includes(kind))
    bad();
  const r: Occurrence = {
    id: id(o, "id"),
    schedule_id: id(o, "schedule_id"),
    schedule_version: num(o, "schedule_version"),
    due_at: date(o, "due_at", true),
    deadline_at: date(o, "deadline_at", true),
    kind: kind as Occurrence["kind"],
    skipped_until: nullableDate(o, "skipped_until"),
    input_count: num(o, "input_count", 0, 64),
    event_id: id(o, "event_id"),
  };
  if (
    (scheduleID && scheduleID !== r.schedule_id) ||
    r.deadline_at <= r.due_at ||
    (kind === "queued") !== r.input_count > 0 ||
    (kind === "skipped") !== (r.skipped_until !== null) ||
    (r.skipped_until !== null && r.skipped_until <= r.due_at)
  )
    bad();
  return r;
}
export function asScheduleHistory(
  v: unknown,
  scheduleID: string,
): { occurrences: Occurrence[]; next?: string } {
  const o = object(v),
    rows = arr(o.occurrences, 100).map((v) => asOccurrence(v, scheduleID));
  if (new Set(rows.map((r) => r.id)).size !== rows.length) bad();
  const next = o.next === undefined ? undefined : id(o, "next");
  if (next && next !== rows.at(-1)?.id) bad();
  return { occurrences: rows, ...(next ? { next } : {}) };
}
export function asOccurrenceView(
  v: unknown,
  expected: Occurrence,
): OccurrenceView {
  const o = object(v),
    r = asOccurrence(o, expected.schedule_id);
  if (!same(r, expected)) bad();
  const inputs = arr(o.inputs, 64).map((v) => {
    const i = object(v);
    return {
      schedule_id: id(i, "schedule_id"),
      schedule_version: num(i, "schedule_version"),
      occurrence_id: id(i, "occurrence_id"),
      file_id: id(i, "file_id"),
      run_id: id(i, "run_id"),
      event_id: id(i, "event_id"),
    };
  });
  if (
    inputs.length !== r.input_count ||
    new Set(inputs.map((i) => i.file_id)).size !== inputs.length ||
    new Set(inputs.map((i) => i.run_id)).size !== inputs.length ||
    inputs.some(
      (i) =>
        i.schedule_id !== r.schedule_id ||
        i.schedule_version !== r.schedule_version ||
        i.occurrence_id !== r.id,
    )
  )
    bad();
  return { ...r, inputs };
}
export function asScheduleTick(
  v: unknown,
  expected: ScheduleSummary,
): ScheduleTick {
  const o = object(object(v).resource);
  bool(object(v), "replayed");
  if (o.kind !== "workflow_schedule_tick" || o.external_contact !== false)
    bad();
  const schedule = asScheduleSummary(o.schedule),
    occurrences = arr(o.occurrences, 100).map((v) =>
      asOccurrence(v, expected.id),
    ),
    runs = arr(o.run_ids, 64).map((v) => {
      if (typeof v !== "string" || !uuid(v)) bad();
      return v as string;
    });
  if (
    schedule.id !== expected.id ||
    schedule.version !== expected.version ||
    schedule.definition_hash !== expected.definition_hash ||
    schedule.revision < expected.revision ||
    new Set(occurrences.map((o) => o.id)).size !== occurrences.length ||
    new Set(runs).size !== runs.length ||
    occurrences.some((o) => o.schedule_version !== expected.version) ||
    occurrences.reduce((n, o) => n + o.input_count, 0) !== runs.length
  )
    bad();
  return {
    kind: "workflow_schedule_tick",
    schedule,
    occurrences,
    run_ids: runs,
    reason: str(o, "reason", 80),
    external_contact: false,
  };
}
export type SchedulableWorkflow = Reference & {
  name: string;
  source?: CollectionSource;
  processing?: ScheduledProcessing;
};
export function asSchedulableWorkflows(v: unknown): {
  workflows: SchedulableWorkflow[];
  next?: string;
} {
  const o = object(v),
    list = arr(o.workflows, 100).map((v) => {
      const r = object(v);
      if (r.source !== undefined && r.processing !== undefined) bad();
      return {
        ...reference(r),
        name: str(r, "name"),
        ...(r.source === undefined
          ? {}
          : { source: asCollectionSource(r.source) }),
        ...(r.processing === undefined
          ? {}
          : { processing: scheduledProcessing(r.processing) }),
      };
    });
  if (new Set(list.map((r) => r.id)).size !== list.length) bad();
  const next = o.next === undefined ? undefined : id(o, "next");
  if (next && next !== list.at(-1)?.id) bad();
  return { workflows: list, ...(next ? { next } : {}) };
}
export interface ScheduledRun {
  run: {
    id: string;
    file_id: string;
    source: {
      id: string;
      size_bytes: number;
      sha256: string;
      policy: string;
      accepted_event_id: string;
    };
    workflow_id: string;
    workflow_version: number;
    workflow_hash: string;
    authority_revision: number;
    execution_plan?: ExecutionPlan;
    execution_plan_hash?: string;
    routing_authorization_id?: string;
  };
  steps: { id: string; delivery_id: string; state: string; attempts: number }[];
  observed_state: string;
  observed_reason: string;
}
export function asScheduledRun(
  v: unknown,
  input: { run_id: string; file_id: string },
  definition: Pick<
    ScheduleDefinition,
    "workflow" | "authority_revision" | "effects"
  >,
  workflow?: AnyWorkflowConfiguration,
  expectedSource?: RoutingSource,
  expectedRoutingID?: string,
): ScheduledRun {
  const o = object(v),
    r = object(o.run),
    source = object(r.source),
    steps = arr(o.steps, 16).map((v) => {
      const s = object(v),
        state = str(s, "state", 24);
      if (
        ![
          "draft",
          "queued",
          "staging",
          "publishing",
          "succeeded",
          "retry",
          "blocked",
          "ambiguous",
          "cancelled",
        ].includes(state)
      )
        bad();
      return {
        id: str(s, "id", 64),
        delivery_id: id(s, "delivery_id"),
        state,
        attempts: num(s, "attempts", 0, 8),
      };
    }),
    run: ScheduledRun["run"] = {
      id: id(r, "id"),
      file_id: id(r, "file_id"),
      source: {
        id: id(source, "id"),
        size_bytes: num(source, "size_bytes", 0),
        sha256: hash(source, "sha256"),
        policy: str(source, "policy", 200),
        accepted_event_id: id(source, "accepted_event_id"),
      },
      workflow_id: id(r, "workflow_id"),
      workflow_version: num(r, "workflow_version"),
      workflow_hash: hash(r, "workflow_hash"),
      authority_revision: num(r, "authority_revision"),
    };
  if (r.routing_authorization_id !== expectedRoutingID) bad();
  if (expectedRoutingID !== undefined) {
    run.routing_authorization_id = id(r, "routing_authorization_id");
  }
  let selected = definition.effects.map((e) => e.step_id);
  if (workflow) {
    const wf = asWorkflowConfiguration(workflow, definition.workflow);
    effectsForWorkflow(definition.effects, wf.definition);
    if (wf.definition.schema_version === 2) {
      if (
        (wf.definition.source !== undefined) !==
        (expectedSource !== undefined)
      )
        bad();
      const plan = asExecutionPlan(
        r.execution_plan,
        workflowProgramShape(wf.definition),
        {
          file: run.source,
          ...(expectedSource ? { source: expectedSource } : {}),
        },
      );
      const planHash = hash(r, "execution_plan_hash");
      if (programFingerprint(plan) !== planHash) bad();
      run.execution_plan = plan;
      run.execution_plan_hash = planHash;
      selected = plan.selected_steps;
    } else if (
      r.execution_plan !== undefined ||
      r.execution_plan_hash !== undefined
    )
      bad();
  } else if (
    r.execution_plan !== undefined ||
    r.execution_plan_hash !== undefined
  )
    bad();
  if (
    run.id !== input.run_id ||
    run.file_id !== input.file_id ||
    run.source.id !== run.file_id ||
    run.workflow_id !== definition.workflow.id ||
    run.workflow_version !== definition.workflow.version ||
    run.workflow_hash !== definition.workflow.hash ||
    run.authority_revision !== definition.authority_revision ||
    steps.length !== selected.length ||
    steps.some((s, i) => s.id !== selected[i]) ||
    new Set(steps.map((s) => s.delivery_id)).size !== steps.length
  )
    bad();
  const state = str(o, "observed_state", 24);
  if (
    ![
      "queued",
      "running",
      "attention",
      "succeeded",
      "cancelled",
      "kept_local",
    ].includes(state) ||
    (state === "kept_local") !== !!run.execution_plan?.local_reason
  )
    bad();
  return {
    run,
    steps,
    observed_state: state,
    observed_reason: str(o, "observed_reason", 200),
  };
}
export function asScheduledWork(
  v: unknown,
  input: { run_id: string; file_id: string },
  definition: Pick<
    ScheduleDefinition,
    "workflow" | "authority_revision" | "effects"
  >,
  workflow?: AnyWorkflowConfiguration,
  expectedSource?: RoutingSource,
  expectedRoutingID?: string,
): ScheduledRun {
  const o = object(v);
  bool(o, "replayed");
  const d = object(o.dispatch),
    status = asScheduledRun(
      o.status,
      input,
      definition,
      workflow,
      expectedSource,
      expectedRoutingID,
    );
  if (
    d.run_id !== input.run_id ||
    !status.steps.some(
      (s) => s.id === d.step_id && s.delivery_id === d.delivery_id,
    )
  )
    bad();
  return status;
}

export { reference as asWorkflowReference, effect as asWorkflowEffect };
