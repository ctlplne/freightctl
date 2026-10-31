import { ApiError, object, uuid } from "./types";
import { digestBytes } from "./crypto";
import {
  asScheduleDefinition,
  asScheduleSummary,
  asWorkflowReference,
  canonicalWorkflowBytes,
  scheduleHash,
  calendarContains,
  type Reference,
  type Occurrence,
} from "./schedules-types";
import {
  asProducerManifest,
  asCollectionView,
  dueManifestName,
  type CollectionView,
  type ProducerManifest,
} from "./collections-types";

const bad = (): never => {
  throw new ApiError("invalid_server_response", 502);
};
function keys(
  o: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
) {
  if (
    required.some((k) => !(k in o)) ||
    Object.keys(o).some((k) => !required.includes(k) && !optional.includes(k))
  )
    bad();
}
const str = (o: Record<string, unknown>, k: string, max = 128): string => {
  const v = o[k];
  if (typeof v !== "string" || v.length > max) bad();
  return v as string;
};
const id = (o: Record<string, unknown>, k: string) => {
  const v = str(o, k, 36);
  if (!uuid(v)) bad();
  return v;
};
const hash = (o: Record<string, unknown>, k: string) => {
  const v = str(o, k, 64);
  if (!/^[a-f0-9]{64}$/.test(v)) bad();
  return v;
};
const num = (
  o: Record<string, unknown>,
  k: string,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
) => {
  const v = o[k];
  if (!Number.isSafeInteger(v) || Number(v) < min || Number(v) > max) bad();
  return v as number;
};
const bool = (o: Record<string, unknown>, k: string) => {
  if (typeof o[k] !== "boolean") bad();
  return o[k] as boolean;
};
const date = (o: Record<string, unknown>, k: string) => {
  const v = str(o, k, 40);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(v) ||
    !Number.isFinite(Date.parse(v))
  )
    bad();
  return v;
};
const same = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
// Preserve fractional UTC seconds; Date.parse truncates PostgreSQL microseconds.
const instantKey = (v: string) =>
  v.replace(
    /(?:\.(\d{1,9}))?Z$/,
    (_all, fraction: string | undefined) =>
      "." + (fraction ?? "").padEnd(9, "0") + "Z",
  );
const fingerprint = (a: unknown) => digestBytes(canonicalWorkflowBytes(a));
export const arrivalStates = [
  "waiting",
  "probing",
  "attention",
  "ready",
  "admitted",
  "missing",
  "expired",
  "cancelled",
] as const;
export type ArrivalState = (typeof arrivalStates)[number];
export interface ArrivalBinding {
  schema_version: 1;
  schedule: Reference;
  occurrence_id: string;
  due_at: string;
  late_after_at: string;
  arrival_deadline_at: string;
  deadline_at: string;
  manifest_name: string;
}
export interface Arrival {
  occurrence_id: string;
  schedule_id: string;
  schedule_version: number;
  definition: ArrivalBinding;
  definition_hash: string;
  state: ArrivalState;
  revision: number;
  fence: number;
  probes: number;
  lease_owner: string;
  lease_until: string | null;
  next_probe_at: string;
  observed_at: string | null;
  manifest: ProducerManifest | null;
  manifest_hash: string | null;
  collection_id: string | null;
  reason: string;
}
export interface ArrivalView {
  arrival: Arrival;
  schedule: ReturnType<typeof asScheduleSummary> & {
    definition: ReturnType<typeof asScheduleDefinition>;
  };
  current_authority: boolean;
  observed_state: string;
  arrival_timeliness: "not_observed" | "on_time" | "late";
  probe_due: boolean;
  collection?: CollectionView;
}
export function asArrivalView(
  v: unknown,
  expected: Occurrence,
  authority: number,
): ArrivalView {
  const o = object(v);
  keys(
    o,
    [
      "arrival",
      "schedule",
      "current_authority",
      "observed_state",
      "arrival_timeliness",
      "probe_due",
    ],
    ["collection"],
  );
  const record = object(o.schedule),
    summary = asScheduleSummary(record),
    d = asScheduleDefinition(record.definition),
    c = d.collection;
  if (
    !c ||
    expected.kind !== "collection" ||
    summary.id !== expected.schedule_id ||
    summary.version !== expected.schedule_version ||
    summary.name !== d.name ||
    summary.definition_hash !== scheduleHash(d)
  )
    bad();
  const raw = object(o.arrival),
    b = object(raw.definition);
  keys(b, [
    "schema_version",
    "schedule",
    "occurrence_id",
    "due_at",
    "late_after_at",
    "arrival_deadline_at",
    "deadline_at",
    "manifest_name",
  ]);
  if (b.schema_version !== 1) bad();
  const binding: ArrivalBinding = {
    schema_version: 1,
    schedule: asWorkflowReference(b.schedule),
    occurrence_id: id(b, "occurrence_id"),
    due_at: date(b, "due_at"),
    late_after_at: date(b, "late_after_at"),
    arrival_deadline_at: date(b, "arrival_deadline_at"),
    deadline_at: date(b, "deadline_at"),
    manifest_name: str(b, "manifest_name"),
  };
  if (
    !same(binding.schedule, {
      id: summary.id,
      version: summary.version,
      hash: summary.definition_hash,
    }) ||
    binding.occurrence_id !== expected.id ||
    binding.due_at !== expected.due_at ||
    binding.deadline_at !== expected.deadline_at ||
    !calendarContains(d.calendar, binding.due_at) ||
    binding.manifest_name !== dueManifestName(c!.source, binding.due_at) ||
    Date.parse(binding.late_after_at) - Date.parse(binding.due_at) !==
      c!.arrival.late_after_seconds * 1000 ||
    Date.parse(binding.arrival_deadline_at) - Date.parse(binding.due_at) !==
      c!.arrival.arrival_deadline_seconds * 1000 ||
    Date.parse(binding.deadline_at) - Date.parse(binding.due_at) !==
      d.execution_deadline_seconds * 1000
  )
    bad();
  keys(raw, [
    "occurrence_id",
    "schedule_id",
    "schedule_version",
    "definition",
    "definition_hash",
    "state",
    "revision",
    "fence",
    "probes",
    "lease_owner",
    "lease_until",
    "next_probe_at",
    "observed_at",
    "manifest",
    "manifest_hash",
    "collection_id",
    "reason",
  ]);
  const state = str(raw, "state") as ArrivalState;
  if (!arrivalStates.includes(state)) bad();
  const a: Arrival = {
    occurrence_id: id(raw, "occurrence_id"),
    schedule_id: id(raw, "schedule_id"),
    schedule_version: num(raw, "schedule_version", 1, 2147483647),
    definition: binding,
    definition_hash: hash(raw, "definition_hash"),
    state,
    revision: num(raw, "revision", 1),
    fence: num(raw, "fence", 0, 65536),
    probes: num(raw, "probes", 0, 65536),
    lease_owner: str(raw, "lease_owner", 36),
    lease_until: raw.lease_until === null ? null : date(raw, "lease_until"),
    next_probe_at: date(raw, "next_probe_at"),
    observed_at: raw.observed_at === null ? null : date(raw, "observed_at"),
    manifest:
      raw.manifest === null
        ? null
        : asProducerManifest(raw.manifest, c!.source),
    manifest_hash:
      raw.manifest_hash === null ? null : hash(raw, "manifest_hash"),
    collection_id: raw.collection_id === null ? null : id(raw, "collection_id"),
    reason: str(raw, "reason", 64),
  };
  const limit =
    Math.ceil(
      c!.arrival.arrival_deadline_seconds / c!.arrival.poll_interval_seconds,
    ) + 1;
  if (
    a.occurrence_id !== expected.id ||
    a.schedule_id !== summary.id ||
    a.schedule_version !== summary.version ||
    a.definition_hash !== fingerprint(binding) ||
    a.fence !== a.probes ||
    a.probes > limit ||
    !/^[a-z_]{1,64}$/.test(a.reason) ||
    Date.parse(a.next_probe_at) < Date.parse(binding.due_at) ||
    Date.parse(a.next_probe_at) > Date.parse(binding.arrival_deadline_at) ||
    (a.manifest === null) !== (a.manifest_hash === null) ||
    (a.manifest === null) !== (a.observed_at === null) ||
    (a.manifest && fingerprint(a.manifest) !== a.manifest_hash)
  )
    bad();
  if (
    state === "probing"
      ? !uuid(a.lease_owner) ||
        a.lease_until === null ||
        a.probes < 1 ||
        Date.parse(a.lease_until) > Date.parse(binding.arrival_deadline_at)
      : a.lease_owner !== "" || a.lease_until !== null
  )
    bad();
  if (
    (a.observed_at &&
      (Date.parse(a.observed_at) < Date.parse(binding.due_at) ||
        Date.parse(a.observed_at) >=
          Date.parse(binding.arrival_deadline_at))) ||
    (["ready", "admitted"].includes(state) && !a.manifest) ||
    (["waiting", "probing", "attention", "missing"].includes(state) &&
      a.manifest !== null) ||
    (state === "admitted" && a.collection_id === null) ||
    (a.collection_id !== null && !["admitted", "cancelled"].includes(state))
  )
    bad();
  const observed = str(o, "observed_state", 64),
    timeliness = str(o, "arrival_timeliness", 16),
    current = bool(o, "current_authority"),
    probe = bool(o, "probe_due");
  const expectedTimeliness =
    a.observed_at === null
      ? "not_observed"
      : instantKey(a.observed_at) > instantKey(binding.late_after_at)
        ? "late"
        : "on_time";
  if (
    timeliness !== expectedTimeliness ||
    ![
      state,
      ...(["waiting", "probing", "attention"].includes(state)
        ? ["late_waiting", "arrival_window_elapsed", "probe_budget_exhausted"]
        : state === "ready"
          ? ["execution_window_elapsed"]
          : []),
    ].includes(observed) ||
    (current &&
      (summary.state !== "active" ||
        summary.approval_authority !== authority ||
        d.authority_revision !== authority ||
        ["cancelled", "missing", "expired"].includes(state))) ||
    (probe &&
      (!["waiting", "probing", "attention"].includes(state) ||
        (observed !== "arrival_window_elapsed" &&
          (!current || a.probes >= limit))))
  )
    bad();
  let collection: CollectionView | undefined;
  if (a.collection_id !== null) {
    collection = asCollectionView(o.collection, a.collection_id, authority);
    const cb = collection.job.definition.schedule;
    if (
      !cb ||
      !same(cb.schedule, binding.schedule) ||
      cb.occurrence_id !== a.occurrence_id ||
      cb.due_at !== binding.due_at ||
      cb.arrival_deadline_at !== binding.arrival_deadline_at ||
      cb.deadline_at !== binding.deadline_at ||
      cb.manifest_name !== binding.manifest_name ||
      cb.manifest_hash !== a.manifest_hash
    )
      bad();
  } else if (o.collection !== undefined) bad();
  return {
    arrival: a,
    schedule: { ...summary, definition: d },
    current_authority: current,
    observed_state: observed,
    arrival_timeliness: timeliness as ArrivalView["arrival_timeliness"],
    probe_due: probe,
    ...(collection ? { collection } : {}),
  };
}
export function asArrivalResult(
  v: unknown,
  expected: Arrival,
  action: "probe" | "admit" | "cancel",
) {
  const o = object(v);
  keys(o, ["resource", "replayed"]);
  const r = object(o.resource);
  keys(r, [
    "kind",
    "occurrence_id",
    "definition_hash",
    "state",
    "revision",
    "collection_id",
    "manifest_hash",
    "external_contact",
  ]);
  const state = str(r, "state") as ArrivalState;
  if (
    r.kind !== "workflow_schedule_arrival" ||
    id(r, "occurrence_id") !== expected.occurrence_id ||
    hash(r, "definition_hash") !== expected.definition_hash ||
    !arrivalStates.includes(state) ||
    num(r, "revision", 1) < expected.revision ||
    (action === "cancel" && state !== "cancelled") ||
    (action === "admit" && !["admitted", "expired"].includes(state)) ||
    (action !== "probe" && bool(r, "external_contact"))
  )
    bad();
  if (r.collection_id !== null) id(r, "collection_id");
  if (r.manifest_hash !== null) hash(r, "manifest_hash");
  bool(o, "replayed");
  bool(r, "external_contact");
  return { resource: r, replayed: o.replayed as boolean };
}
