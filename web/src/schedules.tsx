import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { FTPSPeerIdentity, FTPSReceiverTerms } from "./ftps-peer-identity";
import {
  dueManifestName,
  asWorkflowConfiguration,
  type AnyWorkflowConfiguration,
  type CollectionSource,
} from "./collections-types";
import { PlanReview } from "./programs";
import { ScheduleArrival } from "./schedule-arrivals";
import { ProcessingTaskReview } from "./processing-task-review";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { operationKey } from "./crypto";
import { ApprovalConfirm, approvalPost } from "./onboarding-approvals";
import {
  asOccurrenceView,
  asSchedulableWorkflows,
  asScheduleHistory,
  asSchedulePage,
  asSchedulePreview,
  asScheduleResult,
  asScheduleTick,
  asScheduleView,
  asScheduledRun,
  asScheduledWork,
  type CalendarSelection,
  type Occurrence,
  type OccurrenceView,
  type Reference,
  type ScheduleDefinition,
  type SchedulePreview,
  type ScheduleSelection,
  type ScheduleSummary,
  type ScheduleView,
  type ScheduledRun,
  type SchedulableWorkflow,
} from "./schedules-types";
type Props = {
  api: Api;
  session: Session;
  refresh: number;
  onError: (e: unknown) => void;
  onProcessingRun?: (id: string) => void;
};
type Form = {
  name: string;
  source: string;
  pattern: string;
  recursive: boolean;
  zone: string;
  start: string;
  end: string;
  times: string;
  weekdays: number[];
  holidays: string;
  fold: CalendarSelection["fold_policy"];
  missed: ScheduleSelection["missed_run_policy"];
  catchup: number;
  active: number;
  files: number;
  deadline: number;
  grace: number;
  late: number;
  arrivalDeadline: number;
  poll: number;
};
type Pending =
  | {
      kind: "draft";
      key: string;
      preview: SchedulePreview;
      selection: ScheduleSelection;
      family?: { id: string; version: number };
    }
  | {
      kind: "control";
      key: string;
      action: "activate" | "suspend" | "revoke";
      schedule: ScheduleSummary;
      definition: ScheduleDefinition;
    }
  | {
      kind: "tick";
      key: string;
      schedule: ScheduleSummary;
      definition: ScheduleDefinition;
    }
  | {
      kind: "work";
      key: string;
      input: OccurrenceView["inputs"][number];
      definition: ScheduleDefinition;
      run: ScheduledRun;
      workflow: AnyWorkflowConfiguration;
      deadline: string;
    };
const utc = (t: number) =>
  new Date(Math.ceil(t / 1000) * 1000).toISOString().replace(".000Z", "Z");
const initial = (): Form => ({
  name: "",
  source: "",
  pattern: "*.csv",
  recursive: false,
  zone: "UTC",
  start: utc(Date.now() + 60000),
  end: utc(Date.now() + 7 * 86400000),
  times: "07:00:00",
  weekdays: [1, 2, 3, 4, 5],
  holidays: "",
  fold: "first",
  missed: "latest",
  catchup: 4,
  active: 1,
  files: 1,
  deadline: 3600,
  grace: 30,
  late: 300,
  arrivalDeadline: 1800,
  poll: 30,
});
function Field({
  label,
  children,
}: {
  label: string;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      {children(id)}
    </div>
  );
}
function Effects({ d }: { d: ScheduleDefinition }) {
  if (d.processing)
    return (
      <>
        <p>
          This calendar selects owned, released record inputs. Each occurrence
          records a separate processing intent under this exact approved task.
          Outputs remain held for fresh checks and a separate release. No
          delivery permission is granted.
        </p>
        <ProcessingTaskReview
          definition={{
            schema_version: 3,
            name: "Exact scheduled processing task",
            steps: [],
            processing: d.processing.task,
          }}
        />
      </>
    );
  return (
    <ul>
      {d.effects.map((e) => (
        <li key={e.step_id}>
          <strong>{e.step_id}</strong>:{" "}
          {e.protocol === "ftps" ? "FTPS" : "SFTP"} <code>{e.address}</code>,
          directory <code>{e.directory}</code>, final filename{" "}
          <code>{e.final_name_pattern}</code>.{" "}
          {e.ftps ? (
            <>
              <FTPSPeerIdentity proof={e.ftps} />{" "}
              <FTPSReceiverTerms proof={e.ftps} />{" "}
            </>
          ) : (
            <>
              Host fingerprint <code>{e.host_fingerprint}</code>.{" "}
            </>
          )}
          {e.encryption ? (
            <>
              Recipient <code>{e.recipient_fingerprint}</code>;{" "}
              {e.encryption.profile}.
            </>
          ) : (
            "No recipient encryption is configured."
          )}
        </li>
      ))}
    </ul>
  );
}
function Definition({ d }: { d: ScheduleDefinition }) {
  return (
    <>
      <p>
        {d.collection ? "Collect into " : "Watch "}
        <code>{d.source.directory}</code> for{" "}
        <code>{d.source.filename_pattern}</code>
        {d.source.recursive
          ? ", including readable subfolders"
          : " in this folder only"}
        . Only complete, checked, published revisions can be claimed. A revision
        is claimed once across this schedule’s versions.
      </p>
      <p>
        Time zone <strong>{d.calendar.time_zone}</strong>; frozen offset rules
        from {d.calendar.starts_at} to {d.calendar.ends_at}. Missing local times
        are skipped; repeated times use{" "}
        <strong>{d.calendar.fold_policy}</strong>. Local clock times:{" "}
        {d.calendar.local_times.join(", ")}. Weekdays:{" "}
        {d.calendar.weekdays
          .map(
            (i) =>
              [
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
              ][i],
          )
          .join(", ")}
        . Holidays: {d.calendar.holidays.join(", ") || "none"}.
      </p>
      <p>
        Missed-run rule <strong>{d.missed_run_policy}</strong>; skip-policy
        start grace {d.late_start_grace_seconds}s; execution cutoff{" "}
        {d.execution_deadline_seconds}s after each due time. Up to{" "}
        {d.max_catch_up} due decisions per request, {d.max_active_runs} current
        active runs, {d.max_files_per_occurrence} files per occurrence. The
        cutoff stops new scheduled processing or delivery effects. Outcomes
        retain the receipt contract of their exact task.
      </p>
      {d.collection && (
        <p>
          Read-only{" "}
          {d.collection.source.kind === "ftps.collect" ? "FTPS" : "SFTP"} source{" "}
          <code>{d.collection.source_connection.address}</code>, directory{" "}
          <code>{d.collection.source_connection.directory}</code>,{" "}
          {d.collection.source_connection.ftps ? (
            <FTPSPeerIdentity proof={d.collection.source_connection.ftps} />
          ) : (
            <>
              pinned host{" "}
              <code>{d.collection.source_connection.host_fingerprint}</code>.
            </>
          )}{" "}
          Mark an observed manifest late after{" "}
          {d.collection.arrival.late_after_seconds}s; stop observing after{" "}
          {d.collection.arrival.arrival_deadline_seconds}s; probe no faster than
          every {d.collection.arrival.poll_interval_seconds}s. Only verified
          immutable files enter ordinary intake.
        </p>
      )}
      <Effects d={d} />
    </>
  );
}
export function Schedules({
  api,
  session,
  refresh,
  onError,
  onProcessingRun,
}: Props) {
  const grants = session.identity.permissions,
    has = (g: string) => grants.includes(g),
    canDraft = has("workflow_manage") && has("list") && has("read"),
    canControl = has("workflow_approve"),
    canExecute = has("workflow_execute") && has("list") && has("read"),
    authority = session.identity.authority_revision;
  const [form, setForm] = useState(initial),
    [choices, setChoices] = useState<ReturnType<typeof asSchedulableWorkflows>>(
      { workflows: [] },
    ),
    [workflow, setWorkflow] = useState<SchedulableWorkflow | null>(null),
    [family, setFamily] = useState<{ id: string; version: number } | null>(
      null,
    ),
    [preview, setPreview] = useState<{
      value: SchedulePreview;
      selection: ScheduleSelection;
    } | null>(null),
    [page, setPage] = useState<ReturnType<typeof asSchedulePage>>({
      schedules: [],
    }),
    [selected, setSelected] = useState<ScheduleView | null>(null),
    [history, setHistory] = useState<ReturnType<typeof asScheduleHistory>>({
      occurrences: [],
    }),
    [occurrence, setOccurrence] = useState<OccurrenceView | null>(null),
    [run, setRun] = useState<{
      value: ScheduledRun;
      input: OccurrenceView["inputs"][number];
      workflow: AnyWorkflowConfiguration;
    } | null>(null),
    [pending, setPending] = useState<Pending | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [notice, setNotice] = useState("");
  const heading = useRef<HTMLHeadingElement>(null),
    previewHeading = useRef<HTMLHeadingElement>(null),
    runHeading = useRef<HTMLHeadingElement>(null),
    formHeading = useRef<HTMLHeadingElement>(null);
  const list = async (after = "") =>
    setPage(
      await api.request(
        `${api.prefix}/workflow-schedules?limit=20${after ? "&after=" + after : ""}`,
        {},
        asSchedulePage,
      ),
    );
  const loadChoices = async (after = "") =>
    setChoices(
      await api.request(
        `${api.prefix}/workflow-schedule-workflows?limit=20${after ? "&after=" + after : ""}`,
        {},
        asSchedulableWorkflows,
      ),
    );
  async function inspect(id: string, version: number) {
    const v = await api.request(
      `${api.prefix}/workflow-schedules/${id}/${version}`,
      {},
      (v) => asScheduleView(v, id, version, authority),
    );
    setSelected(v);
    setOccurrence(null);
    setRun(null);
    setHistory(
      await api.request(
        `${api.prefix}/workflow-schedules/${id}/history?limit=20`,
        {},
        (v) => asScheduleHistory(v, id),
      ),
    );
  }
  useEffect(() => {
    void list().catch(onError);
    if (canDraft) void loadChoices().catch(onError);
  }, [api, refresh, canDraft]);
  useEffect(() => {
    if (selected) heading.current?.focus();
  }, [
    selected?.schedule.id,
    selected?.schedule.version,
    selected?.schedule.revision,
  ]);
  useEffect(() => {
    if (preview) previewHeading.current?.focus();
  }, [preview]);
  useEffect(() => {
    if (run) runHeading.current?.focus();
  }, [run]);
  function edit(patch: Partial<Form>) {
    setForm((v) => ({ ...v, ...patch }));
    setPreview(null);
  }
  function selection(): ScheduleSelection {
    if (!workflow) throw new ApiError("invalid_workflow_schedule", 400);
    return {
      name: form.name,
      workflow: {
        id: workflow.id,
        version: workflow.version,
        hash: workflow.hash,
      },
      source: {
        directory: form.source,
        filename_pattern: form.pattern,
        recursive: workflow.source ? false : form.recursive,
        ...(workflow.processing
          ? { kind: "owned_released_records" as const }
          : workflow.source
            ? { kind: workflow.source.kind }
            : {}),
      },
      calendar: {
        time_zone: form.zone,
        starts_at: form.start,
        ends_at: form.end,
        local_times: form.times.split(/[\s,]+/).filter(Boolean),
        weekdays: form.weekdays,
        holidays: form.holidays.split(/[\s,]+/).filter(Boolean),
        gap_policy: "skip",
        fold_policy: form.fold,
      },
      missed_run_policy: form.missed,
      max_catch_up: form.catchup,
      max_active_runs: form.active,
      max_files_per_occurrence: form.files,
      execution_deadline_seconds: form.deadline,
      late_start_grace_seconds: form.grace,
      expected_authority_revision: authority,
      ...(workflow.source
        ? {
            arrival: {
              late_after_seconds: form.late,
              arrival_deadline_seconds: form.arrivalDeadline,
              poll_interval_seconds: form.poll,
            },
          }
        : {}),
    };
  }
  async function doPreview() {
    setBusy(true);
    setNotice("");
    try {
      const x = selection(),
        p = await approvalPost(
          api,
          `${api.prefix}/workflow-schedules/preview`,
          x,
          undefined,
          (v) => asSchedulePreview(v, x, authority),
        );
      setPreview({ value: p, selection: x });
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }
  function editRevision(v: ScheduleView) {
    const d = v.schedule.definition;
    setFamily({ id: v.schedule.id, version: v.schedule.version });
    setWorkflow({
      ...d.workflow,
      name: "Previously selected workflow",
      ...(d.collection ? { source: d.collection.source } : {}),
      ...(d.processing ? { processing: d.processing } : {}),
    });
    setForm({
      name: d.name,
      source: d.source.directory,
      pattern: d.source.filename_pattern,
      recursive: d.source.recursive,
      zone: d.calendar.time_zone,
      start: d.calendar.starts_at,
      end: d.calendar.ends_at,
      times: d.calendar.local_times.join(", "),
      weekdays: d.calendar.weekdays,
      holidays: d.calendar.holidays.join("\n"),
      fold: d.calendar.fold_policy,
      missed: d.missed_run_policy,
      catchup: d.max_catch_up,
      active: d.max_active_runs,
      files: d.max_files_per_occurrence,
      deadline: d.execution_deadline_seconds,
      grace: d.late_start_grace_seconds,
      late: d.collection?.arrival.late_after_seconds ?? 300,
      arrivalDeadline: d.collection?.arrival.arrival_deadline_seconds ?? 1800,
      poll: d.collection?.arrival.poll_interval_seconds ?? 30,
    });
    setPreview(null);
    requestAnimationFrame(() => formHeading.current?.focus());
  }
  async function confirm() {
    if (!pending) return;
    const p = pending;
    setBusy(true);
    setFailure("");
    try {
      if (p.kind === "draft") {
        const body = {
            ...(p.family ? { schedule_id: p.family.id } : {}),
            expected_version: p.family?.version ?? 0,
            selection: p.selection,
            definition_hash: p.preview.definition_hash,
          },
          r = await approvalPost(
            api,
            `${api.prefix}/workflow-schedules/drafts`,
            body,
            p.key,
            (v) =>
              asScheduleResult(v, {
                hash: p.preview.definition_hash,
                ...(p.family ? { id: p.family.id } : {}),
                version: (p.family?.version ?? 0) + 1,
                state: "draft",
                revision: 1,
              }),
          );
        setPending(null);
        setPreview(null);
        setNotice(
          "Draft saved. Review it and activate separately before a worker can queue files.",
        );
        await inspect(r.id, r.version);
        await list();
      } else if (p.kind === "control") {
        const r = await approvalPost(
          api,
          `${api.prefix}/workflow-schedules/${p.schedule.id}/${p.schedule.version}/${p.action}`,
          {
            definition_hash: p.schedule.definition_hash,
            expected_revision: p.schedule.revision,
          },
          p.key,
          (v) =>
            asScheduleResult(v, {
              hash: p.schedule.definition_hash,
              id: p.schedule.id,
              version: p.schedule.version,
              state:
                p.action === "activate"
                  ? "active"
                  : p.action === "suspend"
                    ? "suspended"
                    : "revoked",
              revision: p.schedule.revision + 1,
            }),
        );
        setPending(null);
        setNotice(
          "Original schedule decision recorded. Current status is shown below.",
        );
        await inspect(r.id, r.version);
        await list();
      } else if (p.kind === "tick") {
        const r = await approvalPost(
          api,
          `${api.prefix}/workflow-schedules/${p.schedule.id}/${p.schedule.version}/tick`,
          { limit: 1 },
          p.key,
          (v) => asScheduleTick(v, p.schedule),
        );
        setPending(null);
        setNotice(
          `Due-work decision: ${r.reason}. ${r.run_ids.length} runs queued. This action made no receiver contact.`,
        );
        await inspect(p.schedule.id, p.schedule.version);
        await list();
      } else {
        const r = await api.request(
          `${api.prefix}/workflow-runs/${p.input.run_id}/work`,
          { method: "POST", headers: { "Idempotency-Key": p.key } },
          (v) => asScheduledWork(v, p.input, p.definition, p.workflow),
          90000,
        );
        setPending(null);
        setRun({ value: r, input: p.input, workflow: p.workflow });
        setNotice(
          `Observed run state: ${r.observed_state}. Business acceptance needs a receiver contract.`,
        );
        if (selected) {
          const current = await api.request(
            `${api.prefix}/workflow-schedules/${selected.schedule.id}/${selected.schedule.version}`,
            {},
            (v) =>
              asScheduleView(
                v,
                selected.schedule.id,
                selected.schedule.version,
                authority,
              ),
          );
          setSelected(current);
          await list();
        }
      }
    } catch (e) {
      if (pending === p) {
        setFailure(
          "Schedule decision not confirmed. Retry this open review with the same operation key, or inspect private history before starting another operation.",
        );
        onError(e);
      }
    } finally {
      setBusy(false);
    }
  }
  const choose = (p: Pending) => {
    setFailure("");
    setPending(p);
  };
  async function showOccurrence(o: Occurrence) {
    const v = await api.request(
      `${api.prefix}/workflow-schedule-occurrences/${o.id}`,
      {},
      (v) => asOccurrenceView(v, o),
    );
    setOccurrence(v);
    setRun(null);
  }
  async function showRun(i: OccurrenceView["inputs"][number]) {
    if (!selected) return;
    let d = selected.schedule.definition;
    if (i.schedule_version !== selected.schedule.version) {
      const v = await api.request(
        `${api.prefix}/workflow-schedules/${i.schedule_id}/${i.schedule_version}`,
        {},
        (v) => asScheduleView(v, i.schedule_id, i.schedule_version, authority),
      );
      d = v.schedule.definition;
      setSelected(v);
    }
    if (d.processing) {
      if (!onProcessingRun)
        throw new ApiError("processing_inspection_unavailable", 409);
      onProcessingRun(i.run_id);
      return;
    }
    const wf = await api.request(
      `${api.prefix}/workflows/${d.workflow.id}/${d.workflow.version}`,
      {},
      (v) => asWorkflowConfiguration(v, d.workflow),
    );
    const v = await api.request(
      `${api.prefix}/workflow-runs/${i.run_id}`,
      {},
      (v) => asScheduledRun(v, i, d, wf),
    );
    setRun({ value: v, input: i, workflow: wf });
  }
  const currentChoice =
    workflow &&
    !choices.workflows.some(
      (w) => w.id === workflow.id && w.version === workflow.version,
    )
      ? [workflow]
      : [];
  return (
    <section aria-label="Workflow schedules">
      <h2>Workflow schedules</h2>
      <p>
        Queue complete published file revisions on a reviewed calendar. Each
        file revision is claimed once per schedule, including across
        configuration versions. Previewing, saving and queuing record control
        metadata. A separately started worker uses the exact approved task and
        its ordinary processing or delivery guards.
      </p>
      {notice && <p role="status">{notice}</p>}
      {canDraft && (
        <section aria-label="Prepare schedule">
          <h3 tabIndex={-1} ref={formHeading}>
            {family ? "Prepare next schedule revision" : "Prepare a schedule"}
          </h3>
          <form
            className="schedule-editor"
            onSubmit={(e) => {
              e.preventDefault();
              void doPreview();
            }}
          >
            <Field label="Schedule name">
              {(id) => (
                <input
                  id={id}
                  value={form.name}
                  required
                  maxLength={256}
                  onChange={(e) => edit({ name: e.target.value })}
                />
              )}
            </Field>
            <Field label="Approved workflow">
              {(id) => (
                <select
                  id={id}
                  required
                  value={workflow ? workflow.id + ":" + workflow.version : ""}
                  onChange={(e) => {
                    const v = [...currentChoice, ...choices.workflows].find(
                      (w) => w.id + ":" + w.version === e.target.value,
                    );
                    setWorkflow(v ?? null);
                    if (v?.source)
                      edit({
                        source: v.source.target_directory,
                        pattern: v.source.manifest,
                        recursive: false,
                        files: v.source.max_files,
                      });
                    setPreview(null);
                  }}
                >
                  <option value="">Choose an approved workflow</option>
                  {[...currentChoice, ...choices.workflows].map((w) => (
                    <option
                      key={w.id + ":" + w.version}
                      value={w.id + ":" + w.version}
                    >
                      {w.name} · version {w.version} · {w.id.slice(0, 8)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            {choices.next && (
              <button
                type="button"
                onClick={() => void loadChoices(choices.next).catch(onError)}
              >
                More approved workflows
              </button>
            )}
            <Field
              label={
                workflow?.source
                  ? "Approved collection target folder"
                  : "Published source folder"
              }
            >
              {(id) => (
                <input
                  id={id}
                  required
                  readOnly={!!workflow?.source}
                  value={form.source}
                  onChange={(e) => edit({ source: e.target.value })}
                />
              )}
            </Field>
            <Field label="Filename pattern">
              {(id) => (
                <input
                  id={id}
                  required
                  maxLength={160}
                  readOnly={!!workflow?.source}
                  value={form.pattern}
                  onChange={(e) => edit({ pattern: e.target.value })}
                />
              )}
            </Field>
            <p>
              Use letters, digits, dot, underscore, dash, * for any characters
              and ? for one character. A temporary upload or unchanged-size
              guess is never a complete file.
            </p>
            <label className="schedule-checkbox">
              <input
                type="checkbox"
                disabled={!!workflow?.source}
                checked={form.recursive}
                onChange={(e) => edit({ recursive: e.target.checked })}
              />
              Include readable subfolders
            </label>
            {workflow?.source && (
              <fieldset>
                <legend>Expected remote arrival</legend>
                <p>
                  The approved source and target are fixed by the workflow. Each
                  due time expects its own UTC manifest. Missing means no
                  verified ready manifest was observed before the arrival
                  cutoff.
                </p>
                {(
                  [
                    ["Late after due time (seconds)", "late", 0, 604798],
                    [
                      "Arrival cutoff after due time (seconds)",
                      "arrivalDeadline",
                      1,
                      604799,
                    ],
                    [
                      "Minimum time between source probes (seconds)",
                      "poll",
                      1,
                      3600,
                    ],
                  ] as const
                ).map(([label, key, min, max]) => (
                  <Field key={key} label={label}>
                    {(id) => (
                      <input
                        id={id}
                        type="number"
                        required
                        min={min}
                        max={max}
                        value={form[key]}
                        onChange={(e) =>
                          edit({ [key]: Number(e.target.value) })
                        }
                      />
                    )}
                  </Field>
                ))}
              </fieldset>
            )}
            <Field label="Time zone">
              {(id) => (
                <input
                  id={id}
                  required
                  value={form.zone}
                  placeholder="America/New_York"
                  onChange={(e) => edit({ zone: e.target.value })}
                />
              )}
            </Field>
            <Field label="Start of calendar (UTC)">
              {(id) => (
                <input
                  id={id}
                  required
                  value={form.start}
                  onChange={(e) => edit({ start: e.target.value })}
                />
              )}
            </Field>
            <Field label="End of calendar (UTC)">
              {(id) => (
                <input
                  id={id}
                  required
                  value={form.end}
                  onChange={(e) => edit({ end: e.target.value })}
                />
              )}
            </Field>
            <p>
              Use UTC timestamps ending in Z. The reviewed horizon is bounded to
              five years; a changed time-zone rule needs a new reviewed
              revision.
            </p>
            <Field label="Local clock times (HH:MM:SS)">
              {(id) => (
                <input
                  id={id}
                  required
                  value={form.times}
                  onChange={(e) => edit({ times: e.target.value })}
                />
              )}
            </Field>
            <fieldset className="schedule-weekdays">
              <legend>Business weekdays</legend>
              {[
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
              ].map((day, i) => (
                <label key={day} className="schedule-checkbox">
                  <input
                    type="checkbox"
                    checked={form.weekdays.includes(i)}
                    onChange={(e) =>
                      edit({
                        weekdays: e.target.checked
                          ? [...form.weekdays, i]
                          : form.weekdays.filter((x) => x !== i),
                      })
                    }
                  />
                  {day}
                </label>
              ))}
            </fieldset>
            <Field label="Holiday dates (YYYY-MM-DD)">
              {(id) => (
                <textarea
                  id={id}
                  value={form.holidays}
                  onChange={(e) => edit({ holidays: e.target.value })}
                />
              )}
            </Field>
            <p>
              Missing local clock times are skipped. Holidays are explicit local
              dates; no online calendar is fetched.
            </p>
            <Field label="Repeated local time">
              {(id) => (
                <select
                  id={id}
                  value={form.fold}
                  onChange={(e) =>
                    edit({ fold: e.target.value as Form["fold"] })
                  }
                >
                  <option value="first">First occurrence</option>
                  <option value="second">Second occurrence</option>
                  <option value="both">Both occurrences</option>
                </select>
              )}
            </Field>
            <Field label="Missed-run rule">
              {(id) => (
                <select
                  id={id}
                  value={form.missed}
                  onChange={(e) =>
                    edit({ missed: e.target.value as Form["missed"] })
                  }
                >
                  <option value="skip">
                    Skip starts beyond their grace window
                  </option>
                  <option value="latest">
                    Keep only the latest due occurrence
                  </option>
                  <option value="all">
                    Catch up all unexpired occurrences
                  </option>
                </select>
              )}
            </Field>
            <Field label="Start grace for skip rule (seconds)">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={3600}
                  required
                  value={form.grace}
                  onChange={(e) => edit({ grace: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field label="Execution cutoff after due time (seconds)">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={604800}
                  required
                  value={form.deadline}
                  onChange={(e) => edit({ deadline: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field label="Catch-up decisions per request">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={100}
                  required
                  value={form.catchup}
                  onChange={(e) => edit({ catchup: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field label="Maximum current active runs">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={64}
                  required
                  value={form.active}
                  onChange={(e) => edit({ active: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field label="Maximum files per occurrence">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={64}
                  required
                  readOnly={!!workflow?.source}
                  value={form.files}
                  onChange={(e) => edit({ files: Number(e.target.value) })}
                />
              )}
            </Field>
            <button disabled={busy}>Preview schedule</button>
            {family && (
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setFamily(null);
                  setPreview(null);
                  setForm(initial());
                  setWorkflow(null);
                }}
              >
                Prepare a separate schedule
              </button>
            )}
          </form>
        </section>
      )}
      {preview && (
        <section aria-label="Schedule preview">
          <h3 ref={previewHeading} tabIndex={-1}>
            Review schedule preview
          </h3>
          <Definition d={preview.value.definition} />
          <p>
            First due: {preview.value.first_due ?? "none"}. Most recent due:{" "}
            {preview.value.latest_due ?? "none"}. Future matching revisions may
            be claimed; this preview does not reserve any file.
          </p>
          <ul>
            {preview.value.upcoming.map((v) => (
              <li key={v.at}>
                {v.local_time} {v.abbreviation} → {v.at}
                {preview.value.definition.collection && (
                  <>
                    ; expected{" "}
                    <code>
                      {dueManifestName(
                        preview.value.definition.collection.source,
                        v.at,
                      )}
                    </code>
                  </>
                )}
              </li>
            ))}
          </ul>
          <p>
            Definition SHA-256 <code>{preview.value.definition_hash}</code>.
          </p>
          <button
            disabled={busy}
            onClick={() =>
              choose({
                kind: "draft",
                key: operationKey(),
                preview: preview.value,
                selection: preview.selection,
                ...(family ? { family } : {}),
              })
            }
          >
            Review saving schedule draft
          </button>
        </section>
      )}
      <section aria-label="Private schedule history">
        <h3>Your schedules</h3>
        <button disabled={busy} onClick={() => void list().catch(onError)}>
          Reload schedules
        </button>
        {!page.schedules.length && (
          <p>No saved schedules in this account’s history.</p>
        )}
        <ul>
          {page.schedules.map((s) => (
            <li key={s.id}>
              {s.name}: version {s.version}, {s.state}; active version{" "}
              {s.active_version || "none"}.{" "}
              <button
                disabled={busy}
                onClick={() => void inspect(s.id, s.version).catch(onError)}
              >
                Inspect schedule {s.name} version {s.version}
              </button>
              {s.active_version > 0 && s.active_version !== s.version && (
                <button
                  disabled={busy}
                  onClick={() =>
                    void inspect(s.id, s.active_version).catch(onError)
                  }
                >
                  Inspect active version {s.active_version} of {s.name}
                </button>
              )}
            </li>
          ))}
        </ul>
        {page.next && (
          <button onClick={() => void list(page.next).catch(onError)}>
            More schedules
          </button>
        )}
      </section>
      {selected && (
        <section aria-label="Selected schedule">
          <h3 ref={heading} tabIndex={-1}>
            Schedule: {selected.schedule.state}
          </h3>
          <p>
            {selected.schedule.name}, version {selected.schedule.version},
            revision {selected.schedule.revision}. Next due:{" "}
            {selected.schedule.next_due ?? "calendar exhausted"}. Current active
            runs: {selected.active_runs}.{" "}
            {selected.current_authority
              ? "Current schedule authority matches this account."
              : "Current authorization does not match this schedule revision."}
          </p>
          <Definition d={selected.schedule.definition} />
          <details className="schedule-references">
            <summary>Exact schedule references</summary>
            <p>
              Schedule <code>{selected.schedule.id}</code>; definition{" "}
              <code>{selected.schedule.definition_hash}</code>; workflow{" "}
              <code>{selected.schedule.definition.workflow.id}</code> version{" "}
              {selected.schedule.definition.workflow.version}; frozen account
              authority {selected.schedule.definition.authority_revision}.
            </p>
          </details>
          <button
            disabled={busy}
            onClick={() =>
              void inspect(
                selected.schedule.id,
                selected.schedule.version,
              ).catch(onError)
            }
          >
            Refresh selected schedule
          </button>
          {canDraft && (
            <button disabled={busy} onClick={() => editRevision(selected)}>
              Prepare next revision
            </button>
          )}
          {canControl && selected.schedule.state !== "revoked" && (
            <>
              {[
                ...(selected.schedule.state === "draft" ||
                selected.schedule.state === "suspended"
                  ? ["activate" as const]
                  : []),
                ...(selected.schedule.state === "active"
                  ? ["suspend" as const]
                  : []),
                "revoke" as const,
              ].map((action) => (
                <button
                  key={action}
                  disabled={busy || (action === "activate" && !canExecute)}
                  onClick={() =>
                    choose({
                      kind: "control",
                      key: operationKey(),
                      action,
                      schedule: selected.schedule,
                      definition: selected.schedule.definition,
                    })
                  }
                >
                  Review schedule {action}
                </button>
              ))}
            </>
          )}
          {canExecute && selected.current_authority && (
            <button
              disabled={busy}
              onClick={() =>
                choose({
                  kind: "tick",
                  key: operationKey(),
                  schedule: selected.schedule,
                  definition: selected.schedule.definition,
                })
              }
            >
              Review queuing due work
            </button>
          )}
          <p>
            Pending run references: {selected.pending_runs.length}. Inspect
            occurrence history to review their exact source files and receipts.
          </p>
          <h4>Occurrence history</h4>
          <ul>
            {history.occurrences.map((o) => (
              <li key={o.id}>
                {o.due_at}: {o.kind}, {o.input_count} claimed files, version{" "}
                {o.schedule_version}.{" "}
                <button
                  disabled={busy}
                  onClick={() => void showOccurrence(o).catch(onError)}
                >
                  Inspect occurrence {o.id.slice(0, 8)}
                </button>
              </li>
            ))}
          </ul>
          {history.next && (
            <button
              onClick={() =>
                void api
                  .request(
                    `${api.prefix}/workflow-schedules/${selected.schedule.id}/history?limit=20&after=${history.next}`,
                    {},
                    (v) => asScheduleHistory(v, selected.schedule.id),
                  )
                  .then(setHistory)
                  .catch(onError)
              }
            >
              More occurrences
            </button>
          )}
        </section>
      )}
      {occurrence?.kind === "collection" && (
        <ScheduleArrival
          key={occurrence.id}
          api={api}
          session={session}
          occurrence={occurrence}
          refresh={refresh}
          onError={onError}
        />
      )}
      {occurrence && (
        <section aria-label="Selected occurrence">
          <h3>Occurrence: {occurrence.kind}</h3>
          <p>
            Due {occurrence.due_at}; execution cutoff {occurrence.deadline_at}.{" "}
            {occurrence.skipped_until && (
              <>Skipped interval ends before {occurrence.skipped_until}.</>
            )}
          </p>
          <ul>
            {occurrence.inputs.map((i) => (
              <li key={i.run_id}>
                Accepted revision <code>{i.file_id}</code>.{" "}
                <button
                  disabled={busy}
                  onClick={() => void showRun(i).catch(onError)}
                >
                  Inspect scheduled run {i.run_id.slice(0, 8)}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
      {run && selected && occurrence && (
        <section aria-label="Selected scheduled run">
          <h3 ref={runHeading} tabIndex={-1}>
            Scheduled run: {run.value.observed_state}
          </h3>
          <p>
            Run <code>{run.value.run.id}</code>; accepted revision{" "}
            <code>{run.value.run.file_id}</code>;{" "}
            {run.value.run.source.size_bytes} bytes, SHA-256{" "}
            <code>{run.value.run.source.sha256}</code>. Reason:{" "}
            {run.value.observed_reason}.
          </p>
          {run.value.run.execution_plan && (
            <PlanReview plan={run.value.run.execution_plan} />
          )}
          <ul>
            {run.value.steps.map((s) => (
              <li key={s.id}>
                {s.id}: {s.state}, {s.attempts} attempts. Delivery{" "}
                <code>{s.delivery_id}</code>.
              </li>
            ))}
          </ul>
          {canExecute &&
            run.value.observed_state !== "succeeded" &&
            run.value.observed_state !== "cancelled" &&
            run.value.observed_state !== "kept_local" && (
              <button
                disabled={busy}
                onClick={() =>
                  choose({
                    kind: "work",
                    key: operationKey(),
                    input: run.input,
                    definition: selected.schedule.definition,
                    run: run.value,
                    workflow: run.workflow,
                    deadline: occurrence.deadline_at,
                  })
                }
              >
                Review executing next scheduled step
              </button>
            )}
        </section>
      )}
      {pending && (
        <ApprovalConfirm
          title={
            pending.kind === "draft"
              ? "Save reviewed schedule draft"
              : pending.kind === "control"
                ? "Confirm schedule " + pending.action
                : pending.kind === "tick"
                  ? "Queue reviewed due work"
                  : "Execute scheduled workflow step"
          }
          busy={busy}
          failure={failure}
          onCancel={() => {
            setPending(null);
            setFailure("");
          }}
          onConfirm={() => void confirm()}
        >
          {pending.kind === "draft" ? (
            <>
              <p>
                This saves exact metadata and sends no bytes. Activation is
                separate.
              </p>
              <Definition d={pending.preview.definition} />
              <p>
                Definition SHA-256{" "}
                <code>{pending.preview.definition_hash}</code>.
              </p>
            </>
          ) : pending.kind === "control" ? (
            <>
              <p>
                {pending.definition.processing
                  ? pending.action === "activate"
                    ? "Activation allows a separately started worker to select owned released inputs under this exact approved task. It suspends the previous active version. Each output needs fresh checks and separate release."
                    : "This stops future processing under this calendar version. Existing artifacts remain in custody and receipts retain their recorded meaning."
                  : pending.action === "activate"
                    ? "Activation allows a separately started worker to claim future matching published revisions under this exact definition. It suspends the previous active version. Existing claims and queued intent meanings remain unchanged; their old authority cannot authorize a new send."
                    : "This stops future sending under this version. Existing bytes and receipts remain intact; it cannot recall receiver bytes."}
              </p>
              <p>
                Schedule <code>{pending.schedule.id}</code>, version{" "}
                {pending.schedule.version}, exact revision{" "}
                {pending.schedule.revision} and hash{" "}
                <code>{pending.schedule.definition_hash}</code>.
              </p>
              <Definition d={pending.definition} />
            </>
          ) : pending.kind === "tick" ? (
            <>
              <Definition d={pending.definition} />
              <p>
                This makes at most one due occurrence decision and queues
                ordinary workflow intents within the configured file and
                concurrency bounds. It sends no bytes and does not bypass
                independent file approval. Exact schedule{" "}
                <code>{pending.schedule.id}</code>, version{" "}
                {pending.schedule.version}, hash{" "}
                <code>{pending.schedule.definition_hash}</code>.
              </p>
            </>
          ) : (
            <>
              <p>
                This may contact the registered receiver and execute the next
                available step of this exact run. The server rechecks current
                schedule, source, connection, account and dispatch approval
                before and during sending. Cutoff {pending.deadline}. Source{" "}
                <code>{pending.run.run.source.sha256}</code>,{" "}
                {pending.run.run.source.size_bytes} bytes. Existing receipts are
                preserved.
              </p>
              <Effects d={pending.definition} />
              {pending.run.run.execution_plan && (
                <PlanReview plan={pending.run.run.execution_plan} />
              )}
            </>
          )}
        </ApprovalConfirm>
      )}
    </section>
  );
}
