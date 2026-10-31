import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import type { Session } from "./types";
import type { Occurrence } from "./schedules-types";
import { operationKey } from "./crypto";
import { ApprovalConfirm } from "./onboarding-approvals";
import {
  asArrivalView,
  asArrivalResult,
  type ArrivalView,
} from "./arrivals-types";
import { Collections } from "./collections";

type Props = {
  api: Api;
  session: Session;
  occurrence: Occurrence;
  refresh: number;
  onError: (e: unknown) => void;
};
type Pending = {
  action: "probe" | "admit" | "cancel";
  view: ArrivalView;
  key: string;
};
export function ScheduleArrival({
  api,
  session,
  occurrence,
  refresh,
  onError,
}: Props) {
  const [view, setView] = useState<ArrivalView | null>(null),
    [pending, setPending] = useState<Pending | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [notice, setNotice] = useState(""),
    [jobRefresh, setJobRefresh] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null),
    authority = session.identity.authority_revision;
  const canExecute = session.identity.permissions.includes("workflow_execute");
  async function inspect() {
    setView(
      await api.request(
        api.prefix + "/workflow-schedule-arrivals/" + occurrence.id,
        {},
        (v) => asArrivalView(v, occurrence, authority),
      ),
    );
  }
  useEffect(() => {
    void inspect().catch(onError);
  }, [api, occurrence.id, refresh]);
  useEffect(() => {
    if (view) heading.current?.focus();
  }, [view?.arrival.occurrence_id]);
  function review(action: Pending["action"]) {
    if (!view) return;
    setFailure("");
    setPending({ action, view: structuredClone(view), key: operationKey() });
  }
  async function confirm() {
    if (!pending) return;
    const p = pending,
      a = p.view.arrival;
    setBusy(true);
    setFailure("");
    try {
      const body = {
        definition_hash: a.definition_hash,
        ...(p.action === "probe" ? {} : { expected_revision: a.revision }),
      };
      await api.request(
        api.prefix +
          "/workflow-schedule-arrivals/" +
          a.occurrence_id +
          "/" +
          p.action,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": p.key,
          },
          body: JSON.stringify(body),
        },
        (v) => asArrivalResult(v, a, p.action),
        45000,
      );
      setPending(null);
      setNotice("Original arrival decision recorded. Reloaded status follows.");
      await inspect();
      setJobRefresh((n) => n + 1);
    } catch (e) {
      setFailure(
        "Decision not confirmed. Retry this open review with its original operation key, or close and inspect durable status before starting another operation.",
      );
      onError(e);
    } finally {
      setBusy(false);
    }
  }
  if (!view) return <p role="status">Loading expected arrival…</p>;
  const a = view.arrival,
    b = a.definition,
    c = view.schedule.definition.collection!;
  return (
    <section aria-label="Expected scheduled arrival">
      <h3 ref={heading} tabIndex={-1}>
        Expected arrival: {view.observed_state.replaceAll("_", " ")}
      </h3>
      <p>
        Manifest <code>{b.manifest_name}</code> for due time{" "}
        <time dateTime={b.due_at}>{b.due_at}</time>. Late after{" "}
        <time dateTime={b.late_after_at}>{b.late_after_at}</time>; arrival
        cutoff{" "}
        <time dateTime={b.arrival_deadline_at}>{b.arrival_deadline_at}</time>;
        collection and sending cutoff{" "}
        <time dateTime={b.deadline_at}>{b.deadline_at}</time>.
      </p>
      <p>
        Read-only source <code>{c.source_connection.address}</code>, folder{" "}
        <code>{c.source_connection.directory}</code>, pinned host{" "}
        <code>{c.source_connection.host_fingerprint}</code>. Local target{" "}
        <code>{c.source.target_directory}</code>. {c.source.max_files} files, at
        most {c.source.max_file_bytes} bytes each and {c.source.max_total_bytes}{" "}
        bytes in total.
      </p>
      <p>
        Verified arrival: {view.arrival_timeliness.replaceAll("_", " ")}.{" "}
        {a.observed_at && <time dateTime={a.observed_at}>{a.observed_at}</time>}{" "}
        A missing result means no eligible verified manifest was observed by the
        cutoff; it cannot prove when a producer published bytes.
      </p>
      <p>
        {a.probes} source probes. Minimum interval{" "}
        {c.arrival.poll_interval_seconds}s; next eligible observation{" "}
        <time dateTime={a.next_probe_at}>{a.next_probe_at}</time>. Waiting does
        not consume the collection worker’s eight byte-transfer attempts.{" "}
        {a.lease_until && (
          <>
            Original probe lease ends{" "}
            <time dateTime={a.lease_until}>{a.lease_until}</time>; replacement
            workers wait for this boundary.
          </>
        )}
      </p>
      {a.manifest && (
        <p>
          Frozen ready manifest SHA-256 <code>{a.manifest_hash}</code>,{" "}
          {a.manifest.files.length} immutable files. Waiting for collection
          capacity cannot change this snapshot.
        </p>
      )}
      <p>
        {view.current_authority
          ? "Current calendar and source authority match."
          : "Current authority or cutoff blocks new source work. Historical observations remain available."}
      </p>
      {notice && <p role="status">{notice}</p>}
      <button disabled={busy} onClick={() => void inspect().catch(onError)}>
        Reload arrival status
      </button>
      {canExecute && view.probe_due && (
        <button disabled={busy} onClick={() => review("probe")}>
          {view.observed_state === "arrival_window_elapsed"
            ? "Review recording missing arrival"
            : "Review reading expected manifest"}
        </button>
      )}
      {canExecute &&
        a.state === "ready" &&
        (view.current_authority ||
          view.observed_state === "execution_window_elapsed") && (
          <button disabled={busy} onClick={() => review("admit")}>
            Review collection admission
          </button>
        )}
      {canExecute && !["cancelled", "missing", "expired"].includes(a.state) && (
        <button disabled={busy} onClick={() => review("cancel")}>
          Review stopping this occurrence
        </button>
      )}
      <details className="schedule-references">
        <summary>Exact arrival references</summary>
        <p>
          Occurrence <code>{a.occurrence_id}</code>; schedule{" "}
          <code>{a.schedule_id}</code> version {a.schedule_version}; arrival
          revision {a.revision}, fence {a.fence}, definition{" "}
          <code>{a.definition_hash}</code>. Recorded reason:{" "}
          {a.reason.replaceAll("_", " ")}. Business acceptance remains unknown
          without a receiver contract.
        </p>
      </details>
      {view.collection && (
        <Collections
          key={view.collection.job.id}
          api={api}
          session={session}
          refresh={refresh + jobRefresh}
          onError={onError}
          onConfirmed={setNotice}
          jobID={view.collection.job.id}
          jobHash={view.collection.job.definition_hash}
        />
      )}
      {pending && (
        <ApprovalConfirm
          title={
            pending.action === "probe"
              ? "Read the reviewed expected manifest"
              : pending.action === "admit"
                ? "Admit the frozen scheduled collection"
                : "Stop further work for this occurrence"
          }
          busy={busy}
          failure={failure}
          onConfirm={() => void confirm()}
          onCancel={() => {
            setPending(null);
            setFailure("");
          }}
        >
          <p>
            Exact occurrence <code>{pending.view.arrival.occurrence_id}</code>,
            definition <code>{pending.view.arrival.definition_hash}</code>,
            revision {pending.view.arrival.revision}. Expected manifest{" "}
            <code>{pending.view.arrival.definition.manifest_name}</code>.
          </p>
          <p>
            {pending.action === "probe"
              ? "This can make one bounded read from the approved source. It records absence, a verified immutable manifest, or attention. After the arrival cutoff it records missing without source contact."
              : pending.action === "admit"
                ? "This records a collection job for the already frozen manifest without contacting the source. It keeps the original execution cutoff. A later ordinary collection worker verifies bytes; intake and independent dispatch approval still apply."
                : "This blocks future source work and sending for this occurrence. Already captured local bytes and receiver copies remain; cancellation cannot recall them."}
          </p>
          <p>
            Original operation key <code>{pending.key}</code>. Keep this review
            open for an exact retry after a lost response.
          </p>
        </ApprovalConfirm>
      )}
    </section>
  );
}
