import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, type CheckView } from "./types";

export function CheckRecovery({
  view,
  api,
  onUpdated,
  onError,
}: {
  view: CheckView;
  api: Api;
  onUpdated: (v: CheckView) => void;
  onError: (e: unknown) => void;
}) {
  const [review, setReview] = useState<CheckView | null>(null),
    [acting, setActing] = useState(false),
    [failure, setFailure] = useState(""),
    [blocked, setBlocked] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (review) {
      dialog.current?.showModal();
      title.current?.focus();
    } else dialog.current?.close();
  }, [review]);
  if (view.check.state !== "running") return null;
  const recovery = view.recovery;
  const descriptions: Record<string, string> = {
    lease_active:
      "The original worker still owns its reservation. The server must wait for that reservation to expire before admitting a replacement.",
    ready:
      "The server observed an expired reservation. You may review a replacement attempt for these same bytes and policy.",
    attempt_budget_exhausted:
      "All three attempts are used. An administrator must review further recovery; this action cannot reset the budget.",
    authority_or_policy_changed:
      "Access, storage or policy changed. An administrator must review this revision before any replacement.",
    permission_denied:
      "This identity needs read and check_run permission to replace this attempt.",
  };
  const refresh = async () => {
    try {
      const next = await api.check(view.check.file_id);
      if (alive.current) onUpdated(next);
    } catch (e) {
      if (alive.current) onError(e);
    }
  };
  const recover = async () => {
    if (!review?.recovery || acting || blocked) return;
    setActing(true);
    setFailure("");
    try {
      const next = await api.recoverCheck(review, review.recovery.decision);
      if (!alive.current) return;
      setReview(null);
      onUpdated(next);
    } catch (e) {
      if (!alive.current) return;
      const definitive =
        e instanceof ApiError && e.status >= 400 && e.status < 500;
      setBlocked(definitive);
      setFailure(
        definitive
          ? "The server refused this reviewed recovery. Cancel, refresh status and review its current reservation again."
          : "Recovery was not confirmed. Retry this same reviewed command to recover its original receipt.",
      );
      onError(e);
    } finally {
      if (alive.current) setActing(false);
    }
  };
  return (
    <div className="signature-box" aria-label="Check worker reservation">
      <h3>Check worker reservation</h3>
      <p>
        A lease is the worker’s temporary reservation. A replacement gets a new
        reservation; the former worker can no longer save a result for it.
      </p>
      <p>
        {recovery
          ? descriptions[recovery.code]
          : "Refresh status to read the server’s current worker reservation. Recovery needs matching server metadata."}
      </p>
      {recovery && (
        <dl className="facts">
          <dt>Reservation ends</dt>
          <dd>
            <time dateTime={recovery.decision.expected_lease_until}>
              {recovery.decision.expected_lease_until}
            </time>
          </dd>
          <dt>Server observed time</dt>
          <dd>
            <time dateTime={recovery.observedAt}>{recovery.observedAt}</time>
          </dd>
          <dt>Attempts already used</dt>
          <dd>{view.check.attempts} of 3</dd>
        </dl>
      )}
      <div className="actions">
        <button
          className="secondary"
          disabled={acting}
          onClick={() => void refresh()}
        >
          Refresh worker status
        </button>
        <button
          className="primary"
          disabled={acting || !view.current || !recovery?.eligible}
          onClick={() => {
            setFailure("");
            setBlocked(false);
            setReview(view);
          }}
        >
          Recover expired check
        </button>
      </div>
      <dialog
        ref={dialog}
        aria-labelledby="recovery-title"
        onCancel={(e) => {
          if (acting) e.preventDefault();
          else setReview(null);
        }}
      >
        <h2 id="recovery-title" ref={title} tabIndex={-1}>
          Recover this check?
        </h2>
        {review?.recovery && (
          <>
            <p>
              Start the next bounded attempt for this exact file and policy. The
              server rechecks the reservation and current authority under the
              same database lock as the replacement claim. The file stays held
              until checks pass and release is separately approved.
            </p>
            <dl className="facts">
              <dt>File revision</dt>
              <dd>
                <code>{review.check.file_id}</code>
              </dd>
              <dt>Source SHA-256</dt>
              <dd>
                <code>{review.recovery.decision.sha256}</code>
              </dd>
              <dt>Policy SHA-256</dt>
              <dd>
                <code>{review.recovery.decision.policy_hash}</code>
              </dd>
              <dt>Expected check revision</dt>
              <dd>{review.recovery.decision.expected_revision}</dd>
              <dt>Original worker reservation</dt>
              <dd>
                <code>{review.recovery.decision.expected_worker_id}</code>
              </dd>
              <dt>Original reservation ends</dt>
              <dd>{review.recovery.decision.expected_lease_until}</dd>
              <dt>Next attempt</dt>
              <dd>{review.check.attempts + 1} of 3</dd>
            </dl>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                className="primary"
                disabled={acting || blocked}
                onClick={() => void recover()}
              >
                {acting
                  ? "Checking…"
                  : failure
                    ? "Retry reviewed recovery"
                    : "Start replacement check"}
              </button>
              <button
                className="secondary"
                disabled={acting}
                onClick={() => setReview(null)}
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </dialog>
    </div>
  );
}
