import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, uuid } from "./types";
import { RechecksApi } from "./rechecks-api";
import {
  type Recheck,
  type RecheckPreview,
  type RecheckView,
  type RecheckMode,
} from "./rechecks-types";

type Review =
  | { operation: "propose"; preview: RecheckPreview; key: string }
  | {
      operation: "approve" | "cancel" | "copy";
      row: Recheck;
      previous?: unknown;
      policy?: unknown;
    };
export function FileRechecks({
  api,
  sourceId,
  path,
  onCopied,
  onError,
}: {
  api: Api;
  sourceId: string;
  path: string;
  onCopied: (id: string) => void;
  onError: (e: unknown) => void;
}) {
  const client = useMemo(() => new RechecksApi(api), [api]),
    [source, setSource] = useState(sourceId),
    [target, setTarget] = useState(path),
    [mode, setMode] = useState<RecheckMode>("not_required"),
    [reason, setReason] = useState("");
  const [preview, setPreview] = useState<RecheckPreview | null>(null),
    [rows, setRows] = useState<Recheck[]>([]),
    [next, setNext] = useState(""),
    [after, setAfter] = useState(""),
    [selected, setSelected] = useState<RecheckView | null>(null),
    [review, setReview] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [blocked, setBlocked] = useState(false);
  const alive = useRef(true),
    currentSource = useRef(source),
    dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    selectedTitle = useRef<HTMLHeadingElement>(null),
    returnFocus = useRef<HTMLElement | null>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (review) {
      returnFocus.current = document.activeElement as HTMLElement;
      dialog.current?.showModal();
      title.current?.focus();
    } else {
      dialog.current?.close();
      returnFocus.current?.focus();
    }
  }, [review]);
  useLayoutEffect(() => {
    if (selected) selectedTitle.current?.focus();
  }, [selected]);
  const load = async (cursor = after) => {
    if (!uuid(source)) return;
    try {
      const p = await client.list(source, cursor);
      if (alive.current && currentSource.current === source) {
        setRows(p.rechecks);
        setNext(p.next);
      }
    } catch (e) {
      if (alive.current && currentSource.current === source) onError(e);
    }
  };
  useEffect(() => {
    void load();
  }, [source, after, client]);
  const get = async (id: string) => {
    try {
      const v = await client.get(id);
      if (alive.current && currentSource.current === source) {
        setSelected(v);
      }
    } catch (e) {
      if (alive.current && currentSource.current === source) onError(e);
    }
  };
  const prepare = async () => {
    if (busy || !uuid(source)) return;
    setBusy(true);
    setFailure("");
    try {
      const p = await client.preview(source, {
        target_path: target,
        signature_mode: mode,
        reason,
      });
      if (!alive.current) return;
      setPreview(p);
      setBlocked(false);
      setReview({
        operation: "propose",
        preview: structuredClone(p),
        key: client.proposalKey(p.plan),
      });
    } catch (e) {
      if (alive.current) {
        setFailure(
          "The server could not prepare this re-check. Confirm current policy, source ownership and required controls, then review again.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  const act = async () => {
    if (!review || busy || blocked) return;
    const frozen = review;
    setBusy(true);
    setFailure("");
    try {
      let row: Recheck;
      if (frozen.operation === "propose")
        row = await client.propose(frozen.preview.plan, frozen.key);
      else if (frozen.operation === "copy") row = await client.copy(frozen.row);
      else row = await client.decide(frozen.row, frozen.operation);
      if (!alive.current) return;
      setReview(null);
      await get(row.id);
      await load();
    } catch (e) {
      if (alive.current) {
        const definitive =
          e instanceof ApiError && e.status >= 400 && e.status < 500;
        setBlocked(definitive);
        setFailure(
          definitive
            ? "This reviewed command was refused. Close, reload current state and prepare a fresh review."
            : "The result was not confirmed. Retry this same reviewed command or reload private history to recover its saved result.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  const open = (operation: "approve" | "cancel" | "copy", row: Recheck) => {
    setBlocked(false);
    setFailure("");
    setReview({
      operation,
      row: structuredClone(row),
      previous: structuredClone(selected?.previous_policy),
      policy: structuredClone(selected?.selected_policy),
    });
  };
  const plan =
    review?.operation === "propose"
      ? review.preview.plan
      : review?.row.definition.plan;
  return (
    <section className="panel rechecks" aria-label="Governed file re-checks">
      <h2>Review a new checked revision</h2>
      <p>
        The original report and queued jobs stay unchanged. A copy starts held;
        fresh checks and a separate exact release still control access.
      </p>
      <div className="form-grid">
        <label>
          Source file revision
          <input
            value={source}
            onChange={(e) => {
              currentSource.current = e.target.value;
              setSource(e.target.value);
              setSelected(null);
              setPreview(null);
              setRows([]);
              setNext("");
              setAfter("");
            }}
            disabled={busy || !!review}
          />
        </label>
        <label>
          Target path after separate release
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={busy || !!review}
          />
        </label>
        <label>
          Signature handling
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as RecheckMode)}
            disabled={busy || !!review}
          >
            <option value="not_required">
              Current policy requires no signature
            </option>
            <option value="reuse_exact">
              Reuse the exact retained signature
            </option>
            <option value="require_new">
              Require a new detached signature
            </option>
          </select>
        </label>
        <label>
          Reason
          <input
            maxLength={240}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={busy || !!review}
          />
        </label>
      </div>
      <p className="help">
        A blank target keeps the checked revision available by ID only after
        release. Re-checking cannot remove a required signature or scanner.
        Signature reuse still performs fresh verification.
      </p>
      <button
        onClick={() => void prepare()}
        disabled={busy || !!review || !uuid(source) || reason.trim().length < 3}
      >
        Preview re-check request
      </button>
      {preview && (
        <button
          className="secondary"
          disabled={busy || !!review}
          onClick={() => {
            client.forgetProposal(preview.plan);
            setPreview(null);
            setFailure("");
          }}
        >
          Start a distinct request
        </button>
      )}
      {failure && <p role="alert">{failure}</p>}
      {busy && (
        <p role="status">
          Waiting for the server to confirm this re-check operation.
        </p>
      )}
      <h3>Private re-check history</h3>
      <button
        className="secondary"
        onClick={() => void load()}
        disabled={busy || !uuid(source)}
      >
        Reload re-check history
      </button>
      <ul>
        {rows.map((r) => (
          <li key={r.id}>
            <button
              className="file-link"
              onClick={() => void get(r.id)}
              disabled={busy}
            >
              {r.state} · {r.id}
            </button>
          </li>
        ))}
      </ul>
      <div className="actions">
        <button disabled={busy || !after} onClick={() => setAfter("")}>
          First re-check page
        </button>
        <button disabled={busy || !next} onClick={() => setAfter(next)}>
          More re-checks
        </button>
      </div>
      {selected && (
        <div className="signature-box">
          <h3 ref={selectedTitle} tabIndex={-1}>
            Selected re-check: {selected.recheck.state}
          </h3>
          <p>
            {selected.current
              ? "The server observed matching current bindings. Approval and copy recheck them again."
              : "This is historical or changed context. It cannot be treated as a current approval."}
          </p>
          <dl className="facts">
            <dt>Request</dt>
            <dd>
              <code>{selected.recheck.id}</code>
            </dd>
            <dt>Approval fingerprint</dt>
            <dd>
              <code>{selected.recheck.definition_hash}</code>
            </dd>
            <dt>Selected policy</dt>
            <dd>
              <code>{selected.recheck.definition.plan.policy.hash}</code>
            </dd>
          </dl>
          {selected.current && selected.recheck.state === "proposed" && (
            <button
              onClick={() => open("approve", selected.recheck)}
              disabled={busy}
            >
              Review re-check approval
            </button>
          )}
          {selected.current && selected.recheck.state === "approved" && (
            <button
              onClick={() => open("copy", selected.recheck)}
              disabled={busy}
            >
              Review held copy
            </button>
          )}
          {["proposed", "approved"].includes(selected.recheck.state) && (
            <button
              className="secondary"
              onClick={() => open("cancel", selected.recheck)}
              disabled={busy}
            >
              Review cancellation
            </button>
          )}
          {selected.recheck.state === "copied" && (
            <>
              <p>
                The new revision is not certified by this receipt. Open its
                current check, then attach any required signature, run checks
                and separately release its exact report.
              </p>
              <button
                onClick={() => onCopied(selected.recheck.new_file_id)}
                disabled={busy}
              >
                Open new checked revision
              </button>
            </>
          )}
          {selected.previous_policy && (
            <details>
              <summary>Original policy definition</summary>
              <pre tabIndex={0}>
                {JSON.stringify(selected.previous_policy, null, 2)}
              </pre>
            </details>
          )}
          {selected.selected_policy && (
            <details>
              <summary>Selected policy definition</summary>
              <pre tabIndex={0}>
                {JSON.stringify(selected.selected_policy, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
      <dialog
        ref={dialog}
        aria-labelledby="recheck-review-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        <div className="dialog-content">
          <h2 id="recheck-review-title" tabIndex={-1} ref={title}>
            {review?.operation === "propose"
              ? "Save this immutable request"
              : review?.operation === "approve"
                ? "Approve this re-check"
                : review?.operation === "copy"
                  ? "Create a held checked revision"
                  : "Cancel this request"}
          </h2>
          {plan && (
            <>
              <dl className="facts">
                <dt>Source revision</dt>
                <dd>
                  <code>{plan.source.file.id}</code>
                </dd>
                <dt>Exact source SHA-256</dt>
                <dd>
                  <code>{plan.source.file.sha256}</code>
                </dd>
                <dt>Bytes</dt>
                <dd>{plan.source.file.size_bytes}</dd>
                <dt>Selected policy SHA-256</dt>
                <dd>
                  <code>{plan.policy.hash}</code>
                </dd>
                <dt>Signature handling</dt>
                <dd>{plan.signature_mode}</dd>
                <dt>Target after release</dt>
                <dd>
                  {plan.target
                    ? String(
                        (plan.target.command as Record<string, unknown>).path,
                      )
                    : "Raw revision only; no path publication"}
                </dd>
                <dt>Reason</dt>
                <dd>{plan.reason}</dd>
                <dt>Authority revision</dt>
                <dd>{plan.authority_revision}</dd>
              </dl>
              <p>
                Saving or approving reads no payload bytes. Copy uses private
                bounded staging, produces a held revision and does not publish
                or run a workflow. Original verdicts are preserved.
              </p>
            </>
          )}
          {review?.operation === "propose" && (
            <>
              <details>
                <summary>Compare original policy</summary>
                <pre tabIndex={0}>
                  {JSON.stringify(
                    review.preview.previous_policy ??
                      "No original intake policy",
                    null,
                    2,
                  )}
                </pre>
              </details>
              <details open>
                <summary>Selected policy to apply</summary>
                <pre tabIndex={0}>
                  {JSON.stringify(review.preview.current_policy, null, 2)}
                </pre>
              </details>
            </>
          )}
          {review && review.operation !== "propose" && (
            <>
              <details>
                <summary>Original policy definition</summary>
                <pre tabIndex={0}>
                  {JSON.stringify(
                    review.previous ?? "No original intake policy",
                    null,
                    2,
                  )}
                </pre>
              </details>
              <details open>
                <summary>Selected policy definition</summary>
                <pre tabIndex={0}>{JSON.stringify(review.policy, null, 2)}</pre>
              </details>
              <p>
                Reviewed request SHA-256:{" "}
                <code>{review.row.definition_hash}</code> · revision{" "}
                {review.row.revision}
              </p>
            </>
          )}
          {failure && <p role="alert">{failure}</p>}
          <div className="actions">
            <button onClick={() => void act()} disabled={busy || blocked}>
              {busy
                ? "Waiting for confirmed result…"
                : review?.operation === "propose"
                  ? "Save reviewed request"
                  : review?.operation === "approve"
                    ? "Approve exact re-check"
                    : review?.operation === "copy"
                      ? "Create held revision"
                      : "Confirm cancellation"}
            </button>
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setReview(null)}
            >
              Close review
            </button>
          </div>
        </div>
      </dialog>
    </section>
  );
}
