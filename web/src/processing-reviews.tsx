import { useEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { operationKey } from "./crypto";
import { ProcessingApi } from "./processing-api";
import {
  processingStamp,
  type Configuration,
  type ProcessingDefinition,
} from "./processing-types";
import { ProcessingTaskReview } from "./processing-task-review";
import {
  ProcessingReviewApi,
  reviewAllowed,
  reviewMutation,
  reviewRecovery,
  type Review,
  type ReviewSummary,
  type ReviewMutation,
} from "./processing-review-api";
import { importReviewRecoveryFile } from "./processing-review-import";

type Confirmation = {
  mutation: ReviewMutation;
  review?: Review;
  definition: ProcessingDefinition;
  recovery: boolean;
};
export function ProcessingReviews({
  api,
  session,
  active,
  refresh,
  configuration,
  onWorkflow,
  onMutation,
  onError,
}: {
  api: Api;
  session: Session;
  active: boolean;
  refresh: number;
  configuration: Configuration | null;
  onWorkflow: (id: string, version: number, hash: string) => void;
  onMutation: () => void;
  onError: (e: unknown) => void;
}) {
  const stamp = processingStamp(session),
    client = useMemo(() => new ProcessingReviewApi(api), [api, stamp]),
    workflows = useMemo(() => new ProcessingApi(api), [api, stamp]);
  const [reviewer, setReviewer] = useState(""),
    [expires, setExpires] = useState(""),
    [reviewID, setReviewID] = useState(""),
    [row, setRow] = useState<Review | null>(null),
    [rows, setRows] = useState<ReviewSummary[]>([]),
    [next, setNext] = useState(""),
    [busy, setBusy] = useState(false),
    [pending, setPending] = useState<ReviewMutation | null>(null),
    [confirmation, setConfirmation] = useState<Confirmation | null>(null),
    [receipt, setReceipt] = useState<ReviewSummary | null>(null),
    [notice, setNotice] = useState(""),
    [failure, setFailure] = useState("");
  const alive = useRef(true),
    running = useRef(false),
    pendingRef = useRef<ReviewMutation | null>(null),
    dialog = useRef<HTMLDialogElement>(null),
    heading = useRef<HTMLHeadingElement>(null),
    returnFocus = useRef<HTMLElement | null>(null);
  const current = () => alive.current && processingStamp(api.session) === stamp;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (confirmation && active) {
      returnFocus.current = document.activeElement as HTMLElement;
      dialog.current?.showModal();
      heading.current?.focus();
    } else {
      dialog.current?.close();
      returnFocus.current?.focus();
    }
  }, [confirmation, active]);
  const reportFailure = (e: unknown) => {
    if (current()) {
      setFailure(
        pendingRef.current
          ? "This command is not confirmed. Keep its original key and inspect current state before a new action."
          : e instanceof ApiError && e.code === "review_inspection_busy"
            ? "Wait for the current inspection to finish, then import the same recovery file again."
            : "The command or current inspection was refused. A historical receipt is not current approval.",
      );
      onError(e);
    }
  };
  const perform = async (fn: () => Promise<void>) => {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setFailure("");
    try {
      await fn();
    } catch (e) {
      reportFailure(e);
    } finally {
      running.current = false;
      if (current()) setBusy(false);
    }
  };
  const list = () =>
    perform(async () => {
      const page = await client.list();
      if (current()) {
        setRows(page.reviews);
        setNext(page.next);
      }
    });
  const inspect = (id = reviewID) =>
    perform(async () => {
      const value = await client.get(id);
      if (current()) {
        setReviewID(value.id);
        setRow(value);
      }
    });
  useEffect(() => {
    if (active) {
      void perform(async () => {
        if (reviewID) {
          const value = await client.get(reviewID);
          if (current()) setRow(value);
        }
        const page = await client.list();
        if (current()) {
          setRows(page.reviews);
          setNext(page.next);
        }
      });
    }
  }, [refresh, active]);
  const prepare = async (m: ReviewMutation, recovery = false) => {
    const request = reviewMutation(m);
    if (pendingRef.current && pendingRef.current.key !== request.key)
      throw new ApiError("request_recovery_required", 409);
    if (request.kind === "request") {
      const ref = request.body.workflow as {
          id: string;
          version: number;
          hash: string;
        },
        cfg = await workflows.configuration(ref.id, ref.version);
      if (
        cfg.definition_hash !== ref.hash ||
        (!recovery &&
          (cfg.state !== "draft" ||
            cfg.revision !== request.body.expected_revision))
      )
        throw new ApiError("revision_conflict", 409);
      if (current())
        setConfirmation({
          mutation: request,
          definition: cfg.definition,
          recovery,
        });
    } else {
      const value = await client.get(request.id!);
      if (
        value.definition_hash !== request.body.definition_hash ||
        !reviewAllowed(api.session, request.kind, value)
      )
        throw new ApiError("permission_denied", 403);
      if (current()) {
        setRow(value);
        setReviewID(value.id);
        setConfirmation({
          mutation: request,
          review: value,
          definition: value.definition.definition,
          recovery,
        });
      }
    }
  };
  const propose = (kind: ReviewMutation["kind"]) =>
    perform(async () => {
      let mutation: ReviewMutation;
      if (kind === "request") {
        if (
          !configuration ||
          configuration.state !== "draft" ||
          !reviewAllowed(session, "request")
        )
          throw new ApiError("permission_denied", 403);
        mutation = reviewMutation({
          kind,
          body: {
            workflow: {
              id: configuration.id,
              version: configuration.version,
              hash: configuration.definition_hash,
            },
            expected_revision: configuration.revision,
            reviewer_id: reviewer,
            expires_at: expires,
          },
          key: operationKey(),
        });
      } else {
        if (!row) throw new ApiError("review_required", 409);
        mutation = reviewMutation({
          kind,
          id: row.id,
          body: {
            definition_hash: row.definition_hash,
            expected_revision: row.revision,
          },
          key: operationKey(),
        });
      }
      await prepare(mutation);
    });
  const execute = () =>
    perform(async () => {
      if (!confirmation) throw new ApiError("review_required", 409);
      const c = confirmation,
        m = c.mutation;
      pendingRef.current = m;
      setPending(m);
      const result = await client.mutate(m, c.review);
      if (!current()) return;
      pendingRef.current = null;
      setPending(null);
      setConfirmation(null);
      setReceipt(result.summary);
      setNotice(
        result.replayed
          ? "Recovered the original command receipt. Current review state is read separately."
          : "Command recorded. Current review state is read separately.",
      );
      onMutation();
      const latest = await client.get(result.summary.id);
      if (current()) {
        setReviewID(latest.id);
        setRow(latest);
      }
    });
  const save = (m: ReviewMutation) => {
    try {
      const wire =
        JSON.stringify(reviewRecovery(m, session, location.origin)) + "\n";
      if (new TextEncoder().encode(wire).length > 32 * 1024)
        throw new ApiError("invalid_processing_review", 400);
      const url = URL.createObjectURL(
          new Blob([wire], { type: "application/json" }),
        ),
        link = document.createElement("a");
      link.href = url;
      link.download = "freightctl-processing-review-recovery.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (e) {
      onError(e);
    }
  };
  const importRecovery = async (file: File) => {
    try {
      await importReviewRecoveryFile({
        file,
        session,
        origin: location.origin,
        current,
        busy: () => running.current,
        prepare: (m) => perform(() => prepare(m, true)),
      });
    } catch (e) {
      // Do not clear the running/busy state owned by an existing inspection.
      reportFailure(e);
    }
  };
  return (
    <section aria-label="Independent processing review">
      <h2>Independent processing review</h2>
      <p>
        Show one exact task to a named reviewer. Their decision does not grant
        file access, execution, release or delivery. The creator separately
        adopts approval before its worker can run.
      </p>
      {notice && <p role="status">{notice}</p>}
      {failure && <p role="alert">{failure}</p>}
      {receipt && (
        <p>
          Original command receipt: review <code>{receipt.id}</code>,state{" "}
          {receipt.state}, revision {receipt.revision}. This is
          historical;current inspection appears below.
        </p>
      )}
      {pending && (
        <section
          aria-label="Unconfirmed independent review command"
          className="warning"
        >
          <h3>Keep this request key</h3>
          <p>
            A missing reply does not prove the command stopped. Retry the exact
            saved request after inspecting current state.
          </p>
          <p>
            Key:<code>{pending.key}</code>
          </p>
          <button disabled={busy} onClick={() => save(pending)}>
            Save independent review recovery
          </button>
          <button
            disabled={busy}
            onClick={() => void perform(() => prepare(pending, true))}
          >
            Review exact saved retry
          </button>
          <button
            disabled={busy}
            onClick={() => {
              pendingRef.current = null;
              setPending(null);
              setNotice(
                "Local saved request cleared. This does not cancel or undo any server command.",
              );
            }}
          >
            Clear local saved request
          </button>
        </section>
      )}
      {reviewAllowed(session, "request") && (
        <section aria-label="Request independent task review">
          <h3>Request review of the loaded draft</h3>
          <p>
            {configuration ? (
              <>
                Workflow <code>{configuration.id}</code> version{" "}
                {configuration.version}, state {configuration.state},revision{" "}
                {configuration.revision}.
              </>
            ) : (
              "Load an owned task in Open a task revision before requesting review."
            )}
          </p>
          <label>
            Reviewer actor ID
            <input
              value={reviewer}
              disabled={busy || !!pending}
              onChange={(e) => setReviewer(e.target.value)}
              autoComplete="off"
            />
          </label>
          <label>
            Approval expiry (UTC)
            <input
              value={expires}
              placeholder="2026-11-07T18:00:00Z"
              disabled={busy || !!pending}
              onChange={(e) => setExpires(e.target.value)}
              autoComplete="off"
            />
          </label>
          <p>
            The named reviewer can see this task's name,reason,column
            rules,logical output path and policy references.
          </p>
          <button
            disabled={busy || !!pending || configuration?.state !== "draft"}
            onClick={() => void propose("request")}
          >
            Review disclosure and request
          </button>
        </section>
      )}
      <label>
        Independent review ID
        <input
          value={reviewID}
          disabled={busy}
          onChange={(e) => {
            setReviewID(e.target.value);
            setRow(null);
          }}
          autoComplete="off"
        />
      </label>
      <button disabled={busy} onClick={() => void inspect()}>
        Inspect independent review
      </button>
      <button disabled={busy} onClick={() => void list()}>
        List my independent reviews
      </button>
      <label>
        Import independent review recovery JSON
        <input
          type="file"
          accept="application/json,.json"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (f) void importRecovery(f);
          }}
        />
      </label>
      {rows.length > 0 && (
        <ul aria-label="My independent reviews">
          {rows.map((value) => (
            <li key={value.id}>
              <button disabled={busy} onClick={() => void inspect(value.id)}>
                Inspect {value.id}
              </button>{" "}
              · {value.state}, revision {value.revision},expires{" "}
              {value.expires_at}
            </li>
          ))}
        </ul>
      )}
      {next && (
        <button
          disabled={busy}
          onClick={() =>
            void perform(async () => {
              const page = await client.list(next);
              if (current()) {
                setRows(page.reviews);
                setNext(page.next);
              }
            })
          }
        >
          Next review page
        </button>
      )}
      {row && (
        <section aria-label="Current independent review">
          <h3>Current inspection</h3>
          <p>
            Review <code>{row.id}</code>: {row.state}, revision {row.revision}.
            Hash <code>{row.definition_hash}</code>.
          </p>
          <p>
            Creator <code>{row.definition.author.actor_id}</code>,authority{" "}
            {row.definition.author.authority_revision};reviewer{" "}
            <code>{row.definition.reviewer.actor_id}</code>,authority{" "}
            {row.definition.reviewer.authority_revision}. Expires{" "}
            {row.definition.expires_at}.
          </p>
          {Date.parse(row.definition.expires_at) <= Date.now() && (
            <p className="warning">
              This review has expired. Its recorded decision supplies no current
              execution authority.
            </p>
          )}
          <ProcessingTaskReview definition={row.definition.definition} />
          {row.state === "pending" &&
            reviewAllowed(session, "approve", row) && (
              <>
                <button
                  disabled={busy || !!pending}
                  onClick={() => void propose("approve")}
                >
                  Review independent approval
                </button>
                <button
                  disabled={busy || !!pending}
                  onClick={() => void propose("reject")}
                >
                  Review rejection
                </button>
              </>
            )}
          {row.state === "approved" && reviewAllowed(session, "adopt", row) && (
            <button
              disabled={busy || !!pending}
              onClick={() => void propose("adopt")}
            >
              Review adoption into my workflow
            </button>
          )}
          {["pending", "approved", "adopted"].includes(row.state) &&
            reviewAllowed(session, "withdraw", row) && (
              <button
                disabled={busy || !!pending}
                onClick={() => void propose("withdraw")}
              >
                Review withdrawal
              </button>
            )}
          {row.definition.author.actor_id === session.identity.actor_id && (
            <button
              disabled={busy}
              onClick={() =>
                onWorkflow(
                  row.definition.workflow.id,
                  row.definition.workflow.version,
                  row.definition.workflow.hash,
                )
              }
            >
              Load reviewed workflow revision
            </button>
          )}
        </section>
      )}
      <dialog
        ref={dialog}
        aria-labelledby="processing-independent-confirm-title"
        onCancel={(e) => {
          if (busy) e.preventDefault();
          else setConfirmation(null);
        }}
      >
        {confirmation && (
          <>
            <h2
              id="processing-independent-confirm-title"
              ref={heading}
              tabIndex={-1}
            >
              Confirm independent review {confirmation.mutation.kind}
            </h2>
            <p>
              {confirmation.recovery
                ? "Recovery preserves the original key and expected revision;the recorded result may be historical."
                : "Only this exact reviewed command will be submitted."}
            </p>
            <p>
              Key:<code>{confirmation.mutation.key}</code>.
            </p>
            {confirmation.review ? (
              <p>
                Exact review hash:
                <code>{confirmation.review.definition_hash}</code>;requested
                revision {String(confirmation.mutation.body.expected_revision)}
                ;current inspected revision {confirmation.review.revision},
                state {confirmation.review.state}.
              </p>
            ) : (
              <p>
                Disclose this task to reviewer{" "}
                <code>{String(confirmation.mutation.body.reviewer_id)}</code>
                ,until {String(confirmation.mutation.body.expires_at)}. No
                approval or execution occurs.
              </p>
            )}
            <ProcessingTaskReview definition={confirmation.definition} />
            <p>
              Approval does not activate the task. Adoption requires the
              original current draft and live participants. Outputs still need
              fresh checks and a separate release. Withdrawal prevents future
              work without erasing artifacts or prior receipts.
            </p>
            {failure && <p role="alert">{failure}</p>}
            <button disabled={busy} onClick={() => save(confirmation.mutation)}>
              Save exact review request
            </button>
            <button disabled={busy} onClick={() => setConfirmation(null)}>
              Close without submitting
            </button>
            <button disabled={busy} onClick={() => void execute()}>
              Confirm exact review command
            </button>
          </>
        )}
      </dialog>
    </section>
  );
}
