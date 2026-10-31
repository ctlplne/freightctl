import { useEffect, useRef, useState, useId, type ReactNode } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { uuid, type Session } from "./types";
import {
  asApprovalPage,
  asApprovalPolicy,
  asApprovalPolicyResult,
  asApprovalPreview,
  asApprovalResult,
  asApprovalReview,
  type ApprovalDefinition,
  type ApprovalPolicy,
  type ApprovalPreview,
  type ApprovalReview,
  type ApprovalSelection,
  type ApprovalSummary,
} from "./onboarding-approvals-types";
import type { ReleaseSummary } from "./onboarding-releases-types";
type Props = { api: Api; session: Session; onError: (e: unknown) => void };
export function approvalPost<T>(
  api: Api,
  path: string,
  input: unknown,
  key: string | undefined,
  decode: (v: unknown) => T,
): Promise<T> {
  return api.request(
    path,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(key ? { "Idempotency-Key": key } : {}),
      },
      body: JSON.stringify(input),
    },
    decode,
  );
}
export function ApprovalConfirm({
  title,
  children,
  busy,
  failure,
  onConfirm,
  onCancel,
}: {
  title: string;
  children: ReactNode;
  busy: boolean;
  failure: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const labelID = useId();
  const dialog = useRef<HTMLDialogElement>(null),
    heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    const origin = document.activeElement;
    dialog.current?.showModal();
    heading.current?.focus();
    return () => {
      if (origin instanceof HTMLElement) origin.focus();
    };
  }, []);
  return (
    <dialog
      ref={dialog}
      aria-labelledby={labelID}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <h2 id={labelID} tabIndex={-1} ref={heading}>
        {title}
      </h2>
      {children}
      {failure && <p role="alert">{failure}</p>}
      <div className="actions">
        <button disabled={busy} onClick={onConfirm}>
          {busy ? "Recording…" : "Confirm exact decision"}
        </button>
        <button className="secondary" disabled={busy} onClick={onCancel}>
          Close review
        </button>
      </div>
      <p>
        If the response is lost, retry here with the same operation key. Closing
        this dialog does not undo a recorded decision; inspect the private
        history before starting again.
      </p>
    </dialog>
  );
}
function Effects({ d }: { d: ApprovalDefinition }) {
  return (
    <>
      <p>
        Release <code>{d.release_id}</code>, revision {d.release_revision};
        author <code>{d.author_id}</code>; reviewer <code>{d.reviewer_id}</code>{" "}
        at authority revision {d.reviewer_authority_revision}. Partner approval
        policy revision {d.policy.revision} requires an independent reviewer.
      </p>
      <p>
        Release SHA-256 <code>{d.release_hash}</code>. This review shares the
        metadata below. It grants no file download or private-draft access and
        contacts no receiver.
      </p>
      {d.effects.map((e, i) => (
        <section className="signature-box" key={e.requirement_id}>
          <h4>Requirement {e.requirement_id}</h4>
          <p>
            Test <code>{d.release.proofs[i]?.test_id}</code>; receipt SHA-256{" "}
            <code>{d.release.proofs[i]?.receipt_hash}</code>.
          </p>
          <p>
            Exact file <code>{e.file.id}</code>, {e.file.size_bytes} bytes,
            SHA-256 <code>{e.file.sha256}</code>; intake policy{" "}
            <code>{e.file.policy}</code>.
          </p>
          <p>
            SFTP{" "}
            <code>
              {e.effect.user}@{e.effect.address}
            </code>
            , directory <code>{e.effect.directory}</code>, reserved filename{" "}
            <code>{e.effect.filename}</code>. Host{" "}
            <code>{e.effect.host_fingerprint}</code>; client key{" "}
            <code>{e.effect.key_fingerprint}</code>.
          </p>
          <p>
            {e.effect.encryption ? (
              <>
                Recipient encryption <code>{e.effect.encryption.profile}</code>,
                key <code>{e.effect.encryption.key.id}</code> version{" "}
                {e.effect.encryption.key.version}, fingerprint{" "}
                <code>{e.effect.recipient_fingerprint}</code>.
              </>
            ) : (
              "No recipient encryption is configured for these wire bytes."
            )}
          </p>
        </section>
      ))}
      <p>
        Transport integrity evidence does not establish downstream business
        acceptance. Approval is checked again before activation and new transfer
        work; later policy or authority changes can block it.
      </p>
    </>
  );
}
export function IndependentReviewRequest({
  api,
  session,
  onError,
  release,
}: { release: ReleaseSummary } & Props) {
  const [reviewer, setReviewer] = useState(""),
    [pending, setPending] = useState<{
      selection: ApprovalSelection;
      preview: ApprovalPreview;
      key: string;
    } | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [saved, setSaved] = useState<ApprovalSummary | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  async function preview() {
    if (!uuid(reviewer) || reviewer === session.identity.actor_id) return;
    setBusy(true);
    setFailure("");
    const selection: ApprovalSelection = {
      release_id: release.id,
      expected_revision: release.revision,
      definition_hash: release.definition_hash,
      reviewer_id: reviewer,
    };
    try {
      const p = await approvalPost(
        api,
        `${api.prefix}/onboarding-approval-reviews/preview`,
        selection,
        undefined,
        (v) => asApprovalPreview(v, session.identity.actor_id, selection),
      );
      if (alive.current)
        setPending({ selection, preview: p, key: operationKey() });
    } catch (e) {
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function confirm() {
    if (!pending) return;
    setBusy(true);
    setFailure("");
    try {
      const r = await approvalPost(
        api,
        `${api.prefix}/onboarding-approval-reviews`,
        {
          selection: pending.selection,
          definition_hash: pending.preview.definition_hash,
        },
        pending.key,
        (v) =>
          asApprovalResult(v, session.identity.actor_id, {
            hash: pending.preview.definition_hash,
            state: "pending",
            revision: 1,
          }),
      );
      if (alive.current) {
        setSaved(r);
        setPending(null);
      }
    } catch (e) {
      if (alive.current)
        setFailure(
          "Request not confirmed. Retry with the original key or inspect Approvals history; an uncertain response does not mean the request was absent.",
        );
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <section className="signature-box">
      <h4>Request independent production approval</h4>
      <p>
        Choose an existing account in this partner with inspection and
        workflow-approval permission. Only that account receives this exact
        metadata package. The release author cannot approve it.
      </p>
      <label>
        Assigned reviewer account ID
        <input
          value={reviewer}
          onChange={(e) => setReviewer(e.target.value)}
          disabled={busy}
        />
      </label>
      <button
        disabled={
          busy ||
          !uuid(reviewer) ||
          reviewer === session.identity.actor_id ||
          release.state !== "proposed"
        }
        onClick={() => void preview()}
      >
        Preview independent review package
      </button>
      {saved && (
        <p role="status">
          Review <code>{saved.id}</code> is pending. The named reviewer must
          sign in and open Approvals. After approval, refresh this release and
          record the separate approval and activation.
        </p>
      )}
      {pending && (
        <ApprovalConfirm
          title="Share exact review metadata"
          busy={busy}
          failure={failure}
          onConfirm={() => void confirm()}
          onCancel={() => setPending(null)}
        >
          <Effects d={pending.preview.definition} />
          <p>
            Package SHA-256 <code>{pending.preview.definition_hash}</code>.
          </p>
        </ApprovalConfirm>
      )}
    </section>
  );
}
export function OnboardingApprovals({
  api,
  session,
  onError,
  refresh,
}: { refresh: number } & Props) {
  const actor = session.identity.actor_id,
    has = (p: string) => session.identity.permissions.includes(p),
    canGovern = has("admin") && has("accounts_manage");
  const [policy, setPolicy] = useState<ApprovalPolicy | null>(null),
    [mode, setMode] = useState<ApprovalPolicy["mode"]>("independent"),
    [page, setPage] = useState<{ reviews: ApprovalSummary[]; next?: string }>({
      reviews: [],
    }),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [selected, setSelected] = useState<ApprovalReview | null>(null),
    [pending, setPending] = useState<
      | {
          kind: "policy";
          policy: ApprovalPolicy;
          mode: ApprovalPolicy["mode"];
          key: string;
        }
      | {
          kind: "review";
          review: ApprovalReview;
          action: "approve" | "reject" | "withdraw";
          key: string;
        }
      | null
    >(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState("");
  const alive = useRef(true),
    heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (selected) heading.current?.focus();
  }, [selected]);
  useEffect(() => {
    const c = new AbortController();
    api
      .request(
        `${api.prefix}/onboarding-approval-policy`,
        { signal: c.signal },
        asApprovalPolicy,
      )
      .then((p) => {
        if (!c.signal.aborted) setPolicy(p);
      })
      .catch((e) => {
        if (!c.signal.aborted) onError(e);
      });
    api
      .request(
        `${api.prefix}/onboarding-approval-reviews?limit=50&after=${after}`,
        { signal: c.signal },
        (v) => asApprovalPage(v, actor),
      )
      .then((p) => {
        if (!c.signal.aborted) setPage(p);
      })
      .catch((e) => {
        if (!c.signal.aborted) onError(e);
      });
    return () => c.abort();
  }, [api, actor, after, reload, refresh]);
  async function load(r: ApprovalSummary) {
    setBusy(true);
    try {
      const v = await api.request(
        `${api.prefix}/onboarding-approval-reviews/${r.id}`,
        {},
        (v) => asApprovalReview(v, actor, r),
      );
      if (alive.current) setSelected(v);
    } catch (e) {
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function confirm() {
    if (!pending) return;
    setBusy(true);
    setFailure("");
    try {
      if (pending.kind === "policy") {
        const p = await approvalPost(
          api,
          `${api.prefix}/onboarding-approval-policy`,
          { expected_revision: pending.policy.revision, mode: pending.mode },
          pending.key,
          (v) =>
            asApprovalPolicyResult(
              v,
              { ...pending.policy, mode: pending.mode },
              actor,
            ),
        );
        if (alive.current) setPolicy(p);
      } else {
        const x = pending,
          r = x.review;
        await approvalPost(
          api,
          `${api.prefix}/onboarding-approval-reviews/${r.id}/${x.action}`,
          { definition_hash: r.definition_hash, expected_revision: r.revision },
          x.key,
          (v) =>
            asApprovalResult(v, actor, {
              hash: r.definition_hash,
              id: r.id,
              state:
                x.action === "approve"
                  ? "approved"
                  : x.action === "reject"
                    ? "rejected"
                    : "withdrawn",
              revision: r.revision + 1,
            }),
        );
        if (alive.current) setSelected(null);
      }
      if (alive.current) {
        setPending(null);
        setReload((n) => n + 1);
      }
    } catch (e) {
      if (alive.current)
        setFailure(
          "Decision not confirmed. Retry with the same key, or close and inspect current history. A changed policy, authority or revision requires fresh review.",
        );
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <>
      <section className="panel">
        <h2>Onboarding production approval policy</h2>
        <p>
          {policy
            ? `Revision ${policy.revision}: ${policy.mode === "independent" ? "a different named account must approve the exact release" : "the release author uses the existing separate approval step"}.`
            : "Loading current policy…"}
        </p>
        <p>
          This policy governs onboarding production releases. Ordinary workflows
          and direct deliveries use their existing approvals. A policy revision
          blocks old production bindings until a new release is reviewed. It
          preserves original runs, bytes and receipts. It does not recall files
          already received.
        </p>
        {canGovern && policy && (
          <>
            <label>
              Policy for new production releases
              <select
                value={mode}
                disabled={busy}
                onChange={(e) =>
                  setMode(e.target.value as ApprovalPolicy["mode"])
                }
              >
                <option value="independent">Independent named reviewer</option>
                <option value="author">Author approval</option>
              </select>
            </label>
            <button
              disabled={busy}
              onClick={() => {
                setFailure("");
                setPending({
                  kind: "policy",
                  policy,
                  mode,
                  key: operationKey(),
                });
              }}
            >
              Review policy change
            </button>
          </>
        )}
      </section>
      <section className="panel">
        <h2>Private approval history</h2>
        <p>
          Only requests you authored or were explicitly assigned appear here.
          Approval alone does not activate a release or send a file.
        </p>
        {page.reviews.length === 0 && <p>No review requests on this page.</p>}
        <ul>
          {page.reviews.map((r) => (
            <li key={r.id}>
              <code>{r.id}</code> — {r.state}, revision {r.revision}.{" "}
              <button
                className="secondary"
                disabled={busy}
                onClick={() => void load(r)}
              >
                Inspect exact review {r.id.slice(0, 8)}
              </button>
            </li>
          ))}
        </ul>
        <div className="actions">
          <button
            className="secondary"
            disabled={busy || !after}
            onClick={() => setAfter("")}
          >
            First review page
          </button>
          <button
            className="secondary"
            disabled={busy || !page.next}
            onClick={() => setAfter(page.next ?? "")}
          >
            Next review page
          </button>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => setReload((n) => n + 1)}
          >
            Refresh approval history
          </button>
        </div>
        {selected && (
          <section className="signature-box">
            <h3 ref={heading} tabIndex={-1}>
              Independent review: {selected.state}
            </h3>
            <Effects d={selected.definition} />
            <p>
              Package SHA-256 <code>{selected.definition_hash}</code>.
            </p>
            <div className="actions">
              {selected.state === "pending" &&
                selected.reviewer_id === actor &&
                has("workflow_approve") &&
                has("inspect") &&
                (["approve", "reject"] as const).map((action) => (
                  <button
                    disabled={busy}
                    key={action}
                    onClick={() => {
                      setFailure("");
                      setPending({
                        kind: "review",
                        review: selected,
                        action,
                        key: operationKey(),
                      });
                    }}
                  >
                    {action === "approve"
                      ? "Review independent approval"
                      : "Review rejection"}
                  </button>
                ))}
              {["pending", "approved"].includes(selected.state) &&
                selected.author_id === actor &&
                has("workflow_manage") && (
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => {
                      setFailure("");
                      setPending({
                        kind: "review",
                        review: selected,
                        action: "withdraw",
                        key: operationKey(),
                      });
                    }}
                  >
                    Review withdrawal
                  </button>
                )}
            </div>
            <p>
              After an independent approval, the author must refresh the
              original release, record its approval and activate it separately.
              Later withdrawal or policy/credential changes block new work.
            </p>
          </section>
        )}
      </section>
      {pending && (
        <ApprovalConfirm
          title={
            pending.kind === "policy"
              ? "Change partner approval policy"
              : `Confirm ${pending.action} review`
          }
          busy={busy}
          failure={failure}
          onConfirm={() => void confirm()}
          onCancel={() => setPending(null)}
        >
          {pending.kind === "policy" ? (
            <p>
              Change revision {pending.policy.revision} to{" "}
              {pending.policy.revision + 1}, requiring{" "}
              {pending.mode === "independent"
                ? "a different named reviewer"
                : "author approval"}
              . Existing production bindings will fail current-policy checks.
              This is an administrator decision.
            </p>
          ) : (
            <>
              <Effects d={pending.review.definition} />
              <p>
                Exact review <code>{pending.review.id}</code>, revision{" "}
                {pending.review.revision}, SHA-256{" "}
                <code>{pending.review.definition_hash}</code>. Action:{" "}
                {pending.action}.
              </p>
            </>
          )}
        </ApprovalConfirm>
      )}
    </>
  );
}
