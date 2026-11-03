import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { uuid, type Session } from "./types";
import { ApprovalConfirm, approvalPost } from "./onboarding-approvals";
import {
  asDispatchPolicy,
  asDispatchPolicyResult,
  asDispatchView,
  asDispatchPreview,
  asDispatchPage,
  asDispatchReview,
  asDispatchResult,
  type DispatchPolicy,
  type DispatchView,
  type DispatchPreview,
  type DispatchSelection,
  type DispatchSummary,
  type DispatchReview,
  type DispatchDefinition,
} from "./outbound-approvals-types";
export function DispatchDetails({
  d,
}: {
  d: Pick<DispatchDefinition, "delivery_id" | "source" | "effect">;
}) {
  const e = d.effect;
  return (
    <>
      <p>
        Delivery <code>{d.delivery_id}</code>, accepted file{" "}
        <code>{d.source.id}</code>, {d.source.size_bytes} bytes; SHA-256{" "}
        <code>{d.source.sha256}</code>. Intake policy{" "}
        <code>{d.source.policy}</code>.
      </p>
      <p>
        {e.protocol === "ftps" ? "FTPS" : "SFTP"}{" "}
        <code>
          {e.user}@{e.address}
        </code>
        . {e.ftps ? "Exact final path" : "Exact reserved final path"}{" "}
        <code>{e.final_path}</code>.
      </p>
      {e.ftps ? (
        <>
          <p>
            {e.ftps.mode === "explicit" ? "Explicit" : "Implicit"} TLS 1.3
            required; certificate hostname <code>{e.ftps.server_name}</code>.
            Approved certificate authority (CA) SHA-256{" "}
            <code>{e.ftps.ca_sha256}</code>.
          </p>
          <p>
            CA reference fingerprint <code>{e.ftps.ca_reference_sha256}</code>;
            credential reference fingerprint{" "}
            <code>{e.ftps.password_reference_sha256}</code>. These identify the
            approved references; password values and local paths are not shared.
            Certificate and credential checks run when sending starts.
          </p>
          <p>
            Private staging path <code>{e.ftps.staging_path}</code>; upload may
            replace bytes at this path. Receiver contract document SHA-256{" "}
            <code>{e.ftps.receiver_contract.document_sha256}</code>. The
            receiver must hide staged files from consumers and deduplicate
            business processing by delivery ID. This records the
            administrator&apos;s agreed contract; it does not verify those
            receiver promises.
          </p>
          <p>
            Rename may replace an existing final file. The required receipt
            verifies exact bytes read back; it does not acknowledge a receiver
            disk flush (fsync), power-loss persistence or business processing.
          </p>
        </>
      ) : (
        <p>
          Host identity <code>{e.host_fingerprint}</code>; client key{" "}
          <code>{e.key_fingerprint}</code>. Protected key-reference SHA-256{" "}
          <code>{e.key_reference_sha256}</code>. No private-key value or local
          key path is shared.
        </p>
      )}
      {e.encryption ? (
        <p>
          Recipient encryption <code>{e.encryption.profile}</code>, key{" "}
          <code>{e.encryption.key.id}</code> version {e.encryption.key.version},
          fingerprint <code>{e.recipient_fingerprint}</code>. Ciphertext is
          created from these exact approved plaintext bytes and key.
        </p>
      ) : (
        <p>No recipient encryption is configured.</p>
      )}
      {e.workflow_binding && (
        <p>
          Workflow <code>{e.workflow_binding.workflow_id}</code> version{" "}
          {e.workflow_binding.workflow_version}, run{" "}
          <code>{e.workflow_binding.run_id}</code>, step{" "}
          <code>{e.workflow_binding.step_id}</code>; registered connection{" "}
          <code>{e.workflow_binding.connection_id}</code> version{" "}
          {e.workflow_binding.connection_version}.
        </p>
      )}
      {e.ftps ? (
        <p>
          Up to eight connection attempts are allowed before a write intent is
          committed. Once upload may begin, a missing reply blocks automatic
          resend. Recovery only reads the exact final bytes and cannot invent
          the original upload or rename reply.
        </p>
      ) : (
        <p>
          Approval permits this intent's existing bounded retry rules, up to
          eight attempts. Uncertain publication is reconciled by a bounded read;
          it is not blindly resent. Transport integrity does not establish
          downstream business acceptance.
        </p>
      )}
    </>
  );
}
export function OutboundDispatchApprovals({
  api,
  session,
  refresh,
  onError,
}: {
  api: Api;
  session: Session;
  refresh: number;
  onError: (e: unknown) => void;
}) {
  const actor = session.identity.actor_id,
    has = (p: string) => session.identity.permissions.includes(p),
    canGovern = has("admin") && has("accounts_manage"),
    canSend = has("read") && has("deliver"),
    canReview = has("inspect") && has("workflow_approve");
  const [policy, setPolicy] = useState<DispatchPolicy | null>(null),
    [mode, setMode] = useState<DispatchPolicy["mode"]>("independent"),
    [page, setPage] = useState<{ reviews: DispatchSummary[]; next?: string }>({
      reviews: [],
    }),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [deliveryID, setDeliveryID] = useState(""),
    [view, setView] = useState<DispatchView | null>(null),
    [reviewer, setReviewer] = useState(""),
    [selected, setSelected] = useState<DispatchReview | null>(null),
    [pending, setPending] = useState<
      | {
          kind: "policy";
          policy: DispatchPolicy;
          mode: DispatchPolicy["mode"];
          key: string;
        }
      | {
          kind: "proposal";
          selection: DispatchSelection;
          preview: DispatchPreview;
          key: string;
        }
      | {
          kind: "decision";
          review: DispatchReview;
          action: "approve" | "reject" | "withdraw";
          key: string;
        }
      | null
    >(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [notice, setNotice] = useState("");
  const alive = useRef(true),
    viewHeading = useRef<HTMLHeadingElement>(null),
    reviewHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (view) viewHeading.current?.focus();
  }, [view]);
  useEffect(() => {
    if (selected) reviewHeading.current?.focus();
  }, [selected]);
  useEffect(() => {
    const c = new AbortController();
    api
      .request(
        `${api.prefix}/outbound-dispatch-policy`,
        { signal: c.signal },
        asDispatchPolicy,
      )
      .then((p) => {
        if (!c.signal.aborted) setPolicy(p);
      })
      .catch((e) => {
        if (!c.signal.aborted) onError(e);
      });
    api
      .request(
        `${api.prefix}/outbound-dispatch-reviews?limit=50&after=${after}`,
        { signal: c.signal },
        (v) => asDispatchPage(v, actor),
      )
      .then((p) => {
        if (!c.signal.aborted) setPage(p);
      })
      .catch((e) => {
        if (!c.signal.aborted) onError(e);
      });
    return () => c.abort();
  }, [api, actor, refresh, reload, after]);
  async function loadDelivery() {
    if (!uuid(deliveryID)) return;
    setBusy(true);
    try {
      const d = await api.request(
        `${api.prefix}/outbound-deliveries/${deliveryID}`,
        {},
        (v) => asDispatchView(v, deliveryID),
      );
      if (alive.current) setView(d);
    } catch (e) {
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function preview() {
    if (!view || !uuid(reviewer) || reviewer === actor) return;
    setBusy(true);
    setFailure("");
    const x: DispatchSelection = {
      delivery_id: view.id,
      definition_hash: view.definition_hash,
      expected_revision: view.revision,
      reviewer_id: reviewer,
    };
    try {
      const p = await approvalPost(
        api,
        `${api.prefix}/outbound-dispatch-reviews/preview`,
        x,
        undefined,
        (v) =>
          asDispatchPreview(
            v,
            actor,
            session.identity.authority_revision,
            x,
            view,
          ),
      );
      if (alive.current)
        setPending({
          kind: "proposal",
          selection: x,
          preview: p,
          key: operationKey(),
        });
    } catch (e) {
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function loadReview(r: DispatchSummary) {
    setBusy(true);
    try {
      const p = await api.request(
        `${api.prefix}/outbound-dispatch-reviews/${r.id}`,
        {},
        (v) => asDispatchReview(v, actor, r),
      );
      if (alive.current) setSelected(p);
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
        const x = pending;
        const p = await approvalPost(
          api,
          `${api.prefix}/outbound-dispatch-policy`,
          { expected_revision: x.policy.revision, mode: x.mode },
          x.key,
          (v) =>
            asDispatchPolicyResult(v, { ...x.policy, mode: x.mode }, actor),
        );
        if (alive.current) {
          setPolicy(p);
          setView(null);
          setNotice(
            "Dispatch policy recorded. Old intents keep their original revision and may be blocked; inspect exact work before recovery.",
          );
        }
      } else if (pending.kind === "proposal") {
        const x = pending;
        const r = await approvalPost(
          api,
          `${api.prefix}/outbound-dispatch-reviews`,
          {
            selection: x.selection,
            definition_hash: x.preview.definition_hash,
          },
          x.key,
          (v) =>
            asDispatchResult(v, actor, {
              hash: x.preview.definition_hash,
              delivery: x.selection.delivery_id,
              state: "pending",
              revision: 1,
            }),
        );
        if (alive.current)
          setNotice(
            `Dispatch review ${r.id} is pending. The named reviewer must inspect and approve it before a sender can start.`,
          );
      } else {
        const x = pending,
          r = x.review;
        await approvalPost(
          api,
          `${api.prefix}/outbound-dispatch-reviews/${r.id}/${x.action}`,
          { definition_hash: r.definition_hash, expected_revision: r.revision },
          x.key,
          (v) =>
            asDispatchResult(v, actor, {
              hash: r.definition_hash,
              id: r.id,
              delivery: r.delivery_id,
              state:
                x.action === "approve"
                  ? "approved"
                  : x.action === "reject"
                    ? "rejected"
                    : "withdrawn",
              revision: r.revision + 1,
            }),
        );
        if (alive.current) {
          setSelected(null);
          setNotice(
            "Dispatch review decision recorded. Starting the delivery remains a separate action that rechecks current state and authority.",
          );
        }
      }
      if (alive.current) {
        setPending(null);
        setReload((n) => n + 1);
      }
    } catch (e) {
      if (alive.current)
        setFailure(
          "Dispatch decision not confirmed. Retry with the same key, or inspect current private history before starting again. Changed state, authority or policy requires fresh review.",
        );
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <section className="panel" aria-label="Outbound dispatch approvals">
      <h2>Outbound dispatch approvals</h2>
      <p>
        This rule applies to every outbound delivery intent, including ordinary
        workflows, onboarding test/production sends and direct CLI sends.
        Release/configuration approval and approval of this exact file are
        separate controls. It does not govern incoming transfers or ordinary
        downloads.
      </p>
      <p>
        {policy
          ? `Dispatch policy revision ${policy.revision}: ${policy.mode === "independent" ? "a different named account must approve each exact intent before sending" : "existing author/workflow approval rules apply"}.`
          : "Loading dispatch policy…"}
      </p>
      {canGovern && policy && (
        <>
          <label>
            Policy for outbound dispatches
            <select
              value={mode}
              disabled={busy}
              onChange={(e) =>
                setMode(e.target.value as DispatchPolicy["mode"])
              }
            >
              <option value="independent">Independent named reviewer</option>
              <option value="author">Existing author approval</option>
            </select>
          </label>
          <button
            disabled={busy}
            onClick={() => {
              setFailure("");
              setPending({ kind: "policy", policy, mode, key: operationKey() });
            }}
          >
            Review dispatch policy change
          </button>
        </>
      )}
      <p>
        Changing policy does not rewrite queued work or undo prior effects.
        Stale intents remain recorded and blocked. Never treat an old approval
        receipt as permission for a new send. Ordinary bounded read-only receipt
        reconciliation remains available under current authority.
      </p>
      {notice && <p role="status">{notice}</p>}
      {canSend && (
        <section className="signature-box">
          <h3>Prepare an exact dispatch review</h3>
          <p>
            Use the delivery ID from its CLI result or workflow step. Inspect
            its saved file, destination, policy and attempt state before sharing
            metadata.
          </p>
          <label>
            Outbound delivery ID
            <input
              value={deliveryID}
              onChange={(e) => setDeliveryID(e.target.value)}
              disabled={busy}
            />
          </label>
          <button
            disabled={busy || !uuid(deliveryID)}
            onClick={() => void loadDelivery()}
          >
            Inspect outbound delivery
          </button>
          {view && (
            <>
              <h4 tabIndex={-1} ref={viewHeading}>
                Outbound delivery: {view.state}
              </h4>
              <DispatchDetails
                d={{
                  delivery_id: view.id,
                  source: view.source,
                  effect: view.effect,
                }}
              />
              <p>
                Revision {view.revision}, attempts {view.attempts}; definition
                SHA-256 <code>{view.definition_hash}</code>. Frozen policy{" "}
                {view.policy.revision}/{view.policy.mode}; current policy{" "}
                {view.current_policy.revision}/{view.current_policy.mode}.{" "}
                {view.current_approval
                  ? "Current dispatch approval checks pass."
                  : "Sending remains blocked by current dispatch approval checks."}
              </p>
              {view.reviewable ? (
                <>
                  <label>
                    Dispatch reviewer account ID
                    <input
                      value={reviewer}
                      onChange={(e) => setReviewer(e.target.value)}
                      disabled={busy}
                    />
                  </label>
                  <button
                    disabled={busy || !uuid(reviewer) || reviewer === actor}
                    onClick={() => void preview()}
                  >
                    Preview dispatch review package
                  </button>
                </>
              ) : (
                <p>
                  This intent cannot receive a fresh dispatch review in its
                  current state. New review requires an untouched draft/queued
                  intent at the current policy revision. Inspect recorded
                  evidence and use the appropriate cancellation/recovery path;
                  do not resend uncertain work.
                </p>
              )}
            </>
          )}
        </section>
      )}
      <h3>Private dispatch review history</h3>
      <p>
        Only requests you authored or were explicitly assigned are listed. The
        package grants no source-file download or private
        workflow/delivery-record access.
      </p>
      {page.reviews.length === 0 && <p>No dispatch reviews on this page.</p>}
      <ul>
        {page.reviews.map((r) => (
          <li key={r.id}>
            <code>{r.id}</code> — {r.state}, delivery{" "}
            <code>{r.delivery_id}</code>.{" "}
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void loadReview(r)}
            >
              Inspect dispatch review {r.id.slice(0, 8)}
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
          First dispatch review page
        </button>
        <button
          className="secondary"
          disabled={busy || !page.next}
          onClick={() => setAfter(page.next ?? "")}
        >
          Next dispatch review page
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          Refresh dispatch review history
        </button>
      </div>
      {selected && (
        <section className="signature-box">
          <h4 tabIndex={-1} ref={reviewHeading}>
            Dispatch review: {selected.state}
          </h4>
          <DispatchDetails d={selected.definition} />
          <p>
            Author <code>{selected.author_id}</code>, assigned reviewer{" "}
            <code>{selected.reviewer_id}</code> at authority revision{" "}
            {selected.definition.reviewer_authority_revision}; policy revision{" "}
            {selected.definition.policy.revision}. Package SHA-256{" "}
            <code>{selected.definition_hash}</code>.
          </p>
          <div className="actions">
            {selected.state === "pending" &&
              selected.reviewer_id === actor &&
              canReview &&
              (["approve", "reject"] as const).map((action) => (
                <button
                  key={action}
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "decision",
                      review: selected,
                      action,
                      key: operationKey(),
                    });
                  }}
                >
                  {action === "approve"
                    ? "Review dispatch approval"
                    : "Review dispatch rejection"}
                </button>
              ))}
            {["pending", "approved"].includes(selected.state) &&
              ((selected.author_id === actor && canSend) ||
                (selected.reviewer_id === actor && canReview)) && (
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "decision",
                      review: selected,
                      action: "withdraw",
                      key: operationKey(),
                    });
                  }}
                >
                  Review dispatch withdrawal
                </button>
              )}
          </div>
          <p>
            Either participant can withdraw pending/approved consent. A later
            credential change or expiry invalidates the old approval. An
            untouched intent can be reviewed again without changing its ID or
            bytes; attempted/uncertain work needs its separate recovery proof.
          </p>
        </section>
      )}
      {pending && (
        <ApprovalConfirm
          title={
            pending.kind === "policy"
              ? "Change outbound dispatch policy"
              : pending.kind === "proposal"
                ? "Share exact dispatch metadata"
                : `Confirm dispatch ${pending.action}`
          }
          busy={busy}
          failure={failure}
          onConfirm={() => void confirm()}
          onCancel={() => setPending(null)}
        >
          {pending.kind === "policy" ? (
            <p>
              Change dispatch policy revision {pending.policy.revision} to{" "}
              {pending.policy.revision + 1}, using{" "}
              {pending.mode === "independent"
                ? "a different named account's approval for every outbound intent"
                : "existing author/workflow approval rules"}
              . Existing intents retain their old policy revision and fail
              current-policy checks. No files are sent or removed by this
              decision.
            </p>
          ) : pending.kind === "proposal" ? (
            <>
              <DispatchDetails d={pending.preview.definition} />
              <p>
                Share this metadata with{" "}
                <code>{pending.preview.definition.reviewer_id}</code>. Delivery
                definition{" "}
                <code>{pending.preview.definition.delivery_hash}</code>,
                snapshot revision {pending.preview.definition.delivery_revision}
                , policy revision {pending.preview.definition.policy.revision},
                package SHA-256 <code>{pending.preview.definition_hash}</code>.
                No receiver contact or file access is granted.
              </p>
            </>
          ) : (
            <>
              <DispatchDetails d={pending.review.definition} />
              <p>
                Exact review <code>{pending.review.id}</code>, revision{" "}
                {pending.review.revision}, SHA-256{" "}
                <code>{pending.review.definition_hash}</code>. Action:{" "}
                {pending.action}. This records consent only; sending rechecks
                the target state and current authority.
              </p>
            </>
          )}
        </ApprovalConfirm>
      )}
    </section>
  );
}
