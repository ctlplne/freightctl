import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { uuid, type Session } from "./types";
import { asOnboardingView, type OnboardingPlan } from "./onboarding-types";
import {
  asReleaseView,
  asProductionStatus,
  type ProductionStatus,
} from "./onboarding-releases-types";
import {
  asHandoffPreview,
  asHandoffResult,
  asHandoffPage,
  asHandoffView,
  type HandoffSelection,
  type HandoffPreview,
  type HandoffSummary,
  type HandoffView,
} from "./onboarding-handoffs-types";
import type { TestEffect } from "./onboarding-tests-types";
type Review =
  | { kind: "proposal"; preview: HandoffPreview; key: string }
  | {
      kind: "decision";
      action: "approve" | "cancel" | "execute";
      view: HandoffView;
      key: string;
    };
function Receiver({ effect }: { effect: TestEffect }) {
  return (
    <>
      <p>
        {effect.user}@{effect.address} · <code>{effect.directory}</code> ·{" "}
        <code>{effect.filename}</code>.
      </p>
      <p>
        Host fingerprint <code>{effect.host_fingerprint}</code> · client
        fingerprint <code>{effect.key_fingerprint}</code>.
      </p>
      <p>
        {effect.encryption ? (
          <>
            Recipient <code>{effect.recipient_fingerprint}</code> · key{" "}
            <code>{effect.encryption.key.id}</code> version{" "}
            {effect.encryption.key.version} · {effect.encryption.profile}.
          </>
        ) : (
          "This workflow has no recipient encryption."
        )}
      </p>
    </>
  );
}
export function OnboardingHandoffs({
  api,
  session,
  plan,
  onError,
  source,
}: {
  api: Api;
  session: Session;
  plan: OnboardingPlan;
  onError: (e: unknown) => void;
  source?: { id: string; hash: string; fileID?: string };
}) {
  const [runID, setRunID] = useState(""),
    [profile, setProfile] = useState<NonNullable<HandoffSelection["profile"]>>(
      "untouched-production-handoff-v1",
    ),
    [sourceHash, setSourceHash] = useState(""),
    [releaseID, setReleaseID] = useState(""),
    [revision, setRevision] = useState(""),
    [releaseHash, setReleaseHash] = useState(""),
    [fileID, setFileID] = useState(""),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [history, setHistory] = useState<{
      handoffs: HandoffSummary[];
      next?: string;
    }>({ handoffs: [] }),
    [view, setView] = useState<HandoffView | null>(null),
    [review, setReview] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [replacement, setReplacement] = useState<ProductionStatus | null>(null);
  const alive = useRef(true),
    dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    result = useRef<HTMLHeadingElement>(null),
    replacementTitle = useRef<HTMLHeadingElement>(null),
    workKeys = useRef(new Map<string, string>()),
    author = session.identity.actor_id,
    has = (p: string) => session.identity.permissions.includes(p),
    canManage = has("workflow_manage"),
    canApprove = has("workflow_approve"),
    canExecute = has("workflow_execute") && has("deliver");
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (source) {
      setRunID(source.id);
      setSourceHash(source.hash);
      if (source.fileID) setFileID(source.fileID);
    }
  }, [source?.id, source?.hash, source?.fileID]);
  useEffect(() => {
    const abort = new AbortController();
    api
      .request(
        `${api.prefix}/onboarding-plans/${plan.id}/handoffs?limit=50&after=${after}`,
        { signal: abort.signal },
        (v) => asHandoffPage(v, author),
      )
      .then((p) => {
        if (!abort.signal.aborted) setHistory(p);
      })
      .catch((e) => {
        if (!abort.signal.aborted) onError(e);
      });
    return () => abort.abort();
  }, [api, plan.id, after, reload, author]);
  useEffect(() => {
    if (review) {
      dialog.current?.showModal();
      title.current?.focus();
    } else dialog.current?.close();
  }, [review]);
  useEffect(() => {
    if (view) result.current?.focus();
  }, [view]);
  useEffect(() => {
    if (replacement) replacementTitle.current?.focus();
  }, [replacement]);
  async function inspect(h: { id: string; definition_hash: string }) {
    return api.request(`${api.prefix}/onboarding-handoffs/${h.id}`, {}, (v) =>
      asHandoffView(v, author, plan.id, { id: h.id, hash: h.definition_hash }),
    );
  }
  async function load(h: HandoffSummary) {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const value = await inspect(h);
      if (alive.current) {
        setView(value);
        setReplacement(null);
      }
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function preview() {
    if (busy) return;
    const n = Number(revision);
    if (
      !uuid(runID) ||
      !uuid(releaseID) ||
      !uuid(fileID) ||
      !/^[a-f0-9]{64}$/.test(sourceHash) ||
      !/^[a-f0-9]{64}$/.test(releaseHash) ||
      !Number.isSafeInteger(n) ||
      n < 3
    ) {
      setFailure(
        "Choose the exact original production run/hash, tested active target release/revision/hash and accepted source UUID from their receipts.",
      );
      return;
    }
    const selection: HandoffSelection = {
      source_run_id: runID,
      source_hash: sourceHash,
      target_release: { id: releaseID, revision: n, hash: releaseHash },
      file_id: fileID,
      ...(profile === "prepublication-production-handoff-v1"
        ? { profile }
        : {}),
    };
    setBusy(true);
    setFailure("");
    try {
      const p = await api.request(
        `${api.prefix}/onboarding-handoffs/preview`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(selection),
        },
        (v) => asHandoffPreview(v, selection, author, plan.id),
      );
      if (alive.current)
        setReview({ kind: "proposal", preview: p, key: operationKey() });
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function save() {
    if (!review || busy) return;
    const frozen = review;
    setBusy(true);
    setFailure("");
    try {
      let h: HandoffSummary;
      if (frozen.kind === "proposal") {
        const d = frozen.preview.definition;
        h = await api.request(
          `${api.prefix}/onboarding-handoffs`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify({ definition: d }),
          },
          (v) =>
            asHandoffResult(v, author, {
              hash: frozen.preview.definition_hash,
              state: "proposed",
              source: d.source.dispatch.id,
              target: d.target.release,
            }),
        );
      } else {
        const h0 = frozen.view.handoff,
          d = h0.definition;
        h = await api.request(
          `${api.prefix}/onboarding-handoffs/${h0.id}/${frozen.action}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify({
              definition_hash: h0.definition_hash,
              expected_revision: h0.revision,
            }),
          },
          (v) =>
            asHandoffResult(v, author, {
              hash: h0.definition_hash,
              id: h0.id,
              state: {
                approve: "approved",
                cancel: "cancelled",
                execute: "completed",
              }[frozen.action],
              source: h0.source_run_id,
              target: d.target.release,
            }),
        );
      }
      const value = await inspect(h);
      if (!alive.current) return;
      setView(value);
      setReplacement(null);
      setReview(null);
      setReload((n) => n + 1);
    } catch (e) {
      if (alive.current) {
        setFailure(
          "The handoff result is not confirmed. Retry this same reviewed command and key; inspect private history before creating another operation.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function replacementState() {
    if (!view || !view.handoff.replacement_run_id) return null;
    const h = view.handoff,
      d = h.definition,
      p = d.source.plan;
    const historical =
      p.version === plan.version && p.hash === plan.definition_hash
        ? plan
        : (
            await api.request(
              `${api.prefix}/onboarding-plans/${plan.id}?version=${p.version}`,
              {},
              asOnboardingView,
            )
          ).plan;
    const target = await api.request(
      `${api.prefix}/onboarding-releases/${d.target.release.id}`,
      {},
      (v) =>
        asReleaseView(v, historical, author, {
          id: d.target.release.id,
          definition_hash: d.target.release.hash,
        }),
    );
    return api.request(
      `${api.prefix}/onboarding-production/${h.replacement_run_id}`,
      {},
      (v) =>
        asProductionStatus(
          v,
          target,
          { id: h.replacement_run_id, hash: d.target_hash },
          author,
        ),
    );
  }
  async function inspectReplacement() {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const status = await replacementState();
      if (alive.current) setReplacement(status);
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function executeReplacement() {
    if (
      !view?.handoff.replacement_run_id ||
      busy ||
      !canExecute ||
      !replacement?.current
    )
      return;
    const id = view.handoff.replacement_run_id;
    let key = workKeys.current.get(id);
    if (!key) {
      key = operationKey();
      workKeys.current.set(id, key);
    }
    setBusy(true);
    setFailure("");
    try {
      await api.request(
        `${api.prefix}/workflow-runs/${id}/work`,
        { method: "POST", headers: { "Idempotency-Key": key } },
        () => true,
      );
      const status = await replacementState();
      if (alive.current) setReplacement(status);
    } catch (e) {
      if (alive.current) {
        setFailure(
          "Transfer outcome is not confirmed. Inspect this exact replacement run before recovery; a lost response does not prove the receiver received nothing.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  const d =
    review?.kind === "proposal"
      ? review.preview.definition
      : review?.view.handoff.definition;
  return (
    <section className="signature-box" aria-label="Queued production handoffs">
      <h2>Queued work after rotation</h2>
      <p>
        Preserve queued production bytes across a tested key, credential or
        activation change. Review and approve the exact replacement, then cancel
        the old intent and queue one successor together. Separate execution
        sends bytes. Choose untouched work, or explicitly review a failed
        attempt whose complete journal proves publication never started. Live
        workers, publication and uncertain outcomes require reconciliation.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Handoff</th>
              <th scope="col">Original run / state</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {history.handoffs.map((h) => (
              <tr key={h.id}>
                <td>
                  <code>{h.id}</code>
                </td>
                <td>
                  <code>{h.source_run_id}</code> · {h.state}
                </td>
                <td>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => void load(h)}
                  >
                    Inspect handoff {h.id.slice(0, 8)}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="actions">
        <button
          className="secondary"
          disabled={busy || !after}
          onClick={() => setAfter("")}
        >
          First handoff page
        </button>
        <button
          className="secondary"
          disabled={busy || !history.next}
          onClick={() => setAfter(history.next ?? "")}
        >
          Next handoff page
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          Refresh handoffs
        </button>
      </div>
      {view && (
        <div className="signature-box">
          <h3 ref={result} tabIndex={-1}>
            Queued handoff: {view.handoff.state}
          </h3>
          <p role="status">
            {view.handoff.state === "completed"
              ? "The original intent was cancelled and its exact successor queued atomically. This handoff sent no bytes. Inspect and execute the successor separately."
              : view.current_bindings
                ? "The reviewed source still meets its exact eligibility proof and the target activation is current. Approval reserves no worker or remote state."
                : view.handoff.state === "cancelled"
                  ? "This handoff was cancelled; original job history is retained."
                  : "A reviewed source or target binding changed. New approval/execution is blocked; prepare a new review when appropriate."}
          </p>
          <p>
            Handoff <code>{view.handoff.id}</code> · revision{" "}
            {view.handoff.revision} · definition{" "}
            <code>{view.handoff.definition_hash}</code>. Original run{" "}
            <code>{view.handoff.source_run_id}</code>.{" "}
            {view.handoff.replacement_run_id && (
              <>
                Replacement <code>{view.handoff.replacement_run_id}</code>.
              </>
            )}
          </p>
          <div className="actions">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void load(view.handoff)}
            >
              Inspect current handoff state
            </button>
            {(["approve", "execute", "cancel"] as const).map((action) => {
              const allowed =
                action === "approve"
                  ? canApprove &&
                    view.handoff.state === "proposed" &&
                    view.current_bindings
                  : action === "execute"
                    ? canExecute &&
                      view.handoff.state === "approved" &&
                      view.current_bindings
                    : canManage &&
                      ["proposed", "approved"].includes(view.handoff.state);
              return (
                <button
                  key={action}
                  disabled={busy || !allowed}
                  onClick={() => {
                    setFailure("");
                    setReview({
                      kind: "decision",
                      action,
                      view,
                      key: operationKey(),
                    });
                  }}
                >
                  {action === "approve"
                    ? "Approve handoff"
                    : action === "execute"
                      ? "Execute approved handoff"
                      : "Cancel handoff"}
                </button>
              );
            })}
          </div>
          {view.handoff.replacement_run_id && (
            <>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => void inspectReplacement()}
              >
                Inspect replacement run
              </button>
              {replacement && (
                <div>
                  <h4 ref={replacementTitle} tabIndex={-1}>
                    Replacement run: {replacement.state}
                  </h4>
                  <p role="status">
                    {replacement.reason} · current bindings:{" "}
                    {String(replacement.current)}.{" "}
                    {replacement.steps
                      .map(
                        (s) => `${s.state}; attempts ${s.attempts}; ${s.code}`,
                      )
                      .join(" ")}
                  </p>
                  <p>
                    Source <code>{replacement.definition.file.id}</code> ·
                    SHA-256 <code>{replacement.definition.file.sha256}</code> ·{" "}
                    {replacement.definition.file.size_bytes} bytes.
                  </p>
                  <button
                    disabled={
                      busy ||
                      !canExecute ||
                      !replacement.current ||
                      !["queued", "running"].includes(replacement.state)
                    }
                    onClick={() => void executeReplacement()}
                  >
                    Execute replacement transfer
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void preview();
        }}
      >
        <h3>Prepare a queued-work handoff</h3>
        <label htmlFor="handoff-profile">Original delivery eligibility</label>
        <select
          id="handoff-profile"
          disabled={busy}
          value={profile}
          onChange={(e) =>
            setProfile(
              e.target.value as NonNullable<HandoffSelection["profile"]>,
            )
          }
        >
          <option value="untouched-production-handoff-v1">
            Untouched: zero delivery attempts
          </option>
          <option value="prepublication-production-handoff-v1">
            Failed before publication: verify the complete journal
          </option>
        </select>
        <label htmlFor="handoff-source-run">Original production run UUID</label>
        <input
          id="handoff-source-run"
          required
          maxLength={36}
          disabled={busy}
          value={runID}
          onChange={(e) => setRunID(e.target.value)}
        />
        <label htmlFor="handoff-source-hash">
          Original production definition SHA-256
        </label>
        <input
          id="handoff-source-hash"
          required
          maxLength={64}
          disabled={busy}
          value={sourceHash}
          onChange={(e) => setSourceHash(e.target.value)}
        />
        <label htmlFor="handoff-target-release">
          Tested target release UUID
        </label>
        <input
          id="handoff-target-release"
          required
          maxLength={36}
          disabled={busy}
          value={releaseID}
          onChange={(e) => setReleaseID(e.target.value)}
        />
        <label htmlFor="handoff-target-revision">
          Target activation revision
        </label>
        <input
          id="handoff-target-revision"
          required
          type="number"
          min={3}
          disabled={busy}
          value={revision}
          onChange={(e) => setRevision(e.target.value)}
        />
        <label htmlFor="handoff-target-hash">Target release SHA-256</label>
        <input
          id="handoff-target-hash"
          required
          maxLength={64}
          disabled={busy}
          value={releaseHash}
          onChange={(e) => setReleaseHash(e.target.value)}
        />
        <label htmlFor="handoff-file">Accepted replacement file UUID</label>
        <input
          id="handoff-file"
          required
          maxLength={36}
          disabled={busy}
          value={fileID}
          onChange={(e) => setFileID(e.target.value)}
        />
        <p>
          Keep the original accepted file, or select its linked checked revision
          with identical bytes and fresh release. A new raw upload cannot
          replace checked lineage. Receiver account, directory, filename,
          workflow family and encryption mode/profile must stay the same.
        </p>
        <button type="submit" disabled={busy}>
          Preview queued handoff
        </button>
      </form>
      {failure && !review && <p role="alert">{failure}</p>}
      <dialog
        ref={dialog}
        className="review-dialog"
        aria-labelledby="handoff-review-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        {review && d && (
          <>
            <h2 id="handoff-review-title" ref={title} tabIndex={-1}>
              {review.kind === "proposal"
                ? "Review queued handoff"
                : `Review ${review.action} handoff`}
            </h2>
            <p>
              {review.kind === "proposal"
                ? "Save this exact source eligibility proof and tested target as a private proposal. No cancellation, successor or receiver contact occurs."
                : review.action === "approve"
                  ? "Approve this exact before/after definition. The source is rechecked now and again at execution; approval does not reserve it."
                  : review.action === "execute"
                    ? "Atomically cancel the exact eligible original intent and queue one distinct successor with the reviewed source and tested activation. A failed transaction preserves the original. This step sends no bytes."
                    : "Cancel only this handoff proposal. It does not delete original work or evidence."}
            </p>
            <div className="signature-box">
              <h3>Reviewed original snapshot</h3>
              <p>
                Run <code>{d.source.dispatch.id}</code> · run revision{" "}
                {d.source.run_revision} · delivery{" "}
                <code>{d.source.delivery.id}</code> revision{" "}
                {d.source.delivery.revision} · attempts {d.source.attempts} ·
                fence {d.source.fence}. Original activation{" "}
                <code>{d.source.dispatch.definition.release.id}</code> revision{" "}
                {d.source.dispatch.definition.release.revision}.
              </p>
              <Receiver effect={d.source.dispatch.definition.effect} />
              {d.prepublication_proof && (
                <p>
                  Original state {d.source.state}. The complete journal has{" "}
                  {d.prepublication_proof.transitions} transitions and no
                  publication boundary. History SHA-256{" "}
                  <code>{d.prepublication_proof.history_hash}</code>; last event{" "}
                  <code>{d.prepublication_proof.last_event_id}</code>.
                  {d.prepublication_proof.ciphertext ? (
                    <>
                      {" "}
                      Retain original ciphertext{" "}
                      <code>
                        {d.prepublication_proof.ciphertext.object_id}
                      </code>{" "}
                      ({d.prepublication_proof.ciphertext.size_bytes} bytes),
                      SHA-256{" "}
                      <code>{d.prepublication_proof.ciphertext.sha256}</code>.
                    </>
                  ) : (
                    " No original ciphertext artifact is recorded."
                  )}{" "}
                  Remote partial files remain retained. This proof does not
                  establish receiver business acceptance.
                </p>
              )}
              <p>
                File <code>{d.source.dispatch.definition.file.id}</code> ·{" "}
                {d.source.dispatch.definition.file.size_bytes} bytes · SHA-256{" "}
                <code>{d.source.dispatch.definition.file.sha256}</code> · policy{" "}
                {d.source.dispatch.definition.file.policy}.
              </p>
            </div>
            <div className="signature-box">
              <h3>Reviewed successor</h3>
              <p>
                Activation <code>{d.target.release.id}</code> revision{" "}
                {d.target.release.revision} · workflow{" "}
                <code>{d.target.workflow.id}</code> version{" "}
                {d.target.workflow.version} · authority{" "}
                {d.source.dispatch.definition.authority_revision} →{" "}
                {d.target.authority_revision}.
              </p>
              <Receiver effect={d.target.effect} />
              <p>
                File <code>{d.target.file.id}</code> ·{" "}
                {d.target.file.size_bytes} bytes · SHA-256{" "}
                <code>{d.target.file.sha256}</code> · policy{" "}
                {d.target.file.policy}.{" "}
                {d.source_recheck_id ? (
                  <>
                    Linked checked revision <code>{d.source_recheck_id}</code>.
                  </>
                ) : (
                  "The original accepted revision is retained."
                )}
              </p>
            </div>
            <p>
              Definition SHA-256{" "}
              <code>
                {review.kind === "proposal"
                  ? review.preview.definition_hash
                  : review.view.handoff.definition_hash}
              </code>
              . Publication or business ambiguity cannot be cleared by this
              handoff.
            </p>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                disabled={
                  busy ||
                  (review.kind === "proposal"
                    ? !canManage
                    : review.action === "approve"
                      ? !canApprove
                      : review.action === "execute"
                        ? !canExecute
                        : !canManage)
                }
                onClick={() => void save()}
              >
                {review.kind === "proposal"
                  ? "Save reviewed handoff"
                  : `Confirm ${review.action} handoff`}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setReview(null)}
              >
                Cancel handoff review
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
