import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { OnboardingObservations } from "./onboarding-observations";
import { OnboardingHandoffs } from "./onboarding-handoffs";
import { uuid, type Session } from "./types";
import { asOnboardingView, type OnboardingPlan } from "./onboarding-types";
import {
  asReleasePage,
  asReleasePreview,
  asReleaseResult,
  asReleaseView,
  asProductionPreview,
  asProductionResult,
  asProductionPage,
  asProductionStatus,
  type ProductionSummary,
  type ProductionStatus,
  type ReleasePreview,
  type ReleaseSelection,
  type ReleaseSummary,
  type ReleaseView,
  type ProductionPreview,
} from "./onboarding-releases-types";

type Review =
  | {
      kind: "proposal";
      preview: ReleasePreview;
      selection: ReleaseSelection;
      key: string;
    }
  | {
      kind: "decision";
      action: "approve" | "activate" | "suspend" | "revoke";
      view: ReleaseView;
      plan: OnboardingPlan;
      key: string;
    }
  | {
      kind: "production";
      preview: ProductionPreview;
      view: ReleaseView;
      key: string;
    };
export function OnboardingReleases({
  api,
  session,
  plan,
  authority,
  onError,
}: {
  api: Api;
  session: Session;
  plan: OnboardingPlan;
  authority: number;
  onError: (e: unknown) => void;
}) {
  const [ids, setIDs] = useState(""),
    [page, setPage] = useState<{ releases: ReleaseSummary[]; next?: string }>({
      releases: [],
    }),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [selected, setSelected] = useState<{
      view: ReleaseView;
      plan: OnboardingPlan;
    } | null>(null),
    [review, setReview] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [requirement, setRequirement] = useState(""),
    [file, setFile] = useState(""),
    [run, setRun] = useState<{ id: string; hash: string } | null>(null),
    [runState, setRunState] = useState("");
  const [productionPage, setProductionPage] = useState<{
      dispatches: ProductionSummary[];
      next?: string;
    }>({ dispatches: [] }),
    [productionAfter, setProductionAfter] = useState(""),
    [productionStatus, setProductionStatus] = useState<ProductionStatus | null>(
      null,
    );
  const alive = useRef(true),
    dialog = useRef<HTMLDialogElement>(null),
    heading = useRef<HTMLHeadingElement>(null),
    runHeading = useRef<HTMLHeadingElement>(null),
    statusHeading = useRef<HTMLHeadingElement>(null),
    workKeys = useRef(new Map<string, string>());
  const author = session.identity.actor_id,
    has = (grant: string) => session.identity.permissions.includes(grant),
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
    const abort = new AbortController();
    api
      .request(
        `${api.prefix}/onboarding-plans/${plan.id}/releases?limit=50&after=${after}`,
        { signal: abort.signal },
        (v) => asReleasePage(v, author, plan.id),
      )
      .then((p) => {
        if (!abort.signal.aborted) setPage(p);
      })
      .catch((e) => {
        if (!abort.signal.aborted) onError(e);
      });
    return () => abort.abort();
  }, [api, plan.id, after, reload, author]);
  useEffect(() => {
    if (review) {
      dialog.current?.showModal();
      heading.current?.focus();
    } else dialog.current?.close();
  }, [review]);
  useEffect(() => {
    if (selected) statusHeading.current?.focus();
  }, [selected]);
  useEffect(() => {
    if (!selected) return;
    const abort = new AbortController();
    api
      .request(
        `${api.prefix}/onboarding-releases/${selected.view.release.id}/runs?limit=50&after=${productionAfter}`,
        { signal: abort.signal },
        (v) => asProductionPage(v, selected.view),
      )
      .then((p) => {
        if (!abort.signal.aborted) setProductionPage(p);
      })
      .catch((e) => {
        if (!abort.signal.aborted) onError(e);
      });
    return () => abort.abort();
  }, [api, selected, productionAfter, reload]);
  async function inspectProduction(ref: { id: string; hash: string }) {
    if (!selected) return null;
    return api.request(
      `${api.prefix}/onboarding-production/${ref.id}`,
      {},
      (v) => asProductionStatus(v, selected.view, ref, author),
    );
  }
  async function loadProduction(ref: { id: string; hash: string }) {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const s = await inspectProduction(ref);
      if (alive.current && s) {
        setRun(ref);
        setRunState(s.state);
        setProductionStatus(s);
      }
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  useEffect(() => {
    if (run) runHeading.current?.focus();
  }, [run, runState]);
  async function inspect(r: ReleaseSummary) {
    const historical =
      r.plan.version === plan.version && r.plan.hash === plan.definition_hash
        ? plan
        : (
            await api.request(
              `${api.prefix}/onboarding-plans/${plan.id}?version=${r.plan.version}`,
              {},
              asOnboardingView,
            )
          ).plan;
    const view = await api.request(
      `${api.prefix}/onboarding-releases/${r.id}`,
      {},
      (v) => asReleaseView(v, historical, author, r),
    );
    return { view, plan: historical };
  }
  async function load(r: ReleaseSummary) {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const value = await inspect(r);
      if (alive.current) setSelected(value);
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function preview() {
    if (busy) return;
    const test_ids = ids
      .split(/[\s,]+/)
      .filter(Boolean)
      .sort();
    if (
      test_ids.length < 1 ||
      test_ids.length > 64 ||
      new Set(test_ids).size !== test_ids.length ||
      !test_ids.every(uuid)
    ) {
      setFailure(
        "Supply one distinct completed pre-contact test UUID for every saved requirement.",
      );
      return;
    }
    const selection: ReleaseSelection = {
      plan: { id: plan.id, version: plan.version, hash: plan.definition_hash },
      test_ids,
      expected_authority_revision: authority,
    };
    setBusy(true);
    setFailure("");
    try {
      const value = await api.request(
        `${api.prefix}/onboarding-releases/preview`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(selection),
        },
        (v) => asReleasePreview(v, plan, selection, author),
      );
      if (alive.current)
        setReview({
          kind: "proposal",
          preview: value,
          selection,
          key: operationKey(),
        });
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function previewProduction() {
    if (
      busy ||
      !selected?.view.production_active ||
      !uuid(file) ||
      !uuid(requirement)
    )
      return;
    const v = selected.view,
      r = v.release;
    setBusy(true);
    setFailure("");
    try {
      const preview = await api.request(
        `${api.prefix}/onboarding-releases/${r.id}/production-preview`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            definition_hash: r.definition_hash,
            expected_revision: r.revision,
            requirement_id: requirement,
            file_id: file,
          }),
        },
        (value) => asProductionPreview(value, v, requirement, file),
      );
      if (alive.current)
        setReview({
          kind: "production",
          preview,
          view: v,
          key: operationKey(),
        });
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
      if (frozen.kind === "proposal") {
        const r = await api.request(
          `${api.prefix}/onboarding-releases`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify({
              selection: frozen.selection,
              definition_hash: frozen.preview.definition_hash,
            }),
          },
          (v) =>
            asReleaseResult(
              v,
              author,
              plan,
              frozen.preview.definition_hash,
              "proposed",
            ),
        );
        const value = await inspect(r);
        if (!alive.current) return;
        setSelected(value);
        setProductionAfter("");
        setReload((n) => n + 1);
      } else if (frozen.kind === "decision") {
        const r = frozen.view.release,
          next = {
            approve: "approved",
            activate: "active",
            suspend: "suspended",
            revoke: "revoked",
          }[frozen.action];
        const saved = await api.request(
          `${api.prefix}/onboarding-releases/${r.id}/${frozen.action}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify({
              definition_hash: r.definition_hash,
              expected_revision: r.revision,
            }),
          },
          (v) =>
            asReleaseResult(
              v,
              author,
              frozen.plan,
              r.definition_hash,
              next,
              r.id,
            ),
        );
        const value = await inspect(saved);
        if (!alive.current) return;
        setSelected(value);
        setReload((n) => n + 1);
      } else {
        const saved = await api.request(
          `${api.prefix}/onboarding-production`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify({ definition: frozen.preview.definition }),
          },
          (v) => asProductionResult(v, author, frozen.view, frozen.preview),
        );
        if (!alive.current) return;
        setRun(saved);
        setRunState("queued");
        setProductionStatus(null);
        setReload((n) => n + 1);
      }
      setReview(null);
    } catch (e) {
      if (alive.current) {
        setFailure(
          "The saved result is not confirmed. Retry this same reviewed command and key; inspect durable history before creating another operation.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function execute() {
    if (!run || busy || !canExecute) return;
    let key = workKeys.current.get(run.id);
    if (!key) {
      key = operationKey();
      workKeys.current.set(run.id, key);
    }
    setBusy(true);
    setFailure("");
    try {
      await api.request(
        `${api.prefix}/workflow-runs/${run.id}/work`,
        { method: "POST", headers: { "Idempotency-Key": key } },
        () => true,
      );
      const status = await inspectProduction(run);
      if (alive.current && status) {
        setRunState(status.state);
        setProductionStatus(status);
      }
    } catch (e) {
      if (alive.current) {
        setFailure(
          "Execution is not confirmed. Inspect this exact run and its receipts before recovery; a lost response does not mean the receiver saw no bytes.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  const view = selected?.view,
    r = view?.release,
    reviewTests =
      review?.kind === "proposal"
        ? review.preview.tests
        : review?.kind === "decision"
          ? review.view.tests
          : [];
  return (
    <section
      className="signature-box"
      aria-label="Onboarding production releases"
    >
      <h2>Production releases</h2>
      <p>
        Cover every saved requirement with completed pre-contact test evidence.
        Save a release proposal, approve it, then activate it separately.
        Production dispatch records the exact activation revision before bytes
        can leave. These controls apply to this explicit production route;
        ordinary approved manual workflows retain their existing purpose.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Release</th>
              <th scope="col">Plan / state / revision</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {page.releases.map((r) => (
              <tr key={r.id}>
                <td>
                  <code>{r.id}</code>
                </td>
                <td>
                  {r.plan.version} / {r.state} / {r.revision}
                </td>
                <td>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => void load(r)}
                  >
                    Inspect release {r.id.slice(0, 8)}
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
          First release page
        </button>
        <button
          className="secondary"
          disabled={busy || !page.next}
          onClick={() => setAfter(page.next ?? "")}
        >
          Next release page
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          Refresh releases
        </button>
      </div>
      {view && r && (
        <div className="signature-box">
          <h3 ref={statusHeading} tabIndex={-1}>
            Onboarding release: {r.state}
          </h3>
          <p role="status">
            {view.production_active
              ? "This exact release is active for explicit production dispatch."
              : view.current_bindings
                ? "Production dispatch is not active. Approval and activation are separate decisions."
                : "A recorded binding or source policy changed. New production attempts are blocked; historical receipts keep their meanings."}
          </p>
          <p>
            Release <code>{r.id}</code> · revision {r.revision} · approved
            revision {r.approved_revision} · plan version {r.plan.version} ·
            SHA-256 <code>{r.definition_hash}</code>.
          </p>
          <div className="actions">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void load(r)}
            >
              Inspect current release state
            </button>
            {(["approve", "activate", "suspend", "revoke"] as const).map(
              (action) => {
                const eligible =
                  action === "approve"
                    ? r.state === "proposed" &&
                      view.current_bindings &&
                      canApprove
                    : action === "activate"
                      ? ["approved", "suspended"].includes(r.state) &&
                        view.current_bindings &&
                        canExecute
                      : action === "suspend"
                        ? r.state === "active" && canExecute
                        : r.state !== "revoked" && canApprove;
                return (
                  <button
                    key={action}
                    disabled={busy || !eligible}
                    onClick={() => {
                      setFailure("");
                      setReview({
                        kind: "decision",
                        action,
                        view,
                        plan: selected!.plan,
                        key: operationKey(),
                      });
                    }}
                  >
                    {action.charAt(0).toUpperCase() + action.slice(1)} release
                  </button>
                );
              },
            )}
          </div>
          {view.production_active && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void previewProduction();
              }}
            >
              <h4>Prepare a production dispatch</h4>
              <label htmlFor="production-requirement">
                Active release requirement
              </label>
              <select
                id="production-requirement"
                required
                disabled={busy}
                value={requirement}
                onChange={(e) => setRequirement(e.target.value)}
              >
                <option value="">Choose an approved requirement</option>
                {selected?.plan.definition.requirements.map((req) => (
                  <option key={req.id} value={req.id}>
                    {req.name}
                  </option>
                ))}
              </select>
              <label htmlFor="production-file">
                Accepted production file UUID
              </label>
              <input
                id="production-file"
                required
                maxLength={36}
                disabled={busy}
                value={file}
                onChange={(e) => setFile(e.target.value)}
              />
              <button type="submit" disabled={busy || !canExecute}>
                Preview production dispatch
              </button>
            </form>
          )}
        </div>
      )}
      {selected && (
        <div className="signature-box">
          <h3>Recorded production runs</h3>
          <ul>
            {productionPage.dispatches.map((d) => (
              <li key={d.id}>
                <code>{d.id}</code> · activation revision {d.release.revision}{" "}
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() =>
                    void loadProduction({ id: d.id, hash: d.definition_hash })
                  }
                >
                  Inspect production {d.id.slice(0, 8)}
                </button>
              </li>
            ))}
          </ul>
          <div className="actions">
            <button
              className="secondary"
              disabled={busy || !productionAfter}
              onClick={() => setProductionAfter("")}
            >
              First production page
            </button>
            <button
              className="secondary"
              disabled={busy || !productionPage.next}
              onClick={() => setProductionAfter(productionPage.next ?? "")}
            >
              Next production page
            </button>
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setReload((n) => n + 1)}
            >
              Refresh production runs
            </button>
          </div>
        </div>
      )}
      {run && (
        <div className="signature-box">
          <h3 ref={runHeading} tabIndex={-1}>
            Production run: {runState}
          </h3>
          <p>
            Run <code>{run.id}</code> uses the recorded activation revision.
            Queueing made no receiver contact; explicit execution sends bytes
            through the ordinary worker. Inspect its durable state and original
            receipt before recovery.
          </p>
          {productionStatus && (
            <p role="status">
              {productionStatus.reason} · current activation bindings:{" "}
              {String(productionStatus.current)}. Source SHA-256{" "}
              <code>{productionStatus.definition.file.sha256}</code>.{" "}
              {productionStatus.steps
                .map((s) => `${s.state}; attempts ${s.attempts}; ${s.code}`)
                .join(" ")}
            </p>
          )}
          {productionStatus?.recovered_receipt && (
            <p role="status">
              Recovered integrity receipt{" "}
              <code>{productionStatus.recovered_receipt.id}</code>, recorded at{" "}
              <time>{productionStatus.recovered_receipt.completed_at}</time>.
              Exact original wire SHA-256{" "}
              <code>{productionStatus.recovered_receipt.result.sha256}</code> ·{" "}
              {productionStatus.recovered_receipt.result.size_bytes} bytes.
              Business acceptance remains unknown. The original execution
              projection and activation stay unchanged; this receipt grants no
              resend.
            </p>
          )}
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void loadProduction(run)}
          >
            Inspect current production run
          </button>
          <button
            disabled={
              busy ||
              !canExecute ||
              (productionStatus !== null && !productionStatus.current) ||
              !["queued", "running"].includes(runState)
            }
            onClick={() => void execute()}
          >
            Execute production run
          </button>
        </div>
      )}
      <OnboardingObservations
        api={api}
        session={session}
        plan={plan}
        onError={onError}
        {...(run
          ? {
              source: {
                ...run,
                ...(productionStatus
                  ? { fileID: productionStatus.definition.file.id }
                  : {}),
              },
            }
          : {})}
      />
      <OnboardingHandoffs
        api={api}
        session={session}
        plan={plan}
        onError={onError}
        {...(run
          ? {
              source: {
                ...run,
                ...(productionStatus
                  ? { fileID: productionStatus.definition.file.id }
                  : {}),
              },
            }
          : {})}
      />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void preview();
        }}
      >
        <h3>Prepare release proposal</h3>
        <label htmlFor="release-tests">Completed pre-contact test UUIDs</label>
        <textarea
          id="release-tests"
          required
          maxLength={4096}
          disabled={busy}
          value={ids}
          onChange={(e) => setIDs(e.target.value)}
        />
        <p>
          One test per requirement, separated by spaces or commas. Unsupported
          requirements, unfinished tests and missing business receipts remain
          blocking.
        </p>
        <button type="submit" disabled={busy || !authority}>
          Preview release proposal
        </button>
      </form>
      {failure && !review && <p role="alert">{failure}</p>}
      <dialog
        ref={dialog}
        className="review-dialog"
        aria-labelledby="release-review-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        {review && (
          <>
            <h2 id="release-review-title" ref={heading} tabIndex={-1}>
              {review.kind === "proposal"
                ? "Review release proposal"
                : review.kind === "decision"
                  ? `Review ${review.action} release`
                  : "Review production dispatch"}
            </h2>
            {review.kind === "proposal" ? (
              <p>
                Save immutable evidence for all{" "}
                {review.preview.definition.proofs.length} saved requirements.
                This creates a proposal. It does not approve, activate or
                contact a receiver. Review contact obligations, notes and
                receiver contracts in the saved draft.
              </p>
            ) : review.kind === "decision" ? (
              <p>
                {review.action === "approve"
                  ? "Approve this exact requirement/test evidence and definition. Production remains inactive until the separate activation action."
                  : review.action === "activate"
                    ? "Activate this exact approved definition for the explicit production route. This action sends no file; each later dispatch rechecks authority and evidence."
                    : review.action === "suspend"
                      ? "Suspend new production attempts for this exact release. Already sent bytes cannot be recalled. Queued runs retain the old activation revision and do not silently revive after reactivation."
                      : "Revoke this exact release permanently. Existing evidence stays visible; new attempts are blocked."}
              </p>
            ) : (
              <p>
                Queue one production workflow run using this exact active
                release, receiver and accepted source. Saving makes no receiver
                contact. Separate execution sends the file.
              </p>
            )}
            {review.kind === "decision" && (
              <p>
                Release <code>{review.view.release.id}</code> · exact revision{" "}
                {review.view.release.revision} · definition{" "}
                <code>{review.view.release.definition_hash}</code>.
              </p>
            )}
            {reviewTests.map((t) => (
              <div key={t.id} className="signature-box">
                <p>
                  Requirement <code>{t.definition.requirement_id}</code> · test{" "}
                  <code>{t.id}</code> · test definition{" "}
                  <code>{t.definition_hash}</code>.
                </p>
                <p>
                  {t.definition.effect.user}@{t.definition.effect.address} ·{" "}
                  <code>{t.definition.effect.directory}</code> ·{" "}
                  <code>{t.definition.effect.filename}</code>. Source SHA-256{" "}
                  <code>{t.definition.file.sha256}</code> · required receipt{" "}
                  {t.definition.required_receipt}.
                </p>
                <p>
                  Host <code>{t.definition.effect.host_fingerprint}</code> ·
                  client <code>{t.definition.effect.key_fingerprint}</code>.{" "}
                  {t.definition.effect.encryption ? (
                    <>
                      Recipient{" "}
                      <code>{t.definition.effect.recipient_fingerprint}</code> ·{" "}
                      {t.definition.effect.encryption.profile}.
                    </>
                  ) : (
                    "No recipient encryption in this approved workflow."
                  )}
                </p>
              </div>
            ))}
            {review.kind === "proposal" && (
              <p>
                Release definition SHA-256{" "}
                <code>{review.preview.definition_hash}</code>. Business
                acceptance is unknown; transport/integrity evidence cannot
                satisfy a business receipt.
              </p>
            )}
            {review.kind === "production" && (
              <div className="signature-box">
                <p>
                  Release <code>{review.preview.definition.release.id}</code> ·
                  activation revision{" "}
                  {review.preview.definition.release.revision}.{" "}
                  {review.preview.definition.effect.user}@
                  {review.preview.definition.effect.address} ·{" "}
                  <code>{review.preview.definition.effect.directory}</code> ·{" "}
                  <code>{review.preview.definition.effect.filename}</code>.
                </p>
                <p>
                  Host{" "}
                  <code>
                    {review.preview.definition.effect.host_fingerprint}
                  </code>{" "}
                  · client{" "}
                  <code>
                    {review.preview.definition.effect.key_fingerprint}
                  </code>
                  .{" "}
                  {review.preview.definition.effect.encryption ? (
                    <>
                      Recipient{" "}
                      <code>
                        {review.preview.definition.effect.recipient_fingerprint}
                      </code>{" "}
                      · {review.preview.definition.effect.encryption.profile}.
                    </>
                  ) : (
                    "No recipient encryption."
                  )}
                </p>
                <p>
                  Accepted file <code>{review.preview.definition.file.id}</code>{" "}
                  · {review.preview.definition.file.size_bytes} bytes · SHA-256{" "}
                  <code>{review.preview.definition.file.sha256}</code> · policy{" "}
                  {review.preview.definition.file.policy}. Dispatch definition{" "}
                  <code>{review.preview.definition_hash}</code>.
                </p>
              </div>
            )}
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                disabled={
                  busy ||
                  (review.kind === "proposal"
                    ? !canManage
                    : review.kind === "production"
                      ? !canExecute
                      : ["approve", "revoke"].includes(review.action)
                        ? !canApprove
                        : !canExecute)
                }
                onClick={() => void save()}
              >
                {review.kind === "proposal"
                  ? "Save release proposal"
                  : review.kind === "production"
                    ? "Queue reviewed production run"
                    : `Confirm ${review.action} release`}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setReview(null)}
              >
                Cancel release review
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
