import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { uuid, type Session } from "./types";
import type { OnboardingPlan } from "./onboarding-types";
import {
  asObservationPreview,
  asObservationReceipt,
  asObservationView,
  asObservationPage,
  type ObservationSelection,
  type ObservationPreview,
  type ObservationSummary,
  type ObservationView,
} from "./onboarding-observations-types";
type Review =
  | { kind: "proposal"; preview: ObservationPreview; key: string }
  | { kind: "approve" | "cancel" | "work"; view: ObservationView; key: string };
export function OnboardingObservations({
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
    [sourceHash, setSourceHash] = useState(""),
    [probeID, setProbeID] = useState(""),
    [fileID, setFileID] = useState(""),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [history, setHistory] = useState<{
      observations: ObservationSummary[];
      next?: string;
    }>({ observations: [] }),
    [view, setView] = useState<ObservationView | null>(null),
    [review, setReview] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState("");
  const alive = useRef(true),
    dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    result = useRef<HTMLHeadingElement>(null),
    author = session.identity.actor_id,
    has = (p: string) => session.identity.permissions.includes(p),
    canManage = has("workflow_manage"),
    canApprove = has("workflow_approve"),
    canWork = has("workflow_execute");
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    setView(null);
    setReview(null);
    setAfter("");
  }, [plan.id]);
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
        `${api.prefix}/onboarding-plans/${plan.id}/observations?limit=50&after=${after}`,
        { signal: abort.signal },
        (v) => asObservationPage(v, author),
      )
      .then((v) => {
        if (!abort.signal.aborted) setHistory(v);
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
  async function inspect(o: { id: string; definition_hash: string }) {
    return api.request(
      `${api.prefix}/onboarding-observations/${o.id}`,
      {},
      (v) =>
        asObservationView(v, author, plan.id, {
          id: o.id,
          hash: o.definition_hash,
        }),
    );
  }
  async function load(o: ObservationSummary) {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const v = await inspect(o);
      if (alive.current) setView(v);
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function preview() {
    if (busy) return;
    if (
      !uuid(runID) ||
      !uuid(probeID) ||
      !uuid(fileID) ||
      !/^[a-f0-9]{64}$/.test(sourceHash)
    ) {
      setFailure(
        "Choose the exact published run/hash, current successful connectivity probe and authorized same-byte file UUID.",
      );
      return;
    }
    const selection: ObservationSelection = {
      source_run_id: runID,
      source_hash: sourceHash,
      probe_id: probeID,
      file_id: fileID,
      expected_authority_revision: session.identity.authority_revision,
    };
    setBusy(true);
    setFailure("");
    try {
      const p = await api.request(
        `${api.prefix}/onboarding-observations/preview`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(selection),
        },
        (v) => asObservationPreview(v, selection, author, plan.id),
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
      let v: ObservationView;
      if (frozen.kind === "work") {
        const o = frozen.view.observation;
        v = await api.request(
          `${api.prefix}/onboarding-observations/${o.id}/work`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify({ definition_hash: o.definition_hash }),
          },
          (r) =>
            asObservationView(
              r,
              author,
              plan.id,
              { id: o.id, hash: o.definition_hash },
              true,
            ),
        );
      } else {
        const d =
            frozen.kind === "proposal"
              ? frozen.preview.definition
              : frozen.view.observation.definition,
          hash =
            frozen.kind === "proposal"
              ? frozen.preview.definition_hash
              : frozen.view.observation.definition_hash;
        const o = await api.request(
          frozen.kind === "proposal"
            ? `${api.prefix}/onboarding-observations`
            : `${api.prefix}/onboarding-observations/${frozen.view.observation.id}/${frozen.kind}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.key,
            },
            body: JSON.stringify(
              frozen.kind === "proposal"
                ? { definition: d }
                : {
                    definition_hash: hash,
                    expected_revision: frozen.view.observation.revision,
                  },
            ),
          },
          (r) =>
            asObservationReceipt(r, author, {
              hash,
              state:
                frozen.kind === "proposal"
                  ? "proposed"
                  : frozen.kind === "approve"
                    ? "approved"
                    : "cancelled",
              source: d.source.dispatch.id,
              ...(frozen.kind !== "proposal"
                ? { id: frozen.view.observation.id }
                : {}),
            }),
        );
        v = await inspect(o);
      }
      if (alive.current) {
        setView(v);
        setReview(null);
        setReload((n) => n + 1);
      }
    } catch (e) {
      if (alive.current) {
        setFailure(
          "The receipt observation result is not confirmed. Retry this exact reviewed operation and key, or inspect its private history. Do not submit the business file again.",
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
      : review?.view.observation.definition;
  return (
    <section
      className="signature-box"
      aria-label="Read-only receipt observations"
    >
      <h2>Recover a receipt after rotation</h2>
      <p>
        Inspect a published file using current tested SSH trust, without sending
        or changing receiver bytes. Separate approval binds the exact original
        file/ciphertext and final path. A missing or different file leaves the
        outcome unresolved; it does not authorize a resend.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Observation</th>
              <th scope="col">Original run / state</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {history.observations.map((o) => (
              <tr key={o.id}>
                <td>
                  <code>{o.id}</code>
                </td>
                <td>
                  <code>{o.source_run_id}</code> · {o.state}
                </td>
                <td>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => void load(o)}
                  >
                    Inspect observation {o.id.slice(0, 8)}
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
          First observation page
        </button>
        <button
          className="secondary"
          disabled={busy || !history.next}
          onClick={() => setAfter(history.next ?? "")}
        >
          Next observation page
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          Refresh observations
        </button>
      </div>
      {view && (
        <div className="signature-box">
          <h3 ref={result} tabIndex={-1}>
            Receipt observation: {view.observation.state}
          </h3>
          <p role="status">
            {view.observation.result.integrity_confirmed
              ? "The exact original final bytes were observed. This is recovered integrity evidence at the recorded time; business acceptance remains unknown. No file was sent or replaced."
              : view.observation.state === "unconfirmed"
                ? "The original postcondition was not confirmed. Absence or different bytes cannot prove the receiver never consumed the original. Keep the business outcome unresolved."
                : view.observation.state === "running"
                  ? "A durable read-only observation is running. Inspect this exact record after an uncertain response; expiry does not authorize another contact."
                  : view.current_bindings
                    ? "The exact source and tested observer bindings are current. Approval does not reserve a worker or remote state."
                    : view.binding_reason === "binding_changed"
                      ? "A reviewed binding changed. New contact is blocked; retain this record and prepare a new review if appropriate."
                      : "This observation is terminal. Its result and original history remain intact; replay does not contact the receiver again."}
          </p>
          <p>
            Observation <code>{view.observation.id}</code> · revision{" "}
            {view.observation.revision} · definition SHA-256{" "}
            <code>{view.observation.definition_hash}</code>. Original run{" "}
            <code>{view.observation.source_run_id}</code>.
          </p>
          <p>
            Result {view.observation.result.code} · business acceptance unknown
            · file fsync not observed · directory power-loss durability not
            established.
            {view.observation.completed_at && (
              <>
                {" "}
                Recorded at <time>{view.observation.completed_at}</time>.
              </>
            )}
            {view.observation.result.integrity_confirmed && (
              <>
                {" "}
                Exact original wire SHA-256{" "}
                <code>{view.observation.result.sha256}</code> ·{" "}
                {view.observation.result.size_bytes} bytes.
              </>
            )}
          </p>
          {view.observation.lease_until && (
            <p>
              Observation lease ends <time>{view.observation.lease_until}</time>
              ; server observed time <time>{view.observed_at}</time>. The server
              rechecks expiry and authority before any result can commit.
            </p>
          )}
          <div className="actions">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void load(view.observation)}
            >
              Inspect current observation state
            </button>
            <button
              disabled={
                busy ||
                !canApprove ||
                view.observation.state !== "proposed" ||
                !view.current_bindings
              }
              onClick={() => {
                setFailure("");
                setReview({ kind: "approve", view, key: operationKey() });
              }}
            >
              Approve receipt observation
            </button>
            <button
              disabled={
                busy ||
                !canManage ||
                !["proposed", "approved"].includes(view.observation.state)
              }
              onClick={() => {
                setFailure("");
                setReview({ kind: "cancel", view, key: operationKey() });
              }}
            >
              Cancel receipt observation
            </button>
            <button
              disabled={
                busy ||
                !canWork ||
                !(
                  view.observation.state === "running" ||
                  (view.observation.state === "approved" &&
                    view.current_bindings)
                )
              }
              onClick={() => {
                setFailure("");
                setReview({
                  kind: "work",
                  view,
                  key: view.observation.worker_key || operationKey(),
                });
              }}
            >
              {view.observation.state === "running"
                ? "Recover recorded read result"
                : "Review read-only observation"}
            </button>
          </div>
        </div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void preview();
        }}
      >
        <h3>Prepare a receipt observation</h3>
        <label htmlFor="observation-run">Published production run UUID</label>
        <input
          id="observation-run"
          required
          maxLength={36}
          disabled={busy}
          value={runID}
          onChange={(e) => setRunID(e.target.value)}
        />
        <label htmlFor="observation-source-hash">
          Original production definition SHA-256
        </label>
        <input
          id="observation-source-hash"
          required
          maxLength={64}
          disabled={busy}
          value={sourceHash}
          onChange={(e) => setSourceHash(e.target.value)}
        />
        <label htmlFor="observation-probe">Current successful probe UUID</label>
        <input
          id="observation-probe"
          required
          maxLength={36}
          disabled={busy}
          value={probeID}
          onChange={(e) => setProbeID(e.target.value)}
        />
        <label htmlFor="observation-file">Authorized same-byte file UUID</label>
        <input
          id="observation-file"
          required
          maxLength={36}
          disabled={busy}
          value={fileID}
          onChange={(e) => setFileID(e.target.value)}
        />
        <p>
          Choose the original readable accepted file, or its completed direct
          re-check child with identical bytes and fresh release. The observer
          must use the same connection family, receiver account/address and
          directory. Only its reviewed SSH trust may change.
        </p>
        <button type="submit" disabled={busy}>
          Preview receipt observation
        </button>
      </form>
      {failure && !review && <p role="alert">{failure}</p>}
      <dialog
        ref={dialog}
        className="review-dialog"
        aria-labelledby="observation-review-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        {review && d && (
          <>
            <h2 id="observation-review-title" ref={title} tabIndex={-1}>
              {review.kind === "proposal"
                ? "Review receipt observation"
                : review.kind === "work"
                  ? "Review read-only receiver contact"
                  : `Review ${review.kind} receipt observation`}
            </h2>
            <p>
              {review.kind === "proposal"
                ? "Save the exact source and current observer as a private proposal. Saving makes no receiver contact."
                : review.kind === "approve"
                  ? "Approve this exact read-only definition. A separate action performs the bounded receiver read; approval does not reserve its bindings."
                  : review.kind === "work"
                    ? "Make at most one bounded read-only contact for this approved record, or recover its already recorded result. Never send, write, rename, remove or decrypt receiver bytes. A missing or changed file cannot authorize resubmission."
                    : "Cancel only this observation proposal. Original transfers and evidence remain intact."}
            </p>
            <div className="signature-box">
              <h3>Original publication evidence</h3>
              <p>
                Original connection <code>{d.original_connection.id}</code>{" "}
                version {d.original_connection.version}.
              </p>
              <p>
                Run <code>{d.source.dispatch.id}</code> revision{" "}
                {d.source.run_revision} · delivery{" "}
                <code>{d.source.delivery.id}</code> revision{" "}
                {d.source.delivery.revision} · {d.source.state} · attempts{" "}
                {d.source.attempts} · fence {d.source.fence}.
              </p>
              <p>
                Original accepted plaintext SHA-256{" "}
                <code>{d.source.dispatch.definition.file.sha256}</code> ·{" "}
                {d.source.dispatch.definition.file.size_bytes} bytes. Original
                SSH host{" "}
                <code>
                  {d.source.dispatch.definition.effect.host_fingerprint}
                </code>{" "}
                · client{" "}
                <code>
                  {d.source.dispatch.definition.effect.key_fingerprint}
                </code>
                .
              </p>
              <p>
                Expected final wire SHA-256 <code>{d.wire.sha256}</code> ·{" "}
                {d.wire.size_bytes} bytes.
                {d.wire.ciphertext && (
                  <>
                    {" "}
                    Original ciphertext object{" "}
                    <code>{d.wire.ciphertext.object_id}</code> · original
                    recipient{" "}
                    <code>
                      {
                        d.source.dispatch.definition.effect
                          .recipient_fingerprint
                      }
                    </code>
                    . Only its ciphertext is hashed; no old key is loaded.
                  </>
                )}
              </p>
            </div>
            <div className="signature-box">
              <h3>Current read-only observer</h3>
              <p>
                {d.effect.user}@{d.effect.address} · exact final path{" "}
                <code>{d.effect.path}</code>.
              </p>
              <p>
                Observer host <code>{d.effect.host_fingerprint}</code> · client{" "}
                <code>{d.effect.key_fingerprint}</code> · connection{" "}
                <code>{d.observer.connection.id}</code> version{" "}
                {d.observer.connection.version}. Probe <code>{d.probe.id}</code>{" "}
                · current authority {d.authority_revision}.
              </p>
              <p>
                Authorized source <code>{d.authorized_file.id}</code> · policy{" "}
                {d.authorized_file.policy}.
                {d.source_recheck_id && (
                  <>
                    {" "}
                    Direct re-check link <code>{d.source_recheck_id}</code>.
                  </>
                )}
              </p>
            </div>
            <p>
              Definition SHA-256{" "}
              <code>
                {review.kind === "proposal"
                  ? review.preview.definition_hash
                  : review.view.observation.definition_hash}
              </code>
              . Strongest possible result: original file integrity observed at
              one time. Required receipt: {d.required_receipt}. Business
              acceptance remains unknown; no resend is authorized.
            </p>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                disabled={
                  busy ||
                  (review.kind === "proposal"
                    ? !canManage
                    : review.kind === "approve"
                      ? !canApprove
                      : review.kind === "work"
                        ? !canWork
                        : !canManage)
                }
                onClick={() => void save()}
              >
                {review.kind === "proposal"
                  ? "Save reviewed observation"
                  : review.kind === "work"
                    ? "Confirm read-only observation"
                    : `Confirm ${review.kind} receipt observation`}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setReview(null)}
              >
                Cancel observation review
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
