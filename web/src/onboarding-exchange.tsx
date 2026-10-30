import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { uuid } from "./types";
import type { OnboardingPlan } from "./onboarding-types";
import {
  asExchangeReview,
  type ExchangeReview,
  type ExchangeSelection,
} from "./onboarding-exchange-types";

const reasons: Record<ExchangeReview["reason"], string> = {
  recorded_evidence_matches:
    "The recorded remote integrity receipt meets this requirement's transport or integrity level. Review the exact evidence below; approval and production activation are still required.",
  business_receipt_missing:
    "Remote file integrity was observed, but downstream business acceptance is unknown. This requirement needs its agreed business acknowledgment before approval can proceed.",
  probe_not_succeeded:
    "The selected connectivity probe has not succeeded. Inspect that probe before relying on this exchange.",
  exchange_not_succeeded:
    "The workflow or selected delivery is not complete. Inspect its current state and receipts; this review does not run or retry it.",
};
export function OnboardingExchange({
  api,
  plan,
  authority,
  onError,
}: {
  api: Api;
  plan: OnboardingPlan;
  authority: number;
  onError: (e: unknown) => void;
}) {
  const [requirement, setRequirement] = useState(""),
    [probe, setProbe] = useState(""),
    [run, setRun] = useState(""),
    [step, setStep] = useState("");
  const [view, setView] = useState<ExchangeReview | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const result = useRef<HTMLHeadingElement>(null),
    pending = useRef<AbortController | null>(null);
  useEffect(() => {
    setView(null);
    setBusy(false);
    return () => pending.current?.abort();
  }, [plan.id, plan.version, authority]);
  useEffect(() => {
    if (view) result.current?.focus();
  }, [view]);
  async function review() {
    if (busy) return;
    if (
      !plan.definition.requirements.some(
        (r) =>
          r.id === requirement &&
          r.direction === "send" &&
          r.protocol === "sftp",
      ) ||
      !uuid(probe) ||
      !uuid(run) ||
      !/^[a-z][a-z0-9_]{0,63}$/.test(step)
    ) {
      setError(
        "Choose a saved outbound SFTP requirement, exact probe and run UUIDs, and the workflow step ID from its definition.",
      );
      return;
    }
    const selection: ExchangeSelection = {
      plan: { id: plan.id, version: plan.version, hash: plan.definition_hash },
      requirement_id: requirement,
      probe_id: probe,
      run_id: run,
      step_id: step,
      expected_authority_revision: authority,
    };
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setView(null);
    setError("");
    try {
      const observed = await api.request(
        `${api.prefix}/onboarding-exchange-review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(selection),
          signal: controller.signal,
        },
        (v) => asExchangeReview(v, selection),
      );
      if (!controller.signal.aborted) setView(observed);
    } catch (e) {
      if (!controller.signal.aborted) onError(e);
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  function changed() {
    setView(null);
    setError("");
  }
  return (
    <section
      className="signature-box"
      aria-label="Onboarding file exchange evidence"
    >
      <h2>Review file exchange evidence</h2>
      <p>
        Compare a saved requirement with an existing connectivity probe and
        workflow delivery. This reads recorded evidence without contacting the
        receiver. It does not create an exchange, approve onboarding or activate
        production. This compares direction, protocol and receipt level. Contact
        obligations, free-text notes and receipt contracts still need human
        assessment.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void review();
        }}
      >
        <label htmlFor="exchange-requirement">
          Saved outbound SFTP requirement
        </label>
        <select
          id="exchange-requirement"
          required
          disabled={busy}
          value={requirement}
          onChange={(e) => {
            changed();
            setRequirement(e.target.value);
          }}
        >
          <option value="">Choose a saved requirement</option>
          {plan.definition.requirements
            .filter((r) => r.direction === "send" && r.protocol === "sftp")
            .map((r) => (
              <option value={r.id} key={r.id}>
                {r.name}
              </option>
            ))}
        </select>
        <label htmlFor="exchange-probe">Connectivity probe UUID</label>
        <input
          id="exchange-probe"
          required
          maxLength={36}
          disabled={busy}
          value={probe}
          onChange={(e) => {
            changed();
            setProbe(e.target.value);
          }}
        />
        <label htmlFor="exchange-run">Completed workflow run UUID</label>
        <input
          id="exchange-run"
          required
          maxLength={36}
          disabled={busy}
          value={run}
          onChange={(e) => {
            changed();
            setRun(e.target.value);
          }}
        />
        <label htmlFor="exchange-step">Exact workflow step ID</label>
        <input
          id="exchange-step"
          required
          maxLength={64}
          disabled={busy}
          value={step}
          onChange={(e) => {
            changed();
            setStep(e.target.value);
          }}
        />
        <button type="submit" disabled={busy || !authority}>
          {busy ? "Reading recorded evidence…" : "Compare recorded exchange"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {view && (
        <div className="signature-box">
          <h3 tabIndex={-1} ref={result}>
            {view.ready_for_approval_review
              ? "Recorded exchange evidence matches"
              : "Onboarding evidence incomplete"}
          </h3>
          <p role="status">{reasons[view.reason]}</p>
          <dl className="review-facts">
            <dt>Observed at</dt>
            <dd>{view.observed_at}</dd>
            <dt>Required / observed receipt</dt>
            <dd>
              {view.snapshot.required_receipt} /{" "}
              {view.snapshot.observed_receipt}
            </dd>
            <dt>Exact source</dt>
            <dd>
              <code>{view.snapshot.file.id}</code> ·{" "}
              {view.snapshot.file.size_bytes} bytes · SHA-256{" "}
              <code>{view.snapshot.file.sha256}</code>
            </dd>
            <dt>Connection version and SHA-256</dt>
            <dd>
              <code>{view.snapshot.connection.id}</code> ·{" "}
              {view.snapshot.connection.version} ·{" "}
              <code>{view.snapshot.connection.hash}</code>
            </dd>
            <dt>Workflow version and SHA-256</dt>
            <dd>
              <code>{view.snapshot.workflow.id}</code> ·{" "}
              {view.snapshot.workflow.version} ·{" "}
              <code>{view.snapshot.workflow.hash}</code>
            </dd>
            <dt>Delivery and stored receipt SHA-256</dt>
            <dd>
              <code>{view.snapshot.delivery.id}</code> ·{" "}
              <code>{view.snapshot.receipt_hash}</code>
            </dd>
            <dt>Transferred object</dt>
            <dd>
              {view.snapshot.observed_receipt === "integrity" ? (
                <>
                  {view.snapshot.transfer_bytes} bytes · SHA-256{" "}
                  <code>{view.snapshot.transfer_sha256}</code>.{" "}
                  {view.snapshot.reconciled
                    ? "Integrity observed during reconciliation; file fsync was not acknowledged in this observation."
                    : "Remote file fsync acknowledged; directory durability across power loss remains unproven."}
                </>
              ) : (
                "No qualifying completed exchange receipt."
              )}
            </dd>
            <dt>Review snapshot SHA-256</dt>
            <dd>
              <code>{view.snapshot_hash}</code>
            </dd>
          </dl>
          <p>
            This is an observation of saved records, not a live receiver test.
            Business acceptance remains unknown. Credential, storage, policy and
            evidence must be checked again before any approved execution.
            Explicit onboarding approval and production activation are still
            required.
          </p>
        </div>
      )}
    </section>
  );
}
