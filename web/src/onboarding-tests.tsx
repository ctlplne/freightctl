import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { uuid, type Session } from "./types";
import type { OnboardingPlan } from "./onboarding-types";
import {
  asTestPage,
  asTestPreview,
  asTestStart,
  asTestView,
  type RecordedTest,
  type TestPreview,
  type TestSelection,
  type TestView,
} from "./onboarding-tests-types";

export function OnboardingTests({
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
  const [requirement, setRequirement] = useState(""),
    [probe, setProbe] = useState(""),
    [workflow, setWorkflow] = useState(""),
    [version, setVersion] = useState(""),
    [hash, setHash] = useState(""),
    [file, setFile] = useState("");
  const [history, setHistory] = useState<{
      tests: RecordedTest[];
      next?: string;
    }>({ tests: [] }),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [view, setView] = useState<TestView | null>(null),
    [review, setReview] = useState<{
      preview: TestPreview;
      key: string;
    } | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState("");
  const dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    result = useRef<HTMLHeadingElement>(null),
    alive = useRef(true),
    workKeys = useRef(new Map<string, string>());
  const author = session.identity.actor_id,
    canExecute =
      session.identity.permissions.includes("workflow_execute") &&
      session.identity.permissions.includes("deliver");
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
        `${api.prefix}/onboarding-plans/${plan.id}/tests?limit=50&after=${after}`,
        { signal: abort.signal },
        (v) => asTestPage(v, author, plan.id),
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
  async function inspect(p: RecordedTest) {
    return api.request(`${api.prefix}/onboarding-tests/${p.id}`, {}, (v) =>
      asTestView(v, author, { id: p.id, hash: p.definition_hash }),
    );
  }
  async function load(p: RecordedTest) {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const v = await inspect(p);
      if (alive.current) setView(v);
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function preview() {
    if (busy) return;
    const n = Number(version);
    if (
      !plan.definition.requirements.some(
        (r) =>
          r.id === requirement &&
          r.protocol === "sftp" &&
          r.direction === "send",
      ) ||
      !uuid(probe) ||
      !uuid(workflow) ||
      !uuid(file) ||
      !Number.isSafeInteger(n) ||
      n < 1 ||
      n > 2147483647 ||
      !/^[a-f0-9]{64}$/.test(hash)
    ) {
      setFailure(
        "Choose a saved outbound SFTP requirement and exact probe, approved workflow and accepted file references from their receipts.",
      );
      return;
    }
    const selected: TestSelection = {
      plan: { id: plan.id, version: plan.version, hash: plan.definition_hash },
      requirement_id: requirement,
      probe_id: probe,
      workflow: { id: workflow, version: n, hash },
      file_id: file,
      expected_authority_revision: authority,
    };
    setBusy(true);
    setFailure("");
    try {
      const p = await api.request(
        `${api.prefix}/onboarding-tests/preview`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(selected),
        },
        (v) => asTestPreview(v, selected),
      );
      if (alive.current) setReview({ preview: p, key: operationKey() });
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function save() {
    if (!review || busy || !canExecute) return;
    const frozen = review;
    setBusy(true);
    setFailure("");
    try {
      const p = await api.request(
        `${api.prefix}/onboarding-tests`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": frozen.key,
          },
          body: JSON.stringify({ definition: frozen.preview.definition }),
        },
        (v) => asTestStart(v, author, frozen.preview),
      );
      if (!alive.current) return;
      const observed = await inspect(p);
      if (!alive.current) return;
      setReview(null);
      setView(observed);
      setReload((n) => n + 1);
    } catch (e) {
      if (alive.current) {
        setFailure(
          "The saved result is not confirmed. Retry this same reviewed command and key; do not create another test because a response was lost.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function work() {
    if (!view || busy || !canExecute || !view.current_bindings) return;
    const frozen = view;
    let key = workKeys.current.get(frozen.test.id);
    if (!key) {
      key = operationKey();
      workKeys.current.set(frozen.test.id, key);
    }
    setBusy(true);
    setFailure("");
    try {
      await api.request(
        `${api.prefix}/workflow-runs/${frozen.test.run_id}/work`,
        { method: "POST", headers: { "Idempotency-Key": key } },
        () => true,
      );
      const observed = await inspect(frozen.test);
      if (alive.current) {
        setView(observed);
        setReload((n) => n + 1);
      }
    } catch (e) {
      if (alive.current) {
        setFailure(
          "Execution outcome is not confirmed. Inspect the recorded test and recover this same operation; a lost response does not mean the receiver saw no bytes.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  const d = review?.preview.definition,
    c = review?.preview.connection;
  return (
    <section
      className="signature-box"
      aria-label="Recorded onboarding test exchanges"
    >
      <h2>Recorded test exchanges</h2>
      <p>
        Freeze the saved requirement, successful probe, approved one-step SFTP
        workflow and accepted file before sending test bytes. Preview makes no
        receiver contact. Saving creates a queued ordinary workflow run; a
        separate execution sends the file. Neither action activates production.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Test / run</th>
              <th scope="col">Saved draft version</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {history.tests.map((p) => (
              <tr key={p.id}>
                <td>
                  <code>{p.id}</code>
                </td>
                <td>{p.definition.plan.version}</td>
                <td>
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy}
                    onClick={() => void load(p)}
                  >
                    Inspect test {p.id.slice(0, 8)}
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
          First test page
        </button>
        <button
          className="secondary"
          disabled={busy || !history.next}
          onClick={() => setAfter(history.next ?? "")}
        >
          Next test page
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          Refresh recorded tests
        </button>
      </div>
      {view && (
        <div className="signature-box">
          <h3 ref={result} tabIndex={-1}>
            Recorded test: {view.status.observed_state}
          </h3>
          <p role="status">
            {view.current_bindings
              ? "The recorded onboarding bindings are current. Inspect actual worker state and receipt strength before any later approval."
              : "A recorded binding, policy, source or storage reference is no longer current. New execution is blocked; the original run and evidence keep their meanings."}
          </p>
          <p>
            Test/run <code>{view.test.id}</code> · definition SHA-256{" "}
            <code>{view.test.definition_hash}</code> ·{" "}
            {view.status.observed_reason}. Source{" "}
            <code>{view.test.definition.file.sha256}</code>; required receipt{" "}
            {view.test.definition.required_receipt}. This test record does not
            activate production.
          </p>
          <div className="actions">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void load(view.test)}
            >
              Inspect current test state
            </button>
            <button
              disabled={
                busy ||
                !canExecute ||
                !view.current_bindings ||
                !["queued", "running"].includes(view.status.observed_state)
              }
              onClick={() => void work()}
            >
              Execute recorded test exchange
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
        <h3>Prepare a test exchange</h3>
        <label htmlFor="test-requirement">Saved test requirement</label>
        <select
          id="test-requirement"
          required
          disabled={busy}
          value={requirement}
          onChange={(e) => setRequirement(e.target.value)}
        >
          <option value="">Choose an outbound SFTP requirement</option>
          {plan.definition.requirements
            .filter((r) => r.protocol === "sftp" && r.direction === "send")
            .map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
        </select>
        <label htmlFor="test-probe">Successful probe UUID</label>
        <input
          id="test-probe"
          required
          maxLength={36}
          disabled={busy}
          value={probe}
          onChange={(e) => setProbe(e.target.value)}
        />
        <label htmlFor="test-workflow">Approved test workflow UUID</label>
        <input
          id="test-workflow"
          required
          maxLength={36}
          disabled={busy}
          value={workflow}
          onChange={(e) => setWorkflow(e.target.value)}
        />
        <label htmlFor="test-workflow-version">
          Approved test workflow version
        </label>
        <input
          id="test-workflow-version"
          required
          type="number"
          min={1}
          max={2147483647}
          disabled={busy}
          value={version}
          onChange={(e) => setVersion(e.target.value)}
        />
        <label htmlFor="test-workflow-hash">
          Approved test workflow SHA-256
        </label>
        <input
          id="test-workflow-hash"
          required
          maxLength={64}
          disabled={busy}
          value={hash}
          onChange={(e) => setHash(e.target.value)}
        />
        <label htmlFor="test-source">Accepted test file UUID</label>
        <input
          id="test-source"
          required
          maxLength={36}
          disabled={busy}
          value={file}
          onChange={(e) => setFile(e.target.value)}
        />
        <button type="submit" disabled={busy || !authority}>
          Preview test exchange
        </button>
      </form>
      {failure && !review && <p role="alert">{failure}</p>}
      <dialog
        ref={dialog}
        className="review-dialog"
        aria-labelledby="onboarding-test-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        {review && d && c && (
          <>
            <h2 id="onboarding-test-title" ref={title} tabIndex={-1}>
              Review recorded test intent
            </h2>
            <p>
              Save one immutable test record, ordinary workflow run and delivery
              intent together. No receiver contact occurs until execution. Use
              safe test data: executing this approved workflow sends its file to
              the exact receiver below.
            </p>
            <dl className="review-facts">
              <dt>Saved draft / requirement</dt>
              <dd>
                <code>{d.plan.id}</code> · version {d.plan.version} ·{" "}
                <code>{d.requirement_id}</code>
              </dd>
              <dt>Successful probe</dt>
              <dd>
                <code>{d.probe.id}</code> · <code>{d.probe.hash}</code>
              </dd>
              <dt>Receiver and directory</dt>
              <dd>
                {c.user}@{c.address} · <code>{c.directory}</code>
              </dd>
              <dt>Pinned host / client identity</dt>
              <dd>
                <code>{c.host_fingerprint}</code>
                <br />
                <code>{c.key_fingerprint}</code>
              </dd>
              <dt>Approved workflow and exact filename</dt>
              <dd>
                <code>{d.workflow.id}</code> · version {d.workflow.version} ·{" "}
                <code>{d.workflow.hash}</code> · step {d.step_id} ·{" "}
                <code>{review.preview.filename}</code>
              </dd>
              <dt>Recipient encryption</dt>
              <dd>
                {d.effect.encryption ? (
                  <>
                    <code>{d.effect.encryption.key.id}</code> · version{" "}
                    {d.effect.encryption.key.version} · profile{" "}
                    {d.effect.encryption.profile} · primary fingerprint{" "}
                    <code>{d.effect.recipient_fingerprint}</code>
                  </>
                ) : (
                  "This workflow sends the accepted source without recipient encryption."
                )}
              </dd>
              <dt>Accepted source</dt>
              <dd>
                <code>{d.file.id}</code> · {d.file.size_bytes} bytes · SHA-256{" "}
                <code>{d.file.sha256}</code>
              </dd>
              <dt>Authority / required receipt</dt>
              <dd>
                {d.authority_revision} / {d.required_receipt}. A transport or
                integrity receipt cannot establish business acceptance.
              </dd>
              <dt>Reviewed test definition SHA-256</dt>
              <dd>
                <code>{review.preview.definition_hash}</code>
              </dd>
            </dl>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                disabled={busy || !canExecute}
                onClick={() => void save()}
              >
                Save reviewed test intent
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setReview(null)}
              >
                Cancel test review
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
