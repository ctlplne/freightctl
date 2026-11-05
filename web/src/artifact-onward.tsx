import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Api } from "./api";
import { uuid, type Session } from "./types";
import { operationKey } from "./crypto";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import { ArtifactOnwardApi } from "./artifact-onward-api";
import {
  onwardProfile,
  type OnwardRecovery,
  type OnwardAcceptance,
  type OnwardObservation,
} from "./artifact-onward-types";
import { offerRecoveryMaximum } from "./artifact-recovery";

export function ArtifactOnward({
  api,
  session,
  onError,
}: {
  api: Api;
  session: Session;
  onError: (error: unknown) => void;
}) {
  const client = useMemo(() => new ArtifactOnwardApi(api), [api, session]);
  const [fileID, setFileID] = useState(""),
    [workflowID, setWorkflowID] = useState(""),
    [version, setVersion] = useState("1"),
    [hash, setHash] = useState("");
  const [saved, setSaved] = useState<OnwardRecovery | null>(null),
    [accepted, setAccepted] = useState<OnwardAcceptance | null>(null),
    [observed, setObserved] = useState<OnwardObservation | null>(null);
  const [busy, setBusy] = useState(false),
    [uncertain, setUncertain] = useState(false),
    [imported, setImported] = useState(false);
  const active = useRef<AbortController | null>(null),
    generation = useRef(0),
    owner = useRef(client),
    download = useRef<string | null>(null),
    heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (owner.current !== client) {
      owner.current = client;
      setSaved(null);
      setAccepted(null);
      setObserved(null);
      setBusy(false);
      setUncertain(false);
      setImported(false);
      setFileID("");
      setWorkflowID("");
      setVersion("1");
      setHash("");
    }
    return () => {
      generation.current++;
      active.current?.abort();
      if (download.current) {
        URL.revokeObjectURL(download.current);
        download.current = null;
      }
    };
  }, [client]);
  useEffect(() => {
    if (saved) heading.current?.focus();
  }, [saved?.request_key]);
  async function action(
    operation: (signal: AbortSignal, current: () => boolean) => Promise<void>,
  ) {
    active.current?.abort();
    const controller = new AbortController(),
      serial = ++generation.current;
    active.current = controller;
    setBusy(true);
    const current = () =>
      serial === generation.current &&
      !controller.signal.aborted &&
      client.isCurrent();
    try {
      await operation(controller.signal, current);
    } catch (error) {
      if (current()) onError(error);
    } finally {
      if (current()) setBusy(false);
    }
  }
  function start() {
    if (!saved) return null;
    return {
      request: saved.review.request,
      review_hash: saved.review.review_hash,
    };
  }
  async function prepare(e: FormEvent) {
    e.preventDefault();
    if (saved || busy || !uuid(fileID) || !uuid(workflowID)) return;
    await action(async (signal, current) => {
      const source = await new ExchangeReceiveApi(api).source(fileID, signal);
      const review = await client.prepare(
        {
          schema_version: 1,
          profile: onwardProfile,
          workflow: { id: workflowID, version: Number(version), hash },
          artifact: source,
        },
        signal,
      );
      if (current()) {
        const i = session.identity;
        setSaved(
          client.recovery(
            {
              schema_version: 1,
              profile: "freightctl-onward-recovery-v1",
              server_origin: location.origin,
              participant: {
                tenant_id: i.tenant_id,
                partner_id: i.partner_id,
                actor_id: i.actor_id,
                authority_revision: i.authority_revision,
                root_policy_digest: i.root_policy_digest,
              },
              review,
              request_key: operationKey(),
            },
            location.origin,
          ),
        );
        setAccepted(null);
        setObserved(null);
        setUncertain(false);
        setImported(false);
      }
    });
  }
  async function queue(lookup = false) {
    const original = start();
    if (!saved || !original || busy || (imported && !lookup)) return;
    setUncertain(true);
    await action(async (signal, current) => {
      const receipt = lookup
        ? await client.receipt(
            original,
            saved.request_key,
            saved.expected_run_id,
            signal,
          )
        : await client.start(
            original,
            saved.request_key,
            saved.expected_run_id,
            signal,
          );
      if (current()) {
        setAccepted(receipt);
        setSaved({ ...saved, expected_run_id: receipt.run_id });
        setUncertain(!!saved.work_key);
      }
    });
  }
  async function observe() {
    const original = start();
    if (!saved || !original || !accepted || busy) return;
    await action(async (signal, current) => {
      const result = await client.observe(
        original,
        saved.request_key,
        accepted.run_id,
        signal,
      );
      if (current()) setObserved(result);
    });
  }
  async function work() {
    const original = start();
    if (!saved || !original || !accepted || busy || imported) return;
    const key = saved.work_key || operationKey(),
      pending = { ...saved, work_key: key };
    setSaved(pending);
    setUncertain(true);
    await action(async (signal, current) => {
      const result = await client.work(
        original,
        saved.request_key,
        accepted.run_id,
        key,
        signal,
      );
      if (current()) {
        setObserved(result);
        const { work_key: _, ...settled } = pending;
        setSaved(settled);
        setUncertain(false);
      }
    });
  }
  async function verifyImported() {
    if (!saved || !imported || busy) return;
    await action(async (signal, current) => {
      const review = await client.refresh(saved.review, signal);
      if (current()) {
        setSaved({ ...saved, review });
        setImported(false);
      }
    });
  }
  function save() {
    if (!saved || busy) return;
    try {
      const value = client.recovery(saved, location.origin),
        bytes = new TextEncoder().encode(JSON.stringify(value));
      if (download.current) URL.revokeObjectURL(download.current);
      download.current = URL.createObjectURL(new Blob([bytes]));
      const a = document.createElement("a");
      a.href = download.current;
      a.download = "freightctl-onward-recovery.json";
      a.click();
    } catch (error) {
      onError(error);
    }
  }
  async function restore(file: File | undefined) {
    if (!file || busy || saved) return;
    if (file.size > offerRecoveryMaximum) {
      onError(new Error("Recovery document is too large"));
      return;
    }
    await action(async (_, current) => {
      const value = client.readRecovery(await file.text(), location.origin);
      if (current()) {
        setSaved(value);
        setAccepted(null);
        setObserved(null);
        setUncertain(true);
        setImported(true);
      }
    });
  }
  return (
    <section aria-label="Onward artifact delivery">
      <p>
        Use an artifact you can send and a workflow already approved for your
        account. Each destination is a registered connection. Receiving an
        artifact adds no permission to send it onward.
      </p>
      <form onSubmit={prepare}>
        <label>
          Onward source file revision ID
          <input
            value={fileID}
            disabled={busy || !!saved}
            onChange={(e) => setFileID(e.target.value)}
            required
            maxLength={36}
          />
        </label>
        <label>
          Approved onward workflow ID
          <input
            value={workflowID}
            disabled={busy || !!saved}
            onChange={(e) => setWorkflowID(e.target.value)}
            required
            maxLength={36}
          />
        </label>
        <label>
          Approved onward workflow version
          <input
            value={version}
            disabled={busy || !!saved}
            onChange={(e) => setVersion(e.target.value)}
            required
            type="number"
            min="1"
            max="2147483647"
          />
        </label>
        <label>
          Approved onward workflow SHA256
          <input
            value={hash}
            disabled={busy || !!saved}
            onChange={(e) => setHash(e.target.value)}
            required
            pattern="[0-9a-f]{64}"
            maxLength={64}
          />
        </label>
        <button disabled={busy || !!saved}>Review onward delivery</button>
      </form>
      {!saved && (
        <label>
          Import saved onward review
          <input
            type="file"
            accept="application/json"
            disabled={busy}
            onChange={(e) => {
              void restore(e.target.files?.[0]);
              e.target.value = "";
            }}
          />
        </label>
      )}
      {saved && (
        <section aria-label="Exact onward review">
          <h2 ref={heading} tabIndex={-1}>
            Review exact onward delivery
          </h2>
          <p>
            Review creates no run and contacts no destination. Queueing records
            a run and transfer intents; a separate work action can write to
            approved destinations.
          </p>
          {imported && (
            <p role="status">
              Saved review imported. It supplies no receipt or permission. Its
              destination hints are unverified. Verify them with the server
              before queueing or work. Receipt lookup performs no transfer.
            </p>
          )}
          <dl>
            <dt>Source revision</dt>
            <dd>
              <code>{saved.review.request.artifact.file_revision_id}</code>
            </dd>
            <dt>Source bytes</dt>
            <dd>{saved.review.request.artifact.size_bytes}</dd>
            <dt>Source SHA256</dt>
            <dd>
              <code>{saved.review.request.artifact.sha256}</code>
            </dd>
            <dt>Intake policy</dt>
            <dd>{saved.review.request.artifact.acceptance_policy}</dd>
            <dt>Workflow</dt>
            <dd>
              {saved.review.request.workflow.id} · version{" "}
              {saved.review.request.workflow.version}
            </dd>
            <dt>Workflow SHA256</dt>
            <dd>
              <code>{saved.review.request.workflow.hash}</code>
            </dd>
            <dt>Exact review SHA256</dt>
            <dd>
              <code>{saved.review.review_hash}</code>
            </dd>
          </dl>
          <ol>
            {saved.review.effects.map((e) => (
              <li key={e.ordinal}>
                {e.protocol.toUpperCase()} connection{" "}
                <code>{e.connection.id}</code> · version {e.connection.version}{" "}
                · SHA256 <code>{e.connection.hash}</code>
              </li>
            ))}
          </ol>
          {imported && (
            <button disabled={busy} onClick={() => void verifyImported()}>
              Verify saved onward review with server
            </button>
          )}
          <p>
            Physical bytes and current permissions are checked by ordinary
            transfer workers. Receiver persistence: unknown. Business
            processing: unknown.
          </p>
          <button disabled={busy} onClick={save}>
            Save onward recovery
          </button>
          {!accepted && (
            <>
              <button
                disabled={busy || imported}
                onClick={() => void queue(false)}
              >
                Confirm queue or recover original run
              </button>
              <button disabled={busy} onClick={() => void queue(true)}>
                Find original onward receipt only
              </button>
            </>
          )}
          {uncertain && (
            <p role="status">
              A result may already be recorded. Keep this review and its
              original keys. A missing or lost response does not mean nothing
              happened.
            </p>
          )}
          {accepted && (
            <section aria-label="Recorded onward acceptance">
              <h2>Recorded onward run</h2>
              <p>
                Run <code>{accepted.run_id}</code>. Historical acceptance:
                queued run and intents only. Current state has not been checked
                by this receipt.
              </p>
              <button disabled={busy} onClick={() => void observe()}>
                Inspect current onward state
              </button>
              <p>
                Work can contact registered destinations and perform the
                approved remote writes. The server rechecks live authority,
                checks and approvals before effects.
              </p>
              <button disabled={busy || imported} onClick={() => void work()}>
                {saved.work_key
                  ? "Retry the same onward work step"
                  : "Perform one onward work step"}
              </button>
            </section>
          )}
          {observed && (
            <section aria-label="Current onward observation">
              <h2>Current onward observation</h2>
              <p>
                Observed state: {observed.observed_state}. Receiver persistence:
                unknown. Business processing: unknown.
              </p>
              <ol>
                {observed.steps.map((s) => (
                  <li key={s.delivery_id}>
                    Step {s.ordinal}: {s.state}. Delivery{" "}
                    <code>{s.delivery_id}</code>. Observation SHA256{" "}
                    <code>{s.observation_sha256}</code>.
                  </li>
                ))}
              </ol>
              <p>
                Reason SHA256: <code>{observed.reason_sha256}</code>. A
                successful integrity receipt does not prove receiver business
                acceptance.
              </p>
            </section>
          )}
        </section>
      )}
      {busy && <p role="status">Checking exact onward delivery…</p>}
    </section>
  );
}
