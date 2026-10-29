import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, uuid, type Session } from "./types";
import { operationKey } from "./crypto";
import type { OnboardingPlan } from "./onboarding-types";
import {
  asProbeConnection,
  asProbePage,
  asProbeStart,
  asProbeView,
  probeDefinition,
  probeFingerprint,
  type Probe,
  type ProbeConnection,
  type ProbeDefinition,
  type ProbeRequest,
  type ProbeView,
} from "./onboarding-probes-types";

type Review = {
  request?: ProbeRequest;
  probe?: Probe;
  connection?: ProbeConnection;
  definition: ProbeDefinition;
  startKey: string;
  workKey: string;
};
const outcomes: Record<string, string> = {
  awaiting_worker: "Intent saved; no connection has been started.",
  probing: "A worker owns this recorded probe. Refresh to read its outcome.",
  connectivity_verified:
    "Pinned SSH identity, authentication, SFTP negotiation, advertised extensions and directory traversal passed. No file was exchanged.",
  connection_failed:
    "The pinned SSH connection or SFTP negotiation failed. Check the receiver and registered trust/credential references.",
  required_extensions_missing:
    "The receiver did not advertise the required fsync and hardlink extensions.",
  directory_unavailable:
    "The approved directory could not be traversed safely. Check its existence, permissions and links.",
  binding_changed:
    "A reviewed requirement, connection or account revision changed. Review the current saved configuration before starting a new probe.",
  lease_expired:
    "The worker lease expired. This recorded probe will not contact the receiver again; review and start a new test.",
  probe_deadline_exceeded:
    "The five-second connection test deadline expired. Check receiver availability before a new test.",
};

export function OnboardingProbes({
  api,
  session,
  plan,
  authority,
  onError,
  onConfirmed,
}: {
  api: Api;
  session: Session;
  plan: OnboardingPlan;
  authority: number;
  onError: (error: unknown) => void;
  onConfirmed: () => void;
}) {
  const [page, setPage] = useState<{ probes: Probe[]; next?: string }>({
      probes: [],
    }),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0);
  const [requirement, setRequirement] = useState(""),
    [connectionID, setConnectionID] = useState(""),
    [version, setVersion] = useState("");
  const [connection, setConnection] = useState<ProbeConnection | null>(null),
    [view, setView] = useState<ProbeView | null>(null);
  const [review, setReview] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [blocked, setBlocked] = useState(false),
    [failure, setFailure] = useState("");
  const dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    alive = useRef(true);
  const author = session.identity.actor_id;
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
        `${api.prefix}/onboarding-plans/${plan.id}/probes?limit=50&after=${after}`,
        { signal: abort.signal },
        (v) => asProbePage(v, author, plan.id),
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
      title.current?.focus();
    } else dialog.current?.close();
  }, [review]);
  async function loadConnection() {
    if (busy) return;
    setFailure("");
    const n = Number(version);
    if (
      !uuid(connectionID) ||
      !Number.isInteger(n) ||
      n < 1 ||
      n > 2147483647
    ) {
      setFailure(
        "Enter the registered connection UUID and exact positive version from its enrollment receipt.",
      );
      return;
    }
    setBusy(true);
    try {
      const c = await api.request(
        `${api.prefix}/connections/${connectionID}/${n}`,
        {},
        asProbeConnection,
      );
      if (!alive.current) return;
      if (c.id !== connectionID || c.version !== n || c.state !== "active")
        throw new ApiError("invalid_server_response", 502);
      setConnection(c);
    } catch (e) {
      if (alive.current) {
        setConnection(null);
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function inspect(p: Probe) {
    if (busy) return;
    setBusy(true);
    setFailure("");
    try {
      const v = await api.request(
        `${api.prefix}/onboarding-probes/${p.id}`,
        {},
        (x) => asProbeView(x, author, { id: p.id, hash: p.definition_hash }),
      );
      if (alive.current) setView(v);
    } catch (e) {
      if (alive.current) onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  function prepare() {
    if (busy || !connection) return;
    if (
      !plan.definition.requirements.some(
        (r) =>
          r.id === requirement &&
          r.protocol === "sftp" &&
          r.direction === "send",
      )
    ) {
      setFailure(
        "Choose a saved outbound SFTP requirement. Other roles and protocols still need their own implemented tests.",
      );
      return;
    }
    const request: ProbeRequest = {
      plan: { id: plan.id, version: plan.version, hash: plan.definition_hash },
      requirement_id: requirement,
      connection: {
        id: connection.id,
        version: connection.version,
        hash: connection.hash,
      },
      expected_authority_revision: authority,
    };
    setReview({
      request,
      definition: probeDefinition(request),
      connection,
      startKey: operationKey(),
      workKey: operationKey(),
    });
    setBlocked(false);
    setFailure("");
  }
  function recover() {
    if (!view || busy) return;
    setReview({
      probe: view.probe,
      definition: view.probe.definition,
      ...(view.connection ? { connection: view.connection } : {}),
      startKey: "",
      workKey: view.probe.worker_key || operationKey(),
    });
    setBlocked(false);
    setFailure("");
  }
  async function run() {
    if (!review || busy || blocked) return;
    const frozen = review;
    setBusy(true);
    setFailure("");
    try {
      let p = frozen.probe;
      if (!p) {
        if (!frozen.request) throw new ApiError("invalid_server_response", 502);
        const request = frozen.request;
        p = await api.request(
          `${api.prefix}/onboarding-probes`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": frozen.startKey,
            },
            body: JSON.stringify(request),
          },
          (v) => asProbeStart(v, author, request),
        );
        if (!alive.current) return;
        setReview({ ...frozen, probe: p });
        setReload((n) => n + 1);
      }
      const probe = p;
      const result = await api.request(
        `${api.prefix}/onboarding-probes/${probe.id}/work`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": frozen.workKey,
          },
          body: JSON.stringify({ definition_hash: probe.definition_hash }),
        },
        (v) =>
          asProbeView(v, author, { id: probe.id, hash: probe.definition_hash }),
      );
      if (!alive.current) return;
      setView(result);
      setReview(null);
      setReload((n) => n + 1);
      onConfirmed();
    } catch (e) {
      if (!alive.current) return;
      const refused =
        e instanceof ApiError && e.status >= 400 && e.status < 500;
      setBlocked(refused);
      setFailure(
        refused
          ? "The server refused this reviewed probe. Cancel, inspect the current saved draft and connection, then review again."
          : "The probe result is not confirmed. Recover this same recorded operation; do not create another test just because a response was lost. Cancel does not undo contact that already started.",
      );
      onError(e);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <section
      className="signature-box onboarding-probes"
      aria-label="Onboarding connectivity tests"
    >
      <h2>Connectivity tests</h2>
      <p>
        Tests use saved draft version {plan.version}. Save and review edits
        first. This read-only SFTP profile contacts the exact registered
        receiver, checks its pinned host identity and login, reads advertised
        extensions and traverses its directory. It does not test write
        permission, exchange a file, verify business acceptance or activate
        production.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Probe</th>
              <th scope="col">Draft version</th>
              <th scope="col">State</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {page.probes.map((p) => (
              <tr key={p.id}>
                <td>
                  <code>{p.id}</code>
                </td>
                <td>{p.definition.plan.version}</td>
                <td>{p.state}</td>
                <td>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => void inspect(p)}
                  >
                    Inspect probe {p.id.slice(0, 8)}
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
          First probe page
        </button>
        <button
          className="secondary"
          disabled={busy || !page.next}
          onClick={() => setAfter(page.next ?? "")}
        >
          Next probe page
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => setReload((n) => n + 1)}
        >
          Refresh probe history
        </button>
      </div>
      {view && (
        <div className="signature-box" role="status">
          <h3>Read-only connectivity: {view.probe.state}</h3>
          <p>{outcomes[view.probe.observation.code]}</p>
          <p>
            Probe <code>{view.probe.id}</code> · draft version{" "}
            {view.probe.definition.plan.version} · definition SHA-256{" "}
            <code>{view.probe.definition_hash}</code>
          </p>
          <p>
            {view.current_bindings
              ? "The selected requirement, connection and account revisions still match."
              : "The recorded bindings have changed; this observation cannot qualify current onboarding."}
          </p>
          <button className="secondary" disabled={busy} onClick={recover}>
            Review recorded probe recovery
          </button>
        </div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          prepare();
        }}
      >
        <h3>Prepare a new connectivity test</h3>
        <label htmlFor="probe-requirement">Saved exchange requirement</label>
        <select
          id="probe-requirement"
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
        <label htmlFor="probe-connection">Registered connection UUID</label>
        <input
          id="probe-connection"
          required
          disabled={busy}
          value={connectionID}
          maxLength={36}
          onChange={(e) => {
            setConnectionID(e.target.value);
            setConnection(null);
          }}
        />
        <label htmlFor="probe-version">Registered connection version</label>
        <input
          id="probe-version"
          required
          type="number"
          min={1}
          max={2147483647}
          disabled={busy}
          value={version}
          onChange={(e) => {
            setVersion(e.target.value);
            setConnection(null);
          }}
        />
        <button
          className="secondary"
          type="button"
          disabled={busy}
          onClick={() => void loadConnection()}
        >
          Read registered connection
        </button>
        {connection && (
          <p>
            Registered receiver: {connection.user}@{connection.address},
            directory <code>{connection.directory}</code>. Host{" "}
            <code>{connection.host_fingerprint}</code>; client{" "}
            <code>{connection.key_fingerprint}</code>.
          </p>
        )}
        <button
          type="submit"
          disabled={busy || !connection || !requirement || !authority}
        >
          Review connectivity test
        </button>
      </form>
      {failure && !review && <p role="alert">{failure}</p>}
      <dialog
        ref={dialog}
        className="review-dialog"
        aria-labelledby="onboarding-probe-review-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        {review && (
          <>
            <h2 ref={title} tabIndex={-1} id="onboarding-probe-review-title">
              Review connectivity probe
            </h2>
            <p>
              {review.probe
                ? "Recover the exact recorded probe. Only a queued probe with current bindings can begin contact. A running or completed probe returns its recorded state; an expired worker is recorded without starting another connection."
                : "Save one durable intent and run one read-only connection test. No remote file is opened, written, renamed or deleted. A successful probe still needs a separate file exchange and approval before onboarding can progress."}
            </p>
            <dl className="review-facts">
              <dt>Draft ID and version</dt>
              <dd>
                <code>{review.definition.plan.id}</code> ·{" "}
                {review.definition.plan.version}
              </dd>
              <dt>Draft SHA-256</dt>
              <dd>
                <code>{review.definition.plan.hash}</code>
              </dd>
              <dt>Requirement ID</dt>
              <dd>
                <code>{review.definition.requirement_id}</code>
              </dd>
              <dt>Connection ID and version</dt>
              <dd>
                <code>{review.definition.connection.id}</code> ·{" "}
                {review.definition.connection.version}
              </dd>
              <dt>Connection SHA-256</dt>
              <dd>
                <code>{review.definition.connection.hash}</code>
              </dd>
              <dt>Reviewed account revision</dt>
              <dd>{review.definition.authority_revision}</dd>
              <dt>Probe definition SHA-256</dt>
              <dd>
                <code>{probeFingerprint(review.definition)}</code>
              </dd>
              {review.connection && (
                <>
                  <dt>Receiver</dt>
                  <dd>
                    {review.connection.user}@{review.connection.address}
                  </dd>
                  <dt>Directory</dt>
                  <dd>
                    <code>{review.connection.directory}</code>
                  </dd>
                  <dt>Pinned host / client identity</dt>
                  <dd>
                    <code>{review.connection.host_fingerprint}</code>
                    <br />
                    <code>{review.connection.key_fingerprint}</code>
                  </dd>
                </>
              )}
              {review.probe && (
                <>
                  <dt>Recorded probe</dt>
                  <dd>
                    <code>{review.probe.id}</code> · {review.probe.state}
                  </dd>
                </>
              )}
            </dl>
            <p>
              The network test has five seconds and makes one contact. A worker
              has 20 seconds of temporary ownership, called a lease; after it
              expires, that worker cannot save a result. Two probe workers can
              run at once. Advertised extensions still need a separate file
              exchange to test writes and durability.
            </p>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button disabled={busy || blocked} onClick={() => void run()}>
                {busy
                  ? "Reading probe outcome…"
                  : review.probe
                    ? "Recover same recorded probe"
                    : "Run reviewed connectivity test"}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => setReview(null)}
              >
                Cancel probe review
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
