import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Api } from "./api";
import { ApiError, uuid, type Session } from "./types";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import type {
  IncomingExchange,
  IncomingPage,
  EndpointPage,
} from "./artifact-exchanges-types";

export function ArtifactExchanges({
  api,
  session,
  refresh,
  onError,
}: {
  api: Api;
  session: Session;
  refresh: number;
  onError: (error: unknown) => void;
}) {
  const client = useMemo(() => new ExchangeReceiveApi(api), [api, session]);
  const [draft, setDraft] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [page, setPage] = useState<IncomingPage>({ exchanges: [], next: "" });
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<IncomingExchange | null>(null);
  const [directory, setDirectory] = useState<EndpointPage>({
    endpoints: [],
    next: "",
  });
  const [directoryLoaded, setDirectoryLoaded] = useState(false);
  const active = useRef<AbortController | null>(null);
  const generation = useRef(0);

  function clear() {
    generation.current++;
    active.current?.abort();
    active.current = null;
    setPage({ exchanges: [], next: "" });
    setSelected(null);
    setLoaded(false);
    setBusy(false);
  }
  async function load(id: string, after = "") {
    clear();
    const serial = ++generation.current;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    try {
      const result = await client.incoming(id, after, controller.signal);
      if (serial !== generation.current || controller.signal.aborted) return;
      setPage(result);
      setLoaded(true);
    } catch (error) {
      if (serial === generation.current && !controller.signal.aborted)
        onError(error);
    } finally {
      if (serial === generation.current) setBusy(false);
    }
  }
  async function findEndpoints(after = "") {
    clear();
    const serial = ++generation.current,
      controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setDirectory({ endpoints: [], next: "" });
    setDirectoryLoaded(false);
    try {
      const result = await client.endpoints(after, controller.signal);
      if (serial !== generation.current || controller.signal.aborted) return;
      setDirectory(result);
      setDirectoryLoaded(true);
    } catch (error) {
      if (serial === generation.current && !controller.signal.aborted)
        onError(error);
    } finally {
      if (serial === generation.current) setBusy(false);
    }
  }
  async function inspect(row: IncomingExchange) {
    active.current?.abort();
    const serial = ++generation.current;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setSelected(null);
    try {
      const result = await client.inspect(row.id, endpoint, controller.signal);
      if (serial !== generation.current || controller.signal.aborted) return;
      setSelected(result);
      setPage((value) => ({
        ...value,
        exchanges: value.exchanges.map((item) =>
          item.id === result.id ? result : item,
        ),
      }));
    } catch (error) {
      if (serial === generation.current && !controller.signal.aborted) {
        setPage({ exchanges: [], next: "" });
        setLoaded(false);
        onError(error);
      }
    } finally {
      if (serial === generation.current) setBusy(false);
    }
  }
  useEffect(() => {
    if (endpoint) void load(endpoint);
    else clear();
    return () => {
      generation.current++;
      active.current?.abort();
    };
  }, [client, endpoint, refresh]);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!uuid(draft) || busy) return;
    if (draft === endpoint) void load(endpoint);
    else setEndpoint(draft);
  }
  if (!client.isCurrent())
    return (
      <section aria-label="Receive context changed">
        <p role="alert">
          Your workspace or account authority changed. Reconnect before viewing
          incoming artifacts.
        </p>
        <button
          type="button"
          onClick={() => onError(new ApiError("unauthorized", 401))}
        >
          Reconnect account
        </button>
      </section>
    );
  return (
    <section aria-labelledby="artifact-receive-title">
      <h2 id="artifact-receive-title">Receive artifacts</h2>
      <p>
        Open an endpoint registered for this account. The server checks the
        sender, recipient, exact artifact, current policy and permissions again
        before serving bytes.
      </p>
      <form onSubmit={submit}>
        <label htmlFor="artifact-endpoint">Approved receive endpoint ID</label>
        <input
          id="artifact-endpoint"
          value={draft}
          required
          maxLength={36}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="artifact-endpoint-help"
          onChange={(event) => {
            clear();
            setEndpoint("");
            setDraft(event.target.value);
          }}
        />
        <p id="artifact-endpoint-help" className="help">
          Use the endpoint ID from your administrator’s registration receipt. An
          ID alone grants no access.
        </p>
        <button
          className="primary"
          type="submit"
          disabled={busy || !uuid(draft)}
        >
          Open receive endpoint
        </button>
      </form>
      <div className="actions">
        <button
          type="button"
          disabled={busy}
          onClick={() => void findEndpoints()}
        >
          Find my receive endpoints
        </button>
        {directory.next && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void findEndpoints(directory.next)}
          >
            Next endpoint page
          </button>
        )}
      </div>
      {directoryLoaded && (
        <section aria-label="Discovered receive endpoints">
          <h3>Receive endpoints at last directory check</h3>
          {!directory.endpoints.some((row) =>
            client.isReceiveEndpoint(row),
          ) && (
            <p>No active receive endpoints for this account on this page.</p>
          )}
          <ul>
            {directory.endpoints
              .filter((row) => client.isReceiveEndpoint(row))
              .map((row) => (
                <li key={row.id}>
                  <code>{row.id}</code> · revision {row.revision}{" "}
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      clear();
                      setDraft(row.id);
                      if (row.id === endpoint) void load(row.id);
                      else setEndpoint(row.id);
                    }}
                  >
                    Open {row.id.slice(0, 8)}
                  </button>
                </li>
              ))}
          </ul>
          <p className="help">
            Registration and current permissions decide access. Opening a
            discovered endpoint rechecks the current head.
          </p>
        </section>
      )}
      {endpoint && (
        <p>
          Receive endpoint: <code>{endpoint}</code>
        </p>
      )}
      {busy && <p role="status">Checking current receive permissions…</p>}
      {loaded && !page.exchanges.length && (
        <p role="status">
          No currently authorized artifacts on this page. Refresh starts a new
          polling cycle.
        </p>
      )}
      {!!page.exchanges.length && (
        <table>
          <caption>Authorized incoming artifacts</caption>
          <thead>
            <tr>
              <th scope="col">Exchange</th>
              <th scope="col">Availability</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {page.exchanges.map((row) => (
              <tr key={row.id}>
                <th scope="row">
                  <code>{row.id}</code>
                </th>
                <td>
                  {row.state === "offered"
                    ? "Available at last check"
                    : "Held; bytes unavailable"}
                </td>
                <td>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void inspect(row)}
                  >
                    Inspect {row.id.slice(0, 8)}
                  </button>
                  {row.state === "offered" && !busy && (
                    <>
                      {" "}
                      <a href={client.downloadPath(row)} download="artifact">
                        Download artifact
                      </a>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {endpoint && (
        <div className="actions">
          <button
            type="button"
            disabled={busy}
            onClick={() => void load(endpoint)}
          >
            Check for new artifacts
          </button>
          {page.next && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void load(endpoint, page.next)}
            >
              Next receive page
            </button>
          )}
        </div>
      )}
      {selected && (
        <section aria-labelledby="artifact-detail-title">
          <h3 id="artifact-detail-title">Current exchange details</h3>
          <p>
            Exchange <code>{selected.id}</code>
          </p>
          {selected.state === "held" ? (
            <p>
              Artifact details and bytes are withheld. Complete the required
              checks and review current access before trying again.
            </p>
          ) : (
            <>
              <dl className="facts">
                <dt>Source participant</dt>
                <dd>
                  <code>{selected.exchange.sender_actor_id}</code>
                </dd>
                <dt>Immutable file revision</dt>
                <dd>
                  <code>
                    {selected.exchange.request.artifact.file_revision_id}
                  </code>
                </dd>
                <dt>Complete length</dt>
                <dd>
                  {selected.exchange.request.artifact.size_bytes.toLocaleString()}{" "}
                  bytes
                </dd>
                <dt>Complete SHA-256</dt>
                <dd>
                  <code>{selected.exchange.request.artifact.sha256}</code>
                </dd>
                <dt>Original acceptance policy</dt>
                <dd>
                  <code>
                    {selected.exchange.request.artifact.acceptance_policy}
                  </code>
                </dd>
                <dt>View expires</dt>
                <dd>
                  <time dateTime={selected.exchange.request.expires_at}>
                    {selected.exchange.request.expires_at}
                  </time>
                </dd>
                <dt>Availability evidence</dt>
                <dd>Committed receive view, subject to live checks</dd>
                {selected.exchange.request.reply_to && (
                  <>
                    <dt>Reply correlation</dt>
                    <dd>
                      <code>{selected.exchange.request.reply_to}</code>
                    </dd>
                  </>
                )}
              </dl>
              <p>
                Compare the complete downloaded length and SHA-256 before
                treating interrupted output as a complete artifact.
              </p>
            </>
          )}
        </section>
      )}
      <p className="help">
        Receiving an artifact grants no forwarding or execution permission.
        Availability, download, receiver persistence and business processing are
        separate outcomes. A reply needs its own source and delivery
        authorization.
      </p>
    </section>
  );
}
