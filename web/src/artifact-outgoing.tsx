import { useEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import type {
  OutgoingExchange,
  OutgoingPage,
} from "./artifact-exchanges-types";

const states: Record<OutgoingExchange["state"], string> = {
  offered: "Open at last metadata check",
  held: "Held by current checks or policy",
  unavailable: "Unavailable under current endpoint or participant state",
  expired: "Expired",
  canceled: "Withdrawn by sender",
  declined: "Declined by recipient",
};
export function ArtifactOutgoing({
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
  const [page, setPage] = useState<OutgoingPage>({ exchanges: [], next: "" }),
    [selected, setSelected] = useState<OutgoingExchange | null>(null),
    [busy, setBusy] = useState(false),
    [loaded, setLoaded] = useState(false);
  const active = useRef<AbortController | null>(null),
    generation = useRef(0),
    owner = useRef(client);
  function begin() {
    active.current?.abort();
    const controller = new AbortController(),
      serial = ++generation.current;
    active.current = controller;
    setBusy(true);
    return { controller, serial };
  }
  const current = (serial: number, controller: AbortController) =>
    serial === generation.current && !controller.signal.aborted;
  async function load(after = "") {
    const { controller, serial } = begin();
    setPage({ exchanges: [], next: "" });
    setSelected(null);
    setLoaded(false);
    try {
      const result = await client.outgoing(after, controller.signal);
      if (current(serial, controller)) {
        setPage(result);
        setLoaded(true);
      }
    } catch (error) {
      if (current(serial, controller)) onError(error);
    } finally {
      if (current(serial, controller)) setBusy(false);
    }
  }
  async function inspect(row: OutgoingExchange) {
    const { controller, serial } = begin();
    setSelected(null);
    try {
      const result = await client.outgoingExchange(
        row.exchange.id,
        controller.signal,
      );
      if (!current(serial, controller)) return;
      setSelected(result);
      setPage((p) => ({
        ...p,
        exchanges: p.exchanges.map((e) =>
          e.exchange.id === result.exchange.id ? result : e,
        ),
      }));
    } catch (error) {
      if (current(serial, controller)) {
        setPage({ exchanges: [], next: "" });
        setLoaded(false);
        onError(error);
      }
    } finally {
      if (current(serial, controller)) setBusy(false);
    }
  }
  useEffect(() => {
    owner.current = client;
    void load();
    return () => {
      generation.current++;
      active.current?.abort();
    };
  }, [client, refresh]);
  if (!client.isCurrent() || owner.current !== client)
    return (
      <section aria-label="Sent context changed">
        <p role="alert">
          Your account or workspace changed. Reconnect before viewing sent
          artifacts.
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
    <section aria-labelledby="sent-artifacts-title">
      <h2 id="sent-artifacts-title">Sent artifacts</h2>
      <p>
        Review your original offers and their current access state. This history
        requires your original account binding and current permission to read
        and deliver the source. An offer or a reply does not prove a download or
        business processing.
      </p>
      <button type="button" disabled={busy} onClick={() => void load()}>
        Check sent artifacts
      </button>
      {busy && (
        <p role="status">Checking current sender and source permissions…</p>
      )}
      {loaded && !page.exchanges.length && (
        <p role="status">
          No currently authorized sent artifacts on this page.
        </p>
      )}
      {!!page.exchanges.length && (
        <table>
          <caption>Currently authorized outgoing history</caption>
          <thead>
            <tr>
              <th scope="col">Exchange</th>
              <th scope="col">Recipient</th>
              <th scope="col">Access state</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {page.exchanges.map((row) => (
              <tr key={row.exchange.id}>
                <th scope="row">
                  <code>{row.exchange.id}</code>
                </th>
                <td>
                  <code>{row.exchange.recipient_actor_id}</code>
                </td>
                <td>{states[row.state]}</td>
                <td>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void inspect(row)}
                  >
                    Inspect sent {row.exchange.id.slice(0, 8)}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {page.next && (
        <button
          type="button"
          disabled={busy}
          onClick={() => void load(page.next)}
        >
          Next sent page
        </button>
      )}
      {selected && (
        <section aria-labelledby="sent-artifact-detail">
          <h3 id="sent-artifact-detail">Original offer and current state</h3>
          <dl className="facts">
            <dt>Exchange</dt>
            <dd>
              <code>{selected.exchange.id}</code>
            </dd>
            <dt>Current metadata state</dt>
            <dd>{states[selected.state]}</dd>
            <dt>Checked by server at</dt>
            <dd>
              <time dateTime={selected.checked_at}>{selected.checked_at}</time>
            </dd>
            <dt>Immutable source revision</dt>
            <dd>
              <code>{selected.exchange.request.artifact.file_revision_id}</code>
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
            <dt>Recipient account</dt>
            <dd>
              <code>{selected.exchange.recipient_actor_id}</code>
            </dd>
            <dt>Original endpoint revision</dt>
            <dd>
              <code>{selected.exchange.request.endpoint.id}</code> ·{" "}
              {selected.exchange.request.endpoint.revision}
            </dd>
            <dt>Original endpoint fingerprint</dt>
            <dd>
              <code>{selected.exchange.request.endpoint.hash}</code>
            </dd>
            <dt>View expires</dt>
            <dd>{selected.exchange.request.expires_at}</dd>
            {selected.exchange.request.reply_to && (
              <>
                <dt>Reply correlation</dt>
                <dd>
                  <code>{selected.exchange.request.reply_to}</code>
                </dd>
              </>
            )}
            <dt>Original request hash</dt>
            <dd>
              <code>{selected.exchange.request_hash}</code>
            </dd>
            <dt>Publication event</dt>
            <dd>
              <code>{selected.exchange.event_id}</code>
            </dd>
            {selected.closure_event_id && (
              <>
                <dt>Terminal decision event</dt>
                <dd>
                  <code>{selected.closure_event_id}</code>
                </dd>
              </>
            )}
            <dt>Byte retrieval</dt>
            <dd>Unknown</dd>
            <dt>Receiver persistence</dt>
            <dd>Unknown</dd>
            <dt>Business processing</dt>
            <dd>Unknown</dd>
          </dl>
          <p>
            The original receipt remains historical. Current metadata does not
            verify physical storage bytes or grant retrieval. Every retrieval
            performs its own live checks.
          </p>
        </section>
      )}
    </section>
  );
}
