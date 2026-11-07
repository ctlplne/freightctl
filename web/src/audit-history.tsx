import { useEffect, useRef, useState, type FormEvent } from "react";
import { Api } from "./api";
import type { Session } from "./types";
import {
  auditHistorySessionStamp,
  auditHistoryAllowed,
  normalizeAuditHistory,
  type AuditHistoryPage,
  type AuditHistoryRequest,
} from "./audit-history-types";

export function AuditHistory({
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
  const [actor, setActor] = useState(""),
    [resource, setResource] = useState(""),
    [kind, setKind] = useState(""),
    [from, setFrom] = useState(""),
    [until, setUntil] = useState(""),
    [limit, setLimit] = useState("25"),
    [busy, setBusy] = useState(false),
    [page, setPage] = useState<AuditHistoryPage | null>(null),
    [query, setQuery] = useState<AuditHistoryRequest | null>(null);
  const stamp = auditHistorySessionStamp(session),
    owner = useRef(stamp),
    apiOwner = useRef(api),
    active = useRef<AbortController | null>(null),
    generation = useRef(0);
  const current = () =>
    apiOwner.current === api &&
    api.session === session &&
    owner.current === stamp &&
    auditHistorySessionStamp(api.session) === stamp &&
    auditHistoryAllowed(session.identity);
  useEffect(() => {
    const changed = owner.current !== stamp || apiOwner.current !== api;
    owner.current = stamp;
    apiOwner.current = api;
    generation.current++;
    active.current?.abort();
    setPage(null);
    setQuery(null);
    setBusy(false);
    if (changed) {
      setActor("");
      setResource("");
      setKind("");
      setFrom("");
      setUntil("");
      setLimit("25");
    }
    return () => {
      generation.current++;
      active.current?.abort();
    };
  }, [api, stamp, refresh]);
  async function search(input: AuditHistoryRequest) {
    if (!current() || busy) return;
    const serial = ++generation.current,
      controller = new AbortController();
    active.current?.abort();
    active.current = controller;
    setPage(null);
    setBusy(true);
    try {
      const pinned = normalizeAuditHistory(input),
        result = await api.auditHistory(pinned, controller.signal);
      if (
        serial === generation.current &&
        !controller.signal.aborted &&
        current()
      ) {
        setQuery(pinned);
        setPage(result);
      }
    } catch (error) {
      if (
        serial === generation.current &&
        !controller.signal.aborted &&
        current()
      )
        onError(error);
    } finally {
      if (serial === generation.current) setBusy(false);
    }
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    void search({
      limit: Number(limit),
      ...(actor ? { actor_id: actor } : {}),
      ...(resource ? { resource_id: resource } : {}),
      ...(kind ? { kinds: [kind] } : {}),
      ...(from ? { from } : {}),
      ...(until ? { until } : {}),
    });
  }
  function changed(action: () => void) {
    action();
    setPage(null);
    setQuery(null);
  }
  if (!current())
    return (
      <p role="alert">
        Reconnect with current root audit permission to read action history.
      </p>
    );
  return (
    <section aria-label="Operator audit history">
      <h2>Search recorded actions</h2>
      <p>
        Find events for an account or file in this workspace. Results show
        IDs,event types and recorded times. Event contents stay omitted. Use the
        corresponding receipt to investigate delivery or processing outcomes.
      </p>
      <form onSubmit={submit}>
        <label>
          Actor ID (optional)
          <input
            value={actor}
            onChange={(e) => changed(() => setActor(e.target.value))}
            disabled={busy}
            maxLength={36}
          />
        </label>
        <label>
          File or resource ID (optional)
          <input
            value={resource}
            onChange={(e) => changed(() => setResource(e.target.value))}
            disabled={busy}
            maxLength={36}
          />
        </label>
        <label>
          Event type (optional)
          <input
            value={kind}
            onChange={(e) => changed(() => setKind(e.target.value))}
            disabled={busy}
            maxLength={128}
            placeholder="FileAccepted"
          />
        </label>
        <label>
          From UTC (optional)
          <input
            value={from}
            onChange={(e) => changed(() => setFrom(e.target.value))}
            disabled={busy}
            maxLength={27}
            placeholder="2026-11-05T00:00:00Z"
          />
        </label>
        <label>
          Until UTC (optional)
          <input
            value={until}
            onChange={(e) => changed(() => setUntil(e.target.value))}
            disabled={busy}
            maxLength={27}
            placeholder="2026-11-06T00:00:00Z"
          />
        </label>
        <label>
          Actions per page
          <select
            aria-label="Actions per page"
            value={limit}
            onChange={(e) => changed(() => setLimit(e.target.value))}
            disabled={busy}
          >
            {[1, 10, 25, 50, 100].map((n) => (
              <option key={n} value={String(n)}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <p>
          UTC times may include up to six fractional digits. “From” includes
          that instant;“Until” stops before it.
        </p>
        <button type="submit" disabled={busy}>
          {busy ? "Searching…" : "Search recorded actions"}
        </button>
      </form>
      {busy && (
        <p role="status">
          Checking current audit permission and reading metadata…
        </p>
      )}
      {page && (
        <>
          <p role="status">
            {page.events.length} recorded actions in this page. Observed{" "}
            <time dateTime={page.observed_at}>{page.observed_at}</time>.
          </p>
          <table>
            <caption>Recorded action metadata</caption>
            <thead>
              <tr>
                <th scope="col">Recorded UTC</th>
                <th scope="col">Event type</th>
                <th scope="col">Event ID</th>
                <th scope="col">Actor ID</th>
                <th scope="col">Resource ID</th>
              </tr>
            </thead>
            <tbody>
              {page.events.map((e) => (
                <tr key={e.event_id}>
                  <td>
                    <time dateTime={e.recorded_at}>{e.recorded_at}</time>
                  </td>
                  <td>{e.kind}</td>
                  <td>
                    <code>{e.event_id}</code>
                  </td>
                  <td>
                    <code>{e.actor_id}</code>
                  </td>
                  <td>
                    <code>{e.resource_id}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.next && query && (
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                if (page.next) void search({ ...query, after: page.next });
              }}
            >
              Next action page
            </button>
          )}
          <p>
            Each page is a fresh observation. Start a new search to check again.
            Recorded times do not establish the order of business effects;use
            the signed snapshot export when you need one fixed evidence set.
          </p>
        </>
      )}
    </section>
  );
}
