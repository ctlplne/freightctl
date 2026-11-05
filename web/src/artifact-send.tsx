import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Api } from "./api";
import { ApiError, uuid, type Session } from "./types";
import { operationKey } from "./crypto";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import {
  asExchangeRequest,
  type EndpointPage,
  type EndpointRecord,
  type ExchangeRequest,
  type ExchangeOfferResult,
} from "./artifact-exchanges-types";

function defaultExpiry() {
  return new Date(Date.now() + 15 * 60 * 1000)
    .toISOString()
    .replace(/\.([0-9]*?)0*Z$/, (_, fraction: string) =>
      fraction ? `.${fraction}Z` : "Z",
    );
}

export function ArtifactSend({
  api,
  session,
  initialFileID = "",
  onError,
}: {
  api: Api;
  session: Session;
  initialFileID?: string;
  onError: (error: unknown) => void;
}) {
  const client = useMemo(() => new ExchangeReceiveApi(api), [api, session]);
  const [fileID, setFileID] = useState(initialFileID),
    [endpointID, setEndpointID] = useState("");
  const [expires, setExpires] = useState(defaultExpiry),
    [replyTo, setReplyTo] = useState("");
  const [directory, setDirectory] = useState<EndpointPage>({
      endpoints: [],
      next: "",
    }),
    [directoryLoaded, setDirectoryLoaded] = useState(false);
  const [review, setReview] = useState<{
    request: ExchangeRequest;
    endpoint: EndpointRecord;
    key: string;
  } | null>(null);
  const [receipt, setReceipt] = useState<ExchangeOfferResult | null>(null),
    [closed, setClosed] = useState(false);
  const [busy, setBusy] = useState(false),
    [uncertain, setUncertain] = useState(false);
  const [cancelKey, setCancelKey] = useState("");
  const active = useRef<AbortController | null>(null),
    generation = useRef(0),
    owner = useRef(client);
  function start() {
    active.current?.abort();
    const controller = new AbortController(),
      serial = ++generation.current;
    active.current = controller;
    setBusy(true);
    return { controller, serial };
  }
  function current(serial: number, controller: AbortController) {
    return serial === generation.current && !controller.signal.aborted;
  }
  useEffect(() => {
    if (owner.current !== client) {
      owner.current = client;
      setReview(null);
      setReceipt(null);
      setClosed(false);
      setCancelKey("");
      setUncertain(false);
      setFileID("");
      setEndpointID("");
      setDirectory({ endpoints: [], next: "" });
      setDirectoryLoaded(false);
      setExpires(defaultExpiry());
      setReplyTo("");
      setBusy(false);
    }
    return () => {
      generation.current++;
      active.current?.abort();
    };
  }, [client]);
  async function find(after = "") {
    const { controller, serial } = start();
    setDirectory({ endpoints: [], next: "" });
    setDirectoryLoaded(false);
    try {
      const result = await client.endpoints(after, controller.signal);
      if (current(serial, controller)) {
        setDirectory(result);
        setDirectoryLoaded(true);
      }
    } catch (error) {
      if (current(serial, controller)) onError(error);
    } finally {
      if (current(serial, controller)) setBusy(false);
    }
  }
  async function prepare(event: FormEvent) {
    event.preventDefault();
    if (review || busy || !uuid(fileID) || !uuid(endpointID)) return;
    const { controller, serial } = start();
    setReceipt(null);
    setClosed(false);
    setUncertain(false);
    setCancelKey("");
    try {
      const [source, endpoint] = await Promise.all([
        client.source(fileID, controller.signal),
        client.endpoint(endpointID, controller.signal),
      ]);
      if (!current(serial, controller)) return;
      if (!client.isSendEndpoint(endpoint))
        throw new ApiError("permission_denied", 403);
      let request: ExchangeRequest;
      try {
        request = asExchangeRequest({
          schema_version: 1,
          artifact: source,
          endpoint: {
            id: endpoint.id,
            revision: endpoint.revision,
            hash: endpoint.definition_hash,
          },
          expires_at: expires,
          receipt: "availability-only-v1",
          ...(replyTo ? { reply_to: replyTo } : {}),
        });
      } catch {
        throw new ApiError("invalid_artifact_exchange_contract", 400);
      }
      setReview({ request, endpoint, key: operationKey() });
    } catch (error) {
      if (current(serial, controller)) onError(error);
    } finally {
      if (current(serial, controller)) setBusy(false);
    }
  }
  async function offer() {
    if (!review || receipt || busy) return;
    const { controller, serial } = start();
    setUncertain(true);
    try {
      const result = await client.offer(
        review.request,
        review.endpoint,
        review.key,
        controller.signal,
      );
      if (!current(serial, controller)) return;
      setReceipt(result);
      setUncertain(false);
    } catch (error) {
      if (current(serial, controller)) onError(error);
    } finally {
      if (current(serial, controller)) setBusy(false);
    }
  }
  async function cancel() {
    if (!receipt || closed || busy) return;
    const key = cancelKey || operationKey();
    setCancelKey(key);
    const { controller, serial } = start();
    setUncertain(true);
    try {
      await client.cancelOffer(receipt.exchange, key, controller.signal);
      if (!current(serial, controller)) return;
      setClosed(true);
      setUncertain(false);
    } catch (error) {
      if (current(serial, controller)) onError(error);
    } finally {
      if (current(serial, controller)) setBusy(false);
    }
  }
  if (!client.isCurrent() || owner.current !== client)
    return (
      <section aria-label="Send context changed">
        <p role="alert">
          Your account or workspace changed. Reconnect before reviewing or
          sending an artifact.
        </p>
        <button
          type="button"
          onClick={() => onError(new ApiError("unauthorized", 401))}
        >
          Reconnect account
        </button>
      </section>
    );
  const locked = busy || review !== null;
  return (
    <section aria-labelledby="artifact-send-title">
      <h2 id="artifact-send-title">Send an artifact</h2>
      <p>
        Choose a file you can read and deliver, then an approved receive
        endpoint. Review the exact bytes and recipient before offering access.
        Receiving someone else’s artifact grants no onward permission.
      </p>
      <form onSubmit={prepare}>
        <label htmlFor="send-file-revision">Source file revision ID</label>
        <input
          id="send-file-revision"
          value={fileID}
          maxLength={36}
          autoComplete="off"
          spellCheck={false}
          disabled={locked}
          required
          onChange={(e) => setFileID(e.target.value)}
        />
        <p className="help">
          Choose Send artifact from Files, or use the immutable file ID in your
          own upload receipt.
        </p>
        <label htmlFor="send-endpoint">Approved recipient endpoint ID</label>
        <input
          id="send-endpoint"
          value={endpointID}
          maxLength={36}
          autoComplete="off"
          spellCheck={false}
          disabled={locked}
          required
          onChange={(e) => setEndpointID(e.target.value)}
        />
        <label htmlFor="send-expiry">Access expires at (UTC)</label>
        <input
          id="send-expiry"
          value={expires}
          maxLength={32}
          autoComplete="off"
          spellCheck={false}
          disabled={locked}
          required
          onChange={(e) => setExpires(e.target.value)}
        />
        <p className="help">
          Use an exact UTC timestamp ending in Z, such as 2026-11-05T22:00:00Z.
          The server enforces its configured lifetime.
        </p>
        <label htmlFor="send-reply">Reply to exchange ID (optional)</label>
        <input
          id="send-reply"
          value={replyTo}
          maxLength={36}
          autoComplete="off"
          spellCheck={false}
          disabled={locked}
          onChange={(e) => setReplyTo(e.target.value)}
        />
        <p className="help">
          This links the reply to an earlier exchange. The new source and
          recipient still need separate permission.
        </p>
        <button
          type="submit"
          className="primary"
          disabled={
            locked ||
            !uuid(fileID) ||
            !uuid(endpointID) ||
            (replyTo !== "" && !uuid(replyTo))
          }
        >
          Review artifact offer
        </button>
      </form>
      <div className="actions">
        <button type="button" disabled={locked} onClick={() => void find()}>
          Find approved recipients
        </button>
        {directory.next && (
          <button
            type="button"
            disabled={locked}
            onClick={() => void find(directory.next)}
          >
            Next recipient page
          </button>
        )}
      </div>
      {directoryLoaded && (
        <section aria-label="Approved send endpoints">
          <h3>Approved recipients at last check</h3>
          <ul>
            {directory.endpoints
              .filter((e) => client.isSendEndpoint(e))
              .map((e) => (
                <li key={e.id}>
                  <code>{e.id}</code> · recipient{" "}
                  <code>{e.definition.recipient.actor_id}</code> · revision{" "}
                  {e.revision}{" "}
                  <button
                    type="button"
                    disabled={locked}
                    onClick={() => setEndpointID(e.id)}
                  >
                    Use endpoint {e.id.slice(0, 8)}
                  </button>
                </li>
              ))}
          </ul>
          {!directory.endpoints.some((e) => client.isSendEndpoint(e)) && (
            <p>No active endpoints permit this sender on this page.</p>
          )}
        </section>
      )}
      {busy && <p role="status">Checking or committing this exact exchange…</p>}
      {review && (
        <section aria-labelledby="send-review-title">
          <h3 id="send-review-title">Review exact artifact offer</h3>
          <dl className="facts">
            <dt>Immutable source revision</dt>
            <dd>
              <code>{review.request.artifact.file_revision_id}</code>
            </dd>
            <dt>Complete length</dt>
            <dd>{review.request.artifact.size_bytes.toLocaleString()} bytes</dd>
            <dt>Complete SHA-256</dt>
            <dd>
              <code>{review.request.artifact.sha256}</code>
            </dd>
            <dt>Acceptance policy</dt>
            <dd>
              <code>{review.request.artifact.acceptance_policy}</code>
            </dd>
            <dt>Recipient account</dt>
            <dd>
              <code>{review.endpoint.definition.recipient.actor_id}</code>
            </dd>
            <dt>Approved endpoint revision</dt>
            <dd>
              <code>{review.endpoint.id}</code> · {review.endpoint.revision}
            </dd>
            <dt>Access expires</dt>
            <dd>{review.request.expires_at}</dd>
            <dt>Original offer operation</dt>
            <dd>
              <code>{review.key}</code>
            </dd>
          </dl>
          <p>
            The server will check current source access, recipient, endpoint,
            policy and exact stored bytes again. This offers availability;
            retrieval, receiver persistence and business processing remain
            unknown.
          </p>
          {!receipt && (
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void offer()}
            >
              Confirm artifact offer or recover result
            </button>
          )}
          <button
            type="button"
            disabled={busy || uncertain}
            onClick={() => {
              setReview(null);
              setReceipt(null);
              setClosed(false);
              setCancelKey("");
            }}
          >
            Start a new review
          </button>
        </section>
      )}
      {uncertain && (
        <p role="alert">
          The outcome is not confirmed. Retry the same operation to recover its
          recorded result. Keep this page open; navigating away or reloading
          loses this in-memory review. A timeout does not prove the operation
          failed.
        </p>
      )}
      {receipt && (
        <section aria-label="Artifact offer receipt">
          <h3>Committed availability receipt</h3>
          <p>
            Exchange <code>{receipt.exchange.id}</code>.{" "}
            {receipt.replayed
              ? "Recovered the original offer."
              : "The receive view was committed."}
          </p>
          <p>
            Request hash <code>{receipt.exchange.request_hash}</code>. Journal
            event <code>{receipt.exchange.event_id}</code>.
          </p>
          {closed ? (
            <p role="status">
              This offer was withdrawn. Future retrieval through this view is
              disabled. Earlier copies cannot be recalled.
            </p>
          ) : (
            <>
              <p>
                Withdrawing closes this receive view. Source bytes and other
                offers keep their own permissions.
              </p>
              <button
                type="button"
                disabled={busy}
                onClick={() => void cancel()}
              >
                Withdraw this artifact offer or recover result
              </button>
              {cancelKey && (
                <p>
                  Withdrawal operation <code>{cancelKey}</code>
                </p>
              )}
            </>
          )}
        </section>
      )}
    </section>
  );
}
