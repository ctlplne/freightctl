import { useEffect, useRef, useState } from "react";
import type { Api } from "./api";
import { operationKey } from "./crypto";
import {
  asPendingProvision,
  asProvisionAssignments,
  asProvisionRecipients,
  asProvisionResult,
  asProvisionSources,
  connectionProvisionAllowed,
  connectionProvisionScope,
  type PendingProvision,
  type ProvisionCommand,
} from "./connection-provisioning-types";
import type { CollectionConnection } from "./collections-types";
import { ApiError, type Session } from "./types";

const path = "/connections/provisioning";
const start = { sources: "", recipients: "", assignments: "" };
const ref = (source: CollectionConnection) => ({
  id: source.id,
  version: source.version,
  hash: source.definition_hash,
});

function readReview(key: string) {
  try {
    const raw = sessionStorage.getItem(key);
    if (raw && raw.length <= 4096) return asPendingProvision(JSON.parse(raw));
  } catch {
    // The browser draft carries no authority. A new review reads fresh choices.
  }
  return null;
}

export function ConnectionProvisioning({
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
  const scope = connectionProvisionScope(session),
    actor = session.identity.actor_id;
  const storage = "freightctl-connection-provision-v1:" + scope;
  const [after, setAfter] = useState(start),
    [reload, setReload] = useState(0);
  const [pages, setPages] = useState<{
    sources: ReturnType<typeof asProvisionSources>;
    recipients: ReturnType<typeof asProvisionRecipients>;
    assignments: ReturnType<typeof asProvisionAssignments>;
  } | null>(null);
  const [sourceID, setSourceID] = useState(""),
    [recipientID, setRecipientID] = useState("");
  const [pending, setPending] = useState(() => readReview(storage));
  const [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState(""),
    [notice, setNotice] = useState("");
  const dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null);
  const dispatch = useRef<AbortController | null>(null);

  useEffect(() => () => dispatch.current?.abort(), []);
  useEffect(() => {
    const controller = new AbortController();
    if (!connectionProvisionAllowed(session)) return () => controller.abort();
    const route = (name: keyof typeof start) =>
      api.prefix +
      path +
      "/" +
      name +
      "?" +
      new URLSearchParams({ limit: "20", after: after[name] });
    const request = { signal: controller.signal };
    setLoading(true);
    setPages(null);
    void Promise.all([
      api.request(route("sources"), request, asProvisionSources),
      api.request(route("recipients"), request, (v) =>
        asProvisionRecipients(v, actor),
      ),
      api.request(route("assignments"), request, (v) =>
        asProvisionAssignments(v, actor),
      ),
    ])
      .then(([sources, recipients, assignments]) => {
        if (!controller.signal.aborted)
          setPages({ sources, recipients, assignments });
      })
      .catch((error) => {
        if (!controller.signal.aborted) onError(error);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [api, actor, after, refresh, reload, session]);

  useEffect(() => {
    if (pending && !dialog.current?.open) {
      dialog.current?.showModal();
      title.current?.focus();
    } else if (!pending && dialog.current?.open) dialog.current.close();
  }, [pending]);

  function saveReview(review: PendingProvision | null) {
    setPending(review);
    try {
      if (review) sessionStorage.setItem(storage, JSON.stringify(review));
      else sessionStorage.removeItem(storage);
    } catch {
      // The in-memory review still keeps the original key for this tab.
    }
  }

  function review(command: ProvisionCommand) {
    setFailure("");
    setNotice("");
    saveReview({ command, key: operationKey() });
  }

  function cancel() {
    if (dispatch.current) return;
    saveReview(null);
    setFailure("");
    setReload((value) => value + 1);
  }

  async function apply() {
    if (!pending || dispatch.current) return;
    if (
      !api.session ||
      connectionProvisionScope(api.session) !== scope ||
      !connectionProvisionAllowed(api.session)
    ) {
      onError(new ApiError("context_changed", 409));
      return;
    }
    const controller = new AbortController();
    dispatch.current = controller;
    setBusy(true);
    setFailure("");
    try {
      const result = await api.request(
        api.prefix + path + "/commands",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": pending.key,
          },
          body: JSON.stringify(pending.command),
          signal: controller.signal,
        },
        (value) => asProvisionResult(value, session, pending.command),
      );
      if (
        controller.signal.aborted ||
        !api.session ||
        connectionProvisionScope(api.session) !== scope
      )
        return;
      saveReview(null);
      setNotice(
        result.replayed
          ? `Original receipt recovered for ${result.receipt.connection.id}.`
          : `Route ${result.receipt.recorded}. Connection ${result.receipt.connection.id}.`,
      );
      setReload((value) => value + 1);
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof ApiError && error.status === 401) onError(error);
      setFailure(
        error instanceof ApiError && [400, 403, 404, 409].includes(error.status)
          ? "The command was refused. Close the review and refresh the route and account before making another decision."
          : "The result is uncertain. Retry this review to recover the original receipt with the same key.",
      );
    } finally {
      dispatch.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  const source = pages?.sources.rows.find((v) => v.id === sourceID);
  const recipient = pages?.recipients.rows.find((v) => v.id === recipientID);
  const command = pending?.command;
  const reviewed =
    command?.operation === "provision" ? command.source : command?.connection;
  const reviewedSource =
    command?.operation === "provision" &&
    pages?.sources.rows.find(
      (v) =>
        v.id === reviewed?.id &&
        v.version === reviewed.version &&
        v.definition_hash === reviewed.hash,
    );
  function paging(kind: keyof typeof start, next: string, label: string) {
    if (!after[kind] && !next) return null;
    return (
      <div className="actions" aria-label={`${label} pages`}>
        <button
          type="button"
          disabled={loading || !after[kind]}
          onClick={() => setAfter({ ...after, [kind]: "" })}
        >
          First {label} page
        </button>
        <button
          type="button"
          disabled={loading || !next}
          onClick={() => setAfter({ ...after, [kind]: next })}
        >
          Next {label} page
        </button>
      </div>
    );
  }

  return (
    <section
      className="panel connection-provisioning"
      aria-label="SFTP route management"
    >
      {notice && <p role="status">{notice}</p>}
      {loading && <p role="status">Loading routes and eligible recipients.</p>}
      {pages && (
        <>
          <form
            className="connection-provisioning-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (source && recipient)
                review({
                  operation: "provision",
                  source: ref(source),
                  recipient_actor_id: recipient.id,
                  recipient_authority_revision: recipient.authority_revision,
                });
            }}
          >
            <label htmlFor="provision-source">Registered SFTP source</label>
            <select
              id="provision-source"
              value={source?.id ?? ""}
              onChange={(event) => setSourceID(event.target.value)}
            >
              <option value="">Choose a source</option>
              {pages.sources.rows.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.user}@{v.address} {v.directory} · version {v.version}
                </option>
              ))}
            </select>
            {pages.sources.rows.length === 0 && (
              <p>Register an SFTP connection before assigning a route.</p>
            )}
            {paging("sources", pages.sources.next, "source")}
            <label htmlFor="provision-recipient">Receiving account</label>
            <select
              id="provision-recipient"
              value={recipient?.id ?? ""}
              onChange={(event) => setRecipientID(event.target.value)}
            >
              <option value="">Choose a recipient</option>
              {pages.recipients.rows.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.label || v.id} · {v.id.slice(0, 8)}
                </option>
              ))}
            </select>
            {pages.recipients.rows.length === 0 && (
              <p>
                The recipient needs workspace root access and read, deliver and
                workflow execution permissions.
              </p>
            )}
            {paging("recipients", pages.recipients.next, "recipient")}
            <button
              type="submit"
              className="primary"
              disabled={!source || !recipient || !!pending}
            >
              Review assignment
            </button>
          </form>
          <div
            className="table-scroll"
            tabIndex={0}
            role="region"
            aria-label="Recorded SFTP route assignments"
          >
            <table>
              <caption>Your recorded assignments</caption>
              <thead>
                <tr>
                  <th scope="col">Assigned connection</th>
                  <th scope="col">Recipient</th>
                  <th scope="col">Operator decision</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {pages.assignments.rows.map((v) => (
                  <tr key={v.connection.id}>
                    <td>
                      <code>{v.connection.id}</code>
                    </td>
                    <td>
                      <code>{v.recipient}</code>
                    </td>
                    <td>
                      <span>
                        {v.recorded === "assigned" ? "Assigned" : "Withdrawn"}
                      </span>
                      <br />
                      <code>{v.event}</code>
                    </td>
                    <td>
                      {v.recorded === "assigned" && (
                        <button
                          disabled={!!pending}
                          onClick={() =>
                            review({
                              operation: "revoke",
                              connection: v.connection,
                              provision_event_id: v.provisionEvent,
                            })
                          }
                        >
                          Review withdrawal
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {pages.assignments.rows.length === 0 && (
                  <tr>
                    <td colSpan={4}>No recorded assignments on this page.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {paging("assignments", pages.assignments.next, "assignment")}
        </>
      )}
      <dialog
        ref={dialog}
        aria-labelledby="provision-review-title"
        onCancel={(event) => {
          event.preventDefault();
          cancel();
        }}
      >
        {command && reviewed && (
          <>
            <h2 ref={title} tabIndex={-1} id="provision-review-title">
              {command.operation === "provision"
                ? "Review SFTP assignment"
                : "Review SFTP withdrawal"}
            </h2>
            <dl className="facts">
              <dt>
                {command.operation === "provision"
                  ? "Source connection"
                  : "Assigned connection"}
              </dt>
              <dd>
                <code>{reviewed.id}</code>
              </dd>
              <dt>Connection version</dt>
              <dd>{reviewed.version}</dd>
              <dt>Definition fingerprint</dt>
              <dd>
                <code>{reviewed.hash}</code>
              </dd>
              {command.operation === "provision" ? (
                <>
                  <dt>Receiving account</dt>
                  <dd>
                    <code>{command.recipient_actor_id}</code>
                  </dd>
                  <dt>Recipient authority revision</dt>
                  <dd>{command.recipient_authority_revision}</dd>
                  {reviewedSource && (
                    <>
                      <dt>Destination</dt>
                      <dd>
                        {reviewedSource.user}@{reviewedSource.address}{" "}
                        {reviewedSource.directory}
                      </dd>
                      <dt>SSH host fingerprint</dt>
                      <dd>
                        <code>{reviewedSource.host_fingerprint}</code>
                      </dd>
                      <dt>SSH key fingerprint</dt>
                      <dd>
                        <code>{reviewedSource.key_fingerprint}</code>
                      </dd>
                    </>
                  )}
                </>
              ) : (
                <>
                  <dt>Original assignment event</dt>
                  <dd>
                    <code>{command.provision_event_id}</code>
                  </dd>
                </>
              )}
            </dl>
            <p>
              {command.operation === "provision"
                ? "The recipient can use this assigned connection in its own approved workflow."
                : "Queued work that needs this exact connection will be refused before it contacts the receiver."}
            </p>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button className="secondary" disabled={busy} onClick={cancel}>
                Close review
              </button>
              <button
                className="primary"
                disabled={busy}
                onClick={() => void apply()}
              >
                {busy
                  ? "Submitting…"
                  : failure
                    ? "Retry exact command"
                    : command.operation === "provision"
                      ? "Assign SFTP route"
                      : "Withdraw SFTP route"}
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
