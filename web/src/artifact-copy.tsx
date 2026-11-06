import { useEffect, useRef, useState, type FormEvent } from "react";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import { operationKey } from "./crypto";
import { offerRecoveryMaximum } from "./artifact-recovery";
import {
  asReceivedCopyRequest,
  type CopyOperation,
  type ReceivedCopyResult,
} from "./artifact-copy-types";
import type { IncomingExchange } from "./artifact-exchanges-types";

export function ArtifactCopy({
  client,
  selected,
  onError,
}: {
  client: ExchangeReceiveApi;
  selected: IncomingExchange | null;
  onError: (error: unknown) => void;
}) {
  const [path, setPath] = useState(""),
    [saved, setSaved] = useState<CopyOperation | null>(null),
    [accepted, setAccepted] = useState<ReceivedCopyResult | null>(null),
    [reviewed, setReviewed] = useState(false),
    [imported, setImported] = useState(false),
    [uncertain, setUncertain] = useState(false),
    [busy, setBusy] = useState(false);
  const owner = useRef(client),
    serial = useRef(0),
    active = useRef<AbortController | null>(null),
    url = useRef<string | null>(null),
    heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => {
    owner.current = client;
    setSaved(null);
    setAccepted(null);
    setPath("");
    setReviewed(false);
    setImported(false);
    setUncertain(false);
    setBusy(false);
    return () => {
      serial.current++;
      active.current?.abort();
      if (url.current) {
        URL.revokeObjectURL(url.current);
        url.current = null;
      }
    };
  }, [client]);
  useEffect(() => {
    if (saved) heading.current?.focus();
  }, [saved?.request_key]);
  function clear() {
    setSaved(null);
    setAccepted(null);
    setReviewed(false);
    setImported(false);
    setUncertain(false);
    setPath("");
    if (url.current) {
      URL.revokeObjectURL(url.current);
      url.current = null;
    }
  }
  function prepare(event: FormEvent) {
    event.preventDefault();
    if (saved || busy || selected?.state !== "offered" || !client.canCopy())
      return;
    try {
      const e = selected.exchange;
      setSaved({
        request: asReceivedCopyRequest({
          exchange_id: e.id,
          request_hash: e.request_hash,
          artifact: e.request.artifact,
          virtual_path: path,
        }),
        request_key: operationKey(),
      });
      setReviewed(true);
      setImported(false);
    } catch (error) {
      onError(error);
    }
  }
  async function submit() {
    if (!saved || !reviewed || busy || !client.canCopy()) return;
    active.current?.abort();
    const controller = new AbortController(),
      generation = ++serial.current;
    active.current = controller;
    setBusy(true);
    setUncertain(true);
    try {
      const result = await client.copyReceived(
        saved.request,
        saved.request_key,
        controller.signal,
        saved.expected_artifact_id,
      );
      if (
        generation !== serial.current ||
        controller.signal.aborted ||
        !client.isCurrent()
      )
        return;
      setAccepted(result);
      setSaved({
        ...saved,
        expected_artifact_id: result.artifact.file_revision_id,
      });
      setUncertain(false);
    } catch (error) {
      if (
        generation === serial.current &&
        !controller.signal.aborted &&
        client.isCurrent()
      )
        onError(error);
    } finally {
      if (generation === serial.current) setBusy(false);
    }
  }
  function save() {
    if (!saved || busy) return;
    try {
      const value = client.copyRecovery(saved, location.origin);
      if (url.current) URL.revokeObjectURL(url.current);
      url.current = URL.createObjectURL(new Blob([JSON.stringify(value)]));
      const link = document.createElement("a");
      link.href = url.current;
      link.download = "freightctl-received-copy-recovery.json";
      link.click();
    } catch (error) {
      onError(error);
    }
  }
  async function load(file: File) {
    if (saved || busy || !client.canCopy()) return;
    const generation = ++serial.current;
    setBusy(true);
    try {
      if (file.size > offerRecoveryMaximum)
        throw new Error("Recovery file is too large");
      const text = await file.text();
      if (generation !== serial.current || !client.isCurrent()) return;
      const value = client.readCopyRecovery(text, location.origin);
      setSaved(value);
      setReviewed(false);
      setImported(true);
      setUncertain(true);
    } catch (error) {
      if (generation === serial.current && client.isCurrent()) onError(error);
    } finally {
      if (generation === serial.current) setBusy(false);
    }
  }
  if (owner.current !== client || !client.isCurrent()) return null;
  return (
    <section aria-label="Copy received artifact">
      <h3>Keep an owned copy</h3>
      <p>
        A copy requires separate write permission. It gets a new private file
        identity and fresh checks. It grants no forwarding or execution
        permission.
      </p>
      {!client.canCopy() ? (
        <p>
          This account cannot create an owned copy. Receiving and writing are
          separate permissions.
        </p>
      ) : saved ? (
        <>
          <h4 ref={heading} tabIndex={-1}>
            Review received copy
          </h4>
          <dl>
            <dt>Original exchange</dt>
            <dd>
              <code>{saved.request.exchange_id}</code>
            </dd>
            <dt>Exact source revision</dt>
            <dd>
              <code>{saved.request.artifact.file_revision_id}</code>
            </dd>
            <dt>Length</dt>
            <dd>{saved.request.artifact.size_bytes} bytes</dd>
            <dt>SHA-256</dt>
            <dd>
              <code>{saved.request.artifact.sha256}</code>
            </dd>
            <dt>New path in your workspace</dt>
            <dd>
              <code>{saved.request.virtual_path}</code>
            </dd>
            <dt>Original operation key</dt>
            <dd>
              <code>{saved.request_key}</code>
            </dd>
          </dl>
          {imported && (
            <p>
              Recovery files are untrusted hints. Review the source and path
              before submitting. If this operation never committed, the server
              may create the copy after checking current access.
            </p>
          )}
          {!reviewed && (
            <button
              type="button"
              disabled={busy}
              onClick={() => setReviewed(true)}
            >
              I reviewed these copy details
            </button>
          )}
          {uncertain && (
            <p role="status">
              No confirmed copy receipt is loaded. Keep this original key when
              retrying; a missing response does not prove failure.
            </p>
          )}
          <button
            type="button"
            disabled={busy || !reviewed}
            onClick={() => void submit()}
          >
            {busy ? "Checking and copying…" : "Submit or recover original copy"}
          </button>
          <button type="button" disabled={busy} onClick={save}>
            Save copy recovery file
          </button>
          {(!uncertain || accepted) && (
            <button type="button" disabled={busy} onClick={clear}>
              {accepted ? "Start another copy" : "Dismiss copy review"}
            </button>
          )}
          {accepted && (
            <div role="status">
              <p>
                Original custody acceptance:{" "}
                <strong>{accepted.acceptance}</strong>. Owned revision{" "}
                <code>{accepted.artifact.file_revision_id}</code>.
              </p>
              <p>
                Current availability is not checked. Receiver persistence and
                business processing remain unknown.
              </p>
            </div>
          )}
        </>
      ) : (
        <>
          <form onSubmit={prepare}>
            <label>
              New owned copy path
              <input
                value={path}
                onChange={(event) => setPath(event.target.value)}
                maxLength={1024}
                required
                placeholder="/received/document.dat"
                disabled={busy || selected?.state !== "offered"}
              />
            </label>
            <button
              type="submit"
              disabled={busy || selected?.state !== "offered" || !path}
            >
              Review new owned copy
            </button>
          </form>
          {selected?.state !== "offered" && (
            <p>
              Inspect an available incoming artifact to choose its exact source.
            </p>
          )}
          <label>
            Open copy recovery file
            <input
              type="file"
              accept="application/json,.json"
              disabled={busy}
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.target.value = "";
                if (file) void load(file);
              }}
            />
          </label>
        </>
      )}
    </section>
  );
}
