import { useEffect, useRef, useState } from "react";
import type { ArtifactExchange } from "./artifact-exchanges-types";
import type { ExchangeReceiveApi } from "./artifact-exchanges-api";
import type {
  EvidenceDirection,
  ExchangeIntegrityCommand,
  ExchangeIntegrityReport,
} from "./artifact-evidence-types";
import { digestFile, operationKey } from "./crypto";
import { ApiError } from "./types";

export function IntegrityReportStatement({
  report,
}: {
  report: ExchangeIntegrityReport;
}) {
  return (
    <p>
      Recipient reported matching length and SHA-256. Receiver persistence and
      business processing are unknown. Recorded at{" "}
      <time dateTime={report.recordedAt}>{report.recordedAt}</time> in event{" "}
      <code>{report.event}</code>.
    </p>
  );
}

export function ArtifactIntegrity({
  client,
  exchange,
  direction,
  onError,
}: {
  client: ExchangeReceiveApi;
  exchange: ArtifactExchange;
  direction: EvidenceDirection;
  onError: (error: unknown) => void;
}) {
  const id = exchange.id;
  const expected = {
    request_hash: exchange.request_hash,
    artifact: exchange.request.artifact,
    expires_at: exchange.request.expires_at,
  };
  const [read] = useState(operationKey);
  const [started, setStarted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [notice, setNotice] = useState("");
  const [draft, setDraft] = useState<{
    command: ExchangeIntegrityCommand;
    key: string;
  } | null>(null);
  const [report, setReport] = useState<ExchangeIntegrityReport | null>(null);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), [client]);

  async function run(action: (signal: AbortSignal) => Promise<void>) {
    if (active.current || !client.isCurrent()) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setNotice("");
    try {
      await action(controller.signal);
    } catch (error) {
      if (!controller.signal.aborted && client.isCurrent()) onError(error);
    } finally {
      active.current = null;
      if (!controller.signal.aborted && client.isCurrent()) {
        setBusy(false);
        setProgress(null);
      }
    }
  }

  async function verify(file: File, signal: AbortSignal) {
    if (file.size !== expected.artifact.size_bytes) {
      setNotice("The selected file's length differs from the offer.");
      return;
    }
    const command = await client
      .selectIntegrityRead(id, read, expected, signal)
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      });
    if (signal.aborted || !client.isCurrent()) return;
    if (!command) {
      setNotice(
        "No authorized full read is available. Try the download again and check the current offer.",
      );
      return;
    }
    setProgress(0);
    const digest = await digestFile(
      file,
      (bytes) => {
        setProgress(Math.floor((bytes / file.size) * 100));
      },
      signal,
    );
    if (signal.aborted || !client.isCurrent()) return;
    if (digest !== command.sha256) {
      setNotice("The selected file's SHA-256 differs from the offer.");
      return;
    }
    setDraft({ command, key: operationKey() });
    setNotice(
      "The saved file matches the offered length and SHA-256. Submit to record your report.",
    );
  }

  async function load(signal: AbortSignal) {
    const result = await client
      .readIntegrityReport(id, direction, expected, signal)
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      });
    if (signal.aborted || !client.isCurrent()) return;
    setReport(result);
    if (result) setDraft(null);
    else setNotice("No integrity report is available for this offer.");
  }

  async function submit(signal: AbortSignal) {
    if (!draft) return;
    try {
      const result = await client.submitIntegrityReport(
        id,
        expected,
        draft.command,
        draft.key,
        signal,
      );
      if (signal.aborted || !client.isCurrent()) return;
      setReport(result);
      setDraft(null);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status >= 500) {
        if (!signal.aborted && client.isCurrent())
          setNotice(
            "The browser did not receive a receipt. Submit again to recover the original report, or read the recorded report.",
          );
        return;
      }
      throw error;
    }
  }

  return (
    <section aria-label="Recipient integrity report">
      <h4>Recipient integrity report</h4>
      <button type="button" disabled={busy} onClick={() => void run(load)}>
        Read integrity report
      </button>
      {direction === "incoming" && !draft && !report && (
        <>
          <p>
            <a
              href={client.integrityDownloadPath(id, read)}
              download="artifact"
              onClick={(event) => {
                if (active.current || !client.isCurrent()) {
                  event.preventDefault();
                  return;
                }
                setNotice("");
                setStarted(true);
              }}
            >
              Download for integrity report
            </a>
          </p>
          <label>
            Verify saved artifact
            <input
              type="file"
              disabled={!started || busy}
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                event.currentTarget.value = "";
                if (file && started) void run((signal) => verify(file, signal));
              }}
            />
          </label>
        </>
      )}
      {draft && !report && (
        <button type="button" disabled={busy} onClick={() => void run(submit)}>
          Submit integrity report
        </button>
      )}
      {progress !== null && (
        <progress
          aria-label="Verifying file bytes"
          max={100}
          value={progress}
        />
      )}
      <div role="status">
        {notice && <p>{notice}</p>}
        {report && <IntegrityReportStatement report={report} />}
      </div>
    </section>
  );
}
