import { useEffect, useRef, useState } from "react";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import { IntegrityReportStatement } from "./artifact-integrity";
import {
  evidenceV3,
  type EvidenceDirection,
  type EvidenceExpectation,
  type ExchangeEvidence,
} from "./artifact-evidence-types";

const labels = {
  "custody-acceptance": "Source accepted into custody",
  "availability-offer": "Receive offer recorded",
  "view-canceled": "Sender withdrew the offer",
  "view-declined": "Recipient declined the offer",
};
export function ArtifactEvidence({
  client,
  id,
  direction,
  expected,
  onError,
}: {
  client: ExchangeReceiveApi;
  id: string;
  direction: EvidenceDirection;
  expected?: EvidenceExpectation;
  onError: (error: unknown) => void;
}) {
  const binding = JSON.stringify([id, direction, expected]),
    serial = useRef(0),
    active = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false),
    [record, setRecord] = useState<{
      client: ExchangeReceiveApi;
      binding: string;
      trace: ExchangeEvidence;
    } | null>(null);
  useEffect(() => {
    serial.current++;
    active.current?.abort();
    active.current = null;
    setRecord(null);
    setBusy(false);
    return () => {
      serial.current++;
      active.current?.abort();
    };
  }, [client, binding]);
  const trace =
    record?.client === client &&
    record.binding === binding &&
    client.isCurrent()
      ? record.trace
      : null;
  async function load() {
    active.current?.abort();
    const controller = new AbortController(),
      generation = ++serial.current;
    active.current = controller;
    setRecord(null);
    setBusy(true);
    try {
      const result = await client.evidence(
        id,
        direction,
        expected,
        controller.signal,
        evidenceV3,
      );
      if (
        generation === serial.current &&
        !controller.signal.aborted &&
        client.isCurrent()
      )
        setRecord({ client, binding, trace: result });
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
  return (
    <section aria-label="Recorded exchange evidence">
      <h4>Recorded evidence</h4>
      <p>
        Read the custody, offer, decision and integrity records you can
        currently inspect.
      </p>
      <button type="button" disabled={busy} onClick={() => void load()}>
        {busy ? "Reading evidence…" : "Read recorded evidence"}
      </button>
      {trace && (
        <div aria-live="polite">
          <p>
            Metadata state: <strong>{trace.current_metadata_state}</strong>,
            observed <time dateTime={trace.checked_at}>{trace.checked_at}</time>
            .
          </p>
          {trace.details === "opaque" ? (
            <p>
              The view is held. Artifact identity and recorded event details are
              not disclosed.
            </p>
          ) : (
            <>
              <ol>
                {trace.recorded_events.map((event) => (
                  <li key={event.event_id}>
                    {labels[event.kind]} —{" "}
                    <time dateTime={event.recorded_at}>
                      {event.recorded_at}
                    </time>
                    . Event <code>{event.event_id}</code>; resource{" "}
                    <code>{event.resource_id}</code>.
                  </li>
                ))}
              </ol>
              {trace.integrity_report && (
                <IntegrityReportStatement report={trace.integrity_report} />
              )}
              {trace.record_projection && (
                <section aria-label="Record projection lineage">
                  <h5>Record projection lineage</h5>
                  <p>
                    Input revision{" "}
                    <code>
                      {trace.record_projection.source_artifact.file_revision_id}
                    </code>{" "}
                    was accepted in event{" "}
                    <code>
                      {trace.record_projection.source_accepted_event_id}
                    </code>
                    . Its SHA-256 is{" "}
                    <code>
                      {trace.record_projection.source_artifact.sha256}
                    </code>
                    .
                  </p>
                  <p>
                    Projection{" "}
                    <code>{trace.record_projection.projection_id}</code>{" "}
                    produced this artifact. Definition SHA-256{" "}
                    <code>{trace.record_projection.definition_hash}</code>.
                    Completion event{" "}
                    <code>{trace.record_projection.completed_event_id}</code> at{" "}
                    <time dateTime={trace.record_projection.completed_at}>
                      {trace.record_projection.completed_at}
                    </time>
                    .
                  </p>
                </section>
              )}
              {trace.reply_reference_only && (
                <p>
                  Reply reference: <code>{trace.reply_reference_only}</code>.
                  This reference grants no parent access and proves no byte
                  derivation.
                </p>
              )}
            </>
          )}
          <p>
            Retrieval, receiver persistence and business processing remain
            unknown. Recorded availability does not prove any of them.
          </p>
        </div>
      )}
    </section>
  );
}
