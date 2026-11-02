import { useEffect, useId, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { ApprovalConfirm, approvalPost } from "./onboarding-approvals";
import { PlanReview, ProgramReview } from "./programs";
import { RoutingEffects } from "./collection-routing";
import {
  asCollectionView,
  asCollectionConfiguration,
  type CollectionView,
} from "./collections-types";
import {
  asCollectionHandoffPreview,
  asCollectionHandoffView,
  asCollectionHandoffHistory,
  asCollectionHandoffResult,
  handoffSelection,
  type CollectionHandoffPreview,
  type CollectionHandoffView,
  type CollectionHandoffReview,
  type CollectionHandoffRecord,
  type HandoffEffect,
  type HandoffState,
} from "./collection-handoffs-types";
import {
  routingKeyReference,
  retainRoutingKey,
  savedRoutingKey,
  forgetRoutingKey,
} from "./collection-routing-recovery";

type Operation = "propose" | "approve" | "cancel" | "execute";
type Review = { view: CollectionView; preview: CollectionHandoffPreview };
type Command = {
  operation: Operation;
  view: CollectionView;
  review: CollectionHandoffReview;
  record?: CollectionHandoffRecord;
  body: unknown;
  hash: string;
  reference: string;
  key: string;
  expected: {
    hash: string;
    state: HandoffState;
    revision: number;
    id?: string;
  };
};
type Props = {
  api: Api;
  session: Session;
  view: CollectionView;
  disabled: boolean;
  onChanged: () => Promise<void>;
  onError: (e: unknown) => void;
  onConfirmed: (message: string) => void;
  onInspectRun: (inputID: string) => Promise<void>;
};
function storage(): Storage | undefined {
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}
const proposalBody = (p: CollectionHandoffPreview) => ({
  selection: handoffSelection(p.definition),
  definition_hash: p.definition_hash,
});
const decisionBody = (r: CollectionHandoffRecord, revision = r.revision) => ({
  definition_hash: r.definition_hash,
  expected_revision: revision,
});
const stateFor: Record<Operation, HandoffState> = {
  propose: "proposed",
  approve: "approved",
  cancel: "cancelled",
  execute: "completed",
};

function Effects({ effects }: { effects: HandoffEffect[] }) {
  return (
    <>
      <RoutingEffects effects={effects} />
      {effects.length > 0 && (
        <ul>
          {effects.map((e) => (
            <li key={e.step_id}>
              {e.step_id}: SSH account <code>{e.user}</code>, client public key{" "}
              <code>{e.key_fingerprint}</code>.
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
function ReviewDetails({ review }: { review: CollectionHandoffReview }) {
  return (
    <>
      <h5>Previous workflow and exact source plan</h5>
      <p>
        Workflow <code>{review.source_workflow.id}</code> version{" "}
        {review.source_workflow.version}, fingerprint{" "}
        <code>{review.source_workflow.definition_hash}</code>;{" "}
        {review.source_workflow.state}.
      </p>
      <Effects effects={review.source_effects} />
      <PlanReview plan={review.source_plan} />
      <h5>Replacement workflow and recipient catalog</h5>
      <p>
        Workflow <code>{review.workflow.id}</code> version{" "}
        {review.workflow.version}, fingerprint{" "}
        <code>{review.workflow.definition_hash}</code>; {review.workflow.state}.
      </p>
      <Effects effects={review.effects} />
      {review.workflow.definition.program && (
        <ProgramReview program={review.workflow.definition.program} />
      )}
    </>
  );
}

export function CollectionHandoffs({
  api,
  session,
  view,
  disabled,
  onChanged,
  onError,
  onConfirmed,
  onInspectRun,
}: Props) {
  const base =
    api.prefix + "/workflow-collections/" + view.job.id + "/handoffs";
  const has = (p: string) => session.identity.permissions.includes(p);
  const execute = ["workflow_execute", "read", "write", "list"].every(has);
  const manage = execute && has("workflow_manage"),
    approve = execute && has("workflow_approve");
  const eligible = view.inputs.filter(
    (i) =>
      i.first_job_id === view.job.id &&
      i.run_id !== null &&
      i.state === "queued",
  );
  const [inputID, setInputID] = useState(eligible[0]?.id ?? ""),
    [version, setVersion] = useState(view.job.workflow_version + 1);
  const [history, setHistory] = useState<
    ReturnType<typeof asCollectionHandoffHistory>
  >({ handoffs: [] });
  const [details, setDetails] = useState<CollectionHandoffView | null>(null),
    [review, setReview] = useState<Review | null>(null);
  const [reviewed, setReviewed] = useState(""),
    [command, setCommand] = useState<Command | null>(null);
  const [busy, setBusy] = useState(false),
    [failure, setFailure] = useState("");
  const [receipt, setReceipt] = useState<{
    operation: Operation;
    id: string;
    state: HandoffState;
    replayed: boolean;
  } | null>(null);
  const inputLabel = useId(),
    versionLabel = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const active = disabled || busy;
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
    } catch (error) {
      onError(error);
    } finally {
      setBusy(false);
    }
  }
  async function loadHistory(after = "") {
    setHistory(
      await api.request(
        base + "?limit=20" + (after ? "&after=" + after : ""),
        {},
        (v) => asCollectionHandoffHistory(v, view, after, 20),
      ),
    );
  }
  useEffect(() => {
    void loadHistory().catch(onError);
  }, [api, view.job.id, JSON.stringify(view.replacements)]);
  useEffect(() => {
    if (review || details) heading.current?.focus();
  }, [
    review?.preview.definition_hash,
    details?.handoff.id,
    details?.handoff.revision,
  ]);
  async function freshView() {
    return api.request(
      api.prefix + "/workflow-collections/" + view.job.id,
      {},
      (v) =>
        asCollectionView(
          v,
          view.job.id,
          session.identity.authority_revision,
          view.job.definition_hash,
        ),
    );
  }
  async function inspect(id: string) {
    const fresh = await freshView();
    const metadata = await api.request(base + "/" + id, {}, (v) =>
      asCollectionHandoffView(v, fresh, id),
    );
    setDetails(metadata);
    setReview(null);
    setReviewed("");
    setReceipt(null);
  }
  async function prepare() {
    if (!Number.isSafeInteger(version) || version < 1 || version > 2147483647)
      throw new ApiError("invalid_workflow_revision", 400);
    const fresh = await freshView(),
      input = fresh.inputs.find(
        (i) => i.id === inputID && i.first_job_id === fresh.job.id,
      );
    if (!input?.run_id) throw new ApiError("collected_run_required", 409);
    const target = await api.request(
      api.prefix + "/workflows/" + fresh.job.workflow_id + "/" + version,
      {},
      asCollectionConfiguration,
    );
    if (
      target.id !== fresh.job.workflow_id ||
      target.version !== version ||
      target.state !== "approved" ||
      target.definition.schema_version !== 2
    )
      throw new ApiError("approved_routing_revision_required", 409);
    const selection = {
      input_id: input.id,
      source_run_id:
        fresh.replacements?.find((r) => r.input_id === input.id)
          ?.current_run_id ?? input.run_id,
      workflow: {
        id: target.id,
        version: target.version,
        hash: target.definition_hash,
      },
      expected_authority_revision: session.identity.authority_revision,
    };
    const p = await approvalPost(
      api,
      base + "/preview",
      selection,
      undefined,
      (v) => asCollectionHandoffPreview(v, fresh, selection),
    );
    if (p.workflow.definition_hash !== target.definition_hash)
      throw new ApiError("handoff_review_stale", 409);
    setReview({ view: fresh, preview: p });
    setDetails(null);
    setReviewed("");
    setReceipt(null);
  }
  function queue(operation: Operation) {
    try {
      if (
        operation === "propose"
          ? !review || reviewed !== review.preview.definition_hash
          : !details ||
            (operation !== "cancel" &&
              (!details.current_bindings ||
                reviewed !== details.handoff.definition_hash))
      )
        return;
      const snapshot = structuredClone(
        operation === "propose" ? review! : { view, preview: details! },
      );
      const record =
        operation === "propose" ? undefined : structuredClone(details!.handoff);
      const metadata = operation === "propose" ? review!.preview : details!;
      const hash = record?.definition_hash ?? review!.preview.definition_hash;
      const body =
        operation === "propose"
          ? proposalBody(review!.preview)
          : decisionBody(record!);
      const reference = routingKeyReference(
        session.identity,
        view.job.id,
        "handoff_" + operation,
        record?.id ?? "",
        body,
      );
      const retained = retainRoutingKey(reference, storage());
      if (!retained.persisted)
        onConfirmed(
          "The operation key is retained only while this review stays open. Keep it open until the receipt is confirmed.",
        );
      setFailure("");
      setCommand({
        operation,
        view: snapshot.view,
        review: structuredClone(metadata),
        ...(record ? { record } : {}),
        body,
        hash,
        reference,
        key: retained.key,
        expected: {
          hash,
          state: stateFor[operation],
          revision: record ? record.revision + 1 : 1,
          ...(record ? { id: record.id } : {}),
        },
      });
    } catch (error) {
      onError(error);
    }
  }
  async function confirm() {
    if (!command) return;
    const c = command;
    setBusy(true);
    setFailure("");
    try {
      const result = await approvalPost(
        api,
        c.operation === "propose"
          ? base + "/proposals"
          : base + "/" + c.record!.id + "/" + c.operation,
        c.body,
        c.key,
        (v) => asCollectionHandoffResult(v, c.view, c.review, c.expected),
      );
      forgetRoutingKey(c.reference, storage());
      setCommand(null);
      setReview(null);
      setReviewed("");
      setReceipt({
        operation: c.operation,
        id: result.resource.handoff.id,
        state: result.resource.handoff.state,
        replayed: result.replayed,
      });
      onConfirmed(
        c.operation === "execute"
          ? "Old untouched work was cancelled and one exact replacement was queued together. No receiver was contacted. Review ordinary dispatch approval before sending."
          : "The exact handoff decision is recorded. No source or receiver was contacted.",
      );
      await onChanged();
      await loadHistory();
      const fresh = await freshView();
      setDetails(
        await api.request(base + "/" + result.resource.handoff.id, {}, (v) =>
          asCollectionHandoffView(v, fresh, result.resource.handoff.id),
        ),
      );
    } catch (error) {
      if (command === c)
        setFailure(
          "The result was not confirmed. Keep this review open and retry the same original key, or inspect history and look up its saved receipt after reloading.",
        );
      onError(error);
    } finally {
      setBusy(false);
    }
  }
  function recoveries() {
    if (!details) return [];
    const h = details.handoff;
    return (["propose", "approve", "execute", "cancel"] as Operation[])
      .map((operation) => {
        const before =
          operation === "propose"
            ? 0
            : operation === "approve"
              ? 1
              : operation === "execute"
                ? 2
                : h.state === "cancelled"
                  ? h.revision - 1
                  : h.revision;
        const body =
          operation === "propose"
            ? {
                selection: handoffSelection(h.definition),
                definition_hash: h.definition_hash,
              }
            : decisionBody(h, before);
        const reference = routingKeyReference(
          session.identity,
          view.job.id,
          "handoff_" + operation,
          operation === "propose" ? "" : h.id,
          body,
        );
        return {
          operation,
          reference,
          key: savedRoutingKey(reference, storage()),
          expected: {
            id: h.id,
            hash: h.definition_hash,
            state: stateFor[operation],
            revision: before + 1,
          },
        };
      })
      .filter((r) => r.key);
  }
  async function recover(r: ReturnType<typeof recoveries>[number]) {
    const result = await api.request(
      base + "/receipts/" + r.key + "/result",
      {},
      (v) => asCollectionHandoffResult(v, view, details!, r.expected),
    );
    forgetRoutingKey(r.reference, storage());
    setReceipt({
      operation: r.operation,
      id: result.resource.handoff.id,
      state: result.resource.handoff.state,
      replayed: result.replayed,
    });
    onConfirmed(
      "The original saved receipt was read. No command was retried and no receiver was contacted.",
    );
  }
  const metadata = review?.preview ?? details,
    definition = review?.preview.definition ?? details?.handoff.definition;
  const fingerprint =
    review?.preview.definition_hash ?? details?.handoff.definition_hash;
  return (
    <section aria-label="Collected run handoffs">
      <h4>Replace untouched collected work</h4>
      <p>
        A handoff cancels an old run only while every delivery is still
        untouched, then queues one replacement under a separately approved
        workflow. Original capture and input assignment remain in history.
        Attempted, encrypted or uncertain deliveries require a different
        recovery path.
      </p>
      {manage && eligible.length > 0 && view.current_authority && (
        <div>
          <label htmlFor={inputLabel}>Collected input to replace</label>
          <select
            id={inputLabel}
            value={inputID}
            disabled={active}
            onChange={(e) => {
              setInputID(e.target.value);
              setReview(null);
              setDetails(null);
              setReviewed("");
            }}
          >
            {eligible.map((i) => (
              <option key={i.id} value={i.id}>
                {i.source_name}
              </option>
            ))}
          </select>
          <label htmlFor={versionLabel}>Replacement workflow version</label>
          <input
            id={versionLabel}
            type="number"
            min={1}
            max={2147483647}
            step={1}
            value={version}
            disabled={active}
            onChange={(e) => {
              setVersion(Number(e.target.value));
              setReview(null);
              setReviewed("");
            }}
          />
          <button disabled={active} onClick={() => void perform(prepare)}>
            Preview collected run handoff
          </button>
        </div>
      )}
      <button
        disabled={active}
        onClick={() => void perform(() => loadHistory())}
      >
        Refresh handoff history
      </button>
      <ul>
        {history.handoffs.map((h) => (
          <li key={h.id}>
            Handoff <code>{h.id}</code>: {h.state}; input{" "}
            <code>{h.input_id}</code>.{" "}
            <button
              disabled={active}
              onClick={() => void perform(() => inspect(h.id))}
            >
              {"Inspect handoff " + h.id}
            </button>
          </li>
        ))}
      </ul>
      {history.next && (
        <button
          disabled={active}
          onClick={() => void perform(() => loadHistory(history.next))}
        >
          Next handoff history page
        </button>
      )}
      {metadata && definition && fingerprint && (
        <div>
          <h4 ref={heading} tabIndex={-1}>
            Exact collected run handoff review
          </h4>
          <p>
            Old run <code>{definition.source_run.id}</code>, revision{" "}
            {definition.source_run.revision}; input{" "}
            <code>{definition.input_id}</code>; plan{" "}
            <code>{definition.source_run.plan_hash}</code>.
          </p>
          <ReviewDetails review={metadata} />
          <h5>Exact replacement plan</h5>
          <PlanReview plan={definition.plan} />
          <p>
            Handoff fingerprint <code>{fingerprint}</code>. This preparation
            made no source or receiver contact.
          </p>
          <p>
            {definition.intents.length} old delivery intents must still be
            queued with zero claims, attempts or ciphertext. Their revisions and
            fingerprints are bound into this review.
          </p>
          <ul>
            {definition.intents.map((i) => (
              <li key={i.id}>
                {i.step_id}: <code>{i.id}</code> revision {i.revision},
                fingerprint <code>{i.definition_hash}</code>.
              </li>
            ))}
          </ul>
          {details && (
            <p>
              Decision {details.handoff.state};{" "}
              {details.current_bindings
                ? "bindings still current"
                : details.binding_reason.replaceAll("_", " ")}
              . Reserved successor <code>{details.handoff.planned_run_id}</code>
              {details.handoff.state !== "completed"
                ? " is not a completed replacement yet"
                : " was created with the old cancellation"}
              .
            </p>
          )}
          {(review || details?.current_bindings) && (
            <label>
              <input
                type="checkbox"
                checked={reviewed === fingerprint}
                disabled={active}
                onChange={(e) =>
                  setReviewed(e.target.checked ? fingerprint : "")
                }
              />
              I reviewed both workflows, exact file facts, old intents, selected
              recipients and key identities for this fingerprint.
            </label>
          )}
          {review && manage && (
            <button
              disabled={active || reviewed !== fingerprint}
              onClick={() => queue("propose")}
            >
              Review proposing collected handoff
            </button>
          )}
          {details?.handoff.state === "proposed" &&
            details.current_bindings &&
            approve && (
              <button
                disabled={active || reviewed !== fingerprint}
                onClick={() => queue("approve")}
              >
                Review approving collected handoff
              </button>
            )}
          {details?.handoff.state === "approved" &&
            details.current_bindings &&
            manage && (
              <button
                disabled={active || reviewed !== fingerprint}
                onClick={() => queue("execute")}
              >
                Review executing collected handoff
              </button>
            )}
          {details &&
            ["proposed", "approved"].includes(details.handoff.state) &&
            manage && (
              <button disabled={active} onClick={() => queue("cancel")}>
                Review withdrawing collected handoff
              </button>
            )}
          {details?.handoff.state === "completed" && (
            <button
              disabled={active}
              onClick={() =>
                void perform(() => onInspectRun(details.handoff.input_id))
              }
            >
              Inspect current replacement run
            </button>
          )}
          {recoveries().map((r) => (
            <button
              key={r.operation}
              disabled={active}
              onClick={() => void perform(() => recover(r))}
            >
              {"Look up saved " + r.operation + " handoff receipt"}
            </button>
          ))}
        </div>
      )}
      {receipt && (
        <p role="status">
          Original {receipt.operation} receipt: handoff{" "}
          <code>{receipt.id}</code>, recorded state {receipt.state};{" "}
          {receipt.replayed
            ? "recovered original result"
            : "new decision confirmed"}
          .
        </p>
      )}
      {command && (
        <ApprovalConfirm
          title={
            {
              propose: "Propose exact collected handoff",
              approve: "Approve exact collected handoff",
              cancel: "Withdraw exact collected handoff",
              execute: "Cancel untouched work and queue exact replacement",
            }[command.operation]
          }
          busy={busy}
          failure={failure}
          onConfirm={() => void confirm()}
          onCancel={() => {
            setCommand(null);
            setFailure("");
          }}
        >
          <p>
            Fingerprint <code>{command.hash}</code>. Original operation key{" "}
            <code>{command.key}</code>.
          </p>
          <ReviewDetails review={command.review} />
          <PlanReview
            plan={
              command.record?.definition.plan ?? review!.preview.definition.plan
            }
          />
          <p>
            {command.operation === "execute"
              ? "This atomically cancels the exact untouched intents and old run, queues one exact successor and records the receipt. Sending remains a separate ordinary worker action and requires current dispatch policy."
              : command.operation === "cancel"
                ? "Withdraw only this proposal or approval. The original run and all delivery work remain as they are."
                : "Record only this exact proposal or approval. No run is replaced and no file is sent by this decision."}
          </p>
        </ApprovalConfirm>
      )}
    </section>
  );
}
