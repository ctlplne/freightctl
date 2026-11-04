import { useEffect, useRef, useState } from "react";
import { FTPSPeerIdentity, FTPSReceiverTerms } from "./ftps-peer-identity";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { ApprovalConfirm, approvalPost } from "./onboarding-approvals";
import { PlanReview, ProgramReview } from "./programs";
import {
  asCollectionView,
  asCollectionConfiguration,
  type CollectionView,
  type WorkflowConfiguration,
  type CollectionRunPreview,
} from "./collections-types";
import {
  asCapturedRoutingMetadata,
  asCapturedRoutingHistory,
  asCapturedRoutingPreview,
  asCapturedRoutingInputPreview,
  asCapturedRoutingResult,
  type CapturedRoutingMetadata,
  type CapturedRoutingRecord,
  type CapturedRoutingPreview,
  type CapturedRoutingSelection,
  type CapturedRoutingState,
} from "./collection-routing-types";
import {
  routingKeyReference,
  savedRoutingKey,
  retainRoutingKey,
  forgetRoutingKey,
} from "./collection-routing-recovery";
import type { ScheduleEffect } from "./schedules-types";

type Props = {
  api: Api;
  session: Session;
  view: CollectionView;
  metadata: CapturedRoutingMetadata;
  disabled: boolean;
  onChanged: () => Promise<void>;
  onError: (e: unknown) => void;
  onConfirmed: (message: string) => void;
};
type Review = {
  view: CollectionView;
  workflow: WorkflowConfiguration;
  selection: CapturedRoutingSelection;
  preview: CapturedRoutingPreview;
  record?: CapturedRoutingRecord;
  checked: Record<string, string>;
  active?: { id: string; preview: CollectionRunPreview };
};
type Operation = "propose" | "approve" | "revoke" | "withdraw";
type Command = {
  operation: Operation;
  record?: CapturedRoutingRecord;
  review?: Review;
  body: unknown;
  reference: string;
  key: string;
  hash: string;
};

export function RoutingEffects({ effects }: { effects: ScheduleEffect[] }) {
  return effects.length ? (
    <ul>
      {effects.map((e) => (
        <li key={e.step_id}>
          <strong>{e.step_id}</strong>: {e.address}, directory{" "}
          <code>{e.directory}</code>, final name{" "}
          <code>{e.final_name_pattern}</code>.{" "}
          {e.ftps ? (
            <>
              <FTPSPeerIdentity proof={e.ftps} /> Account <code>{e.user}</code>.{" "}
              <FTPSReceiverTerms proof={e.ftps} />{" "}
            </>
          ) : (
            <>
              SSH host <code>{e.host_fingerprint}</code>.{" "}
            </>
          )}
          Connection <code>{e.connection.id}</code> revision{" "}
          {e.connection.version}, fingerprint <code>{e.connection.hash}</code>.{" "}
          {e.encryption && (
            <>
              Encryption {e.encryption.profile}, recipient{" "}
              <code>{e.recipient_fingerprint}</code>, encryption key{" "}
              <code>{e.encryption_fingerprint}</code>.
            </>
          )}
        </li>
      ))}
    </ul>
  ) : (
    <p>No recipient catalog. Local outcomes create no delivery intent.</p>
  );
}

function selectionFor(record: CapturedRoutingRecord): CapturedRoutingSelection {
  const d = record.definition;
  return {
    collection: {
      definition_hash: d.collection.definition_hash,
      expected_revision: d.collection.revision,
    },
    workflow: d.workflow,
    expected_authority_revision: d.authority_revision,
  };
}
function proposalBody(selection: CapturedRoutingSelection, hash: string) {
  return { selection, definition_hash: hash };
}
function decisionBody(
  record: CapturedRoutingRecord,
  revision = record.revision,
) {
  return {
    definition_hash: record.definition_hash,
    expected_revision: revision,
  };
}
function storage(): Storage | undefined {
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}

export function CapturedRouting({
  api,
  session,
  view,
  metadata,
  disabled,
  onChanged,
  onError,
  onConfirmed,
}: Props) {
  const base = api.prefix + "/workflow-collections/" + view.job.id + "/routing";
  const has = (p: string) => session.identity.permissions.includes(p);
  const execute =
    has("workflow_execute") && has("read") && has("write") && has("list");
  const approve = execute && has("workflow_approve");
  const [version, setVersion] = useState(view.job.workflow_version + 1);
  const [target, setTarget] = useState<WorkflowConfiguration | null>(null);
  const [history, setHistory] = useState<
    ReturnType<typeof asCapturedRoutingHistory>
  >({ authorizations: [] });
  const [details, setDetails] = useState<CapturedRoutingMetadata | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  const [command, setCommand] = useState<Command | null>(null);
  const [busy, setBusy] = useState(false),
    [failure, setFailure] = useState("");
  const reviewHeading = useRef<HTMLHeadingElement>(null),
    planHeading = useRef<HTMLHeadingElement>(null);
  const active = busy || disabled;
  const eligible =
    view.current_authority &&
    view.job.state === "captured" &&
    view.inputs
      .filter((i) => i.first_job_id === view.job.id)
      .every(
        (i) =>
          i.state === "accepted" &&
          i.run_id === null &&
          view.local_states.find((s) => s.input_id === i.id)?.state ===
            "published",
      );
  const allReviewed =
    !!review &&
    review.preview.definition.inputs.every(
      (b) => review.checked[b.input_id] === b.plan_hash,
    );

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
  async function loadHistory(after = 0) {
    setHistory(
      await api.request(base + "?limit=20&after=" + after, {}, (v) =>
        asCapturedRoutingHistory(v, view, after, 20),
      ),
    );
  }
  async function inspect(record: Pick<CapturedRoutingRecord, "id">) {
    const d = await api.request(base + "/" + record.id + "/details", {}, (v) =>
      asCapturedRoutingMetadata(v, view, record.id),
    );
    setDetails(d);
    setReview(null);
  }
  useEffect(() => {
    void loadHistory().catch(onError);
  }, [
    api,
    view.job.id,
    metadata.authorization?.revision,
    metadata.proposal?.id,
  ]);
  useEffect(() => {
    if (review) reviewHeading.current?.focus();
  }, [review?.preview.definition_hash]);
  useEffect(() => {
    if (review?.active) planHeading.current?.focus();
  }, [review?.active?.id]);

  async function loadTarget() {
    if (!Number.isSafeInteger(version) || version < 1 || version > 2147483647)
      throw new ApiError("invalid_workflow_revision", 400);
    const w = await api.request(
      api.prefix + "/workflows/" + view.job.workflow_id + "/" + version,
      {},
      asCollectionConfiguration,
    );
    if (
      w.id !== view.job.workflow_id ||
      w.version !== version ||
      w.definition.schema_version !== 2 ||
      w.state !== "approved"
    )
      throw new ApiError("approved_routing_revision_required", 409);
    setTarget(w);
    setReview(null);
  }
  async function prepare(
    w: WorkflowConfiguration,
    record?: CapturedRoutingRecord,
  ) {
    const fresh = await api.request(
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
    const current = await api.request(base + "/current", {}, (v) =>
      asCapturedRoutingMetadata(v, fresh),
    );
    if (!record && current.proposal) {
      await inspect(current.proposal);
      onConfirmed(
        "A pending proposal already exists. Inspect it before approving or withdrawing it.",
      );
      return;
    }
    const selection: CapturedRoutingSelection = record
      ? selectionFor(record)
      : {
          collection: {
            definition_hash: fresh.job.definition_hash,
            expected_revision: fresh.job.revision,
          },
          workflow: { id: w.id, version: w.version, hash: w.definition_hash },
          expected_authority_revision: session.identity.authority_revision,
        };
    const p = await approvalPost(
      api,
      base + "/preview",
      selection,
      undefined,
      (v) =>
        asCapturedRoutingPreview(v, fresh, selection, w, current.authorization),
    );
    if (record && p.definition_hash !== record.definition_hash)
      throw new ApiError("routing_review_stale", 409);
    setReview({
      view: fresh,
      workflow: w,
      selection,
      preview: p,
      ...(record ? { record } : {}),
      checked: {},
    });
  }
  async function inspectInput(inputID: string) {
    if (!review) return;
    const frozen = review;
    const p = await approvalPost(
      api,
      base + "/inputs/" + inputID + "/preview",
      frozen.selection,
      undefined,
      (v) =>
        asCapturedRoutingInputPreview(
          v,
          inputID,
          frozen.view,
          frozen.workflow,
          frozen.preview.definition,
        ),
    );
    setReview((current) =>
      current?.preview.definition_hash === frozen.preview.definition_hash
        ? { ...current, active: { id: inputID, preview: p } }
        : current,
    );
  }
  function queue(operation: Operation, r?: CapturedRoutingRecord) {
    try {
      makeCommand(operation, r);
    } catch (error) {
      onError(error);
    }
  }
  function makeCommand(operation: Operation, r?: CapturedRoutingRecord) {
    const snapshot =
      review && (operation === "propose" || operation === "approve")
        ? structuredClone(review)
        : undefined;
    const selected = r ?? snapshot?.record;
    const record = selected ? structuredClone(selected) : undefined;
    if (
      (operation === "propose" || operation === "approve") &&
      (!snapshot || !allReviewed)
    )
      return;
    if (operation !== "propose" && !record) return;
    const hash =
      operation === "propose"
        ? snapshot!.preview.definition_hash
        : record!.definition_hash;
    const body =
      operation === "propose"
        ? proposalBody(snapshot!.selection, hash)
        : decisionBody(record!);
    const reference = routingKeyReference(
      session.identity,
      view.job.id,
      operation,
      operation === "propose" ? "" : record!.id,
      body,
    );
    const retained = retainRoutingKey(reference, storage());
    if (!retained.persisted)
      onConfirmed(
        "This browser could not retain the operation key across reload. Keep this review open until its receipt is confirmed.",
      );
    setFailure("");
    setCommand({
      operation,
      ...(record ? { record } : {}),
      ...(snapshot ? { review: snapshot } : {}),
      body,
      reference,
      key: retained.key,
      hash,
    });
  }
  async function confirm() {
    if (!command) return;
    const c = command;
    setBusy(true);
    setFailure("");
    let receiptConfirmed = false;
    try {
      const expected = {
        job: view.job.id,
        hash: c.hash,
        state: (
          {
            propose: "proposed",
            approve: "approved",
            revoke: "revoked",
            withdraw: "withdrawn",
          } as const
        )[c.operation],
        revision: c.operation === "propose" ? 1 : c.record!.revision + 1,
        ...(c.record ? { id: c.record.id, version: c.record.version } : {}),
      };
      const response = await approvalPost(
        api,
        c.operation === "propose"
          ? base + "/proposals"
          : base + "/" + c.record!.id + "/" + c.operation,
        c.body,
        c.key,
        (v) => asCapturedRoutingResult(v, expected),
      );
      receiptConfirmed = true;
      forgetRoutingKey(c.reference, storage());
      if (c.operation === "withdraw" && c.record)
        forgetRoutingKey(
          routingKeyReference(
            session.identity,
            view.job.id,
            "propose",
            "",
            proposalBody(selectionFor(c.record), c.record.definition_hash),
          ),
          storage(),
        );
      setCommand(null);
      setReview(null);
      onConfirmed(
        "Routing decision recorded: " +
          response.resource.state +
          ". Sending still uses ordinary current policy and separate file/step consent.",
      );
      await onChanged();
      await loadHistory();
      await inspect({ id: response.resource.id });
    } catch (error) {
      if (!receiptConfirmed)
        setFailure(
          "The command result was not confirmed. Retry here with the same saved key, or recover its receipt from routing history. A stale review requires a new review before approval.",
        );
      else
        onConfirmed(
          "The original decision receipt is confirmed. Refresh routing history to inspect its current state.",
        );
      onError(error);
    } finally {
      setBusy(false);
    }
  }
  async function recover(record: CapturedRoutingRecord, operation: Operation) {
    const revision = operation === "revoke" ? 2 : 1;
    const body =
      operation === "propose"
        ? proposalBody(selectionFor(record), record.definition_hash)
        : decisionBody(record, revision);
    const ref = routingKeyReference(
        session.identity,
        view.job.id,
        operation,
        operation === "propose" ? "" : record.id,
        body,
      ),
      key = savedRoutingKey(ref, storage());
    if (!key) return;
    const states: Record<Operation, CapturedRoutingState> = {
      propose: "proposed",
      approve: "approved",
      revoke: "revoked",
      withdraw: "withdrawn",
    };
    const r = await api.request(
      base + "/receipts/" + encodeURIComponent(key) + "/result",
      {},
      (v) =>
        asCapturedRoutingResult(v, {
          job: view.job.id,
          id: record.id,
          version: record.version,
          hash: record.definition_hash,
          state: states[operation],
          revision: operation === "propose" ? 1 : revision + 1,
        }),
    );
    forgetRoutingKey(ref, storage());
    onConfirmed(
      "Recovered the original " +
        operation +
        " receipt, recorded as " +
        r.resource.state +
        ". Current authority is shown separately.",
    );
    await onChanged();
    await loadHistory();
  }
  function recoveryActions(record: CapturedRoutingRecord) {
    return (["propose", "approve", "revoke", "withdraw"] as const)
      .filter((operation) => {
        const body =
          operation === "propose"
            ? proposalBody(selectionFor(record), record.definition_hash)
            : decisionBody(record, operation === "revoke" ? 2 : 1);
        return !!savedRoutingKey(
          routingKeyReference(
            session.identity,
            view.job.id,
            operation,
            operation === "propose" ? "" : record.id,
            body,
          ),
          storage(),
        );
      })
      .map((operation) => (
        <button
          key={operation}
          disabled={active}
          onClick={() => void perform(() => recover(record, operation))}
        >
          {"Recover original " + operation + " receipt"}
        </button>
      ));
  }
  const selectedRecord = details?.authorization;
  return (
    <section aria-label="Captured batch routing authorization">
      <h4>Routing authorization for this captured batch</h4>
      <p>
        A separately approved revision can decide this batch’s unassigned files.
        The original capture, source and cutoff stay fixed. An existing run or
        local outcome on an input owned by this job prevents a new routing
        authorization.
      </p>
      {metadata.authorization ? (
        <>
          <p>
            Effective decision: {metadata.authorization.state}, version{" "}
            {metadata.authorization.version}; authorization{" "}
            <code>{metadata.authorization.id}</code>.{" "}
            {metadata.current_authority
              ? "Current authority permits ordinary admission."
              : "New execution under this decision is blocked; historical plans remain readable."}
          </p>
          {metadata.workflow?.definition.program && (
            <ProgramReview program={metadata.workflow.definition.program} />
          )}
          <h5>Target recipient catalog</h5>
          <RoutingEffects effects={metadata.effects} />
          <button
            disabled={active}
            onClick={() => void perform(() => inspect(metadata.authorization!))}
          >
            Inspect effective routing decision
          </button>
          {recoveryActions(metadata.authorization)}
        </>
      ) : (
        <p>
          No effective routing decision. The job retains its original rules.
        </p>
      )}
      {metadata.proposal && (
        <p>
          Pending proposal, version {metadata.proposal.version}.{" "}
          <button
            disabled={active}
            onClick={() => void perform(() => inspect(metadata.proposal!))}
          >
            Inspect pending routing proposal
          </button>
          {recoveryActions(metadata.proposal)}
        </p>
      )}
      {execute && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void perform(loadTarget);
          }}
        >
          <label>
            Approved workflow revision{" "}
            <input
              aria-label="Approved routing workflow revision"
              type="number"
              min={1}
              max={2147483647}
              value={version}
              disabled={active}
              onChange={(e) => {
                setVersion(Number(e.target.value));
                setTarget(null);
                setReview(null);
              }}
            />
          </label>
          <p>
            Create and approve a corrected revision in Workflows, then inspect
            that revision here. It must use the same collection source.
          </p>
          <button disabled={active}>Inspect approved routing revision</button>
        </form>
      )}
      {target && (
        <>
          <p>
            Target: {target.definition.name}, revision {target.version},
            fingerprint <code>{target.definition_hash}</code>.
          </p>
          {target.definition.program && (
            <ProgramReview program={target.definition.program} />
          )}
          <button
            disabled={active || !execute || !eligible || !!metadata.proposal}
            onClick={() => void perform(() => prepare(target))}
          >
            Preview routing authorization
          </button>
        </>
      )}
      {review && (
        <section aria-label="Captured routing plan review">
          <h5 ref={reviewHeading} tabIndex={-1}>
            Review every owned input plan
          </h5>
          <p>
            Authorization fingerprint{" "}
            <code>{review.preview.definition_hash}</code>.{" "}
            {Object.keys(review.checked).length} of{" "}
            {review.preview.definition.inputs.length} input plans reviewed. This
            preview contacts no peer and reserves no work.
          </p>
          <ul>
            {review.preview.definition.inputs.map((b) => (
              <li key={b.input_id}>
                {
                  review.view.inputs.find((i) => i.id === b.input_id)
                    ?.source_name
                }
                : plan <code>{b.plan_hash}</code>.{" "}
                <button
                  disabled={active}
                  onClick={() => void perform(() => inspectInput(b.input_id))}
                >
                  {"Inspect routing plan for " +
                    review.view.inputs.find((i) => i.id === b.input_id)
                      ?.source_name}
                </button>
              </li>
            ))}
          </ul>
          {review.active && (
            <section aria-label="Exact captured input plan">
              <h6 ref={planHeading} tabIndex={-1}>
                Exact captured input plan
              </h6>
              <PlanReview plan={review.active.preview.execution_plan!} />
              <h6>Selected recipients</h6>
              <RoutingEffects
                effects={review.active.preview.selected_effects}
              />
              <label>
                <input
                  type="checkbox"
                  checked={
                    review.checked[review.active.id] ===
                    review.active.preview.execution_plan_hash
                  }
                  disabled={active}
                  onChange={(e) => {
                    const checked = { ...review.checked };
                    if (e.target.checked)
                      checked[review.active!.id] =
                        review.active!.preview.execution_plan_hash!;
                    else delete checked[review.active!.id];
                    setReview({ ...review, checked });
                  }}
                />
                I reviewed this file’s plan and selected recipients
              </label>
            </section>
          )}
          <button
            disabled={
              active || !allReviewed || (review.record ? !approve : !execute)
            }
            onClick={() => queue(review.record ? "approve" : "propose")}
          >
            {review.record
              ? "Review approving exact routing authorization"
              : "Review proposing routing authorization"}
          </button>
        </section>
      )}
      {selectedRecord && details && (
        <section aria-label="Routing decision details">
          <h5>Routing decision: {selectedRecord.state}</h5>
          <p>
            Authorization <code>{selectedRecord.id}</code>, version{" "}
            {selectedRecord.version}, revision {selectedRecord.revision},
            fingerprint <code>{selectedRecord.definition_hash}</code>. Target
            workflow revision {selectedRecord.definition.workflow.version}.
          </p>
          <RoutingEffects effects={details.effects} />
          {selectedRecord.state === "proposed" && (
            <>
              <button
                disabled={active || !approve || !eligible}
                onClick={() =>
                  void perform(() => prepare(details.workflow!, selectedRecord))
                }
              >
                Review pending routing plans for approval
              </button>
              <button
                disabled={active || !has("workflow_execute") || !has("read")}
                onClick={() => queue("withdraw", selectedRecord)}
              >
                Review withdrawing routing proposal
              </button>
            </>
          )}
          {selectedRecord.state === "approved" && (
            <button
              disabled={active || !has("workflow_approve") || !has("read")}
              onClick={() => queue("revoke", selectedRecord)}
            >
              Review revoking routing authorization
            </button>
          )}
          {recoveryActions(selectedRecord)}
        </section>
      )}
      <h5>Private routing history</h5>
      <ul>
        {history.authorizations.map((r) => (
          <li key={r.id}>
            Version {r.version}: {r.state}.{" "}
            <button
              disabled={active}
              onClick={() => void perform(() => inspect(r))}
            >
              {"Inspect routing version " + r.version}
            </button>
          </li>
        ))}
      </ul>
      <button
        disabled={active}
        onClick={() => void perform(() => loadHistory())}
      >
        Refresh routing history
      </button>
      {history.next !== undefined && (
        <button
          disabled={active}
          onClick={() => void perform(() => loadHistory(history.next!))}
        >
          Next routing history page
        </button>
      )}
      {command && (
        <ApprovalConfirm
          title={
            {
              propose: "Propose exact captured routing",
              approve: "Approve exact captured routing",
              revoke: "Revoke routing authorization",
              withdraw: "Withdraw routing proposal",
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
            Original job <code>{view.job.id}</code>. Definition fingerprint{" "}
            <code>{command.hash}</code>. Operation key{" "}
            <code>{command.key}</code>.
          </p>
          {command.review && (
            <>
              <p>
                {command.review.preview.definition.inputs.length} exact input
                plan fingerprints were individually reviewed. Target workflow
                revision {command.review.workflow.version}; fingerprint{" "}
                <code>{command.review.workflow.definition_hash}</code>.
              </p>
              <ul>
                {command.review.preview.definition.inputs.map((i) => (
                  <li key={i.input_id}>
                    File <code>{i.file_id}</code>, plan{" "}
                    <code>{i.plan_hash}</code>.
                  </li>
                ))}
              </ul>
            </>
          )}
          <p>
            {command.operation === "propose"
              ? "This creates a pending proposal. Approval remains a separate decision."
              : command.operation === "approve"
                ? "This authorizes the exact reviewed plans for ordinary admission. The original source, cutoff, current policy and separate dispatch consent remain required. No file is sent by this approval."
                : command.operation === "revoke"
                  ? "This blocks unfinished work under this authorization. It cannot recall bytes already sent and does not restore older rules."
                  : "This retires the pending proposal without changing the effective routing decision."}
          </p>
        </ApprovalConfirm>
      )}
    </section>
  );
}
