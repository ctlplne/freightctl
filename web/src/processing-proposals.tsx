import { useEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { operationKey } from "./crypto";
import { ProcessingTaskReview } from "./processing-task-review";
import {
  processingDefinition,
  processingHash,
  processingStamp,
  type ProcessingDefinition,
} from "./processing-types";
import {
  ProcessingProposalApi,
  proposalAllowed,
  proposalMutation,
  proposalRecovery,
  parseProposalRecovery,
  type ProposalMutation,
  type ProposalView,
  type ProposalSummary,
} from "./processing-proposal-api";

type Confirmation = {
  mutation: ProposalMutation;
  definition: ProcessingDefinition;
  view?: ProposalView;
  recovery: boolean;
};
export function ProcessingProposals({
  api,
  session,
  active,
  onWorkflow,
  onError,
}: {
  api: Api;
  session: Session;
  active: boolean;
  onWorkflow: (id: string, version: number, hash: string) => void;
  onError: (e: unknown) => void;
}) {
  const stamp = processingStamp(session),
    client = useMemo(() => new ProcessingProposalApi(api), [api, stamp]);
  const [definition, setDefinition] = useState<ProcessingDefinition | null>(
      null,
    ),
    [executor, setExecutor] = useState(""),
    [expires, setExpires] = useState(""),
    [proposalID, setProposalID] = useState(""),
    [row, setRow] = useState<ProposalView | null>(null),
    [rows, setRows] = useState<ProposalSummary[]>([]),
    [next, setNext] = useState(""),
    [busy, setBusy] = useState(false),
    [pending, setPending] = useState<ProposalMutation | null>(null),
    [confirmation, setConfirmation] = useState<Confirmation | null>(null),
    [receipt, setReceipt] = useState<ProposalSummary | null>(null),
    [notice, setNotice] = useState(""),
    [failure, setFailure] = useState("");
  const alive = useRef(true),
    running = useRef(false),
    pendingRef = useRef<ProposalMutation | null>(null),
    dialog = useRef<HTMLDialogElement>(null),
    heading = useRef<HTMLHeadingElement>(null),
    returnFocus = useRef<HTMLElement | null>(null);
  const current = () => alive.current && processingStamp(api.session) === stamp;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (confirmation && active) {
      returnFocus.current = document.activeElement as HTMLElement;
      dialog.current?.showModal();
      heading.current?.focus();
    } else {
      dialog.current?.close();
      returnFocus.current?.focus();
    }
  }, [confirmation, active]);
  const perform = async (fn: () => Promise<void>) => {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setFailure("");
    try {
      await fn();
    } catch (e) {
      if (current()) {
        setFailure(
          pendingRef.current
            ? "This command is unconfirmed. Keep its original key and inspect current state before retrying."
            : "The request or inspection was refused. Review the current account and proposal.",
        );
        onError(e);
      }
    } finally {
      running.current = false;
      if (current()) setBusy(false);
    }
  };
  const inspect = (id = proposalID) =>
    perform(async () => {
      setRow(null);
      const v = await client.get(id);
      if (current()) {
        setProposalID(v.proposal.id);
        setRow(v);
      }
    });
  const list = (after = "") =>
    perform(async () => {
      const page = await client.list(after);
      if (current()) {
        setRows(page.proposals);
        setNext(page.next);
      }
    });
  const prepare = async (input: ProposalMutation, recovery = false) => {
    const m = proposalMutation(input);
    if (
      pendingRef.current &&
      processingHash(pendingRef.current) !== processingHash(m)
    )
      throw new ApiError("request_recovery_required", 409);
    if (m.kind === "submit") {
      if (
        !proposalAllowed(api.session, "submit") ||
        m.body.executor_id === session.identity.actor_id
      )
        throw new ApiError("permission_denied", 403);
      if (current())
        setConfirmation({
          mutation: m,
          definition: processingDefinition(m.body.definition),
          recovery,
        });
    } else {
      setRow(null);
      const v = await client.get(m.id!);
      if (
        v.proposal.definition_hash !== m.body.definition_hash ||
        !proposalAllowed(api.session, m.kind, v) ||
        (!recovery &&
          (v.proposal.state !== "pending" ||
            v.proposal.revision !== m.body.expected_revision))
      )
        throw new ApiError("revision_conflict", 409);
      if (current()) {
        setProposalID(v.proposal.id);
        setRow(v);
        setConfirmation({
          mutation: m,
          definition: v.proposal.definition.definition,
          view: v,
          recovery,
        });
      }
    }
  };
  const propose = (kind: ProposalMutation["kind"]) =>
    perform(async () => {
      if (pendingRef.current)
        throw new ApiError("request_recovery_required", 409);
      const m =
        kind === "submit"
          ? proposalMutation({
              kind,
              key: operationKey(),
              body: { executor_id: executor, definition, expires_at: expires },
            })
          : proposalMutation({
              kind,
              id: row?.proposal.id,
              key: operationKey(),
              body: {
                definition_hash: row?.proposal.definition_hash,
                expected_revision: row?.proposal.revision,
              },
            });
      await prepare(m);
    });
  const save = (m: ProposalMutation) => {
    try {
      const text =
        JSON.stringify(proposalRecovery(m, session, location.origin)) + "\n";
      if (new TextEncoder().encode(text).length > 32 * 1024)
        throw new ApiError("invalid_processing_proposal", 400);
      const url = URL.createObjectURL(
          new Blob([text], { type: "application/json" }),
        ),
        link = document.createElement("a");
      link.href = url;
      link.download = "freightctl-processing-proposal-recovery.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (e) {
      onError(e);
    }
  };
  const importFile = (f: File, recovery: boolean) =>
    perform(async () => {
      if (f.size > 32 * 1024)
        throw new ApiError("invalid_processing_proposal", 400);
      const text = await f.text();
      if (!current()) return;
      if (recovery)
        await prepare(
          parseProposalRecovery(text, session, location.origin),
          true,
        );
      else {
        if (pendingRef.current)
          throw new ApiError("request_recovery_required", 409);
        setDefinition(null);
        setDefinition(processingDefinition(JSON.parse(text)));
        setNotice(
          "Rules loaded locally for review. No proposal was submitted.",
        );
      }
    });
  const confirm = () =>
    perform(async () => {
      if (!confirmation) return;
      const c = confirmation,
        m = proposalMutation(c.mutation);
      pendingRef.current = m;
      setPending(m);
      const result = await client.mutate(m, c.view);
      if (!current()) return;
      pendingRef.current = null;
      setPending(null);
      setConfirmation(null);
      setReceipt(result.summary);
      setProposalID(result.summary.id);
      setRow(null);
      setNotice(
        result.replayed
          ? "Recovered the original command receipt. Inspect current state separately."
          : "Command recorded. Adoption creates a draft;approval and execution remain separate.",
      );
      const latest = await client.get(result.summary.id);
      if (
        latest.proposal.definition_hash !== result.summary.definition_hash ||
        (m.kind === "submit" &&
          latest.proposal.definition.workflow_definition_hash !==
            processingHash(m.body.definition))
      )
        throw new ApiError("revision_conflict", 409);
      if (current()) setRow(latest);
    });
  if (!proposalAllowed(session)) return null;
  return (
    <section aria-label="Processing definition proposals">
      <h2>Processing definition proposals</h2>
      <p>
        Send bounded task rules to a named executor. The author needs no file
        access. The executor reviews the rules and adopts an owned
        draft;approval,input access,execution,checks and release remain
        separate.
      </p>
      {notice && <p role="status">{notice}</p>}
      {failure && <p role="alert">{failure}</p>}
      {receipt && (
        <section aria-label="Original proposal command receipt">
          <h3>Original proposal command receipt</h3>
          <p>
            Proposal <code>{receipt.id}</code>,state {receipt.state},revision{" "}
            {receipt.revision}. This records the original command and does not
            assert current approval.
          </p>
        </section>
      )}
      {pending && (
        <section
          aria-label="Unconfirmed definition proposal command"
          className="warning"
        >
          <h3>Keep the original request key</h3>
          <p>
            A lost reply may follow a committed command. Key:
            <code>{pending.key}</code>. Save this exact request before leaving.
          </p>
          <button disabled={busy} onClick={() => save(pending)}>
            Save proposal recovery
          </button>
          <button
            disabled={busy}
            onClick={() => void perform(() => prepare(pending, true))}
          >
            Review exact proposal retry
          </button>
          <button
            disabled={busy}
            onClick={() => {
              pendingRef.current = null;
              setPending(null);
              setNotice(
                "Local request cleared. This does not cancel a server command.",
              );
            }}
          >
            Clear local proposal request
          </button>
        </section>
      )}
      <section aria-label="Author a processing definition">
        <h3>Propose rules to an executor</h3>
        <p>
          Import a typed processing definition,then review every mapping and
          bound below. Importing does not read artifacts or contact an executor.
          The named executor receives the task name,reason,mappings,policy
          references and logical output path.
        </p>
        <label>
          Processing definition JSON
          <input
            type="file"
            accept="application/json,.json"
            disabled={busy || !!pending}
            onChange={(e) => {
              const f = e.target.files?.[0];
              e.target.value = "";
              if (f) void importFile(f, false);
            }}
          />
        </label>
        {definition && <ProcessingTaskReview definition={definition} />}
        <label>
          Executor actor ID
          <input
            value={executor}
            disabled={busy || !!pending}
            onChange={(e) => setExecutor(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label>
          Proposal expiry (UTC)
          <input
            value={expires}
            disabled={busy || !!pending}
            onChange={(e) => setExpires(e.target.value)}
            placeholder="2026-11-07T18:00:00Z"
            autoComplete="off"
          />
        </label>
        <button
          disabled={busy || !!pending || !definition}
          onClick={() => void propose("submit")}
        >
          Review definition disclosure
        </button>
      </section>
      <label>
        Definition proposal ID
        <input
          value={proposalID}
          disabled={busy}
          onChange={(e) => {
            setProposalID(e.target.value);
            setRow(null);
          }}
          autoComplete="off"
        />
      </label>
      <button disabled={busy} onClick={() => void inspect()}>
        Inspect definition proposal
      </button>
      <button disabled={busy} onClick={() => void list()}>
        List my definition proposals
      </button>
      <label>
        Import proposal recovery JSON
        <input
          type="file"
          accept="application/json,.json"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (f) void importFile(f, true);
          }}
        />
      </label>
      {rows.length > 0 && (
        <ul aria-label="My definition proposals">
          {rows.map((r) => (
            <li key={r.id}>
              <button disabled={busy} onClick={() => void inspect(r.id)}>
                Inspect proposal {r.id}
              </button>{" "}
              · {r.state},revision {r.revision},expires {r.expires_at}
            </li>
          ))}
        </ul>
      )}
      {next && (
        <button disabled={busy} onClick={() => void list(next)}>
          Next definition proposal page
        </button>
      )}
      {row && (
        <section aria-label="Current definition proposal">
          <h3>Current definition proposal</h3>
          <p>
            ID:<code>{row.proposal.id}</code> · {row.proposal.state},revision{" "}
            {row.proposal.revision}. Author:
            <code>{row.proposal.definition.author.actor_id}</code> · executor:
            <code>{row.proposal.definition.executor.actor_id}</code>.
          </p>
          <p>
            Proposal hash:<code>{row.proposal.definition_hash}</code> · workflow
            hash:<code>{row.proposal.definition.workflow_definition_hash}</code>
            .
          </p>
          <p>
            Participant bindings current:
            {row.participant_bindings_current_at_observation ? "yes" : "no"}.
            Expired:{row.expired_at_observation ? "yes" : "no"}. These
            observations do not establish input,approval or execution readiness.
          </p>
          <ProcessingTaskReview
            definition={row.proposal.definition.definition}
          />
          {(["adopt", "reject", "withdraw"] as const).map((kind) => (
            <button
              key={kind}
              disabled={
                busy ||
                !!pending ||
                row.proposal.state !== "pending" ||
                !proposalAllowed(session, kind, row) ||
                (kind === "adopt" &&
                  (!row.participant_bindings_current_at_observation ||
                    row.expired_at_observation))
              }
              onClick={() => void propose(kind)}
            >
              {kind === "adopt"
                ? "Review adoption into a draft"
                : kind === "reject"
                  ? "Review proposal rejection"
                  : "Review proposal withdrawal"}
            </button>
          ))}
          {row.proposal.adopted_workflow &&
            session.identity.actor_id ===
              row.proposal.definition.executor.actor_id && (
              <button
                disabled={busy || !!pending}
                onClick={() => {
                  const r = row.proposal.adopted_workflow!;
                  onWorkflow(r.id, r.version, r.hash);
                }}
              >
                Open adopted task
              </button>
            )}
        </section>
      )}
      <dialog
        ref={dialog}
        aria-labelledby="processing-proposal-confirm-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setConfirmation(null);
        }}
      >
        {confirmation && (
          <>
            {failure && <p role="alert">{failure}</p>}
            <h2
              id="processing-proposal-confirm-title"
              tabIndex={-1}
              ref={heading}
            >
              {confirmation.recovery
                ? "Review exact saved proposal request"
                : "Review definition proposal command"}
            </h2>
            <p>
              Action:{confirmation.mutation.kind} · request key:
              <code>{confirmation.mutation.key}</code>.
            </p>
            <p>
              {confirmation.mutation.kind === "submit" ? (
                <>
                  Disclose these rules to executor{" "}
                  <code>{String(confirmation.mutation.body.executor_id)}</code>{" "}
                  until {String(confirmation.mutation.body.expires_at)}.
                </>
              ) : (
                <>
                  Proposal <code>{confirmation.mutation.id}</code> · hash{" "}
                  <code>
                    {String(confirmation.mutation.body.definition_hash)}
                  </code>{" "}
                  · expected revision{" "}
                  {String(confirmation.mutation.body.expected_revision)}.
                </>
              )}
            </p>
            <ProcessingTaskReview definition={confirmation.definition} />
            <p>
              Adoption records an unapproved executor-owned draft. It grants no
              file access,execution,release or delivery. A saved retry repeats
              this exact original request. The recovery file contains private
              rules and policy references;keep it protected.
            </p>
            <button disabled={busy} onClick={() => save(confirmation.mutation)}>
              Save exact proposal request
            </button>
            <button disabled={busy} onClick={() => void confirm()}>
              Confirm exact proposal command
            </button>
            <button disabled={busy} onClick={() => setConfirmation(null)}>
              Back without sending proposal
            </button>
          </>
        )}
      </dialog>
    </section>
  );
}
