import { ProcessingTaskReview } from "./processing-task-review";
import { ProcessingReviews } from "./processing-reviews";
import type { ProcessingCatalog } from "./processing-catalog-types";
import type { OutputContractCatalog } from "./processing-output-types";
import { useEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, object, uuid, type Session } from "./types";
import {
  ProcessingApi,
  newProcessingMutation,
  processingMutation,
  processingRecovery,
  parseProcessingRecovery,
  type Mutation,
} from "./processing-api";
import {
  processingAllowed,
  processingStamp,
  processingDefinition,
  processingHash,
  type Contracts,
  type Reference,
  type Configuration,
  type Mapping,
  type ProcessingDefinition,
  type RunView,
  type WorkView,
} from "./processing-types";

const ruleLabels: Record<string, string> = {
  identity: "Keep value and type",
  text: "Write exact value as text",
  normalize_lf: "Use LF line endings (text only)",
  preserve: "Keep distinct value",
  missing: "Make missing",
  null: "Make null",
  empty: "Make empty text",
  error: "Stop this output",
};
const labels: Record<string, string> = {
  awaiting_worker: "Ready for a worker.",
  processing_in_progress: "Processing is in progress.",
  processing_failed:
    "The processing attempt failed. Inspect its original result before retrying.",
  processing_cancelled: "The processing intent was cancelled.",
  output_held:
    "Output was created and is held. It needs fresh checks and a separate release.",
  transformed_output_released:
    "The transformed output was checked and separately released. Nothing was sent onward.",
  processing_binding_changed:
    "A source check,permission,workflow or output policy changed. Review the current dependencies.",
  operator_cancelled:
    "The workflow was cancelled. Existing artifacts remain in custody.",
};
export function ProcessingWorkflows({
  api,
  session,
  active: visible,
  refresh,
  onError,
  onOutput,
}: {
  api: Api;
  session: Session;
  active: boolean;
  refresh: number;
  onError: (e: unknown) => void;
  onOutput: (id: string) => void;
}) {
  const stamp = processingStamp(session),
    client = useMemo(() => new ProcessingApi(api), [api, stamp]);
  const [source, setSource] = useState(""),
    [catalog, setCatalog] = useState<ProcessingCatalog | null>(null),
    [contracts, setContracts] = useState<Contracts | null>(null),
    [outputContracts, setOutputContracts] =
      useState<OutputContractCatalog | null>(null),
    [outputReference, setOutputReference] = useState<Reference | null>(null),
    [name, setName] = useState(""),
    [reason, setReason] = useState(""),
    [target, setTarget] = useState("/derived.json"),
    [mappings, setMappings] = useState<Mapping[]>([]),
    [reviewed, setReviewed] = useState<ProcessingDefinition | null>(null),
    [base, setBase] = useState<Configuration | null>(null);
  const [workflowID, setWorkflowID] = useState(""),
    [version, setVersion] = useState("1"),
    [configuration, setConfiguration] = useState<Configuration | null>(null),
    [configurationCurrent, setConfigurationCurrent] = useState(false),
    [runID, setRunID] = useState(""),
    [view, setView] = useState<RunView | null>(null),
    [viewCurrent, setViewCurrent] = useState(false),
    [history, setHistory] = useState<WorkView["history"]>(undefined);
  const [busy, setBusy] = useState(false),
    [pending, setPending] = useState<Mutation | null>(null),
    [review, setReview] = useState<Mutation | null>(null),
    [reviewDefinition, setReviewDefinition] =
      useState<ProcessingDefinition | null>(null),
    [notice, setNotice] = useState(""),
    [failure, setFailure] = useState("");
  const active = useRef(false),
    alive = useRef(true),
    pendingRef = useRef<Mutation | null>(null),
    dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    returnFocus = useRef<HTMLElement | null>(null);
  const current = () => alive.current && processingStamp(api.session) === stamp;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (review && visible) {
      returnFocus.current = document.activeElement as HTMLElement;
      dialog.current?.showModal();
      title.current?.focus();
    } else {
      dialog.current?.close();
      returnFocus.current?.focus();
    }
  }, [review, visible]);
  const allowed = (action: string) => processingAllowed(session, action);
  const perform = async (work: () => Promise<void>) => {
    if (active.current) return;
    active.current = true;
    setBusy(true);
    setNotice("");
    setFailure("");
    try {
      await work();
    } catch (e) {
      if (current()) {
        setFailure(
          pendingRef.current
            ? "This request is not confirmed. Keep its exact recovery key;inspect the current task or run before choosing a new action."
            : "Current metadata could not be refreshed. A recorded receipt is not a current observation.",
        );
        onError(e);
      }
    } finally {
      active.current = false;
      if (current()) setBusy(false);
    }
  };
  const loadContracts = (selected: Reference | null = outputReference) =>
    perform(async () => {
      setContracts(null);
      setReviewed(null);
      setOutputReference(selected);
      const c = await client.contracts(source, selected ?? undefined);
      if (!current()) return;
      setContracts(c);
      setReviewed(null);
      setMappings(
        c.output_policy.definition.columns.map((t) => ({
          source: c.source_policy.definition.columns.some(
            (s) => s.name === t.name,
          )
            ? t.name
            : "",
          target: t.name,
          conversion: "identity",
          missing: "preserve",
          null: "preserve",
          empty: "preserve",
        })),
      );
    });
  const definition = () => {
    if (
      !contracts ||
      !["csv", "json_records"].includes(contracts.output_policy.definition.kind)
    )
      throw new ApiError("invalid_processing_output_policy", 400);
    const output = contracts.output_policy.definition;
    return processingDefinition({
      schema_version: 3,
      name,
      steps: [],
      processing: {
        id: "project",
        kind: "records.project",
        definition: {
          schema_version: 1,
          kind: "record_projection",
          engine: "freightctl-record-projection-v1",
          source_policy_hash: contracts.source_policy.reference.hash,
          output_kind: output.kind,
          columns: mappings,
          max_bytes: output.max_bytes,
          max_record_bytes: output.max_record_bytes,
          max_rows: output.max_rows,
          timeout_seconds: output.timeout_seconds,
        },
        output_policy: contracts.output_policy.reference,
        target_path: target,
        reason,
      },
    });
  };
  const validate = () =>
    perform(async () => {
      const result = await client.review(definition(), source);
      if (current()) {
        setReviewed(result.definition);
        setNotice(
          "Review passed for this exact task and input metadata. No run or output has been created.",
        );
      }
    });
  const loadConfiguration = () =>
    perform(async () => {
      const c = await client.configuration(workflowID, Number(version));
      if (current()) {
        setConfiguration(c);
        setConfigurationCurrent(true);
      }
    });
  const loadRun = () =>
    perform(async () => {
      const r = await client.status(runID);
      if (current()) {
        setView(r);
        setViewCurrent(true);
      }
    });
  const propose = (m: Omit<Mutation, "key">) => {
    if (active.current || pendingRef.current) return;
    void perform(() => reviewRecovery(newProcessingMutation(m)));
  };
  const execute = (m: Mutation) =>
    perform(async () => {
      const frozen = processingMutation(m);
      if (
        pendingRef.current &&
        processingHash(pendingRef.current) !== processingHash(frozen)
      )
        throw new ApiError("context_changed", 409);
      pendingRef.current = frozen;
      setPending(frozen);
      const result = await client.mutate(frozen);
      if (!current()) return;
      pendingRef.current = null;
      setPending(null);
      setReview(null);
      setNotice(
        result.replayed
          ? "Recovered the original request receipt. The latest state is checked separately below."
          : "Request recorded. The latest state is checked separately below.",
      );
      if (result.configuration) {
        setWorkflowID(result.configuration.id);
        setVersion(String(result.configuration.version));
        setConfiguration(result.configuration);
        setConfigurationCurrent(false);
        const latest = await client.configuration(
          result.configuration.id,
          result.configuration.version,
        );
        if (current()) {
          setConfiguration(latest);
          setConfigurationCurrent(true);
        }
      }
      if (result.run) {
        setRunID(result.run.id);
        setView(null);
        setViewCurrent(false);
        const latest = await client.status(result.run.id);
        if (current()) {
          setView(latest);
          setViewCurrent(true);
        }
      }
      if (result.status) {
        setRunID(result.status.run.id);
        setView(result.status);
        setViewCurrent(false);
        if (result.work) setHistory(result.work.history);
        const latest = result.work
          ? result.work.status
          : await client.status(result.status.run.id);
        if (current()) {
          setView(latest);
          setViewCurrent(true);
        }
      }
    });
  const run = () =>
    perform(async () => {
      if (
        !configuration ||
        !configurationCurrent ||
        configuration.state !== "approved"
      )
        return;
      await client.review(configuration.definition, source);
      if (current()) {
        setReviewDefinition(configuration.definition);
        setReview(
          newProcessingMutation({
            kind: "run",
            body: {
              workflow: {
                id: configuration.id,
                version: configuration.version,
                hash: configuration.definition_hash,
              },
              file_id: source,
            },
          }),
        );
      }
    });
  const saveRecovery = (m: Mutation) => {
    const wire =
      JSON.stringify(processingRecovery(m, session, location.origin)) + "\n";
    if (new TextEncoder().encode(wire).length > 32 * 1024) {
      onError(new ApiError("invalid_processing_recovery", 400));
      return;
    }
    const file = new Blob([wire], { type: "application/json" }),
      url = URL.createObjectURL(file),
      link = document.createElement("a");
    link.href = url;
    link.download = "freightctl-processing-recovery.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };
  const reviewRecovery = async (m: Mutation) => {
    let definition: ProcessingDefinition;
    if (m.kind === "draft")
      definition = processingDefinition(m.body.definition);
    else if (m.kind === "approve" || m.kind === "revoke") {
      const c = await client.configuration(m.target!.id, m.target!.version!);
      if (c.definition_hash !== m.body.definition_hash)
        throw new ApiError("invalid_processing_recovery", 400);
      definition = c.definition;
    } else if (m.kind === "run") {
      const ref = object(m.body.workflow),
        c = await client.configuration(String(ref.id), Number(ref.version));
      if (c.definition_hash !== ref.hash)
        throw new ApiError("invalid_processing_recovery", 400);
      definition = c.definition;
    } else {
      const r = await client.status(m.target!.id),
        c = await client.configuration(
          r.run.workflow_id,
          r.run.workflow_version,
        );
      if (
        c.definition_hash !== r.run.workflow_hash ||
        (m.kind === "cancel" && m.body.definition_hash !== r.run.workflow_hash)
      )
        throw new ApiError("invalid_processing_recovery", 400);
      definition = c.definition;
    }
    if (current()) {
      setReviewDefinition(definition);
      setReview(m);
    }
  };
  const importRecovery = (file: File) =>
    perform(async () => {
      if (file.size > 32 * 1024)
        throw new ApiError("invalid_processing_recovery", 400);
      const m = parseProcessingRecovery(
        await file.text(),
        session,
        location.origin,
      );
      if (!current()) return;
      if (
        pendingRef.current &&
        processingHash(pendingRef.current) !== processingHash(m)
      )
        throw new ApiError("invalid_processing_recovery", 400);
      await reviewRecovery(m);
      if (current())
        setNotice(
          "Saved request loaded for review. Importing it has not executed anything.",
        );
    });
  const revise = () => {
    if (!contracts || !configuration) return;
    const p = configuration.definition.processing;
    if (
      contracts.source_policy.reference.hash !==
        p.definition.source_policy_hash ||
      processingHash(contracts.output_policy.reference) !==
        processingHash(p.output_policy)
    ) {
      onError(new ApiError("processing_contract_changed", 409));
      return;
    }
    setBase(configuration);
    setName(configuration.definition.name);
    setReason(p.reason);
    setTarget(p.target_path);
    setMappings(p.definition.columns.map((m) => ({ ...m })));
    setReviewed(null);
  };
  const output = view?.processing.output_file_id;
  useEffect(() => {
    if (visible && !active.current && !pendingRef.current) {
      if (uuid(runID)) void loadRun();
      else if (uuid(workflowID)) void loadConfiguration();
    }
  }, [refresh, visible]);
  return (
    <section aria-label="Record processing workflows">
      <p>
        Map an owned,successfully checked input into a new artifact. Its output
        stays held for fresh checks and a separate release. Receiving an
        artifact supplies no processing or onward delivery permission.
      </p>
      <section aria-label="Find processing tasks">
        <h2>Find processing tasks</h2>
        <p>
          Browse your latest task versions. Approval and output policy are
          separate observations;an exact input still needs ordinary review
          before execution.
        </p>
        <button
          disabled={busy || !allowed("configuration")}
          onClick={() =>
            void perform(async () => {
              const page = await client.catalog();
              if (current()) setCatalog(page);
            })
          }
        >
          List my processing tasks
        </button>
        {catalog && (
          <>
            {catalog.workflows.length === 0 ? (
              <p>No processing tasks were found for this account.</p>
            ) : (
              <table>
                <caption>
                  Observed task metadata;open an exact version before any action
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Task</th>
                    <th scope="col">Version and state</th>
                    <th scope="col">Approval current</th>
                    <th scope="col">Output policy current</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.workflows.map((task) => (
                    <tr key={task.id}>
                      <td>{task.name}</td>
                      <td>
                        {task.version} · {task.state}
                      </td>
                      <td>{task.approval_current ? "Yes" : "No"}</td>
                      <td>{task.output_policy_current ? "Yes" : "No"}</td>
                      <td>
                        <button
                          disabled={busy || !!pending}
                          onClick={() =>
                            void perform(async () => {
                              const cfg = await client.configuration(
                                task.id,
                                task.version,
                              );
                              if (cfg.definition_hash !== task.hash)
                                throw new ApiError("revision_conflict", 409);
                              if (current()) {
                                setWorkflowID(cfg.id);
                                setVersion(String(cfg.version));
                                setConfiguration(cfg);
                                setConfigurationCurrent(true);
                              }
                            })
                          }
                        >
                          Open task {task.id}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {catalog.next && (
              <button
                disabled={busy}
                onClick={() =>
                  void perform(async () => {
                    const page = await client.catalog(catalog.next);
                    if (current()) setCatalog(page);
                  })
                }
              >
                Next processing task page
              </button>
            )}
          </>
        )}
      </section>
      <ProcessingReviews
        api={api}
        session={session}
        active={visible}
        refresh={refresh}
        configuration={configuration}
        onWorkflow={(id, version, hash) =>
          void perform(async () => {
            const c = await client.configuration(id, version);
            if (c.definition_hash !== hash)
              throw new ApiError("revision_conflict", 409);
            if (current()) {
              setWorkflowID(id);
              setVersion(String(version));
              setConfiguration(c);
              setConfigurationCurrent(true);
            }
          })
        }
        onMutation={() => {
          setConfigurationCurrent(false);
          setViewCurrent(false);
        }}
        onError={onError}
      />
      {notice && <p role="status">{notice}</p>}
      {pending && (
        <section
          className="warning"
          aria-label="Unconfirmed processing request"
        >
          <h2>Request not yet confirmed</h2>
          <p>
            Keep its original key. A lost reply does not prove the server
            stopped. Recovery resends this exact request; it cannot select a
            different attempt.
          </p>
          <p>
            Action: {pending.kind} · key <code>{pending.key}</code>
          </p>
          <button
            disabled={busy}
            onClick={() => perform(() => reviewRecovery(pending))}
          >
            Review recovery
          </button>
          <button disabled={busy} onClick={() => saveRecovery(pending)}>
            Save recovery JSON
          </button>
          <button
            disabled={busy}
            className="secondary"
            onClick={() => {
              pendingRef.current = null;
              setPending(null);
              setReview(null);
              setNotice(
                "Saved request cleared from this page. This did not undo server work. Inspect the task or run before creating another request.",
              );
            }}
          >
            Clear saved request from this page
          </button>
        </section>
      )}
      <label>
        Open saved request JSON
        <input
          aria-label="Open processing recovery JSON"
          type="file"
          accept="application/json"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (f) void importRecovery(f);
          }}
        />
      </label>
      <fieldset disabled={busy || !!pending}>
        <legend>Input for review or execution</legend>
        <label>
          Input file revision ID
          <input
            value={source}
            onChange={(e) => {
              setSource(e.target.value);
              setContracts(null);
              setReviewed(null);
            }}
          />
        </label>
        <button
          disabled={!uuid(source) || !allowed("inspect")}
          onClick={() => void loadContracts()}
        >
          Load processing contracts
        </button>
      </fieldset>
      <fieldset disabled={busy || !!pending}>
        <legend>Output contract</legend>
        <p>
          Choose a contract registered for this producer. Incoming files keep
          their own policy. Selection reads metadata; it does not approve,
          process, release or send bytes.
        </p>
        <button
          disabled={!allowed("configuration")}
          onClick={() =>
            perform(async () => {
              const page = await client.outputContracts();
              if (current()) setOutputContracts(page);
            })
          }
        >
          Find my output contracts
        </button>
        <button
          disabled={!uuid(source) || !allowed("inspect")}
          onClick={() => void loadContracts(null)}
        >
          Use default policy for output
        </button>
        <p>
          {outputReference ? (
            <>
              Selected contract <code>{outputReference.id}</code> version{" "}
              {outputReference.version}.
            </>
          ) : (
            "Output selection uses the current default policy."
          )}
        </p>
        {outputContracts && (
          <section aria-label="Available output contracts">
            {outputContracts.policies.length === 0 ? (
              <p>
                No current CSV or JSON output contracts for this producer on
                this page. A policy administrator can register the required
                contract.
              </p>
            ) : (
              <table>
                <caption>
                  Current registered output contracts for this producer
                </caption>
                <thead>
                  <tr>
                    <th>Contract</th>
                    <th>Version</th>
                    <th>Format</th>
                    <th>Columns</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {outputContracts.policies.map((row) => (
                    <tr key={row.reference.id}>
                      <td>
                        <code>{row.reference.id}</code>
                      </td>
                      <td>{row.reference.version}</td>
                      <td>
                        {row.kind === "json_records" ? "JSON records" : "CSV"}
                      </td>
                      <td>{row.column_count}</td>
                      <td>
                        <button
                          disabled={!uuid(source) || !allowed("inspect")}
                          onClick={() => void loadContracts(row.reference)}
                        >
                          Use this output contract
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {outputContracts.next && (
              <button
                disabled={!allowed("configuration")}
                onClick={() =>
                  perform(async () => {
                    const page = await client.outputContracts(
                      outputContracts.next,
                    );
                    if (current()) setOutputContracts(page);
                  })
                }
              >
                Next output contracts
              </button>
            )}
          </section>
        )}
      </fieldset>
      {contracts && (
        <section aria-label="Processing contracts">
          <h2>Exact input and output contracts</h2>
          <p>
            Input <code>{contracts.source.file_revision_id}</code> ·{" "}
            {contracts.source.size_bytes} bytes ·{" "}
            <code>{contracts.source.sha256}</code>
          </p>
          <p>
            Input policy version {contracts.source_policy.reference.version} (
            {contracts.source_policy.state}) · output policy version{" "}
            {contracts.output_policy.reference.version} (
            {contracts.output_policy.definition.kind}).
          </p>
          {contracts.output_binding && (
            <p>
              This output contract is pinned to your current identity,
              permission revision and namespace. The input policy is unchanged.
            </p>
          )}
          {contracts.source_proof_valid_until && (
            <p>
              Original source protection proof expires at{" "}
              {contracts.source_proof_valid_until}.
            </p>
          )}
          {!["csv", "json_records"].includes(
            contracts.output_policy.definition.kind,
          ) ? (
            <p role="alert">
              The current output policy must describe CSV or JSON records for
              this processing engine. Ask a policy administrator to configure
              the required output contract.
            </p>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void validate();
              }}
              onChange={() => setReviewed(null)}
            >
              <fieldset disabled={busy || !!pending || !allowed("manage")}>
                <legend>
                  {base
                    ? `Revise task ${base.id},version ${base.version}`
                    : "Create a processing task"}
                </legend>
                <label>
                  Task name
                  <input
                    value={name}
                    maxLength={256}
                    onChange={(e) => setName(e.target.value)}
                  />
                </label>
                <label>
                  Reason
                  <textarea
                    value={reason}
                    maxLength={1024}
                    onChange={(e) => setReason(e.target.value)}
                  />
                </label>
                <label>
                  Output logical path (optional)
                  <input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  />
                </label>
                <p>
                  The output policy fixes column order and types. Choose the
                  input source and explicit presence/conversion rules for each
                  output column. CSV cannot preserve missing or null values;
                  choose an explicit conversion or keep JSON output.
                </p>
                <div className="table-scroll">
                  <table>
                    <caption>Reviewed column mapping</caption>
                    <thead>
                      <tr>
                        <th>Output</th>
                        <th>Input</th>
                        <th>Conversion</th>
                        <th>Missing</th>
                        <th>Null</th>
                        <th>Empty text</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mappings.map((m, index) => (
                        <tr key={index}>
                          <th scope="row">
                            {m.target} (
                            {
                              contracts.output_policy.definition.columns[index]
                                ?.type
                            }
                            )
                          </th>
                          <td>
                            <select
                              aria-label={`Input column for ${m.target}`}
                              value={m.source}
                              onChange={(e) =>
                                setMappings((rows) =>
                                  rows.map((r, i) =>
                                    i === index
                                      ? { ...r, source: e.target.value }
                                      : r,
                                  ),
                                )
                              }
                            >
                              <option value="">Choose input</option>
                              {contracts.source_policy.definition.columns.map(
                                (c) => (
                                  <option key={c.name} value={c.name}>
                                    {c.name} ({c.type})
                                  </option>
                                ),
                              )}
                            </select>
                          </td>
                          {(
                            ["conversion", "missing", "null", "empty"] as const
                          ).map((field) => (
                            <td key={field}>
                              <select
                                aria-label={`${field} rule for ${m.target}`}
                                value={m[field]}
                                onChange={(e) =>
                                  setMappings((rows) =>
                                    rows.map((r, i) =>
                                      i === index
                                        ? { ...r, [field]: e.target.value }
                                        : r,
                                    ),
                                  )
                                }
                              >
                                {(field === "conversion"
                                  ? ["identity", "text", "normalize_lf"]
                                  : field === "missing"
                                    ? ["preserve", "empty", "null", "error"]
                                    : field === "null"
                                      ? [
                                          "preserve",
                                          "empty",
                                          "missing",
                                          "error",
                                        ]
                                      : ["preserve", "missing", "null", "error"]
                                ).map((v) => (
                                  <option key={v} value={v}>
                                    {ruleLabels[v]}
                                  </option>
                                ))}
                              </select>
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p>
                  Policy bounds: {contracts.output_policy.definition.max_bytes}{" "}
                  bytes,{contracts.output_policy.definition.max_rows} rows,
                  {contracts.output_policy.definition.max_record_bytes} bytes
                  per record,
                  {contracts.output_policy.definition.timeout_seconds} seconds.
                </p>
                <button type="submit">Review processing task</button>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => {
                    setBase(null);
                    setReviewed(null);
                  }}
                >
                  Use a new task family
                </button>
              </fieldset>
              {reviewed && (
                <section aria-label="Reviewed processing task">
                  <h3>Task review passed</h3>
                  <p>
                    Exact task SHA256 <code>{processingHash(reviewed)}</code>
                  </p>
                  <p>
                    This saves rules only. Execution selects an owned input
                    matching the approved contract and rechecks its current
                    protections.
                  </p>
                  <button
                    type="button"
                    disabled={busy || !!pending || !allowed("manage")}
                    onClick={() =>
                      propose({
                        kind: "draft",
                        body: {
                          ...(base ? { workflow_id: base.id } : {}),
                          expected_version: base?.version ?? 0,
                          definition: reviewed,
                        },
                      })
                    }
                  >
                    Review saving this draft
                  </button>
                </section>
              )}
            </form>
          )}
        </section>
      )}
      <fieldset disabled={busy || !!pending}>
        <legend>Open a task revision</legend>
        <label>
          Workflow ID
          <input
            value={workflowID}
            onChange={(e) => {
              setWorkflowID(e.target.value);
              setConfiguration(null);
              setConfigurationCurrent(false);
            }}
          />
        </label>
        <label>
          Version
          <input
            type="number"
            min="1"
            value={version}
            onChange={(e) => {
              setVersion(e.target.value);
              setConfiguration(null);
              setConfigurationCurrent(false);
            }}
          />
        </label>
        <button
          disabled={!uuid(workflowID) || !allowed("configuration")}
          onClick={loadConfiguration}
        >
          Load task revision
        </button>
      </fieldset>
      {configuration && (
        <section aria-label="Processing task revision">
          <h2>{configuration.definition.name}</h2>
          <p>
            {configurationCurrent
              ? "Current task revision"
              : "Original receipt;current state not checked"}
            : {configuration.state} · version {configuration.version} · revision{" "}
            {configuration.revision}
          </p>
          <p>
            Task SHA256 <code>{configuration.definition_hash}</code>
          </p>
          <p>
            Source contract{" "}
            <code>
              {
                configuration.definition.processing.definition
                  .source_policy_hash
              }
            </code>{" "}
            · output policy{" "}
            <code>{configuration.definition.processing.output_policy.id}</code>{" "}
            version {configuration.definition.processing.output_policy.version}{" "}
            ·{" "}
            <code>
              {configuration.definition.processing.output_policy.hash}
            </code>
          </p>
          <p>
            Reason: {configuration.definition.processing.reason} · logical
            output:{" "}
            {configuration.definition.processing.target_path ||
              "unpublished custody"}
          </p>
          <ul>
            {configuration.definition.processing.definition.columns.map(
              (m, i) => (
                <li key={i}>
                  {m.source} → {m.target}; {m.conversion}; missing:{m.missing}
                  ,null:{m.null},empty:{m.empty}
                </li>
              ),
            )}
          </ul>
          <p>
            Approval permits this bounded mapping only. It grants no
            release,forwarding or arbitrary code execution.
          </p>
          <button
            disabled={
              busy ||
              !!pending ||
              !configurationCurrent ||
              !allowed("approve") ||
              configuration.state !== "draft"
            }
            onClick={() =>
              propose({
                kind: "approve",
                target: {
                  id: configuration.id,
                  version: configuration.version,
                },
                body: {
                  definition_hash: configuration.definition_hash,
                  expected_revision: configuration.revision,
                },
              })
            }
          >
            Review approving this task
          </button>
          <button
            disabled={
              busy ||
              !!pending ||
              !configurationCurrent ||
              !allowed("approve") ||
              configuration.state !== "approved"
            }
            onClick={() =>
              propose({
                kind: "revoke",
                target: {
                  id: configuration.id,
                  version: configuration.version,
                },
                body: {
                  definition_hash: configuration.definition_hash,
                  expected_revision: configuration.revision,
                },
              })
            }
          >
            Review revocation
          </button>
          <button
            disabled={busy || !!pending || !contracts || !allowed("manage")}
            onClick={revise}
          >
            Edit as a new revision
          </button>
          <button
            disabled={
              busy ||
              !!pending ||
              !configurationCurrent ||
              !allowed("execute") ||
              configuration.state !== "approved" ||
              configuration.approval_authority !==
                session.identity.authority_revision ||
              !uuid(source)
            }
            onClick={run}
          >
            Review running on this input
          </button>
        </section>
      )}
      <fieldset disabled={busy || !!pending}>
        <legend>Open a processing run</legend>
        <label>
          Run ID
          <input
            value={runID}
            onChange={(e) => {
              setRunID(e.target.value);
              setView(null);
              setViewCurrent(false);
              setHistory(undefined);
            }}
          />
        </label>
        <button
          disabled={!uuid(runID) || !allowed("inspect")}
          onClick={loadRun}
        >
          Load processing run
        </button>
      </fieldset>
      {view && (
        <section aria-label="Processing run outcome">
          <h2>
            Processing run <code>{view.run.id}</code>
          </h2>
          <p>
            {viewCurrent
              ? "Current observation"
              : "Original result;current state not checked"}
            : {labels[view.observed_reason]}
          </p>
          <p>
            Input <code>{view.run.file_id}</code> · intent{" "}
            <code>{view.processing.projection_id}</code> · attempts{" "}
            {view.processing.attempts}/3.
          </p>
          {history && (
            <p>
              Original work command: {history.state},attempt {history.attempts}.
              The current intent observation above can differ after a later
              retry.
            </p>
          )}
          {output && (
            <p>
              Output file revision <code>{output}</code> ·{" "}
              {view.processing.released
                ? "separately released"
                : "held;fresh checks and release still required"}
              .
            </p>
          )}
          <button
            disabled={
              busy ||
              !!pending ||
              !viewCurrent ||
              !allowed("execute") ||
              ["cancelled", "succeeded"].includes(view.run.state)
            }
            onClick={() =>
              propose({ kind: "work", target: { id: view.run.id }, body: {} })
            }
          >
            Review working this run
          </button>
          <button
            disabled={busy || !!pending || !allowed("execute")}
            onClick={() =>
              propose({
                kind: "refresh",
                target: { id: view.run.id },
                body: {},
              })
            }
          >
            Review recording current outcome
          </button>
          <button
            disabled={
              busy ||
              !!pending ||
              !viewCurrent ||
              !allowed("execute") ||
              ["cancelled", "succeeded"].includes(view.run.state)
            }
            onClick={() =>
              propose({
                kind: "cancel",
                target: { id: view.run.id },
                body: {
                  definition_hash: view.run.workflow_hash,
                  expected_revision: view.run.revision,
                },
              })
            }
          >
            Review cancellation
          </button>
          {output && (
            <button
              disabled={busy || !!pending}
              onClick={() => onOutput(output)}
            >
              Open output checks
            </button>
          )}
          <p>
            This workflow creates no delivery intent. Sending a released output
            onward requires its own current permission and approved delivery
            workflow.
          </p>
        </section>
      )}
      <dialog
        ref={dialog}
        aria-labelledby="processing-action-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setReview(null);
        }}
      >
        <h2 id="processing-action-title" ref={title} tabIndex={-1}>
          Review processing action
        </h2>
        {failure && <p role="alert">{failure}</p>}
        {review && (
          <>
            <p>
              Action: <strong>{review.kind}</strong>
            </p>
            <p>
              Original request key <code>{review.key}</code>
            </p>
            <p>
              Exact request SHA256 <code>{processingHash(review)}</code>
            </p>
            {review.target && (
              <p>
                Target <code>{review.target.id}</code>
                {review.target.version
                  ? ` version ${review.target.version}`
                  : ""}
              </p>
            )}
            {review.kind === "draft" && (
              <p>This creates an unapproved draft.</p>
            )}
            {reviewDefinition && (
              <ProcessingTaskReview definition={reviewDefinition} />
            )}
            {review.kind === "run" && (
              <p>
                Input <code>{String(review.body.file_id)}</code>. This records
                one processing intent;it does not release or deliver bytes.
              </p>
            )}
            {["approve", "revoke", "cancel"].includes(review.kind) && (
              <p>
                Exact revision {String(review.body.expected_revision)} ·
                definition <code>{String(review.body.definition_hash)}</code>.
              </p>
            )}
            <p>
              Existing permissions and revisions are checked again on the
              server. A recovery file is data,not permission.
            </p>
            <button disabled={busy} onClick={() => execute(review)}>
              Confirm this exact action
            </button>
            <button disabled={busy} onClick={() => saveRecovery(review)}>
              Save recovery JSON
            </button>
            <button
              disabled={busy}
              className="secondary"
              onClick={() => setReview(null)}
            >
              Back
            </button>
          </>
        )}
      </dialog>
    </section>
  );
}
