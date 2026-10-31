import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Api } from "./api";
import { ApiError, type Session } from "./types";
import { operationKey } from "./crypto";
import { ProgramEditor, ProgramReview, PlanReview } from "./programs";
import { CapturedRouting, RoutingEffects } from "./collection-routing";
import {
  asCapturedRoutingMetadata,
  type CapturedRoutingMetadata,
} from "./collection-routing-types";
import type { Program } from "./programs-types";
import { ApprovalConfirm, approvalPost } from "./onboarding-approvals";
import {
  asSchedulableWorkflows,
  type Reference,
  type ScheduleEffect,
  type ScheduledRun,
} from "./schedules-types";
import {
  collectionContract,
  scheduledCollectionContract,
  asCollectionWorkflow,
  asCollectionWorkflowPreview,
  asCollectionConfiguration,
  asCollectionConfigurationResult,
  asCollectionConnections,
  asCollectionConnection,
  asCollectionPreview,
  asCollectionResult,
  asCollectionView,
  asCollectionPage,
  asCollectedRun,
  asCollectedWork,
  asCollectionRunPreview,
  asWorkflowDifference,
  type WorkflowDifference,
  type CollectionRunContext,
  type CollectionRunPreview,
  type CollectionWorkflow,
  type WorkflowStep,
  type WorkflowConfiguration,
  type CollectionConnection,
  type CollectionDefinition,
  type CollectionPreview,
  type CollectionSelection,
  type CollectionView,
  type CollectionInput,
} from "./collections-types";

type Props = {
  api: Api;
  session: Session;
  refresh: number;
  onError: (e: unknown) => void;
  onConfirmed: (message: string) => void;
  jobID?: string;
  jobHash?: string;
};
type WorkflowPreview = ReturnType<typeof asCollectionWorkflowPreview>;
type Form = {
  name: string;
  source: string;
  manifest: string;
  scheduled: boolean;
  directory: string;
  maxFiles: number;
  maxFile: number;
  maxTotal: number;
  program: Program | undefined;
  steps: {
    id: string;
    connection: string;
    filename: string;
    encryption?: WorkflowStep["encryption"];
  }[];
};
type Pending =
  | {
      kind: "draft";
      preview: WorkflowPreview;
      family?: { id: string; version: number };
      key: string;
    }
  | {
      kind: "approve";
      configuration: WorkflowConfiguration;
      preview: WorkflowPreview;
      key: string;
      difference?: WorkflowDifference;
    }
  | {
      kind: "revoke";
      configuration: WorkflowConfiguration;
      preview: WorkflowPreview;
      key: string;
    }
  | {
      kind: "start";
      preview: CollectionPreview;
      selection: CollectionSelection;
      workflow: WorkflowConfiguration;
      key: string;
    }
  | {
      kind: "work" | "refresh" | "cancel";
      view: CollectionView;
      key: string;
      workflow?: WorkflowConfiguration;
      routing?: CapturedRoutingMetadata;
    }
  | {
      kind: "send";
      input: CollectionInput;
      definition: CollectionDefinition;
      run: ScheduledRun;
      context: CollectionRunContext;
      key: string;
    };
const connectionKey = (c: { id: string; version: number }) =>
  c.id + ":" + c.version;
const reference = (c: CollectionConnection): Reference => ({
  id: c.id,
  version: c.version,
  hash: c.definition_hash,
});
const keyReference = (r: Reference) => r.id + ":" + r.version;
const initial = (maxFile: number): Form => ({
  name: "",
  source: "",
  manifest: "settlement.ready.json",
  scheduled: false,
  directory: "",
  maxFiles: 4,
  maxFile: Math.min(maxFile, 1048576),
  maxTotal: Math.min(maxFile, 1048576) * 4,
  steps: [],
  program: undefined,
});
function Field({
  label,
  children,
}: {
  label: string;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      {children(id)}
    </div>
  );
}
function ReceiverEffects({ effects }: { effects: ScheduleEffect[] }) {
  return effects.length ? (
    <ol>
      {effects.map((e) => (
        <li key={e.step_id}>
          <strong>{e.step_id}</strong>: SFTP <code>{e.address}</code>, folder{" "}
          <code>{e.directory}</code>, final name{" "}
          <code>{e.final_name_pattern}</code>. Pinned host{" "}
          <code>{e.host_fingerprint}</code>.{" "}
          {e.encryption ? (
            <>
              Recipient encryption {e.encryption.profile}, fingerprint{" "}
              <code>{e.recipient_fingerprint}</code>.
            </>
          ) : (
            "No recipient encryption is configured for this step."
          )}
        </li>
      ))}
    </ol>
  ) : (
    <p>Local collection only. This workflow has no outgoing receiver.</p>
  );
}
function SourceReview({
  source,
  connection,
  effects,
}: {
  source: CollectionWorkflow["source"];
  connection: CollectionConnection;
  effects: ScheduleEffect[];
}) {
  return (
    <>
      <p>
        Read <code>{source.manifest}</code> from{" "}
        <code>
          {connection.user}@{connection.address}
        </code>
        , folder <code>{connection.directory}</code>. The producer must publish
        its ready manifest after finishing the named immutable files. Each file
        must match the manifest’s exact length and SHA-256 digest.
      </p>
      <p>
        Copy into virtual folder <code>{source.target_directory}</code> using{" "}
        <code>&lt;SHA-256&gt;-&lt;source name&gt;</code>. The batch stays
        unavailable until every source file has a durable local receipt.
        Ordinary intake checks still apply afterward. The source files remain in
        place.
      </p>
      <p>
        At most {source.max_files} files,{" "}
        {source.max_file_bytes.toLocaleString()} bytes per file and{" "}
        {source.max_total_bytes.toLocaleString()} bytes per batch. Pinned source
        host <code>{connection.host_fingerprint}</code>; client identity{" "}
        <code>{connection.key_fingerprint}</code>.
      </p>
      <ReceiverEffects effects={effects} />
    </>
  );
}
function DifferenceReview({
  difference: d,
}: {
  difference: WorkflowDifference;
}) {
  return (
    <section aria-label="Workflow changes since previous version">
      <h4>
        Changes from version {d.from_version} to {d.to_version}
      </h4>
      <p>
        Name: {d.name_changed ? "changed" : "unchanged"}. Catalog order:{" "}
        {d.order_changed ? "changed" : "unchanged"}. Source contract:{" "}
        {d.source_changed ? "changed" : "unchanged"}. Routing decisions:{" "}
        {d.program_changed ? "changed" : "unchanged"}.
      </p>
      <p>
        Added steps: {d.added_steps.join(", ") || "none"}. Removed steps:{" "}
        {d.removed_steps.join(", ") || "none"}. Changed delivery templates:{" "}
        {d.changed_steps.join(", ") || "none"}.
      </p>
      <details>
        <summary>Exact previous definition</summary>
        <pre>{JSON.stringify(d.before, null, 2)}</pre>
        <p>
          Previous definition SHA-256 <code>{d.from_hash}</code>.
        </p>
      </details>
      <p>
        Approve the current definition only after reviewing its source,
        potential recipients and routing decisions above.
      </p>
    </section>
  );
}
const reasons: Record<string, string> = {
  awaiting_collection_worker:
    "Queued metadata only. A separately confirmed worker can read the approved source.",
  source_read_pending:
    "The worker is reading the approved source under its recorded lease.",
  producer_batch_bound:
    "The producer manifest is fixed for this job. Its named revisions are being verified.",
  batch_captured:
    "Every source file has a durable local receipt. Intake checks and downstream sending approvals still apply.",
  source_connection_unavailable:
    "The source connection, pinned identity or credentials could not be confirmed.",
  source_manifest_unavailable:
    "The ready manifest was not readable. The original source rule and cutoff remain in place.",
  producer_manifest_invalid:
    "The producer manifest did not match the approved completion contract. Review its names, sizes and digests.",
  producer_batch_binding_refused:
    "The batch ID conflicts with an earlier claim, or an existing input prevents admission. Inspect the original job.",
  input_claim_owned_by_prior_job:
    "An earlier job owns this unfinished input. Follow that original job’s recovery history.",
  source_file_verification_or_capacity_failed:
    "A file read, promised digest or custody capacity check failed. Accepted siblings stay unavailable until the batch completes.",
  collection_authority_or_lease_changed:
    "The worker lost its current authority, lease or cutoff. It cannot accept new input.",
  input_fence_or_binding_changed:
    "Another worker or a changed input binding prevents this attempt from accepting bytes.",
  local_acceptance_not_confirmed:
    "Sealed bytes have no confirmed acceptance for this attempt. A retry checks the same job and its existing receipts.",
  collection_capture_not_confirmed:
    "The batch’s final capture or publication was not confirmed. Inspect durable inputs before retrying.",
  custody_capacity_unavailable:
    "Local custody capacity is busy or full. The job keeps its original input claims.",
  operator_cancelled:
    "Further work under this job is stopped. Already captured local bytes and receiver copies remain.",
};
const labels: Record<string, string> = {
  pending: "Waiting for durable acceptance",
  awaiting_batch_capture: "Held until the batch is complete",
  held_or_unavailable: "Held by policy or unavailable",
  unpublished_or_removed: "Local path changed or removed",
  published: "Published under current file policy",
};

export function Collections({
  api,
  session,
  refresh,
  onError,
  onConfirmed,
  jobID,
  jobHash,
}: Props) {
  const has = (p: string) => session.identity.permissions.includes(p),
    authority = session.identity.authority_revision;
  const canManage =
      !jobID && has("workflow_manage") && has("write") && has("list"),
    canApprove = has("workflow_approve") && has("write") && has("list"),
    canExecute =
      has("workflow_execute") && has("read") && has("write") && has("list");
  const [form, setForm] = useState<Form>(() =>
      initial(session.limits.max_file_bytes),
    ),
    [family, setFamily] = useState<
      { id: string; version: number } | undefined
    >(),
    [connections, setConnections] = useState<CollectionConnection[]>([]),
    [connectionNext, setConnectionNext] = useState<string | undefined>();
  const [choices, setChoices] = useState<
      ReturnType<typeof asSchedulableWorkflows>
    >({ workflows: [] }),
    [chosen, setChosen] = useState<WorkflowConfiguration | null>(null),
    [chosenDifference, setChosenDifference] =
      useState<WorkflowDifference | null>(null),
    [chosenPreview, setChosenPreview] = useState<WorkflowPreview | null>(null),
    [workflowPreview, setWorkflowPreview] = useState<WorkflowPreview | null>(
      null,
    ),
    [timeout, setTimeoutSeconds] = useState(120),
    [preview, setPreview] = useState<{
      value: CollectionPreview;
      selection: CollectionSelection;
    } | null>(null);
  const [page, setPage] = useState<ReturnType<typeof asCollectionPage>>({
      jobs: [],
    }),
    [selected, setSelected] = useState<CollectionView | null>(null),
    [selectedWorkflow, setSelectedWorkflow] =
      useState<WorkflowConfiguration | null>(null),
    [selectedRouting, setSelectedRouting] =
      useState<CapturedRoutingMetadata | null>(null),
    [routingPreview, setRoutingPreview] = useState<CollectionRunPreview | null>(
      null,
    ),
    [run, setRun] = useState<{
      input: CollectionInput;
      definition: CollectionDefinition;
      status: ScheduledRun;
      context: CollectionRunContext;
    } | null>(null),
    [pending, setPending] = useState<Pending | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [notice, setNotice] = useState("");
  const heading = useRef<HTMLHeadingElement>(null),
    formHeading = useRef<HTMLHeadingElement>(null),
    previewHeading = useRef<HTMLHeadingElement>(null),
    routingHeading = useRef<HTMLHeadingElement>(null),
    runHeading = useRef<HTMLHeadingElement>(null);
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }
  function confirmed(message: string) {
    setNotice(message);
    onConfirmed(message);
  }
  async function list(after = "") {
    if (jobID) return;
    setPage(
      await api.request(
        api.prefix +
          "/workflow-collections?limit=20" +
          (after ? "&after=" + after : ""),
        {},
        asCollectionPage,
      ),
    );
  }
  async function workflowChoices(after = "") {
    setChoices(
      await api.request(
        api.prefix +
          "/workflow-collection-workflows?limit=20" +
          (after ? "&after=" + after : ""),
        {},
        asSchedulableWorkflows,
      ),
    );
  }
  async function connectionChoices(after = "") {
    const p = await api.request(
      api.prefix +
        "/workflow-collection-connections?limit=20" +
        (after ? "&after=" + after : ""),
      {},
      asCollectionConnections,
    );
    setConnections((old) => [
      ...new Map(
        [...old, ...p.connections].map((c) => [connectionKey(c), c]),
      ).values(),
    ]);
    setConnectionNext(p.next);
  }
  async function inspect(id: string, hash?: string) {
    const view = await api.request(
      api.prefix + "/workflow-collections/" + id,
      {},
      (v) => asCollectionView(v, id, authority, hash),
    );
    const workflow = await api.request(
      api.prefix +
        "/workflows/" +
        view.job.workflow_id +
        "/" +
        view.job.workflow_version,
      {},
      (v) => asCollectionConfiguration(v, view.job.definition.workflow),
    );
    const routing = await api.request(
      api.prefix + "/workflow-collections/" + id + "/routing/current",
      {},
      (v) => asCapturedRoutingMetadata(v, view),
    );
    setSelected(view);
    setSelectedWorkflow(workflow);
    setSelectedRouting(routing);
    setRoutingPreview(null);
    setRun(null);
  }
  async function loadWorkflow(r: Reference) {
    const c = await api.request(
      api.prefix + "/workflows/" + r.id + "/" + r.version,
      {},
      (v) => asCollectionConfiguration(v, r),
    );
    const difference =
      c.version > 1
        ? await api.request(
            api.prefix +
              "/workflows/" +
              c.id +
              "/" +
              c.version +
              "/diff?against=" +
              (c.version - 1),
            {},
            (v) => asWorkflowDifference(v, c),
          )
        : null;
    setChosen(c);
    setChosenDifference(difference);
    setPreview(null);
    setChosenPreview(null);
    if (has("write") && has("list"))
      setChosenPreview(
        await approvalPost(
          api,
          api.prefix + "/workflows/validate",
          { definition: c.definition },
          undefined,
          (v) => asCollectionWorkflowPreview(v, c.definition),
        ),
      );
  }
  useEffect(() => {
    if (jobID) {
      void inspect(jobID, jobHash).catch(onError);
      return;
    }
    void list().catch(onError);
    void workflowChoices().catch(onError);
    void connectionChoices().catch(onError);
  }, [api, refresh, jobID, jobHash]);
  useEffect(() => {
    if (selected) heading.current?.focus();
  }, [selected?.job.id, selected?.job.revision]);
  useEffect(() => {
    if (preview || workflowPreview) previewHeading.current?.focus();
  }, [preview, workflowPreview]);
  useEffect(() => {
    if (run) runHeading.current?.focus();
  }, [run]);
  useEffect(() => {
    if (routingPreview) routingHeading.current?.focus();
  }, [routingPreview]);
  function edit(patch: Partial<Form>) {
    setForm((v) => ({ ...v, ...patch }));
    setWorkflowPreview(null);
  }
  function stepEdit(index: number, patch: Partial<Form["steps"][number]>) {
    edit({
      steps: form.steps.map((s, i) => (i === index ? { ...s, ...patch } : s)),
    });
  }
  function selectedConnection(value: string): CollectionConnection {
    const c = connections.find((c) => connectionKey(c) === value);
    if (!c || c.state !== "active")
      throw new ApiError("invalid_workflow_collection", 400);
    return c;
  }
  function definition(): CollectionWorkflow {
    const source = selectedConnection(form.source);
    return asCollectionWorkflow({
      schema_version: form.program ? 2 : 1,
      name: form.name.normalize("NFC"),
      steps: form.steps.map((s) => ({
        id: s.id,
        kind: "sftp.deliver",
        connection: reference(selectedConnection(s.connection)),
        filename: s.filename,
        ...(s.encryption ? { encryption: s.encryption } : {}),
      })),
      source: {
        kind: "sftp.collect",
        connection: reference(source),
        manifest: form.manifest,
        target_directory: form.directory,
        completion_contract: form.scheduled
          ? scheduledCollectionContract
          : collectionContract,
        max_files: form.maxFiles,
        max_file_bytes: form.maxFile,
        max_total_bytes: form.maxTotal,
      },
      ...(form.program ? { program: form.program } : {}),
    });
  }
  async function editWorkflow(c: WorkflowConfiguration) {
    const refs = [
      c.definition.source.connection,
      ...c.definition.steps.map((s) => s.connection),
    ];
    const extra: CollectionConnection[] = [];
    for (const r of refs) {
      if (!connections.some((v) => v.id === r.id && v.version === r.version))
        extra.push(
          await api.request(
            api.prefix + "/connections/" + r.id + "/" + r.version,
            {},
            asCollectionConnection,
          ),
        );
    }
    setConnections((old) => [
      ...new Map([...old, ...extra].map((c) => [connectionKey(c), c])).values(),
    ]);
    const d = c.definition;
    setFamily({ id: c.id, version: c.version });
    setForm({
      name: d.name,
      source: keyReference(d.source.connection),
      manifest: d.source.manifest,
      scheduled: d.source.completion_contract === scheduledCollectionContract,
      directory: d.source.target_directory,
      maxFiles: d.source.max_files,
      maxFile: d.source.max_file_bytes,
      maxTotal: d.source.max_total_bytes,
      program: d.program ? structuredClone(d.program) : undefined,
      steps: d.steps.map((s) => ({
        id: s.id,
        connection: keyReference(s.connection),
        filename: s.filename,
        ...(s.encryption ? { encryption: s.encryption } : {}),
      })),
    });
    setWorkflowPreview(null);
    requestAnimationFrame(() => formHeading.current?.focus());
  }
  async function inspectRun(input: CollectionInput) {
    if (!selected || !input.run_id) return;
    const context = await inputContext(input),
      d = context.job.definition;
    const status = await api.request(
      api.prefix + "/workflow-runs/" + input.run_id,
      {},
      (v) => asCollectedRun(v, input, d, context),
    );
    setRun({ input, definition: d, status, context });
  }
  async function previewInput(input: CollectionInput) {
    if (!selected || !input.file_id) return;
    const context = await inputContext(input),
      d = context.job.definition;
    const preview = await approvalPost(
      api,
      api.prefix + "/workflow-runs/preview",
      {
        workflow:
          context.routing?.metadata.authorization?.definition.workflow ??
          d.workflow,
        file_id: input.file_id,
      },
      undefined,
      (v) => asCollectionRunPreview(v, input, d, context),
    );
    setRoutingPreview(preview);
  }
  async function inputContext(
    input: CollectionInput,
  ): Promise<CollectionRunContext> {
    const view = await api.request(
      api.prefix + "/workflow-collections/" + input.first_job_id,
      {},
      (v) => asCollectionView(v, input.first_job_id, authority),
    );
    const job = view.job,
      d = job.definition;
    const workflow = await api.request(
      api.prefix + "/workflows/" + d.workflow.id + "/" + d.workflow.version,
      {},
      (v) => asCollectionConfiguration(v, d.workflow),
    );
    const metadata = await api.request(
      api.prefix + "/workflow-collections/" + job.id + "/routing/current",
      {},
      (v) => asCapturedRoutingMetadata(v, view),
    );
    return {
      workflow,
      job,
      ...(metadata.authorization ? { routing: { view, metadata } } : {}),
    };
  }
  async function confirm() {
    if (!pending) return;
    const p = pending;
    setBusy(true);
    setFailure("");
    try {
      if (p.kind === "draft") {
        const body = {
          ...(p.family ? { workflow_id: p.family.id } : {}),
          expected_version: p.family?.version ?? 0,
          definition: p.preview.definition,
        };
        const c = await approvalPost(
          api,
          api.prefix + "/workflows/drafts",
          body,
          p.key,
          (v) =>
            asCollectionConfigurationResult(v, p.preview.definition, "draft"),
        );
        if (
          c.version !== (p.family?.version ?? 0) + 1 ||
          (p.family && c.id !== p.family.id)
        )
          throw new ApiError("invalid_server_response", 502);
        await loadWorkflow({
          id: c.id,
          version: c.version,
          hash: c.definition_hash,
        });
        setWorkflowPreview(null);
        setPending(null);
        confirmed(
          "Workflow draft saved. Approve this exact definition separately before starting collection.",
        );
        await workflowChoices();
      } else if (p.kind === "approve" || p.kind === "revoke") {
        const c = p.configuration;
        const result = await approvalPost(
          api,
          api.prefix + "/workflows/" + c.id + "/" + c.version + "/" + p.kind,
          { definition_hash: c.definition_hash, expected_revision: c.revision },
          p.key,
          (v) =>
            asCollectionConfigurationResult(
              v,
              c.definition,
              p.kind === "approve" ? "approved" : "revoked",
              { id: c.id, version: c.version, hash: c.definition_hash },
            ),
        );
        setChosen(result);
        setChosenPreview(p.preview);
        setPending(null);
        confirmed(
          p.kind === "approve"
            ? "Workflow definition approved. Preview and queue a collection job separately."
            : "Workflow definition revoked. Existing sending authority is checked again.",
        );
        await workflowChoices();
      } else if (p.kind === "start") {
        const r = await approvalPost(
          api,
          api.prefix + "/workflow-collections",
          {
            selection: p.selection,
            definition_hash: p.preview.definition_hash,
          },
          p.key,
          (v) =>
            asCollectionResult(v, {
              hash: p.preview.definition_hash,
              states: ["queued"],
              revision: 1,
            }),
        );
        setPending(null);
        setPreview(null);
        confirmed(
          "Collection job queued. No source was contacted; inspect it and confirm the input worker separately.",
        );
        await inspect(r.resource.id, r.resource.definition_hash);
        await list();
      } else if (p.kind === "send") {
        const next = await api.request(
          api.prefix + "/workflow-runs/" + p.input.run_id + "/work",
          { method: "POST", headers: { "Idempotency-Key": p.key } },
          (v) => asCollectedWork(v, p.input, p.definition, p.context),
        );
        setRun({
          input: p.input,
          definition: p.definition,
          status: next,
          context: p.context,
        });
        setPending(null);
        confirmed(
          "The original ordered transfer command is recorded. Current receipts are shown below.",
        );
      } else {
        const j = p.view.job,
          body =
            p.kind === "work"
              ? { definition_hash: j.definition_hash }
              : {
                  definition_hash: j.definition_hash,
                  expected_revision: j.revision,
                };
        const r = await approvalPost(
          api,
          api.prefix + "/workflow-collections/" + j.id + "/" + p.kind,
          body,
          p.key,
          (v) =>
            asCollectionResult(v, {
              id: j.id,
              hash: j.definition_hash,
              states:
                p.kind === "work"
                  ? ["captured", "retry", "attention", "expired"]
                  : p.kind === "cancel"
                    ? ["cancelled"]
                    : ["captured"],
              ...(p.kind === "refresh"
                ? { revision: j.revision }
                : p.kind === "cancel"
                  ? { revision: j.revision + 1 }
                  : {}),
            }),
        );
        setPending(null);
        confirmed(
          p.kind === "work"
            ? r.resource.state === "captured"
              ? "The batch has durable local receipts. Inspect intake status before queueing downstream work."
              : "The attempt is recorded. Inspect the failure and held inputs before choosing a new retry."
            : p.kind === "refresh"
              ? "Downstream admission checked against the current complete batch and ordinary policy."
              : "Further work under this job is stopped; existing receipts remain.",
        );
        await inspect(j.id, j.definition_hash);
        await list();
      }
    } catch (e) {
      const code = e instanceof ApiError ? e.code : "";
      setFailure(
        code === "workflow_routing_decision_required"
          ? "The approved rules give a file no complete outcome. Close this dialog and inspect each file’s exact facts and rule path. This job keeps its original workflow revision."
          : code === "dispatch_approval_required"
            ? "A named reviewer must approve this exact file before sending. Use Approvals, then retry here with the same operation key."
            : code === "collection_authority_input_or_lease_required"
              ? "This job cannot proceed under its current source, cutoff, retry time or lease. Close and inspect its current state before making another decision."
              : "The result was not confirmed. Retry here with this original key, or close and inspect the current private state.",
      );
    } finally {
      setBusy(false);
    }
  }
  const connectionOptions = () => (
    <>
      <option value="">Choose a registered connection</option>
      {connections.map((c) => (
        <option
          key={connectionKey(c)}
          value={connectionKey(c)}
          disabled={c.state !== "active"}
        >
          {c.user +
            "@" +
            c.address +
            " · " +
            c.directory +
            " · v" +
            c.version +
            " · " +
            c.id.slice(0, 8)}
        </option>
      ))}
    </>
  );
  const activeChoice =
    chosen &&
    !choices.workflows.some(
      (w) => w.id === chosen.id && w.version === chosen.version,
    )
      ? [
          {
            id: chosen.id,
            version: chosen.version,
            hash: chosen.definition_hash,
            name: chosen.definition.name,
          },
        ]
      : [];
  const canStart =
    canExecute &&
    chosen?.state === "approved" &&
    chosen.definition.source.completion_contract === collectionContract &&
    (!chosen.definition.steps.length || has("deliver"));
  const effectiveWorkflow = selectedRouting?.workflow ?? selectedWorkflow;
  const effectiveEffects = selectedRouting?.authorization
    ? selectedRouting.effects
    : (selected?.job.definition.effects ?? []);
  const routingCurrent =
    !selectedRouting?.authorization || selectedRouting.current_authority;
  return (
    <section aria-label="Collection workflows">
      <h2>Collection workflows</h2>
      <p>
        Read a producer’s ready manifest, verify its exact files, then use the
        ordinary intake and ordered transfer engine. Each unchanged source
        revision is claimed once across workflow versions. A new batch ID alone
        cannot resend an unchanged file.
      </p>
      {notice && <p role="status">{notice}</p>}
      {canManage && (
        <section aria-label="Prepare collection workflow">
          <h3 ref={formHeading} tabIndex={-1}>
            {family
              ? "Prepare next workflow revision"
              : "Prepare a collection workflow"}
          </h3>
          <form
            className="collection-editor"
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                const d = definition();
                setWorkflowPreview(
                  await approvalPost(
                    api,
                    api.prefix + "/workflows/validate",
                    { definition: d },
                    undefined,
                    (v) => asCollectionWorkflowPreview(v, d),
                  ),
                );
              });
            }}
          >
            <Field label="Collection workflow name">
              {(id) => (
                <input
                  id={id}
                  value={form.name}
                  required
                  maxLength={256}
                  onChange={(e) => edit({ name: e.target.value })}
                />
              )}
            </Field>
            <Field label="Registered source connection">
              {(id) => (
                <select
                  id={id}
                  value={form.source}
                  required
                  disabled={busy}
                  onChange={(e) => edit({ source: e.target.value })}
                >
                  {connectionOptions()}
                </select>
              )}
            </Field>
            <label className="schedule-checkbox">
              <input
                type="checkbox"
                checked={form.scheduled}
                onChange={(e) =>
                  edit({
                    scheduled: e.target.checked,
                    manifest: e.target.checked
                      ? "settlement-{due_utc}.ready.json"
                      : "settlement.ready.json",
                  })
                }
              />
              Expect a separate manifest for each scheduled due time
            </label>
            {form.scheduled && (
              <p>
                Use exactly one <code>{"{due_utc}"}</code> in the filename. It
                becomes the occurrence’s UTC time, for example{" "}
                <code>20261031T070000Z</code>. After workflow approval, choose
                it in Schedules to review arrival and execution cutoffs.
              </p>
            )}
            <Field label="Ready manifest filename">
              {(id) => (
                <input
                  id={id}
                  required
                  value={form.manifest}
                  onChange={(e) => edit({ manifest: e.target.value })}
                />
              )}
            </Field>
            <p>
              The producer publishes this manifest after finishing immutable
              files. Every listed name, byte count and SHA-256 is checked;
              unchanged file size is not a completion signal.
            </p>
            <Field label="Virtual local target folder">
              {(id) => (
                <input
                  id={id}
                  required
                  value={form.directory}
                  placeholder="/incoming"
                  onChange={(e) => edit({ directory: e.target.value })}
                />
              )}
            </Field>
            <Field label="Maximum files per batch">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={64}
                  required
                  value={form.maxFiles}
                  onChange={(e) => edit({ maxFiles: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field label="Maximum bytes per file">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={1073741824}
                  required
                  value={form.maxFile}
                  onChange={(e) => edit({ maxFile: Number(e.target.value) })}
                />
              )}
            </Field>
            <Field label="Maximum bytes per batch">
              {(id) => (
                <input
                  id={id}
                  type="number"
                  min={1}
                  max={form.maxFiles * form.maxFile}
                  required
                  value={form.maxTotal}
                  onChange={(e) => edit({ maxTotal: Number(e.target.value) })}
                />
              )}
            </Field>
            <h4>Ordered downstream transfers</h4>
            {!form.steps.length && (
              <p>
                Local collection only. Add a step to route captured files to a
                receiver.
              </p>
            )}
            {form.steps.map((s, index) => (
              <fieldset key={index}>
                <legend>{"Transfer step " + (index + 1)}</legend>
                <Field label={"Step " + (index + 1) + " ID"}>
                  {(id) => (
                    <input
                      id={id}
                      required
                      value={s.id}
                      onChange={(e) => stepEdit(index, { id: e.target.value })}
                    />
                  )}
                </Field>
                <Field label={"Step " + (index + 1) + " receiver"}>
                  {(id) => (
                    <select
                      id={id}
                      required
                      disabled={busy}
                      value={s.connection}
                      onChange={(e) =>
                        stepEdit(index, { connection: e.target.value })
                      }
                    >
                      {connectionOptions()}
                    </select>
                  )}
                </Field>
                <Field label={"Step " + (index + 1) + " filename"}>
                  {(id) => (
                    <input
                      id={id}
                      required
                      value={s.filename}
                      onChange={(e) =>
                        stepEdit(index, { filename: e.target.value })
                      }
                    />
                  )}
                </Field>
                {s.encryption && (
                  <p>
                    Recipient encryption {s.encryption.profile} stays attached
                    to reviewed key <code>{s.encryption.key.id}</code>, version{" "}
                    {s.encryption.key.version}.
                  </p>
                )}
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    edit({ steps: form.steps.filter((_, i) => i !== index) })
                  }
                >
                  {"Remove step " + (index + 1)}
                </button>
              </fieldset>
            ))}
            <button
              type="button"
              disabled={busy || form.steps.length >= 16}
              onClick={() =>
                edit({
                  steps: [
                    ...form.steps,
                    {
                      id: "send_" + (form.steps.length + 1),
                      connection: "",
                      filename:
                        "settlement-" + (form.steps.length + 1) + ".csv",
                    },
                  ],
                })
              }
            >
              Add transfer step
            </button>
            {connectionNext && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void perform(() => connectionChoices(connectionNext))
                }
              >
                More registered connections
              </button>
            )}
            <div className="actions">
              <Field label="Route each file with approved conditions and finite loops">
                {(id) => (
                  <input
                    id={id}
                    className="routing-toggle"
                    type="checkbox"
                    disabled={busy}
                    checked={!!form.program}
                    onChange={(e) =>
                      edit({
                        program: e.target.checked
                          ? {
                              nodes: [
                                {
                                  kind: "keep_local",
                                  reason: "review_required",
                                },
                              ],
                            }
                          : undefined,
                      })
                    }
                  />
                )}
              </Field>
              {form.program && (
                <ProgramEditor
                  disabled={busy}
                  value={form.program}
                  catalog={form.steps.map((s) => s.id)}
                  onChange={(program) => edit({ program })}
                />
              )}
              <button disabled={busy}>Preview workflow definition</button>
              {family && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setFamily(undefined);
                    setForm(initial(session.limits.max_file_bytes));
                    setWorkflowPreview(null);
                  }}
                >
                  Prepare a new workflow family
                </button>
              )}
            </div>
          </form>
          {workflowPreview && (
            <section aria-label="Workflow definition preview">
              <h3 ref={previewHeading} tabIndex={-1}>
                Workflow definition preview
              </h3>
              <SourceReview
                source={workflowPreview.definition.source}
                connection={workflowPreview.collection.connection}
                effects={workflowPreview.effects}
              />
              {workflowPreview.definition.program && (
                <ProgramReview program={workflowPreview.definition.program} />
              )}
              <p>
                Definition SHA-256{" "}
                <code>{workflowPreview.definition_hash}</code>. Preview makes no
                source or receiver contact.
              </p>
              <button
                disabled={busy}
                onClick={() => {
                  setFailure("");
                  setPending({
                    kind: "draft",
                    preview: structuredClone(workflowPreview),
                    ...(family ? { family: { ...family } } : {}),
                    key: operationKey(),
                  });
                }}
              >
                Review saving workflow draft
              </button>
            </section>
          )}
        </section>
      )}
      {!jobID && (
        <section aria-label="Choose collection workflow">
          <h3>Approved workflow and collection job</h3>
          <Field label="Saved collection workflow">
            {(id) => (
              <select
                id={id}
                disabled={busy}
                value={
                  chosen
                    ? keyReference({
                        id: chosen.id,
                        version: chosen.version,
                        hash: chosen.definition_hash,
                      })
                    : ""
                }
                onChange={(e) => {
                  const c = [...activeChoice, ...choices.workflows].find(
                    (c) => keyReference(c) === e.target.value,
                  );
                  if (c) void perform(() => loadWorkflow(c));
                }}
              >
                <option value="">Choose a saved collection workflow</option>
                {[...activeChoice, ...choices.workflows].map((w) => (
                  <option key={keyReference(w)} value={keyReference(w)}>
                    {w.name + " · v" + w.version + " · " + w.id.slice(0, 8)}
                  </option>
                ))}
              </select>
            )}
          </Field>
          {choices.next && (
            <button
              disabled={busy}
              onClick={() => void perform(() => workflowChoices(choices.next))}
            >
              More collection workflows
            </button>
          )}
          {chosen && (
            <section aria-label="Selected workflow definition">
              <h4>{chosen.definition.name + ": " + chosen.state}</h4>
              <p>
                Version {chosen.version}, revision {chosen.revision}. Definition{" "}
                <code>{chosen.definition_hash}</code>.
              </p>
              {chosenPreview && (
                <>
                  <SourceReview
                    source={chosenPreview.definition.source}
                    connection={chosenPreview.collection.connection}
                    effects={chosenPreview.effects}
                  />
                  {chosenPreview.definition.program && (
                    <ProgramReview program={chosenPreview.definition.program} />
                  )}
                </>
              )}
              {chosenDifference && (
                <DifferenceReview difference={chosenDifference} />
              )}
              {canManage && (
                <button
                  disabled={busy}
                  onClick={() => void perform(() => editWorkflow(chosen))}
                >
                  Prepare next workflow revision
                </button>
              )}
              {canApprove && chosenPreview && chosen.state === "draft" && (
                <button
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "approve",
                      configuration: structuredClone(chosen),
                      preview: structuredClone(chosenPreview),
                      key: operationKey(),
                      ...(chosenDifference
                        ? { difference: structuredClone(chosenDifference) }
                        : {}),
                    });
                  }}
                >
                  Review workflow approval
                </button>
              )}
              {canApprove && chosenPreview && chosen.state === "approved" && (
                <button
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "revoke",
                      configuration: structuredClone(chosen),
                      preview: structuredClone(chosenPreview),
                      key: operationKey(),
                    });
                  }}
                >
                  Review workflow revocation
                </button>
              )}
              {chosen.definition.source.completion_contract ===
                scheduledCollectionContract && (
                <p>
                  This workflow expects a calendar occurrence. Open Schedules,
                  choose this workflow, and review its due times and arrival
                  policy before activation.
                </p>
              )}
              {canStart && (
                <>
                  <Field label="Collection and sending cutoff from queue time (seconds)">
                    {(id) => (
                      <input
                        id={id}
                        type="number"
                        min={1}
                        max={3600}
                        required
                        value={timeout}
                        onChange={(e) => {
                          setTimeoutSeconds(Number(e.target.value));
                          setPreview(null);
                        }}
                      />
                    )}
                  </Field>
                  <button
                    disabled={busy}
                    onClick={() =>
                      void perform(async () => {
                        const selection: CollectionSelection = {
                          workflow: {
                            id: chosen.id,
                            version: chosen.version,
                            hash: chosen.definition_hash,
                          },
                          timeout_seconds: timeout,
                          expected_authority_revision: authority,
                        };
                        setPreview({
                          selection,
                          value: await approvalPost(
                            api,
                            api.prefix + "/workflow-collections/preview",
                            selection,
                            undefined,
                            (v) =>
                              asCollectionPreview(
                                v,
                                selection,
                                authority,
                                chosen,
                              ),
                          ),
                        });
                      })
                    }
                  >
                    Preview collection job
                  </button>
                </>
              )}
            </section>
          )}
          {preview && chosen && (
            <section aria-label="Collection job preview">
              <h3 ref={previewHeading} tabIndex={-1}>
                Collection job preview
              </h3>
              <SourceReview
                source={preview.value.definition.source}
                connection={preview.value.definition.source_connection}
                effects={preview.value.definition.effects}
              />
              <p>
                New collection and sending are bounded to{" "}
                {preview.selection.timeout_seconds} seconds from durable
                queueing. Queueing records metadata only; a later confirmed
                worker reads the source.
              </p>
              <button
                disabled={busy}
                onClick={() => {
                  setFailure("");
                  setPending({
                    kind: "start",
                    preview: structuredClone(preview.value),
                    selection: structuredClone(preview.selection),
                    workflow: structuredClone(chosen),
                    key: operationKey(),
                  });
                }}
              >
                Review queueing collection
              </button>
            </section>
          )}
        </section>
      )}
      {!jobID && (
        <section aria-label="Private collection jobs">
          <h3>Your collection jobs</h3>
          <button disabled={busy} onClick={() => void perform(() => list())}>
            Reload collection jobs
          </button>
          <ul>
            {page.jobs.map((j) => (
              <li key={j.id}>
                {"Job " +
                  j.id.slice(0, 8) +
                  " · " +
                  j.state +
                  " · workflow " +
                  j.workflow_id.slice(0, 8) +
                  " v" +
                  j.workflow_version +
                  " "}
                <button
                  disabled={busy}
                  onClick={() =>
                    void perform(() => inspect(j.id, j.definition_hash))
                  }
                >
                  {"Inspect collection " + j.id}
                </button>
              </li>
            ))}
          </ul>
          {page.next && (
            <button
              disabled={busy}
              onClick={() => void perform(() => list(page.next))}
            >
              Next collection jobs
            </button>
          )}
        </section>
      )}
      {selected && (
        <section aria-label="Selected collection">
          <h3 ref={heading} tabIndex={-1}>
            {"Collection: " + selected.observed_state}
          </h3>
          <p>
            {reasons[selected.job.reason] ??
              "Inspect this job’s current source, receipt and retry state."}
          </p>
          <p>
            Job <code>{selected.job.id}</code>. Capture recorded:{" "}
            {selected.job.captured ? "yes" : "no"}. Attempts{" "}
            {selected.job.attempts} of 8; takeover fence {selected.job.fence}. A
            fence is the counter that prevents an older worker from accepting
            bytes after a takeover.
          </p>
          <p>
            Cutoff{" "}
            <time dateTime={selected.job.deadline_at}>
              {selected.job.deadline_at}
            </time>
            .{" "}
            {selected.current_authority
              ? "Current source and workflow authority match this account."
              : "New work is blocked under the current authority or cutoff; historical receipts remain."}
          </p>
          {selected.job.lease_until && (
            <p>
              Original worker lease until{" "}
              <time dateTime={selected.job.lease_until}>
                {selected.job.lease_until}
              </time>
              . A replacement must wait for expiry.
            </p>
          )}
          {selected.job.state === "retry" && (
            <p>
              Next eligible retry{" "}
              <time dateTime={selected.job.next_at}>
                {selected.job.next_at}
              </time>
              . Retrying keeps the original fixed manifest and input claims.
            </p>
          )}
          <h4>Original job source and recipient catalog</h4>
          <SourceReview
            source={selected.job.definition.source}
            connection={selected.job.definition.source_connection}
            effects={selected.job.definition.effects}
          />
          {selectedWorkflow?.definition.program && (
            <ProgramReview program={selectedWorkflow.definition.program} />
          )}
          <details className="collection-references">
            <summary>Exact collection references</summary>
            <p>
              Job definition <code>{selected.job.definition_hash}</code>;
              workflow <code>{selected.job.workflow_id}</code> version{" "}
              {selected.job.workflow_version}; authority{" "}
              {selected.job.definition.authority_revision}. Producer batch{" "}
              <code>{selected.job.manifest?.batch_id ?? "not observed"}</code>,
              manifest{" "}
              <code>{selected.job.manifest_hash ?? "not observed"}</code>.
            </p>
          </details>
          {selectedRouting && selected.job.captured && (
            <CapturedRouting
              key={selected.job.id}
              api={api}
              session={session}
              view={selected}
              metadata={selectedRouting}
              disabled={busy || pending !== null}
              onError={onError}
              onConfirmed={confirmed}
              onChanged={async () => {
                await inspect(selected.job.id, selected.job.definition_hash);
              }}
            />
          )}
          <div className="actions">
            <button
              disabled={busy}
              onClick={() =>
                void perform(() =>
                  inspect(selected.job.id, selected.job.definition_hash),
                )
              }
            >
              Refresh selected collection
            </button>
            {canExecute &&
              selected.current_authority &&
              selected.job.attempts < 8 &&
              ["queued", "retry", "reading", "attention"].includes(
                selected.job.state,
              ) && (
                <button
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "work",
                      view: structuredClone(selected),
                      key: operationKey(),
                    });
                  }}
                >
                  Review reading source batch
                </button>
              )}
            {canExecute &&
              (has("deliver") || effectiveEffects.length === 0) &&
              selected.current_authority &&
              routingCurrent &&
              selected.job.state === "captured" &&
              (effectiveEffects.length > 0 ||
                effectiveWorkflow?.definition.schema_version === 2) && (
                <button
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "refresh",
                      view: structuredClone(selected),
                      ...(effectiveWorkflow
                        ? { workflow: structuredClone(effectiveWorkflow) }
                        : {}),
                      ...(selectedRouting?.authorization
                        ? { routing: structuredClone(selectedRouting) }
                        : {}),
                      key: operationKey(),
                    });
                  }}
                >
                  {effectiveWorkflow?.definition.schema_version === 2
                    ? "Review recording routing outcomes"
                    : "Review queueing downstream work"}
                </button>
              )}
            {has("workflow_execute") &&
              !["cancelled", "expired"].includes(selected.job.state) && (
                <button
                  disabled={busy}
                  onClick={() => {
                    setFailure("");
                    setPending({
                      kind: "cancel",
                      view: structuredClone(selected),
                      key: operationKey(),
                    });
                  }}
                >
                  Review stopping collection job
                </button>
              )}
          </div>
          <h4>Exact input receipts</h4>
          <ul>
            {selected.inputs.map((i, index) => (
              <li key={i.id}>
                <strong>{i.source_name}</strong>:{" "}
                {i.size_bytes.toLocaleString()} bytes, SHA-256{" "}
                <code>{i.sha256}</code>.{" "}
                {labels[selected.local_states[index]!.state]}.{" "}
                {i.first_job_id !== selected.job.id && (
                  <>
                    Previously claimed by job <code>{i.first_job_id}</code>;
                    this job does not resend it.{" "}
                    <button
                      disabled={busy}
                      onClick={() =>
                        void perform(() => inspect(i.first_job_id))
                      }
                    >
                      Inspect original input job
                    </button>
                  </>
                )}
                <p>
                  Local path <code>{i.target_path}</code>; exact file{" "}
                  <code>{i.file_id ?? "not accepted"}</code>.
                </p>
                {i.run_id && (
                  <button
                    disabled={busy}
                    onClick={() => void perform(() => inspectRun(i))}
                  >
                    {"Inspect downstream run for " + i.source_name}
                  </button>
                )}
                {canExecute &&
                  selected.current_authority &&
                  selected.job.captured &&
                  i.file_id && (
                    <button
                      disabled={busy}
                      onClick={() => void perform(() => previewInput(i))}
                    >
                      {"Preview routing for " + i.source_name}
                    </button>
                  )}
              </li>
            ))}
          </ul>
          <p>
            Business acceptance remains unknown. A local capture or remote
            integrity receipt does not prove that the recipient’s business
            system imported the file.
          </p>
        </section>
      )}
      {routingPreview && (
        <section aria-label="Input-specific routing preview">
          <h3 ref={routingHeading} tabIndex={-1}>
            Input-specific routing preview
          </h3>
          <p>
            This preview made no source or receiver contact and reserved no
            work. The server rechecks the workflow, file policy and authority
            before execution.
          </p>
          <h4>Potential recipient catalog</h4>
          <ReceiverEffects effects={routingPreview.potential_effects} />
          <h4>Selected recipients for this input</h4>
          {routingPreview.selected_effects.length ? (
            <ReceiverEffects effects={routingPreview.selected_effects} />
          ) : (
            <p>No recipient selected for this input.</p>
          )}
          {routingPreview.execution_plan && (
            <PlanReview plan={routingPreview.execution_plan} />
          )}
        </section>
      )}
      {run && (
        <section aria-label="Collected input downstream run">
          <h3 ref={runHeading} tabIndex={-1}>
            {"Downstream run: " + run.status.observed_state}
          </h3>
          <p>
            Exact source <code>{run.input.file_id}</code>, SHA-256{" "}
            <code>{run.input.sha256}</code>.{" "}
            {run.status.observed_reason.replaceAll("_", " ")}.
          </p>
          {run.status.run.execution_plan && (
            <PlanReview plan={run.status.run.execution_plan} />
          )}
          <ol>
            {run.status.steps.map((s) => (
              <li key={s.id}>
                {s.id +
                  ": " +
                  s.state +
                  "; attempts " +
                  s.attempts +
                  ". Intent "}
                <code>{s.delivery_id}</code>.
              </li>
            ))}
          </ol>
          <button
            disabled={busy}
            onClick={() => void perform(() => inspectRun(run.input))}
          >
            Refresh downstream run
          </button>
          {canExecute &&
            has("deliver") &&
            (!run.context.routing ||
              run.context.routing.metadata.current_authority) &&
            !["succeeded", "cancelled", "kept_local"].includes(
              run.status.observed_state,
            ) && (
              <button
                disabled={busy}
                onClick={() => {
                  setFailure("");
                  setPending({
                    kind: "send",
                    input: structuredClone(run.input),
                    definition: structuredClone(run.definition),
                    run: structuredClone(run.status),
                    context: structuredClone(run.context),
                    key: operationKey(),
                  });
                }}
              >
                Review working next transfer step
              </button>
            )}
        </section>
      )}
      {pending && (
        <ApprovalConfirm
          title={
            pending.kind === "draft"
              ? "Save exact workflow draft"
              : pending.kind === "approve"
                ? "Approve exact collection workflow"
                : pending.kind === "revoke"
                  ? "Revoke exact collection workflow"
                  : pending.kind === "start"
                    ? "Queue exact collection job"
                    : pending.kind === "work"
                      ? "Read approved source batch"
                      : pending.kind === "refresh"
                        ? "Queue ordinary downstream intents"
                        : pending.kind === "cancel"
                          ? "Stop further work under this job"
                          : "Work next eligible transfer step"
          }
          busy={busy}
          failure={failure}
          onConfirm={() => void confirm()}
          onCancel={() => {
            setPending(null);
            setFailure("");
          }}
        >
          {pending.kind === "draft" ||
          pending.kind === "approve" ||
          pending.kind === "revoke" ? (
            <>
              <SourceReview
                source={pending.preview.definition.source}
                connection={pending.preview.collection.connection}
                effects={pending.preview.effects}
              />
              {pending.preview.definition.program && (
                <ProgramReview program={pending.preview.definition.program} />
              )}
              {pending.kind === "approve" && pending.difference && (
                <DifferenceReview difference={pending.difference} />
              )}
              <p>
                Definition <code>{pending.preview.definition_hash}</code>. This
                records a configuration decision and makes no source or receiver
                contact.
              </p>
            </>
          ) : pending.kind === "start" ? (
            <>
              <SourceReview
                source={pending.preview.definition.source}
                connection={pending.preview.definition.source_connection}
                effects={pending.preview.definition.effects}
              />
              {pending.workflow.definition.program && (
                <ProgramReview program={pending.workflow.definition.program} />
              )}
              <p>
                Cutoff {pending.selection.timeout_seconds} seconds from durable
                queueing. This action queues metadata only.
              </p>
            </>
          ) : pending.kind === "send" ? (
            <>
              <p>
                This executes one next eligible step of the approved ordered
                workflow. Another worker may have advanced it. All approved
                receivers are shown below; exact-file dispatch approval is
                checked again.
              </p>
              <p>
                Run <code>{pending.run.run.id}</code>, file{" "}
                <code>{pending.input.file_id}</code>, SHA-256{" "}
                <code>{pending.input.sha256}</code>.
              </p>
              <ReceiverEffects
                effects={
                  pending.context.routing?.metadata.effects ??
                  pending.definition.effects
                }
              />
              {pending.context.routing?.metadata.authorization && (
                <p>
                  Routing authorization{" "}
                  <code>
                    {pending.context.routing.metadata.authorization.id}
                  </code>
                  , fingerprint{" "}
                  <code>
                    {
                      pending.context.routing.metadata.authorization
                        .definition_hash
                    }
                  </code>
                  .
                </p>
              )}
              {pending.run.run.execution_plan && (
                <PlanReview plan={pending.run.run.execution_plan} />
              )}
            </>
          ) : (
            <>
              <p>
                Job <code>{pending.view.job.id}</code>, immutable definition{" "}
                <code>{pending.view.job.definition_hash}</code>.
              </p>
              <SourceReview
                source={pending.view.job.definition.source}
                connection={pending.view.job.definition.source_connection}
                effects={pending.view.job.definition.effects}
              />
              {pending.routing?.authorization && (
                <>
                  <p>
                    Effective routing authorization{" "}
                    <code>{pending.routing.authorization.id}</code>, fingerprint{" "}
                    <code>{pending.routing.authorization.definition_hash}</code>
                    , target workflow revision{" "}
                    {pending.routing.authorization.definition.workflow.version}.
                  </p>
                  <h4>Target recipient catalog</h4>
                  <RoutingEffects effects={pending.routing.effects} />
                </>
              )}
              {pending.workflow?.definition.program && (
                <ProgramReview program={pending.workflow.definition.program} />
              )}
              <p>
                {pending.kind === "work"
                  ? "This reads the source and accepts verified local bytes under the original lease, cutoff and intake policy. It does not send downstream."
                  : pending.kind === "refresh"
                    ? "This queues ordinary intents only after the complete batch and required intake checks. It contacts neither source nor receiver."
                    : "This stops further collection and sending under the job. It cannot recall local or receiver bytes already captured."}
              </p>
            </>
          )}
        </ApprovalConfirm>
      )}
    </section>
  );
}
