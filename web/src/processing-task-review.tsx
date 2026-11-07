import type { ProcessingDefinition } from "./processing-types";

export function ProcessingTaskReview({
  definition,
}: {
  definition: ProcessingDefinition;
}) {
  const task = definition.processing,
    rules = task.definition;
  return (
    <section aria-label="Exact processing rules">
      <h3>{definition.name}</h3>
      <p>
        Input contract <code>{rules.source_policy_hash}</code> · output policy{" "}
        <code>{task.output_policy.id}</code> version{" "}
        {task.output_policy.version} · <code>{task.output_policy.hash}</code>.
      </p>
      <p>
        Output:{rules.output_kind} · logical path:
        {task.target_path || "unpublished custody"}. Reason:{task.reason}
      </p>
      <ol>
        {rules.columns.map((m, i) => (
          <li key={i}>
            {m.source} → {m.target}; conversion:{m.conversion}; missing:
            {m.missing}; null:{m.null}; empty:{m.empty}
          </li>
        ))}
      </ol>
      <p>
        Limits:{rules.max_bytes} output bytes,{rules.max_rows} rows,
        {rules.max_record_bytes} bytes per record,{rules.timeout_seconds}{" "}
        seconds. The output remains held for fresh checks and a separate
        release.
      </p>
    </section>
  );
}
