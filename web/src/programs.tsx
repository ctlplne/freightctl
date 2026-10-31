import { useId } from "react";
import type {
  Condition,
  Program,
  ProgramNode,
  ExecutionPlan,
} from "./programs-types";

function Input({
  label,
  value,
  onChange,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}
function Select({
  label,
  value,
  values,
  onChange,
}: {
  label: string;
  value: string;
  values: { value: string; label: string }[];
  onChange: (v: string) => void;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {values.map((v) => (
          <option key={v.value} value={v.value}>
            {v.label}
          </option>
        ))}
      </select>
    </div>
  );
}
const defaultCondition = (): Condition => ({
  op: "eq",
  field: "file.policy",
  text: "integrity-only-v1",
});
const fields = [
  { value: "file.id", label: "Exact file ID" },
  { value: "file.sha256", label: "File SHA-256" },
  { value: "file.policy", label: "File policy" },
  { value: "file.size_bytes", label: "File size in bytes" },
  { value: "source.name", label: "Original producer filename" },
  { value: "source.batch_id", label: "Original producer batch ID" },
  { value: "source.file_count", label: "Original batch file count" },
  { value: "source.index", label: "Original batch position, starting at zero" },
];
function ConditionEditor({
  value,
  onChange,
  variables,
  depth = 0,
}: {
  value: Condition;
  onChange: (c: Condition) => void;
  variables: string[];
  depth?: number;
}) {
  const compound = value.all
    ? "all"
    : value.any
      ? "any"
      : value.not
        ? "not"
        : "comparison";
  const children = value.all ?? value.any ?? (value.not ? [value.not] : []);
  const updateChildren = (items: Condition[]) =>
    onChange(
      compound === "all"
        ? { op: "all", all: items }
        : compound === "any"
          ? { op: "any", any: items }
          : { op: "not", not: items[0] ?? defaultCondition() },
    );
  const subject = value.variable
    ? "variable:" + value.variable
    : (value.field ?? "file.policy");
  const numeric = [
    "file.size_bytes",
    "source.file_count",
    "source.index",
  ].includes(subject);
  return (
    <fieldset>
      <legend>Condition</legend>
      <Select
        label="Condition group"
        value={compound}
        values={[
          { value: "comparison", label: "Compare one fact" },
          ...(depth < 2
            ? [
                { value: "all", label: "All conditions must match" },
                { value: "any", label: "Any condition may match" },
                { value: "not", label: "Condition must not match" },
              ]
            : []),
        ]}
        onChange={(v) =>
          onChange(
            v === "all"
              ? { op: "all", all: [defaultCondition()] }
              : v === "any"
                ? { op: "any", any: [defaultCondition()] }
                : v === "not"
                  ? { op: "not", not: defaultCondition() }
                  : defaultCondition(),
          )
        }
      />
      {compound !== "comparison" ? (
        <>
          {children.map((c, i) => (
            <div key={i}>
              <ConditionEditor
                value={c}
                variables={variables}
                depth={depth + 1}
                onChange={(next) =>
                  updateChildren(
                    children.map((old, j) => (i === j ? next : old)),
                  )
                }
              />
              {compound !== "not" && children.length > 1 && (
                <button
                  type="button"
                  onClick={() =>
                    updateChildren(children.filter((_, j) => j !== i))
                  }
                >
                  Remove condition {i + 1}
                </button>
              )}
            </div>
          ))}
          {compound !== "not" && children.length < 16 && (
            <button
              type="button"
              onClick={() => updateChildren([...children, defaultCondition()])}
            >
              Add condition
            </button>
          )}
        </>
      ) : (
        <>
          <Select
            label="Fact to compare"
            value={subject}
            values={[
              ...fields,
              ...variables.map((v) => ({
                value: "variable:" + v,
                label: "Current loop step: " + v,
              })),
            ]}
            onChange={(v) =>
              onChange({
                ...([
                  "file.size_bytes",
                  "source.file_count",
                  "source.index",
                ].includes(v)
                  ? { op: "eq", number: "0" }
                  : { op: "eq", text: "" }),
                ...(v.startsWith("variable:")
                  ? { variable: v.slice(9) }
                  : { field: v }),
              })
            }
          />
          <Select
            label="Comparison"
            value={value.op}
            values={(numeric
              ? ["eq", "ne", "lt", "le", "gt", "ge"]
              : ["eq", "ne", "prefix", "suffix", "glob"]
            ).map((v) => ({
              value: v,
              label: (
                {
                  eq: "Equals",
                  ne: "Does not equal",
                  lt: "Less than",
                  le: "At most",
                  gt: "Greater than",
                  ge: "At least",
                  prefix: "Starts with",
                  suffix: "Ends with",
                  glob: "Matches * and ? pattern",
                } as Record<string, string>
              )[v]!,
            }))}
            onChange={(op) => onChange({ ...value, op })}
          />
          <Input
            label={
              numeric
                ? "Exact whole-number threshold"
                : "Comparison text (case-sensitive)"
            }
            value={numeric ? (value.number ?? "0") : (value.text ?? "")}
            onChange={(v) =>
              onChange(
                numeric ? { ...value, number: v } : { ...value, text: v },
              )
            }
          />
        </>
      )}
    </fieldset>
  );
}
function NodeList({
  nodes,
  onChange,
  catalog,
  variables,
  depth = 0,
  path = "Program",
}: {
  nodes: ProgramNode[];
  onChange: (nodes: ProgramNode[]) => void;
  catalog: string[];
  variables: string[];
  depth?: number;
  path?: string;
}) {
  const update = (index: number, next: ProgramNode) =>
    onChange(nodes.map((n, i) => (i === index ? next : n)));
  const move = (index: number, direction: number) => {
    const next = [...nodes];
    [next[index], next[index + direction]] = [
      next[index + direction]!,
      next[index]!,
    ];
    onChange(next);
  };
  return (
    <fieldset>
      <legend>{path}</legend>
      <ol>
        {nodes.map((node, index) => (
          <li key={index}>
            <fieldset>
              <legend>
                {path +
                  " step " +
                  (index + 1) +
                  ": " +
                  node.kind.replaceAll("_", " ")}
              </legend>
              {node.kind === "deliver" && (
                <Select
                  label="Approved delivery step or loop item"
                  value={
                    node.step_variable
                      ? "variable:" + node.step_variable
                      : (node.step ?? "")
                  }
                  values={[
                    { value: "", label: "Choose an approved step" },
                    ...catalog.map((v) => ({ value: v, label: v })),
                    ...variables.map((v) => ({
                      value: "variable:" + v,
                      label: "Current loop step: " + v,
                    })),
                  ]}
                  onChange={(v) =>
                    update(
                      index,
                      v.startsWith("variable:")
                        ? { kind: "deliver", step_variable: v.slice(9) }
                        : { kind: "deliver", step: v },
                    )
                  }
                />
              )}
              {node.kind === "keep_local" && (
                <Input
                  label="Recorded local reason code"
                  value={node.reason ?? ""}
                  onChange={(reason) => update(index, { ...node, reason })}
                />
              )}
              {node.kind === "if" && (
                <>
                  <ConditionEditor
                    value={node.when ?? defaultCondition()}
                    variables={variables}
                    onChange={(when) => update(index, { ...node, when })}
                  />
                  <NodeList
                    path={path + " " + (index + 1) + " when matched"}
                    nodes={node.then ?? []}
                    catalog={catalog}
                    variables={variables}
                    depth={depth + 1}
                    onChange={(then) => update(index, { ...node, then })}
                  />
                  <NodeList
                    path={path + " " + (index + 1) + " otherwise"}
                    nodes={node.else ?? []}
                    catalog={catalog}
                    variables={variables}
                    depth={depth + 1}
                    onChange={(otherwise) =>
                      update(index, { ...node, else: otherwise })
                    }
                  />
                </>
              )}
              {node.kind === "for_each" && (
                <>
                  <Input
                    label="Loop variable name"
                    value={node.variable ?? ""}
                    onChange={(variable) =>
                      update(index, { ...node, variable })
                    }
                  />
                  <p>
                    Choose a finite list of approved steps. The loop visits them
                    in the order below.
                  </p>
                  {catalog.map((step) => (
                    <label key={step} className="routing-choice">
                      <input
                        type="checkbox"
                        checked={node.steps?.includes(step) ?? false}
                        onChange={(e) =>
                          update(index, {
                            ...node,
                            steps: e.target.checked
                              ? [...(node.steps ?? []), step]
                              : (node.steps ?? []).filter((s) => s !== step),
                          })
                        }
                      />
                      {step}
                    </label>
                  ))}
                  <ol>
                    {(node.steps ?? []).map((step, i) => (
                      <li key={step}>
                        {step}
                        {i > 0 && (
                          <button
                            type="button"
                            onClick={() => {
                              const steps = [...node.steps!];
                              [steps[i - 1], steps[i]] = [
                                steps[i]!,
                                steps[i - 1]!,
                              ];
                              update(index, { ...node, steps });
                            }}
                          >
                            Move {step} earlier in loop
                          </button>
                        )}
                      </li>
                    ))}
                  </ol>
                  <NodeList
                    path={path + " " + (index + 1) + " loop body"}
                    nodes={node.body ?? []}
                    catalog={catalog}
                    variables={[...variables, node.variable ?? ""]}
                    depth={depth + 1}
                    onChange={(body) => update(index, { ...node, body })}
                  />
                </>
              )}
              <div className="actions">
                <button
                  type="button"
                  disabled={index === 0}
                  onClick={() => move(index, -1)}
                >
                  Move program step {index + 1} earlier
                </button>
                <button
                  type="button"
                  disabled={index === nodes.length - 1}
                  onClick={() => move(index, 1)}
                >
                  Move program step {index + 1} later
                </button>
                <button
                  type="button"
                  onClick={() => onChange(nodes.filter((_, i) => i !== index))}
                >
                  Remove program step {index + 1}
                </button>
              </div>
            </fieldset>
          </li>
        ))}
      </ol>
      {depth < 4 && nodes.length < 64 && (
        <div className="actions">
          <button
            type="button"
            onClick={() =>
              onChange([
                ...nodes,
                {
                  kind: "deliver",
                  ...(catalog[0] ? { step: catalog[0] } : {}),
                },
              ])
            }
          >
            Add approved delivery
          </button>
          {depth < 3 && (
            <>
              <button
                type="button"
                onClick={() =>
                  onChange([
                    ...nodes,
                    {
                      kind: "if",
                      when: defaultCondition(),
                      then: [{ kind: "keep_local", reason: "review_required" }],
                      else: [
                        { kind: "keep_local", reason: "unmatched_source_file" },
                      ],
                    },
                  ])
                }
              >
                Add conditional branch
              </button>
              <button
                type="button"
                onClick={() =>
                  onChange([
                    ...nodes,
                    {
                      kind: "for_each",
                      variable: "recipient",
                      steps: [...catalog],
                      body: [{ kind: "deliver", step_variable: "recipient" }],
                    },
                  ])
                }
              >
                Add finite recipient loop
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() =>
              onChange([
                ...nodes,
                { kind: "keep_local", reason: "review_required" },
              ])
            }
          >
            Add explicit local outcome
          </button>
        </div>
      )}
    </fieldset>
  );
}
export function ProgramEditor({
  value,
  onChange,
  catalog,
  disabled,
}: {
  value: Program;
  onChange: (p: Program) => void;
  catalog: string[];
  disabled: boolean;
}) {
  return (
    <fieldset disabled={disabled} className="routing-editor">
      <legend>Routing decisions</legend>
      <p>
        Rules select from the approved delivery catalog above. They use original
        file and batch facts. A path must deliver to at least one step or record
        an explicit local outcome. Each selected step may run once per file.
      </p>
      <NodeList
        nodes={value.nodes}
        onChange={(nodes) => onChange({ nodes })}
        catalog={catalog}
        variables={[]}
      />
      <p>
        Validation enforces 64 program nodes, four control levels and 256
        evaluation visits, including loops. No source file can supply a
        recipient.
      </p>
    </fieldset>
  );
}
function conditionText(c: Condition): string {
  if (c.all) return "all of (" + c.all.map(conditionText).join("; ") + ")";
  if (c.any) return "any of (" + c.any.map(conditionText).join("; ") + ")";
  if (c.not) return "not (" + conditionText(c.not) + ")";
  const field =
    fields.find((f) => f.value === c.field)?.label ??
    "current loop step " + c.variable;
  const operation =
    (
      {
        eq: "equals",
        ne: "does not equal",
        lt: "is less than",
        le: "is at most",
        gt: "is greater than",
        ge: "is at least",
        prefix: "starts with",
        suffix: "ends with",
        glob: "matches pattern",
      } as Record<string, string>
    )[c.op] ?? c.op;
  return field + " " + operation + " " + (c.number ?? JSON.stringify(c.text));
}
export function ProgramReview({ program }: { program: Program }) {
  const nodes = (items: ProgramNode[]) => (
    <ol>
      {items.map((n, i) => (
        <li key={i}>
          {n.kind === "deliver" ? (
            <>
              Deliver using{" "}
              {n.step_variable ? (
                "current loop step " + n.step_variable
              ) : (
                <code>{n.step}</code>
              )}
              .
            </>
          ) : n.kind === "keep_local" ? (
            <>
              Keep local: <code>{n.reason}</code>. No receiver receipt is
              created.
            </>
          ) : n.kind === "if" ? (
            <>
              <p>If {conditionText(n.when!)}:</p>
              {nodes(n.then ?? [])}
              <p>Otherwise:</p>
              {nodes(n.else ?? [])}
            </>
          ) : (
            <>
              <p>
                For each approved step <code>{n.steps?.join(", ")}</code>, in
                that order, bind <code>{n.variable}</code>:
              </p>
              {nodes(n.body ?? [])}
            </>
          )}
        </li>
      ))}
    </ol>
  );
  return (
    <section aria-label="Approved routing rules">
      <h4>Routing rules</h4>
      <p>
        Delivery steps are potential recipients. The exact input preview shows
        the selected recipients and decision path.
      </p>
      {nodes(program.nodes)}
    </section>
  );
}
export function PlanReview({ plan }: { plan: ExecutionPlan }) {
  return (
    <section aria-label="Exact input routing plan">
      <h4>Exact input routing plan</h4>
      <p>
        File <code>{plan.facts.file.id}</code>, SHA-256{" "}
        <code>{plan.facts.file.sha256}</code>.
      </p>
      {plan.facts.source && (
        <p>
          Original producer file <code>{plan.facts.source.name}</code>, batch{" "}
          <code>{plan.facts.source.batch_id}</code>, position{" "}
          {plan.facts.source.index + 1} of {plan.facts.source.file_count}.
        </p>
      )}
      {plan.local_reason ? (
        <p>
          Keep local: <code>{plan.local_reason}</code>. This outcome creates no
          delivery intent or receiver receipt.
        </p>
      ) : (
        <p>
          Selected delivery order: <code>{plan.selected_steps.join(", ")}</code>
          . Each file and step retains its ordinary sending approval.
        </p>
      )}
      <details>
        <summary>Recorded decision path</summary>
        <ol>
          {plan.decisions.map((d, i) => (
            <li key={i}>
              <code>{d.path}</code>: {d.kind.replaceAll("_", " ")}
              {d.matched === undefined
                ? ""
                : d.matched
                  ? " matched"
                  : " did not match"}
              {d.step ? " → " + d.step : ""}
              {d.steps ? " → " + d.steps.join(", ") : ""}
              {d.reason ? " → " + d.reason : ""}.
            </li>
          ))}
        </ol>
      </details>
    </section>
  );
}
