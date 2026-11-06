import { useEffect, useRef, useState, type FormEvent } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { ApiError, object } from "./types";
import {
  asIntakePolicy,
  defaultIntakeDefinition,
  intakeDefinition,
  intakeHash,
  type IntakeColumn,
  type IntakeDefinition,
  type IntakePolicy,
} from "./intake-policy-types";

type Review =
  | {
      key: string;
      kind: "register";
      definition: IntakeDefinition;
      hash: string;
      prior: IntakePolicy | null;
    }
  | { key: string; kind: "revoke"; prior: IntakePolicy };
export function IntakePolicyEditor({
  api,
  refresh,
  onError,
}: {
  api: Api;
  refresh: number;
  onError: (error: unknown) => void;
}) {
  const [current, setCurrent] = useState<IntakePolicy | null>(null),
    [draft, setDraft] = useState(defaultIntakeDefinition),
    [loaded, setLoaded] = useState(false),
    [reload, setReload] = useState(0),
    [pending, setPending] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [failure, setFailure] = useState(""),
    [notice, setNotice] = useState("");
  const currentApi = useRef(api),
    [loadedApi, setLoadedApi] = useState(api);
  currentApi.current = api;
  const dialog = useRef<HTMLDialogElement>(null),
    alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    const c = new AbortController();
    // A context change clears old metadata and reviews. Same-context refresh
    // keeps an uncertain original-key command available for receipt recovery.
    if (loadedApi !== api) {
      setLoadedApi(api);
      setLoaded(false);
      setCurrent(null);
      setPending(null);
      setBusy(false);
      setNotice("");
      setFailure("");
      setDraft(defaultIntakeDefinition());
    }
    api
      .request(
        api.prefix + "/intake-policy",
        { signal: c.signal },
        asIntakePolicy,
      )
      .then((p) => {
        if (!c.signal.aborted && currentApi.current === api) {
          setCurrent(p);
          setDraft(
            p ? structuredClone(p.definition) : defaultIntakeDefinition(),
          );
          setLoaded(true);
        }
      })
      .catch((e) => {
        if (!c.signal.aborted && currentApi.current === api) {
          setLoaded(false);
          onError(e);
        }
      });
    return () => c.abort();
  }, [api, refresh, reload]);
  useEffect(() => {
    if (pending) dialog.current?.showModal();
    else dialog.current?.close();
  }, [pending]);
  function review(event: FormEvent) {
    event.preventDefault();
    setNotice("");
    setFailure("");
    try {
      const definition = intakeDefinition(draft);
      setPending({
        key: operationKey(),
        kind: "register",
        definition,
        hash: intakeHash(definition),
        prior: current,
      });
    } catch {
      setNotice(
        "Review unique column names, types, decimal precision and processing limits. Each column must fit inside the record limit.",
      );
    }
  }
  function column(index: number, patch: Partial<IntakeColumn>) {
    setDraft((d) => ({
      ...d,
      columns: d.columns.map((c, i) => (i === index ? { ...c, ...patch } : c)),
    }));
  }
  async function apply() {
    if (!pending || busy || currentApi.current !== api || loadedApi !== api)
      return;
    const reviewed = pending;
    setBusy(true);
    setFailure("");
    try {
      const path =
        api.prefix +
        "/intake-policy" +
        (reviewed.kind === "revoke" ? "/revoke" : "");
      const body =
        reviewed.kind === "register"
          ? {
              expected_version: reviewed.prior?.version ?? 0,
              definition: reviewed.definition,
            }
          : {
              definition_hash: reviewed.prior.definition_hash,
              expected_version: reviewed.prior.version,
              expected_revision: reviewed.prior.revision,
            };
      const p = await api.request(
        path,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": reviewed.key,
          },
          body: JSON.stringify(body),
        },
        (v) => {
          if (currentApi.current !== api)
            throw new ApiError("operation_context_changed", 409);
          const o = object(v),
            p = asIntakePolicy(o.resource);
          if (
            typeof o.replayed !== "boolean" ||
            !p ||
            (reviewed.prior && p.id !== reviewed.prior.id) ||
            (reviewed.kind === "register"
              ? p.version !== (reviewed.prior?.version ?? 0) + 1 ||
                p.revision !== 1 ||
                p.state !== "active" ||
                p.definition_hash !== reviewed.hash
              : p.version !== reviewed.prior.version ||
                p.revision !== reviewed.prior.revision + 1 ||
                p.state !== "revoked" ||
                p.definition_hash !== reviewed.prior.definition_hash)
          )
            throw new ApiError("invalid_server_response", 502);
          return p;
        },
      );
      if (!alive.current || currentApi.current !== api) return;
      setCurrent(p);
      setDraft(structuredClone(p.definition));
      setPending(null);
      setNotice(
        `Saved intake policy version ${p.version}, revision ${p.revision}: ${p.state}. Existing file checks keep their original policy binding.`,
      );
      setReload((v) => v + 1);
    } catch (e) {
      if (alive.current && currentApi.current === api) {
        setFailure(
          e instanceof ApiError && e.status === 409
            ? "The policy changed. Cancel, refresh and review its current version before applying a new command."
            : "The change was not confirmed. Retry this exact reviewed command to recover its saved receipt, or cancel and refresh current state.",
        );
        onError(e);
      }
    } finally {
      if (alive.current && currentApi.current === api) setBusy(false);
    }
  }
  if (loadedApi !== api)
    return (
      <section className="panel" aria-label="Incoming file policy">
        <p role="status">Reading policy for the current session…</p>
      </section>
    );
  return (
    <section className="panel" aria-label="Incoming file policy">
      <p>
        New uploads under this policy stay held until their exact bytes pass the
        required checks and a separate release is approved. This also applies to
        FTPS and other transfer interfaces.
      </p>
      <p>
        Changing or revoking a policy can block existing releases and in-flight
        work. A new policy version does not approve files checked under an older
        version.
      </p>
      {notice && <p role="status">{notice}</p>}
      {current ? (
        <dl className="facts">
          <dt>Current policy</dt>
          <dd>
            Version {current.version} · revision {current.revision} ·{" "}
            {current.state}
          </dd>
          <dt>Policy SHA-256</dt>
          <dd>
            <code>{current.definition_hash}</code>
          </dd>
          <dt>Format</dt>
          <dd>
            {current.definition.kind === "csv"
              ? "CSV columns"
              : "JSON record array"}
          </dd>
        </dl>
      ) : loaded ? (
        <p>
          No intake policy is configured. Ordinary integrity checks still apply.
        </p>
      ) : (
        <p>Reading current policy…</p>
      )}
      <form onSubmit={review}>
        <fieldset disabled={!loaded || busy || !!pending}>
          <legend>Expected file contract</legend>
          <label>
            File format
            <select
              value={draft.kind}
              onChange={(event) => {
                const kind = event.target.value;
                if (kind === "csv")
                  setDraft((d) => ({ ...d, schema_version: 1, kind: "csv" }));
                else if (kind === "json_records")
                  setDraft((d) => ({
                    ...d,
                    schema_version: 2,
                    kind: "json_records",
                  }));
              }}
            >
              <option value="csv">CSV columns</option>
              <option value="json_records">JSON record array</option>
            </select>
          </label>
          <p>
            Start with these example columns or replace them with your actual
            contract.{" "}
            {draft.kind === "csv"
              ? "Column order and header names must match the file."
              : "Use an array of flat objects with these exact field names. Numeric fields require JSON numbers;duplicate,unknown or nested fields fail. No content is executed."}
          </p>
          {draft.columns.map((c, i) => (
            <fieldset key={i}>
              <legend>Column {i + 1}</legend>
              <label>
                Column {i + 1} name
                <input
                  required
                  maxLength={128}
                  value={c.name}
                  onChange={(e) => column(i, { name: e.target.value })}
                />
              </label>
              <label>
                Column {i + 1} type
                <select
                  value={c.type}
                  onChange={(e) => {
                    const type = e.target.value as IntakeColumn["type"];
                    setDraft((d) => ({
                      ...d,
                      columns: d.columns.map((prior, index) => {
                        if (index !== i) return prior;
                        const {
                          precision: _precision,
                          scale: _scale,
                          ...plain
                        } = prior;
                        return type === "decimal"
                          ? { ...plain, type, precision: 12, scale: 2 }
                          : { ...plain, type };
                      }),
                    }));
                  }}
                >
                  <option value="text">Text</option>
                  <option value="integer">Integer</option>
                  <option value="decimal">Decimal</option>
                  <option value="date">Date (YYYY-MM-DD)</option>
                </select>
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={c.required}
                  onChange={(e) => column(i, { required: e.target.checked })}
                />
                Column {i + 1} is required
              </label>
              <label>
                Column {i + 1} maximum bytes
                <input
                  required
                  type="number"
                  min={1}
                  max={65536}
                  value={c.max_bytes}
                  onChange={(e) =>
                    column(i, { max_bytes: Number(e.target.value) })
                  }
                />
              </label>
              {c.type === "decimal" && (
                <>
                  <label>
                    Column {i + 1} decimal precision
                    <input
                      required
                      type="number"
                      min={1}
                      max={38}
                      value={c.precision ?? 12}
                      onChange={(e) =>
                        column(i, { precision: Number(e.target.value) })
                      }
                    />
                  </label>
                  <label>
                    Column {i + 1} decimal scale
                    <input
                      required
                      type="number"
                      min={0}
                      max={c.precision ?? 12}
                      value={c.scale ?? 0}
                      onChange={(e) =>
                        column(i, { scale: Number(e.target.value) })
                      }
                    />
                  </label>
                </>
              )}
              <button
                type="button"
                disabled={draft.columns.length === 1}
                onClick={() =>
                  setDraft((d) => ({
                    ...d,
                    columns: d.columns.filter((_, index) => index !== i),
                  }))
                }
              >
                Remove column {i + 1}
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            disabled={draft.columns.length >= 128}
            onClick={() =>
              setDraft((d) => ({
                ...d,
                columns: [
                  ...d.columns,
                  { name: "", type: "text", required: true, max_bytes: 64 },
                ],
              }))
            }
          >
            Add column
          </button>
          <fieldset>
            <legend>Processing limits</legend>
            {(
              [
                ["Maximum file bytes", "max_bytes", 1, 1073741824],
                ["Maximum data rows", "max_rows", 1, 1000000],
                ["Maximum record bytes", "max_record_bytes", 64, 1048576],
                ["Check timeout seconds", "timeout_seconds", 1, 60],
              ] as const
            ).map(([label, key, min, max]) => (
              <label key={key}>
                {label}
                <input
                  required
                  type="number"
                  min={min}
                  max={max}
                  value={draft[key]}
                  onChange={(e) =>
                    setDraft((d) => ({ ...d, [key]: Number(e.target.value) }))
                  }
                />
              </label>
            ))}
          </fieldset>
          {draft.signature && (
            <p>
              Keep required signer <code>{draft.signature.key.id}</code>,
              version {draft.signature.key.version}, definition SHA-256{" "}
              <code>{draft.signature.key.hash}</code>. This form preserves that
              requirement.
            </p>
          )}
          {draft.scanner && (
            <p>
              Keep required scanner <code>{draft.scanner.id}</code>, version{" "}
              {draft.scanner.version}, definition SHA-256{" "}
              <code>{draft.scanner.hash}</code>. This form preserves that
              requirement.
            </p>
          )}
          <button type="submit">Review intake policy</button>
          <button
            type="button"
            disabled={!current || current.state !== "active"}
            onClick={() => {
              if (current) {
                setFailure("");
                setPending({
                  key: operationKey(),
                  kind: "revoke",
                  prior: current,
                });
              }
            }}
          >
            Review policy revocation
          </button>
        </fieldset>
      </form>
      <dialog
        ref={dialog}
        aria-labelledby="intake-policy-review-title"
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setPending(null);
        }}
      >
        <h2 id="intake-policy-review-title">
          Review intake policy{" "}
          {pending?.kind === "revoke" ? "revocation" : "registration"}
        </h2>
        {failure && <p role="alert">{failure}</p>}
        {pending?.kind === "register" ? (
          <>
            <p>
              Activate version {(pending.prior?.version ?? 0) + 1} after
              expected version {pending.prior?.version ?? 0}. New uploads are
              held; existing files need their original checks and approval.
            </p>
            <p>
              Format:{" "}
              {pending.definition.kind === "csv"
                ? "CSV columns"
                : "JSON record array"}
              . The definition hash binds this choice and every protected
              requirement.
            </p>
            <ol>
              {pending.definition.columns.map((c, i) => (
                <li key={i}>
                  {c.name}: {c.type}, {c.required ? "required" : "optional"}, at
                  most {c.max_bytes} bytes
                  {c.type === "decimal"
                    ? `, precision ${c.precision}, scale ${c.scale ?? 0}`
                    : ""}
                </li>
              ))}
            </ol>
            <p>
              File {pending.definition.max_bytes} bytes;{" "}
              {pending.definition.max_rows} rows; record{" "}
              {pending.definition.max_record_bytes} bytes; timeout{" "}
              {pending.definition.timeout_seconds} seconds.
            </p>
            <p>
              Definition SHA-256: <code>{pending.hash}</code>
            </p>
            {pending.definition.signature && (
              <p>Signer requirement preserved.</p>
            )}
            {pending.definition.scanner && (
              <p>Scanner requirement preserved.</p>
            )}
          </>
        ) : (
          pending && (
            <>
              <p>
                Revoke version {pending.prior.version}, revision{" "}
                {pending.prior.revision}, SHA-256{" "}
                <code>{pending.prior.definition_hash}</code>.
              </p>
              <p>
                Uploads cannot silently fall back to unconfigured acceptance.
                Existing reads and releases bound to this policy may stop;
                revocation does not erase copies already retrieved.
              </p>
            </>
          )
        )}
        <div className="actions">
          <button disabled={busy} onClick={() => setPending(null)}>
            Cancel
          </button>
          <button disabled={busy} onClick={() => void apply()}>
            {busy ? "Saving…" : "Apply reviewed policy"}
          </button>
        </div>
      </dialog>
    </section>
  );
}
