import { useEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { ApiError, uuid, type Session } from "./types";
import { operationKey } from "./crypto";
import {
  intakeDefinition,
  intakeHash,
  type IntakeDefinition,
} from "./intake-policy-types";
import { processingStamp, type Reference } from "./processing-types";
import {
  OutputPolicyApi,
  outputPolicyAllowed,
  outputPolicyMutation,
  outputPolicyRecovery,
  parseOutputPolicyRecovery,
  type OutputPolicyMutation,
  type OutputPolicyRecord,
  type OutputPolicyAdminPage,
} from "./output-policy-api";

export function OutputPolicies({
  api,
  session,
  onError,
}: {
  api: Api;
  session: Session;
  onError: (error: unknown) => void;
}) {
  const stamp = processingStamp(session),
    client = useMemo(() => new OutputPolicyApi(api), [api, stamp]);
  const [producer, setProducer] = useState(""),
    [definition, setDefinition] = useState<IntakeDefinition | null>(null),
    [base, setBase] = useState<Reference | null>(null),
    [page, setPage] = useState<OutputPolicyAdminPage | null>(null),
    [currentRecord, setCurrentRecord] = useState<OutputPolicyRecord | null>(
      null,
    ),
    [receipt, setReceipt] = useState<{
      resource: OutputPolicyRecord;
      replayed: boolean;
    } | null>(null),
    [review, setReview] = useState<OutputPolicyMutation | null>(null),
    [pending, setPending] = useState<OutputPolicyMutation | null>(null),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState("");
  const alive = useRef(true),
    active = useRef(false),
    dialog = useRef<HTMLDialogElement>(null),
    heading = useRef<HTMLHeadingElement>(null),
    focus = useRef<HTMLElement | null>(null);
  const current = () =>
    alive.current &&
    api.session !== null &&
    processingStamp(api.session) === stamp &&
    outputPolicyAllowed(api.session);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (review) {
      focus.current = document.activeElement as HTMLElement;
      if (!dialog.current?.open) dialog.current?.showModal();
      heading.current?.focus();
    } else {
      dialog.current?.close();
      focus.current?.focus();
    }
  }, [review]);
  const perform = async (work: () => Promise<void>) => {
    if (active.current) return;
    active.current = true;
    setBusy(true);
    try {
      await work();
    } catch (error) {
      if (current()) onError(error);
    } finally {
      active.current = false;
      if (current()) setBusy(false);
    }
  };
  const refOf = (record: OutputPolicyRecord): Reference => ({
    id: record.policy.id,
    version: record.policy.version,
    hash: record.policy.definition_hash,
  });
  const inspect = (ref: Reference) =>
    perform(async () => {
      setCurrentRecord(null);
      const result = await client.get(ref);
      if (current()) setCurrentRecord(result);
    });
  const saveRecovery = (request: OutputPolicyMutation) => {
    const saved = outputPolicyRecovery(request, session, location.origin),
      url = URL.createObjectURL(
        new Blob([JSON.stringify(saved, null, 2) + "\n"], {
          type: "application/json",
        }),
      ),
      link = document.createElement("a");
    link.href = url;
    link.download = "freightctl-output-policy-request.json";
    link.click();
    URL.revokeObjectURL(url);
  };
  const importDefinition = (file: File) =>
    perform(async () => {
      if (file.size > 32768)
        throw new ApiError("policy_definition_too_large", 400);
      let value: unknown;
      try {
        value = JSON.parse(await file.text());
      } catch {
        throw new ApiError("invalid_policy_definition", 400);
      }
      const parsed = intakeDefinition(value);
      if (current()) {
        setDefinition(parsed);
        setReview(null);
        setNotice("Definition loaded for review. Nothing has been registered.");
      }
    });
  const importRecovery = (file: File) =>
    perform(async () => {
      if (file.size > 65536)
        throw new ApiError("invalid_output_policy_recovery", 400);
      const request = parseOutputPolicyRecovery(
        await file.text(),
        session,
        location.origin,
      );
      if (current()) {
        setPending(request);
        setReview(request);
        setNotice(
          "Saved request loaded. Review its exact producer, rules and key before retrying.",
        );
      }
    });
  const prepare = () => {
    try {
      if (!definition || !uuid(producer))
        throw new ApiError(
          "output_policy_definition_and_producer_required",
          400,
        );
      setReview(
        outputPolicyMutation({
          kind: "register",
          key: operationKey(),
          body: {
            ...(base ? { policy_id: base.id } : {}),
            expected_version: base?.version ?? 0,
            producer_id: producer,
            definition,
          },
        }),
      );
    } catch (error) {
      onError(error);
    }
  };
  const submit = (request: OutputPolicyMutation) =>
    perform(async () => {
      setPending(request);
      setNotice("Waiting for the exact command receipt.");
      try {
        const result = await client.mutate(request);
        if (!current()) return;
        setReceipt(result);
        setPending(null);
        setReview(null);
        setCurrentRecord(null);
        setNotice(
          "Original command receipt recorded. Current status is fetched separately.",
        );
        try {
          const fresh = await client.get(refOf(result.resource));
          if (current()) setCurrentRecord(fresh);
        } catch (error) {
          if (current()) {
            setNotice(
              "Original receipt is available. Current status could not be refreshed.",
            );
            onError(error);
          }
        }
      } catch (error) {
        if (current()) {
          setNotice(
            "This command is not confirmed. Keep its saved request and exact key; retry that request to recover its original receipt.",
          );
          onError(error);
        }
      }
    });
  return (
    <section aria-label="Producer output policy administration">
      <h2>Output checking contracts</h2>
      <p>
        Register the rules that a named account will use for its generated
        files. Incoming-file checks stay in place. This grants no file access,
        processing, release or forwarding permission.
      </p>
      {notice && !review && <p role="status">{notice}</p>}
      {pending && (
        <section aria-label="Unconfirmed output policy request">
          <p>
            Unconfirmed request key <code>{pending.key}</code>. Preserve it
            before leaving this page.
          </p>
          <button disabled={busy} onClick={() => saveRecovery(pending)}>
            Save exact output policy request
          </button>
          <button disabled={busy} onClick={() => setReview(pending)}>
            Review exact output policy retry
          </button>
        </section>
      )}
      <label>
        Open saved output policy request
        <input
          aria-label="Open output policy recovery JSON"
          type="file"
          accept="application/json"
          disabled={busy || !!pending}
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = "";
            if (file) void importRecovery(file);
          }}
        />
      </label>
      <fieldset disabled={busy || !!pending}>
        <legend>
          {base ? "New version of an output contract" : "New output contract"}
        </legend>
        {base && (
          <p>
            Contract <code>{base.id}</code>, expected latest version{" "}
            {base.version}. A concurrent change will refuse this request.
          </p>
        )}
        <label>
          Producer account ID
          <input
            value={producer}
            onChange={(event) => setProducer(event.target.value)}
          />
        </label>
        <p>
          The producer is the account that will create these files. Choose its
          ID from Accounts. It needs input reading, output writing, checks and
          approved workflow execution.
        </p>
        {session.identity.permissions.includes("read") &&
          session.identity.permissions.includes("write") &&
          session.identity.permissions.includes("check_run") &&
          session.identity.permissions.includes("workflow_execute") && (
            <button onClick={() => setProducer(session.identity.actor_id)}>
              Use my producer account
            </button>
          )}
        <label>
          Checking definition JSON
          <input
            aria-label="Output checking definition JSON"
            type="file"
            accept="application/json"
            onChange={(event) => {
              const file = event.target.files?.[0];
              event.target.value = "";
              if (file) void importDefinition(file);
            }}
          />
        </label>
        <p>
          Import a checking definition: format, columns, bounds and any
          signer/scanner references. Do not include a producer, credential or
          execution request in this file.
        </p>
        {definition && (
          <details open>
            <summary>Loaded output checking rules</summary>
            <p>
              Definition SHA-256 <code>{intakeHash(definition)}</code>
            </p>
            <pre>{JSON.stringify(definition, null, 2)}</pre>
          </details>
        )}
        <button disabled={!definition || !uuid(producer)} onClick={prepare}>
          Review output contract registration
        </button>
        <button
          onClick={() => {
            setBase(null);
            setDefinition(null);
            setProducer("");
          }}
        >
          Start a new output contract
        </button>
      </fieldset>
      <fieldset disabled={busy || !!pending}>
        <legend>Registered output contracts</legend>
        <button
          onClick={() =>
            perform(async () => {
              const result = await client.list();
              if (current()) setPage(result);
            })
          }
        >
          Refresh registered output contracts
        </button>
        {page && (
          <>
            {page.policies.length === 0 ? (
              <p>No active output contracts on this page.</p>
            ) : (
              <table>
                <caption>Active output contracts in this partner scope</caption>
                <thead>
                  <tr>
                    <th>Contract</th>
                    <th>Version</th>
                    <th>Producer</th>
                    <th>Format</th>
                    <th>Producer current</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {page.policies.map((row) => (
                    <tr key={row.reference.id}>
                      <td>
                        <code>{row.reference.id}</code>
                      </td>
                      <td>{row.reference.version}</td>
                      <td>
                        <code>{row.producer_id}</code>
                      </td>
                      <td>{row.kind}</td>
                      <td>{row.producer_current ? "Yes" : "No"}</td>
                      <td>
                        <button onClick={() => void inspect(row.reference)}>
                          Inspect output contract
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {page.next && (
              <button
                onClick={() =>
                  perform(async () => {
                    const result = await client.list(page.next);
                    if (current()) setPage(result);
                  })
                }
              >
                Next registered output contracts
              </button>
            )}
          </>
        )}
      </fieldset>
      {receipt && (
        <section aria-label="Original output policy command receipt">
          <h3>Original command receipt</h3>
          <p>
            {receipt.replayed
              ? "Recovered original receipt"
              : "Recorded receipt"}{" "}
            · <code>{receipt.resource.policy.id}</code> version{" "}
            {receipt.resource.policy.version} · recorded state{" "}
            {receipt.resource.policy.state}. This is not current status.
          </p>
        </section>
      )}
      {currentRecord && (
        <section aria-label="Current output contract">
          <h3>Current output contract</h3>
          <p>
            <code>{currentRecord.policy.id}</code> version{" "}
            {currentRecord.policy.version} · {currentRecord.policy.state} ·
            producer <code>{currentRecord.binding.producer.actor_id}</code> ·
            producer binding current:{" "}
            {currentRecord.producer_binding_current_at_observation
              ? "Yes"
              : "No"}
            .
          </p>
          <p>
            Definition SHA-256{" "}
            <code>{currentRecord.policy.definition_hash}</code>
          </p>
          <details>
            <summary>Current output checking rules</summary>
            <pre>
              {JSON.stringify(currentRecord.policy.definition, null, 2)}
            </pre>
          </details>
          <button
            disabled={busy || !!pending}
            onClick={() => {
              setBase(refOf(currentRecord));
              setProducer(currentRecord.binding.producer.actor_id);
              setDefinition(intakeDefinition(currentRecord.policy.definition));
              setReview(null);
            }}
          >
            Prepare a new output contract version
          </button>
          {currentRecord.policy.state === "output_active" && (
            <button
              disabled={busy || !!pending}
              onClick={() =>
                setReview(
                  outputPolicyMutation({
                    kind: "revoke",
                    key: operationKey(),
                    policy: refOf(currentRecord),
                    revision: currentRecord.policy.revision,
                  }),
                )
              }
            >
              Review output contract revocation
            </button>
          )}
        </section>
      )}
      <dialog
        ref={dialog}
        aria-labelledby="output-policy-command-heading"
        onCancel={(event) => {
          if (busy || pending) event.preventDefault();
          else setReview(null);
        }}
      >
        <h3 id="output-policy-command-heading" ref={heading} tabIndex={-1}>
          {review?.kind === "register"
            ? "Review output contract registration"
            : "Review output contract revocation"}
        </h3>
        {review && (
          <>
            {notice && <p role="status">{notice}</p>}
            <p>
              Request key <code>{review.key}</code>. No incoming policy, file,
              approval, release or delivery is changed by registration.
            </p>
            {review.kind === "register" ? (
              <>
                <p>
                  Producer <code>{review.body.producer_id}</code>.{" "}
                  {review.body.policy_id ? (
                    <>
                      Contract <code>{review.body.policy_id}</code>, expected
                      version {review.body.expected_version}.
                    </>
                  ) : (
                    "Create a new independent contract."
                  )}
                </p>
                <p>
                  Definition SHA-256{" "}
                  <code>{intakeHash(review.body.definition)}</code>
                </p>
                <pre>{JSON.stringify(review.body.definition, null, 2)}</pre>
              </>
            ) : (
              <p>
                Revoke <code>{review.policy.id}</code>, version{" "}
                {review.policy.version}, expected revision {review.revision},
                definition SHA-256 <code>{review.policy.hash}</code>. New use
                and availability under this contract will refuse.
              </p>
            )}
            <button disabled={busy} onClick={() => saveRecovery(review)}>
              Save exact output policy request
            </button>
            <button
              disabled={busy}
              onClick={() => void submit(pending ?? review)}
            >
              {pending
                ? "Retry exact output policy command"
                : review.kind === "register"
                  ? "Register reviewed output contract"
                  : "Revoke reviewed output contract"}
            </button>
            <button
              disabled={busy || !!pending}
              onClick={() => setReview(null)}
            >
              Cancel output policy review
            </button>
            {pending && (
              <button disabled={busy} onClick={() => setReview(null)}>
                Close review keeping request
              </button>
            )}
          </>
        )}
      </dialog>
    </section>
  );
}
