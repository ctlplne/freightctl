import { useEffect, useMemo, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { ApiError, type Account, type Session } from "./types";
import { ExchangeReceiveApi } from "./artifact-exchanges-api";
import {
  endpointParticipantFromAccount,
  endpointCommandBytes,
  type ExchangeBinding,
  type EndpointCommand,
  type EndpointRecord,
  type EndpointPage,
} from "./artifact-exchanges-types";

export function ArtifactEndpointAdmin({
  api,
  session,
  onError,
}: {
  api: Api;
  session: Session;
  onError: (error: unknown) => void;
}) {
  const client = useMemo(() => new ExchangeReceiveApi(api), [api, session]);
  const scope = {
    tenant: session.identity.tenant_id,
    partner: session.identity.partner_id,
    actor: session.identity.actor_id,
  };
  const [directory, setDirectory] = useState<EndpointPage>({
    endpoints: [],
    next: "",
  });
  const [accounts, setAccounts] = useState<{
    accounts: Account[];
    next?: string;
  }>({ accounts: [] });
  const [target, setTarget] = useState<EndpointRecord | null>(null);
  const [newID, setNewID] = useState(operationKey);
  const [recipient, setRecipient] = useState<ExchangeBinding | null>(null);
  const [senders, setSenders] = useState<ExchangeBinding[]>([]);
  const [pending, setPending] = useState<{
    command: EndpointCommand;
    key: string;
    previous?: EndpointRecord;
  } | null>(null);
  const [receipt, setReceipt] = useState<{
    endpoint: EndpointRecord;
    replayed: boolean;
  } | null>(null);
  const [busy, setBusy] = useState(false),
    [uncertain, setUncertain] = useState(false);
  const active = useRef<AbortController | null>(null),
    generation = useRef(0);
  useEffect(
    () => () => {
      generation.current++;
      active.current?.abort();
    },
    [client],
  );
  async function run(task: (signal: AbortSignal) => Promise<void>) {
    active.current?.abort();
    const controller = new AbortController(),
      serial = ++generation.current;
    active.current = controller;
    setBusy(true);
    try {
      await task(controller.signal);
    } catch (error) {
      if (!controller.signal.aborted && serial === generation.current)
        onError(error);
    } finally {
      if (!controller.signal.aborted && serial === generation.current)
        setBusy(false);
    }
  }
  function select(record: EndpointRecord | null) {
    setTarget(record);
    setNewID(operationKey());
    setRecipient(record?.definition.recipient ?? null);
    setSenders(record?.definition.senders ?? []);
    setPending(null);
    setReceipt(null);
    setUncertain(false);
  }
  function eligible(account: Account, role: "sender" | "recipient") {
    try {
      return endpointParticipantFromAccount(account, scope, role);
    } catch {
      return null;
    }
  }
  function review(operation: EndpointCommand["operation"]) {
    try {
      if (operation !== "create" && (!target || target.state !== "active"))
        throw new ApiError("invalid_artifact_exchange_contract", 400);
      const command: EndpointCommand = {
        operation,
        endpoint_id: target?.id ?? newID,
        expected_revision: target?.revision ?? 0,
      };
      if (operation !== "revoke") {
        if (!recipient)
          throw new ApiError("invalid_artifact_exchange_contract", 400);
        command.definition = {
          schema_version: 1,
          profile: "custody-https-poll-v1",
          recipient,
          senders: [...senders].sort((a, b) =>
            a.actor_id.localeCompare(b.actor_id),
          ),
        };
      }
      const copy = JSON.parse(
        new TextDecoder().decode(endpointCommandBytes(command, scope)),
      ) as EndpointCommand;
      setPending({
        command: copy,
        key: operationKey(),
        ...(target ? { previous: target } : {}),
      });
      setReceipt(null);
      setUncertain(false);
    } catch (error) {
      onError(error);
    }
  }
  const locked = busy || pending !== null;
  return (
    <section className="panel" aria-label="Exchange endpoint management">
      <p>
        Approve who may offer an artifact and who may receive it. Registration
        grants no file access, forwarding or execution permission. Only a root
        account manager can record these changes.
      </p>
      <div className="actions">
        <button
          disabled={busy}
          onClick={() =>
            run(async (signal) => {
              const p = await client.endpoints("", signal);
              if (!signal.aborted) setDirectory(p);
            })
          }
        >
          Check endpoint directory
        </button>
        <button
          disabled={busy || !directory.next}
          onClick={() =>
            run(async (signal) => {
              const p = await client.endpoints(directory.next, signal);
              if (!signal.aborted) setDirectory(p);
            })
          }
        >
          Next endpoint page
        </button>
        <button disabled={locked} onClick={() => select(null)}>
          New receive endpoint
        </button>
      </div>
      <table>
        <caption>Registered receive endpoints</caption>
        <thead>
          <tr>
            <th scope="col">Endpoint</th>
            <th scope="col">Revision</th>
            <th scope="col">State</th>
            <th scope="col">Action</th>
          </tr>
        </thead>
        <tbody>
          {directory.endpoints.map((e) => (
            <tr key={e.id}>
              <td>
                <code>{e.id}</code>
              </td>
              <td>{e.revision}</td>
              <td>{e.state}</td>
              <td>
                <button
                  disabled={locked}
                  onClick={() =>
                    run(async (signal) => {
                      const p = await client.endpoint(e.id, signal);
                      if (!signal.aborted) select(p);
                    })
                  }
                >
                  Manage {e.id.slice(0, 8)}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>{target ? "Selected receive endpoint" : "New receive endpoint"}</h2>
      <dl>
        <dt>Endpoint ID</dt>
        <dd>
          <code>{target?.id ?? newID}</code>
        </dd>
        <dt>Expected revision</dt>
        <dd>{target?.revision ?? 0}</dd>
        {target && (
          <>
            <dt>Current state</dt>
            <dd>{target.state}</dd>
            <dt>Current definition SHA256</dt>
            <dd>
              <code>{target.definition_hash}</code>
            </dd>
          </>
        )}
      </dl>
      <p>
        Bindings pin the account’s authority revision and the SHA256 of its
        namespace root. An account change can make a binding stale. Pick a
        freshly checked account to review its new binding; confirmation rechecks
        every participant on the server.
      </p>
      <div className="actions">
        <button
          disabled={locked}
          onClick={() =>
            run(async (signal) => {
              const p = await client.endpointAccounts("", signal);
              if (!signal.aborted) setAccounts(p);
            })
          }
        >
          Check participant accounts
        </button>
        <button
          disabled={locked || !accounts.next}
          onClick={() =>
            run(async (signal) => {
              const p = await client.endpointAccounts(accounts.next, signal);
              if (!signal.aborted) setAccounts(p);
            })
          }
        >
          Next account page
        </button>
      </div>
      <table>
        <caption>Participant accounts for this endpoint</caption>
        <thead>
          <tr>
            <th scope="col">Account</th>
            <th scope="col">State</th>
            <th scope="col">Recipient</th>
            <th scope="col">Allowed sender</th>
          </tr>
        </thead>
        <tbody>
          {accounts.accounts.map((account) => {
            const receiver = eligible(account, "recipient"),
              sender = eligible(account, "sender");
            return (
              <tr key={account.id}>
                <td>
                  {account.label}
                  <br />
                  <code>{account.id}</code>
                </td>
                <td>{account.state}</td>
                <td>
                  <button
                    disabled={locked || !receiver}
                    onClick={() => receiver && setRecipient(receiver)}
                  >
                    Receive as {account.id.slice(0, 8)}
                  </button>
                </td>
                <td>
                  <label>
                    <input
                      type="checkbox"
                      disabled={
                        locked ||
                        !sender ||
                        (!senders.some((s) => s.actor_id === account.id) &&
                          senders.length >= 128)
                      }
                      checked={senders.some((s) => s.actor_id === account.id)}
                      onChange={(e) => {
                        const checked = e.currentTarget.checked;
                        setSenders((old) =>
                          checked && sender
                            ? [
                                ...old.filter((s) => s.actor_id !== account.id),
                                sender,
                              ]
                            : old.filter((s) => s.actor_id !== account.id),
                        );
                      }}
                    />
                    Allow sender {account.id.slice(0, 8)}
                  </label>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <h3>Selected participant bindings</h3>
      <Binding label="Recipient" value={recipient} />
      {senders.map((s) => (
        <div key={s.actor_id}>
          <Binding label="Allowed sender" value={s} />
          <button
            disabled={locked}
            onClick={() =>
              setSenders((old) => old.filter((x) => x.actor_id !== s.actor_id))
            }
          >
            Remove sender {s.actor_id.slice(0, 8)}
          </button>
        </div>
      ))}
      <div className="actions">
        <button
          disabled={
            locked ||
            target?.state === "revoked" ||
            !recipient ||
            senders.length === 0
          }
          onClick={() => review(target ? "replace" : "create")}
        >
          Review endpoint {target ? "replacement" : "creation"}
        </button>
        <button
          disabled={locked || !target || target.state !== "active"}
          onClick={() => review("revoke")}
        >
          Review endpoint revocation
        </button>
      </div>
      {pending && (
        <section aria-label="Endpoint change review">
          <h2>Review exact endpoint change</h2>
          <p>
            Replacing or revoking the current endpoint stops its older receive
            views from authorizing future retrieval. It does not recall copies
            already retrieved. A revoked endpoint ID cannot be reused.
          </p>
          <dl>
            <dt>Operation</dt>
            <dd>{pending.command.operation}</dd>
            <dt>Endpoint</dt>
            <dd>
              <code>{pending.command.endpoint_id}</code>
            </dd>
            <dt>Required current revision</dt>
            <dd>{pending.command.expected_revision}</dd>
          </dl>
          {pending.command.definition && (
            <>
              <Binding
                label="Reviewed recipient"
                value={pending.command.definition.recipient}
              />
              {pending.command.definition.senders.map((s) => (
                <Binding key={s.actor_id} label="Reviewed sender" value={s} />
              ))}
            </>
          )}
          <p>
            The original retry key and exact command remain fixed until this
            review is cleared. A missing response leaves the outcome uncertain;
            use the same confirmation to recover it.
          </p>
          {uncertain && (
            <p role="status">
              No confirmed endpoint receipt. The server may have committed;
              retry this exact review to recover its result.
            </p>
          )}
          <div className="actions">
            <button
              disabled={busy}
              onClick={() =>
                run(async (signal) => {
                  setUncertain(true);
                  const result = await client.endpointCommand(
                    pending.command,
                    pending.key,
                    pending.previous,
                    signal,
                  );
                  if (!signal.aborted) {
                    setReceipt(result);
                    setUncertain(false);
                  }
                })
              }
            >
              Confirm or recover endpoint command
            </button>
            <button
              disabled={busy}
              onClick={() => {
                if (receipt) select(receipt.endpoint);
                else {
                  setPending(null);
                  setUncertain(false);
                }
              }}
            >
              {receipt
                ? "Use confirmed endpoint version"
                : "Clear review without undoing a possible commit"}
            </button>
          </div>
        </section>
      )}
      {receipt && (
        <section role="status" aria-label="Endpoint command receipt">
          <h2>Confirmed endpoint command</h2>
          <dl>
            <dt>Endpoint</dt>
            <dd>
              <code>{receipt.endpoint.id}</code>
            </dd>
            <dt>Committed revision</dt>
            <dd>{receipt.endpoint.revision}</dd>
            <dt>Committed state</dt>
            <dd>{receipt.endpoint.state}</dd>
            <dt>Definition SHA256</dt>
            <dd>
              <code>{receipt.endpoint.definition_hash}</code>
            </dd>
            <dt>Journal event</dt>
            <dd>
              <code>{receipt.endpoint.event_id}</code>
            </dd>
            <dt>Recovered original result</dt>
            <dd>{receipt.replayed ? "Yes" : "No"}</dd>
          </dl>
        </section>
      )}
    </section>
  );
}
function Binding({
  label,
  value,
}: {
  label: string;
  value: ExchangeBinding | null;
}) {
  return (
    <dl>
      <dt>{label}</dt>
      <dd>
        {value ? (
          <>
            <code>{value.actor_id}</code>; authority {value.authority_revision};
            root SHA256 <code>{value.root_policy_digest}</code>
          </>
        ) : (
          "Choose an eligible account."
        )}
      </dd>
    </dl>
  );
}
