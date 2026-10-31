import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { operationKey } from "./crypto";
import { OnboardingProbes } from "./onboarding-probes";
import { OnboardingExchange } from "./onboarding-exchange";
import { OnboardingTests } from "./onboarding-tests";
import { ApiError, type Session } from "./types";
import {
  asOnboardingDefinition,
  asOnboardingPage,
  asOnboardingResult,
  asOnboardingView,
  onboardingFingerprint,
  onboardingProtocols,
  type OnboardingCommand,
  type OnboardingContact,
  type OnboardingDefinition,
  type OnboardingPlan,
  type OnboardingRequirement,
} from "./onboarding-types";

const contact = (): OnboardingContact => ({
  id: operationKey(),
  name: "",
  role: "",
  email: "",
  phone: "",
});
const requirement = (): OnboardingRequirement => ({
  id: operationKey(),
  name: "",
  contact_id: "",
  direction: "",
  protocol: "",
  required_receipt: "",
  receipt_contract: "",
  notes: "",
});
const empty = (): OnboardingDefinition => ({
  schema_version: 1,
  name: "",
  contacts: [contact()],
  requirements: [requirement()],
});
const receipts: Record<string, string> = {
  transport: "Remote transport acceptance",
  integrity: "Verified exact bytes",
  business: "Downstream business acceptance",
};

export function Onboarding({
  api,
  session,
  refresh,
  onError,
  onConfirmed,
}: {
  api: Api;
  session: Session;
  refresh: number;
  onError: (error: unknown) => void;
  onConfirmed: (message?: string) => void;
}) {
  const [page, setPage] = useState<ReturnType<typeof asOnboardingPage>>({
    plans: [],
    authority_revision: 0,
  });
  const [after, setAfter] = useState(""),
    [reload, setReload] = useState(0);
  const [definition, setDefinition] = useState<OnboardingDefinition>(empty);
  const [selected, setSelected] = useState<OnboardingPlan | null>(null),
    [authority, setAuthority] = useState(0);
  const [pending, setPending] = useState<OnboardingCommand | null>(null),
    [key, setKey] = useState("");
  const [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(false),
    [blocked, setBlocked] = useState(false);
  const [failure, setFailure] = useState(""),
    [notice, setNotice] = useState("");
  const dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null);
  const alive = useRef(true),
    detail = useRef<AbortController | null>(null);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      detail.current?.abort();
    };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    api
      .request(
        `${api.prefix}/onboarding-plans?limit=50&after=${after}`,
        { signal: controller.signal },
        asOnboardingPage,
      )
      .then((p) => {
        if (!controller.signal.aborted) {
          setPage(p);
          if (!selected) setAuthority(p.authority_revision);
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted) onError(error);
      });
    return () => controller.abort();
  }, [api, after, reload, refresh]);
  useEffect(() => {
    if (pending) {
      dialog.current?.showModal();
      title.current?.focus();
    } else dialog.current?.close();
  }, [pending]);
  async function open(id: string) {
    if (busy || loading) return;
    detail.current?.abort();
    const controller = new AbortController();
    detail.current = controller;
    setLoading(true);
    setFailure("");
    setNotice("");
    try {
      const v = await api.request(
        `${api.prefix}/onboarding-plans/${id}`,
        { signal: controller.signal },
        asOnboardingView,
      );
      if (!alive.current || controller.signal.aborted) return;
      if (v.plan.id !== id) throw new ApiError("invalid_server_response", 502);
      setSelected(v.plan);
      setDefinition(v.plan.definition);
      setAuthority(v.authority_revision);
    } catch (error) {
      if (alive.current && !controller.signal.aborted) onError(error);
    } finally {
      if (alive.current && !controller.signal.aborted) setLoading(false);
    }
  }
  function fresh() {
    if (busy || loading) return;
    setSelected(null);
    setDefinition(empty());
    setAuthority(page.authority_revision);
    setFailure("");
    setNotice("");
  }
  function editContact(
    index: number,
    field: keyof OnboardingContact,
    value: string,
  ) {
    setDefinition((d) => ({
      ...d,
      contacts: d.contacts.map((c, i) =>
        i === index ? { ...c, [field]: value } : c,
      ),
    }));
  }
  function editRequirement(
    index: number,
    field: keyof OnboardingRequirement,
    value: string,
  ) {
    setDefinition((d) => ({
      ...d,
      requirements: d.requirements.map((r, i) =>
        i === index ? { ...r, [field]: value } : r,
      ),
    }));
  }
  function review() {
    if (busy || loading || !authority) return;
    try {
      const d = asOnboardingDefinition(definition);
      setPending({
        plan_id: selected?.id ?? operationKey(),
        expected_version: selected?.version ?? 0,
        expected_authority_revision: authority,
        definition: d,
      });
      setKey(operationKey());
      setFailure("");
      setNotice("");
      setBlocked(false);
    } catch {
      setFailure(
        "Check names, contact ownership and exchange choices. Use NFC text without extra spaces, at most 128 UTF-8 bytes per name and 24 KiB for this draft. No credentials belong in these notes.",
      );
    }
  }
  async function save() {
    if (!pending || busy || blocked) return;
    const frozen = pending;
    setBusy(true);
    setFailure("");
    try {
      const plan = await api.request(
        `${api.prefix}/onboarding-plans`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": key,
          },
          body: JSON.stringify(frozen),
        },
        (value) => asOnboardingResult(value, frozen, session.identity.actor_id),
      );
      if (!alive.current) return;
      setSelected(plan);
      setDefinition(plan.definition);
      setPending(null);
      setReload((v) => v + 1);
      setNotice(
        `Draft version ${plan.version} saved. Protocol tests, exchange evidence, approval and activation remain required.`,
      );
      onConfirmed();
    } catch (error) {
      if (!alive.current) return;
      const definitive =
        error instanceof ApiError && error.status >= 400 && error.status < 500;
      setBlocked(definitive);
      setFailure(
        definitive
          ? "The server refused this draft. Cancel, reopen its latest version and review current access before saving again."
          : "Saving was not confirmed. Retry this same frozen draft to recover its original receipt. Cancel does not undo a version already saved by the server.",
      );
      onError(error);
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  function download() {
    if (!selected) return;
    const url = URL.createObjectURL(
      new Blob(
        [JSON.stringify({ schema_version: 1, plan: selected }, null, 2)],
        { type: "application/json" },
      ),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `freightctl-onboarding-${selected.id}-v${selected.version}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <section
      className="panel onboarding-plan"
      aria-label="Partner onboarding plans"
    >
      <p>
        Record the people responsible for an exchange and what the partner
        requires. A saved draft does not configure a destination, verify a
        transfer, grant permissions or activate production.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Draft</th>
              <th scope="col">Version</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {page.plans.map((p) => (
              <tr key={p.id}>
                <td>
                  {p.name}
                  <div>
                    <code>{p.id}</code>
                  </div>
                </td>
                <td>{p.version} · draft</td>
                <td>
                  <button
                    className="secondary"
                    disabled={loading || busy}
                    onClick={() => void open(p.id)}
                  >
                    Open {p.name}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="actions">
        <button
          className="secondary"
          disabled={!after || loading || busy}
          onClick={() => setAfter("")}
        >
          First drafts page
        </button>
        <button
          className="secondary"
          disabled={!page.next || loading || busy}
          onClick={() => setAfter(page.next ?? "")}
        >
          Next drafts page
        </button>
        <button
          className="secondary"
          disabled={loading || busy}
          onClick={fresh}
        >
          New onboarding draft
        </button>
      </div>
      {notice && <p role="status">{notice}</p>}
      {loading && <p role="status">Reading the latest saved version…</p>}
      {selected && (
        <div className="signature-box">
          <p>
            Editing draft <code>{selected.id}</code> from version{" "}
            {selected.version}. Saving creates a new version; earlier versions
            and receipts remain.
          </p>
          <p>
            Saved definition SHA-256: <code>{selected.definition_hash}</code>
          </p>
          <button className="secondary" onClick={download}>
            Download saved draft JSON
          </button>
          <p>
            This download contains contact details. Keep it in a protected
            location.
          </p>
        </div>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          review();
        }}
      >
        <h2>
          {selected ? "Revise onboarding draft" : "Prepare onboarding draft"}
        </h2>
        <label htmlFor="onboarding-name">Draft name</label>
        <input
          id="onboarding-name"
          required
          maxLength={128}
          value={definition.name}
          onChange={(e) =>
            setDefinition({ ...definition, name: e.target.value })
          }
        />
        <h3>Responsible contacts</h3>
        <p>
          A responsibility describes a person’s job. It does not grant an
          account any access.
        </p>
        {definition.contacts.map((c, index) => (
          <fieldset key={c.id}>
            <legend>Contact {index + 1}</legend>
            <label htmlFor={`contact-name-${index}`}>
              Contact name {index + 1}
            </label>
            <input
              id={`contact-name-${index}`}
              required
              maxLength={128}
              value={c.name}
              onChange={(e) => editContact(index, "name", e.target.value)}
            />
            <label htmlFor={`contact-role-${index}`}>
              Responsibility {index + 1}
            </label>
            <input
              id={`contact-role-${index}`}
              required
              maxLength={64}
              value={c.role}
              onChange={(e) => editContact(index, "role", e.target.value)}
            />
            <label htmlFor={`contact-email-${index}`}>Email {index + 1}</label>
            <input
              id={`contact-email-${index}`}
              required
              type="email"
              maxLength={254}
              value={c.email}
              onChange={(e) => editContact(index, "email", e.target.value)}
            />
            <label htmlFor={`contact-phone-${index}`}>
              Phone {index + 1} · optional
            </label>
            <input
              id={`contact-phone-${index}`}
              maxLength={64}
              value={c.phone}
              onChange={(e) => editContact(index, "phone", e.target.value)}
            />
            <button
              type="button"
              className="secondary"
              disabled={
                definition.contacts.length === 1 ||
                definition.requirements.some((r) => r.contact_id === c.id)
              }
              onClick={() =>
                setDefinition((d) => ({
                  ...d,
                  contacts: d.contacts.filter((v) => v.id !== c.id),
                }))
              }
            >
              Remove contact {index + 1}
            </button>
            {definition.requirements.some((r) => r.contact_id === c.id) && (
              <p>
                Choose another responsible contact on its requirements before
                removing this person.
              </p>
            )}
          </fieldset>
        ))}
        <button
          type="button"
          className="secondary"
          disabled={definition.contacts.length >= 64}
          onClick={() =>
            setDefinition((d) => ({
              ...d,
              contacts: [...d.contacts, contact()],
            }))
          }
        >
          Add responsible contact
        </button>
        <h3>Exchange requirements</h3>
        {definition.requirements.map((r, index) => (
          <fieldset key={r.id}>
            <legend>Requirement {index + 1}</legend>
            <label htmlFor={`requirement-name-${index}`}>
              Requirement name {index + 1}
            </label>
            <input
              id={`requirement-name-${index}`}
              required
              maxLength={128}
              value={r.name}
              onChange={(e) => editRequirement(index, "name", e.target.value)}
            />
            <label htmlFor={`requirement-contact-${index}`}>
              Responsible contact {index + 1}
            </label>
            <select
              id={`requirement-contact-${index}`}
              required
              value={r.contact_id}
              onChange={(e) =>
                editRequirement(index, "contact_id", e.target.value)
              }
            >
              <option value="">Choose a contact</option>
              {definition.contacts.map((c, i) => (
                <option key={c.id} value={c.id}>
                  {c.name || `Contact ${i + 1}`}
                </option>
              ))}
            </select>
            <label htmlFor={`requirement-direction-${index}`}>
              Direction {index + 1}
            </label>
            <select
              id={`requirement-direction-${index}`}
              required
              value={r.direction}
              onChange={(e) =>
                editRequirement(index, "direction", e.target.value)
              }
            >
              <option value="">Choose a direction</option>
              <option value="send">Send to partner</option>
              <option value="receive">Receive from partner</option>
            </select>
            <label htmlFor={`requirement-protocol-${index}`}>
              Required protocol {index + 1}
            </label>
            <select
              id={`requirement-protocol-${index}`}
              required
              value={r.protocol}
              onChange={(e) =>
                editRequirement(index, "protocol", e.target.value)
              }
            >
              <option value="">Choose the required protocol</option>
              {onboardingProtocols.map((p) => (
                <option key={p} value={p}>
                  {p.toUpperCase()}
                </option>
              ))}
            </select>
            <p>
              A recorded protocol choice is a requirement, not evidence that a
              connection is configured or qualified.
            </p>
            <label htmlFor={`requirement-receipt-${index}`}>
              Required delivery evidence {index + 1}
            </label>
            <select
              id={`requirement-receipt-${index}`}
              required
              value={r.required_receipt}
              onChange={(e) =>
                editRequirement(index, "required_receipt", e.target.value)
              }
            >
              <option value="">Choose the required evidence</option>
              {Object.entries(receipts).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <label htmlFor={`requirement-contract-${index}`}>
              Receiver agreement reference {index + 1} · optional in a draft
            </label>
            <textarea
              id={`requirement-contract-${index}`}
              maxLength={512}
              value={r.receipt_contract}
              onChange={(e) =>
                editRequirement(index, "receipt_contract", e.target.value)
              }
            />
            {r.required_receipt === "business" && !r.receipt_contract && (
              <p>
                Business acceptance still needs a receiver agreement. Transport
                success cannot establish it.
              </p>
            )}
            <label htmlFor={`requirement-notes-${index}`}>
              Requirement notes {index + 1} · no credentials
            </label>
            <textarea
              id={`requirement-notes-${index}`}
              maxLength={2048}
              value={r.notes}
              onChange={(e) => editRequirement(index, "notes", e.target.value)}
            />
            <button
              type="button"
              className="secondary"
              disabled={definition.requirements.length === 1}
              onClick={() =>
                setDefinition((d) => ({
                  ...d,
                  requirements: d.requirements.filter((v) => v.id !== r.id),
                }))
              }
            >
              Remove requirement {index + 1}
            </button>
          </fieldset>
        ))}
        <button
          type="button"
          className="secondary"
          disabled={definition.requirements.length >= 64}
          onClick={() =>
            setDefinition((d) => ({
              ...d,
              requirements: [...d.requirements, requirement()],
            }))
          }
        >
          Add exchange requirement
        </button>
        <p>
          Each draft is bounded to 24 KiB and 64 contacts/requirements.
          Additional exchanges can use another draft. Save credentials through
          their protected account/key controls.
        </p>
        {!pending && failure && <p role="alert">{failure}</p>}
        <button
          className="primary"
          type="submit"
          disabled={busy || loading || !authority}
        >
          Review onboarding draft
        </button>
      </form>
      {selected &&
        session.identity.permissions.includes("connections_manage") && (
          <OnboardingProbes
            key={selected.id + ":" + selected.version}
            api={api}
            session={session}
            plan={selected}
            authority={authority}
            onError={onError}
            onConfirmed={() =>
              onConfirmed(
                "Connectivity probe outcome recorded. A file exchange, approval and activation remain required.",
              )
            }
          />
        )}
      {selected &&
        session.identity.permissions.includes("connections_manage") &&
        session.identity.permissions.includes("read") &&
        ["workflow_manage", "workflow_approve", "workflow_execute"].some((p) =>
          session.identity.permissions.includes(p),
        ) && (
          <>
            <OnboardingTests
              key={"tests:" + selected.id + ":" + selected.version}
              api={api}
              session={session}
              plan={selected}
              authority={authority}
              onError={onError}
            />
            <OnboardingExchange
              key={selected.id + ":" + selected.version}
              api={api}
              plan={selected}
              authority={authority}
              onError={onError}
            />
          </>
        )}
      <dialog
        ref={dialog}
        aria-labelledby="onboarding-review-title"
        onCancel={(event) => {
          if (busy) event.preventDefault();
          else {
            setPending(null);
            setReload((v) => v + 1);
          }
        }}
      >
        <h2 id="onboarding-review-title" ref={title} tabIndex={-1}>
          Review onboarding draft
        </h2>
        {pending && (
          <>
            <p>
              Save these contacts and requirements as draft version{" "}
              {pending.expected_version + 1}. This decision does not approve a
              workflow, send a file or activate production.
            </p>
            <dl className="facts">
              <dt>Draft name</dt>
              <dd>{pending.definition.name}</dd>
              <dt>Plan ID</dt>
              <dd>
                <code>{pending.plan_id}</code>
              </dd>
              <dt>Previous version</dt>
              <dd>{pending.expected_version}</dd>
              <dt>Reviewed account access revision</dt>
              <dd>{pending.expected_authority_revision}</dd>
              <dt>Definition SHA-256</dt>
              <dd>
                <code>{onboardingFingerprint(pending.definition)}</code>
              </dd>
            </dl>
            <h3>Contacts in this review</h3>
            {pending.definition.contacts.map((c) => (
              <div className="signature-box" key={c.id}>
                <p>
                  {c.name} · {c.role}
                </p>
                <p>
                  {c.email}
                  {c.phone && ` · ${c.phone}`}
                </p>
                <code>{c.id}</code>
              </div>
            ))}
            <h3>Requirements in this review</h3>
            {pending.definition.requirements.map((r) => (
              <div className="signature-box" key={r.id}>
                <p>
                  {r.name} · {r.direction} · {r.protocol.toUpperCase()}
                </p>
                <p>
                  Responsible:{" "}
                  {
                    pending.definition.contacts.find(
                      (c) => c.id === r.contact_id,
                    )?.name
                  }
                </p>
                <p>Required evidence: {receipts[r.required_receipt]}</p>
                <p>{r.receipt_contract || "Receiver agreement not recorded"}</p>
                <p className="requirement-notes">{r.notes}</p>
              </div>
            ))}
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                className="primary"
                disabled={busy || blocked}
                onClick={() => void save()}
              >
                {busy
                  ? "Saving draft…"
                  : failure
                    ? "Retry reviewed draft"
                    : "Save reviewed draft"}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => {
                  setPending(null);
                  setReload((v) => v + 1);
                }}
              >
                Cancel review
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
