import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { newAccountCredential, operationKey } from "./crypto";
import {
  ApiError,
  asPartnerPage,
  asPartnerResult,
  type Partner,
  type PartnerCommand,
  type Session,
} from "./types";

export function Partners({
  api,
  session,
  refresh,
  onError,
  onConfirmed,
}: {
  api: Api;
  session: Session;
  refresh: number;
  onError: (e: unknown) => void;
  onConfirmed: () => void;
}) {
  const [page, setPage] = useState<{
      partners: Partner[];
      next?: string;
      authority_revision?: number;
      tenant_administration_revision?: number;
    }>({
      partners: [],
    }),
    [after, setAfter] = useState(""),
    [reload, setReload] = useState(0);
  const [label, setLabel] = useState(""),
    [adminLabel, setAdminLabel] = useState(""),
    [grants, setGrants] = useState<string[]>(
      [...session.identity.permissions].sort(),
    );
  const [pending, setPending] = useState<{
      command: PartnerCommand;
      key: string;
    } | null>(null),
    [busy, setBusy] = useState(false),
    [downloaded, setDownloaded] = useState(false),
    [saved, setSaved] = useState(false),
    [failure, setFailure] = useState(""),
    [blocked, setBlocked] = useState(false),
    [created, setCreated] = useState<Partner | null>(null);
  const credential = useRef<Uint8Array | null>(null),
    dialog = useRef<HTMLDialogElement>(null),
    title = useRef<HTMLHeadingElement>(null),
    alive = useRef(true);
  const clear = () => {
    credential.current?.fill(0);
    credential.current = null;
  };
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      clear();
    };
  }, []);
  useEffect(() => {
    const c = new AbortController();
    api
      .request(
        `${api.prefix}/partner-directory?limit=50&after=${after}`,
        { signal: c.signal },
        asPartnerPage,
      )
      .then((v) => {
        if (!c.signal.aborted) setPage(v);
      })
      .catch((e) => {
        if (!c.signal.aborted) onError(e);
      });
    return () => c.abort();
  }, [api, after, reload, refresh]);
  useEffect(() => {
    if (pending) {
      dialog.current?.showModal();
      title.current?.focus();
    } else dialog.current?.close();
  }, [pending]);
  function review() {
    if (busy) return;
    if (!page.authority_revision || !page.tenant_administration_revision) {
      setFailure(
        "Refresh the tenant directory to read current enrollment authority.",
      );
      return;
    }
    for (const text of [label, adminLabel])
      if (
        !text ||
        text !== text.trim() ||
        text !== text.normalize("NFC") ||
        new TextEncoder().encode(text).length > 128 ||
        /[\u0000-\u001f\u007f-\u009f]/.test(text)
      ) {
        setFailure(
          "Enter names of at most 128 UTF-8 bytes, without extra spaces or control characters.",
        );
        return;
      }
    if (!grants.includes("admin") || !grants.includes("accounts_manage")) {
      setFailure(
        "The first administrator needs admin and accounts_manage. Select the remaining grants deliberately.",
      );
      return;
    }
    clear();
    const c = newAccountCredential();
    credential.current = c.bytes;
    setDownloaded(false);
    setSaved(false);
    setBlocked(false);
    setFailure("");
    setCreated(null);
    setPending({
      key: operationKey(),
      command: {
        expected_authority_revision: page.authority_revision ?? 0,
        expected_tenant_revision: page.tenant_administration_revision ?? 0,
        partner_id: operationKey(),
        admin_id: operationKey(),
        label,
        admin_label: adminLabel,
        permissions: [...grants].sort(),
        credential_sha256: c.fingerprint,
      },
    });
  }
  function download(bytes: Uint8Array, name: string, type: string) {
    const url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function apply() {
    if (!pending || busy || blocked || !saved) return;
    const frozen = pending;
    setBusy(true);
    setFailure("");
    try {
      const p = await api.request(
        `${api.prefix}/partner-directory`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": frozen.key,
          },
          body: JSON.stringify(frozen.command),
        },
        (v) => asPartnerResult(v, frozen.command),
      );
      if (!alive.current) return;
      clear();
      setPending(null);
      setCreated(p);
      setLabel("");
      setAdminLabel("");
      onConfirmed();
      setReload((v) => v + 1);
    } catch (e) {
      if (alive.current) {
        const definitive =
          e instanceof ApiError && e.status >= 400 && e.status < 500;
        setBlocked(definitive);
        setFailure(
          definitive
            ? "The server refused this enrollment. Cancel, refresh the directory and review current authority before trying again."
            : "Enrollment was not confirmed. Retry this same reviewed command to recover its original receipt. Cancel keeps any enrollment already saved by the server.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <section
      className="panel partner-directory"
      aria-label="Tenant partner directory"
    >
      <p>
        This account has explicit tenant directory authority. Enroll a partner
        and its first administrator. File and account actions use credentials
        inside each partner’s workspace.
      </p>
      {created && (
        <div className="signature-box" role="status">
          <h2>Partner enrolled</h2>
          <p>
            {created.label} · <code>{created.id}</code>
          </p>
          <p>
            The saved credential belongs to this partner’s first administrator.
            Download its workspace IDs for sign-in.
          </p>
          <button
            className="secondary"
            onClick={() =>
              download(
                new TextEncoder().encode(
                  JSON.stringify(
                    {
                      schema_version: 1,
                      tenant_id: session.identity.tenant_id,
                      partner_id: created.id,
                    },
                    null,
                    2,
                  ),
                ),
                `freightctl-${created.id}-workspace.json`,
                "application/json",
              )
            }
          >
            Download partner workspace
          </button>
        </div>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Partner</th>
              <th scope="col">Partner ID</th>
              <th scope="col">Initial administrator</th>
            </tr>
          </thead>
          <tbody>
            {page.partners.map((p) => (
              <tr key={p.id}>
                <td>{p.label || "Earlier enrollment"}</td>
                <td>
                  <code>{p.id}</code>
                </td>
                <td>
                  {p.admin_label ?? "Metadata unavailable"}
                  {p.admin_id && (
                    <div>
                      <code>{p.admin_id}</code>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="actions">
        <button
          className="secondary"
          disabled={!after}
          onClick={() => setAfter("")}
        >
          First directory page
        </button>
        <button
          className="secondary"
          disabled={!page.next}
          onClick={() => setAfter(page.next ?? "")}
        >
          Next directory page
        </button>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          review();
        }}
      >
        <h2>Enroll a partner</h2>
        <label htmlFor="partner-label">Partner name</label>
        <input
          id="partner-label"
          required
          maxLength={128}
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <label htmlFor="partner-admin-label">First administrator name</label>
        <input
          id="partner-admin-label"
          required
          maxLength={128}
          value={adminLabel}
          onChange={(e) => setAdminLabel(e.target.value)}
        />
        <fieldset className="account-grants">
          <legend>First administrator grants</legend>
          <p>
            These grants apply inside the new partner. Tenant directory
            authority requires a separate approval.
          </p>
          {[...session.identity.permissions].sort().map((p) => (
            <label key={p}>
              <input
                type="checkbox"
                checked={grants.includes(p)}
                onChange={(e) =>
                  setGrants((old) =>
                    e.target.checked ? [...old, p] : old.filter((x) => x !== p),
                  )
                }
              />
              {p}
            </label>
          ))}
        </fieldset>
        {!pending && failure && <p role="alert">{failure}</p>}
        <button
          className="primary"
          type="submit"
          disabled={
            busy ||
            !page.authority_revision ||
            !page.tenant_administration_revision
          }
        >
          Review partner enrollment
        </button>
      </form>
      <dialog
        ref={dialog}
        aria-labelledby="partner-review-title"
        onCancel={(e) => {
          if (busy) e.preventDefault();
          else {
            clear();
            setPending(null);
          }
        }}
      >
        <h2 id="partner-review-title" ref={title} tabIndex={-1}>
          Review partner enrollment
        </h2>
        {pending && (
          <>
            <p>
              Create this partner and the reviewed administrator together. The
              server checks current tenant authority and records both enrollment
              events with one receipt.
            </p>
            <dl className="facts">
              <dt>Partner name</dt>
              <dd>{pending.command.label}</dd>
              <dt>Partner ID</dt>
              <dd>
                <code>{pending.command.partner_id}</code>
              </dd>
              <dt>First administrator</dt>
              <dd>{pending.command.admin_label}</dd>
              <dt>Administrator ID</dt>
              <dd>
                <code>{pending.command.admin_id}</code>
              </dd>
              <dt>Credential SHA-256</dt>
              <dd>
                <code>{pending.command.credential_sha256}</code>
              </dd>
              <dt>Virtual root</dt>
              <dd>/</dd>
              <dt>Reviewed credential revision</dt>
              <dd>{pending.command.expected_authority_revision}</dd>
              <dt>Reviewed tenant grant revision</dt>
              <dd>{pending.command.expected_tenant_revision}</dd>
              <dt>Grants</dt>
              <dd>{pending.command.permissions.join(", ")}</dd>
            </dl>
            <button
              className="secondary"
              disabled={busy || !credential.current}
              onClick={() => {
                if (credential.current) {
                  download(
                    credential.current,
                    `freightctl-${pending.command.admin_id}.token`,
                    "application/octet-stream",
                  );
                  setDownloaded(true);
                }
              }}
            >
              Download partner credential
            </button>
            <label className="account-confirm">
              <input
                type="checkbox"
                disabled={!downloaded || busy}
                checked={saved}
                onChange={(e) => setSaved(e.target.checked)}
              />
              I saved the partner credential in a protected location
            </label>
            {failure && <p role="alert">{failure}</p>}
            <div className="actions">
              <button
                className="primary"
                disabled={busy || blocked || !saved}
                onClick={() => void apply()}
              >
                {busy
                  ? "Enrolling…"
                  : failure
                    ? "Retry reviewed enrollment"
                    : "Enroll reviewed partner"}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => {
                  clear();
                  setPending(null);
                }}
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </dialog>
    </section>
  );
}
