import { useEffect, useRef, useState } from "react";
import { Api } from "./api";
import { newAccountCredential, operationKey } from "./crypto";
import {
  ApiError,
  asAccount,
  asAccountPage,
  object,
  type Account,
  type AccountCommand,
  type Session,
} from "./types";

export function Accounts({
  api,
  session,
  refresh,
  onError,
}: {
  api: Api;
  session: Session;
  refresh: number;
  onError: (e: unknown) => void;
}) {
  const [failure, setFailure] = useState("");
  const [page, setPage] = useState<{ accounts: Account[]; next?: string }>({
    accounts: [],
  });
  const [after, setAfter] = useState(""),
    [reload, setReload] = useState(0),
    [target, setTarget] = useState<Account | null>(null);
  const [label, setLabel] = useState(""),
    [root, setRoot] = useState("/"),
    [expires, setExpires] = useState(""),
    [grants, setGrants] = useState<string[]>(["read", "list"]);
  const [pending, setPending] = useState<{
      command: AccountCommand;
      key: string;
    } | null>(null),
    [busy, setBusy] = useState(false),
    [downloaded, setDownloaded] = useState(false),
    [saved, setSaved] = useState(false),
    [notice, setNotice] = useState("");
  const credential = useRef<Uint8Array | null>(null),
    dialog = useRef<HTMLDialogElement>(null),
    alive = useRef(true);
  const clearCredential = () => {
    credential.current?.fill(0);
    credential.current = null;
  };
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      clearCredential();
    };
  }, []);
  useEffect(() => {
    const c = new AbortController();
    api
      .request(
        `${api.prefix}/accounts?limit=50&after=${after}`,
        { signal: c.signal },
        asAccountPage,
      )
      .then((p) => {
        if (!c.signal.aborted) setPage(p);
      })
      .catch((e) => {
        if (!c.signal.aborted) onError(e);
      });
    return () => c.abort();
  }, [api, after, reload, refresh]);
  useEffect(() => {
    if (pending) dialog.current?.showModal();
    else dialog.current?.close();
  }, [pending]);
  const select = (a: Account | null) => {
    setTarget(a);
    setLabel(a?.label ?? "");
    setRoot(a?.namespace_root ?? "/");
    setExpires(a?.expires_at ?? "");
    setGrants(a?.permissions ?? ["read", "list"]);
    setNotice("");
  };
  const review = (operation: AccountCommand["operation"]) => {
    clearCredential();
    setFailure("");
    setDownloaded(false);
    setSaved(false);
    setNotice("");
    const command: AccountCommand = {
      operation,
      account_id: target?.id ?? operationKey(),
      expected_revision: target?.revision ?? 0,
    };
    if (operation === "create" || operation === "update") {
      if (expires && !Number.isFinite(Date.parse(expires))) {
        setNotice("Enter an ISO timestamp, for example 2027-01-01T00:00:00Z.");
        return;
      }
      command.policy = {
        label,
        namespace_root: root,
        permissions: [...grants].sort(),
        expires_at: expires ? new Date(expires).toISOString() : null,
      };
    }
    if (operation === "create" || operation === "rotate") {
      const c = newAccountCredential();
      credential.current = c.bytes;
      command.credential_sha256 = c.fingerprint;
    }
    setPending({ command, key: operationKey() });
  };
  const cancel = () => {
    if (busy) return;
    clearCredential();
    setPending(null);
  };
  const download = () => {
    if (!credential.current || !pending) return;
    const url = URL.createObjectURL(
      new Blob([credential.current.slice().buffer], {
        type: "application/octet-stream",
      }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `freightctl-${pending.command.account_id}.token`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setDownloaded(true);
  };
  const apply = async () => {
    if (!pending || busy || (credential.current && !saved)) return;
    setBusy(true);
    try {
      const r = await api.request(
        `${api.prefix}/accounts/commands`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": pending.key,
          },
          body: JSON.stringify(pending.command),
        },
        (v) => asAccount(object(v).account),
      );
      if (!alive.current) return;
      clearCredential();
      setPending(null);
      select(r);
      setNotice(
        `Saved account revision ${r.revision}. Refresh reads current state; retry receipts describe the original command.`,
      );
      setReload((v) => v + 1);
    } catch (e) {
      if (alive.current) {
        setFailure(
          e instanceof ApiError && e.status === 409
            ? "The account changed. Cancel, refresh and review its current revision before applying a new command."
            : "The change was not confirmed. Retry this reviewed command to recover its saved receipt, or cancel and refresh current state.",
        );
        onError(e);
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  const locked =
    target?.state === "revoked" || target?.id === session.identity.actor_id;
  return (
    <section className="panel" aria-label="Account management">
      <p>
        Create and manage accounts inside this partner. A credential proves
        identity; its grants and virtual root limit what that identity can do.
        Existing jobs keep their original authority binding.
      </p>
      <p>
        Bootstrap enrollment still needs the local administrator. Invitations,
        SSO and MFA remain unavailable.
      </p>
      {notice && <p role="status">{notice}</p>}
      <div className="actions">
        <button onClick={() => select(null)}>New account</button>
        <button disabled={!after} onClick={() => setAfter("")}>
          First page
        </button>
        <button disabled={!page.next} onClick={() => setAfter(page.next ?? "")}>
          Next page
        </button>
      </div>
      <table>
        <caption>Accounts in this partner</caption>
        <thead>
          <tr>
            <th scope="col">Account</th>
            <th scope="col">State</th>
            <th scope="col">Revision</th>
            <th scope="col">Action</th>
          </tr>
        </thead>
        <tbody>
          {page.accounts.map((a) => (
            <tr key={a.id}>
              <td>
                {a.label || "Unlabeled account"}
                <br />
                <code>{a.id}</code>
              </td>
              <td>{a.state}</td>
              <td>{a.revision}</td>
              <td>
                <button
                  onClick={() => select(a)}
                  aria-label={`Review ${a.label || a.id}`}
                >
                  Review
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          review(target ? "update" : "create");
        }}
      >
        <h2>{target ? "Account policy" : "Create account"}</h2>
        {target && (
          <p>
            <code>{target.id}</code> · revision {target.revision} · authority{" "}
            {target.authority_revision} · {target.state}
          </p>
        )}
        <fieldset disabled={locked || busy}>
          <legend>Access policy</legend>
          <label>
            Account label
            <input
              value={label}
              maxLength={128}
              onChange={(e) => setLabel(e.target.value)}
            />
          </label>
          <label>
            Virtual root
            <input
              required
              value={root}
              onChange={(e) => setRoot(e.target.value)}
            />
          </label>
          <label>
            Expires at (ISO timestamp; blank means no expiry)
            <input
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
              placeholder="2027-01-01T00:00:00Z"
            />
          </label>
          <fieldset className="account-grants">
            <legend>Permissions</legend>
            {session.identity.permissions.map((p) => (
              <label key={p}>
                <input
                  type="checkbox"
                  checked={grants.includes(p)}
                  onChange={(e) =>
                    setGrants((g) =>
                      e.target.checked ? [...g, p] : g.filter((v) => v !== p),
                    )
                  }
                />
                {p}
              </label>
            ))}
          </fieldset>
          <button type="submit">
            {target ? "Review policy change" : "Review new account"}
          </button>
          {target && (
            <>
              <button type="button" onClick={() => review("rotate")}>
                Review credential rotation
              </button>
              <button type="button" onClick={() => review("revoke")}>
                Review revocation
              </button>
            </>
          )}
        </fieldset>
        {locked && (
          <p>
            This account is revoked or belongs to your current session. Another
            authorized manager must review changes.
          </p>
        )}
      </form>
      <dialog
        ref={dialog}
        aria-labelledby="account-review-title"
        onCancel={(e) => {
          e.preventDefault();
          cancel();
        }}
      >
        {failure && <p role="alert">{failure}</p>}
        <h2 id="account-review-title">
          Review account {pending?.command.operation}
        </h2>
        <p>
          Target <code>{pending?.command.account_id}</code>, expected revision{" "}
          {pending?.command.expected_revision}. A changed revision requires a
          new review.
        </p>
        {pending?.command.policy && (
          <>
            <p>
              Label: {pending.command.policy.label || "Unlabeled"}
              <br />
              Virtual root: <code>{pending.command.policy.namespace_root}</code>
              <br />
              Expiry: {pending.command.policy.expires_at ?? "None"}
            </p>
            <p>
              Permissions:{" "}
              {pending.command.policy.permissions.join(", ") || "None"}
            </p>
          </>
        )}
        <p>
          Credential or access changes invalidate this account’s existing
          browser sessions and authority-bound work. Revocation is permanent.
          Rotation preserves registered SSH keys and does not extend expiry.
        </p>
        {credential.current && (
          <>
            <p>
              Save the new credential before applying. The server receives only
              its SHA-256 fingerprint. Transfer the saved file to the intended
              person through your protected channel.
            </p>
            <button onClick={download} disabled={busy}>
              Download new credential
            </button>
            <label className="account-confirm">
              <input
                type="checkbox"
                checked={saved}
                disabled={!downloaded || busy}
                onChange={(e) => setSaved(e.target.checked)}
              />
              I saved the credential file securely.
            </label>
          </>
        )}
        <div className="actions">
          <button disabled={busy} onClick={cancel}>
            Cancel
          </button>
          <button
            disabled={busy || (!!credential.current && !saved)}
            onClick={() => void apply()}
          >
            {busy ? "Saving…" : "Apply reviewed change"}
          </button>
        </div>
      </dialog>
    </section>
  );
}
