import { useEffect, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { Api } from "./api";
import { Accounts } from "./accounts";
import { Partners } from "./partners";
import { Onboarding } from "./onboarding";
import { CheckEvidence } from "./check-evidence";
import { CheckRecovery } from "./check-recovery";
import { WorkspaceReference } from "./workspace-reference";
import { digestBytes, digestFile, operationKey } from "./crypto";
import {
  ApiError,
  type Session,
  type Upload,
  type UploadPage,
  type EntryPage,
  type CheckPage,
  type CheckView,
} from "./types";
import "./style.css";

const api = new Api();
const emptyUploads: UploadPage = {
  uploads: [],
  blocked_by_access_change: false,
};
const bytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1048576
      ? `${(n / 1024).toFixed(1)} KiB`
      : `${(n / 1048576).toFixed(1)} MiB`;
const short = (s: string) => s.slice(0, 8);
const name = (path: string) => path.split("/").at(-1) || "/";
const aborted = (error: unknown) =>
  error instanceof DOMException && error.name === "AbortError";
const messages: Record<string, string> = {
  invalid_onboarding_command:
    "Review the draft name, responsible contacts and exchange requirements. Each requirement must name a contact in this draft; keep credentials out of notes.",
  invalid_partner_command:
    "Review the partner name, first administrator, credential fingerprint and permitted grants. The first administrator needs admin and accounts_manage.",
  partner_exists:
    "That partner ID is already enrolled. Refresh the tenant directory and inspect its original enrollment.",
  invalid_account_command:
    "Review the account label, permissions, existing virtual root and future expiry timestamp. Create or rotate with a new credential fingerprint; other actions must not include one.",
  unauthorized:
    "Your session or access has expired. Sign in again to continue from the server’s saved position.",
  invalid_credential_file:
    "Choose the credential file provided for this account. It must contain the enrolled 64-character token.",
  permission_denied:
    "This account does not have permission for that action. Ask your administrator to review its access.",
  storage_quota_reached:
    "The server’s storage quota is full. Saved progress remains; an administrator must restore capacity.",
  revision_conflict:
    "The item you reviewed or its access settings changed. Refresh and review its current revision before continuing.",
  path_exists:
    "A file already exists at that destination. Choose a new path; this upload will not replace it.",
  operation_state_conflict:
    "The current state does not allow that action. Refresh the job and inspect its intake checks.",
  integrity_mismatch:
    "The received bytes did not match their fingerprint. The server did not publish this file.",
  connection_timeout:
    "The request timed out. The server may have saved progress. Resume reads its confirmed position before sending more.",
  csrf_required:
    "The session’s change token is no longer current. Reload the page and try again.",
  evidence_bound_exceeded:
    "The server’s configured admission limit was reached. Review existing work or ask an administrator to adjust capacity.",
  scanner_unavailable:
    "The scanner is unavailable or unverified. The file remains held.",
  scanner_detected: "The scanner reported a detection. The file remains held.",
  scanner_blocked:
    "The scanner could not clear this file. Review its limits or encrypted-content policy.",
  invalid_signature_file:
    "Choose one detached OpenPGP signature (.sig or .asc), no larger than 32 KiB, created for this complete file.",
  signature_invalid:
    "The signature does not verify under the selected signer policy. The file remains held.",
  invalid_csv:
    "The file does not meet its CSV contract. The file remains held.",
};
function explain(error: unknown): string {
  if (error instanceof ApiError)
    return (
      messages[error.code] ??
      `The server refused this operation (${error.code}). Refresh its current state before retrying.`
    );
  if (error instanceof Error && error.message === "source_mismatch")
    return "Choose the original complete file. Its size and SHA-256 must match this saved upload.";
  if (error instanceof Error && error.message === "file_read_failed")
    return "The browser could not read the selected file. Select it again and retry.";
  return "The connection was interrupted. Saved progress may be ahead of this screen; reconnect and resume to read the server’s confirmed position.";
}
function Badge({ state }: { state: string }) {
  return (
    <span
      className={`badge ${["completed", "released", "passed"].includes(state) ? "good" : ["failed", "rejected", "aborted"].includes(state) ? "bad" : "neutral"}`}
    >
      {state === "passed"
        ? "Passed · release required"
        : state === "completed"
          ? "Accepted"
          : state}
    </span>
  );
}

function App() {
  const [session, setSession] = useState<Session | null>(null),
    [starting, setStarting] = useState(true);
  const [tenant, setTenant] = useState(""),
    [partner, setPartner] = useState(""),
    [credential, setCredential] = useState<File | null>(null);
  const [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [signingIn, setSigningIn] = useState(false);
  const [tab, setTab] = useState<
      "files" | "uploads" | "checks" | "accounts" | "partners" | "onboarding"
    >("files"),
    [refresh, setRefresh] = useState(0);
  const [folder, setFolder] = useState("/"),
    [files, setFiles] = useState<EntryPage>({ entries: [] }),
    [fileAfter, setFileAfter] = useState("");
  const [uploads, setUploads] = useState<UploadPage>(emptyUploads),
    [uploadAfter, setUploadAfter] = useState("");
  const [checks, setChecks] = useState<CheckPage>({ checks: [] }),
    [checkAfter, setCheckAfter] = useState(""),
    [view, setView] = useState<CheckView | null>(null);
  const [releaseError, setReleaseError] = useState(""),
    [releaseBlocked, setReleaseBlocked] = useState(false);
  const [approval, setApproval] = useState<CheckView | null>(null),
    [acting, setActing] = useState(false),
    [signingOut, setSigningOut] = useState(false),
    [signature, setSignature] = useState<File | null>(null);
  const [selected, setSelected] = useState<Upload | null>(null),
    [file, setFile] = useState<File | null>(null),
    [destination, setDestination] = useState("");
  const [phase, setPhase] = useState("idle"),
    [hashed, setHashed] = useState(0),
    [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null),
    epoch = useRef(0),
    intent = useRef<{
      path: string;
      size: number;
      hash: string;
      key: string;
    } | null>(null);
  const alert = useRef<HTMLDivElement>(null),
    dialog = useRef<HTMLDialogElement>(null),
    releaseTitle = useRef<HTMLHeadingElement>(null),
    credentialInput = useRef<HTMLInputElement>(null),
    fileInput = useRef<HTMLInputElement>(null);
  const allowed = (grant: string) =>
    session?.identity.permissions.includes(grant) ?? false;
  const resetWork = () => {
    setTab("files");
    dialog.current?.close();
    setSignature(null);
    active.current?.abort();
    active.current = null;
    setBusy(false);
    setSelected(null);
    setFile(null);
    setDestination("");
    setHashed(0);
    setPhase("idle");
    intent.current = null;
    setFiles({ entries: [] });
    setUploads(emptyUploads);
    setChecks({ checks: [] });
    setView(null);
    setApproval(null);
    setReleaseError("");
    setReleaseBlocked(false);
    setFolder("/");
    setFileAfter("");
    setUploadAfter("");
    setCheckAfter("");
  };
  const reportError = (e: unknown) => {
    if (aborted(e)) return;
    setError(explain(e));
    if (e instanceof ApiError && e.status === 401) {
      setNotice("");
      epoch.current++;
      api.clear();
      resetWork();
      setSession(null);
    }
  };
  useEffect(() => {
    const c = new AbortController();
    api
      .restore(c.signal)
      .then((s) => {
        if (!c.signal.aborted) setSession(s);
      })
      .catch((e) => {
        if (!(e instanceof ApiError && e.status === 401) && !aborted(e))
          setError(explain(e));
      })
      .finally(() => {
        if (!c.signal.aborted) setStarting(false);
      });
    return () => c.abort();
  }, []);
  useEffect(() => {
    if (error) alert.current?.focus();
  }, [error]);
  useEffect(() => {
    if (approval && dialog.current && !dialog.current.open) {
      dialog.current.showModal();
      releaseTitle.current?.focus();
    }
  }, [approval]);
  useEffect(() => {
    if (!session) return;
    const c = new AbortController();
    const generation = epoch.current;
    if (tab === "files" && allowed("list"))
      api
        .entries(folder, fileAfter, c.signal)
        .then((v) => {
          if (!c.signal.aborted && generation === epoch.current) setFiles(v);
        })
        .catch(reportError);
    if (tab === "uploads" && allowed("write"))
      api
        .uploads(uploadAfter, c.signal)
        .then((v) => {
          if (!c.signal.aborted && generation === epoch.current) setUploads(v);
        })
        .catch(reportError);
    if (
      tab === "checks" &&
      (allowed("write") || allowed("check_run") || allowed("check_release"))
    )
      api
        .checks(checkAfter, c.signal)
        .then((v) => {
          if (!c.signal.aborted && generation === epoch.current) setChecks(v);
        })
        .catch(reportError);
    if (tab === "checks" && view)
      api
        .check(view.check.file_id, c.signal)
        .then((v) => {
          if (!c.signal.aborted && generation === epoch.current) setView(v);
        })
        .catch(reportError);
    return () => c.abort();
  }, [
    session,
    tab,
    folder,
    fileAfter,
    uploadAfter,
    checkAfter,
    refresh,
    view?.check.file_id,
  ]);

  async function login(event: FormEvent) {
    event.preventDefault();
    if (!credential || signingIn) return;
    const c = new AbortController();
    active.current = c;
    setSigningIn(true);
    setError("");
    try {
      const s = await api.login(
        tenant.trim().toLowerCase(),
        partner.trim().toLowerCase(),
        credential,
        c.signal,
      );
      if (!c.signal.aborted) {
        epoch.current++;
        resetWork();
        setSession(s);
        setNotice(
          "Connected. Access and intake rules are checked by your server.",
        );
      }
    } catch (e) {
      reportError(e);
    } finally {
      setSigningIn(false);
      setCredential(null);
      if (credentialInput.current) credentialInput.current.value = "";
    }
  }
  async function logout() {
    if (signingOut) return;
    active.current?.abort();
    api.abortAll();
    setSigningOut(true);
    setError("");
    try {
      await api.logout();
      epoch.current++;
      resetWork();
      setSession(null);
      setNotice("Signed out. The server revoked this browser session.");
    } catch (e) {
      reportError(e);
    } finally {
      setSigningOut(false);
    }
  }
  function selectUpload(upload: Upload | null) {
    active.current?.abort();
    setBusy(false);
    intent.current = null;
    setSelected(upload);
    setDestination(upload?.path ?? "");
    setFile(null);
    setHashed(0);
    setPhase(upload?.state === "completed" ? "accepted" : "idle");
    if (fileInput.current) fileInput.current.value = "";
    setError("");
    setNotice("");
    setTab("uploads");
  }
  async function transfer(event: FormEvent) {
    event.preventDefault();
    if (!session || !file || busy || acting) return;
    const c = new AbortController();
    active.current = c;
    const generation = epoch.current;
    setBusy(true);
    setError("");
    setNotice("");
    setPhase("hashing");
    setHashed(0);
    try {
      if (file.size > session.limits.max_file_bytes)
        throw new ApiError("evidence_bound_exceeded", 413);
      let upload = selected ? await api.upload(selected.id, c.signal) : null;
      if (upload && upload.state !== "open")
        throw new ApiError("operation_state_conflict", 409);
      const digest = await digestFile(
        file,
        (n) => {
          if (generation === epoch.current && !c.signal.aborted) setHashed(n);
        },
        c.signal,
      );
      if (c.signal.aborted) throw new DOMException("Canceled", "AbortError");
      if (
        upload &&
        (upload.expected_size !== file.size ||
          upload.expected_sha256 !== digest)
      )
        throw new Error("source_mismatch");
      if (!upload) {
        const path = destination.trim();
        const previous = intent.current;
        if (
          !previous ||
          previous.path !== path ||
          previous.size !== file.size ||
          previous.hash !== digest
        )
          intent.current = {
            path,
            size: file.size,
            hash: digest,
            key: operationKey(),
          };
        const plan = intent.current;
        if (!plan) throw new Error("missing_upload_intent");
        setPhase("creating");
        upload = (
          await api.createUpload(
            plan.path,
            plan.size,
            plan.hash,
            plan.key,
            c.signal,
          )
        ).upload;
      }
      if (generation !== epoch.current || c.signal.aborted)
        throw new DOMException("Canceled", "AbortError");
      setSelected(upload);
      setPhase("sending");
      const chunkSize = Math.max(
        session.limits.min_chunk_bytes,
        Math.min(1048576, session.limits.max_chunk_bytes),
      );
      while (upload.committed_offset < file.size) {
        if (c.signal.aborted) throw new DOMException("Canceled", "AbortError");
        const data: Uint8Array<ArrayBuffer> = new Uint8Array(
          await file
            .slice(
              upload.committed_offset,
              Math.min(file.size, upload.committed_offset + chunkSize),
            )
            .arrayBuffer(),
        );
        const oldOffset = upload.committed_offset;
        try {
          upload = (await api.append(upload, data, digestBytes(data), c.signal))
            .upload;
        } finally {
          data.fill(0);
        }
        if (upload.committed_offset <= oldOffset)
          throw new ApiError("invalid_server_response", 502);
        if (generation !== epoch.current || c.signal.aborted)
          throw new DOMException("Canceled", "AbortError");
        setSelected(upload);
      }
      setPhase("completing");
      const result = await api.complete(upload.id, c.signal);
      if (generation === epoch.current && !c.signal.aborted) {
        setSelected(result.upload);
        setPhase("accepted");
        setFile(null);
        if (fileInput.current) fileInput.current.value = "";
        setNotice(
          result.acceptance === "durable-held-pending-checks-and-release"
            ? "Accepted and held. Run the required checks, then approve release separately."
            : "Accepted with exact size and SHA-256 verified. The server’s current policy controls availability.",
        );
        setRefresh((v) => v + 1);
      }
    } catch (e) {
      if (generation === epoch.current) {
        setPhase(aborted(e) ? "paused" : "interrupted");
        if (aborted(e))
          setNotice(
            "Paused. Resume will read the server’s saved position before sending more.",
          );
        else reportError(e);
      }
    } finally {
      if (generation === epoch.current) setBusy(false);
    }
  }
  async function abortUpload() {
    if (!selected || busy) return;
    setActing(true);
    try {
      const r = await api.abortUpload(selected.id);
      setSelected(r.upload);
      setNotice(
        "Upload stopped. Retained pieces remain subject to the server’s retention policy.",
      );
      setRefresh((v) => v + 1);
    } catch (e) {
      reportError(e);
    } finally {
      setActing(false);
    }
  }
  async function inspect(id: string) {
    const generation = epoch.current;
    setSignature(null);
    setActing(true);
    setError("");
    try {
      const v = await api.check(id);
      if (generation === epoch.current) {
        setView(v);
        setTab("checks");
      }
    } catch (e) {
      reportError(e);
    } finally {
      setActing(false);
    }
  }
  async function runCheck() {
    if (!view || acting) return;
    const generation = epoch.current;
    setActing(true);
    setError("");
    try {
      const updated = await api.runCheck(view);
      if (generation === epoch.current) {
        setView(updated);
        setRefresh((v) => v + 1);
      }
    } catch (e) {
      reportError(e);
    } finally {
      setActing(false);
    }
  }
  async function release() {
    if (!approval || acting) return;
    const generation = epoch.current;
    const frozen = approval;
    setActing(true);
    setError("");
    setReleaseError("");
    try {
      const updated = await api.release(frozen);
      if (generation !== epoch.current) return;
      setView(updated);
      setApproval(null);
      dialog.current?.close();
      setNotice(
        "Released. Normal path permissions and current intake rules still apply.",
      );
      setRefresh((v) => v + 1);
    } catch (e) {
      if (generation !== epoch.current) return;
      const definitive =
        e instanceof ApiError && e.status >= 400 && e.status < 500;
      setReleaseBlocked(definitive);
      setReleaseError(
        definitive
          ? "The server refused this reviewed change. Cancel, refresh the current state and review again."
          : "Release was not confirmed. Retry this same reviewed command to recover its saved receipt, or cancel and refresh current state.",
      );
      reportError(e);
    } finally {
      setActing(false);
    }
  }

  async function attachSignature() {
    if (!view || !signature || acting) return;
    const generation = epoch.current;
    setActing(true);
    setError("");
    try {
      const updated = await api.attachSignature(view, signature);
      if (generation === epoch.current) {
        setView(updated);
        setSignature(null);
        setRefresh((v) => v + 1);
      }
    } catch (e) {
      reportError(e);
    } finally {
      setActing(false);
    }
  }

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="top">
        <a className="brand" href="/">
          <span className="brand-mark" aria-hidden="true">
            ↗
          </span>
          freightctl
        </a>
        <span className="build-label">Self-hosted file exchange</span>
        {session && (
          <div className="top-account">
            <span className="connected">Connected</span>
            <button
              className="quiet"
              onClick={() => void logout()}
              disabled={signingOut}
            >
              {signingOut ? "Signing out…" : "Sign out"}
            </button>
          </div>
        )}
      </header>
      {session && (
        <aside className="sidebar">
          <p className="eyebrow">WORKSPACE</p>
          <p className="scope-line">
            Tenant{" "}
            <code title={session.identity.tenant_id}>
              {short(session.identity.tenant_id)}
            </code>
          </p>
          <p className="scope-line">
            Partner{" "}
            <code title={session.identity.partner_id}>
              {short(session.identity.partner_id)}
            </code>
          </p>
          <p className="scope-line">
            Account{" "}
            <code title={session.identity.actor_id}>
              {short(session.identity.actor_id)}
            </code>
          </p>
          <nav aria-label="Workspace">
            <button
              aria-current={tab === "files" ? "page" : undefined}
              onClick={() => setTab("files")}
            >
              Files
            </button>
            <button
              aria-current={tab === "uploads" ? "page" : undefined}
              onClick={() => setTab("uploads")}
            >
              Uploads
            </button>
            <button
              aria-current={tab === "checks" ? "page" : undefined}
              onClick={() => setTab("checks")}
            >
              Intake checks
            </button>
            {allowed("admin") && allowed("accounts_manage") && (
              <button
                aria-current={tab === "accounts" ? "page" : undefined}
                onClick={() => setTab("accounts")}
              >
                Accounts
              </button>
            )}
            {allowed("admin") && allowed("accounts_manage") && (
              <button
                aria-current={tab === "onboarding" ? "page" : undefined}
                onClick={() => setTab("onboarding")}
              >
                Onboarding
              </button>
            )}
            {session.identity.tenant_administration && (
              <button
                aria-current={tab === "partners" ? "page" : undefined}
                onClick={() => setTab("partners")}
              >
                Partners
              </button>
            )}
          </nav>
          <div className="session-note">
            <p className="eyebrow">BROWSER SESSION</p>
            <p>
              Expires{" "}
              {new Date(session.session.expires_at).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              })}
            </p>
            <small>Sign in again after expiry to resume saved work.</small>
          </div>
        </aside>
      )}
      <main id="main" className={session ? "workspace" : "welcome"}>
        <div
          ref={alert}
          className="alert error"
          role="alert"
          tabIndex={-1}
          hidden={!error}
        >
          {error}
        </div>
        <div className="notice" role="status" aria-live="polite">
          {notice}
        </div>
        {starting ? (
          <p role="status">Checking your browser session…</p>
        ) : !session ? (
          <section className="login-card">
            <p className="eyebrow">YOUR SERVER. YOUR FILES.</p>
            <h1>Connect to your workspace</h1>
            <p>
              Your administrator provides two workspace IDs and an enrolled
              credential file. Your server checks access before each file
              action.
            </p>
            <form onSubmit={(e) => void login(e)}>
              <WorkspaceReference
                disabled={signingIn}
                onSelected={(tenant, partner) => {
                  setTenant(tenant);
                  setPartner(partner);
                }}
              />
              <label htmlFor="tenant">Tenant ID</label>
              <input
                id="tenant"
                required
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              />
              <label htmlFor="partner">Partner ID</label>
              <input
                id="partner"
                required
                value={partner}
                onChange={(e) => setPartner(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              />
              <label htmlFor="credential">Account credential file</label>
              <input
                id="credential"
                ref={credentialInput}
                type="file"
                required
                onChange={(e) => setCredential(e.target.files?.[0] ?? null)}
                aria-describedby="credential-help"
              />
              <p id="credential-help" className="help">
                The account credential is used only in memory to establish a
                short-lived session. That session uses a protected cookie.
              </p>
              <button
                className="primary wide"
                type="submit"
                disabled={signingIn || !credential}
              >
                {signingIn ? "Connecting…" : "Connect"}
              </button>
            </form>
            <details>
              <summary>Need an account?</summary>
              <p>
                An administrator must enroll your identity and give it the
                required file permissions. Identity-provider and self-service
                onboarding are still being built.
              </p>
            </details>
          </section>
        ) : (
          <>
            <div className="heading">
              <div>
                <p className="eyebrow">
                  {tab === "partners"
                    ? "TENANT DIRECTORY"
                    : "PARTNER WORKSPACE"}
                </p>
                <h1>
                  {tab === "files"
                    ? "Files"
                    : tab === "uploads"
                      ? "Uploads"
                      : tab === "partners"
                        ? "Partners"
                        : tab === "onboarding"
                          ? "Onboarding plans"
                          : tab === "accounts"
                            ? "Accounts"
                            : "Intake checks"}
                </h1>
                <p>
                  {tab === "files"
                    ? "Published paths. Retrieval checks your current access and intake policy."
                    : tab === "uploads"
                      ? "Send one exact file. Continue from the last server-confirmed checkpoint."
                      : tab === "partners"
                        ? "Enroll partners under explicit tenant authority; review each administrator credential and grants."
                        : tab === "onboarding"
                          ? "Record responsible contacts and exact exchange requirements as versioned drafts."
                          : tab === "accounts"
                            ? "Review scoped access, credential rotation, expiry and revocation."
                            : "Held files need their required checks and a separate release decision."}
                </p>
              </div>
              <button
                className="secondary"
                onClick={() => {
                  setError("");
                  setRefresh((v) => v + 1);
                }}
              >
                Refresh
              </button>
            </div>
            {tab === "partners" && session.identity.tenant_administration && (
              <Partners
                api={api}
                session={session}
                refresh={refresh}
                onError={reportError}
                onConfirmed={() => {
                  setError("");
                  setNotice(
                    "Partner enrolled. Use the saved credential and workspace IDs to sign in as its administrator.",
                  );
                }}
              />
            )}
            {tab === "onboarding" &&
              allowed("admin") &&
              allowed("accounts_manage") && (
                <Onboarding
                  api={api}
                  session={session}
                  refresh={refresh}
                  onError={reportError}
                  onConfirmed={(message) => {
                    setError("");
                    setNotice(
                      message ??
                        "Onboarding draft saved. Tests, approval and activation remain required.",
                    );
                  }}
                />
              )}
            {tab === "accounts" && (
              <Accounts
                api={api}
                session={session}
                refresh={refresh}
                onError={reportError}
              />
            )}
            {tab === "files" && (
              <section className="panel">
                <div className="panel-heading">
                  <div className="breadcrumbs">
                    <button
                      onClick={() => {
                        setFolder("/");
                        setFileAfter("");
                      }}
                      aria-label="Workspace root"
                    >
                      Workspace
                    </button>
                    {folder !== "/" && (
                      <>
                        <span aria-hidden="true">/</span>
                        <span>{folder}</span>
                      </>
                    )}
                  </div>
                  {allowed("write") && (
                    <button
                      className="primary"
                      onClick={() => selectUpload(null)}
                    >
                      Upload file
                    </button>
                  )}
                </div>
                {!allowed("list") ? (
                  <p className="empty">
                    This account cannot list files. Use Uploads for its
                    permitted sending actions.
                  </p>
                ) : (
                  <>
                    <div className="table-scroll">
                      <table>
                        <caption className="sr-only">
                          Published files in {folder}
                        </caption>
                        <thead>
                          <tr>
                            <th scope="col">Name</th>
                            <th scope="col">Size</th>
                            <th scope="col">Revision</th>
                            <th scope="col">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {files.entries.map((entry) => (
                            <tr key={entry.id}>
                              <td>
                                {entry.kind === "dir" ? (
                                  <button
                                    className="file-link"
                                    onClick={() => {
                                      setFolder(entry.path);
                                      setFileAfter("");
                                    }}
                                  >
                                    {name(entry.path)}
                                    <span className="sr-only"> folder</span>
                                  </button>
                                ) : (
                                  <span className="filename">
                                    {name(entry.path)}
                                  </span>
                                )}
                              </td>
                              <td>
                                {entry.kind === "dir"
                                  ? "Folder"
                                  : bytes(entry.size_bytes)}
                              </td>
                              <td>{entry.revision}</td>
                              <td>
                                {entry.kind === "file" && allowed("read") && (
                                  <a
                                    className="download"
                                    href={`${api.prefix}/namespace/file?${new URLSearchParams({ path: entry.path })}`}
                                  >
                                    Download
                                    <span className="sr-only">
                                      {" "}
                                      {name(entry.path)}
                                    </span>
                                  </a>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {files.entries.length === 0 && (
                      <div className="empty">
                        <h2>No published files here</h2>
                        <p>
                          New uploads may be held until their required checks
                          and release are complete.
                        </p>
                      </div>
                    )}
                    <Pagination
                      next={files.next}
                      first={() => setFileAfter("")}
                      more={() => setFileAfter(files.next ?? "")}
                    />
                  </>
                )}
              </section>
            )}
            {tab === "uploads" && (
              <>
                <section className="panel upload-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>
                        {selected?.state === "completed"
                          ? "Upload receipt"
                          : selected
                            ? "Saved upload"
                            : "New upload"}
                      </h2>
                      <p className="help">
                        Files stay unavailable until the server finishes
                        acceptance and any required release.
                      </p>
                    </div>
                    {selected && !busy && (
                      <button
                        className="quiet"
                        onClick={() => selectUpload(null)}
                      >
                        Start a new upload
                      </button>
                    )}
                  </div>
                  {allowed("write") ? (
                    <form onSubmit={(e) => void transfer(e)}>
                      {(!selected || selected.state === "open") && (
                        <>
                          <label htmlFor="upload-file">
                            {selected
                              ? "Original complete file"
                              : "File to send"}
                          </label>
                          <input
                            id="upload-file"
                            ref={fileInput}
                            type="file"
                            disabled={
                              busy || selected?.state === "completed" || acting
                            }
                            onChange={(e) => {
                              const chosen = e.target.files?.[0] ?? null;
                              setFile(chosen);
                              if (!selected && chosen)
                                setDestination(
                                  `${folder === "/" ? "" : folder}/${chosen.name}`,
                                );
                            }}
                          />
                        </>
                      )}
                      <label htmlFor="destination">Destination path</label>
                      <input
                        id="destination"
                        value={destination}
                        readOnly={selected !== null}
                        disabled={busy || acting}
                        onChange={(e) => setDestination(e.target.value)}
                        required
                        placeholder="/inbox/report.csv"
                        aria-describedby="destination-help"
                      />
                      <p className="help" id="destination-help">
                        A saved upload keeps its original destination. Existing
                        files require a separately reviewed replacement.
                      </p>
                      {(busy || selected) && (
                        <div className="progress-box">
                          <p className="progress-label">
                            {phase === "hashing"
                              ? "Computing the file fingerprint"
                              : phase === "completing"
                                ? "Verifying and accepting complete bytes"
                                : selected?.state === "completed"
                                  ? "Upload accepted"
                                  : "Server-confirmed progress"}
                          </p>
                          <progress
                            aria-label={
                              phase === "hashing"
                                ? "File fingerprint progress"
                                : "Confirmed upload progress"
                            }
                            max={Math.max(
                              1,
                              file?.size ?? selected?.expected_size ?? 1,
                            )}
                            value={
                              phase === "hashing"
                                ? hashed
                                : (selected?.committed_offset ?? 0)
                            }
                          />
                          <p className="help">
                            {phase === "hashing"
                              ? bytes(hashed)
                              : bytes(selected?.committed_offset ?? 0)}{" "}
                            of{" "}
                            {bytes(file?.size ?? selected?.expected_size ?? 0)}
                            {selected && (
                              <>
                                {" "}
                                · Upload <code>{selected.id}</code>
                              </>
                            )}
                          </p>
                        </div>
                      )}
                      <div className="actions">
                        {busy ? (
                          <button
                            key="pause-upload"
                            type="button"
                            className="secondary"
                            onClick={(event) => {
                              event.preventDefault();
                              active.current?.abort();
                            }}
                          >
                            Pause upload
                          </button>
                        ) : (
                          (!selected || selected.state === "open") && (
                            <button
                              key="submit-upload"
                              type="submit"
                              className="primary"
                              disabled={
                                !file ||
                                acting ||
                                Boolean(selected && selected.state !== "open")
                              }
                            >
                              {selected ? "Resume upload" : "Start upload"}
                            </button>
                          )
                        )}
                        {selected?.state === "open" && !busy && (
                          <button
                            type="button"
                            className="quiet danger"
                            onClick={() => void abortUpload()}
                            disabled={acting}
                          >
                            Stop upload
                          </button>
                        )}
                        {selected?.state === "completed" &&
                          selected.acceptance ===
                            "durable-local-integrity-only" &&
                          allowed("list") && (
                            <button
                              type="button"
                              className="secondary"
                              onClick={() => {
                                setFolder(
                                  selected.path.slice(
                                    0,
                                    selected.path.lastIndexOf("/"),
                                  ) || "/",
                                );
                                setFileAfter("");
                                setTab("files");
                              }}
                            >
                              Show published path
                            </button>
                          )}
                        {selected?.file_id &&
                          selected.acceptance ===
                            "durable-held-pending-checks-and-release" && (
                            <button
                              type="button"
                              className="secondary"
                              onClick={() =>
                                void inspect(selected.file_id ?? "")
                              }
                              disabled={acting}
                            >
                              Inspect intake check
                            </button>
                          )}
                      </div>
                    </form>
                  ) : (
                    <p>This account does not have upload permission.</p>
                  )}
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Saved uploads</h2>
                    <span className="help">Private to this account</span>
                  </div>
                  {uploads.blocked_by_access_change && (
                    <p className="inline-warning">
                      Older open uploads use access settings that have changed.
                      Ask an administrator to review them.
                    </p>
                  )}
                  <div className="table-scroll">
                    <table>
                      <caption className="sr-only">
                        Saved uploads for this account
                      </caption>
                      <thead>
                        <tr>
                          <th scope="col">Destination</th>
                          <th scope="col">Saved bytes</th>
                          <th scope="col">Upload state</th>
                          <th scope="col">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {uploads.uploads.map((u) => (
                          <tr key={u.id}>
                            <td>
                              <span className="filename">{u.path}</span>
                              <small>
                                <code>{u.id}</code>
                              </small>
                            </td>
                            <td>
                              {bytes(u.committed_offset)} /{" "}
                              {bytes(u.expected_size)}
                            </td>
                            <td>
                              <Badge state={u.state} />
                            </td>
                            <td>
                              <button
                                className="file-link"
                                disabled={busy || acting}
                                onClick={() => selectUpload(u)}
                              >
                                {u.state === "open"
                                  ? "Resume"
                                  : "Inspect upload"}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {uploads.uploads.length === 0 && (
                    <p className="empty">
                      No saved uploads under your current access settings.
                    </p>
                  )}
                  <Pagination
                    next={uploads.next}
                    first={() => setUploadAfter("")}
                    more={() => setUploadAfter(uploads.next ?? "")}
                  />
                </section>
              </>
            )}
            {tab === "checks" && (
              <>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Held revisions and results</h2>
                    <span className="help">Private to this account</span>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <caption className="sr-only">Intake checks</caption>
                      <thead>
                        <tr>
                          <th scope="col">File</th>
                          <th scope="col">State</th>
                          <th scope="col">Result</th>
                          <th scope="col">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {checks.checks.map((c) => (
                          <tr key={c.file_id}>
                            <td>{c.path || <code>{c.file_id}</code>}</td>
                            <td>
                              <Badge state={c.state} />
                            </td>
                            <td>{c.code || "Awaiting check"}</td>
                            <td>
                              <button
                                className="file-link"
                                onClick={() => void inspect(c.file_id)}
                                disabled={acting}
                              >
                                Inspect check
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {checks.checks.length === 0 && (
                    <p className="empty">
                      No controlled intake revisions are visible to this
                      account.
                    </p>
                  )}
                  <Pagination
                    next={checks.next}
                    first={() => setCheckAfter("")}
                    more={() => setCheckAfter(checks.next ?? "")}
                  />
                </section>
                {view && (
                  <section className="panel check-detail">
                    <div className="panel-heading">
                      <h2>Exact revision</h2>
                      <Badge state={view.check.state} />
                    </div>
                    <p className="filename">
                      {view.check.path || view.check.file_id}
                    </p>
                    <p>
                      {messages[view.check.code] ??
                        (view.check.state === "passed"
                          ? "Validation passed. These bytes remain held until you approve release."
                          : view.check.state === "released"
                            ? "Released under this intake policy. Current access and policy checks still apply."
                            : "The server keeps this revision held while its required work is incomplete.")}
                    </p>
                    {!view.current && (
                      <p className="inline-warning">
                        Access or policy changed. An administrator must review
                        this revision before further action.
                      </p>
                    )}
                    <dl className="facts">
                      <dt>File revision</dt>
                      <dd>
                        <code>{view.check.file_id}</code>
                      </dd>
                      <dt>Source SHA-256</dt>
                      <dd>
                        <code>{view.check.source_sha256}</code>
                      </dd>
                      <dt>Policy SHA-256</dt>
                      <dd>
                        <code>{view.check.policy_hash}</code>
                      </dd>
                      <dt>Report SHA-256</dt>
                      <dd>
                        <code>
                          {view.check.report_hash || "No passing report"}
                        </code>
                      </dd>
                      <dt>Attempts</dt>
                      <dd>{view.check.attempts} of 3</dd>
                    </dl>
                    <CheckEvidence view={view} />
                    <CheckRecovery
                      key={session.identity.actor_id + view.check.file_id}
                      view={view}
                      api={api}
                      onError={reportError}
                      onUpdated={(updated) => {
                        setView(updated);
                        setRefresh((v) => v + 1);
                      }}
                    />
                    {view.requirements?.signature && (
                      <div className="signature-box">
                        <h3>Detached signature</h3>
                        <p className="help">
                          The server verifies a public signature beside this
                          exact file using the signer selected by its intake
                          policy.
                        </p>
                        {view.signatureAttached ? (
                          <p>
                            Signature attached. Its validity is determined by
                            the required check.
                          </p>
                        ) : (
                          view.current &&
                          view.check.state === "held" &&
                          view.check.attempts === 0 &&
                          allowed("write") && (
                            <>
                              <label htmlFor="signature-file">
                                Public signature file
                              </label>
                              <input
                                id="signature-file"
                                type="file"
                                accept=".sig,.asc"
                                onChange={(e) =>
                                  setSignature(e.target.files?.[0] ?? null)
                                }
                                disabled={acting}
                              />
                              <button
                                className="secondary"
                                disabled={!signature || acting}
                                onClick={() => void attachSignature()}
                              >
                                Attach signature
                              </button>
                            </>
                          )
                        )}
                      </div>
                    )}
                    <div className="actions">
                      {allowed("check_run") && allowed("read") && (
                        <button
                          className="primary"
                          disabled={
                            acting ||
                            !view.current ||
                            !["held", "failed"].includes(view.check.state) ||
                            view.check.attempts >= 3 ||
                            Boolean(
                              view.requirements?.signature &&
                              !view.signatureAttached,
                            )
                          }
                          onClick={() => void runCheck()}
                        >
                          Run required checks
                        </button>
                      )}
                      {allowed("check_release") &&
                        allowed("read") &&
                        allowed("write") && (
                          <button
                            className="secondary"
                            disabled={
                              acting ||
                              !view.current ||
                              view.check.state !== "passed"
                            }
                            onClick={() => {
                              setReleaseError("");
                              setReleaseBlocked(false);
                              setApproval(view);
                            }}
                          >
                            Review release
                          </button>
                        )}
                    </div>
                  </section>
                )}
              </>
            )}
          </>
        )}
        <footer>
          Transfers follow your server’s access and intake policy. Development
          build; complete customer journeys remain unqualified.
        </footer>
      </main>
      <dialog
        ref={dialog}
        aria-labelledby="release-title"
        onCancel={(e) => {
          if (acting) e.preventDefault();
          else setApproval(null);
        }}
      >
        <h2 id="release-title" ref={releaseTitle} tabIndex={-1}>
          Release this exact revision?
        </h2>
        {approval && (
          <>
            <p>
              Release makes these checked bytes available at{" "}
              <strong>{approval.check.path || approval.check.file_id}</strong>.
              Normal path permissions control who can retrieve them.
            </p>
            <p className="help">
              A SHA-256 digest is the file’s byte fingerprint. Changing one byte
              changes it.
            </p>
            <dl className="facts">
              <dt>Source SHA-256</dt>
              <dd>
                <code>{approval.check.source_sha256}</code>
              </dd>
              <dt>Policy SHA-256</dt>
              <dd>
                <code>{approval.check.policy_hash}</code>
              </dd>
              <dt>Report SHA-256</dt>
              <dd>
                <code>{approval.check.report_hash}</code>
              </dd>
              <dt>Expected check revision</dt>
              <dd>{approval.check.revision}</dd>
            </dl>
            <CheckEvidence view={approval} />
            {releaseError && <p role="alert">{releaseError}</p>}
            <div className="actions">
              <button
                className="primary"
                onClick={() => void release()}
                disabled={acting || releaseBlocked}
              >
                {releaseError ? "Retry reviewed release" : "Release file"}
              </button>
              <button
                className="secondary"
                onClick={() => {
                  setApproval(null);
                  dialog.current?.close();
                }}
                disabled={acting}
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </dialog>
    </>
  );
}
function Pagination({
  next,
  first,
  more,
}: {
  next: string | undefined;
  first: () => void;
  more: () => void;
}) {
  return (
    <div className="pagination">
      <button className="quiet" onClick={first}>
        First page
      </button>
      <button className="secondary" disabled={!next} onClick={more}>
        Next page
      </button>
    </div>
  );
}

const root = document.getElementById("root");
if (root) createRoot(root).render(<App />);
