// GitHub-only native receive UI proof. No raw credentials or responses in stdout.
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile, lstat, chmod } from "node:fs/promises";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
import { artifactExchangeRequestAllowed } from "./artifact-exchange-network.mjs";
import {
  fetchPinnedBrowserRequest,
  guardBrowserCommandRoute,
} from "./browser-pinned-https.mjs";

assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
const { chromium } = createRequire(import.meta.url)(
  "../web/node_modules/playwright",
);
const axe = createRequire(import.meta.url)("../web/node_modules/axe-core");
let browser,
  phase = "configuration-identities",
  state = "failed",
  egress = 0,
  accessibilityChecks = 0,
  evidenceReads = 0,
  ownedCopies = 0,
  copyRecoveries = 0,
  copyRequests = 0,
  historySearches = 0,
  downloads = 0,
  declines = 0,
  offers = 0,
  cancels = 0,
  recoveryRoundtrips = 0,
  endpointCommands = 0,
  humanIngress = 0,
  onwardRuns = 0,
  onwardRecoveries = 0,
  onwardRefusals = 0,
  onwardRequests = 0,
  offerRequests = 0,
  exchangeRequests = 0,
  failureHash,
  routeFailure,
  routeFailurePhase,
  routeFailed = false;
const guardRoute = (handler) =>
  guardBrowserCommandRoute(handler, (error) => {
    if (!routeFailed) {
      routeFailed = true;
      routeFailure = error;
      routeFailurePhase = phase;
    }
  });
try {
  const origin = new URL(c.url);
  assert.equal(origin.protocol, "https:");
  assert.equal(origin.hostname, "127.0.0.1");
  assert.equal(origin.pathname, "/");
  for (const value of [
    c.tenant,
    c.partner,
    c.endpoint,
    c.exchange,
    c.closure_exchange,
    c.file,
    c.sender_actor,
    c.recipient_actor,
    c.manager_actor,
    c.onward_file,
    c.onward_workflow,
    c.copy_actor,
    c.copy_endpoint,
    c.copy_exchange,
    c.audit_actor,
    c.audit_event,
  ])
    assert.match(value, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  phase = "configuration-integrity";
  assert.match(c.sha256, /^[0-9a-f]{64}$/);
  assert.match(c.closure_request_hash, /^[0-9a-f]{64}$/);
  assert.match(c.copy_request_hash, /^[0-9a-f]{64}$/);
  assert.notEqual(c.closure_exchange, c.exchange);
  assert.ok(Number.isSafeInteger(c.size) && c.size > 0 && c.size < 16384);
  phase = "configuration-certificate";
  const spki = createHash("sha256")
    .update(
      new X509Certificate(
        Buffer.from(c.certificate_der, "base64"),
      ).publicKey.export({ type: "spki", format: "der" }),
    )
    .digest("base64");
  phase = "launch";
  browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
    channel: "chrome",
    args: [
      "--ignore-certificate-errors-spki-list=" + spki,
      "--disable-background-networking",
      "--disable-component-update",
    ],
  });
  process.once("SIGINT", async () => {
    await browser.close();
    process.exit(1);
  });
  async function login(token) {
    const info = await lstat(token);
    assert.ok(
      info.isFile() &&
        !info.isSymbolicLink() &&
        (info.mode & 0o077) === 0 &&
        info.size === 64,
    );
    const context = await browser.newContext({
      serviceWorkers: "block",
      acceptDownloads: true,
    });
    context.setDefaultTimeout(15000);
    await context.route("**/*", (route) => {
      const target = new URL(route.request().url());
      if (
        !artifactExchangeRequestAllowed(
          target,
          route.request().method(),
          origin.origin,
          c.tenant,
          c.partner,
        )
      ) {
        egress++;
        return route.abort();
      }
      if (
        target.pathname.startsWith(
          `/v1/tenants/${c.tenant}/partners/${c.partner}/exchange`,
        )
      )
        exchangeRequests++;
      if (
        target.pathname ===
          `/v1/tenants/${c.tenant}/partners/${c.partner}/exchanges` &&
        route.request().method() === "POST"
      )
        offerRequests++;
      if (
        target.pathname.startsWith(
          `/v1/tenants/${c.tenant}/partners/${c.partner}/onward/`,
        )
      )
        onwardRequests++;
      return route.continue(); // Original requests and responses; no mock/replay.
    });
    const page = await context.newPage();
    await page.goto(c.url);
    await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
    await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
    await page
      .getByLabel("Account credential file", { exact: true })
      .setInputFiles(token);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await page
      .getByRole("button", { name: "Receive artifacts", exact: true })
      .waitFor();
    const cookies = await context.cookies(c.url);
    assert.equal(cookies.length, 1);
    assert.equal(cookies[0].name, "__Host-freightctl-session");
    assert.equal(cookies[0].httpOnly, true);
    assert.equal(cookies[0].secure, true);
    assert.equal(cookies[0].sameSite, "Strict");
    await page
      .getByRole("button", { name: "Receive artifacts", exact: true })
      .click();
    return { context, page };
  }
  async function open(page) {
    await page
      .getByLabel("Approved receive endpoint ID", { exact: true })
      .fill(c.endpoint);
    const result = page.waitForResponse((r) =>
      r.url().includes("/exchange-endpoints/" + c.endpoint + "/incoming?"),
    );
    await page
      .getByRole("button", { name: "Open receive endpoint", exact: true })
      .click();
    return result;
  }
  async function directory(page) {
    const result = page.waitForResponse(
      (r) =>
        new URL(r.url()).pathname ===
        `/v1/tenants/${c.tenant}/partners/${c.partner}/exchange-endpoints`,
    );
    await page
      .getByRole("button", { name: "Find my receive endpoints", exact: true })
      .click();
    return result;
  }
  async function accessibility(page, name) {
    phase = name;
    await page.evaluate(axe.source);
    const violations = await page.evaluate(async () => {
      const result = await globalThis.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
        },
      });
      return result.violations.map((v) => ({ id: v.id, impact: v.impact }));
    });
    await writeFile(
      c.result + "." + name + ".json",
      JSON.stringify(violations) + "\n",
      { mode: 0o600, flag: "wx" },
    );
    assert.equal(violations.length, 0);
    accessibilityChecks++;
  }
  phase = "recipient-login";
  const recipient = await login(c.recipient_token);
  assert.equal(
    await recipient.page
      .getByRole("button", { name: "Audit history", exact: true })
      .count(),
    0,
  );
  phase = "recipient-directory";
  assert.equal((await directory(recipient.page)).status(), 200);
  const incoming = recipient.page.waitForResponse((r) =>
    r.url().includes("/exchange-endpoints/" + c.endpoint + "/incoming?"),
  );
  await recipient.page
    .getByRole("button", {
      name: "Open " + c.endpoint.slice(0, 8),
      exact: true,
    })
    .click();
  phase = "recipient-discovery";
  assert.equal((await incoming).status(), 200);
  await recipient.page
    .getByRole("table", { name: "Authorized incoming artifacts" })
    .waitFor();
  await accessibility(recipient.page, "receive-accessibility");
  phase = "recipient-details";
  await recipient.page
    .getByRole("button", {
      name: "Inspect " + c.exchange.slice(0, 8),
      exact: true,
    })
    .click();
  await recipient.page
    .getByRole("heading", { name: "Current exchange details", exact: true })
    .waitFor();
  assert.ok(
    (await recipient.page.locator("body").innerText()).includes(c.sha256),
  );
  await accessibility(recipient.page, "details-accessibility");
  phase = "incoming-evidence";
  const incomingEvidence = recipient.page.getByRole("region", {
    name: "Recorded exchange evidence",
    exact: true,
  });
  await incomingEvidence
    .getByRole("button", { name: "Read recorded evidence", exact: true })
    .click();
  await incomingEvidence
    .getByRole("listitem")
    .filter({ hasText: "Source accepted into custody" })
    .waitFor();
  assert.equal(await incomingEvidence.getByRole("listitem").count(), 2);
  const incomingEvidenceText = await incomingEvidence.innerText();
  assert.ok(
    incomingEvidenceText.includes(c.file) &&
      incomingEvidenceText.includes(c.exchange) &&
      incomingEvidenceText.includes("remain unknown"),
  );
  evidenceReads++;
  await accessibility(recipient.page, "incoming-evidence-accessibility");
  phase = "exact-download";
  const attachment = recipient.page.waitForEvent("download");
  await recipient.page
    .getByRole("row")
    .filter({ hasText: c.exchange })
    .getByRole("link", { name: "Download artifact", exact: true })
    .click();
  const download = await attachment;
  assert.equal(download.suggestedFilename(), "artifact");
  assert.equal(await download.failure(), null);
  await download.saveAs(c.download);
  await chmod(c.download, 0o600);
  const bytes = await readFile(c.download);
  assert.equal(bytes.length, c.size);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), c.sha256);
  downloads++;
  assert.equal(
    await recipient.page.evaluate(() => globalThis.freightctlArtifactExecuted),
    undefined,
  );
  assert.equal(
    await recipient.page
      .getByRole("button", { name: "Review new owned copy", exact: true })
      .count(),
    0,
  );
  phase = "copy-login";
  const copyOwner = await login(c.copy_token);
  assert.equal(
    await copyOwner.page
      .getByRole("button", { name: "Audit history", exact: true })
      .count(),
    0,
  );
  assert.equal(
    await copyOwner.page
      .getByRole("button", { name: "Send artifacts", exact: true })
      .count(),
    0,
  );
  assert.equal(
    await copyOwner.page
      .getByRole("button", { name: "Onward delivery", exact: true })
      .count(),
    0,
  );
  assert.equal((await directory(copyOwner.page)).status(), 200);
  const copyIncoming = copyOwner.page.waitForResponse((r) =>
    r.url().includes("/exchange-endpoints/" + c.copy_endpoint + "/incoming?"),
  );
  await copyOwner.page
    .getByRole("button", {
      name: "Open " + c.copy_endpoint.slice(0, 8),
      exact: true,
    })
    .click();
  assert.equal((await copyIncoming).status(), 200);
  await copyOwner.page
    .getByRole("button", {
      name: "Inspect " + c.copy_exchange.slice(0, 8),
      exact: true,
    })
    .click();
  const copyRegion = copyOwner.page.getByRole("region", {
    name: "Copy received artifact",
    exact: true,
  });
  await copyRegion
    .getByLabel("New owned copy path", { exact: true })
    .fill("/browser-owned-copy.dat");
  await copyRegion
    .getByRole("button", { name: "Review new owned copy", exact: true })
    .click();
  await copyRegion
    .getByRole("heading", { name: "Review received copy", exact: true })
    .waitFor();
  phase = "copy-review-accessibility";
  await accessibility(copyOwner.page, "copy-review-accessibility");
  const copyDownload = copyOwner.page.waitForEvent("download");
  await copyRegion
    .getByRole("button", { name: "Save copy recovery file", exact: true })
    .click();
  const copyRecovery = await copyDownload;
  assert.equal(await copyRecovery.failure(), null);
  await copyRecovery.saveAs(c.copy_recovery);
  await chmod(c.copy_recovery, 0o600);
  const copySaved = JSON.parse(await readFile(c.copy_recovery, "utf8"));
  assert.equal(copySaved.profile, "freightctl-received-copy-recovery-v1");
  assert.equal(copySaved.server_origin, origin.origin);
  assert.equal(copySaved.participant.actor_id, c.copy_actor);
  assert.equal(copySaved.request.exchange_id, c.copy_exchange);
  assert.equal(copySaved.request.request_hash, c.copy_request_hash);
  assert.equal(copySaved.request.artifact.file_revision_id, c.file);
  assert.equal(copySaved.request.virtual_path, "/browser-owned-copy.dat");
  const wrongOwner = structuredClone(copySaved);
  wrongOwner.participant.actor_id = c.recipient_actor;
  await writeFile(
    c.copy_recovery + ".wrong-actor.json",
    JSON.stringify(wrongOwner) + "\n",
    { mode: 0o600, flag: "wx" },
  );
  const copyURL =
    origin.origin +
    `/v1/tenants/${c.tenant}/partners/${c.partner}/exchange-copies`;
  copyOwner.page.on("request", (r) => {
    if (r.url() === copyURL && r.method() === "POST") copyRequests++;
  });
  let copiedID;
  await copyOwner.page.route(
    copyURL,
    guardRoute(async (route) => {
      assert.equal(
        route.request().headers()["idempotency-key"],
        copySaved.request_key,
      );
      assert.deepEqual(route.request().postDataJSON(), copySaved.request);
      const real = await fetchPinnedBrowserRequest(
        route.request(),
        origin.origin,
        Buffer.from(c.certificate_der, "base64"),
      );
      assert.equal(real.status, 201);
      const receipt = JSON.parse(real.body);
      assert.equal(receipt.replayed, false);
      assert.equal(receipt.source.exchange_id, c.copy_exchange);
      assert.equal(receipt.artifact.sha256, c.sha256);
      copiedID = receipt.artifact.file_revision_id;
      assert.notEqual(copiedID, c.file);
      await route.abort("failed");
    }),
  );
  phase = "copy-lost-response";
  await copyRegion
    .getByRole("button", {
      name: "Submit or recover original copy",
      exact: true,
    })
    .click();
  await copyOwner.page.getByRole("alert").waitFor();
  await copyRegion
    .getByRole("button", {
      name: "Submit or recover original copy",
      exact: true,
    })
    .waitFor();
  assert.match(copiedID, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.equal(copyRequests, 1);
  ownedCopies++;
  phase = "copy-uncertain-accessibility";
  await accessibility(copyOwner.page, "copy-uncertain-accessibility");
  await copyOwner.page.unroute(copyURL);
  await copyOwner.page.reload();
  await copyOwner.page
    .getByRole("button", { name: "Receive artifacts", exact: true })
    .click();
  phase = "copy-import";
  const copyAfterReload = copyOwner.page.getByRole("region", {
    name: "Copy received artifact",
    exact: true,
  });
  await copyAfterReload
    .getByLabel("Open copy recovery file", { exact: true })
    .setInputFiles(c.copy_recovery + ".wrong-actor.json");
  await copyOwner.page.getByRole("alert").waitFor();
  assert.equal(copyRequests, 1);
  assert.equal(
    await copyAfterReload
      .getByRole("heading", { name: "Review received copy", exact: true })
      .count(),
    0,
  );
  await copyAfterReload
    .getByLabel("Open copy recovery file", { exact: true })
    .setInputFiles(c.copy_recovery);
  await copyAfterReload
    .getByRole("heading", { name: "Review received copy", exact: true })
    .waitFor();
  assert.equal(
    await copyAfterReload
      .getByRole("button", {
        name: "Submit or recover original copy",
        exact: true,
      })
      .isDisabled(),
    true,
  );
  assert.equal(copyRequests, 1);
  phase = "copy-import-accessibility";
  await accessibility(copyOwner.page, "copy-import-accessibility");
  await copyAfterReload
    .getByRole("button", { name: "I reviewed these copy details", exact: true })
    .click();
  phase = "copy-recover";
  const copyReplayed = copyOwner.page.waitForResponse(
    (r) => r.url() === copyURL && r.request().method() === "POST",
  );
  await copyAfterReload
    .getByRole("button", {
      name: "Submit or recover original copy",
      exact: true,
    })
    .click();
  const recoveredCopy = await copyReplayed;
  assert.equal(recoveredCopy.status(), 200);
  const recoveredReceipt = await recoveredCopy.json();
  assert.equal(recoveredReceipt.replayed, true);
  assert.equal(recoveredReceipt.artifact.file_revision_id, copiedID);
  assert.equal(copyRequests, 2);
  copyRecoveries++;
  await copyAfterReload
    .getByRole("status")
    .filter({ hasText: "Original custody acceptance:" })
    .waitFor();
  phase = "copy-receipt-accessibility";
  await accessibility(copyOwner.page, "copy-receipt-accessibility");
  const copyBytes = await copyOwner.page.evaluate(async (path) => {
    const r = await fetch(path, {
      credentials: "same-origin",
      redirect: "error",
    });
    if (r.status !== 200) throw new Error("copy byte read refused");
    return Array.from(new Uint8Array(await r.arrayBuffer()));
  }, `/v1/tenants/${c.tenant}/partners/${c.partner}/files/${copiedID}`);
  assert.equal(copyBytes.length, c.size);
  assert.equal(
    createHash("sha256").update(Buffer.from(copyBytes)).digest("hex"),
    c.sha256,
  );
  assert.equal(
    await copyOwner.page.evaluate(() => globalThis.freightctlArtifactExecuted),
    undefined,
  );
  phase = "sender-login";
  const sender = await login(c.sender_token);
  assert.equal(
    await sender.page
      .getByRole("button", { name: "Receive endpoints", exact: true })
      .count(),
    0,
  );

  phase = "sender-upload";
  await sender.page.getByRole("button", { name: "Files", exact: true }).click();
  await sender.page
    .getByRole("button", { name: "Upload file", exact: true })
    .click();
  await sender.page
    .getByLabel("File to send", { exact: true })
    .setInputFiles(c.upload_source);
  await sender.page
    .getByLabel("Destination path", { exact: true })
    .fill("/human-upload-artifact.json");
  const uploadReceipt = sender.page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname.endsWith("/complete") &&
      r.request().method() === "POST",
  );
  await sender.page
    .getByRole("button", { name: "Start upload", exact: true })
    .click();
  const acceptedUpload = await uploadReceipt;
  assert.equal(acceptedUpload.status(), 200);
  const uploaded = await acceptedUpload.json();
  assert.equal(uploaded.upload.state, "completed");
  assert.equal(uploaded.upload.committed_offset, c.size);
  assert.equal(uploaded.upload.expected_sha256, c.sha256);
  const uploadedFile = uploaded.upload.file_id;
  assert.match(uploadedFile, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.notEqual(uploadedFile, c.file);
  await sender.page
    .getByRole("heading", { name: "Upload receipt", exact: true })
    .waitFor();
  await accessibility(sender.page, "sender-upload-accessibility");
  await sender.page
    .getByRole("button", { name: "Review accepted artifact", exact: true })
    .click();
  assert.equal(
    await sender.page
      .getByLabel("Source file revision ID", { exact: true })
      .inputValue(),
    uploadedFile,
  );
  phase = "sender-directory";
  const recipients = sender.page.waitForResponse((r) =>
    new URL(r.url()).pathname.endsWith("/exchange-endpoints"),
  );
  await sender.page
    .getByRole("button", { name: "Find approved recipients", exact: true })
    .click();
  assert.equal((await recipients).status(), 200);
  await sender.page
    .getByRole("button", {
      name: "Use endpoint " + c.endpoint.slice(0, 8),
      exact: true,
    })
    .click();
  phase = "sender-review";
  await sender.page
    .getByRole("button", { name: "Review artifact offer", exact: true })
    .click();
  await sender.page
    .getByRole("heading", { name: "Review exact artifact offer", exact: true })
    .waitFor();
  assert.ok((await sender.page.locator("body").innerText()).includes(c.sha256));
  await accessibility(sender.page, "sender-review-accessibility");
  phase = "sender-offer";
  const publication = sender.page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname.endsWith("/exchanges") &&
      r.request().method() === "POST",
  );
  await sender.page
    .getByRole("button", {
      name: "Confirm artifact offer or recover result",
      exact: true,
    })
    .click();
  const publicationResponse = await publication;
  assert.equal(publicationResponse.status(), 201);
  const sent = await publicationResponse.json();
  assert.equal(sent.replayed, false);
  assert.equal(sent.exchange.sender_actor_id, c.sender_actor);
  assert.equal(sent.exchange.recipient_actor_id, c.recipient_actor);
  assert.equal(sent.exchange.request.artifact.file_revision_id, uploadedFile);
  assert.equal(sent.exchange.request.artifact.size_bytes, c.size);
  assert.equal(sent.exchange.request.artifact.sha256, c.sha256);
  assert.equal(sent.exchange.request.receipt, "availability-only-v1");
  assert.equal(
    sent.exchange.request_hash,
    createHash("sha256")
      .update(JSON.stringify(sent.exchange.request))
      .digest("hex"),
  );
  await sender.page
    .getByRole("heading", {
      name: "Committed availability receipt",
      exact: true,
    })
    .waitFor();
  offers++;
  await accessibility(sender.page, "sender-receipt-accessibility");

  phase = "sender-human-receive";
  assert.equal((await open(recipient.page)).status(), 200);
  await recipient.page
    .getByRole("button", {
      name: "Inspect " + sent.exchange.id.slice(0, 8),
      exact: true,
    })
    .click();
  await recipient.page
    .getByRole("row")
    .filter({ hasText: sent.exchange.id })
    .getByRole("link", { name: "Download artifact", exact: true })
    .waitFor();
  await recipient.page
    .locator('section[aria-labelledby="artifact-detail-title"]')
    .getByText(uploadedFile, { exact: true })
    .waitFor();
  const humanDownload = recipient.page.waitForEvent("download");
  await recipient.page
    .getByRole("row")
    .filter({ hasText: sent.exchange.id })
    .getByRole("link", { name: "Download artifact", exact: true })
    .click();
  const receivedHuman = await humanDownload;
  assert.equal(receivedHuman.suggestedFilename(), "artifact");
  assert.equal(await receivedHuman.failure(), null);
  await receivedHuman.saveAs(c.human_download);
  await chmod(c.human_download, 0o600);
  const humanBytes = await readFile(c.human_download);
  assert.equal(humanBytes.length, c.size);
  assert.equal(createHash("sha256").update(humanBytes).digest("hex"), c.sha256);
  assert.equal(
    await recipient.page.evaluate(() => globalThis.freightctlArtifactExecuted),
    undefined,
  );
  downloads++;
  humanIngress++;
  await accessibility(recipient.page, "sender-human-receive-accessibility");
  phase = "sender-cancel";
  const withdrawal = sender.page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname.endsWith("/exchange-closures") &&
      r.request().method() === "POST",
  );
  await sender.page
    .getByRole("button", {
      name: "Withdraw this artifact offer or recover result",
      exact: true,
    })
    .click();
  const withdrawalResponse = await withdrawal;
  assert.equal(withdrawalResponse.status(), 200);
  const withdrawn = await withdrawalResponse.json();
  assert.equal(withdrawn.exchange_id, sent.exchange.id);
  assert.equal(withdrawn.state, "canceled");
  assert.equal(withdrawn.replayed, false);
  assert.equal(
    withdrawn.command_hash,
    createHash("sha256")
      .update(
        JSON.stringify({
          schema_version: 1,
          exchange_id: sent.exchange.id,
          request_hash: sent.exchange.request_hash,
          operation: "cancel",
        }),
      )
      .digest("hex"),
  );
  await sender.page
    .getByRole("status")
    .filter({ hasText: "This offer was withdrawn." })
    .waitFor();
  cancels++;
  const canceledStatus = await recipient.page.evaluate(
    async (path) =>
      (
        await fetch(path, {
          credentials: "same-origin",
          redirect: "error",
          cache: "no-store",
        })
      ).status,
    `/v1/tenants/${c.tenant}/partners/${c.partner}/exchanges/${sent.exchange.id}/file`,
  );
  assert.equal(canceledStatus, 404);
  phase = "sender-save-recovery";
  const savedDownload = sender.page.waitForEvent("download");
  await sender.page
    .getByRole("button", { name: "Save offer recovery file", exact: true })
    .click();
  const savedFile = await savedDownload;
  assert.equal(savedFile.suggestedFilename(), "freightctl-offer-recovery.json");
  assert.equal(await savedFile.failure(), null);
  await savedFile.saveAs(c.recovery);
  await chmod(c.recovery, 0o600);
  const recoveryBytes = await readFile(c.recovery);
  assert.ok(recoveryBytes.length > 0 && recoveryBytes.length <= 24576);
  const saved = JSON.parse(recoveryBytes.toString("utf8"));
  assert.equal(saved.server_origin, origin.origin);
  assert.equal(
    saved.request_key,
    publicationResponse.request().headers()["idempotency-key"],
  );
  assert.equal(
    saved.withdrawal_key,
    withdrawalResponse.request().headers()["idempotency-key"],
  );
  assert.equal(saved.expected_exchange_id, sent.exchange.id);
  assert.deepEqual(
    saved.request,
    JSON.parse(publicationResponse.request().postData()),
  );
  phase = "sender-reload-recovery";
  await sender.page.reload();
  await sender.page
    .getByRole("button", { name: "Send artifacts", exact: true })
    .click();
  const beforeImport = offerRequests;
  const exchangesBeforeImport = exchangeRequests;
  await sender.page
    .getByLabel("Saved offer recovery file (optional)", { exact: true })
    .setInputFiles(c.recovery);
  await sender.page
    .getByRole("status")
    .filter({ hasText: "Saved review loaded." })
    .waitFor();
  assert.equal(offerRequests, beforeImport);
  assert.equal(exchangeRequests, exchangesBeforeImport);
  assert.equal(
    await sender.page
      .getByRole("heading", {
        name: "Committed availability receipt",
        exact: true,
      })
      .count(),
    0,
  );
  await accessibility(sender.page, "sender-recovery-accessibility");
  phase = "sender-recover-offer";
  const replayPublication = sender.page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname.endsWith("/exchanges") &&
      r.request().method() === "POST",
  );
  await sender.page
    .getByRole("button", {
      name: "Confirm artifact offer or recover result",
      exact: true,
    })
    .click();
  const replayPublicationResponse = await replayPublication;
  assert.equal(replayPublicationResponse.status(), 200);
  assert.equal(
    replayPublicationResponse.request().headers()["idempotency-key"],
    saved.request_key,
  );
  assert.equal(
    replayPublicationResponse.request().postData(),
    publicationResponse.request().postData(),
  );
  const recoveredOffer = await replayPublicationResponse.json();
  assert.equal(recoveredOffer.replayed, true);
  assert.deepEqual(recoveredOffer.exchange, sent.exchange);
  await sender.page
    .getByRole("heading", {
      name: "Committed availability receipt",
      exact: true,
    })
    .waitFor();
  phase = "sender-recover-cancel";
  const replayWithdrawal = sender.page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname.endsWith("/exchange-closures") &&
      r.request().method() === "POST",
  );
  await sender.page
    .getByRole("button", {
      name: "Withdraw this artifact offer or recover result",
      exact: true,
    })
    .click();
  const replayWithdrawalResponse = await replayWithdrawal;
  assert.equal(replayWithdrawalResponse.status(), 200);
  assert.equal(
    replayWithdrawalResponse.request().headers()["idempotency-key"],
    saved.withdrawal_key,
  );
  assert.equal(
    replayWithdrawalResponse.request().postData(),
    withdrawalResponse.request().postData(),
  );
  const recoveredWithdrawal = await replayWithdrawalResponse.json();
  assert.deepEqual(recoveredWithdrawal, { ...withdrawn, replayed: true });
  await sender.page
    .getByRole("status")
    .filter({ hasText: "This offer was withdrawn." })
    .waitFor();
  assert.equal(offerRequests, 2);
  recoveryRoundtrips++;
  phase = "sender-history";
  const sentHistory = sender.page.waitForResponse((r) =>
    new URL(r.url()).pathname.endsWith("/outgoing-exchanges"),
  );
  await sender.page
    .getByRole("button", { name: "Sent artifacts", exact: true })
    .click();
  assert.equal((await sentHistory).status(), 200);
  await sender.page
    .getByRole("table", {
      name: "Currently authorized outgoing history",
      exact: true,
    })
    .waitFor();
  const withdrawnRow = sender.page
    .getByRole("row")
    .filter({ hasText: sent.exchange.id });
  await withdrawnRow
    .getByText("Withdrawn by sender", { exact: true })
    .waitFor();
  await accessibility(sender.page, "sender-history-accessibility");
  phase = "sender-history-details";
  await sender.page
    .getByRole("button", {
      name: "Inspect sent " + sent.exchange.id.slice(0, 8),
      exact: true,
    })
    .click();
  await sender.page
    .getByRole("heading", {
      name: "Original offer and current state",
      exact: true,
    })
    .waitFor();
  const historyText = await sender.page.locator("body").innerText();
  assert.ok(historyText.includes(sent.exchange.request_hash));
  assert.ok(historyText.includes(withdrawn.event_id));
  for (const label of [
    "Byte retrieval",
    "Receiver persistence",
    "Business processing",
  ]) {
    assert.equal(
      await sender.page
        .locator("dt")
        .filter({ hasText: label })
        .evaluate((dt) => dt.nextElementSibling?.textContent),
      "Unknown",
    );
  }
  await accessibility(sender.page, "sender-history-detail-accessibility");
  phase = "outgoing-evidence";
  const outgoingEvidence = sender.page.getByRole("region", {
    name: "Recorded exchange evidence",
    exact: true,
  });
  await outgoingEvidence
    .getByRole("button", { name: "Read recorded evidence", exact: true })
    .click();
  await outgoingEvidence
    .getByRole("listitem")
    .filter({ hasText: "Sender withdrew the offer" })
    .waitFor();
  assert.equal(await outgoingEvidence.getByRole("listitem").count(), 3);
  const outgoingEvidenceText = await outgoingEvidence.innerText();
  assert.ok(
    outgoingEvidenceText.includes(sent.exchange.id) &&
      outgoingEvidenceText.includes(withdrawn.event_id) &&
      outgoingEvidenceText.includes("remain unknown"),
  );
  evidenceReads++;
  await accessibility(sender.page, "outgoing-evidence-accessibility");
  await sender.context.close();
  phase = "recipient-decline-review";
  await recipient.page
    .getByRole("button", {
      name: "Review decline " + c.closure_exchange.slice(0, 8),
      exact: true,
    })
    .click();
  await accessibility(recipient.page, "decline-review-accessibility");
  phase = "recipient-decline";
  const closureResponse = recipient.page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname.endsWith("/exchange-closures") &&
      r.request().method() === "POST",
  );
  await recipient.page
    .getByRole("button", {
      name: "Confirm decline or recover result",
      exact: true,
    })
    .click();
  const closure = await closureResponse;
  assert.equal(closure.status(), 200);
  const receipt = await closure.json();
  assert.equal(receipt.exchange_id, c.closure_exchange);
  assert.equal(receipt.state, "declined");
  assert.equal(receipt.replayed, false);
  assert.match(
    receipt.event_id,
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/,
  );
  assert.equal(
    receipt.command_hash,
    createHash("sha256")
      .update(
        JSON.stringify({
          schema_version: 1,
          exchange_id: c.closure_exchange,
          request_hash: c.closure_request_hash,
          operation: "decline",
        }),
      )
      .digest("hex"),
  );
  await recipient.page
    .getByRole("status")
    .filter({ hasText: "Future retrieval through this view is disabled." })
    .waitFor();
  declines++;
  phase = "declined-retrieval";
  const refused = await recipient.page.evaluate(async (path) => {
    const response = await fetch(path, {
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
    });
    return {
      status: response.status,
      revision: response.headers.get("X-File-Revision-ID"),
      digest: response.headers.get("X-Content-SHA256"),
      contentType: response.headers.get("Content-Type"),
    };
  }, `/v1/tenants/${c.tenant}/partners/${c.partner}/exchanges/${c.closure_exchange}/file`);
  assert.equal(refused.status, 404);
  assert.equal(refused.revision, null);
  assert.equal(refused.digest, null);
  assert.match(refused.contentType, /^application\/json/);
  phase = "declined-discovery";
  const afterDecline = recipient.page.waitForResponse((r) =>
    r.url().includes("/exchange-endpoints/" + c.endpoint + "/incoming?"),
  );
  await recipient.page
    .getByRole("button", { name: "Check for new artifacts", exact: true })
    .click();
  assert.equal((await afterDecline).status(), 200);
  await recipient.page
    .getByRole("row")
    .filter({ hasText: c.exchange })
    .waitFor();
  assert.equal(
    await recipient.page
      .getByRole("row")
      .filter({ hasText: c.closure_exchange })
      .count(),
    0,
  );
  assert.equal(
    await recipient.page
      .getByRole("link", { name: "Download artifact", exact: true })
      .count(),
    1,
  );
  await accessibility(recipient.page, "declined-accessibility");
  // Keep original details visible again so the later endpoint-revocation
  // journey still proves that stale digest/details and links are removed.
  phase = "recipient-details";
  await recipient.page
    .getByRole("button", {
      name: "Inspect " + c.exchange.slice(0, 8),
      exact: true,
    })
    .click();
  await recipient.page
    .getByRole("heading", { name: "Current exchange details", exact: true })
    .waitFor();
  assert.ok(
    (await recipient.page.locator("body").innerText()).includes(c.sha256),
  );
  phase = "unrelated-discovery";
  const unrelated = await login(c.unrelated_token);
  phase = "unrelated-directory";
  assert.equal((await directory(unrelated.page)).status(), 200);
  await unrelated.page
    .getByText("No active receive endpoints for this account on this page.", {
      exact: true,
    })
    .waitFor();
  phase = "unrelated-discovery";
  assert.equal((await open(unrelated.page)).status(), 404);
  await unrelated.page.getByRole("alert").waitFor();
  const unrelatedText = await unrelated.page.locator("body").innerText();
  for (const secretMetadata of [c.exchange, c.file, c.sha256])
    assert.equal(unrelatedText.includes(secretMetadata), false);
  assert.equal(
    await unrelated.page
      .getByRole("link", { name: "Download artifact", exact: true })
      .count(),
    0,
  );
  await accessibility(unrelated.page, "unrelated-accessibility");
  await unrelated.context.close();

  phase = "manager-login";
  const manager = await login(c.manager_token);
  await manager.page
    .getByRole("button", { name: "Receive endpoints", exact: true })
    .click();
  phase = "manager-accounts";
  const accountPage = manager.page.waitForResponse((r) =>
    new URL(r.url()).pathname.endsWith("/accounts"),
  );
  await manager.page
    .getByRole("button", { name: "Check participant accounts", exact: true })
    .click();
  assert.equal((await accountPage).status(), 200);
  await manager.page
    .getByRole("button", {
      name: "Receive as " + c.recipient_actor.slice(0, 8),
      exact: true,
    })
    .click();
  await manager.page
    .getByLabel("Allow sender " + c.sender_actor.slice(0, 8), { exact: true })
    .check();
  phase = "manager-review";
  await manager.page
    .getByRole("button", { name: "Review endpoint creation", exact: true })
    .click();
  await manager.page
    .getByRole("heading", { name: "Review exact endpoint change", exact: true })
    .waitFor();
  await accessibility(manager.page, "manager-review-accessibility");
  const managerCommand = async () => {
    const result = manager.page.waitForResponse(
      (r) =>
        new URL(r.url()).pathname.endsWith("/exchange-endpoints/commands") &&
        r.request().method() === "POST",
    );
    await manager.page
      .getByRole("button", {
        name: "Confirm or recover endpoint command",
        exact: true,
      })
      .click();
    const response = await result;
    assert.equal(response.status(), 200);
    const data = await response.json();
    await manager.page
      .getByRole("heading", { name: "Confirmed endpoint command", exact: true })
      .waitFor();
    return { response, data };
  };
  phase = "manager-create";
  const created = await managerCommand();
  assert.equal(created.data.endpoint.revision, 1);
  assert.equal(created.data.endpoint.state, "active");
  assert.equal(created.data.endpoint.recorded_by, c.manager_actor);
  assert.equal(
    created.data.endpoint.definition.recipient.actor_id,
    c.recipient_actor,
  );
  assert.deepEqual(
    created.data.endpoint.definition.senders.map((s) => s.actor_id),
    [c.sender_actor],
  );
  endpointCommands++;
  await accessibility(manager.page, "manager-create-accessibility");
  phase = "manager-replay";
  const replayed = await managerCommand();
  assert.equal(
    replayed.response.request().headers()["idempotency-key"],
    created.response.request().headers()["idempotency-key"],
  );
  assert.equal(
    replayed.response.request().postData(),
    created.response.request().postData(),
  );
  assert.deepEqual(replayed.data.endpoint, created.data.endpoint);
  assert.equal(replayed.data.replayed, true);
  await manager.page
    .getByRole("button", {
      name: "Use confirmed endpoint version",
      exact: true,
    })
    .click();
  await manager.page
    .getByRole("button", {
      name: "Receive as " + c.manager_actor.slice(0, 8),
      exact: true,
    })
    .click();
  await manager.page
    .getByRole("button", { name: "Review endpoint replacement", exact: true })
    .click();
  phase = "manager-replace";
  const replaced = await managerCommand();
  assert.equal(replaced.data.endpoint.id, created.data.endpoint.id);
  assert.equal(replaced.data.endpoint.revision, 2);
  assert.equal(replaced.data.endpoint.state, "active");
  assert.equal(
    replaced.data.endpoint.definition.recipient.actor_id,
    c.manager_actor,
  );
  assert.notEqual(
    replaced.data.endpoint.definition_hash,
    created.data.endpoint.definition_hash,
  );
  endpointCommands++;
  await accessibility(manager.page, "manager-replace-accessibility");
  await manager.page
    .getByRole("button", {
      name: "Use confirmed endpoint version",
      exact: true,
    })
    .click();
  await manager.page
    .getByRole("button", { name: "Review endpoint revocation", exact: true })
    .click();
  phase = "manager-revoke";
  const removed = await managerCommand();
  assert.equal(removed.data.endpoint.id, created.data.endpoint.id);
  assert.equal(removed.data.endpoint.revision, 3);
  assert.equal(removed.data.endpoint.state, "revoked");
  assert.equal(
    removed.data.endpoint.definition_hash,
    replaced.data.endpoint.definition_hash,
  );
  endpointCommands++;
  await accessibility(manager.page, "manager-revoke-accessibility");
  await manager.context.close();

  phase = "onward-login";
  assert.equal(
    await recipient.page
      .getByRole("button", { name: "Onward delivery", exact: true })
      .count(),
    0,
  );
  const operator = await login(c.onward_token);
  await operator.page
    .getByRole("button", { name: "Onward delivery", exact: true })
    .click();
  await operator.page
    .getByLabel("Onward source file revision ID", { exact: true })
    .fill(c.onward_file);
  await operator.page
    .getByLabel("Approved onward workflow ID", { exact: true })
    .fill(c.onward_workflow);
  await operator.page
    .getByLabel("Approved onward workflow SHA256", { exact: true })
    .fill(c.onward_hash);
  phase = "onward-review";
  await operator.page
    .getByRole("button", { name: "Review onward delivery", exact: true })
    .click();
  await operator.page
    .getByRole("heading", { name: "Review exact onward delivery", exact: true })
    .waitFor();
  assert.ok(
    (await operator.page.locator("body").innerText()).includes(c.onward_hash),
  );
  await accessibility(operator.page, "onward-review-accessibility");
  phase = "onward-save-recovery";
  const onwardDownload = operator.page.waitForEvent("download");
  await operator.page
    .getByRole("button", { name: "Save onward recovery", exact: true })
    .click();
  const onwardSavedFile = await onwardDownload;
  assert.equal(
    onwardSavedFile.suggestedFilename(),
    "freightctl-onward-recovery.json",
  );
  assert.equal(await onwardSavedFile.failure(), null);
  await onwardSavedFile.saveAs(c.onward_recovery);
  await chmod(c.onward_recovery, 0o600);
  const onwardSaved = JSON.parse(await readFile(c.onward_recovery, "utf8"));
  assert.equal(
    onwardSaved.review.request.artifact.file_revision_id,
    c.onward_file,
  );
  const untrustedSaved = structuredClone(onwardSaved);
  untrustedSaved.review.effects[0].connection.id = c.endpoint;
  await writeFile(
    c.onward_recovery + ".untrusted.json",
    JSON.stringify(untrustedSaved),
    { mode: 0o600, flag: "wx" },
  );
  let acceptedRun;
  const startURL = `${origin.origin}/v1/tenants/${c.tenant}/partners/${c.partner}/onward/runs`;
  // Send the original request to the actual server, then deliberately lose its
  // real response. No fabricated acceptance or replay response is supplied.
  await operator.page.route(
    startURL,
    guardRoute(async (route) => {
      assert.equal(route.request().method(), "POST");
      assert.equal(
        route.request().headers()["idempotency-key"],
        onwardSaved.request_key,
      );
      const response = await fetchPinnedBrowserRequest(
        route.request(),
        origin.origin,
        Buffer.from(c.certificate_der, "base64"),
      );
      assert.equal(response.status, 200);
      const actual = JSON.parse(response.body);
      assert.equal(actual.replayed, false);
      acceptedRun = actual.resource.id;
      assert.equal(
        actual.resource.onward_review_hash,
        onwardSaved.review.review_hash,
      );
      await route.abort("failed");
    }),
  );
  phase = "onward-lost-response";
  await operator.page
    .getByRole("button", {
      name: "Confirm queue or recover original run",
      exact: true,
    })
    .click();
  await operator.page.getByRole("alert").waitFor();
  assert.match(acceptedRun, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.equal(
    await operator.page
      .getByRole("heading", { name: "Recorded onward run", exact: true })
      .count(),
    0,
  );
  onwardRuns++;
  phase = "onward-reload-recovery";
  await operator.page.unroute(startURL);
  await operator.page.reload();
  await operator.page
    .getByRole("button", { name: "Onward delivery", exact: true })
    .click();
  const beforeOnwardImport = onwardRequests;
  await operator.page
    .getByLabel("Import saved onward review", { exact: true })
    .setInputFiles(c.onward_recovery + ".untrusted.json");
  await operator.page
    .getByRole("status")
    .filter({ hasText: "Saved review imported." })
    .waitFor();
  assert.equal(onwardRequests, beforeOnwardImport);
  assert.equal(
    await operator.page
      .getByRole("button", {
        name: "Confirm queue or recover original run",
        exact: true,
      })
      .isDisabled(),
    true,
  );
  assert.equal(
    await operator.page
      .getByRole("heading", { name: "Recorded onward run", exact: true })
      .count(),
    0,
  );
  await accessibility(operator.page, "onward-recovery-accessibility");
  phase = "onward-receipt";
  const onwardReceipt = operator.page.waitForResponse((r) =>
    new URL(r.url()).pathname.endsWith("/onward/receipts"),
  );
  await operator.page
    .getByRole("button", {
      name: "Find original onward receipt only",
      exact: true,
    })
    .click();
  const onwardReceiptResponse = await onwardReceipt;
  assert.equal(onwardReceiptResponse.status(), 200);
  const recoveredOnward = await onwardReceiptResponse.json();
  assert.equal(recoveredOnward.replayed, true);
  assert.equal(recoveredOnward.resource.id, acceptedRun);
  await operator.page
    .getByRole("heading", { name: "Recorded onward run", exact: true })
    .waitFor();
  onwardRecoveries++;
  await accessibility(operator.page, "onward-receipt-accessibility");
  assert.equal(
    await operator.page
      .getByRole("button", {
        name: "Perform one onward work step",
        exact: true,
      })
      .isDisabled(),
    true,
  );
  phase = "onward-verify-review";
  const freshOnwardReview = operator.page.waitForResponse((r) =>
    new URL(r.url()).pathname.endsWith("/onward/previews"),
  );
  await operator.page
    .getByRole("button", {
      name: "Verify saved onward review with server",
      exact: true,
    })
    .click();
  assert.equal((await freshOnwardReview).status(), 200);
  await operator.page
    .getByRole("button", {
      name: "Verify saved onward review with server",
      exact: true,
    })
    .waitFor({ state: "hidden" });
  assert.ok(
    (
      await operator.page
        .getByRole("region", { name: "Exact onward review", exact: true })
        .innerText()
    ).includes(onwardSaved.review.effects[0].connection.id),
  );
  assert.equal(
    await operator.page
      .getByRole("button", {
        name: "Perform one onward work step",
        exact: true,
      })
      .isDisabled(),
    false,
  );
  phase = "onward-status";
  await operator.page
    .getByRole("button", { name: "Inspect current onward state", exact: true })
    .click();
  await operator.page
    .getByRole("heading", { name: "Current onward observation", exact: true })
    .waitFor();
  const observedOnward = await operator.page
    .getByRole("region", { name: "Current onward observation", exact: true })
    .innerText();
  assert.ok(observedOnward.includes("Observed state: queued"));
  assert.ok(observedOnward.includes("Receiver persistence: unknown"));
  await accessibility(operator.page, "onward-status-accessibility");
  phase = "audit-login";
  const auditor = await login(c.audit_token);
  const historyURL =
    origin.origin +
    `/v1/tenants/${c.tenant}/partners/${c.partner}/audit/history/search`;
  auditor.page.on("request", (r) => {
    if (r.url() === historyURL && r.method() === "POST") historySearches++;
  });
  await auditor.page
    .getByRole("button", { name: "Audit history", exact: true })
    .click();
  const auditRegion = auditor.page.getByRole("region", {
    name: "Operator audit history",
    exact: true,
  });
  await auditRegion
    .getByLabel("Actor ID (optional)", { exact: true })
    .fill(c.sender_actor);
  await auditRegion
    .getByLabel("Event type (optional)", { exact: true })
    .fill("FileAccepted");
  await auditRegion
    .getByLabel("Actions per page", { exact: true })
    .selectOption("1");
  assert.equal(historySearches, 0);
  phase = "audit-first-page";
  const firstHistory = auditor.page.waitForResponse(
    (r) => r.url() === historyURL && r.request().method() === "POST",
  );
  await auditRegion
    .getByRole("button", { name: "Search recorded actions", exact: true })
    .click();
  const firstHistoryResponse = await firstHistory;
  assert.equal(firstHistoryResponse.status(), 200);
  const firstPage = await firstHistoryResponse.json();
  assert.equal(firstPage.reader_actor_id, c.audit_actor);
  assert.equal(firstPage.payloads, "omitted");
  assert.equal(firstPage.events.length, 1);
  assert.ok(firstPage.next);
  assert.equal(firstPage.events[0].actor_id, c.sender_actor);
  assert.equal(firstPage.events[0].kind, "FileAccepted");
  assert.deepEqual(Object.keys(firstPage.events[0]).sort(), [
    "actor_id",
    "event_id",
    "kind",
    "recorded_at",
    "resource_id",
  ]);
  const historyTable = auditRegion.getByRole("table", {
    name: "Recorded action metadata",
    exact: true,
  });
  await historyTable.waitFor();
  assert.ok(
    (await historyTable.innerText()).includes(firstPage.events[0].event_id),
  );
  phase = "audit-first-accessibility";
  await accessibility(auditor.page, "audit-first-accessibility");
  phase = "audit-next-page";
  const secondHistory = auditor.page.waitForResponse(
    (r) => r.url() === historyURL && r.request().method() === "POST",
  );
  await auditRegion
    .getByRole("button", { name: "Next action page", exact: true })
    .click();
  const secondHistoryResponse = await secondHistory;
  assert.equal(secondHistoryResponse.status(), 200);
  const secondPage = await secondHistoryResponse.json();
  assert.equal(secondPage.events.length, 1);
  assert.equal(secondPage.next, undefined);
  assert.notEqual(secondPage.events[0].event_id, firstPage.events[0].event_id);
  assert.deepEqual(
    new Set([
      firstPage.events[0].resource_id,
      secondPage.events[0].resource_id,
    ]),
    new Set([c.file, uploadedFile]),
  );
  await historyTable.waitFor();
  assert.ok(
    (await historyTable.innerText()).includes(secondPage.events[0].event_id),
  );
  assert.equal(
    await auditRegion
      .getByRole("button", { name: "Next action page", exact: true })
      .count(),
    0,
  );
  phase = "audit-next-accessibility";
  await accessibility(auditor.page, "audit-next-accessibility");
  phase = "audit-resource-search";
  await auditRegion
    .getByLabel("File or resource ID (optional)", { exact: true })
    .fill(c.file);
  const resourceHistory = auditor.page.waitForResponse(
    (r) => r.url() === historyURL && r.request().method() === "POST",
  );
  await auditRegion
    .getByRole("button", { name: "Search recorded actions", exact: true })
    .click();
  const resourceHistoryResponse = await resourceHistory;
  assert.equal(resourceHistoryResponse.status(), 200);
  const resourcePage = await resourceHistoryResponse.json();
  assert.equal(resourcePage.events.length, 1);
  assert.equal(resourcePage.events[0].resource_id, c.file);
  assert.equal(resourcePage.events[0].event_id, c.audit_event);
  assert.equal(resourcePage.next, undefined);
  assert.equal(historySearches, 3);
  await historyTable.waitFor();
  assert.ok((await historyTable.innerText()).includes(c.audit_event));
  phase = "audit-resource-accessibility";
  await accessibility(auditor.page, "audit-resource-accessibility");
  phase = "revocation-barrier";
  await writeFile(c.ready, "ready\n", { mode: 0o600, flag: "wx" });
  const deadline = Date.now() + 15000;
  for (;;) {
    try {
      assert.equal(await readFile(c.revoked, "utf8"), "revoked\n");
      break;
    } catch (error) {
      if (error.code !== "ENOENT" || Date.now() >= deadline) throw error;
    }
    await delay(25);
  }
  phase = "onward-refusal";
  const onwardWork = operator.page.waitForResponse((r) =>
    new URL(r.url()).pathname.endsWith("/onward/work"),
  );
  await operator.page
    .getByRole("button", { name: "Perform one onward work step", exact: true })
    .click();
  assert.equal((await onwardWork).status(), 409);
  await operator.page
    .getByRole("button", {
      name: "Retry the same onward work step",
      exact: true,
    })
    .waitFor();
  await operator.page.getByRole("alert").waitFor();
  onwardRefusals++;
  await accessibility(operator.page, "onward-refusal-accessibility");
  await operator.context.close();
  phase = "revoked-discovery";
  const refusal = recipient.page.waitForResponse((r) =>
    r.url().includes("/exchange-endpoints/" + c.endpoint + "/incoming?"),
  );
  await recipient.page
    .getByRole("button", { name: "Check for new artifacts", exact: true })
    .click();
  assert.equal((await refusal).status(), 404);
  await recipient.page.getByRole("alert").waitFor();
  assert.equal(
    await recipient.page
      .getByRole("link", { name: "Download artifact", exact: true })
      .count(),
    0,
  );
  assert.equal(
    (await recipient.page.locator("body").innerText()).includes(c.sha256),
    false,
  );
  await accessibility(recipient.page, "revoked-accessibility");
  assert.equal(egress, 0);
  await recipient.context.close();
  if (routeFailed) throw routeFailure;
  state = "passed";
  phase = "complete";
} catch (error) {
  const original = routeFailed ? routeFailure : error;
  if (routeFailed) phase = routeFailurePhase;
  const raw = String(original?.stack ?? original);
  await writeFile(c.failure, raw, { mode: 0o600, flag: "wx" });
  failureHash = createHash("sha256").update(raw).digest("hex");
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  const result = {
    state,
    phase,
    external_egress: egress,
    exact_downloads: downloads,
    terminal_declines: declines,
    committed_offers: offers,
    sender_cancellations: cancels,
    recovery_roundtrips: recoveryRoundtrips,
    endpoint_commands: endpointCommands,
    human_ingress: humanIngress,
    onward_runs: onwardRuns,
    onward_recoveries: onwardRecoveries,
    onward_refusals: onwardRefusals,
    model_started: false,
    browser_sandbox: true,
    accessibility_checks: accessibilityChecks,
    evidence_reads: evidenceReads,
    owned_copies: ownedCopies,
    copy_recoveries: copyRecoveries,
    history_searches: historySearches,
    browser_version: browser?.version() ?? "",
    node_version: process.version,
    axe_version: axe.version,
    ...(failureHash ? { failure_sha256: failureHash } : {}),
  };
  await writeFile(c.result, JSON.stringify(result) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
  console.log(JSON.stringify(result));
}
