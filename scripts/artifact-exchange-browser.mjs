// GitHub-only native receive UI proof. No raw credentials or responses in stdout.
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile, lstat, chmod } from "node:fs/promises";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";

assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
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
])
  assert.match(value, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
assert.match(c.sha256, /^[0-9a-f]{64}$/);
assert.match(c.closure_request_hash, /^[0-9a-f]{64}$/);
assert.notEqual(c.closure_exchange, c.exchange);
assert.ok(Number.isSafeInteger(c.size) && c.size > 0 && c.size < 16384);
const spki = createHash("sha256")
  .update(
    new X509Certificate(
      Buffer.from(c.certificate_der, "base64"),
    ).publicKey.export({ type: "spki", format: "der" }),
  )
  .digest("base64");
const { chromium } = createRequire(import.meta.url)(
  "../web/node_modules/playwright",
);
const axe = createRequire(import.meta.url)("../web/node_modules/axe-core");
let browser,
  phase = "launch",
  state = "failed",
  egress = 0,
  accessibilityChecks = 0,
  downloads = 0,
  declines = 0,
  offers = 0,
  cancels = 0,
  failureHash;
try {
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
        target.origin !== origin.origin ||
        !["GET", "POST"].includes(route.request().method())
      ) {
        egress++;
        return route.abort();
      }
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
  phase = "sender-login";
  const sender = await login(c.sender_token);
  await sender.page
    .getByRole("button", { name: "Send artifacts", exact: true })
    .click();
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
  await sender.page
    .getByLabel("Source file revision ID", { exact: true })
    .fill(c.file);
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
  assert.equal(sent.exchange.request.artifact.file_revision_id, c.file);
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
  state = "passed";
  phase = "complete";
} catch (error) {
  const raw = String(error?.stack ?? error);
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
    model_started: false,
    browser_sandbox: true,
    accessibility_checks: accessibilityChecks,
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
