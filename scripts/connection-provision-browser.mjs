import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  fetchPinnedBrowserRequest,
  guardBrowserCommandRoute,
} from "./browser-pinned-https.mjs";

process.umask(0o077);
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const config = JSON.parse(await readFile(process.argv[2], "utf8"));
const origin = new URL(config.url);
assert.equal(origin.origin, config.url);
assert.equal(origin.protocol, "https:");
assert.equal(origin.hostname, "127.0.0.1");
const certificate = Buffer.from(config.certificate_der, "base64");
const pin = createHash("sha256")
  .update(
    new X509Certificate(certificate).publicKey.export({
      type: "spki",
      format: "der",
    }),
  )
  .digest("base64");
const routes = `/v1/tenants/${config.tenant}/partners/${config.partner}/connections/provisioning`;
let browser, first, routeError;
const requests = [];
const summary = {
  state: "failed",
  phase: "launch",
  browser_version: "",
  browser_sandbox: false,
  connection: "",
  command_requests: 0,
  accessibility_checks: 0,
  external_egress: 0,
  runtime_errors: 0,
};
const button = (scope, name) =>
  scope.getByRole("button", { name, exact: true });

async function signedIn(credential) {
  const context = await browser.newContext({
    serviceWorkers: "block",
    viewport: { width: 1180, height: 800 },
  });
  await context.route(
    "**/*",
    guardBrowserCommandRoute(
      async (route) => {
        const request = route.request(),
          url = new URL(request.url());
        if (url.origin !== origin.origin) {
          summary.external_egress++;
          await route.abort();
          return;
        }
        if (
          url.pathname !== routes + "/commands" ||
          request.method() !== "POST"
        ) {
          await route.continue();
          return;
        }
        const headers = await request.allHeaders();
        requests.push({
          key: headers["idempotency-key"],
          command: request.postDataJSON(),
        });
        summary.command_requests = requests.length;
        if (requests.length !== 1) {
          await route.continue();
          return;
        }
        // Omit just the first committed response. The service still receives the
        // browser's real cookie, CSRF header, request bytes and original key.
        const accepted = await fetchPinnedBrowserRequest(
          request,
          config.url,
          certificate,
        );
        assert.equal(accepted.status, 200);
        first = JSON.parse(accepted.body.toString("utf8"));
        assert.equal(first.replayed, false);
        await route.abort("failed");
      },
      (error) => {
        routeError ??= error;
      },
    ),
  );
  const page = await context.newPage();
  page.setDefaultTimeout(6500);
  page.on("pageerror", () => summary.runtime_errors++);
  await page.goto(config.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(config.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(config.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(credential);
  await button(page, "Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  return { context, page };
}

async function accessibility(page, selector) {
  await page.evaluate(require("../web/node_modules/axe-core").source);
  const violations = await page.evaluate(async (context) => {
    const result = await window.axe.run(context, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return result.violations.map((rule) => rule.id);
  }, selector);
  assert.deepEqual(violations, []);
  summary.accessibility_checks++;
}

try {
  const channel = process.env.FREIGHTCTL_BROWSER_CHANNEL;
  assert.ok(channel === undefined || channel === "chrome");
  browser = await chromium.launch({
    ...(channel ? { channel } : {}),
    headless: true,
    chromiumSandbox: true,
    args: [
      "--ignore-certificate-errors-spki-list=" + pin,
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
    ],
    timeout: 15000,
  });
  summary.browser_sandbox = true;
  summary.browser_version = browser.version();
  summary.phase = "review";
  const { context, page } = await signedIn(config.operator);
  await button(page, "SFTP routes").click();
  const panel = page.getByRole("region", {
    name: "SFTP route management",
    exact: true,
  });
  const source = panel.getByLabel("Registered SFTP source", { exact: true });
  const recipient = panel.getByLabel("Receiving account", { exact: true });
  await source.selectOption(config.source.id);
  await recipient.selectOption(config.recipient_id);
  assert.equal(
    await recipient.getByRole("option", { name: /Receiving-only/ }).count(),
    0,
  );
  assert.equal(
    await recipient.getByRole("option", { name: /Second-agent/ }).count(),
    1,
  );
  assert.equal(await source.getByRole("option").count(), 3);
  assert.equal(summary.command_requests, 0);
  await accessibility(page, 'section[aria-label="SFTP route management"]');
  await button(panel, "Review assignment").focus();
  await button(panel, "Review assignment").press("Enter");
  const review = page.getByRole("dialog", {
    name: "Review SFTP assignment",
    exact: true,
  });
  await review
    .getByText(config.source.key_fingerprint, { exact: true })
    .waitFor();
  await review
    .getByText(config.source.definition_hash, { exact: true })
    .waitFor();
  assert.equal(summary.command_requests, 0);
  await accessibility(page, "dialog[open]");
  summary.phase = "lost-reply";
  await button(review, "Assign SFTP route").click();
  await review
    .getByText("The result is uncertain.", { exact: false })
    .waitFor();
  if (routeError) throw routeError;
  assert.deepEqual(requests[0].command.source, {
    id: config.source.id,
    version: config.source.version,
    hash: config.source.definition_hash,
  });
  assert.equal(requests[0].command.recipient_actor_id, config.recipient_id);
  summary.connection = first.resource.connection.id;

  summary.phase = "reload-and-recover";
  await page.reload();
  await button(page, "SFTP routes").click();
  const reply = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === routes + "/commands" &&
      r.request().method() === "POST",
  );
  await button(review, "Assign SFTP route").click();
  const recovered = await (await reply).json();
  assert.equal(recovered.replayed, true);
  assert.deepEqual(recovered.resource, first.resource);
  assert.deepEqual(requests[1], requests[0]);
  await panel
    .getByText(`Original receipt recovered for ${summary.connection}.`, {
      exact: true,
    })
    .waitFor();

  summary.phase = "withdraw";
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(
    await panel.evaluate(
      (node) => node.getBoundingClientRect().right <= innerWidth,
    ),
    true,
  );
  const row = panel.getByRole("row").filter({ hasText: summary.connection });
  await button(row, "Review withdrawal").click();
  const withdrawal = page.getByRole("dialog", {
    name: "Review SFTP withdrawal",
    exact: true,
  });
  await withdrawal
    .getByText(first.resource.event_id, { exact: true })
    .waitFor();
  assert.equal(summary.command_requests, 2);
  const withdrawalReply = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === routes + "/commands" &&
      r.request().method() === "POST",
  );
  await button(withdrawal, "Withdraw SFTP route").click();
  const withdrawn = await withdrawalReply;
  assert.equal(withdrawn.status(), 200);
  assert.equal((await withdrawn.json()).resource.state, "revoked");
  await row.getByText("Withdrawn", { exact: true }).waitFor();
  assert.equal(requests[2].command.provision_event_id, first.resource.event_id);
  assert.deepEqual(requests[2].command.connection, first.resource.connection);
  await context.close();

  summary.phase = "recipient-scope";
  const limited = await signedIn(config.recipient);
  assert.equal(await button(limited.page, "SFTP routes").count(), 0);
  for (const list of ["sources", "recipients", "assignments"]) {
    const code = await limited.page.evaluate(
      async (path) => (await fetch(path)).status,
      routes + "/" + list,
    );
    assert.equal(code, 403);
  }
  await limited.context.close();
  if (routeError) throw routeError;
  assert.equal(summary.command_requests, 3);
  assert.equal(summary.external_egress, 0);
  assert.equal(summary.runtime_errors, 0);
  summary.state = "passed";
  summary.phase = "complete";
} finally {
  try {
    await browser?.close();
  } finally {
    await writeFile(config.result, JSON.stringify(summary) + "\n", {
      mode: 0o600,
    });
  }
}
