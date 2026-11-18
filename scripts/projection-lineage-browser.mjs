import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createInterface } from "node:readline";

process.umask(0o077);
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const axe = require("../web/node_modules/axe-core");
const config = JSON.parse(await readFile(process.argv[2], "utf8"));
const origin = new URL(config.origin);
assert.equal(origin.origin, config.origin);
assert.equal(origin.protocol, "https:");
assert.equal(origin.hostname, "127.0.0.1");
const prefix = `/v1/tenants/${config.tenant}/partners/${config.partner}`;
const tracePath = `${prefix}/exchange-traces/previews`;
const cert = new X509Certificate(Buffer.from(config.certificate_der, "base64"));
const pin = createHash("sha256")
  .update(cert.publicKey.export({ type: "spki", format: "der" }))
  .digest("base64");
const v2 = "authorized-exchange-evidence-v2";
const v4 = "authorized-exchange-evidence-v4";
const summary = {
  phase: "launch",
  browser: "",
  node: process.version,
  sandbox: false,
  logins: 0,
  traces: 0,
  accessibility: 0,
  egress: 0,
  effect_requests: 0,
  runtime_errors: 0,
};
const button = (scope, name) =>
  scope.getByRole("button", { name, exact: true });
const region = (scope, name) =>
  scope.getByRole("region", { name, exact: true });
const label = (scope, name) => scope.getByLabel(name, { exact: true });
let browser;

async function login(token) {
  const context = await browser.newContext({ serviceWorkers: "block" });
  await context.route("**/*", async (route) => {
    const request = route.request();
    const uri = new URL(request.url());
    if (uri.origin !== origin.origin) {
      summary.egress++;
      return route.abort();
    }
    if (request.method() === "GET" || request.method() === "HEAD")
      return route.continue();
    if (
      request.method() === "POST" &&
      uri.pathname === `${prefix}/browser-session`
    ) {
      summary.logins++;
      return route.continue();
    }
    if (request.method() === "POST" && uri.pathname === tracePath) {
      summary.traces++;
      return route.continue();
    }
    summary.effect_requests++;
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  page.on("pageerror", () => summary.runtime_errors++);
  await page.goto(origin.origin);
  await label(page, "Tenant ID").fill(config.tenant);
  await label(page, "Partner ID").fill(config.partner);
  await label(page, "Account credential file").setInputFiles(token);
  await button(page, "Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  const cookies = await context.cookies(origin.origin);
  assert.deepEqual(
    cookies.map((cookie) => cookie.name),
    ["__Host-freightctl-session"],
  );
  assert.ok(cookies[0].secure && cookies[0].httpOnly);
  assert.equal(cookies[0].sameSite, "Strict");
  return { context, page };
}

async function readEvidence(page, direction) {
  const panel = region(page, "Recorded exchange evidence");
  const trigger = button(panel, "Read recorded evidence");
  const [response] = await Promise.all([
    page.waitForResponse(
      (r) =>
        r.url() === origin.origin + tracePath &&
        r.request().method() === "POST",
    ),
    trigger.click(),
  ]);
  assert.equal(response.status(), 200);
  const body = { exchange_id: config.exchange, direction, profile: v4 };
  assert.deepEqual(response.request().postDataJSON(), body);
  await trigger.waitFor();
  await panel.getByRole("listitem").first().waitFor();
  assert.equal(await panel.getByRole("listitem").count(), 2);
  assert.match(await panel.innerText(), /remain unknown/);
  return {
    panel,
    csrf: (await response.request().allHeaders())["x-csrf-token"],
  };
}

async function accessibility(page, panel) {
  await page.evaluate(axe.source);
  const violations = await panel.evaluate(async (element) => {
    const report = await window.axe.run(element, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return report.violations.map(({ id }) => id);
  });
  assert.deepEqual(violations, []);
  summary.accessibility++;
}

try {
  const channel = process.env.FREIGHTCTL_BROWSER_CHANNEL;
  assert.ok(channel === undefined || channel === "chrome");
  browser = await chromium.launch({
    ...(channel ? { channel } : {}),
    headless: true,
    chromiumSandbox: true,
    timeout: 15000,
    args: [
      "--ignore-certificate-errors-spki-list=" + pin,
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
    ],
  });
  process.once("SIGINT", async () => {
    process.exitCode = 130;
    process.stdin.destroy();
    await browser.close();
  });
  summary.browser = browser.version();
  summary.sandbox = true;

  summary.phase = "held-source";
  const sender = await login(config.sender);
  await button(sender.page, "Sent artifacts").click();
  await button(
    sender.page,
    "Inspect sent " + config.exchange.slice(0, 8),
  ).click();
  const held = await readEvidence(sender.page, "outgoing");
  assert.equal(
    await region(held.panel, "Record projection lineage").count(),
    0,
  );
  const checkpoint = createInterface({ input: process.stdin, terminal: false });
  process.stdout.write("source-held-confirmed\n");
  const released = await checkpoint[Symbol.asyncIterator]().next();
  checkpoint.close();
  assert.equal(released.value, "source-released");

  summary.phase = "released-source";
  const current = await readEvidence(sender.page, "outgoing");
  const lineage = region(current.panel, "Record projection lineage");
  await lineage.waitFor();
  const visible = await lineage.innerText();
  const expected = config.expected_lineage;
  for (const value of [
    expected.source_artifact.file_revision_id,
    expected.source_artifact.sha256,
    expected.source_accepted_event_id,
    expected.projection_id,
    expected.definition_hash,
    expected.completed_event_id,
    expected.completed_at,
  ])
    assert.ok(visible.includes(value));
  await accessibility(sender.page, current.panel);
  await sender.context.close();

  summary.phase = "recipient-boundary";
  const recipient = await login(config.recipient);
  await button(recipient.page, "Receive artifacts").click();
  await button(recipient.page, "Find my receive endpoints").click();
  await button(recipient.page, "Open " + config.endpoint.slice(0, 8)).click();
  await button(
    recipient.page,
    "Inspect " + config.exchange.slice(0, 8),
  ).click();
  const incoming = await readEvidence(recipient.page, "incoming");
  assert.equal(
    await region(incoming.panel, "Record projection lineage").count(),
    0,
  );
  for (const privateValue of [
    expected.source_artifact.file_revision_id,
    expected.source_artifact.sha256,
    expected.completed_event_id,
  ])
    assert.ok(!(await incoming.panel.innerText()).includes(privateValue));
  assert.ok(incoming.csrf);
  const direct = await recipient.page.evaluate(
    async (value) => {
      const trace = (direction) =>
        fetch(value.tracePath, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": value.csrf,
          },
          body: JSON.stringify({
            exchange_id: value.exchange,
            direction,
            profile: value.profile,
          }),
        });
      const incoming = await trace("incoming");
      const outgoing = await trace("outgoing");
      const source = await fetch(value.sourceURL, {
        credentials: "same-origin",
      });
      return {
        incomingStatus: incoming.status,
        outgoingStatus: outgoing.status,
        sourceStatus: source.status,
      };
    },
    {
      tracePath,
      csrf: incoming.csrf,
      exchange: config.exchange,
      profile: v2,
      sourceURL: `${prefix}/files/${expected.source_artifact.file_revision_id}`,
    },
  );
  assert.equal(direct.incomingStatus, 200);
  assert.equal(direct.outgoingStatus, 404);
  assert.equal(direct.sourceStatus, 404);
  await accessibility(recipient.page, incoming.panel);

  summary.phase = "exact-output-download";
  const [download] = await Promise.all([
    recipient.page.waitForEvent("download"),
    recipient.page
      .getByRole("row")
      .filter({ hasText: config.exchange })
      .getByRole("link", { name: "Download artifact", exact: true })
      .click(),
  ]);
  assert.equal(await download.failure(), null);
  const output = await readFile(await download.path());
  assert.equal(output.length, config.output.size_bytes);
  assert.equal(
    createHash("sha256").update(output).digest("hex"),
    config.output.sha256,
  );
  await recipient.context.close();
  summary.phase = "complete";
} finally {
  await browser?.close();
  await writeFile(config.result, JSON.stringify(summary) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
}
