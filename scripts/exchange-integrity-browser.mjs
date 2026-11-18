import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";

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
const exchange = `${prefix}/exchanges/${config.exchange}`;
const reportPath = exchange + "/integrity-report";
const tracePath = prefix + "/exchange-traces/previews";
const cert = new X509Certificate(Buffer.from(config.certificate_der, "base64"));
const pin = createHash("sha256")
  .update(cert.publicKey.export({ type: "spki", format: "der" }))
  .digest("base64");
const summary = {
  phase: "launch",
  browser: "",
  node: process.version,
  writes: 0,
  runtime_errors: 0,
  blocked: 0,
  accessibility: 0,
  copy_lineage_checks: 0,
  event: "",
};
const writes = [];
const button = (scope, name) =>
  scope.getByRole("button", { name, exact: true });
const label = (scope, name) => scope.getByLabel(name, { exact: true });
const reportPanel = (page) =>
  page.getByRole("region", { name: "Recipient integrity report", exact: true });
let browser;

async function login(token, sender = false) {
  const context = await browser.newContext({
    serviceWorkers: "block",
    acceptDownloads: true,
  });
  await context.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin === origin.origin) {
      if (request.method() === "GET" || request.method() === "HEAD")
        return route.continue();
      if (
        request.method() === "POST" &&
        [prefix + "/browser-session", tracePath].includes(url.pathname)
      )
        return route.continue();
      if (
        !sender &&
        request.method() === "POST" &&
        url.pathname === reportPath
      ) {
        summary.writes++;
        writes.push({
          key: (await request.allHeaders())["idempotency-key"],
          body: request.postDataJSON(),
        });
        return route.continue();
      }
    }
    summary.blocked++;
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
  return { page, context };
}

async function inspectReport(page, direction, status) {
  const panel = reportPanel(page);
  const [response] = await Promise.all([
    page.waitForResponse(
      (r) => r.url() === config.origin + reportPath + "?direction=" + direction,
    ),
    button(panel, "Read integrity report").click(),
  ]);
  assert.equal(response.status(), status);
  return panel;
}

async function recorded(panel) {
  const statement = panel.getByText(
    /Recipient reported matching length and SHA-256\. Receiver persistence and business processing are unknown\./,
  );
  await statement.waitFor();
  return (await statement.getByRole("code").textContent()).trim();
}

async function readEvidence(page, direction, id = config.exchange) {
  const scope = page.getByRole("region", {
    name: "Recorded exchange evidence",
    exact: true,
  });
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.url() === config.origin + tracePath),
    button(scope, "Read recorded evidence").click(),
  ]);
  assert.equal(response.status(), 200);
  assert.deepEqual(response.request().postDataJSON(), {
    exchange_id: id,
    direction,
    profile: "authorized-exchange-evidence-v4",
  });
  return scope;
}

async function inspectEvidence(page, direction, event) {
  assert.equal(await recorded(await readEvidence(page, direction)), event);
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
    await browser.close();
  });
  summary.browser = browser.version();
  summary.phase = "recipient";
  const recipient = await login(config.recipient);
  const page = recipient.page;
  await button(page, "Receive artifacts").click();
  await button(page, "Find my receive endpoints").click();
  await button(page, "Open " + config.endpoint.slice(0, 8)).click();
  await button(page, "Inspect " + config.exchange.slice(0, 8)).click();
  const panel = await inspectReport(page, "incoming", 404);
  await panel
    .getByText("No integrity report is available for this offer.")
    .waitFor();

  summary.phase = "native-download";
  const link = panel.getByRole("link", {
    name: "Download for integrity report",
    exact: true,
  });
  const file = await link.getAttribute("href");
  assert.ok(
    file.startsWith(exchange + "/integrity-read/") && file.endsWith("/file"),
  );
  const selection = file.replace(/\/file$/, "/selection");
  const picker = label(panel, "Verify saved artifact");
  assert.equal(await picker.isEnabled(), false);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    link.click(),
  ]);
  assert.equal(await download.failure(), null);
  const savedPath = await download.path();
  const bytes = await readFile(savedPath);
  assert.equal(bytes.length, config.artifact.size_bytes);
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    config.artifact.sha256,
  );
  const markerName = "__Secure-freightctl-integrity-read";
  const cookies = await recipient.context.cookies(config.origin + selection);
  const marker = cookies.find((cookie) => cookie.name === markerName);
  assert.ok(marker?.httpOnly && marker.secure && marker.sameSite === "Strict");
  assert.equal(marker.path, selection);
  assert.ok(
    !(await recipient.context.cookies(config.origin + file)).some(
      (cookie) => cookie.name === markerName,
    ),
  );
  assert.doesNotMatch(
    await page.evaluate(() => document.cookie),
    /freightctl-integrity-read/,
  );

  summary.phase = "verify-local-file";
  const submit = button(panel, "Submit integrity report");
  await picker.setInputFiles({
    name: "short",
    mimeType: "application/octet-stream",
    buffer: bytes.subarray(1),
  });
  await panel
    .getByText("The selected file's length differs from the offer.")
    .waitFor();
  assert.equal(await submit.count(), 0);
  const wrong = Buffer.from(bytes);
  wrong[wrong.length - 1] ^= 1;
  await picker.setInputFiles({
    name: "changed",
    mimeType: "application/octet-stream",
    buffer: wrong,
  });
  await panel
    .getByText("The selected file's SHA-256 differs from the offer.")
    .waitFor();
  assert.equal(await submit.count(), 0);
  await picker.setInputFiles(savedPath);
  await panel
    .getByText(/The saved file matches the offered length and SHA-256/)
    .waitFor();
  assert.equal(await submit.isEnabled(), true);
  assert.equal(summary.writes, 0);

  summary.phase = "lost-receipt";
  await submit.click();
  await panel.getByText(/The browser did not receive a receipt/).waitFor();
  assert.equal(summary.writes, 1);
  const [replay] = await Promise.all([
    page.waitForResponse(
      (r) =>
        r.url() === config.origin + reportPath &&
        r.request().method() === "POST",
    ),
    submit.click(),
  ]);
  assert.equal(replay.status(), 200);
  assert.equal(summary.writes, 2);
  assert.deepEqual(writes[0], writes[1]);
  assert.match(writes[0].key, /^[0-9a-f-]{36}$/);
  assert.equal(
    writes[0].body.read_authorization_event_id,
    marker.value.split(".").at(-1),
  );
  assert.equal(
    writes[0].body.file_revision_id,
    config.artifact.file_revision_id,
  );
  assert.equal(writes[0].body.size_bytes, config.artifact.size_bytes);
  assert.equal(writes[0].body.sha256, config.artifact.sha256);
  summary.event = await recorded(panel);
  await inspectEvidence(page, "incoming", summary.event);
  assert.equal(
    await recorded(await inspectReport(page, "incoming", 200)),
    summary.event,
  );
  await accessibility(page, panel);
  await button(page, "Inspect " + config.copied_exchange.slice(0, 8)).click();
  const inboundCopy = await readEvidence(
    page,
    "incoming",
    config.copied_exchange,
  );
  await inboundCopy.getByText(/Source accepted into custody/).waitFor();
  assert.equal(
    await inboundCopy
      .getByRole("region", { name: "Received copy source" })
      .count(),
    0,
  );
  assert.ok(
    !(await inboundCopy.innerText()).includes(
      config.copy_lineage.source.exchange_id,
    ),
  );
  summary.copy_lineage_checks++;
  await recipient.context.close();

  summary.phase = "sender-history";
  const sender = await login(config.sender, true);
  await button(sender.page, "Sent artifacts").click();
  await button(
    sender.page,
    "Inspect sent " + config.exchange.slice(0, 8),
  ).click();
  const history = await inspectReport(sender.page, "outgoing", 200);
  assert.equal(await recorded(history), summary.event);
  await inspectEvidence(sender.page, "outgoing", summary.event);
  assert.equal(await button(history, "Submit integrity report").count(), 0);
  const denied = await sender.page.evaluate(
    async (paths) =>
      Promise.all(paths.map(async (path) => (await fetch(path)).status)),
    [selection, reportPath + "?direction=incoming"],
  );
  assert.deepEqual(denied, [404, 404]);
  await accessibility(sender.page, history);
  await button(
    sender.page,
    "Inspect sent " + config.copied_exchange.slice(0, 8),
  ).click();
  const sentCopy = await readEvidence(
    sender.page,
    "outgoing",
    config.copied_exchange,
  );
  const lineage = sentCopy.getByRole("region", {
    name: "Received copy source",
  });
  await lineage.waitFor();
  assert.deepEqual(await lineage.getByRole("code").allTextContents(), [
    config.copy_lineage.source.artifact.file_revision_id,
    config.copy_lineage.source.exchange_id,
    config.copy_lineage.source_accepted_event_id,
    config.copy_lineage.source_offer_event_id,
  ]);
  await accessibility(sender.page, lineage);
  summary.copy_lineage_checks++;
  await sender.context.close();
  summary.phase = "complete";
} finally {
  await browser?.close();
  await writeFile(config.result, JSON.stringify(summary) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
}
