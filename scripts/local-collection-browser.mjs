// Actual GitHub Chrome/HTTPS/PostgreSQL local collection. No local model or
// synthetic command response;only the first real committed work reply is lost.
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { createRequire } from "node:module";

process.umask(0o077);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const axe = require("../web/node_modules/axe-core");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const certificate = new X509Certificate(
  Buffer.from(c.certificate_der, "base64"),
);
const origin = new URL(c.url);
assert.equal(origin.protocol, "https:");
assert.equal(origin.hostname, "127.0.0.1");
assert.equal(origin.pathname, "/");
const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
let browser,
  state = "failed",
  phase = "launch",
  egress = 0,
  errors = 0,
  accessibility = 0,
  job = "",
  work = [];
try {
  const pin = createHash("sha256")
    .update(certificate.publicKey.export({ type: "spki", format: "der" }))
    .digest("base64");
  browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
    channel: "chrome",
    args: [
      "--ignore-certificate-errors-spki-list=" + pin,
      "--disable-background-networking",
      "--disable-component-update",
    ],
  });
  const context = await browser.newContext({ acceptDownloads: false });
  await context.route("**/*", async (route) => {
    if (new URL(route.request().url()).origin !== origin.origin) {
      egress++;
      await route.abort("blockedbyclient");
    } else await route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => errors++);
  const button = (scope, name) =>
    scope.getByRole("button", { name, exact: true });
  const audit = async () => {
    await page.evaluate(axe.source);
    const result = await page.evaluate(() =>
      axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"],
        },
      }),
    );
    assert.equal(result.violations.length, 0);
    accessibility++;
  };
  const response = async (path, action) => {
    const [r] = await Promise.all([
      page.waitForResponse(
        (r) => r.url() === prefix + path && r.status() === 200,
      ),
      action(),
    ]);
    return r.json();
  };
  phase = "login";
  await page.goto(c.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await button(page, "Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  phase = "review";
  await button(page, "Collections").click();
  const region = page.getByRole("region", {
    name: "Collection workflows",
    exact: true,
  });
  await region
    .getByLabel("Saved collection workflow", { exact: true })
    .selectOption(c.workflow.id + ":" + c.workflow.version);
  const source = region.getByRole("region", {
    name: "Selected workflow definition",
    exact: true,
  });
  await source.getByText(c.root_fingerprint, { exact: true }).waitFor();
  const text = await source.innerText();
  assert.ok(text.includes("Read-only source"));
  assert.ok(text.includes("no outgoing receiver"));
  assert.equal(text.includes(c.directory), false);
  assert.equal(text.includes(c.configuration), false);
  await audit();
  phase = "preview";
  const preview = await response("/workflow-collections/preview", () =>
    button(region, "Preview collection job").click(),
  );
  assert.equal(preview.external_contact, false);
  assert.equal(preview.approval_required, true);
  assert.equal(preview.definition.source.kind, "local.collect");
  assert.equal(preview.definition.source_connection.local.read_only, true);
  assert.deepEqual(preview.definition.effects, []);
  await button(region, "Review queueing collection").click();
  await audit();
  phase = "queue";
  const queued = await response("/workflow-collections", () =>
    button(page, "Confirm exact decision").click(),
  );
  job = queued.resource.id;
  assert.equal(queued.resource.state, "queued");
  const selected = page.getByRole("region", {
    name: "Selected collection",
    exact: true,
  });
  await selected
    .getByRole("heading", { name: "Collection: queued", exact: true })
    .waitFor();
  await button(selected, "Review reading source batch").click();
  await audit();
  phase = "capture-replay";
  const target = prefix + "/workflow-collections/" + job + "/work";
  await page.route(target, async (route) => {
    const r = route.request(),
      body = r.postDataBuffer(),
      headers = await r.allHeaders();
    assert.equal(r.method(), "POST");
    assert.ok(body && body.length <= 32768);
    assert.ok(headers["idempotency-key"]);
    const allowed = Object.fromEntries(
      Object.entries(headers).filter(([k]) =>
        [
          "content-type",
          "idempotency-key",
          "cookie",
          "origin",
          "x-csrf-token",
        ].includes(k),
      ),
    );
    // Per-request exact fixture CA,ordinary hostname verification and no proxy.
    // This sends the browser's real unchanged cookie/CSRF/key/body to the service.
    const reply = await new Promise((resolve, reject) => {
      const req = httpsRequest(
        target,
        {
          method: "POST",
          headers: { ...allowed, "content-length": String(body.length) },
          ca: certificate.toString(),
          agent: false,
        },
        (res) => {
          const parts = [];
          let count = 0;
          res.on("data", (b) => {
            count += b.length;
            if (count > 32768)
              res.destroy(new Error("bounded work receipt exceeded"));
            else parts.push(b);
          });
          res.once("error", reject);
          res.once("end", () =>
            resolve({
              status: res.statusCode,
              body: Buffer.concat(parts).toString("utf8"),
            }),
          );
        },
      );
      req.setTimeout(30000, () =>
        req.destroy(new Error("ordinary command deadline")),
      );
      req.once("error", reject);
      req.end(body);
    });
    assert.equal(reply.status, 200);
    const receipt = JSON.parse(reply.body);
    work.push({ key: headers["idempotency-key"], request: sha(body), receipt });
    if (work.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: reply.status,
        contentType: "application/json",
        body: reply.body,
      });
  });
  await button(page, "Confirm exact decision").click();
  await page.getByText(/^The result was not confirmed\./).waitFor();
  await button(page, "Confirm exact decision").click();
  await page.locator("dialog[open]").waitFor({ state: "hidden" });
  await page.unroute(target);
  assert.equal(work.length, 2);
  assert.equal(work[0].key, work[1].key);
  assert.equal(work[0].request, work[1].request);
  assert.equal(work[0].receipt.replayed, false);
  assert.equal(work[1].receipt.replayed, true);
  assert.deepEqual(work[0].receipt.resource, work[1].receipt.resource);
  phase = "receipt";
  const captured = await response("/workflow-collections/" + job, () =>
    button(selected, "Refresh selected collection").click(),
  );
  assert.equal(captured.job.state, "captured");
  assert.equal(captured.job.captured, true);
  assert.equal(captured.inputs.length, 1);
  assert.equal(captured.inputs[0].run_id, null);
  assert.equal(captured.business_acceptance, "unknown");
  assert.deepEqual(captured.job.definition.effects, []);
  await selected
    .getByRole("heading", { name: "Collection: captured", exact: true })
    .waitFor();
  await audit();
  assert.equal(egress, 0);
  assert.equal(errors, 0);
  state = "passed";
  phase = "complete";
  await context.close();
} catch (error) {
  const raw = String(error?.stack ?? error);
  await writeFile(c.failure, raw, { flag: "wx", mode: 0o600 });
  process.exitCode = 1;
} finally {
  const version = browser?.version() ?? "";
  if (browser) await browser.close();
  const result = {
    state,
    phase,
    job,
    external_egress: egress,
    runtime_errors: errors,
    accessibility_checks: accessibility,
    work_requests: work.length,
    browser_sandbox: true,
    inference_performed: false,
    browser_version: version,
    node_version: process.version,
    axe_version: axe.version,
  };
  await writeFile(c.result, JSON.stringify(result) + "\n", {
    flag: "wx",
    mode: 0o600,
  });
}
