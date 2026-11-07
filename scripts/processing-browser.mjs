// Native Chrome/HTTPS/PostgreSQL proof. Committed response loss never replaces
// the service: stock curl sends the original authenticated request to it.
import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
process.umask(0o077);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
assert.equal(new URL(c.url).protocol, "https:");
assert.equal(new URL(c.url).hostname, "127.0.0.1");
const require = createRequire(import.meta.url),
  { chromium } = require("../web/node_modules/playwright"),
  axe = require("../web/node_modules/axe-core");
const sha = (b) => createHash("sha256").update(b).digest("hex"),
  cert = new X509Certificate(Buffer.from(c.certificate_der, "base64")),
  spki = createHash("sha256")
    .update(cert.publicKey.export({ type: "spki", format: "der" }))
    .digest("base64"),
  ca = c.private + "/fixture-ca.pem",
  prefix = `/v1/tenants/${c.tenant}/partners/${c.partner}`;
await writeFile(ca, cert.toString());
let browser,
  file = "",
  run = "",
  state = "failed",
  failure = "",
  egress = 0,
  errors = 0,
  accessibility = 0;
const drafts = [];
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
  const context = await browser.newContext({
      viewport: { width: 1420, height: 1100 },
      acceptDownloads: true,
    }),
    page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", () => errors++);
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== c.url) egress++;
  });
  const button = (name, parent = page) =>
      parent.getByRole("button", { name, exact: true }),
    dialog = () => page.getByRole("dialog");
  async function audit(label) {
    await page.evaluate(
      await readFile(
        new URL("../web/node_modules/axe-core/axe.min.js", import.meta.url),
        "utf8",
      ),
    );
    const report = await page.evaluate(async () => {
      const r = await window.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
        },
      });
      return { passes: r.passes.length, violations: r.violations };
    });
    await writeFile(
      c.private + "/" + label + "-axe.json",
      JSON.stringify(report),
    );
    assert.equal(report.violations.length, 0);
    assert.ok(report.passes > 0);
    accessibility++;
  }
  async function api(path) {
    return page.evaluate(async (path) => {
      const r = await fetch(path, { credentials: "same-origin" });
      return { status: r.status, body: await r.text() };
    }, prefix + path);
  }
  await page.goto(c.url);
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await button("Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await button("Record processing").click();
  await page
    .getByLabel("Input file revision ID", { exact: true })
    .fill(c.source);
  await button("Load processing contracts").click();
  await page
    .getByRole("heading", { name: "Exact input and output contracts" })
    .waitFor();
  await page
    .getByLabel("Task name", { exact: true })
    .fill("Browser settlement processing");
  await page
    .getByLabel("Reason", { exact: true })
    .fill("Create reviewed settlement records");
  await page
    .getByLabel("Output logical path (optional)", { exact: true })
    .fill("/browser-derived.json");
  await audit("processing-editor");
  await button("Review processing task").click();
  await page.getByRole("heading", { name: "Task review passed" }).waitFor();
  assert.ok((await page.locator("code").allTextContents()).includes(c.hash));
  await button("Review saving this draft").click();
  await audit("processing-draft-review");
  const draftURL = c.url + prefix + "/workflows/drafts";
  const loseFirst = async (route) => {
    const request = route.request();
    if (request.method() !== "POST") {
      await route.continue();
      return;
    }
    assert.equal(request.url(), draftURL);
    const body = request.postDataBuffer(),
      headers = Object.entries(await request.allHeaders()).filter(([k]) =>
        [
          "content-type",
          "idempotency-key",
          "cookie",
          "origin",
          "x-csrf-token",
        ].includes(k),
      ),
      base = c.private + "/draft-" + drafts.length;
    assert.ok(body && body.length <= 32768);
    await writeFile(base + ".request", body);
    await writeFile(
      base + ".headers",
      headers.map(([k, v]) => k + ": " + v).join("\n") + "\n",
    );
    const code = execFileSync(
      "curl",
      [
        "-q",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--cacert",
        ca,
        "--max-time",
        "20",
        "--request",
        "POST",
        "--header",
        "@" + base + ".headers",
        "--data-binary",
        "@" + base + ".request",
        "--output",
        base + ".response",
        "--write-out",
        "%{http_code}",
        draftURL,
      ],
      { encoding: "utf8", maxBuffer: 65536 },
    );
    assert.equal(code, "200");
    const response = await readFile(base + ".response");
    drafts.push({
      key: headers.find(([k]) => k === "idempotency-key")?.[1],
      body: JSON.parse(body),
      reply: JSON.parse(response),
    });
    if (drafts.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: response,
      });
  };
  await page.route(draftURL, loseFirst);
  await button("Confirm this exact action", dialog()).click();
  await dialog().getByRole("alert").waitFor();
  const downloaded = page.waitForEvent("download");
  await button("Save recovery JSON", dialog()).click();
  const download = await downloaded,
    recovery = c.private + "/recovery.json";
  await download.saveAs(recovery);
  const saved = JSON.parse(await readFile(recovery, "utf8"));
  assert.equal(saved.request.key, drafts[0].key);
  assert.equal(JSON.stringify(saved).includes("csrf_token"), false);
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await button("Record processing").click();
  await page
    .getByLabel("Open processing recovery JSON", { exact: true })
    .setInputFiles(recovery);
  await dialog().waitFor();
  await button("Confirm this exact action", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await page.unroute(draftURL, loseFirst);
  assert.equal(drafts.length, 2);
  assert.equal(drafts[0].key, drafts[1].key);
  assert.deepEqual(drafts[0].body, drafts[1].body);
  assert.equal(drafts[0].reply.replayed, false);
  assert.equal(drafts[1].reply.replayed, true);
  assert.equal(drafts[0].reply.resource.definition_hash, c.hash);
  const configured = page.getByRole("region", {
    name: "Processing task revision",
  });
  await configured.waitFor();
  await button("Review approving this task", configured).click();
  await audit("processing-approval-review");
  await button("Confirm this exact action", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await page
    .getByLabel("Input file revision ID", { exact: true })
    .fill(c.source);
  await button("Review running on this input", configured).click();
  await button("Confirm this exact action", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  const outcome = page.getByRole("region", { name: "Processing run outcome" });
  await outcome.waitFor();
  await button("Review working this run", outcome).click();
  const worked = page.waitForResponse(
    (r) => r.url().endsWith("/work") && r.request().method() === "POST",
  );
  await button("Confirm this exact action", dialog()).click();
  const response = await worked;
  assert.equal(response.status(), 200);
  const work = await response.json();
  run = work.status.run.id;
  file = work.status.processing.output_file_id;
  assert.equal(work.status.observed_reason, "output_held");
  assert.equal(work.status.processing.released, false);
  assert.equal(work.status.steps.length, 0);
  await dialog().waitFor({ state: "hidden" });
  assert.equal((await api("/files/" + file)).status, 409);
  const held = JSON.parse((await api("/checks/" + file)).body);
  assert.equal(held.check.state, "held");
  assert.equal(held.check.attempts, 0);
  assert.equal(held.check.report_hash, "");
  await audit("processing-held-output");
  await button("Open output checks", outcome).click();
  await button("Run required checks").click();
  await page
    .getByText(
      "Validation passed. These bytes remain held until you approve release.",
      { exact: true },
    )
    .waitFor();
  assert.equal((await api("/files/" + file)).status, 409);
  await button("Review release").click();
  await button("Release file", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await button("Record processing").click();
  await button("Review recording current outcome", outcome).click();
  await button("Confirm this exact action", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await outcome
    .getByText(
      "The transformed output was checked and separately released. Nothing was sent onward.",
      { exact: false },
    )
    .waitFor();
  await audit("processing-released-output");
  const credential = await readFile(c.token, "utf8"),
    headers = c.private + "/download.headers",
    bytes = c.private + "/independent-output.json";
  await writeFile(headers, "Authorization: Bearer " + credential + "\n");
  const code = execFileSync(
    "curl",
    [
      "-q",
      "--silent",
      "--show-error",
      "--noproxy",
      "*",
      "--proto",
      "=https",
      "--cacert",
      ca,
      "--header",
      "@" + headers,
      "--output",
      bytes,
      "--write-out",
      "%{http_code}",
      c.url + prefix + "/files/" + file,
    ],
    { encoding: "utf8", maxBuffer: 65536 },
  );
  assert.equal(code, "200");
  assert.deepEqual(JSON.parse(await readFile(bytes, "utf8")), [
    { account: "0001", amount: 1.01, day: "2026-10-28" },
  ]);
  assert.equal(egress, 0);
  assert.equal(errors, 0);
  state = "passed";
} catch (error) {
  const raw = String(error.stack ?? error);
  failure = sha(raw);
  await writeFile(c.private + "/failure.log", raw);
} finally {
  if (browser) await browser.close();
  await writeFile(
    c.result,
    JSON.stringify({
      state,
      file,
      run,
      definition_hash: c.hash,
      draft_requests: drafts.length,
      accessibility_checks: accessibility,
      external_egress: egress,
      runtime_errors: errors,
      browser_sandbox: true,
      inference_performed: false,
      failure_sha256: failure,
    }) + "\n",
  );
}
if (state !== "passed") process.exitCode = 1;
