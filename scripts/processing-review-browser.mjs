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
  { chromium } = require("../web/node_modules/playwright");
const sha = (b) => createHash("sha256").update(b).digest("hex"),
  cert = new X509Certificate(Buffer.from(c.certificate_der, "base64")),
  spki = createHash("sha256")
    .update(cert.publicKey.export({ type: "spki", format: "der" }))
    .digest("base64"),
  ca = c.private + "/fixture-ca.pem",
  prefix = `/v1/tenants/${c.tenant}/partners/${c.partner}`;
await writeFile(ca, cert.toString());
let browser,
  state = "failed",
  failure = "",
  review = "",
  egress = 0,
  errors = 0,
  accessibility = 0;
const proposals = [];
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
  const button = (page, name) =>
    page.getByRole("button", { name, exact: true });
  async function login(token) {
    const context = await browser.newContext({
      viewport: { width: 1420, height: 1100 },
      acceptDownloads: true,
    });
    await context.route("**/*", async (route) => {
      if (new URL(route.request().url()).origin !== c.url) {
        egress++;
        await route.abort();
      } else await route.continue();
    });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.on("pageerror", () => errors++);
    await page.goto(c.url);
    await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
    await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
    await page
      .getByLabel("Account credential file", { exact: true })
      .setInputFiles(token);
    await button(page, "Connect").click();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await button(page, "Record processing").click();
    return page;
  }
  async function audit(page, label) {
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
  async function save(page, path) {
    const download = page.waitForEvent("download");
    await button(page.getByRole("dialog"), "Save exact review request").click();
    await (await download).saveAs(path);
  }
  const owner = await login(c.worker_token);
  await owner.getByLabel("Workflow ID", { exact: true }).fill(c.workflow);
  await owner.getByLabel("Version", { exact: true }).fill("1");
  await button(owner, "Load task revision").click();
  await owner
    .getByRole("region", { name: "Processing task revision", exact: true })
    .waitFor();
  await owner
    .getByLabel("Reviewer actor ID", { exact: true })
    .fill(c.reviewer_id);
  await owner
    .getByLabel("Approval expiry (UTC)", { exact: true })
    .fill(c.expires_at);
  await button(owner, "Review disclosure and request").click();
  await owner.getByRole("dialog").waitFor();
  await audit(owner, "review-disclosure");
  const proposalURL = c.url + prefix + "/processing-reviews";
  const responseLoss = async (route) => {
    const request = route.request();
    if (request.method() !== "POST") {
      await route.continue();
      return;
    }
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
      base = c.private + "/proposal-" + proposals.length;
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
        proposalURL,
      ],
      { encoding: "utf8", maxBuffer: 65536 },
    );
    assert.equal(code, "200");
    const raw = await readFile(base + ".response");
    proposals.push({
      key: headers.find(([k]) => k === "idempotency-key")?.[1],
      body: JSON.parse(body),
      reply: JSON.parse(raw),
    });
    if (proposals.length === 1) await route.abort("failed");
    else
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: raw,
      });
  };
  await owner.route(proposalURL, responseLoss);
  await button(
    owner.getByRole("dialog"),
    "Confirm exact review command",
  ).click();
  await owner.getByRole("dialog").getByRole("alert").waitFor();
  const recovery = c.private + "/proposal-recovery.json";
  await save(owner, recovery);
  const saved = JSON.parse(await readFile(recovery, "utf8"));
  assert.equal(saved.request.key, proposals[0].key);
  assert.equal(JSON.stringify(saved).includes("csrf_token"), false);
  assert.equal(saved.request.kind, "request");
  await owner.reload();
  await owner.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await button(owner, "Record processing").click();
  const invalid = structuredClone(saved);
  invalid.server_origin = "https://unapproved.invalid";
  const invalidPath = c.private + "/invalid-recovery.json";
  await writeFile(invalidPath, JSON.stringify(invalid));
  await owner
    .getByLabel("Import independent review recovery JSON", { exact: true })
    .setInputFiles(invalidPath);
  await owner
    .getByText(
      "The command or current inspection was refused. A historical receipt is not current approval.",
      { exact: true },
    )
    .waitFor();
  assert.equal(proposals.length, 1);
  assert.equal(await owner.getByRole("dialog").count(), 0);
  await owner
    .getByLabel("Import independent review recovery JSON", { exact: true })
    .setInputFiles(recovery);
  await owner.getByRole("dialog").waitFor();
  await button(
    owner.getByRole("dialog"),
    "Confirm exact review command",
  ).click();
  await owner.getByRole("dialog").waitFor({ state: "hidden" });
  await owner.unroute(proposalURL, responseLoss);
  assert.equal(proposals.length, 2);
  assert.equal(proposals[0].key, proposals[1].key);
  assert.deepEqual(proposals[0].body, proposals[1].body);
  assert.equal(proposals[0].reply.replayed, false);
  assert.equal(proposals[1].reply.replayed, true);
  assert.equal(proposals[1].reply.resource.workflow_id, c.workflow);
  review = proposals[1].reply.resource.id;
  const ownCurrent = owner.getByRole("region", {
    name: "Current independent review",
    exact: true,
  });
  await ownCurrent.waitFor();
  assert.match(await ownCurrent.innerText(), /pending,\s*revision 1/);
  assert.equal(await button(owner, "Review independent approval").count(), 0);
  await audit(owner, "review-recovered-proposal");
  const reviewer = await login(c.reviewer_token);
  await reviewer
    .getByLabel("Independent review ID", { exact: true })
    .fill(review);
  await button(reviewer, "Inspect independent review").click();
  await reviewer
    .getByRole("region", { name: "Current independent review", exact: true })
    .waitFor();
  const access = await reviewer.evaluate(
    async (path) => {
      const r = await fetch(path, { credentials: "same-origin" });
      return r.status;
    },
    prefix + "/workflows/" + c.workflow + "/1",
  );
  assert.equal(access, 404);
  await button(reviewer, "Review independent approval").click();
  await reviewer.getByRole("dialog").waitFor();
  await audit(reviewer, "review-independent-approval");
  const approvalRecovery = c.private + "/approval-recovery.json";
  await save(reviewer, approvalRecovery);
  await button(
    reviewer.getByRole("dialog"),
    "Confirm exact review command",
  ).click();
  await reviewer.getByRole("dialog").waitFor({ state: "hidden" });
  await button(owner, "Inspect independent review").click();
  await button(owner, "Review adoption into my workflow").waitFor();
  await button(owner, "Review adoption into my workflow").click();
  await owner.getByRole("dialog").waitFor();
  await audit(owner, "review-separate-adoption");
  await button(
    owner.getByRole("dialog"),
    "Confirm exact review command",
  ).click();
  await owner.getByRole("dialog").waitFor({ state: "hidden" });
  await button(owner, "Load reviewed workflow revision").click();
  const configured = owner.getByRole("region", {
    name: "Processing task revision",
    exact: true,
  });
  await configured.waitFor();
  assert.ok((await configured.innerText()).includes("approved"));
  assert.ok((await configured.innerText()).includes(c.workflow_hash));
  await button(reviewer, "Inspect independent review").click();
  await button(reviewer, "Review withdrawal").click();
  await reviewer.getByRole("dialog").waitFor();
  await button(
    reviewer.getByRole("dialog"),
    "Confirm exact review command",
  ).click();
  await reviewer.getByRole("dialog").waitFor({ state: "hidden" });
  const reviewCurrent = reviewer.getByRole("region", {
    name: "Current independent review",
    exact: true,
  });
  assert.match(await reviewCurrent.innerText(), /withdrawn,\s*revision 4/);
  await audit(reviewer, "review-withdrawn");
  await reviewer
    .getByLabel("Import independent review recovery JSON", { exact: true })
    .setInputFiles(approvalRecovery);
  await reviewer.getByRole("dialog").waitFor();
  await button(
    reviewer.getByRole("dialog"),
    "Confirm exact review command",
  ).click();
  await reviewer.getByRole("dialog").waitFor({ state: "hidden" });
  assert.match(await reviewCurrent.innerText(), /withdrawn,\s*revision 4/);
  await reviewer
    .getByText(/Original command receipt: review.*state approved,\s*revision 2/)
    .waitFor();
  await audit(reviewer, "review-historical-approval-current-withdrawal");
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
      review,
      workflow_hash: c.workflow_hash,
      proposal_requests: proposals.length,
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
