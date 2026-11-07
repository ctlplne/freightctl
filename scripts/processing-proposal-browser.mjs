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
  sha = (b) => createHash("sha256").update(b).digest("hex"),
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
  proposal = "",
  workflow = "",
  accessibility = 0,
  egress = 0,
  errors = 0;
const submissions = [],
  adoptions = [];
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
    const r = await page.evaluate(async () => {
      const r = await window.axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
        },
      });
      return { passes: r.passes.length, violations: r.violations };
    });
    await writeFile(c.private + "/" + label + "-axe.json", JSON.stringify(r));
    assert.equal(r.violations.length, 0);
    assert.ok(r.passes > 0);
    accessibility++;
  }
  async function save(page, path) {
    const download = page.waitForEvent("download");
    await button(
      page.getByRole("dialog"),
      "Save exact proposal request",
    ).click();
    await (await download).saveAs(path);
  }
  async function reload(page) {
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await button(page, "Record processing").click();
  }
  function committedReplyLoss(url, records, label) {
    return async (route) => {
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
        base = c.private + "/" + label + "-" + records.length;
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
          url,
        ],
        { encoding: "utf8", maxBuffer: 65536 },
      );
      assert.equal(code, "200");
      const raw = await readFile(base + ".response");
      records.push({
        key: headers.find(([k]) => k === "idempotency-key")?.[1],
        body: JSON.parse(body),
        reply: JSON.parse(raw),
      });
      if (records.length === 1) await route.abort("failed");
      else
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: raw,
        });
    };
  }
  const author = await login(c.author_token);
  await author
    .getByLabel("Processing definition JSON", { exact: true })
    .setInputFiles(c.definition);
  await author
    .getByLabel("Executor actor ID", { exact: true })
    .fill(c.executor_id);
  await author
    .getByLabel("Proposal expiry (UTC)", { exact: true })
    .fill(c.expires_at);
  await button(author, "Review definition disclosure").click();
  await author.getByRole("dialog").waitFor();
  assert.match(
    await author.getByRole("dialog").innerText(),
    /Adoption records an unapproved executor-owned draft/,
  );
  await audit(author, "author-disclosure");
  const submissionURL = c.url + prefix + "/processing-proposals",
    submissionLoss = committedReplyLoss(
      submissionURL,
      submissions,
      "submission",
    );
  await author.route(submissionURL, submissionLoss);
  await button(
    author.getByRole("dialog"),
    "Confirm exact proposal command",
  ).click();
  await author.getByRole("dialog").getByRole("alert").waitFor();
  const submissionRecovery = c.private + "/submission-recovery.json";
  await save(author, submissionRecovery);
  const saved = JSON.parse(await readFile(submissionRecovery, "utf8"));
  assert.equal(saved.request.key, submissions[0].key);
  assert.equal(saved.request.kind, "submit");
  assert.ok(!JSON.stringify(saved).includes("csrf_token"));
  await audit(author, "author-unconfirmed");
  await reload(author);
  const invalid = { ...saved, server_origin: "https://unapproved.invalid" },
    invalidPath = c.private + "/invalid-recovery.json";
  await writeFile(invalidPath, JSON.stringify(invalid));
  await author
    .getByLabel("Import proposal recovery JSON", { exact: true })
    .setInputFiles(invalidPath);
  await author
    .getByText(
      "The request or inspection was refused. Review the current account and proposal.",
      { exact: true },
    )
    .waitFor();
  assert.equal(submissions.length, 1);
  assert.equal(await author.getByRole("dialog").count(), 0);
  await author
    .getByLabel("Import proposal recovery JSON", { exact: true })
    .setInputFiles(submissionRecovery);
  await author.getByRole("dialog").waitFor();
  await button(
    author.getByRole("dialog"),
    "Confirm exact proposal command",
  ).click();
  await author.getByRole("dialog").waitFor({ state: "hidden" });
  await author.unroute(submissionURL, submissionLoss);
  assert.equal(submissions.length, 2);
  assert.equal(submissions[0].key, submissions[1].key);
  assert.deepEqual(submissions[0].body, submissions[1].body);
  assert.equal(submissions[0].reply.replayed, false);
  assert.equal(submissions[1].reply.replayed, true);
  assert.deepEqual(
    submissions[0].reply.resource,
    submissions[1].reply.resource,
  );
  proposal = submissions[1].reply.resource.proposal.id;
  const authorCurrent = author.getByRole("region", {
    name: "Current definition proposal",
    exact: true,
  });
  await authorCurrent.waitFor();
  assert.match(await authorCurrent.innerText(), /pending,revision 1/);
  assert.equal(
    await button(authorCurrent, "Review adoption into a draft").isDisabled(),
    true,
  );
  const byteAccess = await author.evaluate(
    async (path) => (await fetch(path, { credentials: "same-origin" })).status,
    prefix + "/files/11111111-1111-4111-8111-111111111111",
  );
  assert.equal(byteAccess, 403);
  await audit(author, "recovered-author-proposal");
  const executor = await login(c.executor_token);
  await button(executor, "List my definition proposals").click();
  await button(executor, "Inspect proposal " + proposal).click();
  const executorCurrent = executor.getByRole("region", {
    name: "Current definition proposal",
    exact: true,
  });
  await executorCurrent.waitFor();
  await button(executorCurrent, "Review adoption into a draft").click();
  await executor.getByRole("dialog").waitFor();
  await audit(executor, "executor-adoption-review");
  const adoptionURL = submissionURL + "/" + proposal + "/adopt",
    adoptionLoss = committedReplyLoss(adoptionURL, adoptions, "adoption");
  await executor.route(adoptionURL, adoptionLoss);
  await button(
    executor.getByRole("dialog"),
    "Confirm exact proposal command",
  ).click();
  await executor.getByRole("dialog").getByRole("alert").waitFor();
  const adoptionRecovery = c.private + "/adoption-recovery.json";
  await save(executor, adoptionRecovery);
  await reload(executor);
  await executor
    .getByLabel("Import proposal recovery JSON", { exact: true })
    .setInputFiles(adoptionRecovery);
  await executor.getByRole("dialog").waitFor();
  await button(
    executor.getByRole("dialog"),
    "Confirm exact proposal command",
  ).click();
  await executor.getByRole("dialog").waitFor({ state: "hidden" });
  await executor.unroute(adoptionURL, adoptionLoss);
  assert.equal(adoptions.length, 2);
  assert.equal(adoptions[0].key, adoptions[1].key);
  assert.deepEqual(adoptions[0].body, adoptions[1].body);
  assert.equal(adoptions[0].reply.replayed, false);
  assert.equal(adoptions[1].reply.replayed, true);
  assert.deepEqual(adoptions[0].reply.resource, adoptions[1].reply.resource);
  const receipt = adoptions[1].reply.resource;
  assert.equal(receipt.adopted_workflow.state, "draft");
  assert.equal(receipt.adopted_workflow.revision, 1);
  assert.equal(receipt.adopted_workflow.approval_authority, 0);
  assert.equal(receipt.adopted_workflow.definition_hash, c.workflow_hash);
  workflow = receipt.adopted_workflow.id;
  await executorCurrent.waitFor();
  assert.match(await executorCurrent.innerText(), /adopted,revision 2/);
  await audit(executor, "recovered-executor-draft");
  await button(executorCurrent, "Open adopted task").click();
  const task = executor.getByRole("region", {
    name: "Processing task revision",
    exact: true,
  });
  await task.waitFor();
  assert.match(await task.innerText(), /draft/);
  await audit(executor, "ordinary-owned-draft");
  await author
    .getByLabel("Definition proposal ID", { exact: true })
    .fill(proposal);
  await button(author, "Inspect definition proposal").click();
  await authorCurrent.waitFor();
  assert.match(await authorCurrent.innerText(), /adopted,revision 2/);
  assert.equal(
    await button(authorCurrent, "Review proposal withdrawal").isDisabled(),
    true,
  );
  state = "passed";
} catch (e) {
  failure = sha(String(e?.stack || e));
  await writeFile(c.private + "/failure.txt", String(e?.stack || e));
  process.exitCode = 1;
} finally {
  await browser?.close();
  await writeFile(
    c.result,
    JSON.stringify({
      state,
      proposal,
      workflow,
      workflow_hash: c.workflow_hash,
      proposal_requests: submissions.length,
      adoption_requests: adoptions.length,
      accessibility_checks: accessibility,
      external_egress: egress,
      runtime_errors: errors,
      browser_sandbox: true,
      inference_performed: false,
      failure_sha256: failure,
    }) + "\n",
  );
}
