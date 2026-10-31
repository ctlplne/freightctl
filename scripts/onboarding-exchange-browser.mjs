// Native browser qualification against real local services, not mocked API data.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { qualifyRecordedTests } from "./onboarding-tests-browser.mjs";
import { qualifyProductionReleases } from "./onboarding-releases-browser.mjs";
import { qualifyReceiptObservations } from "./onboarding-observations-browser.mjs";
import { qualifyIndependentApprovals } from "./onboarding-approvals-browser.mjs";
import { qualifyQueuedHandoffs } from "./onboarding-handoffs-browser.mjs";
process.umask(0o077);
const require = createRequire(import.meta.url),
  { chromium } = require("../web/node_modules/playwright");
const c = JSON.parse(await readFile(process.argv[2], "utf8"));
const spki = createHash("sha256")
  .update(
    new X509Certificate(await readFile(c.certificate)).publicKey.export({
      format: "der",
      type: "spki",
    }),
  )
  .digest("base64");
const browser = await chromium.launch({
  headless: true,
  chromiumSandbox: true,
  args: [
    "--ignore-certificate-errors-spki-list=" + spki,
    "--disable-background-networking",
    "--disable-component-update",
  ],
});
const context = await browser.newContext({
    viewport: { width: 1320, height: 950 },
  }),
  page = await context.newPage();
page.setDefaultTimeout(15000);
const steps = [],
  errors = [],
  egress = [];
let state = "failed",
  failure;
const record = (name) => {
  steps.push({ name });
  console.log("passed: " + name);
};
page.on("pageerror", (e) => errors.push(e.message));
page.on("request", (r) => {
  if (!r.url().startsWith(c.url + "/")) egress.push(new URL(r.url()).origin);
});
const endpoint =
  c.url +
  `/v1/tenants/${c.tenant}/partners/${c.partner}/onboarding-exchange-review`;
async function audit(name) {
  await page.evaluate(
    await readFile(
      path.join(c.root, "web/node_modules/axe-core/axe.min.js"),
      "utf8",
    ),
  );
  const results = await page.evaluate(async () => {
    const r = await window.axe.run(document, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return {
      violations: r.violations.map((v) => ({
        id: v.id,
        impact: v.impact,
        nodes: v.nodes.map((n) => ({
          target: n.target,
          failureSummary: n.failureSummary,
        })),
      })),
      passes: r.passes.length,
    };
  });
  await writeFile(
    c.raw + "/" + name + "-axe.json",
    JSON.stringify(results, null, 2) + "\n",
  );
  assert.equal(
    results.violations.length,
    0,
    "accessibility violations in " + name,
  );
  record(name + "-axe");
}
async function openPlan() {
  await page.getByRole("button", { name: "Onboarding", exact: true }).click();
  await page
    .getByRole("button", {
      name: "Open " + c.plan.definition.name,
      exact: true,
    })
    .click();
  await page
    .getByRole("heading", {
      name: "Review file exchange evidence",
      exact: true,
    })
    .waitFor();
}
async function select(request) {
  await page
    .getByLabel("Saved outbound SFTP requirement", { exact: true })
    .selectOption(request.requirement_id);
  await page
    .getByLabel("Connectivity probe UUID", { exact: true })
    .fill(request.probe_id);
  await page
    .getByLabel("Completed workflow run UUID", { exact: true })
    .fill(request.run_id);
  await page
    .getByLabel("Exact workflow step ID", { exact: true })
    .fill(request.step_id);
}
async function inspect(request, hash, ready = true) {
  await select(request);
  await page
    .getByRole("button", { name: "Compare recorded exchange", exact: true })
    .click();
  const heading = page.getByRole("heading", {
    name: ready
      ? "Recorded exchange evidence matches"
      : "Onboarding evidence incomplete",
    exact: true,
  });
  await heading.waitFor();
  assert.equal(
    await heading.evaluate((el) => document.activeElement === el),
    true,
    "completed evidence heading must receive focus",
  );
  if (hash) await page.getByText(hash, { exact: true }).waitFor();
}
async function actualReview(route, label, target = endpoint) {
  const request = route.request();
  assert.equal(request.url(), target);
  assert.equal(request.method(), "POST");
  const headers = c.private + "/" + label + ".headers",
    body = c.private + "/" + label + ".request",
    output = c.raw + "/" + label + ".json";
  const fields = Object.entries(await request.allHeaders()).filter(
    ([k]) =>
      !["host", "connection", "content-length", "transfer-encoding"].includes(
        k,
      ),
  );
  await writeFile(
    headers,
    fields.map(([k, v]) => k + ": " + v).join("\n") + "\n",
  );
  const bytes = request.postDataBuffer() ?? Buffer.alloc(0);
  assert.ok(bytes && bytes.length <= 32768);
  await writeFile(body, bytes);
  const status = Number(
    execFileSync(
      "curl",
      [
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--cacert",
        c.certificate,
        "--max-time",
        "12",
        "--max-filesize",
        "262144",
        "--header",
        "@" + headers,
        "--request",
        "POST",
        "--data-binary",
        "@" + body,
        "--output",
        output,
        "--write-out",
        "%{http_code}",
        target,
      ],
      { encoding: "utf8", timeout: 15000, maxBuffer: 4096 },
    ),
  );
  const response = await readFile(output);
  assert.ok(response.length <= 262144);
  assert.equal(status, 200);
  return {
    status,
    body: response.toString("utf8"),
    selection: bytes.length ? JSON.parse(bytes) : null,
    idempotency_key: fields.find(([k]) => k === "idempotency-key")?.[1],
  };
}
try {
  await page.goto(c.url);
  await page
    .getByRole("heading", { name: "Connect to your workspace" })
    .waitFor();
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  if (!(c.approval_only && c.approval_phase === "review")) await openPlan();
  if (c.approval_only) {
    await qualifyIndependentApprovals(page, c, audit, record, actualReview);
  } else if (c.observation_only) {
    await qualifyReceiptObservations(
      page,
      c,
      audit,
      record,
      actualReview,
      openPlan,
    );
  } else if (c.handoff_only) {
    await qualifyQueuedHandoffs(page, c, audit, record, actualReview, openPlan);
  } else if (c.release_only) {
    await qualifyProductionReleases(
      page,
      c,
      audit,
      record,
      actualReview,
      openPlan,
    );
  } else if (c.test_only) {
    await qualifyRecordedTests(page, c, audit, record, actualReview, openPlan);
  } else {
    await inspect(c.plain, c.plain_hash);
    record("native-plain-exchange-and-exact-server-snapshot");
    await audit("plain-review");
    await inspect(c.encrypted, c.encrypted_hash);
    record("native-encrypted-exchange-and-exact-server-snapshot");
    await audit("encrypted-review");
    await inspect(c.business, null, false);
    await page.getByText(/downstream business acceptance is unknown/).waitFor();
    record("native-business-requirement-remains-incomplete");
    await audit("business-review");
    await select(c.plain);
    const observed = [];
    await page.route(endpoint, async (route) => {
      const actual = await actualReview(
        route,
        "browser-review-response-" + observed.length,
      );
      observed.push(actual);
      if (observed.length === 1) await route.abort("failed");
      else
        await route.fulfill({
          status: actual.status,
          contentType: "application/json",
          body: actual.body,
        });
    });
    await page
      .getByRole("button", { name: "Compare recorded exchange", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Compare recorded exchange", exact: true })
      .waitFor({ state: "visible" });
    await page.waitForFunction(
      () =>
        !document.querySelector('button[type="submit"]:disabled') ||
        [...document.querySelectorAll("button")].some(
          (b) => b.textContent === "Compare recorded exchange" && !b.disabled,
        ),
    );
    assert.equal(observed.length, 1);
    assert.equal(JSON.parse(observed[0].body).snapshot_hash, c.plain_hash);
    await inspect(c.plain, c.plain_hash);
    assert.equal(observed.length, 2);
    assert.deepEqual(observed[0].selection, observed[1].selection);
    assert.equal(JSON.parse(observed[1].body).snapshot_hash, c.plain_hash);
    await page.unroute(endpoint);
    record("lost-read-response-recovered-with-same-selected-evidence");
    await page.reload();
    await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
    await openPlan();
    await inspect(c.plain, c.plain_hash);
    record("reload-reads-same-durable-evidence-without-activation");
  }
  assert.deepEqual(errors, []);
  assert.deepEqual(egress, []);
  await page.screenshot({
    path: c.raw + "/onboarding-exchange-review.png",
    fullPage: true,
  });
  state = "passed";
} catch (e) {
  failure = String(e.stack ?? e);
  await page
    .screenshot({
      path: c.raw + "/onboarding-exchange-failure.png",
      fullPage: true,
    })
    .catch(() => {});
  await writeFile(
    c.raw + "/onboarding-exchange-visible.txt",
    await page
      .locator("body")
      .innerText()
      .catch(() => "unavailable"),
  );
} finally {
  await writeFile(
    c.raw + "/onboarding-exchange-browser.json",
    JSON.stringify(
      {
        state,
        failure,
        steps,
        runtime_errors: errors,
        external_egress: egress,
        model_started: false,
        production_activated: false,
      },
      null,
      2,
    ) + "\n",
  );
  await context.close();
  await browser.close();
}
if (state !== "passed") throw new Error(failure);
