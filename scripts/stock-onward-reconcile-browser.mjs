import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  fetchPinnedBrowserRequest,
  guardBrowserCommandRoute,
} from "./browser-pinned-https.mjs";

process.umask(0o077);
const fixture = JSON.parse(await readFile(process.argv[2], "utf8"));
const origin = new URL(fixture.origin);
assert.equal(origin.origin, fixture.origin);
assert.equal(origin.protocol, "https:");
assert.equal(origin.hostname, "127.0.0.1");
assert.equal(
  fixture.prefix,
  `${origin.origin}/v1/tenants/${fixture.tenant}/partners/${fixture.partner}`,
);
const certificate = Buffer.from(fixture.certificate_der, "base64");
const pin = createHash("sha256")
  .update(
    new X509Certificate(certificate).publicKey.export({
      type: "spki",
      format: "der",
    }),
  )
  .digest("base64");
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const axe = require("../web/node_modules/axe-core");
const summary = {
  phase: "launch",
  browser_sandbox: false,
  browser_version: "",
  reconcile_requests: 0,
  work_requests: 0,
  external_egress: 0,
  accessibility_checks: 0,
  runtime_errors: 0,
};
const reconciler = fixture.prefix + "/onward/reconcile";
let browser, routeFailure, recovered;
const button = (scope, name) =>
  scope.getByRole("button", { name, exact: true });
const label = (scope, name) => scope.getByLabel(name, { exact: true });
const heading = (scope, name) =>
  scope.getByRole("heading", { name, exact: true });

async function checkAccessibility(page) {
  await page.evaluate(axe.source);
  const violations = await page.evaluate(async () => {
    const result = await window.axe.run(document.querySelector("main"), {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return result.violations.map((rule) => rule.id);
  });
  assert.deepEqual(violations, []);
  summary.accessibility_checks++;
}

async function restore(page, file) {
  await button(page, "Onward delivery").click();
  await label(page, "Import saved onward review").setInputFiles(file);
  await button(page, "Find original onward receipt only").click();
  await heading(page, "Recorded onward run").waitFor();
  const verify = button(page, "Verify saved onward review with server");
  await verify.click();
  await verify.waitFor({ state: "hidden" });
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
    await browser?.close();
    process.exitCode = 130;
  });
  summary.browser_sandbox = true;
  summary.browser_version = browser.version();
  const context = await browser.newContext({
    serviceWorkers: "block",
    viewport: { width: 1160, height: 820 },
  });
  await context.route(
    "**/*",
    guardBrowserCommandRoute(
      async (route) => {
        const request = route.request();
        if (new URL(request.url()).origin !== origin.origin) {
          summary.external_egress++;
          return route.abort();
        }
        if (request.url() === fixture.prefix + "/onward/work")
          summary.work_requests++;
        if (request.url() !== reconciler) return route.continue();
        assert.equal(request.method(), "POST");
        assert.deepEqual(request.postDataJSON(), fixture.request);
        const key = (await request.allHeaders())["idempotency-key"];
        summary.reconcile_requests++;
        if (summary.reconcile_requests === 2) {
          assert.equal(key, summary.request_key);
          const replay = await fetchPinnedBrowserRequest(
            request,
            origin.origin,
            certificate,
          );
          assert.equal(replay.status, 200);
          recovered = JSON.parse(replay.body);
          return route.fulfill({
            status: replay.status,
            contentType: "application/json",
            body: replay.body,
          });
        }
        assert.equal(summary.reconcile_requests, 1);
        assert.match(key, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
        summary.request_key = key;
        const response = await fetchPinnedBrowserRequest(
          request,
          origin.origin,
          certificate,
        );
        assert.equal(response.status, 200);
        summary.original = JSON.parse(response.body);
        assert.equal(summary.original.observation, "integrity-observed");
        assert.equal(summary.original.delivery_state, "succeeded");
        assert.equal(summary.original.replayed, false);
        assert.equal(summary.original.run_id, fixture.request.run_id);
        assert.equal(summary.original.delivery_id, fixture.request.delivery_id);
        await route.abort("failed");
      },
      (error) => {
        routeFailure ??= error;
      },
    ),
  );

  summary.phase = "authenticated-review";
  const page = await context.newPage();
  page.setDefaultTimeout(6500);
  page.on("pageerror", () => summary.runtime_errors++);
  await page.goto(origin.origin);
  await label(page, "Tenant ID").fill(fixture.tenant);
  await label(page, "Partner ID").fill(fixture.partner);
  await label(page, "Account credential file").setInputFiles(fixture.token);
  await button(page, "Connect").click();
  await heading(page, "Files").waitFor();
  await restore(page, fixture.review_file);
  await button(page, "Inspect current onward state").click();
  await heading(page, "Current onward observation").waitFor();
  await checkAccessibility(page);
  assert.equal(summary.reconcile_requests, 0);

  summary.phase = "drop-committed-check";
  await button(page, "Check receiver file for step 1").press("Enter");
  await page.getByRole("alert").waitFor();
  if (routeFailure) throw routeFailure;
  assert.equal(summary.reconcile_requests, 1);
  const [saved] = await Promise.all([
    page.waitForEvent("download"),
    button(page, "Save onward recovery").click(),
  ]);
  assert.equal(await saved.failure(), null);
  await saved.saveAs(fixture.saved_file);
  await chmod(fixture.saved_file, 0o600);
  const exported = JSON.parse(await readFile(fixture.saved_file, "utf8"));
  assert.deepEqual(exported.reconciliation, {
    delivery_id: fixture.request.delivery_id,
    request_key: summary.request_key,
  });

  summary.phase = "recover-after-reload";
  await page.reload();
  await restore(page, fixture.saved_file);
  assert.equal(summary.reconcile_requests, 1);
  await button(page, "Retry the same receiver check").click();
  await heading(page, "Recorded receiver check").waitFor();
  if (routeFailure) throw routeFailure;
  assert.deepEqual(recovered, { ...summary.original, replayed: true });
  await page
    .getByText("The receiver file matched the approved bytes.", { exact: true })
    .waitFor();
  await page.getByRole("alert").waitFor({ state: "hidden" });
  await checkAccessibility(page);
  assert.equal(summary.reconcile_requests, 2);
  assert.equal(summary.work_requests, 0);
  assert.equal(summary.external_egress, 0);
  assert.equal(summary.runtime_errors, 0);
  summary.phase = "complete";
} catch (error) {
  console.error(routeFailure ?? error);
  process.exitCode = 1;
} finally {
  await browser?.close();
  await writeFile(fixture.result, JSON.stringify(summary) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
}
