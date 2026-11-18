import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  fetchPinnedBrowserRequest,
  guardBrowserCommandRoute,
} from "./browser-pinned-https.mjs";

process.umask(0o077);
const require = createRequire(import.meta.url);
const { chromium } = require("../web/node_modules/playwright");
const axe = require("../web/node_modules/axe-core");
const fixture = JSON.parse(await readFile(process.argv[2], "utf8"));
const prefix = new URL(fixture.prefix);
const origin = prefix.origin;
assert.equal(prefix.protocol, "https:");
assert.equal(prefix.hostname, "127.0.0.1");
assert.equal(
  prefix.pathname,
  `/v1/tenants/${fixture.tenant}/partners/${fixture.partner}`,
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
const summary = {
  state: "failed",
  phase: "launch",
  browser_version: "",
  browser_sandbox: false,
  external_egress: 0,
  runtime_errors: 0,
  accessibility_checks: 0,
  work_requests: 0,
};
let browser, routeError;
const button = (scope, name) =>
  scope.getByRole("button", { name, exact: true });
const heading = (scope, name) =>
  scope.getByRole("heading", { name, exact: true });
const region = (scope, name) =>
  scope.getByRole("region", { name, exact: true });
const label = (scope, name) => scope.getByLabel(name, { exact: true });

async function login(tokenFile) {
  const context = await browser.newContext({
    serviceWorkers: "block",
    viewport: { width: 1160, height: 820 },
  });
  await context.route("**/*", async (route) => {
    if (new URL(route.request().url()).origin !== origin) {
      summary.external_egress++;
      return route.abort();
    }
    return route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(6500);
  page.on("pageerror", () => summary.runtime_errors++);
  await page.goto(origin);
  await label(page, "Tenant ID").fill(fixture.tenant);
  await label(page, "Partner ID").fill(fixture.partner);
  await label(page, "Account credential file").setInputFiles(tokenFile);
  await button(page, "Connect").click();
  await heading(page, "Files").waitFor();
  const cookies = await context.cookies(origin);
  assert.equal(cookies.length, 1);
  assert.equal(cookies[0].name, "__Host-freightctl-session");
  assert.ok(cookies[0].secure && cookies[0].httpOnly);
  assert.equal(cookies[0].sameSite, "Strict");
  return { context, page };
}

async function reply(page, path, method, status, action) {
  const [response] = await Promise.all([
    page.waitForResponse((r) => {
      const url = new URL(r.url());
      return (
        url.origin === origin &&
        url.pathname === prefix.pathname + path &&
        r.request().method() === method
      );
    }),
    action(),
  ]);
  assert.equal(response.status(), status, path);
  return response.json();
}

async function accessibility(page, scope) {
  await page.evaluate(axe.source);
  const failures = await scope.evaluate(async (element) => {
    const report = await window.axe.run(element, {
      runOnly: {
        type: "tag",
        values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
      },
    });
    return report.violations.map((violation) => violation.id);
  });
  assert.deepEqual(failures, []);
  summary.accessibility_checks++;
}

async function receiverSessions() {
  return (
    (await readFile(fixture.receiver_log, "utf8")).split(
      "Accepted publickey for ",
    ).length - 1
  );
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
  summary.browser_version = browser.version();
  summary.browser_sandbox = true;
  process.once("SIGINT", async () => {
    await browser?.close();
    process.exitCode = 130;
  });

  summary.phase = "collection-review";
  const sender = await login(fixture.sender);
  const from = sender.page;
  let offerPosts = 0;
  from.on("request", (request) => {
    if (
      request.url() === fixture.prefix + "/exchanges" &&
      request.method() === "POST"
    )
      offerPosts++;
  });
  await button(from, "Collections").click();
  await button(from, "Inspect collection " + fixture.collection).click();
  const review = await reply(
    from,
    `/workflow-collections/${fixture.collection}/inputs/${fixture.input}/exchange-source`,
    "GET",
    200,
    () =>
      button(from, "Review collected artifact " + fixture.source_name).press(
        "Enter",
      ),
  );
  assert.equal(review.profile, "governed-collection-exchange-source-v1");
  assert.equal(review.origin.collection_id, fixture.collection);
  assert.equal(review.origin.input_id, fixture.input);
  assert.equal(review.origin.manifest_sha256, fixture.manifest);
  assert.equal(review.artifact.file_revision_id, fixture.source_file);
  assert.equal(review.artifact.size_bytes, fixture.source_size);
  assert.equal(review.artifact.sha256, fixture.source_sha256);
  assert.equal(
    await label(from, "Source file revision ID").inputValue(),
    fixture.source_file,
  );
  assert.equal(offerPosts, 0);

  summary.phase = "exact-offer";
  await button(from, "Find approved recipients").click();
  await button(from, "Use endpoint " + fixture.endpoint.slice(0, 8)).click();
  await button(from, "Review artifact offer").click();
  await heading(from, "Review exact artifact offer").waitFor();
  await accessibility(from, from.locator("main"));
  assert.equal(offerPosts, 0);
  const sent = await reply(from, "/exchanges", "POST", 201, () =>
    button(from, "Confirm artifact offer or recover result").click(),
  );
  assert.equal(offerPosts, 1);
  assert.equal(sent.replayed, false);
  assert.equal(sent.exchange.sender_actor_id, fixture.sender_actor);
  assert.equal(sent.exchange.recipient_actor_id, fixture.recipient_actor);
  assert.deepEqual(sent.exchange.request.artifact, review.artifact);
  assert.equal(sent.exchange.request.endpoint.id, fixture.endpoint);
  assert.equal(sent.exchange.request.receipt, "availability-only-v1");
  const exchange = sent.exchange.id;
  summary.offer = exchange;
  await sender.context.close();

  summary.phase = "exact-download";
  const recipient = await login(fixture.recipient);
  const to = recipient.page;
  await button(to, "Receive artifacts").click();
  await button(to, "Find my receive endpoints").click();
  await button(to, "Open " + fixture.endpoint.slice(0, 8)).click();
  await button(to, "Inspect " + exchange.slice(0, 8)).click();
  await region(to, "Copy received artifact").waitFor();
  await accessibility(to, to.locator("main"));
  const [download] = await Promise.all([
    to.waitForEvent("download"),
    to
      .getByRole("row")
      .filter({ hasText: exchange })
      .getByRole("link", { name: "Download artifact", exact: true })
      .click(),
  ]);
  assert.equal(download.suggestedFilename(), "artifact");
  assert.equal(await download.failure(), null);
  await download.saveAs(fixture.download);
  await chmod(fixture.download, 0o600);
  const actual = await readFile(fixture.download);
  assert.equal(actual.length, fixture.source_size);
  assert.equal(
    createHash("sha256").update(actual).digest("hex"),
    fixture.source_sha256,
  );

  summary.phase = "owned-copy";
  const copy = region(to, "Copy received artifact");
  await label(copy, "New owned copy path").fill("/agent-owned.csv");
  await button(copy, "Review new owned copy").click();
  await heading(copy, "Review received copy").waitFor();
  await accessibility(to, copy);
  const copied = await reply(to, "/exchange-copies", "POST", 201, () =>
    button(copy, "Submit or recover original copy").click(),
  );
  assert.equal(copied.replayed, false);
  assert.equal(copied.source.exchange_id, exchange);
  assert.equal(copied.source.request_hash, sent.exchange.request_hash);
  assert.deepEqual(copied.source.artifact, review.artifact);
  assert.notEqual(copied.artifact.file_revision_id, fixture.source_file);
  assert.equal(copied.artifact.sha256, fixture.source_sha256);
  assert.equal(copied.artifact.size_bytes, fixture.source_size);
  summary.copy = copied.artifact.file_revision_id;

  summary.phase = "onward-authority";
  await button(to, "Onward delivery").click();
  const onward = region(to, "Onward artifact delivery");
  await label(onward, "Onward source file revision ID").fill(
    fixture.source_file,
  );
  await label(onward, "Approved onward workflow ID").fill(fixture.workflow.id);
  await label(onward, "Approved onward workflow version").fill(
    String(fixture.workflow.version),
  );
  await label(onward, "Approved onward workflow SHA256").fill(
    fixture.workflow.hash,
  );
  await reply(to, "/exchange-sources/" + fixture.source_file, "GET", 404, () =>
    button(onward, "Review onward delivery").click(),
  );
  await to.getByRole("alert").waitFor();
  assert.equal(
    await heading(onward, "Review exact onward delivery").count(),
    0,
  );
  assert.equal(await receiverSessions(), 0);
  await label(onward, "Onward source file revision ID").fill(summary.copy);
  const approved = await reply(to, "/onward/previews", "POST", 200, () =>
    button(onward, "Review onward delivery").click(),
  );
  await heading(onward, "Review exact onward delivery").waitFor();
  await to.getByRole("alert").waitFor({ state: "hidden" });
  assert.deepEqual(approved.request.artifact, copied.artifact);
  assert.deepEqual(approved.request.workflow, fixture.workflow);
  assert.equal(approved.external_contact, false);
  assert.equal(approved.effects.length, 1);
  assert.deepEqual(approved.effects[0].connection, fixture.connection);
  await accessibility(to, region(to, "Exact onward review"));

  summary.phase = "queue-without-contact";
  const queued = await reply(to, "/onward/runs", "POST", 200, () =>
    button(onward, "Confirm queue or recover original run").click(),
  );
  assert.equal(queued.replayed, false);
  assert.equal(queued.resource.onward_review_hash, approved.review_hash);
  assert.equal(queued.resource.state, "queued");
  await heading(onward, "Recorded onward run").waitFor();
  summary.run = queued.resource.id;
  const before = await reply(to, "/onward/status", "POST", 200, () =>
    button(onward, "Inspect current onward state").click(),
  );
  assert.equal(before.observed_state, "queued");
  assert.equal(await receiverSessions(), 0);

  summary.phase = "work-lost-response";
  const workURL = fixture.prefix + "/onward/work";
  let first, original, recovered;
  await to.route(
    workURL,
    guardBrowserCommandRoute(
      async (route) => {
        const request = route.request();
        const headers = await request.allHeaders();
        const command = {
          key: headers["idempotency-key"],
          body: request.postDataJSON(),
        };
        assert.equal(request.method(), "POST");
        summary.work_requests++;
        if (summary.work_requests === 2) {
          assert.deepEqual(command, original);
          const replay = await fetchPinnedBrowserRequest(
            request,
            origin,
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
        assert.equal(summary.work_requests, 1);
        assert.ok(command.key);
        assert.equal(command.body.run_id, summary.run);
        assert.equal(command.body.start.review_hash, approved.review_hash);
        original = command;
        const accepted = await fetchPinnedBrowserRequest(
          request,
          origin,
          certificate,
        );
        assert.equal(accepted.status, 200);
        first = JSON.parse(accepted.body);
        assert.equal(first.replayed, false);
        assert.equal(first.observed_state, "succeeded");
        assert.equal(await receiverSessions(), 1);
        await route.abort("failed");
      },
      (error) => {
        routeError ??= error;
      },
    ),
  );
  await button(onward, "Perform one onward work step").click();
  await to.getByRole("alert").waitFor();
  if (routeError) throw routeError;
  assert.ok(first);

  summary.phase = "same-work-receipt";
  await button(onward, "Retry the same onward work step").click();
  const observation = region(to, "Current onward observation");
  await observation.getByText(/Observed state: succeeded/).waitFor();
  if (routeError) throw routeError;
  assert.deepEqual(recovered, { ...first, replayed: true });
  assert.equal(recovered.run_id, summary.run);
  assert.deepEqual(recovered.artifact, copied.artifact);
  assert.equal(recovered.receiver_persistence, "unknown");
  assert.equal(recovered.business_processing, "unknown");
  assert.equal(await receiverSessions(), 1);
  await to.getByRole("alert").waitFor({ state: "hidden" });
  await accessibility(to, observation);
  summary.delivery = recovered.selected_delivery_id;
  await recipient.context.close();
  assert.equal(summary.external_egress, 0);
  assert.equal(summary.runtime_errors, 0);
  summary.phase = "complete";
  summary.state = "passed";
} catch (error) {
  console.error(routeError ?? error);
  process.exitCode = 1;
} finally {
  await browser?.close();
  await writeFile(fixture.result, JSON.stringify(summary) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
}
