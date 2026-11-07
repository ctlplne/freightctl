import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  fetchPinnedBrowserRequest,
  guardBrowserCommandRoute,
} from "./browser-pinned-https.mjs";

process.umask(0o077);
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.env.FREIGHTCTL_BROWSER_CHANNEL, "chrome");
const c = JSON.parse(await readFile(process.argv[2], "utf8")),
  origin = new URL(c.url),
  certificate = new X509Certificate(Buffer.from(c.certificate_der, "base64")),
  require = createRequire(import.meta.url),
  { chromium } = require("../web/node_modules/playwright"),
  axe = require("../web/node_modules/axe-core/package.json").version,
  prefix = `/v1/tenants/${c.tenant}/partners/${c.partner}`,
  commands = Object.fromEntries(
    ["draft", "tick", "probe", "admit", "work"].map((k) => [k, []]),
  );
assert.equal(origin.protocol, "https:");
assert.equal(origin.hostname, "127.0.0.1");
assert.equal(origin.origin, c.url);
let browser,
  state = "failed",
  phase = "launch",
  schedule = "",
  occurrence = "",
  job = "",
  egress = 0,
  errors = 0,
  navigationStatus = 0,
  assetStatus = 0,
  documentHTML = false,
  firstRuntimeError,
  accessibility = 0,
  routeFailed = false,
  routeFailure,
  routePhase;
const guard = (handler) =>
  guardBrowserCommandRoute(handler, (error) => {
    if (!routeFailed) {
      routeFailed = true;
      routeFailure = error;
      routePhase = phase;
    }
  });
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
  process.once("SIGINT", async () => {
    await browser.close();
    process.exit(1);
  });
  const context = await browser.newContext({
      viewport: { width: 1420, height: 1100 },
    }),
    page = await context.newPage(),
    button = (name, parent = page) =>
      parent.getByRole("button", { name, exact: true }),
    dialog = () => page.getByRole("dialog");
  page.setDefaultTimeout(15000);
  page.on("pageerror", (error) => {
    errors++;
    firstRuntimeError ??= error;
  });
  page.on("response", (response) => {
    if (response.url() === origin.origin + "/assets/app.js")
      assetStatus = response.status();
  });
  await context.route("**/*", async (route) => {
    if (new URL(route.request().url()).origin !== origin.origin) {
      egress++;
      await route.abort("blockedbyclient");
    } else await route.continue();
  });
  async function audit(label) {
    await page.evaluate(
      await readFile(
        new URL("../web/node_modules/axe-core/axe.min.js", import.meta.url),
        "utf8",
      ),
    );
    const result = await page.evaluate(async () => {
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
      JSON.stringify(result),
      {
        flag: "wx",
        mode: 0o600,
      },
    );
    assert.equal(result.violations.length, 0);
    assert.ok(result.passes > 0);
    accessibility++;
  }
  async function response(path, action) {
    const pending = page.waitForResponse(
      (r) => r.url() === origin.origin + prefix + path,
    );
    await action();
    const r = await pending;
    assert.equal(r.status(), 200);
    return r.json();
  }
  async function loseFirst(path, name, refusal) {
    const url = origin.origin + prefix + path,
      rows = commands[name],
      handler = guard(async (route) => {
        const request = route.request(),
          headers = await request.allHeaders(),
          body = request.postDataBuffer();
        const real = await fetchPinnedBrowserRequest(
          request,
          origin.origin,
          certificate.raw,
        );
        assert.equal(real.status, 200);
        rows.push({
          key: headers["idempotency-key"],
          body: JSON.parse(body),
          reply: JSON.parse(real.body),
        });
        if (rows.length === 1) await route.abort("failed");
        else
          await route.fulfill({
            status: real.status,
            contentType: "application/json",
            body: real.body,
          });
      });
    await page.route(url, handler);
    try {
      await button("Confirm exact decision", dialog()).click();
      await dialog().getByRole("alert").filter({ hasText: refusal }).waitFor();
      await button("Confirm exact decision", dialog()).click();
      await dialog().waitFor({ state: "hidden" });
      if (routeFailed) throw routeFailure;
      assert.equal(rows.length, 2);
      assert.ok(rows[0].key);
      assert.equal(rows[0].key, rows[1].key);
      assert.deepEqual(rows[0].body, rows[1].body);
      assert.equal(rows[0].reply.replayed, false);
      assert.equal(rows[1].reply.replayed, true);
      assert.deepEqual(rows[0].reply.resource, rows[1].reply.resource);
      return rows[1].reply.resource;
    } finally {
      await page.unroute(url, handler);
    }
  }
  phase = "login";
  const navigation = await page.goto(c.url);
  navigationStatus = navigation?.status() ?? 0;
  documentHTML = /^text\/html(?:;|$)/i.test(
    navigation?.headers()["content-type"] ?? "",
  );
  assert.equal(navigationStatus, 200);
  assert.equal(documentHTML, true);
  await page.getByLabel("Tenant ID", { exact: true }).fill(c.tenant);
  await page.getByLabel("Partner ID", { exact: true }).fill(c.partner);
  await page
    .getByLabel("Account credential file", { exact: true })
    .setInputFiles(c.token);
  await button("Connect").click();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await button("Schedules").click();
  const region = page.getByRole("region", {
      name: "Workflow schedules",
      exact: true,
    }),
    x = c.selection;
  phase = "editor";
  await region
    .getByLabel("Approved workflow", { exact: true })
    .selectOption(x.workflow.id + ":" + x.workflow.version);
  for (const [label, value] of [
    ["Approved collection target folder", x.source.directory],
    ["Filename pattern", x.source.filename_pattern],
    ["Maximum files per occurrence", String(x.max_files_per_occurrence)],
  ]) {
    const field = region.getByLabel(label, { exact: true });
    assert.equal(await field.inputValue(), value);
    assert.equal(await field.getAttribute("readonly"), "");
  }
  await region
    .getByRole("group", { name: "Expected local arrival", exact: true })
    .waitFor();
  for (const [label, value] of Object.entries({
    "Schedule name": x.name,
    "Time zone": x.calendar.time_zone,
    "Start of calendar (UTC)": x.calendar.starts_at,
    "End of calendar (UTC)": x.calendar.ends_at,
    "Local clock times (HH:MM:SS)": x.calendar.local_times.join(", "),
    "Holiday dates (YYYY-MM-DD)": x.calendar.holidays.join("\n"),
    "Start grace for skip rule (seconds)": String(x.late_start_grace_seconds),
    "Execution cutoff after due time (seconds)": String(
      x.execution_deadline_seconds,
    ),
    "Catch-up decisions per request": String(x.max_catch_up),
    "Maximum current active runs": String(x.max_active_runs),
    "Late after due time (seconds)": String(x.arrival.late_after_seconds),
    "Arrival cutoff after due time (seconds)": String(
      x.arrival.arrival_deadline_seconds,
    ),
    "Minimum time between source probes (seconds)": String(
      x.arrival.poll_interval_seconds,
    ),
  }))
    await region.getByLabel(label, { exact: true }).fill(value);
  for (const day of [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
  ])
    await region.getByLabel(day, { exact: true }).setChecked(true);
  await region
    .getByLabel("Repeated local time", { exact: true })
    .selectOption(x.calendar.fold_policy);
  await region
    .getByLabel("Missed-run rule", { exact: true })
    .selectOption(x.missed_run_policy);
  await audit("local-calendar-editor");
  phase = "preview";
  const preview = await response("/workflow-schedules/preview", () =>
    button("Preview schedule", region).click(),
  );
  assert.equal(preview.definition.source.kind, "local.collect");
  assert.equal(preview.definition.workflow.hash, x.workflow.hash);
  assert.equal(
    preview.definition.collection.source_connection.local.root_fingerprint,
    c.root_fingerprint,
  );
  assert.equal(
    preview.definition.collection.source_connection.local.configuration_sha256,
    c.configuration_sha256,
  );
  assert.equal(
    preview.definition.collection.source_connection.local.read_only,
    true,
  );
  assert.deepEqual(preview.effects, []);
  assert.equal(preview.external_contact, false);
  assert.equal(preview.approval_required, true);
  const previewRegion = page.getByRole("region", {
    name: "Schedule preview",
    exact: true,
  });
  await previewRegion.getByText(c.root_fingerprint, { exact: true }).waitFor();
  const text = await previewRegion.innerText();
  assert.equal(text.includes(c.directory), false);
  assert.equal(text.includes(c.configuration), false);
  await audit("local-calendar-preview");
  await button("Review saving schedule draft", region).click();
  await dialog().waitFor();
  await audit("local-calendar-draft-review");
  phase = "draft-replay";
  const draft = await loseFirst(
    "/workflow-schedules/drafts",
    "draft",
    /^Schedule decision not confirmed/,
  );
  schedule = draft.schedule.id;
  assert.equal(draft.schedule.definition_hash, preview.definition_hash);
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await button("Schedules").click();
  await button("Reload schedules", region).click();
  await button(`Inspect schedule ${x.name} version 1`, region).click();
  await region
    .getByRole("heading", { name: "Schedule: draft", exact: true })
    .waitFor();
  phase = "activate";
  await button("Review schedule activate", region).click();
  await dialog().getByText(c.root_fingerprint, { exact: true }).waitFor();
  await audit("local-calendar-activation");
  await button("Confirm exact decision", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await region
    .getByRole("heading", { name: "Schedule: active", exact: true })
    .waitFor();
  while (Date.now() < Date.parse(x.calendar.starts_at) + 100)
    await new Promise((resolve) =>
      setTimeout(
        resolve,
        Math.min(1000, Date.parse(x.calendar.starts_at) + 100 - Date.now()),
      ),
    );
  phase = "tick-replay";
  await button("Review queuing due work", region).click();
  const tick = await loseFirst(
    `/workflow-schedules/${schedule}/1/tick`,
    "tick",
    /^Schedule decision not confirmed/,
  );
  assert.equal(tick.external_contact, false);
  assert.deepEqual(tick.run_ids, []);
  assert.equal(tick.occurrences.length, 1);
  assert.equal(tick.occurrences[0].kind, "collection");
  occurrence = tick.occurrences[0].id;
  await button("Inspect occurrence " + occurrence.slice(0, 8), region).click();
  const arrival = page.getByRole("region", {
    name: "Expected scheduled arrival",
    exact: true,
  });
  await arrival.getByText(c.root_fingerprint, { exact: true }).waitFor();
  await arrival.getByText(c.configuration_sha256, { exact: true }).waitFor();
  assert.ok((await arrival.innerText()).includes(c.manifest_name));
  assert.equal((await arrival.innerText()).includes(c.directory), false);
  assert.equal((await arrival.innerText()).includes(c.configuration), false);
  await audit("local-calendar-waiting");
  phase = "probe-replay";
  await button("Review reading expected manifest", arrival).click();
  const ready = await loseFirst(
    `/workflow-schedule-arrivals/${occurrence}/probe`,
    "probe",
    /^Decision not confirmed/,
  );
  assert.equal(ready.state, "ready");
  await arrival
    .getByRole("heading", { name: "Expected arrival: ready", exact: true })
    .waitFor();
  await audit("local-calendar-ready");
  phase = "admit-replay";
  await button("Review collection admission", arrival).click();
  const admitted = await loseFirst(
    `/workflow-schedule-arrivals/${occurrence}/admit`,
    "admit",
    /^Decision not confirmed/,
  );
  assert.equal(admitted.state, "admitted");
  job = admitted.collection_id;
  const collection = page.getByRole("region", {
    name: "Selected collection",
    exact: true,
  });
  await collection
    .getByRole("heading", { name: "Collection: queued", exact: true })
    .waitFor();
  phase = "work-replay";
  await button("Review reading source batch", collection).click();
  const captured = await loseFirst(
    `/workflow-collections/${job}/work`,
    "work",
    /^The result was not confirmed/,
  );
  assert.equal(captured.state, "captured");
  await collection
    .getByRole("heading", { name: "Collection: captured", exact: true })
    .waitFor();
  await audit("local-calendar-captured");
  phase = "reload-captured";
  await page.reload();
  await page.getByRole("heading", { name: "Files", exact: true }).waitFor();
  await button("Schedules").click();
  await button(`Inspect schedule ${x.name} version 1`, region).click();
  await button("Inspect occurrence " + occurrence.slice(0, 8), region).click();
  await collection
    .getByRole("heading", { name: "Collection: captured", exact: true })
    .waitFor();
  assert.equal(egress, 0);
  assert.equal(errors, 0);
  if (routeFailed) throw routeFailure;
  state = "passed";
  phase = "complete";
  await context.close();
} catch (e) {
  if (routeFailed) phase = routePhase;
  const first = routeFailed ? routeFailure : e;
  await writeFile(c.failure, String(first?.stack ?? first), {
    flag: "wx",
    mode: 0o600,
  });
  process.exitCode = 1;
} finally {
  const version = browser?.version() ?? "";
  await browser?.close();
  if (firstRuntimeError)
    await writeFile(
      c.private + "/runtime-error.log",
      Buffer.from(
        String(firstRuntimeError.stack ?? firstRuntimeError),
      ).subarray(0, 65536),
      { flag: "wx", mode: 0o600 },
    );
  await writeFile(c.private + "/commands.json", JSON.stringify(commands), {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(
    c.result,
    JSON.stringify({
      state,
      phase,
      schedule,
      occurrence,
      job,
      commands: Object.fromEntries(
        Object.entries(commands).map(([k, v]) => [k, v.length]),
      ),
      accessibility_checks: accessibility,
      external_egress: egress,
      runtime_errors: errors,
      navigation_status: navigationStatus,
      asset_status: assetStatus,
      document_html: documentHTML,
      browser_sandbox: true,
      inference_performed: false,
      browser_version: version,
      node_version: process.version,
      axe_version: axe,
    }) + "\n",
    { flag: "wx", mode: 0o600 },
  );
}
