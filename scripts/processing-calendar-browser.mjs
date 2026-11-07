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
  schedule = "",
  run = "",
  file = "",
  egress = 0,
  errors = 0,
  accessibility = 0;
const drafts = [],
  ticks = [];
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
  async function actualGet(path) {
    return page.evaluate(async (path) => {
      const r = await fetch(path, { credentials: "same-origin" });
      return { status: r.status, body: await r.text() };
    }, prefix + path);
  }
  async function loseFirst(url, records, label) {
    const routeHandler = async (route) => {
      const request = route.request();
      assert.equal(request.method(), "POST");
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
    await page.route(url, routeHandler);
    await button("Confirm exact decision", dialog()).click();
    await page.getByText(/^Schedule decision not confirmed/).waitFor();
    await button("Confirm exact decision", dialog()).click();
    await dialog().waitFor({ state: "hidden" });
    await page.unroute(url, routeHandler);
    assert.equal(records.length, 2);
    assert.equal(records[0].key, records[1].key);
    assert.deepEqual(records[0].body, records[1].body);
    assert.equal(records[0].reply.replayed, false);
    assert.equal(records[1].reply.replayed, true);
    assert.deepEqual(records[0].reply.resource, records[1].reply.resource);
    return records[1].reply.resource;
  }
  await page.goto(c.url);
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
  await region
    .getByLabel("Approved workflow", { exact: true })
    .selectOption(x.workflow.id + ":" + x.workflow.version);
  for (const [label, value] of Object.entries({
    "Schedule name": x.name,
    "Published source folder": x.source.directory,
    "Filename pattern": x.source.filename_pattern,
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
    "Maximum files per occurrence": String(x.max_files_per_occurrence),
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
  await audit("calendar-processing-editor");
  const previewResponse = page.waitForResponse(
    (r) =>
      r.url() === c.url + prefix + "/workflow-schedules/preview" &&
      r.request().method() === "POST",
  );
  await button("Preview schedule", region).click();
  const previewWire = await previewResponse;
  assert.equal(previewWire.status(), 200);
  const preview = await previewWire.json();
  assert.equal(preview.definition.schema_version, 2);
  assert.equal(preview.definition.source.kind, "owned_released_records");
  assert.equal(
    preview.definition.processing.profile,
    "owned-record-processing-schedule-v1",
  );
  assert.equal(preview.definition.workflow.hash, c.workflow_hash);
  assert.deepEqual(preview.effects, []);
  assert.equal(preview.external_contact, false);
  await page
    .getByRole("heading", { name: "Review schedule preview", exact: true })
    .waitFor();
  await audit("calendar-processing-preview");
  await button("Review saving schedule draft", region).click();
  await dialog().waitFor();
  await audit("calendar-processing-draft-review");
  const drafted = await loseFirst(
    c.url + prefix + "/workflow-schedules/drafts",
    drafts,
    "calendar-draft",
  );
  assert.equal(drafted.profile, "owned-record-processing-schedule-v1");
  assert.equal(drafted.schedule.definition_hash, preview.definition_hash);
  schedule = drafted.schedule.id;
  await page.reload();
  await button("Schedules").click();
  await button("Reload schedules", region).click();
  await button(`Inspect schedule ${x.name} version 1`, region).click();
  await region
    .getByRole("heading", { name: "Schedule: draft", exact: true })
    .waitFor();
  await button("Review schedule activate", region).click();
  await dialog().waitFor();
  assert.match(await dialog().innerText(), /owned released inputs/);
  await audit("calendar-processing-activation");
  await button("Confirm exact decision", dialog()).click();
  await dialog().waitFor({ state: "hidden" });
  await region
    .getByRole("heading", { name: "Schedule: active", exact: true })
    .waitFor();
  while (Date.now() < Date.parse(c.due_at) + 100)
    await new Promise((resolve) =>
      setTimeout(
        resolve,
        Math.min(1000, Date.parse(c.due_at) + 100 - Date.now()),
      ),
    );
  await button("Review queuing due work", region).click();
  await dialog().waitFor();
  const tick = await loseFirst(
    c.url + prefix + `/workflow-schedules/${schedule}/1/tick`,
    ticks,
    "calendar-tick",
  );
  assert.equal(tick.profile, "owned-record-processing-schedule-v1");
  assert.equal(tick.external_contact, false);
  assert.equal(tick.run_ids.length, 1);
  assert.equal(tick.occurrences.length, 1);
  assert.equal(tick.occurrences[0].input_count, 1);
  run = tick.run_ids[0];
  await button(
    "Inspect occurrence " + tick.occurrences[0].id.slice(0, 8),
    region,
  ).click();
  const occurrence = page.getByRole("region", {
    name: "Selected occurrence",
    exact: true,
  });
  await occurrence.waitFor();
  assert.match(await occurrence.innerText(), new RegExp(c.source));
  await audit("calendar-processing-owned-occurrence");
  await button("Inspect scheduled run " + run.slice(0, 8), occurrence).click();
  const outcome = page.getByRole("region", {
    name: "Processing run outcome",
    exact: true,
  });
  await outcome.waitFor();
  await button("Review working this run", outcome).click();
  const workResponse = page.waitForResponse(
    (r) =>
      r.url() === c.url + prefix + `/workflow-runs/${run}/work` &&
      r.request().method() === "POST",
  );
  await button("Confirm this exact action", dialog()).click();
  const workWire = await workResponse;
  assert.equal(workWire.status(), 200);
  const work = await workWire.json();
  assert.equal(work.status.run.id, run);
  assert.equal(work.status.observed_reason, "output_held");
  assert.equal(work.status.processing.released, false);
  assert.deepEqual(work.status.steps, []);
  file = work.status.processing.output_file_id;
  await dialog().waitFor({ state: "hidden" });
  assert.equal((await actualGet("/files/" + file)).status, 409);
  const checked = await actualGet("/checks/" + file);
  assert.equal(checked.status, 200);
  const held = JSON.parse(checked.body);
  assert.equal(held.check.state, "held");
  assert.equal(held.check.attempts, 0);
  assert.equal(held.check.report_hash, "");
  await audit("calendar-processing-held-output");
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
      schedule,
      run,
      file,
      workflow_hash: c.workflow_hash,
      draft_requests: drafts.length,
      tick_requests: ticks.length,
      accessibility_checks: accessibility,
      external_egress: egress,
      runtime_errors: errors,
      browser_sandbox: true,
      inference_performed: false,
      failure_sha256: failure,
    }) + "\n",
  );
}
