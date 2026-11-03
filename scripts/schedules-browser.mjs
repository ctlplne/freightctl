import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { wireResponse } from "./browser-wire.mjs";
export async function qualifySchedules(page, c, audit, record, actual) {
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`,
    region = page.getByRole("region", {
      name: "Workflow schedules",
      exact: true,
    }),
    responses = [];
  const contacts = async () =>
    (await readFile(c.receiver_log, "utf8")).split("Accepted publickey for ")
      .length - 1;
  const before = await contacts();
  await page.getByRole("button", { name: "Schedules", exact: true }).click();
  await region
    .getByRole("heading", { name: "Workflow schedules", level: 2, exact: true })
    .waitFor();
  async function save(label, value) {
    await writeFile(
      c.raw + "/" + label + ".json",
      JSON.stringify(value, null, 2) + "\n",
    );
  }
  async function loss(target, label, action) {
    const seen = [];
    await page.route(target, async (route) => {
      const r = await actual(route, label + "-" + seen.length, target);
      seen.push(r);
      if (seen.length === 1) await route.abort("failed");
      else
        await route.fulfill({
          status: r.status,
          contentType: "application/json",
          body: r.body,
        });
    });
    await action();
    await page.getByText(/^Schedule decision not confirmed/).waitFor();
    await action();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    assert.equal(seen.length, 2);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    assert.equal(JSON.parse(seen[0].body).replayed, false);
    assert.equal(JSON.parse(seen[1].body).replayed, true);
    const first = JSON.parse(seen[0].body),
      second = JSON.parse(seen[1].body);
    let resource = second.resource;
    if (resource === undefined) {
      assert.deepEqual(first.dispatch, second.dispatch);
      assert.deepEqual(first.status, second.status);
      resource = second;
    } else assert.deepEqual(first.resource, resource);
    await page.unroute(target);
    responses.push(...seen);
    return resource;
  }
  const confirm = () =>
    page
      .getByRole("button", { name: "Confirm exact decision", exact: true })
      .click();
  async function inspect(s) {
    await region
      .getByRole("button", {
        name: `Inspect schedule ${s.name} version ${s.version}`,
        exact: true,
      })
      .click();
    await region
      .getByRole("heading", { name: "Schedule: " + s.state, exact: true })
      .waitFor();
  }
  async function fill(x) {
    const fields = {
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
    };
    for (const [label, value] of Object.entries(fields))
      await region.getByLabel(label, { exact: true }).fill(value);
    await region
      .getByLabel("Approved workflow", { exact: true })
      .selectOption(x.workflow.id + ":" + x.workflow.version);
    await region
      .getByLabel("Include readable subfolders", { exact: true })
      .setChecked(x.source.recursive);
    for (const [i, name] of [
      "Sunday",
      "Monday",
      "Tuesday",
      "Wednesday",
      "Thursday",
      "Friday",
      "Saturday",
    ].entries())
      await region
        .getByLabel(name, { exact: true })
        .setChecked(x.calendar.weekdays.includes(i));
    await region
      .getByLabel("Repeated local time", { exact: true })
      .selectOption(x.calendar.fold_policy);
    await region
      .getByLabel("Missed-run rule", { exact: true })
      .selectOption(x.missed_run_policy);
  }
  let schedule = c.schedule,
    result = {};
  const preview = (label) =>
    wireResponse(
      page,
      prefix + "/workflow-schedules/preview",
      () =>
        region
          .getByRole("button", { name: "Preview schedule", exact: true })
          .click(),
      (route, name, target) => {
        assert.equal(route.request().method(), "POST");
        return actual(route, name, target);
      },
      label,
    );
  if (c.schedule_phase === "create") {
    await audit("schedule-prepare");
    await fill(c.calendar_probe);
    const probe = await preview("schedule-historical-preview");
    assert.equal(probe.definition.calendar.fold_policy, "both");
    assert.equal(probe.first_due, "2024-11-03T05:30:00Z");
    assert.equal(probe.latest_due, "2024-11-03T06:30:00Z");
    assert.equal(probe.external_contact, false);
    await save("historical-fold-preview", probe);
    record("historical-civil-fold-preview-without-changing-host-clock");
    await fill(c.selection);
    const current = await preview("schedule-current-preview");
    await save("current-calendar-preview", current);
    await region
      .getByRole("heading", { name: "Review schedule preview", exact: true })
      .waitFor();
    assert.equal(
      await region
        .getByRole("heading", { name: "Review schedule preview", exact: true })
        .evaluate((el) => el === document.activeElement),
      true,
    );
    assert.equal(current.effects.length, 2);
    await audit("schedule-preview");
    await region
      .getByRole("button", {
        name: "Review saving schedule draft",
        exact: true,
      })
      .click();
    await page
      .getByRole("heading", {
        name: "Save reviewed schedule draft",
        exact: true,
      })
      .waitFor();
    await audit("schedule-save-confirmation");
    const draft = await loss(
      prefix + "/workflow-schedules/drafts",
      "browser-schedule-draft",
      confirm,
    );
    schedule = draft.schedule;
    assert.equal(schedule.state, "draft");
    assert.equal(schedule.definition_hash, current.definition_hash);
    await region
      .getByRole("heading", { name: "Schedule: draft", exact: true })
      .waitFor();
    await audit("schedule-private-draft");
    await page.reload();
    await page.getByRole("button", { name: "Schedules", exact: true }).click();
    await inspect(schedule);
    await region
      .getByRole("button", { name: "Review schedule activate", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Confirm schedule activate", exact: true })
      .waitFor();
    await audit("schedule-activation-confirmation");
    const active = await loss(
      prefix +
        `/workflow-schedules/${schedule.id}/${schedule.version}/activate`,
      "browser-schedule-activate",
      confirm,
    );
    schedule = active.schedule;
    assert.equal(schedule.state, "active");
    await region
      .getByRole("heading", { name: "Schedule: active", exact: true })
      .waitFor();
    await audit("schedule-active");
    assert.equal(await contacts(), before);
    record(
      "schedule-exact-preview-draft-activation-original-key-private-reload-no-receiver-contact",
    );
    result = { historical_probe: probe, current_preview: current };
  } else if (c.schedule_phase === "work") {
    await inspect(schedule);
    await audit("schedule-before-due-queue");
    await region
      .getByRole("button", { name: "Review queuing due work", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Queue reviewed due work", exact: true })
      .waitFor();
    await audit("schedule-queue-confirmation");
    const tick = await loss(
      prefix + `/workflow-schedules/${schedule.id}/${schedule.version}/tick`,
      "browser-schedule-tick",
      confirm,
    );
    assert.equal(tick.external_contact, false);
    assert.equal(tick.run_ids.length, 1);
    assert.equal(await contacts(), before);
    const occurrence = tick.occurrences.find((o) => o.input_count === 1);
    assert.ok(occurrence);
    await region
      .getByRole("button", {
        name: "Inspect occurrence " + occurrence.id.slice(0, 8),
        exact: true,
      })
      .click();
    await region
      .getByRole("heading", { name: "Occurrence: queued", exact: true })
      .waitFor();
    await region
      .getByRole("button", {
        name: "Inspect scheduled run " + tick.run_ids[0].slice(0, 8),
        exact: true,
      })
      .click();
    await region
      .getByRole("heading", { name: "Scheduled run: queued", exact: true })
      .waitFor();
    await audit("schedule-exact-source-run");
    for (let step = 0; step < 2; step++) {
      await region
        .getByRole("button", {
          name: "Review executing next scheduled step",
          exact: true,
        })
        .click();
      await page
        .getByRole("heading", {
          name: "Execute scheduled workflow step",
          exact: true,
        })
        .waitFor();
      await audit("schedule-work-confirmation-" + step);
      const target = prefix + "/workflow-runs/" + tick.run_ids[0] + "/work",
        work = await loss(target, "browser-schedule-work-" + step, confirm);
      assert.equal(work.dispatch.step_id, step === 0 ? "first" : "second");
      assert.equal(
        work.status.observed_state,
        step === 0 ? "running" : "succeeded",
      );
      await region
        .getByRole("heading", {
          name: "Scheduled run: " + (step === 0 ? "running" : "succeeded"),
          exact: true,
        })
        .waitFor();
      assert.equal(await contacts(), before + step + 1);
      await audit("schedule-work-receipt-" + step);
    }
    record(
      "schedule-browser-ordered-steps-lost-responses-do-not-advance-or-duplicate",
    );
    result = { tick };
  } else if (c.schedule_phase === "suspend") {
    await inspect(schedule);
    await region
      .getByRole("button", { name: "Review schedule suspend", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Confirm schedule suspend", exact: true })
      .waitFor();
    await audit("schedule-suspend-confirmation");
    const changed = await loss(
      prefix + `/workflow-schedules/${schedule.id}/${schedule.version}/suspend`,
      "browser-schedule-suspend",
      confirm,
    );
    schedule = changed.schedule;
    await region
      .getByRole("heading", { name: "Schedule: suspended", exact: true })
      .waitFor();
    await audit("schedule-suspended");
    assert.equal(await contacts(), before);
    record("schedule-suspension-original-key-no-receiver-contact");
  } else throw Error("unknown schedule phase");
  await save("schedule-browser-result", {
    state: "passed",
    phase: c.schedule_phase,
    schedule,
    ...result,
    responses,
  });
}
