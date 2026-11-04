import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { ftpsCollectionBrowserStages } from "./ftps-collection-browser.mjs";
import { wireResponse } from "./browser-wire.mjs";

export const ftpsOperatorStages = [
  ...ftpsCollectionBrowserStages.slice(0, 16),
  "operator-definition",
  "operator-counter-before",
  "operator-form",
  "operator-preview",
  "operator-draft",
  "operator-approval",
  "operator-queue",
  "operator-counter-queued",
  "operator-work",
  "operator-inspect",
  "operator-counter-after",
  "operator-record",
];

export function ftpsOperatorObservation(c, stage, error) {
  const mode = c.source?.ftps?.mode;
  if (
    c.collection_phase !== "ftps-operator" ||
    !["explicit", "implicit"].includes(mode) ||
    !ftpsOperatorStages.includes(stage)
  )
    return null;
  if (error === undefined)
    return { kind: "ftps-operator-browser-progress", mode, stage };
  const kinds = {
    AssertionError: "assertion",
    TimeoutError: "timeout",
    SyntaxError: "syntax",
  };
  const frame = String(error?.stack ?? "").match(
    /(?:^|[/\\])(ftps-collection-operator-browser|onboarding-exchange-browser)\.mjs:(\d+):\d+/m,
  );
  const line = Number(frame?.[2]);
  const found = frame && Number.isInteger(line) && line >= 1 && line <= 4000;
  return {
    kind: "ftps-operator-browser-failure",
    mode,
    stage,
    error_kind:
      typeof error?.name === "string" && Object.hasOwn(kinds, error.name)
        ? kinds[error.name]
        : "other",
    source_file: found
      ? frame[1] === "ftps-collection-operator-browser"
        ? "driver"
        : "wrapper"
      : null,
    source_line: found ? line : null,
  };
}

export const ftpsOperatorAudits = [
  "ftps-operator-form",
  "ftps-operator-draft",
  "ftps-operator-approval",
  "ftps-operator-queue",
  "ftps-operator-work",
  "ftps-operator-captured",
];

export async function qualifyFTPSCollectionOperator(
  page,
  c,
  audit,
  record,
  actual,
  emit = () => {},
) {
  let stage = "operator-definition";
  const mark = (next) => {
    stage = next;
    emit(ftpsOperatorObservation(c, stage));
  };
  try {
    mark(stage);
    return await runOperator(page, c, audit, record, actual, mark);
  } catch (error) {
    emit(ftpsOperatorObservation(c, stage, error));
    throw error;
  }
}

async function runOperator(page, c, audit, record, actual, mark) {
  assert.equal(c.collection_phase, "ftps-operator");
  assert.equal(c.source.protocol, "ftps");
  assert.ok(["explicit", "implicit"].includes(c.source.ftps.mode));
  assert.equal(c.definition.source.kind, "ftps.collect");
  assert.deepEqual(c.definition.steps, []);
  const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
  const region = page.getByRole("region", {
    name: "Collection workflows",
    exact: true,
  });
  const selected = page.getByRole("region", {
    name: "Selected collection",
    exact: true,
  });
  const counters = [];
  async function counter() {
    const value = JSON.parse(await readFile(c.source_counter, "utf8"));
    assert.deepEqual(Object.keys(value).sort(), [
      "accepted_connections",
      "budget_exhausted",
      "kind",
      "mode",
      "port",
      "schema_version",
      "stopped",
    ]);
    assert.equal(value.schema_version, 1);
    assert.equal(value.kind, "freightctl-ftps-source-witness-v1");
    assert.equal(value.mode, c.source.ftps.mode);
    assert.equal(c.source.address, "127.0.0.1:" + value.port);
    assert.equal(value.stopped, false);
    assert.equal(value.budget_exhausted, false);
    assert.ok(Number.isInteger(value.accepted_connections));
    counters.push(value);
    return value.accepted_connections;
  }
  mark("operator-counter-before");
  const before = await counter();
  assert.equal(
    before,
    2,
    "only the two original producer uploads may precede review",
  );
  const responses = [],
    reads = [];
  async function response(route, name, action) {
    return wireResponse(
      page,
      prefix + route,
      action,
      async (intercepted, label, target) => {
        const value = await actual(intercepted, label, target);
        assert.equal(value.status, 200);
        assert.ok(Buffer.byteLength(value.body) <= 262144);
        reads.push({
          name,
          route,
          method: intercepted.request().method(),
          status: value.status,
          request: value.selection,
        });
        await writeFile(c.raw + "/" + name + ".body", value.body, {
          mode: 0o600,
          flag: "wx",
        });
        return value;
      },
      name,
    );
  }
  async function loss(route, label) {
    const seen = [],
      target = prefix + route;
    await page.route(target, async (intercepted) => {
      assert.ok(
        seen.length < 2,
        "a saved-key decision may be attempted only twice",
      );
      const value = await actual(
        intercepted,
        label + "-" + seen.length,
        target,
      );
      seen.push(value);
      if (seen.length === 1) await intercepted.abort("failed");
      else
        await intercepted.fulfill({
          status: value.status,
          contentType: "application/json",
          body: value.body,
        });
    });
    const confirm = () =>
      page
        .getByRole("button", { name: "Confirm exact decision", exact: true })
        .click();
    await confirm();
    await page.getByText(/^The result was not confirmed\./).waitFor();
    await confirm();
    await page.locator("dialog[open]").waitFor({ state: "hidden" });
    await page.unroute(target);
    assert.equal(seen.length, 2);
    assert.equal(seen[0].status, 200);
    assert.equal(seen[1].status, 200);
    assert.ok(seen[0].idempotency_key);
    assert.equal(seen[0].idempotency_key, seen[1].idempotency_key);
    assert.deepEqual(seen[0].selection, seen[1].selection);
    const first = JSON.parse(seen[0].body),
      second = JSON.parse(seen[1].body);
    assert.equal(first.replayed, false);
    assert.equal(second.replayed, true);
    assert.deepEqual(first.resource, second.resource);
    responses.push({ route, label, observed: seen });
    record(label + "-original-key-recovery");
    return first.resource;
  }
  mark("operator-form");
  await page.getByRole("button", { name: "Collections", exact: true }).click();
  await region
    .getByRole("heading", {
      name: "Collection workflows",
      level: 2,
      exact: true,
    })
    .waitFor();
  const source = c.definition.source;
  const fields = {
    "Collection workflow name": c.definition.name,
    "Ready manifest filename": source.manifest,
    "Virtual local target folder": source.target_directory,
    "Maximum files per batch": String(source.max_files),
    "Maximum bytes per file": String(source.max_file_bytes),
    "Maximum bytes per batch": String(source.max_total_bytes),
  };
  for (const [name, value] of Object.entries(fields))
    await region.getByLabel(name, { exact: true }).fill(value);
  await region
    .getByLabel("Registered source connection", { exact: true })
    .selectOption(c.source.id + ":" + c.source.version);
  await audit(ftpsOperatorAudits[0]);
  mark("operator-preview");
  const preview = await response(
    "/workflows/validate",
    "workflow-preview",
    () =>
      region
        .getByRole("button", {
          name: "Preview workflow definition",
          exact: true,
        })
        .click(),
  );
  assert.deepEqual(preview.definition, c.definition);
  assert.equal(preview.definition_hash, c.definition_hash);
  assert.equal(preview.external_contact, false);
  assert.equal(preview.approval_required, true);
  assert.deepEqual(preview.effects, []);
  assert.deepEqual(preview.collection, {
    kind: "ftps.collect",
    source,
    connection: c.source,
  });
  await region
    .getByRole("heading", { name: "Workflow definition preview", exact: true })
    .waitFor();
  await region
    .getByRole("button", { name: "Review saving workflow draft", exact: true })
    .click();
  await audit(ftpsOperatorAudits[1]);
  mark("operator-draft");
  const draft = await loss("/workflows/drafts", "ftps-operator-draft");
  assert.deepEqual(draft.definition, c.definition);
  assert.equal(draft.definition_hash, c.definition_hash);
  assert.equal(draft.state, "draft");
  assert.equal(draft.version, 1);
  assert.equal(draft.revision, 1);
  await region
    .getByLabel("Saved collection workflow", { exact: true })
    .selectOption(draft.id + ":1");
  await region
    .getByRole("heading", {
      name: draft.definition.name + ": draft",
      exact: true,
    })
    .waitFor();
  await region
    .getByRole("button", { name: "Review workflow approval", exact: true })
    .click();
  await audit(ftpsOperatorAudits[2]);
  mark("operator-approval");
  const approved = await loss(
    "/workflows/" + draft.id + "/1/approve",
    "ftps-operator-approve",
  );
  assert.equal(approved.state, "approved");
  assert.equal(approved.revision, 2);
  assert.equal(approved.id, draft.id);
  assert.equal(approved.definition_hash, draft.definition_hash);
  assert.deepEqual(approved.definition, draft.definition);
  await region
    .getByLabel("Collection and sending cutoff from queue time (seconds)", {
      exact: true,
    })
    .fill("300");
  mark("operator-queue");
  const jobPreview = await response(
    "/workflow-collections/preview",
    "job-preview",
    () =>
      region
        .getByRole("button", { name: "Preview collection job", exact: true })
        .click(),
  );
  assert.equal(jobPreview.external_contact, false);
  assert.equal(jobPreview.approval_required, true);
  assert.deepEqual(jobPreview.definition.source_connection, c.source);
  assert.deepEqual(jobPreview.definition.source, source);
  assert.deepEqual(jobPreview.definition.effects, []);
  await region
    .getByRole("button", { name: "Review queueing collection", exact: true })
    .click();
  await audit(ftpsOperatorAudits[3]);
  const queued = await loss("/workflow-collections", "ftps-operator-queue");
  assert.equal(queued.state, "queued");
  assert.equal(queued.revision, 1);
  assert.equal(queued.definition_hash, jobPreview.definition_hash);
  mark("operator-counter-queued");
  assert.equal(await counter(), before);
  await response("/workflow-collections/" + queued.id, "queued-view", () =>
    region
      .getByRole("button", {
        name: "Inspect collection " + queued.id,
        exact: true,
      })
      .click(),
  );
  await selected
    .getByRole("heading", { name: "Collection: queued", exact: true })
    .waitFor();
  await selected
    .getByRole("button", { name: "Review reading source batch", exact: true })
    .click();
  await audit(ftpsOperatorAudits[4]);
  mark("operator-work");
  const worked = await loss(
    "/workflow-collections/" + queued.id + "/work",
    "ftps-operator-work",
  );
  assert.equal(worked.state, "captured");
  assert.equal(worked.id, queued.id);
  assert.equal(worked.definition_hash, queued.definition_hash);
  mark("operator-inspect");
  const view = await response(
    "/workflow-collections/" + queued.id,
    "captured-view",
    () =>
      selected
        .getByRole("button", {
          name: "Refresh selected collection",
          exact: true,
        })
        .click(),
  );
  await selected
    .getByRole("heading", { name: "Collection: captured", exact: true })
    .waitFor();
  assert.equal(view.job.state, "captured");
  assert.equal(view.job.captured, true);
  assert.equal(view.job.attempts, 1);
  assert.equal(view.job.fence, 1);
  assert.equal(view.job.id, queued.id);
  assert.equal(view.job.manifest_hash, c.manifest_hash);
  assert.deepEqual(view.job.manifest, c.manifest);
  assert.deepEqual(view.job.definition, jobPreview.definition);
  assert.equal(view.current_authority, true);
  assert.equal(view.business_acceptance, "unknown");
  assert.equal(view.inputs.length, 1);
  assert.equal(view.inputs[0].state, "accepted");
  assert.equal(typeof view.inputs[0].file_id, "string");
  assert.match(
    view.inputs[0].file_id,
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/,
  );
  assert.equal(view.inputs[0].file_id, view.inputs[0].object_id);
  assert.notEqual(view.inputs[0].file_id, c.producer_entry.file_id);
  assert.equal(view.inputs[0].source_name, "source.csv");
  assert.equal(view.inputs[0].sha256, c.manifest.files[0].sha256);
  assert.equal(view.inputs[0].size_bytes, c.manifest.files[0].size_bytes);
  assert.equal(
    view.inputs[0].target_path,
    "/" + c.manifest.files[0].sha256 + "-source.csv",
  );
  assert.equal(view.local_states.length, 1);
  assert.equal(view.local_states[0].state, "published");
  const visible = await selected.innerText();
  for (const term of [
    c.source.user + "@" + c.source.address,
    c.source.ftps.mode + " FTPS",
    c.source.ftps.server_name,
    c.source.ftps.ca_sha256,
    "Local collection only",
    view.inputs[0].file_id,
  ])
    assert.ok(
      visible.includes(term),
      "exact collected source/custody identity must remain visible",
    );
  assert.ok(!visible.includes(c.private));
  await audit(ftpsOperatorAudits[5]);
  mark("operator-counter-after");
  assert.equal(
    await counter(),
    before + 1,
    "all saved-key work replays must reuse original source capture",
  );
  mark("operator-record");
  await writeFile(
    c.raw + "/ftps-operator-result.json",
    JSON.stringify(
      {
        kind: "ftps-collection-operator-v1",
        state: "passed",
        mode: c.source.ftps.mode,
        preview,
        draft,
        approved,
        job_preview: jobPreview,
        queued,
        worked,
        view,
        visible,
        counters,
        responses,
        reads,
        audits: ftpsOperatorAudits,
        source_control_connections: 1,
        original_key_replays: 4,
        business_acceptance: "unknown",
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600, flag: "wx" },
  );
}
