// Read-only metadata journey. The caller owns real HTTPS/Chrome and an active
// contact-only source spy; this driver never works or accepts source bytes.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";

export const ftpsCollectionMetadataAudits = [
  "ftps-collection-form",
  "ftps-collection-preview",
  "ftps-collection-selected",
];

export const ftpsCollectionBrowserStages = [
  "certificate",
  "browser-launch",
  "context-create",
  "login-navigation",
  "login-identity",
  "login-credential",
  "login-submit",
  "files-ready",
  "runtime-checks",
  "success-screenshot",
  "failure-capture",
  "record-write",
  "context-close",
  "browser-close",
  "complete",
  "definition",
  "counter-before",
  "navigation",
  "form",
  "form-audit",
  "preview-wire",
  "preview-request",
  "preview-definition",
  "preview-effects",
  "preview-source",
  "preview-visible",
  "preview-audit",
  "inspect-wire",
  "inspect-definition",
  "inspect-state",
  "inspect-visible",
  "selected-audit",
  "counter-after",
  "response-records",
  "result-write",
];

export function ftpsCollectionBrowserObservation(c, stage, error) {
  const mode = c.source?.ftps?.mode;
  if (
    c.collection_phase !== "ftps-metadata" ||
    !["explicit", "implicit"].includes(mode) ||
    !ftpsCollectionBrowserStages.includes(stage)
  )
    return null;
  if (error === undefined)
    return { kind: "ftps-collection-browser-progress", mode, stage };
  const kinds = {
    AssertionError: "assertion",
    TimeoutError: "timeout",
    SyntaxError: "syntax",
  };
  const frame = String(error?.stack ?? "").match(
    /(?:^|[/\\])(ftps-collection-browser|onboarding-exchange-browser)\.mjs:(\d+):\d+/m,
  );
  const line = Number(frame?.[2]);
  return {
    kind: "ftps-collection-browser-failure",
    mode,
    stage,
    error_kind:
      typeof error?.name === "string" && Object.hasOwn(kinds, error.name)
        ? kinds[error.name]
        : "other",
    source_file:
      frame && Number.isInteger(line) && line >= 1 && line <= 4000
        ? frame[1] === "ftps-collection-browser"
          ? "driver"
          : "wrapper"
        : null,
    source_line:
      frame && Number.isInteger(line) && line >= 1 && line <= 4000
        ? line
        : null,
  };
}

export async function qualifyFTPSCollectionMetadata(
  page,
  c,
  audit,
  record,
  emit = () => {},
) {
  let stage = "definition";
  const progress = (next) => {
    stage = next;
    const value = ftpsCollectionBrowserObservation(c, stage);
    if (value) emit(value);
  };
  try {
    progress("definition");
    assert.equal(c.collection_phase, "ftps-metadata");
    assert.equal(c.source.protocol, "ftps");
    assert.ok(["explicit", "implicit"].includes(c.source.ftps.mode));
    const definition = c.workflow.definition;
    assert.equal(definition.schema_version, 1);
    assert.equal(definition.source.kind, "ftps.collect");
    assert.deepEqual(definition.steps, []);
    assert.deepEqual(definition.source.connection, {
      id: c.source.id,
      version: c.source.version,
      hash: c.source.definition_hash,
    });
    const counter = async () => {
      const v = JSON.parse(await readFile(c.source_counter, "utf8"));
      assert.deepEqual(Object.keys(v).sort(), [
        "accepted_connections",
        "budget_exhausted",
        "kind",
        "schema_version",
        "stopped",
      ]);
      assert.equal(v.schema_version, 1);
      assert.equal(v.kind, "freightctl-ftps-contact-spy");
      assert.equal(v.accepted_connections, 0);
      assert.equal(v.budget_exhausted, false);
      assert.equal(v.stopped, false);
      return v;
    };
    progress("counter-before");
    const before = await counter();
    const prefix = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
    const region = page.getByRole("region", {
      name: "Collection workflows",
      exact: true,
    });
    progress("navigation");
    await page
      .getByRole("button", { name: "Collections", exact: true })
      .click();
    await region
      .getByRole("heading", {
        name: "Collection workflows",
        level: 2,
        exact: true,
      })
      .waitFor();
    progress("form");
    const fields = {
      "Collection workflow name": definition.name,
      "Ready manifest filename": definition.source.manifest,
      "Virtual local target folder": definition.source.target_directory,
      "Maximum files per batch": String(definition.source.max_files),
      "Maximum bytes per file": String(definition.source.max_file_bytes),
      "Maximum bytes per batch": String(definition.source.max_total_bytes),
    };
    for (const [label, value] of Object.entries(fields))
      await region.getByLabel(label, { exact: true }).fill(value);
    await region
      .getByLabel("Registered source connection", { exact: true })
      .selectOption(c.source.id + ":" + c.source.version);
    progress("form-audit");
    await audit(ftpsCollectionMetadataAudits[0]);
    progress("preview-wire");
    const [response] = await Promise.all([
      page.waitForResponse(
        (r) => r.url() === prefix + "/workflows/validate" && r.status() === 200,
      ),
      region
        .getByRole("button", {
          name: "Preview workflow definition",
          exact: true,
        })
        .click(),
    ]);
    progress("preview-request");
    const preview = await response.json();
    assert.equal(response.request().method(), "POST");
    assert.deepEqual(response.request().postDataJSON(), { definition });
    progress("preview-definition");
    assert.equal(preview.external_contact, false);
    assert.equal(preview.approval_required, true);
    assert.deepEqual(preview.definition, definition);
    assert.equal(preview.definition_hash, c.workflow.definition_hash);
    progress("preview-effects");
    assert.deepEqual(preview.effects, []);
    progress("preview-source");
    assert.deepEqual(preview.collection, {
      kind: "ftps.collect",
      source: definition.source,
      connection: c.source,
    });
    const terms = [
      c.source.user + "@" + c.source.address,
      c.source.ftps.mode + " FTPS",
      c.source.ftps.server_name,
      c.source.ftps.ca_sha256,
      c.source.directory,
      definition.source.manifest,
      "Local collection only",
    ];
    const requireTerms = async (locator) => {
      const text = await locator.innerText();
      for (const term of terms)
        assert.ok(text.includes(term), "missing reviewed FTPS metadata");
      assert.ok(!text.includes("Pinned source host"));
      assert.ok(!text.includes(c.private));
      assert.ok(!text.includes("password_reference"));
      assert.ok(!text.includes("ca_reference"));
      return text;
    };
    progress("preview-visible");
    const renderedPreview = region.getByRole("region", {
      name: "Workflow definition preview",
      exact: true,
    });
    await renderedPreview
      .getByRole("heading", {
        name: "Workflow definition preview",
        exact: true,
      })
      .waitFor();
    const previewText = await requireTerms(renderedPreview);
    progress("preview-audit");
    await audit(ftpsCollectionMetadataAudits[1]);
    const selected = page.getByRole("region", {
      name: "Selected collection",
      exact: true,
    });
    progress("inspect-wire");
    const [inspected] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url() === prefix + "/workflow-collections/" + c.view.job.id &&
          r.status() === 200,
      ),
      region
        .getByRole("button", {
          name: "Inspect collection " + c.view.job.id,
          exact: true,
        })
        .click(),
    ]);
    progress("inspect-definition");
    assert.equal(inspected.request().method(), "GET");
    assert.equal(inspected.request().postDataJSON(), null);
    const view = await inspected.json();
    assert.deepEqual(view, c.view);
    progress("inspect-state");
    assert.equal(view.job.state, "queued");
    assert.equal(view.job.captured, false);
    assert.equal(view.job.attempts, 0);
    assert.equal(view.job.fence, 0);
    assert.deepEqual(view.inputs, []);
    assert.equal(view.business_acceptance, "unknown");
    progress("inspect-visible");
    await selected
      .getByRole("heading", { name: "Collection: queued", exact: true })
      .waitFor();
    const selectedText = await requireTerms(selected);
    progress("selected-audit");
    await audit(ftpsCollectionMetadataAudits[2]);
    progress("counter-after");
    const after = await counter();
    assert.deepEqual(after, before);
    record("ftps-collection-exact-preview-inspection-without-source-contact");
    progress("response-records");
    const responses = [];
    for (const [name, r, method, route, request] of [
      [
        "workflow-preview",
        response,
        "POST",
        "/workflows/validate",
        { definition },
      ],
      [
        "collection-view",
        inspected,
        "GET",
        "/workflow-collections/" + view.job.id,
        null,
      ],
    ]) {
      const body = await r.text();
      assert.ok(Buffer.byteLength(body) <= 1 << 20);
      await writeFile(c.raw + "/" + name + ".body", body, {
        mode: 0o600,
        flag: "wx",
      });
      responses.push({ name, method, route, status: r.status(), request });
    }
    progress("result-write");
    await writeFile(
      c.raw + "/ftps-collection-browser-result.json",
      JSON.stringify(
        {
          kind: "ftps-collection-browser-metadata-v1",
          state: "passed",
          mode: c.source.ftps.mode,
          workflow_preview: preview,
          view,
          preview_text: previewText,
          selected_text: selectedText,
          source_counter_before: before,
          source_counter_after: after,
          source_work_performed: false,
          bytes_qualified: false,
          audits: ftpsCollectionMetadataAudits,
          responses,
        },
        null,
        2,
      ) + "\n",
      { mode: 0o600, flag: "wx" },
    );
  } catch (error) {
    const value = ftpsCollectionBrowserObservation(c, stage, error);
    if (value) emit(value);
    throw error;
  }
}
