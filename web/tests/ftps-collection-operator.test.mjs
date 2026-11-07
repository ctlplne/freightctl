import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  qualifyFTPSCollectionOperator,
  ftpsOperatorAudits,
  ftpsOperatorObservation,
} from "../../scripts/ftps-collection-operator-browser.mjs";

const fixtures = JSON.parse(
  await readFile(
    new URL("fixtures/ftps-collections.json", import.meta.url),
    "utf8",
  ),
);
const hash = (value) =>
  createHash("sha256")
    .update(
      JSON.stringify(value).replace(
        /[<>&\u2028\u2029]/g,
        (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
      ),
    )
    .digest("hex");

async function exercise({
  mode = "explicit",
  change = () => {},
  changedKey = false,
  earlyContact = false,
} = {}) {
  const directory = await mkdtemp(
    join(tmpdir(), "freightctl-operator-contract-"),
  );
  try {
    const f = structuredClone(
      fixtures[mode === "explicit" ? "explicit-local" : "implicit-sftp"],
    );
    f.workflow.version = 1;
    f.workflow.definition.schema_version = 1;
    f.workflow.definition.steps = [];
    Object.assign(f.workflow.definition.source, {
      target_directory: "/",
      manifest: "operator.ready.json",
    });
    f.workflow.definition_hash = hash(f.workflow.definition);
    f.workflow_preview.definition = f.workflow.definition;
    f.workflow_preview.definition_hash = f.workflow.definition_hash;
    f.workflow_preview.collection.source = f.workflow.definition.source;
    f.workflow_preview.effects = [];
    Object.assign(f.view.job.definition, {
      workflow: {
        id: f.workflow.id,
        version: 1,
        hash: f.workflow.definition_hash,
      },
      source: f.workflow.definition.source,
      effects: [],
      timeout_seconds: 300,
    });
    Object.assign(f.view.job, {
      workflow_hash: f.workflow.definition_hash,
      definition_hash: hash(f.view.job.definition),
    });
    const input = f.view.inputs[0];
    input.state = "accepted";
    input.run_id = null;
    input.source_name = "source.csv";
    input.target_path = "/" + input.sha256 + "-source.csv";
    f.view.inputs = [input];
    f.view.local_states = [{ input_id: input.id, state: "published" }];
    f.view.job.manifest = {
      schema_version: 1,
      batch_id: "11111111-2222-4333-8444-555555555555",
      files: [{ name: "source.csv", size_bytes: 3, sha256: input.sha256 }],
    };
    f.view.job.manifest_hash = hash(f.view.job.manifest);
    const c = {
      collection_phase: "ftps-operator",
      url: "https://127.0.0.1:9443",
      tenant: "tenant",
      partner: "partner",
      source: f.workflow_preview.collection.connection,
      definition: f.workflow.definition,
      definition_hash: f.workflow.definition_hash,
      manifest: f.view.job.manifest,
      manifest_hash: f.view.job.manifest_hash,
      source_counter: join(directory, "counter.json"),
      raw: directory,
      private: "/private-evidence-canary",
      producer_entry: { file_id: "000000ff-1111-4111-8111-111111111111" },
    };
    const draft = { ...f.workflow, state: "draft", revision: 1 };
    const approved = { ...f.workflow, state: "approved", revision: 2 };
    const jobPreview = {
      definition: f.view.job.definition,
      definition_hash: f.view.job.definition_hash,
      external_contact: false,
      approval_required: true,
    };
    const queued = {
      kind: "workflow_collection",
      id: f.view.job.id,
      state: "queued",
      revision: 1,
      definition_hash: f.view.job.definition_hash,
    };
    const worked = {
      ...queued,
      state: "captured",
      revision: f.view.job.revision,
    };
    change(c, f, queued, worked);
    const values = [draft, approved, queued, worked];
    const routes = [
      "/workflows/drafts",
      "/workflows/" + draft.id + "/1/approve",
      "/workflow-collections",
      "/workflow-collections/" + queued.id + "/work",
    ];
    const base = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
    let contacts = 2,
      active,
      index = 0;
    const saveCounter = async () =>
      writeFile(
        c.source_counter,
        JSON.stringify({
          schema_version: 1,
          kind: "freightctl-ftps-source-witness-v1",
          mode,
          port: Number(c.source.address.split(":")[1]),
          accepted_connections: contacts,
          stopped: false,
          budget_exhausted: false,
        }),
      );
    await saveCounter();
    const audits = [],
      clicks = [];
    const visible = [
      c.source.user + "@" + c.source.address,
      mode + " FTPS",
      c.source.ftps.server_name,
      c.source.ftps.ca_sha256,
      "Local collection only",
      input.file_id,
    ].join(" ");
    const locator = (name) => ({
      getByRole: (_role, options) => locator(options.name),
      getByLabel: (label) => locator(label),
      fill: async () => {},
      selectOption: async () => {},
      waitFor: async () => {},
      innerText: async () => visible,
      click: async () => {
        clicks.push(name);
        if (name === "Confirm exact decision") {
          await active.handler({
            abort: async () => {},
            fulfill: async () => {},
          });
          if (active.count === 2) {
            index++;
          }
        } else if (active?.read) {
          await active.handler({
            request: () => ({ method: () => active.method }),
            fulfill: async () => {},
            abort: async () => {},
          });
        }
      },
    });
    const replies = [
      f.workflow_preview,
      jobPreview,
      { ...f.view, job: { ...f.view.job, state: "queued" } },
      f.view,
    ];
    const responseRoutes = [
      "/workflows/validate",
      "/workflow-collections/preview",
      "/workflow-collections/" + queued.id,
      "/workflow-collections/" + queued.id,
    ];
    const page = {
      getByRole: (_role, options) => locator(options.name),
      getByText: (value) => locator(value),
      locator: (value) => locator(value),
      waitForResponse: async () => {
        throw new Error("Chromium response body unavailable");
      },
      route: async (target, handler, options) => {
        if (options?.times === 1) {
          const route = responseRoutes.shift();
          assert.equal(target, base + route);
          active = {
            target,
            handler,
            read: true,
            value: replies.shift(),
            method:
              route.includes("preview") || route.includes("validate")
                ? "POST"
                : "GET",
          };
          return;
        }
        assert.equal(target, base + routes[index]);
        active = { target, handler, count: 0 };
      },
      unroute: async (target) => assert.equal(target, active.target),
    };
    const actual = async (_route, label, target) => {
      if (active.read)
        return {
          status: 200,
          body: JSON.stringify(active.value),
          selection: null,
        };
      assert.equal(target, base + routes[index]);
      const replayed = active.count++ === 1;
      if (index === 2 && earlyContact) {
        contacts++;
        await saveCounter();
      }
      if (index === 3 && !replayed) {
        contacts++;
        await saveCounter();
      }
      return {
        status: 200,
        selection: { synthetic_same_decision: index },
        idempotency_key:
          changedKey && replayed ? "changed" : "original-" + index,
        body: JSON.stringify({ resource: values[index], replayed }),
      };
    };
    await qualifyFTPSCollectionOperator(
      page,
      c,
      (name) => {
        audits.push(name);
      },
      () => {},
      actual,
    );
    return {
      result: JSON.parse(
        await readFile(join(directory, "ftps-operator-result.json"), "utf8"),
      ),
      audits,
      clicks,
    };
  } finally {
    await rm(directory, { recursive: true });
  }
}

test("both modes use ordinary collection controls and four original-key recoveries before exact capture", async () => {
  for (const mode of ["explicit", "implicit"]) {
    const value = await exercise({ mode });
    assert.equal(value.result.state, "passed");
    assert.equal(value.result.source_control_connections, 1);
    assert.equal(value.result.responses.length, 4);
    assert.deepEqual(value.audits, ftpsOperatorAudits);
    assert.equal(
      value.clicks.filter((v) => v === "Confirm exact decision").length,
      8,
    );
    assert.equal(value.result.business_acceptance, "unknown");
  }
});

test("changed retry keys or metadata contact cannot become successful operator evidence", async () => {
  await assert.rejects(exercise({ changedKey: true }));
  await assert.rejects(exercise({ earlyContact: true }));
});

test("receipt cannot hide a different source revision, extra attempt or missing immutable file", async () => {
  for (const change of [
    (_c, f) => {
      f.view.job.attempts = 2;
    },
    (c, f) => {
      f.view.inputs[0].file_id = c.producer_entry.file_id;
    },
    (_c, f) => {
      f.view.inputs[0].file_id = null;
    },
    (_c, f) => {
      f.view.business_acceptance = "accepted";
    },
    (_c, f) => {
      f.view.local_states[0].state = "held";
    },
    (_c, _f, _q, worked) => {
      worked.state = "retry";
    },
  ])
    await assert.rejects(exercise({ change }));
});

test("operator diagnostics carry only fixed stages and bounded source locations", () => {
  const config = {
    collection_phase: "ftps-operator",
    source: { ftps: { mode: "explicit" } },
  };
  const error = {
    name: "AssertionError",
    message: "private-canary",
    stack:
      "Error private-canary\n at /private/ftps-collection-operator-browser.mjs:200:9",
  };
  assert.deepEqual(ftpsOperatorObservation(config, "operator-work", error), {
    kind: "ftps-operator-browser-failure",
    mode: "explicit",
    stage: "operator-work",
    error_kind: "assertion",
    source_file: "driver",
    source_line: 200,
  });
  assert.equal(ftpsOperatorObservation(config, "private-canary", error), null);
  for (const stage of [
    "operator-form-name",
    "operator-form-manifest",
    "operator-form-target",
    "operator-form-file-count",
    "operator-form-file-bytes",
    "operator-form-total-bytes",
    "operator-form-source",
  ]) {
    const observed = ftpsOperatorObservation(config, stage, error);
    assert.ok(
      observed,
      "the exact closed field stage must survive the original timeout",
    );
    assert.equal(observed.stage, stage);
    assert.equal(JSON.stringify(observed).includes("private-canary"), false);
  }
  assert.equal(
    ftpsOperatorObservation(
      { ...config, collection_phase: "ftps-metadata" },
      "operator-work",
      error,
    ),
    null,
  );
  const unknown = ftpsOperatorObservation(config, "operator-work", {
    ...error,
    name: "constructor",
    stack: "/private/canary:5:4",
  });
  assert.equal(unknown.error_kind, "other");
  assert.equal(unknown.source_file, null);
  assert.ok(!JSON.stringify(unknown).includes("canary"));
});
