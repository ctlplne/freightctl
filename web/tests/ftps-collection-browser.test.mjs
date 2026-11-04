import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  qualifyFTPSCollectionMetadata,
  ftpsCollectionMetadataAudits,
  ftpsCollectionBrowserObservation,
  ftpsCollectionBrowserStages,
} from "../../scripts/ftps-collection-browser.mjs";

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
  before = 0,
  after = 0,
  textSuffix = "",
  observe = () => {},
} = {}) {
  const directory = await mkdtemp(
    join(tmpdir(), "freightctl-browser-driver-contract-"),
  );
  try {
    const f = structuredClone(
      fixtures[mode === "explicit" ? "explicit-local" : "implicit-sftp"],
    );
    f.workflow.definition.steps = [];
    f.workflow.definition_hash = hash(f.workflow.definition);
    f.workflow_preview.definition = f.workflow.definition;
    f.workflow_preview.definition_hash = f.workflow.definition_hash;
    f.workflow_preview.effects = [];
    f.view.job.definition.effects = [];
    f.view.job.definition.workflow.hash = f.workflow.definition_hash;
    Object.assign(f.view.job, {
      workflow_hash: f.workflow.definition_hash,
      definition_hash: hash(f.view.job.definition),
      state: "queued",
      revision: 1,
      attempts: 0,
      fence: 0,
      captured: false,
      manifest: null,
      manifest_hash: null,
      lease_owner: "",
      lease_until: null,
    });
    Object.assign(f.view, {
      inputs: [],
      local_states: [],
      current_authority: true,
      observed_state: "queued",
      business_acceptance: "unknown",
    });
    const c = {
      collection_phase: "ftps-metadata",
      source: f.workflow_preview.collection.connection,
      workflow: f.workflow,
      view: f.view,
      url: "https://127.0.0.1:9443",
      tenant: "tenant",
      partner: "partner",
      private: "/private-freightctl-fixture",
      source_counter: join(directory, "counter.json"),
      raw: directory,
    };
    const preview = structuredClone(f.workflow_preview),
      view = structuredClone(f.view);
    change(c, preview, view);
    const counter = (count) => ({
      schema_version: 1,
      kind: "freightctl-ftps-contact-spy",
      accepted_connections: count,
      stopped: false,
      budget_exhausted: false,
    });
    await writeFile(c.source_counter, JSON.stringify(counter(before)), {
      mode: 0o600,
    });
    const clicked = [],
      fields = {},
      audits = [],
      records = [];
    const terms =
      [
        c.source.user + "@" + c.source.address,
        mode + " FTPS",
        c.source.ftps.server_name,
        c.source.ftps.ca_sha256,
        c.source.directory,
        c.workflow.definition.source.manifest,
        "Local collection only",
      ].join(" ") + textSuffix;
    const base = c.url + `/v1/tenants/${c.tenant}/partners/${c.partner}`;
    const replies = [
      { route: "/workflows/validate", method: "POST", data: preview },
      {
        route: "/workflow-collections/" + c.view.job.id,
        method: "GET",
        data: view,
      },
    ];
    const locator = (name) => ({
      getByRole: (_role, options) => locator(options.name),
      getByLabel: (label) => locator(label),
      waitFor: async () => {},
      fill: async (value) => {
        fields[name] = value;
      },
      selectOption: async (value) => {
        fields[name] = value;
      },
      innerText: async () => terms,
      click: async () => {
        // No mutation or worker button exists in this stand-in. The real
        // browser journey must remain a preview and exact read inspection.
        assert.ok(
          [
            "Collections",
            "Preview workflow definition",
            "Inspect collection " + c.view.job.id,
          ].includes(name),
        );
        clicked.push(name);
        if (name.startsWith("Inspect collection"))
          await writeFile(c.source_counter, JSON.stringify(counter(after)));
      },
    });
    const page = {
      getByRole: (_role, options) => locator(options.name),
      waitForResponse: async (predicate) => {
        const next = replies.shift();
        assert.ok(next);
        const response = {
          url: () => base + next.route,
          status: () => 200,
          json: async () => next.data,
          text: async () => JSON.stringify(next.data),
          request: () => ({
            method: () => next.method,
            postDataJSON: () =>
              next.method === "POST"
                ? { definition: c.workflow.definition }
                : null,
          }),
        };
        assert.ok(predicate(response));
        return response;
      },
    };
    await qualifyFTPSCollectionMetadata(
      page,
      c,
      async (name) => {
        audits.push(name);
      },
      (name) => records.push(name),
      observe,
    );
    const result = JSON.parse(
      await readFile(
        join(directory, "ftps-collection-browser-result.json"),
        "utf8",
      ),
    );
    return { result, clicked, fields, audits, records };
  } finally {
    await rm(directory, { recursive: true });
  }
}

test("both FTPS modes use exact metadata preview and queued read inspection without working a source", async () => {
  for (const mode of ["explicit", "implicit"]) {
    const r = await exercise({ mode });
    assert.equal(r.result.state, "passed");
    assert.equal(r.result.mode, mode);
    assert.equal(r.result.bytes_qualified, false);
    assert.equal(r.result.source_work_performed, false);
    assert.equal(r.result.source_counter_before.accepted_connections, 0);
    assert.equal(r.result.source_counter_after.accepted_connections, 0);
    assert.deepEqual(r.audits, ftpsCollectionMetadataAudits);
    assert.equal(r.clicked.length, 3);
    assert.equal(
      r.fields["Maximum files per batch"],
      String(r.result.workflow_preview.definition.source.max_files),
    );
    assert.equal(r.records.length, 1);
  }
});

test("changed transport or registered reference fails before it can become browser authority", async () => {
  for (const change of [
    (c) => {
      c.source.protocol = "sftp";
    },
    (c) => {
      c.workflow.definition.source.kind = "sftp.collect";
    },
    (c) => {
      c.workflow.definition.source.connection.hash = "e".repeat(64);
    },
  ])
    await assert.rejects(exercise({ change }));
});

test("server preview cannot substitute TLS proof, acquire authority or a different source", async () => {
  for (const change of [
    (_c, p) => {
      p.collection.connection.ftps.server_name = "other.invalid";
    },
    (_c, p) => {
      p.external_contact = true;
    },
    (_c, p) => {
      p.definition.source.connection.version++;
    },
    (_c, p) => {
      p.effects = [{ recipient: "unreviewed" }];
    },
  ])
    await assert.rejects(exercise({ change }));
});

test("acquired bytes or claimed business acceptance cannot pass a metadata-only inspection", async () => {
  for (const change of [
    (c, _p, v) => {
      c.view.job.attempts = v.job.attempts = 1;
    },
    (c, _p, v) => {
      c.view.job.captured = v.job.captured = true;
    },
    (c, _p, v) => {
      c.view.business_acceptance = v.business_acceptance = "accepted";
    },
  ])
    await assert.rejects(exercise({ change }));
});

test("any source contact or leaked private reference refuses the read-only browser evidence", async () => {
  for (const options of [
    { before: 1 },
    { after: 1 },
    { textSuffix: " /private-freightctl-fixture/credential" },
    { textSuffix: " password_reference=/private/credential" },
    { textSuffix: " ca_reference=/private/cert.pem" },
    { textSuffix: " Pinned source host SHA256:invented" },
  ])
    await assert.rejects(exercise(options));
});

test("actual driver failure emits only a bounded fixed stage and source location", async () => {
  const seen = [];
  await assert.rejects(
    exercise({
      change: (_c, preview) => {
        preview.effects = [{ recipient: "private-evidence-canary" }];
      },
      observe: (value) => seen.push(value),
    }),
  );
  const failure = seen.find(
    (v) => v.kind === "ftps-collection-browser-failure",
  );
  assert.equal(failure.stage, "preview-effects");
  assert.equal(failure.error_kind, "assertion");
  assert.equal(failure.source_file, "driver");
  assert.ok(failure.source_line > 0 && failure.source_line <= 4000);
  assert.ok(seen.some((v) => v.kind === "ftps-collection-browser-progress"));
  assert.ok(!JSON.stringify(seen).includes("private-evidence-canary"));
});

test("diagnostic emitter cannot publish exception prose, paths or arbitrary mode/stage values", () => {
  const c = {
    collection_phase: "ftps-metadata",
    source: { ftps: { mode: "explicit" } },
  };
  for (const name of [
    "AssertionError",
    "TimeoutError",
    "SyntaxError",
    "private-evidence-canary",
    "constructor",
    "__proto__",
  ]) {
    const value = ftpsCollectionBrowserObservation(c, "preview-visible", {
      name,
      message: "private-evidence-canary",
      stack:
        "private-evidence-canary\n at /private/source/ftps-collection-browser.mjs:203:8",
    });
    assert.equal(value.source_line, 203);
    assert.equal(value.source_file, "driver");
    assert.ok(
      ["assertion", "timeout", "syntax", "other"].includes(value.error_kind),
    );
    assert.ok(!JSON.stringify(value).includes("private-evidence-canary"));
    assert.ok(!JSON.stringify(value).includes("/private/"));
  }
  assert.equal(
    ftpsCollectionBrowserObservation(c, "private-evidence-canary"),
    null,
  );
  assert.equal(
    ftpsCollectionBrowserObservation(
      { ...c, collection_phase: "create" },
      "definition",
    ),
    null,
  );
  assert.equal(
    ftpsCollectionBrowserObservation(
      { ...c, source: { ftps: { mode: "private-evidence-canary" } } },
      "definition",
    ),
    null,
  );
  assert.equal(
    new Set(ftpsCollectionBrowserStages).size,
    ftpsCollectionBrowserStages.length,
  );
});
