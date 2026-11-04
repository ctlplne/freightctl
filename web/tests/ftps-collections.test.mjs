import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";

const bundle = await build({
  entryPoints: ["src/collections-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const fixtures = JSON.parse(
  await readFile(
    new URL("fixtures/ftps-collections.json", import.meta.url),
    "utf8",
  ),
);
const fresh = (name = "explicit-local") => structuredClone(fixtures[name]);
const view = (f) =>
  p.asCollectionView(f.view, f.view.job.id, 3, f.preview.definition_hash);

test("Go FTPS source, mixed sender and encrypted sender metadata keeps exact canonical hashes", () => {
  for (const f of Object.values(fixtures)) {
    const workflow = p.asCollectionConfiguration(f.workflow);
    assert.equal(
      p.collectionWorkflowHash(workflow.definition),
      f.workflow.definition_hash,
    );
    const review = p.asCollectionWorkflowPreview(
      f.workflow_preview,
      workflow.definition,
    );
    assert.equal(review.collection.kind, "ftps.collect");
    assert.equal(review.collection.connection.protocol, "ftps");
    assert.equal(
      p.asCollectionPreview(f.preview, f.selection, 3, workflow)
        .definition_hash,
      f.preview.definition_hash,
    );
    const result = view(f);
    assert.equal(result.job.definition.source.kind, "ftps.collect");
    assert.equal(result.job.definition.source_connection.protocol, "ftps");
    assert.equal(result.business_acceptance, "unknown");
    for (let i = 0; i < workflow.definition.steps.length; i++) {
      assert.equal(
        result.job.definition.effects[i].protocol === "ftps",
        workflow.definition.steps[i].kind === "ftps.deliver",
      );
    }
  }
});

test("FTPS source and connection protocols cannot be mixed with SSH metadata or plaintext", () => {
  for (const mutate of [
    (d) => {
      delete d.source_connection.protocol;
    },
    (d) => {
      d.source_connection.protocol = "ftp";
    },
    (d) => {
      d.source.kind = "sftp.collect";
    },
    (d) => {
      d.source.kind = "ftp.collect";
    },
    (d) => {
      d.source_connection.host_fingerprint = "SHA256:" + "A".repeat(43);
    },
    (d) => {
      d.source_connection.key_fingerprint = "SHA256:" + "A".repeat(43);
    },
    (d) => {
      delete d.source_connection.ftps;
    },
  ]) {
    const f = fresh();
    mutate(f.view.job.definition);
    assert.throws(() => view(f));
  }
});

test("changed peer identity or receiver terms cannot retain the reviewed collection hash", () => {
  for (const mutate of [
    (d) => {
      d.source_connection.address = "127.0.0.1:2990";
    },
    (d) => {
      d.source_connection.user = "other";
    },
    (d) => {
      d.source_connection.ftps.mode = "implicit";
    },
    (d) => {
      d.source_connection.ftps.ca_sha256 = "e".repeat(64);
    },
    (d) => {
      d.source_connection.ftps.password_reference_sha256 = "e".repeat(64);
    },
    (d) => {
      d.source_connection.ftps.receiver_contract.document_sha256 = "e".repeat(
        64,
      );
    },
  ]) {
    const f = fresh();
    mutate(f.view.job.definition);
    assert.throws(() => view(f));
  }
});

test("FTPS metadata refuses raw references, invented receipts and overlapping private staging", () => {
  for (const mutate of [
    (c) => {
      c.password_reference = "/private/credential";
    },
    (c) => {
      c.ftps.password_reference = "/private/credential";
    },
    (c) => {
      c.ftps.ca_reference = "/private/ca";
    },
    (c) => {
      c.ftps.mode = "automatic";
    },
    (c) => {
      c.ftps.server_name = "https://other.invalid/";
    },
    (c) => {
      c.ftps.receiver_contract.receipt = "fsync";
    },
    (c) => {
      c.ftps.receiver_contract.business_acceptance = true;
    },
    (c) => {
      c.ftps.staging_directory = c.directory;
    },
    (c) => {
      c.ftps.staging_directory = c.directory + "/stage";
    },
    (c) => {
      c.ftps.staging_directory = "/";
    },
    (c) => {
      c.directory = c.ftps.staging_directory + "/files";
    },
    (c) => {
      c.ftps.staging_directory = "/../stage";
    },
  ]) {
    const c = fresh().preview.definition.source_connection;
    mutate(c);
    assert.throws(() => p.asCollectionConnection(c));
  }
});

test("FTPS outgoing catalog steps require their exact protocol-specific effect and recipient", () => {
  for (const mutate of [
    (f) => {
      delete f.workflow_preview.effects[0].protocol;
    },
    (f) => {
      f.workflow_preview.effects[0].host_fingerprint =
        "SHA256:" + "A".repeat(43);
    },
    (f) => {
      delete f.workflow_preview.effects[0].ftps;
    },
    (f) => {
      f.workflow_preview.effects[0].ftps.receiver_contract.rename = "exclusive";
    },
    (f) => {
      f.workflow_preview.effects[0].encryption.profile = "automatic";
    },
    (f) => {
      f.workflow_preview.effects[0].encryption.key.hash = "f".repeat(64);
    },
  ]) {
    const f = fresh("implicit-encrypted-ftps");
    mutate(f);
    assert.throws(() =>
      p.asCollectionWorkflowPreview(f.workflow_preview, f.workflow.definition),
    );
  }
});
