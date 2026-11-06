import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";

const bundle = await build({
  entryPoints: ["src/intake-policy-types.ts"],
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
const fixtures = await Promise.all(
  [
    "intake-policy.json",
    "intake-policy-protected.json",
    "intake-policy-json-records.json",
    "intake-policy-fixed-width.json",
    "intake-policy-xml-records.json",
    "intake-policy-xlsx-records.json",
  ].map(async (name) =>
    JSON.parse(
      await readFile(new URL("fixtures/" + name, import.meta.url), "utf8"),
    ),
  ),
);
const view = (f) => ({
  id: "33333333-3333-4333-8333-333333333333",
  version: 1,
  definition: f.definition,
  definition_hash: f.definition_hash,
  state: "active",
  revision: 1,
});

test("XLSX review binds worksheet,date meaning and processing bounds with protected requirements", () => {
  const d = structuredClone(fixtures[5].definition);
  assert.deepEqual(p.intakeDefinition(d), d);
  const hash = p.intakeHash(d);
  for (const key of [
    "sheet",
    "date_mode",
    "max_parts",
    "max_directory_bytes",
    "max_part_bytes",
    "max_expanded_bytes",
    "max_expansion_ratio",
    "max_shared_strings",
    "max_shared_bytes",
  ]) {
    const changed = structuredClone(d);
    changed.xlsx[key] =
      key === "sheet"
        ? "Other"
        : key === "date_mode"
          ? "serial_1900"
          : changed.xlsx[key] - 1;
    assert.notEqual(p.intakeHash(changed), hash);
  }
  for (const change of [
    (v) => (v.xlsx.sheet = "bad/name"),
    (v) => (v.xlsx.sheet = "'quoted"),
    (v) => (v.xlsx.date_mode = "guess"),
    (v) => (v.xlsx.max_parts = 4097),
    (v) => (v.xlsx.max_directory_bytes = 0),
    (v) => (v.xlsx.max_part_bytes = v.xlsx.max_expanded_bytes + 1),
    (v) => (v.xlsx.max_shared_bytes = v.xlsx.max_expanded_bytes + 1),
    (v) => (v.xlsx.max_expansion_ratio = 10001),
    (v) => (v.xlsx.execute = true),
    (v) => (v.xml = { root: "r", record: "r", namespace: "" }),
    (v) => {
      v.kind = "csv";
      v.schema_version = 1;
    },
  ]) {
    const bad = structuredClone(d);
    change(bad);
    assert.throws(() => p.intakeDefinition(bad));
  }
  const csv = p.intakeFormat(d, "csv");
  assert.equal(csv.xlsx, undefined);
  assert.deepEqual(csv.signature, d.signature);
  assert.deepEqual(csv.scanner, d.scanner);
  const fresh = p.intakeFormat(csv, "xlsx_records");
  assert.equal(fresh.xlsx.sheet, "Records");
  assert.equal(fresh.xlsx.date_mode, "iso_text");
  assert.deepEqual(fresh.xlsx, d.xlsx);
  assert.deepEqual(p.intakeDefinition(fresh), fresh);
});

test("XML review binds root,record and literal namespace without losing protected controls", () => {
  const d = structuredClone(fixtures[4].definition);
  assert.deepEqual(p.intakeDefinition(d), d);
  const hash = p.intakeHash(d);
  d.xml.namespace = "urn:other";
  assert.notEqual(p.intakeHash(d), hash);
  for (const change of [
    (v) => (v.xml.root = "prefix:records"),
    (v) => (v.xml.record = ""),
    (v) => (v.xml.namespace = "http://www.w3.org/2000/xmlns/"),
    (v) => (v.xml.namespace = "urn:has space"),
    (v) => (v.xml.fetch_schema = true),
    (v) => (v.columns[0].name = "a:b"),
    (v) => (v.columns[0].width_bytes = 1),
    (v) => {
      v.schema_version = 2;
      v.kind = "json_records";
    },
  ]) {
    const bad = structuredClone(d);
    change(bad);
    assert.throws(() => p.intakeDefinition(bad));
  }
  const csv = p.intakeFormat(d, "csv");
  assert.equal(csv.xml, undefined);
  assert.deepEqual(csv.signature, d.signature);
  assert.deepEqual(csv.scanner, d.scanner);
  assert.deepEqual(p.intakeFormat(csv, "xml_records").xml, {
    root: "records",
    record: "record",
    namespace: "",
  });
});

test("fixed-width reviews bind byte widths and explicit padding with protected requirements", () => {
  const d = structuredClone(fixtures[1].definition);
  d.schema_version = 3;
  d.kind = "fixed_width";
  d.columns = d.columns.map((c) => ({
    ...c,
    width_bytes: c.max_bytes,
    padding: "none",
  }));
  assert.deepEqual(p.intakeDefinition(d), d);
  const original = p.intakeHash(d);
  d.columns[0].padding = "space_right";
  assert.notEqual(p.intakeHash(d), original);
  for (const change of [
    (v) => (v.columns[0].width_bytes = 0),
    (v) => (v.columns[0].width_bytes = v.max_record_bytes),
    (v) => (v.columns[0].width_bytes = v.columns[0].max_bytes - 1),
    (v) => (v.columns[0].padding = "trim"),
    (v) => {
      v.schema_version = 1;
      v.kind = "csv";
    },
    (v) => {
      v.schema_version = 2;
      v.kind = "json_records";
    },
  ]) {
    const invalid = structuredClone(d);
    change(invalid);
    assert.throws(() => p.intakeDefinition(invalid));
  }
  assert.deepEqual(d.signature, fixtures[1].definition.signature);
  assert.deepEqual(d.scanner, fixtures[1].definition.scanner);
  const csv = p.intakeFormat(d, "csv");
  assert.deepEqual(csv, fixtures[1].definition);
  assert.equal(p.intakeHash(csv), fixtures[1].definition_hash);
  const fixed = p.intakeFormat(csv, "fixed_width");
  assert.deepEqual(fixed.signature, csv.signature);
  assert.deepEqual(fixed.scanner, csv.scanner);
  assert.ok(
    fixed.columns.every(
      (c) => c.width_bytes === c.max_bytes && c.padding === "none",
    ),
  );
});

test("JSON record policies have a distinct schema/hash and preserve protected requirements", () => {
  const csv = structuredClone(fixtures[1].definition);
  const json = { ...csv, schema_version: 2, kind: "json_records" };
  assert.deepEqual(p.intakeDefinition(json), json);
  assert.notEqual(p.intakeHash(json), p.intakeHash(csv));
  assert.deepEqual(
    p.asIntakePolicy(
      view({ definition: json, definition_hash: p.intakeHash(json) }),
    ).definition,
    json,
  );
  for (const invalid of [
    { ...json, schema_version: 1 },
    { ...json, kind: "csv" },
    { ...json, kind: "json" },
    { ...json, schema_version: "2" },
  ])
    assert.throws(() => p.intakeDefinition(invalid));
});

test("CSV definitions match actual Go normalized hashes including escaped names and protected requirements", () => {
  for (const f of fixtures) {
    assert.equal(p.intakeHash(f.definition), f.definition_hash);
    assert.deepEqual(p.asIntakePolicy(view(f)).definition, f.definition);
  }
  assert.equal(p.asIntakePolicy(null), null);
});
test("CSV policy bounds, duplicate names and invalid decimal semantics fail before review", () => {
  for (const change of [
    (d) => (d.max_record_bytes = 63),
    (d) => (d.max_rows = 1000001),
    (d) => (d.timeout_seconds = 0),
    (d) => (d.columns[1].name = d.columns[0].name),
    (d) => (d.columns[1].scale = 13),
    (d) => (d.columns[0].precision = 1),
    (d) => (d.columns[0].max_bytes = d.max_record_bytes + 1),
    (d) => (d.columns[0].name = "account\nname"),
    (d) => (d.columns = []),
    (d) =>
      (d.columns = Array.from({ length: 128 }, (_, i) => ({
        name: String(i).padEnd(120, "x"),
        type: "text",
        required: true,
        max_bytes: 64,
      }))),
    (d) => (d.unrecognized_control = true),
  ]) {
    const d = structuredClone(fixtures[0].definition);
    change(d);
    assert.throws(() => p.intakeDefinition(d));
  }
});
test("edited limits retain signer/scanner bindings and cannot keep the old definition hash", () => {
  const f = structuredClone(fixtures[1]);
  f.definition.max_rows++;
  const d = p.intakeDefinition(f.definition);
  assert.deepEqual(d.signature, fixtures[1].definition.signature);
  assert.deepEqual(d.scanner, fixtures[1].definition.scanner);
  assert.notEqual(p.intakeHash(d), f.definition_hash);
  assert.throws(() => p.asIntakePolicy(view(f)));
});
test("changed or malformed server policy identities and references cannot become current review state", () => {
  for (const change of [
    (v) => (v.definition_hash = "f".repeat(64)),
    (v) => (v.revision = 0),
    (v) => (v.state = "unexpected"),
    (v) => (v.definition.signature.key.id = "wrong"),
    (v) => (v.definition.scanner.hash = "wrong"),
  ]) {
    const v = view(structuredClone(fixtures[1]));
    change(v);
    assert.throws(() => p.asIntakePolicy(v));
  }
});
