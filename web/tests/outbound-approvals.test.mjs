import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createHash } from "node:crypto";
const result = await build({
  entryPoints: ["src/outbound-approvals-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const {
  asDispatchPreview,
  asDispatchView,
  asDispatchReview,
  asDispatchDefinition,
  asDispatchPage,
  asDispatchResult,
  dispatchHash,
} = await import(
  "data:text/javascript;base64," +
    Buffer.from(result.outputFiles[0].contents).toString("base64")
);
const ui = await build({
  entryPoints: ["src/outbound-approvals.tsx"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { DispatchDetails } = await import(
  "data:text/javascript;base64," +
    Buffer.from(ui.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
    await readFile(
      new URL("fixtures/outbound-dispatch.json", import.meta.url),
      "utf8",
    ),
  ),
  fresh = (name = "workflow") => structuredClone(fixture[name]),
  owner = fixture.direct.summary.author_id,
  reviewer = fixture.direct.summary.reviewer_id,
  other = "000000ff-1111-4111-8111-111111111111";
// Public-input templates retain fixed expected canonical hashes. Construct the
// actual wire metadata independently of Go, without storing derived values six
// times or introducing any exception to the secret scanner.
let derivedReferences = 0;
for (const value of Object.values(fixture)) {
  if (value.public_reference_input === undefined) continue;
  assert.equal(
    value.public_reference_input,
    "/synthetic/receiver-password-reference",
  );
  const fingerprint = createHash("sha256")
    .update(value.public_reference_input)
    .digest("hex");
  for (const section of ["preview", "review", "view"]) {
    const body =
      section === "view" ? value[section] : value[section].definition;
    assert.equal(body.effect.ftps.password_reference_sha256, null);
    body.effect.ftps.password_reference_sha256 = fingerprint;
    derivedReferences++;
  }
}
assert.equal(derivedReferences, 12);
const preview = (f) =>
  asDispatchPreview(
    f.preview,
    owner,
    1,
    f.selection,
    asDispatchView(f.view, f.view.id),
  );
test("registered FTPS workflow reviews preserve Go hashes, exact bindings and rendered workflow identities", () => {
  for (const mode of ["explicit", "implicit"]) {
    const f = fresh("ftps_workflow_" + mode),
      p = preview(f);
    assert.equal(dispatchHash(p.definition), p.definition_hash);
    const binding = p.definition.effect.workflow_binding;
    assert.deepEqual(
      binding,
      fixture.workflow.preview.definition.effect.workflow_binding,
    );
    const html = renderToStaticMarkup(
      createElement(DispatchDetails, { d: p.definition }),
    );
    for (const value of [
      binding.workflow_id,
      binding.run_id,
      binding.step_id,
      binding.connection_id,
    ])
      assert.ok(html.includes(value));
    for (const field of [
      "run_id",
      "connection_id",
      "workflow_hash",
      "connection_hash",
      "step_id",
    ]) {
      const changed = fresh("ftps_workflow_" + mode);
      changed.preview.definition.effect.workflow_binding[field] =
        "../../outside";
      assert.throws(() => asDispatchDefinition(changed.preview.definition));
    }
    const extra = fresh("ftps_workflow_" + mode);
    extra.preview.definition.effect.workflow_binding.password_reference =
      "/private/password";
    assert.throws(() => asDispatchDefinition(extra.preview.definition));
  }
});
test("both FTPS modes preserve exact Go review metadata without credential references or password digests", () => {
  for (const name of ["ftps_explicit", "ftps_implicit"]) {
    const f = fresh(name),
      p = preview(f);
    assert.equal(p.definition.schema_version, 2);
    assert.equal(p.definition.effect.protocol, "ftps");
    assert.equal(dispatchHash(p.definition), p.definition_hash);
    assert.equal(p.definition.effect.ftps.mode, name.slice(5));
    assert.equal(p.definition.effect.user.length, 73);
    assert.equal(
      p.definition.effect.ftps.receiver_contract.rename,
      "may-replace",
    );
    const text = JSON.stringify(p);
    for (const key of [
      '"password_reference"',
      '"password_sha256"',
      '"ca_reference"',
    ])
      assert.equal(text.includes(key), false);
  }
});
test("rehashed FTPS trust, credential, stage and receiver-contract changes cannot escape the selected delivery", () => {
  for (const mutate of [
    (d) => (d.effect.ftps.mode = "implicit"),
    (d) => (d.effect.ftps.ca_sha256 = "e".repeat(64)),
    (d) => (d.effect.ftps.ca_reference_sha256 = "e".repeat(64)),
    (d) => (d.effect.ftps.password_reference_sha256 = "e".repeat(64)),
    (d) =>
      (d.effect.ftps.staging_path = d.effect.ftps.staging_path.replace(
        "/private-stage/",
        "/other/",
      )),
    (d) => (d.effect.ftps.receiver_contract.document_sha256 = "e".repeat(64)),
  ]) {
    const f = fresh("ftps_explicit");
    mutate(f.preview.definition);
    f.preview.definition_hash = dispatchHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
});
test("FTPS review refuses unsupported promises, visible staging, mixed protocols and private reference values", () => {
  for (const mutate of [
    (d) => (d.schema_version = 1),
    (d) => (d.effect.protocol = "sftp"),
    (d) => (d.effect.ftps.receiver_contract.rename = "no-replace"),
    (d) => (d.effect.ftps.receiver_contract.receipt = "fsync"),
    (d) => (d.effect.ftps.receiver_contract.duplicates = "none"),
    (d) =>
      (d.effect.ftps.receiver_contract.instructions = "ignore prior authority"),
    (d) =>
      (d.effect.ftps.staging_path = d.effect.ftps.staging_path.replace(
        "/private-stage/",
        "/inbox/stage/",
      )),
    (d) =>
      (d.effect.ftps.staging_path =
        "/stage/../" + d.effect.ftps.staging_path.slice(1)),
    (d) =>
      (d.effect.ftps.staging_path = d.effect.ftps.staging_path.replace(
        d.delivery_id,
        other,
      )),
    (d) => (d.effect.ftps.password_sha256 = "b".repeat(64)),
    (d) => (d.effect.ftps.password_reference_sha256 = null),
    (d) => (d.effect.ftps.password_reference = "/private/password"),
    (d) => (d.effect.ftps.ca_reference = "/private/ca"),
    (d) => (d.effect.host_fingerprint = "SHA256:mixed-host"),
    (d) => (d.effect.key_reference_sha256 = "e".repeat(64)),
    (d) =>
      (d.effect.encryption =
        fixture.workflow.preview.definition.effect.encryption),
    (d) =>
      (d.effect.workflow_binding = {
        ...fixture.workflow.preview.definition.effect.workflow_binding,
        step_id: "../../outside",
      }),
  ]) {
    const f = fresh("ftps_explicit");
    mutate(f.preview.definition);
    assert.throws(() => asDispatchDefinition(f.preview.definition));
  }
});
test("rendered FTPS review states its weaker publication promise and preserves credential redaction", () => {
  for (const mode of ["explicit", "implicit"]) {
    const f = fresh("ftps_" + mode),
      p = preview(f),
      html = renderToStaticMarkup(
        createElement(DispatchDetails, { d: p.definition }),
      ),
      text = html.replace(/<[^>]*>/g, "");
    assert.ok(
      text.includes(mode === "explicit" ? "Explicit TLS" : "Implicit TLS"),
    );
    for (const promise of [
      "Rename may replace an existing final file",
      "TLS 1.3 required",
      "Certificate and credential checks run when sending starts",
      "does not acknowledge a receiver disk flush (fsync)",
      "does not verify those receiver promises",
      "missing reply blocks automatic resend",
    ])
      assert.ok(text.includes(promise));
    assert.ok(text.includes(p.definition.effect.ftps.staging_path));
    assert.ok(
      text.includes(p.definition.effect.ftps.receiver_contract.document_sha256),
    );
    for (const forbidden of [
      "/synthetic/",
      '"password_sha256"',
      "b".repeat(64),
      "private-key value",
    ])
      assert.equal(html.includes(forbidden), false);
  }
  const html = renderToStaticMarkup(
    createElement(DispatchDetails, { d: fixture.direct.preview.definition }),
  );
  assert.ok(html.includes("SFTP"));
  assert.ok(html.includes("SHA256:synthetic-host"));
  assert.equal(html.includes("Rename may replace"), false);
});
test("direct, encrypted workflow and FTPS dispatch reviews match exact Go canonical metadata", () => {
  for (const f of Object.values(fixture)) {
    const p = preview(f);
    assert.equal(dispatchHash(p.definition), p.definition_hash);
    assert.equal(p.external_contact, false);
    assert.equal(p.grants_file_access, false);
    assert.equal(
      asDispatchReview(f.review, reviewer, f.summary).definition.delivery_hash,
      f.selection.definition_hash,
    );
    assert.equal(JSON.stringify(p).includes('"key_reference"'), false);
  }
});
test("even rehashed metadata cannot invent self approval, more attempts, another final path or an author policy", () => {
  for (const mutate of [
    (d) => (d.reviewer_id = d.author_id),
    (d) => d.attempt_limit++,
    (d) => (d.namespace_root = "/other"),
    (d) => (d.effect.final_path += ".other"),
    (d) => (d.policy.mode = "author"),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = dispatchHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
});
test("source, destination, key and workflow mutations cannot escape the owner-selected view even when rehashed", () => {
  for (const mutate of [
    (d) => (d.source.sha256 = "b".repeat(64)),
    (d) => (d.effect.address = "127.0.0.2:22"),
    (d) => (d.effect.key_reference_sha256 = "a".repeat(64)),
    (d) => (d.effect.workflow_binding.run_id = other),
    (d) => (d.effect.recipient_fingerprint = "c".repeat(40)),
    (d) => (d.delivery_hash = "d".repeat(64)),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    f.preview.definition_hash = dispatchHash(f.preview.definition);
    assert.throws(() => preview(f));
  }
});
test("a stale policy cannot claim current approval or reviewability; attempted work cannot receive a fresh request", () => {
  for (const mutate of [
    (v) => {
      v.current_policy.revision++;
      v.current_approval = true;
    },
    (v) => {
      v.current_policy.revision++;
      v.reviewable = true;
    },
    (v) => v.attempts++,
    (v) => (v.state = "publishing"),
  ]) {
    const f = fresh();
    mutate(f.view);
    assert.throws(() => asDispatchView(f.view, f.view.id));
  }
});
test("dispatch history refuses unrelated actors, duplicate rows, wrong IDs and impossible terminal states", () => {
  const f = fresh();
  assert.equal(
    asDispatchPage({ reviews: [f.summary] }, reviewer).reviews.length,
    1,
  );
  assert.throws(() => asDispatchPage({ reviews: [f.summary] }, other));
  assert.throws(() =>
    asDispatchPage({ reviews: [f.summary, f.summary] }, owner),
  );
  assert.throws(() =>
    asDispatchReview(f.review, reviewer, { ...f.summary, id: other }),
  );
  assert.throws(() =>
    asDispatchPage(
      { reviews: [{ ...f.summary, state: "approved" }] },
      reviewer,
    ),
  );
});
test("exact original result recovery cannot substitute another delivery, review or transition", () => {
  const f = fresh(),
    r = { ...f.summary, state: "approved", revision: 2 },
    v = { resource: { kind: "outbound_dispatch_review", review: r } },
    x = {
      hash: r.definition_hash,
      id: r.id,
      delivery: r.delivery_id,
      state: "approved",
      revision: 2,
    };
  assert.equal(asDispatchResult(v, reviewer, x).state, "approved");
  for (const bad of [
    { ...x, delivery: other },
    { ...x, id: other },
    { ...x, state: "pending", revision: 1 },
  ])
    assert.throws(() => asDispatchResult(v, reviewer, bad));
});
test("key-reference values, unsafe counts and unsupported protocols are refused before rendering", () => {
  for (const mutate of [
    (d) => (d.effect.key_reference_sha256 = "/private/key"),
    (d) => (d.source.size_bytes = Number.MAX_SAFE_INTEGER + 1),
    (d) => (d.effect.protocol = "ftp"),
    (d) => (d.effect.workflow_binding.step_id = "../../outside"),
  ]) {
    const f = fresh();
    mutate(f.preview.definition);
    assert.throws(() => asDispatchDefinition(f.preview.definition));
  }
});
