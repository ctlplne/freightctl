import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
const web = new URL("..", import.meta.url).pathname;
// Observe the existing internal parser without changing the production export
// surface or replacing any of its checks.
const source = await readFile(
  new URL("../src/collection-handoffs-types.ts", import.meta.url),
  "utf8",
);
const bundle = await build({
  stdin: {
    contents:
      source +
      "\nexport { effects as observedEffects, asCollectionConfiguration };",
    resolveDir: new URL("../src", import.meta.url).pathname,
    loader: "ts",
  },
  absWorkingDir: web,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const ui = await build({
  entryPoints: ["src/collection-routing.tsx"],
  absWorkingDir: web,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { RoutingEffects } = await import(
  "data:text/javascript;base64," +
    Buffer.from(ui.outputFiles[0].contents).toString("base64")
);
const handoffUI = await build({
  jsx: "automatic",
  stdin: {
    contents:
      (await readFile(
        new URL("../src/collection-handoffs.tsx", import.meta.url),
        "utf8",
      )) + "\nexport { Effects as observedHandoffEffects };",
    resolveDir: new URL("../src", import.meta.url).pathname,
    loader: "tsx",
  },
  absWorkingDir: web,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { observedHandoffEffects } = await import(
  "data:text/javascript;base64," +
    Buffer.from(handoffUI.outputFiles[0].contents).toString("base64")
);
const fixtures = JSON.parse(
  await readFile(
    new URL("fixtures/ftps-handoff-effects.json", import.meta.url),
    "utf8",
  ),
);
const legacy = JSON.parse(
  await readFile(
    new URL("fixtures/collection-handoffs.json", import.meta.url),
    "utf8",
  ),
);
test("FTPS handoff wire metadata retains exact public TLS identity without invented SSH keys", () => {
  for (const f of fixtures.cases) {
    const result = p.observedEffects(
      f.handoff_effects,
      p.asCollectionConfiguration(f.workflow),
    );
    assert.deepEqual(result, f.handoff_effects);
    assert.equal(result[0].key_fingerprint, "");
    assert.equal(result[0].user, f.base_effects[0].user);
  }
});
test("routing review renders actual FTPS identity and receiver terms", () => {
  for (const f of fixtures.cases) {
    const effect = f.base_effects[0];
    for (const [component, effects] of [
      [RoutingEffects, f.base_effects],
      [observedHandoffEffects, f.handoff_effects],
    ]) {
      const text = renderToStaticMarkup(
        createElement(component, { effects }),
      ).replace(/<[^>]*>/g, "");
      for (const term of [
        effect.ftps.mode + " FTPS",
        effect.ftps.server_name,
        effect.ftps.ca_sha256,
        effect.ftps.receiver_contract.document_sha256,
        "may replace",
        "exact readback",
        "does not acknowledge receiver fsync or business acceptance",
        "missing reply blocks automatic resend",
      ])
        assert.ok(text.includes(term), term);
      assert.ok(!text.includes("SSH account"));
      assert.ok(!text.includes("password_reference"));
    }
  }
});
test("handoff metadata rejects SSH/TLS mixing, raw references and changed catalog connections", () => {
  for (const mutate of [
    (e) => (e.key_fingerprint = "SHA256:" + "A".repeat(43)),
    (e) => (e.host_fingerprint = "SHA256:" + "A".repeat(43)),
    (e) => delete e.protocol,
    (e) => (e.protocol = "ftp"),
    (e) => (e.ftps.password_reference = "/private/credential"),
    (e) => (e.connection.hash = "e".repeat(64)),
  ]) {
    const f = structuredClone(fixtures.cases[0]);
    mutate(f.handoff_effects[0]);
    assert.throws(() =>
      p.observedEffects(
        f.handoff_effects,
        p.asCollectionConfiguration(f.workflow),
      ),
    );
  }
});
test("existing real PostgreSQL SSH handoff wire metadata retains its original key identities", () => {
  assert.deepEqual(
    p.observedEffects(
      legacy.preview.source_effects,
      p.asCollectionConfiguration(legacy.preview.source_workflow),
    ),
    legacy.preview.source_effects,
  );
  assert.deepEqual(
    p.observedEffects(
      legacy.preview.effects,
      p.asCollectionConfiguration(legacy.preview.workflow),
    ),
    legacy.preview.effects,
  );
});
