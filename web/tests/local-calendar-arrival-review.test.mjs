import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { renderToStaticMarkup } from "react-dom/server";
import { build } from "esbuild";
const built = await build({
  entryPoints: [
    new URL("../src/schedule-arrivals.tsx", import.meta.url).pathname,
  ],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const { ScheduledArrivalSource } = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/local-scheduled-arrivals.json", import.meta.url),
  ),
);
test("local scheduled arrival reviews the exact folder and configuration without empty remote identity fields", () => {
  const c = fixture.waiting.schedule.definition.collection;
  const html = renderToStaticMarkup(ScheduledArrivalSource({ c }));
  assert.ok(html.includes(c.source_connection.local.root_fingerprint));
  assert.ok(html.includes(c.source_connection.local.configuration_sha256));
  assert.ok(html.includes(c.source_connection.id));
  assert.match(html, /Read-only local source/);
  assert.doesNotMatch(html, /pinned host|<code><\/code>/);
  assert.match(html, /no forwarding or execution authority/);
});
