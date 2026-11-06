import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const root = new URL("../../", import.meta.url);
const cases = JSON.parse(
  await readFile(
    new URL("web/tests/fixtures/artifact-policy-cases.json", root),
    "utf8",
  ),
);
const documents = [
  ...[
    "artifact-exchange",
    "artifact-onward",
    "artifact-collection-source",
    "received-artifact-copy",
    "artifact-evidence",
  ].map((name) => [name, "docs/api/" + name + ".openapi.json", 1]),
  ["mcp", "internal/api/mcp-tools.json", 8],
];
for (const [name, path, expected] of documents) {
  const document = JSON.parse(await readFile(new URL(path, root), "utf8"));
  test(
    name + " policy grammar matches domain cases under ECMAScript patterns",
    () => {
      assert.equal(cases.length, 62);
      let count = 0;
      function walk(value) {
        if (!value || typeof value !== "object") return;
        const schema = value.properties?.acceptance_policy;
        if (schema) {
          count++;
          assert.equal(schema.type, "string");
          // Exercise the actual ECMAScript pattern semantics used by JS clients.
          const pattern = new RegExp(schema.pattern, "u");
          for (const c of cases) {
            assert.equal(pattern.test(c.policy), c.valid, c.name);
          }
        }
        for (const child of Object.values(value)) walk(child);
      }
      walk(document);
      assert.equal(count, expected);
    },
  );
}
