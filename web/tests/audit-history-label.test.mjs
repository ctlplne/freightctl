// Static DOM-label stand-in. The actual served Chrome journey stays in CI.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { build } from "esbuild";

const compiled = await build({
  absWorkingDir: new URL("..", import.meta.url).pathname,
  entryPoints: ["src/audit-history.tsx"],
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
  jsx: "automatic",
  external: ["react", "react/jsx-runtime"],
});
// Keep the actual component's React hooks on the same server-renderer runtime.
const code = Buffer.from(compiled.outputFiles[0].contents)
  .toString()
  .replaceAll(
    'from "react"',
    `from "${new URL("../node_modules/react/index.js", import.meta.url).href}"`,
  )
  .replaceAll(
    'from "react/jsx-runtime"',
    `from "${new URL("../node_modules/react/jsx-runtime.js", import.meta.url).href}"`,
  );
const { AuditHistory } = await import(
  "data:text/javascript;base64," + Buffer.from(code).toString("base64")
);
const fixture = JSON.parse(
  await readFile(
    new URL("fixtures/audit-history.json", import.meta.url),
    "utf8",
  ),
);
const text = (html) =>
  html
    .replace(/<[^>]*>/g, "")
    .replace(/\s+/g, " ")
    .trim();
const attribute = (attrs, key) =>
  new RegExp(`(?:^|\\s)${key}="([^"]*)"`).exec(attrs)?.[1];

test("audit pagination has an exact stable label independent of its available options", () => {
  const session = {
    identity: structuredClone(fixture.reader),
    session: { id: "10000000-1111-4111-8111-111111111111" },
  };
  const html = renderToStaticMarkup(
    createElement(AuditHistory, {
      api: { session },
      session,
      refresh: 0,
      onError: assert.fail,
    }),
  );
  assert.match(html, /Operator audit history/);
  const labels = [...html.matchAll(/<label\b([^>]*)>([\s\S]*?)<\/label>/g)];
  const controls = [
    ...html.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/g),
  ].map((select) => {
    const id = attribute(select[1], "id");
    const label = labels.find(
      (label) =>
        (id && attribute(label[1], "for") === id) ||
        label[2].includes(select[0]),
    );
    return {
      name: attribute(select[1], "aria-label") ?? (label ? text(label[2]) : ""),
      options: select[2],
    };
  });
  const matches = controls.filter((c) => c.name === "Actions per page");
  assert.equal(
    matches.length,
    1,
    "exact native locator must identify one page-size control without option text",
  );
  assert.match(matches[0].options, /<option\b[^>]*value="1"/);
  assert.match(matches[0].options, /<option\b[^>]*value="100"/);
});
