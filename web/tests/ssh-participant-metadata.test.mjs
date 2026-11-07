import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";

const built = await build({
  absWorkingDir: new URL("..", import.meta.url).pathname,
  stdin: {
    contents:
      'export { asCollectionConnection } from "./collections-types"; export { asProbeConnection } from "./onboarding-probes-types"; export { asTestEffect } from "./onboarding-tests-types";',
    resolveDir: new URL("../src", import.meta.url).pathname,
    loader: "ts",
  },
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(built.outputFiles[0].contents).toString("base64")
);
const collections = JSON.parse(
  await readFile(new URL("fixtures/collections.json", import.meta.url), "utf8"),
);
const onboarding = JSON.parse(
  await readFile(
    new URL("fixtures/onboarding-test.json", import.meta.url),
    "utf8",
  ),
);
const original = collections.plain.preview.definition.source_connection;
const effect = onboarding.preview.definition.effect;
const participant =
  "10000000-1111-4111-8111-111111111111.10000001-1111-4111-8111-111111111111.10000002-1111-4111-8111-111111111111";
const readers = [
  (user) => p.asCollectionConnection({ ...original, user }),
  (user) => p.asProbeConnection({ ...original, user }),
  (user) => p.asTestEffect({ ...effect, user }),
];

test("collection and onboarding readers retain the existing canonical SSH participant name", () => {
  assert.equal(participant.length, 110);
  for (const parse of readers) {
    assert.equal(parse(participant).user, participant);
    assert.equal(parse("a".repeat(64)).user, "a".repeat(64));
  }
});
test("SSH participant compatibility retains the short-account bound and refuses malformed identities", () => {
  for (const parse of readers)
    for (const user of [
      "",
      "a".repeat(65),
      "a".repeat(110),
      participant + ".",
      participant.slice(1),
      participant.replace(".", "/"),
      "receiver\r\n",
      "réceiver",
    ]) {
      assert.throws(() => parse(user));
    }
});
