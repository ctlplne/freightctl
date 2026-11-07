// Actual decline driver block with Page/wire stand-ins; no browser or HTTP.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(
  new URL("artifact-exchange-browser.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf('  phase = "recipient-decline";');
const end = source.indexOf('  phase = "declined-retrieval";', start);
assert.ok(start >= 0 && end > start, "original decline/receipt block");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction(
  "recipient",
  "c",
  "origin",
  "assert",
  "createHash",
  "nativeWireResponse",
  "nativeWireObservation",
  "let phase, declines = 0;\n" +
    source.slice(start, end) +
    "\nreturn declines;",
);

async function replay(options = {}) {
  const origin = { origin: "https://127.0.0.1:9443" };
  const c = {
    tenant: "10000000-1111-4111-8111-111111111111",
    partner: "10000001-1111-4111-8111-111111111111",
    closure_exchange: "20000000-1111-4111-8111-111111111111",
    closure_request_hash: "a".repeat(64),
  };
  const target = `${origin.origin}/v1/tenants/${c.tenant}/partners/${c.partner}/exchange-closures`;
  const command = {
    schema_version: 1,
    exchange_id: c.closure_exchange,
    request_hash: c.closure_request_hash,
    operation: "decline",
  };
  const actualCommand = { ...command, ...options.command };
  const reply = {
    exchange_id: c.closure_exchange,
    state: "declined",
    replayed: false,
    event_id: "30000000-1111-4111-8111-111111111111",
    command_hash: createHash("sha256")
      .update(JSON.stringify(command))
      .digest("hex"),
    ...options.reply,
  };
  const marker = Symbol("original wire observation");
  let clicks = 0,
    observations = 0;
  const page = {
    getByRole(role, criteria) {
      if (role === "status")
        return {
          filter({ hasText }) {
            assert.equal(
              hasText,
              "Future retrieval through this view is disabled.",
            );
            return { async waitFor() {} };
          },
        };
      assert.equal(role, "button");
      assert.deepEqual(criteria, {
        name: "Confirm decline or recover result",
        exact: true,
      });
      return {
        async click() {
          clicks++;
        },
      };
    },
    async waitForResponse(predicate) {
      const response = {
        url: () => target,
        request: () => ({ method: () => "POST" }),
        status: () => 200,
        json: async () => {
          throw new Error(
            "controlled Chrome inspector response-body lookup unavailable",
          );
        },
      };
      assert.equal(predicate(response), true);
      return response;
    },
  };
  async function observe(actualPage, url, action, actual, label) {
    assert.equal(actualPage, page);
    assert.equal(url, target);
    assert.equal(label, "recipient-decline");
    await action();
    observations++;
    const original = Object.freeze({
      status: options.status ?? 200,
      body: JSON.stringify(reply),
    });
    const observed = {
      request: () => ({
        url: () => target,
        method: () => "POST",
        allHeaders: async () => ({
          "idempotency-key": options.key ?? "decline-original-command",
        }),
        postDataBuffer: () => Buffer.from(JSON.stringify(actualCommand)),
      }),
      [marker]: original,
    };
    assert.equal(await actual(observed, label, target), original);
    return JSON.parse(original.body);
  }
  const declines = await execute(
    { page },
    c,
    origin,
    assert,
    createHash,
    observe,
    marker,
  );
  assert.equal(declines, 1);
  assert.equal(clicks, 1);
  assert.equal(observations, 1);
}

test("actual recipient decline observes one original receipt when inspector body retention is unavailable", async () => {
  await replay();
});
test("actual decline retains exact recipient command and committed receipt assertions", async () => {
  for (const options of [
    { command: { operation: "cancel" } },
    { command: { exchange_id: "40000000-1111-4111-8111-111111111111" } },
    { command: { request_hash: "b".repeat(64) } },
    { key: "invalid key" },
    { status: 409 },
    { reply: { state: "available" } },
    { reply: { replayed: true } },
    { reply: { command_hash: "f".repeat(64) } },
    { reply: { event_id: "not-an-id" } },
  ])
    await assert.rejects(replay(options), { code: "ERR_ASSERTION" });
});
