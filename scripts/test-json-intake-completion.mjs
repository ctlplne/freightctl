// Actual driver fragment with Page/wire stand-ins; no Chrome or HTTP server.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(
  new URL("json-intake-browser.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf('  stage = "upload";');
const end = source.indexOf('  stage = "check";', start);
assert.ok(start >= 0 && end > start, "actual upload/held-receipt block");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction(
  "assert",
  "page",
  "button",
  "c",
  "policyPrefix",
  "api",
  "nativeUploadCompletionResponse",
  "nativeWireObservation",
  "let stage, file;\n" + source.slice(start, end) + "\nreturn file;",
);

async function replay(change = {}) {
  const marker = Symbol("original wire response");
  const id = "10000000-1111-4111-8111-111111111111";
  const c = {
    url: "https://127.0.0.1:9443",
    tenant: "20000000-1111-4111-8111-111111111111",
    partner: "20000001-1111-4111-8111-111111111111",
    source: "/fixture/input",
    hash: "a".repeat(64),
    sha256: "b".repeat(64),
    size: 123,
  };
  const policyPrefix = "intake-fixed-width-v1:";
  const accepted = {
    acceptance: "durable-held-pending-checks-and-release",
    file: {
      id: "30000000-1111-4111-8111-111111111111",
      policy: policyPrefix + c.hash,
    },
    upload: { id, expected_sha256: c.sha256, committed_offset: c.size },
  };
  change.mutate?.(accepted);
  const target = `${c.url}/v1/tenants/${c.tenant}/partners/${c.partner}/uploads/${id}/complete`;
  let starts = 0,
    observations = 0,
    reads = 0;
  const button = (name) => ({
    async click() {
      assert.ok(["Files", "Upload file", "Start upload"].includes(name));
      if (name === "Start upload") starts++;
    },
  });
  const page = {
    getByLabel(name) {
      return {
        async setInputFiles(value) {
          assert.equal(name, "File to send");
          assert.equal(value, c.source);
        },
        async fill(value) {
          assert.equal(name, "Destination path");
          assert.equal(value, "/browser-records.json");
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
  const observe = async (actualPage, scope, action, actual, label) => {
    assert.equal(actualPage, page);
    assert.deepEqual(scope, {
      origin: c.url,
      tenant: c.tenant,
      partner: c.partner,
    });
    assert.equal(label, "intake-upload-complete");
    await action();
    observations++;
    const original = Object.freeze({
      status: 200,
      body: JSON.stringify(accepted),
    });
    const observed = {
      request: () => ({
        url: () => target,
        method: () => "POST",
        allHeaders: async () => ({
          "idempotency-key": "browser-complete-" + id,
        }),
        postDataBuffer: () => Buffer.alloc(0),
      }),
      [marker]: original,
    };
    assert.equal(await actual(observed, label, target), original);
    return JSON.parse(original.body);
  };
  const file = await execute(
    assert,
    page,
    button,
    c,
    policyPrefix,
    async (path) => {
      assert.ok(path === "/files/" + accepted.file.id);
      reads++;
      return { status: 409 };
    },
    observe,
    marker,
  );
  assert.equal(file, accepted.file.id);
  assert.equal(starts, 1);
  assert.equal(observations, 1);
  assert.equal(reads, 2);
}

test("actual intake upload reads its one original completion when inspector body retention is unavailable", async () => {
  await replay();
});
test("actual intake upload retains exact upload identity, policy, digest, offset and held acceptance assertions", async () => {
  for (const mutate of [
    (r) => (r.upload.id = "40000000-1111-4111-8111-111111111111"),
    (r) => (r.file.policy = "another-policy"),
    (r) => (r.upload.expected_sha256 = "f".repeat(64)),
    (r) => r.upload.committed_offset++,
    (r) => (r.acceptance = "published"),
  ])
    await assert.rejects(replay({ mutate }), { code: "ERR_ASSERTION" });
});
