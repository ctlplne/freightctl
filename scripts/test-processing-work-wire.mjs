// Actual processing driver block; Page/wire stand-ins only, no Chrome or HTTP.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(
  new URL("processing-browser.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf(
  '  const outcome = page.getByRole("region", { name: "Processing run outcome" });',
);
const end = source.indexOf(
  '  assert.equal((await api("/files/" + file)).status, 409);',
  start,
);
assert.ok(
  start >= 0 && end > start,
  "actual processing work and held-output block",
);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction(
  "page",
  "button",
  "dialog",
  "assert",
  "c",
  "prefix",
  "nativeWireResponse",
  "nativeWireObservation",
  "let run, file;\n" + source.slice(start, end) + "\nreturn { run, file };",
);

async function replay(options = {}) {
  const c = { url: "https://127.0.0.1:9443" };
  const prefix =
    "/v1/tenants/10000000-1111-4111-8111-111111111111/partners/10000001-1111-4111-8111-111111111111";
  const run = "20000000-1111-4111-8111-111111111111";
  const file = "30000000-1111-4111-8111-111111111111";
  const target = c.url + prefix + "/workflow-runs/" + run + "/work";
  const marker = Symbol("original work response");
  let reviews = 0,
    confirms = 0,
    observations = 0;
  const outcome = {
    async waitFor() {},
    getByRole(role, criteria) {
      assert.equal(role, "heading");
      assert.deepEqual(criteria, { level: 2 });
      return {
        locator(selector) {
          assert.equal(selector, "code");
          return {
            async textContent() {
              return options.displayedRun ?? run;
            },
          };
        },
      };
    },
  };
  const confirmation = {
    async waitFor(criteria) {
      assert.deepEqual(criteria, { state: "hidden" });
    },
  };
  const page = {
    getByRole(role, criteria) {
      assert.equal(role, "region");
      assert.deepEqual(criteria, { name: "Processing run outcome" });
      return outcome;
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
  const button = (name, parent) => ({
    async click() {
      if (name === "Review working this run") {
        assert.equal(parent, outcome);
        reviews++;
      } else {
        assert.equal(name, "Confirm this exact action");
        assert.equal(parent, confirmation);
        confirms++;
      }
    },
  });
  const work = {
    status: {
      run: { id: options.returnedRun ?? run },
      processing: { output_file_id: file, released: options.released ?? false },
      observed_reason: options.reason ?? "output_held",
      steps: options.steps ?? [],
    },
  };
  const result = await execute(
    page,
    button,
    () => confirmation,
    assert,
    c,
    prefix,
    async (actualPage, url, action, actual, label) => {
      assert.equal(actualPage, page);
      assert.equal(url, target);
      assert.equal(label, "processing-work");
      await action();
      observations++;
      const original = Object.freeze({
        status: options.status ?? 200,
        body: JSON.stringify(work),
      });
      const observed = {
        request: () => ({
          url: () => target,
          method: () => "POST",
          allHeaders: async () => ({
            "idempotency-key": options.key ?? "original-work-command",
          }),
          postDataBuffer: () => Buffer.from(options.body ?? ""),
        }),
        [marker]: original,
      };
      assert.equal(await actual(observed, label, target), original);
      return JSON.parse(original.body);
    },
    marker,
  );
  assert.deepEqual(result, { run, file });
  assert.equal(reviews, 1);
  assert.equal(confirms, 1);
  assert.equal(observations, 1);
}

test("actual processing work observes one original response without inspector body retention", async () => {
  await replay();
});
test("actual processing work retains exact run, empty command, held output and no-delivery assertions", async () => {
  for (const options of [
    { displayedRun: "invalid-run" },
    { returnedRun: "40000000-1111-4111-8111-111111111111" },
    { body: "{}" },
    { key: "invalid key" },
    { status: 409 },
    { released: true },
    { reason: "transformed_output_released" },
    { steps: [{}] },
  ])
    await assert.rejects(replay(options), { code: "ERR_ASSERTION" });
});
