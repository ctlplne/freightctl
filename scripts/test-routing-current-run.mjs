// Execute the actual inspection loop with a delayed UI commit, without a browser.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(
  new URL("routing-browser.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf("    const runs = [];");
const end = source.indexOf("    await page.reload();", start);
assert.ok(start >= 0 && end > start, "original downstream inspection loop");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction(
  "view",
  "response",
  "selected",
  "previews",
  "routingAuthorization",
  "c",
  "audit",
  "region",
  "assert",
  source.slice(start, end) + "\nreturn runs;",
);

async function replay(options = {}) {
  const input = {
    run_id: "10000000-1111-4111-8111-111111111111",
    file_id: "20000000-1111-4111-8111-111111111111",
    source_name: "retained-input.txt",
  };
  const plan = { selected_steps: [], facts: { retain_local: true } };
  const authorization = { id: "30000000-1111-4111-8111-111111111111" };
  const c = { routing_target: { version: 2, definition_hash: "a".repeat(64) } };
  const r = {
    observed_state: "kept_local",
    run: {
      id: input.run_id,
      execution_plan: options.invalidPlan ? {} : plan,
      routing_authorization_id: authorization.id,
      workflow_version: c.routing_target.version,
      workflow_hash: c.routing_target.definition_hash,
    },
  };
  let clicked = 0,
    responses = 0,
    waits = 0,
    audits = 0;
  let rendered = {
    id: "40000000-1111-4111-8111-111111111111",
    state: "queued",
  };
  let finishRender;
  const render = new Promise((resolve) => {
    finishRender = resolve;
  });
  const selected = {
    getByRole(role, criteria) {
      assert.equal(role, "button");
      assert.deepEqual(criteria, {
        name: "Inspect downstream run for " + input.source_name,
        exact: true,
      });
      return {
        async click() {
          clicked++;
          // The run response resolves before the component's two context reads.
          setImmediate(() => {
            rendered = {
              id: options.displayedID ?? input.run_id,
              state: options.displayedState ?? "kept_local",
            };
            finishRender();
          });
        },
      };
    },
  };
  const displayed = {
    getByRole(role, criteria) {
      assert.equal(role, "heading");
      assert.deepEqual(criteria, {
        name: "Downstream run: kept_local",
        exact: true,
      });
      return {
        async waitFor() {
          waits++;
          await render;
          assert.equal(rendered.state, "kept_local", "displayed run state");
        },
      };
    },
    getByText(id, criteria) {
      assert.equal(id, input.run_id);
      assert.deepEqual(criteria, { exact: true });
      return {
        async waitFor() {
          waits++;
          await render;
          assert.equal(rendered.id, id, "displayed run identity");
        },
      };
    },
  };
  const region = {
    getByRole(role, criteria) {
      if (role === "region") {
        assert.deepEqual(criteria, {
          name: "Collected input downstream run",
          exact: true,
        });
        return displayed;
      }
      assert.equal(role, "button");
      assert.deepEqual(criteria, {
        name: "Review working next transfer step",
        exact: true,
      });
      return {
        async count() {
          return rendered.state !== "kept_local" || options.retainedButton
            ? 1
            : 0;
        },
      };
    },
  };
  const runs = await execute(
    { inputs: [input] },
    async (route, action) => {
      assert.equal(route, "/workflow-runs/" + input.run_id);
      responses++;
      await action();
      return r;
    },
    selected,
    [{ source: { id: input.file_id }, execution_plan: plan }],
    authorization,
    c,
    async (phase) => {
      assert.equal(phase, "routing-local-outcome");
      audits++;
    },
    region,
    assert,
  );
  assert.deepEqual(runs, [r]);
  assert.equal(clicked, 1);
  assert.equal(responses, 1);
  assert.equal(waits, 2);
  assert.equal(audits, 1);
}

test("actual routing inspection binds displayed run and state before checking local-only controls", async () => {
  await replay();
});
test("actual routing inspection refuses stale identity/state, a transfer button or changed plan", async () => {
  for (const options of [
    { displayedID: "50000000-1111-4111-8111-111111111111" },
    { displayedState: "queued" },
    { retainedButton: true },
    { invalidPlan: true },
  ])
    await assert.rejects(replay(options), { code: "ERR_ASSERTION" });
});
