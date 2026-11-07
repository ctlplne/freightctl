// Execute the actual driver block with Page/CDP stand-ins. No browser or server.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const source = await readFile(
  new URL("artifact-exchange-browser.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf('  phase = "sender-cancel";');
const end = source.indexOf('  phase = "sender-reload-recovery";', start);
assert.ok(start >= 0 && end > start, "original cancellation/recovery block");
const replayStart = source.indexOf('  phase = "sender-recover-cancel";', end);
const replayEnd = source.indexOf('  phase = "sender-history";', replayStart);
assert.ok(
  replayStart > end && replayEnd > replayStart,
  "original cancellation replay block",
);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const execute = new AsyncFunction(
  "sender",
  "recipient",
  "sent",
  "c",
  "origin",
  "assert",
  "createHash",
  "nativeWireResponse",
  "nativeWireObservation",
  "publicationResponse",
  "chmod",
  "readFile",
  "let phase, cancels = 0, recoveryRoundtrips = 0, offerRequests = 2;\n" +
    source.slice(start, end) +
    source.slice(replayStart, replayEnd) +
    "\nreturn {phase, cancels, recoveryRoundtrips};",
);

async function replay(options = {}) {
  const dir = await mkdtemp(join(tmpdir(), "freightctl-offer-recovery-"));
  const marker = Symbol("original wire observation");
  const origin = { origin: "https://127.0.0.1:25443" };
  const c = {
    tenant: "20000000-1111-4111-8111-111111111111",
    partner: "20000001-1111-4111-8111-111111111111",
    recovery: join(dir, "recovery.json"),
  };
  const sent = {
    exchange: {
      id: "10000000-1111-4111-8111-111111111111",
      request_hash: "a".repeat(64),
    },
  };
  const command = {
    schema_version: 1,
    exchange_id: sent.exchange.id,
    request_hash: sent.exchange.request_hash,
    operation: "cancel",
  };
  const reply = {
    exchange_id: sent.exchange.id,
    state: "canceled",
    replayed: false,
    command_hash: createHash("sha256")
      .update(JSON.stringify(command))
      .digest("hex"),
  };
  const offer = { schema_version: 1, immutable_request: "original-offer" };
  const wireKey = options.wireKey ?? "original-withdrawal";
  const saved = {
    server_origin: origin.origin,
    request_key: "original-publication",
    withdrawal_key: options.savedKey ?? wireKey,
    expected_exchange_id: sent.exchange.id,
    request: offer,
  };
  let clicks = 0,
    observations = 0,
    downloads = 0,
    replays = 0;
  const target = `${origin.origin}/v1/tenants/${c.tenant}/partners/${c.partner}/exchange-closures`;
  const page = {
    async waitForResponse(predicate) {
      const body = options.replayBody ?? JSON.stringify(command);
      const response = {
        url: () => target,
        status: () => 200,
        request: () => ({
          method: () => "POST",
          headers: () => ({ "idempotency-key": options.replayKey ?? wireKey }),
          postData: () => body,
          postDataBuffer: () => Buffer.from(body),
        }),
        json: async () => ({ ...reply, replayed: true }),
      };
      assert.equal(predicate(response), true);
      replays++;
      return response;
    },
    getByRole(role, criteria) {
      if (role === "status")
        return {
          filter({ hasText }) {
            assert.equal(hasText, "This offer was withdrawn.");
            return { async waitFor() {} };
          },
        };
      assert.equal(role, "button");
      assert.equal(criteria.exact, true);
      assert.ok(
        [
          "Withdraw this artifact offer or recover result",
          "Save offer recovery file",
        ].includes(criteria.name),
      );
      return {
        async click() {
          clicks++;
        },
      };
    },
    async waitForEvent(name) {
      assert.equal(name, "download");
      downloads++;
      return {
        suggestedFilename: () => "freightctl-offer-recovery.json",
        failure: async () => null,
        async saveAs(path) {
          assert.equal(path, c.recovery);
          await writeFile(path, JSON.stringify(saved), {
            mode: 0o600,
            flag: "wx",
          });
        },
      };
    },
  };
  const recipient = {
    page: {
      async evaluate(_fn, path) {
        assert.equal(
          path,
          `/v1/tenants/${c.tenant}/partners/${c.partner}/exchanges/${sent.exchange.id}/file`,
        );
        return 404;
      },
    },
  };
  async function wire(actualPage, url, action, actual, label) {
    assert.equal(actualPage, page);
    assert.equal(url, target);
    assert.equal(label, "sender-cancel");
    await action();
    observations++;
    const original = Object.freeze({
      status: 200,
      body: JSON.stringify(reply),
    });
    const intercepted = {
      request: () => ({
        url: () => target,
        method: () => "POST",
        allHeaders: async () => ({ "idempotency-key": wireKey }),
        postDataBuffer: () => Buffer.from(JSON.stringify(command)),
      }),
      [marker]: original,
    };
    assert.equal(await actual(intercepted, label, target), original);
    return JSON.parse(original.body);
  }
  try {
    const result = await execute(
      { page },
      recipient,
      sent,
      c,
      origin,
      assert,
      createHash,
      wire,
      marker,
      {
        request: () => ({
          headers: () => ({ "idempotency-key": "original-publication" }),
          postData: () => JSON.stringify(offer),
        }),
      },
      chmod,
      readFile,
    );
    assert.equal(result.phase, "sender-recover-cancel");
    assert.equal(result.cancels, 1);
    assert.equal(result.recoveryRoundtrips, 1);
    assert.equal(clicks, 3);
    assert.equal(observations, 1);
    assert.equal(downloads, 1);
    assert.equal(replays, 1);
    assert.equal((await stat(c.recovery)).mode & 0o777, 0o600);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("actual cancellation, saved recovery and replay retain the original withdrawal key and bytes", async () => {
  await replay();
});
test("actual recovery assertion refuses a substituted withdrawal key", async () => {
  await assert.rejects(replay({ savedKey: "another-withdrawal" }), {
    code: "ERR_ASSERTION",
  });
});
test("actual wire observation refuses an invalid original command key", async () => {
  await assert.rejects(replay({ wireKey: "invalid key" }), {
    code: "ERR_ASSERTION",
  });
});
test("actual cancellation replay refuses a substituted original key or request bytes", async () => {
  for (const options of [
    { replayKey: "another-withdrawal" },
    { replayBody: '{"operation":"cancel"}' },
    // Even equivalent JSON is not the exact original command byte sequence.
    {
      replayBody:
        " " +
        JSON.stringify({
          schema_version: 1,
          exchange_id: "10000000-1111-4111-8111-111111111111",
          request_hash: "a".repeat(64),
          operation: "cancel",
        }),
    },
  ])
    await assert.rejects(replay(options), { code: "ERR_ASSERTION" });
});
