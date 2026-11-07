// CDP/Page stand-ins only. Never launch a browser or make an HTTP request.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import {
  nativeWireObservation,
  nativeWireResponse,
  nativeUploadCompletionResponse,
} from "./browser-native-wire.mjs";

const target = "https://127.0.0.1:9443/v1/workflows/validate";
const token = "a".repeat(64),
  csrf = "b".repeat(64);
const originalTimeout = globalThis.setTimeout;

class Protocol extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = options;
    this.commands = [];
    this.requests = new Map();
    this.streams = new Map();
    this.detached = false;
  }
  async send(method, params = {}) {
    this.commands.push({ method, params });
    if (method === "Fetch.disable" && this.options.failDisable)
      throw new Error("private-cleanup-canary");
    if (method === "Fetch.takeResponseBodyAsStream") {
      const request = this.requests.get(params.requestId),
        handle = "stream-" + params.requestId;
      this.streams.set(handle, { request, offset: 0 });
      return { stream: handle };
    }
    if (method === "IO.read") {
      const stream = this.streams.get(params.handle),
        limit = this.options.chunkSize ?? 65536;
      const value = stream.request.body.subarray(
        stream.offset,
        stream.offset + Math.min(params.size, limit),
      );
      stream.offset += value.length;
      if (this.options.oversizedRead)
        return { data: "A".repeat(100000), base64Encoded: true, eof: true };
      if (this.options.emptyRead)
        return { data: "", base64Encoded: true, eof: false };
      return {
        data: value.toString(this.options.plainRead ? "utf8" : "base64"),
        base64Encoded: !this.options.plainRead,
        eof: stream.offset === stream.request.body.length,
      };
    }
    if (method === "IO.close") {
      this.streams.delete(params.handle);
      return {};
    }
    if (method === "Fetch.fulfillRequest" || method === "Fetch.failRequest") {
      const request = this.requests.get(params.requestId);
      if (request) {
        if (method === "Fetch.fulfillRequest") {
          assert.deepEqual(Buffer.from(params.body, "base64"), request.body);
          assert.equal(params.responseCode, 200);
          assert.ok(
            !params.responseHeaders.some((v) => v.name === "transfer-encoding"),
          );
        }
        request.finish(method);
      }
      return {};
    }
    if (method === "Network.getRequestPostData")
      return { postData: '{"definition":"original"}' };
    return {};
  }
  async detach() {
    this.detached = true;
  }
  dispatch(index = 0) {
    const id = "native-" + index,
      fetchId = "fetch-" + index;
    const body = Buffer.from(
      JSON.stringify({ ok: true, text: "λ", replayed: index > 0 }),
    );
    const request = {
      url: target,
      method: "POST",
      postData: '{"definition":"original"}',
      hasPostData: true,
    };
    if (this.options.method === "GET") {
      request.method = "GET";
      delete request.postData;
      delete request.hasPostData;
    }
    const network = { requestId: id, request };
    const headers = {
      ":authority": "127.0.0.1:9443",
      ":scheme": "https",
      ":method": request.method,
      ":path": "/v1/workflows/validate",
      Cookie: "__Host-freightctl-session=" + token,
      Origin: "https://127.0.0.1:9443",
      "Sec-Fetch-Site": "same-origin",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
      "Idempotency-Key": "original-saved-key",
    };
    if (request.method === "GET") {
      delete headers.Origin;
      delete headers["Content-Type"];
      delete headers["X-CSRF-Token"];
    }
    const extra = { requestId: id, headers };
    const paused = {
      requestId: fetchId,
      networkId: id,
      request: { ...request },
      responseStatusCode: 200,
      responseHeaders: [
        { name: "Content-Type", value: "application/json" },
        { name: "Transfer-Encoding", value: "chunked" },
      ],
    };
    this.options.change?.({ network, extra, paused });
    const done = new Promise((resolve) =>
      this.requests.set(fetchId, { body, finish: resolve }),
    );
    if (this.options.pausedFirst) this.emit("Fetch.requestPaused", paused);
    if (this.options.extraFirst)
      this.emit("Network.requestWillBeSentExtraInfo", extra);
    this.emit("Network.requestWillBeSent", network);
    if (!this.options.extraFirst && !this.options.missingExtra)
      this.emit("Network.requestWillBeSentExtraInfo", extra);
    if (!this.options.pausedFirst) this.emit("Fetch.requestPaused", paused);
    return done;
  }
}
function fixture(options) {
  const protocol = new Protocol(options),
    calls = [];
  const page = { context: () => ({ newCDPSession: async () => protocol }) };
  const actual = async (observed, label, url) => {
    assert.equal(url, target);
    assert.equal(observed.request().url(), target);
    const headers = await observed.request().allHeaders();
    assert.equal(headers["sec-fetch-site"], "same-origin");
    assert.equal(headers.cookie, "__Host-freightctl-session=" + token);
    assert.equal(
      headers["x-csrf-token"],
      observed.request().method() === "POST" ? csrf : undefined,
    );
    assert.ok(!Object.keys(headers).some((name) => name.startsWith(":")));
    const requestBytes = observed.request().postDataBuffer();
    assert.equal(
      requestBytes.toString(),
      observed.request().method() === "POST" ? '{"definition":"original"}' : "",
    );
    const native = observed[nativeWireObservation];
    calls.push({ label, headers, native });
    return {
      ...native,
      selection: requestBytes.length ? JSON.parse(requestBytes) : null,
      idempotency_key: headers["idempotency-key"],
    };
  };
  return { protocol, page, actual, calls };
}

const uploadScope = {
  origin: "https://127.0.0.1:9443",
  tenant: "10000000-1111-4111-8111-111111111111",
  partner: "10000001-1111-4111-8111-111111111111",
};
const checkpoint = "20000000-1111-4111-8111-111111111111";
const uploadPrefix = `${uploadScope.origin}/v1/tenants/${uploadScope.tenant}/partners/${uploadScope.partner}/uploads/`;
const uploadTarget = uploadPrefix + checkpoint + "/complete";
function uploadFixture(options = {}) {
  return fixture({
    ...options,
    change(events) {
      const { network, extra, paused } = events;
      network.request.url = uploadTarget;
      delete network.request.postData;
      delete network.request.hasPostData;
      paused.request = { ...network.request };
      extra.headers[":path"] = new URL(uploadTarget).pathname;
      delete extra.headers["Content-Type"];
      extra.headers["Content-Length"] = "0";
      extra.headers["Idempotency-Key"] = "browser-complete-" + checkpoint;
      options.change?.(events);
    },
  });
}

test("empty upload completion pins one scoped checkpoint and delivers only its original bounded response", async () => {
  for (const options of [
    {},
    { extraFirst: true },
    { pausedFirst: true },
    { chunkSize: 5 },
  ]) {
    const f = uploadFixture(options);
    let observations = 0;
    const result = await nativeUploadCompletionResponse(
      f.page,
      uploadScope,
      () => f.protocol.dispatch(),
      async (observed, label, url) => {
        observations++;
        assert.equal(label, "upload-complete");
        assert.equal(url, uploadTarget);
        assert.equal(observed.request().url(), uploadTarget);
        assert.equal(observed.request().method(), "POST");
        assert.equal(observed.request().postDataBuffer().length, 0);
        const headers = await observed.request().allHeaders();
        assert.equal(
          headers["idempotency-key"],
          "browser-complete-" + checkpoint,
        );
        assert.equal(headers["content-type"], undefined);
        assert.equal(headers.origin, uploadScope.origin);
        assert.equal(headers["x-csrf-token"], csrf);
        return observed[nativeWireObservation];
      },
      "upload-complete",
    );
    assert.deepEqual(result, { ok: true, text: "λ", replayed: false });
    assert.equal(observations, 1);
    assert.equal(
      f.protocol.commands.filter((c) => c.method === "Fetch.fulfillRequest")
        .length,
      1,
    );
    assert.equal(
      f.protocol.commands.find((c) => c.method === "Fetch.enable").params
        .patterns[0].urlPattern,
      uploadPrefix + "*/complete",
    );
    assert.ok(
      !f.protocol.commands.some((c) =>
        [
          "Network.getRequestPostData",
          "Network.replayXHR",
          "Network.setExtraHTTPHeaders",
        ].includes(c.method),
      ),
    );
    assert.equal(f.protocol.streams.size, 0);
    assert.ok(f.protocol.detached);
  }
});

test("empty completion profile refuses foreign scope, body, key and security evidence before delivery", async () => {
  for (const change of [
    (e) => {
      e.network.request.url = e.paused.request.url = uploadTarget + "?other=1";
    },
    (e) => {
      e.network.request.url = e.paused.request.url = uploadTarget + "#other";
    },
    (e) => {
      e.network.request.url = e.paused.request.url = uploadTarget.replace(
        uploadScope.partner,
        checkpoint,
      );
    },
    (e) => {
      e.network.request.url = e.paused.request.url = uploadTarget.replace(
        uploadScope.origin,
        "https://outside.invalid",
      );
    },
    (e) => {
      e.network.request.postData = e.paused.request.postData = "{}";
    },
    (e) => {
      e.network.request.hasPostData = true;
    },
    (e) => {
      e.paused.request.hasPostData = true;
    },
    (e) => {
      e.network.request.method = e.paused.request.method = "GET";
      e.extra.headers[":method"] = "GET";
    },
    (e) => {
      e.extra.headers["Idempotency-Key"] = "another-command";
    },
    (e) => {
      e.extra.headers["Content-Type"] = "application/json";
    },
    (e) => {
      e.extra.headers["Content-Length"] = "1";
    },
    (e) => {
      delete e.extra.headers["X-CSRF-Token"];
    },
    (e) => {
      e.extra.headers.Origin = "https://outside.invalid";
    },
    (e) => {
      e.extra.headers["Sec-Fetch-Site"] = "cross-site";
    },
    (e) => {
      e.extra.headers.Cookie = "";
    },
    (e) => {
      e.paused.responseStatusCode = 201;
    },
  ]) {
    const f = uploadFixture({ change });
    await assert.rejects(
      nativeUploadCompletionResponse(
        f.page,
        uploadScope,
        () => f.protocol.dispatch(),
        async () => {
          assert.fail("invalid completion reached recorder");
        },
        "upload-complete",
      ),
      /native browser wire observation failed/,
    );
    assert.ok(
      !f.protocol.commands.some((c) => c.method === "Fetch.fulfillRequest"),
    );
    assert.ok(f.protocol.detached);
  }
});

test("JSON workflow profile continues to refuse empty completion posts", async () => {
  const f = uploadFixture();
  await assert.rejects(
    nativeWireResponse(
      f.page,
      uploadTarget,
      () => f.protocol.dispatch(),
      async () => {
        assert.fail("empty POST passed JSON contract");
      },
      "upload-complete",
    ),
    /native browser wire observation failed/,
  );
  assert.ok(
    !f.protocol.commands.some((c) => c.method === "Fetch.fulfillRequest"),
  );
});

test("upload observation refuses a second scoped checkpoint instead of treating it as a retry", async () => {
  const second = "20000001-1111-4111-8111-111111111111";
  const f = uploadFixture({
    change(e) {
      if (e.network.requestId === "native-1") {
        e.network.request.url = e.paused.request.url = uploadTarget.replace(
          checkpoint,
          second,
        );
        e.extra.headers[":path"] = new URL(e.network.request.url).pathname;
        e.extra.headers["Idempotency-Key"] = "browser-complete-" + second;
      }
    },
  });
  await assert.rejects(
    nativeUploadCompletionResponse(
      f.page,
      uploadScope,
      () => Promise.all([f.protocol.dispatch(0), f.protocol.dispatch(1)]),
      async (observed) => observed[nativeWireObservation],
      "upload-complete",
    ),
    /native browser wire observation failed/,
  );
  assert.ok(f.protocol.detached);
  assert.ok(
    f.protocol.commands.filter((c) => c.method === "Fetch.fulfillRequest")
      .length <= 1,
  );
});

test("upload scope must be exact typed loopback origin and canonical participant before browser acquisition", async () => {
  let acquisitions = 0;
  const page = {
    context() {
      acquisitions++;
      assert.fail("invalid scope acquired browser");
    },
  };
  for (const scope of [
    { ...uploadScope, origin: uploadScope.origin + "/" },
    { ...uploadScope, origin: "https://outside.invalid" },
    { ...uploadScope, tenant: "not-an-id" },
    { ...uploadScope, partner: [uploadScope.partner] },
    { ...uploadScope, extra: "untrusted" },
  ])
    await assert.rejects(
      nativeUploadCompletionResponse(
        page,
        scope,
        async () => {},
        async () => {},
        "upload-complete",
      ),
    );
  assert.equal(acquisitions, 0);
});

test("native response binds either protocol event order to final headers and exact streamed bytes", async () => {
  for (const options of [
    {},
    { extraFirst: true },
    { pausedFirst: true },
    { chunkSize: 5 },
    { plainRead: true },
    { method: "GET" },
  ]) {
    const f = fixture(options);
    const result = await nativeWireResponse(
      f.page,
      target,
      () => f.protocol.dispatch(),
      f.actual,
      "preview",
    );
    assert.deepEqual(result, { ok: true, text: "λ", replayed: false });
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].label, "preview");
    assert.equal(f.protocol.streams.size, 0);
    assert.ok(f.protocol.detached);
    assert.equal(f.protocol.listenerCount("Fetch.requestPaused"), 0);
    assert.ok(
      f.protocol.commands
        .filter((v) => v.method === "IO.read")
        .every((v) => v.params.size <= 65536),
    );
    assert.ok(
      f.protocol.commands
        .find((v) => v.method === "Fetch.enable")
        .params.patterns.every((v) => v.requestStage === "Response"),
    );
    assert.ok(
      !f.protocol.commands.some((v) =>
        [
          "Network.replayXHR",
          "Fetch.continueRequest",
          "Network.setExtraHTTPHeaders",
        ].includes(v.method),
      ),
    );
  }
});

test("two native decisions drop only first completed response and retain the saved operation key", async () => {
  const f = fixture();
  const result = await nativeWireResponse(
    f.page,
    target,
    async () => {
      assert.equal(await f.protocol.dispatch(0), "Fetch.failRequest");
      assert.equal(await f.protocol.dispatch(1), "Fetch.fulfillRequest");
    },
    f.actual,
    "queue",
    { attempts: 2, dropFirst: true },
  );
  assert.equal(result.replayed, true);
  assert.deepEqual(
    f.calls.map((v) => v.label),
    ["queue-0", "queue-1"],
  );
  assert.equal(
    f.calls[0].headers["idempotency-key"],
    f.calls[1].headers["idempotency-key"],
  );
  assert.equal(
    f.protocol.commands.filter((v) => v.method === "Fetch.failRequest").length,
    1,
  );
  assert.equal(
    f.protocol.commands.filter((v) => v.method === "Fetch.fulfillRequest")
      .length,
    1,
  );
});

test("missing or foreign security fields, framing or detached request identity never get normalized", async () => {
  const changes = [
    ({ extra }) => delete extra.headers["Sec-Fetch-Site"],
    ({ extra }) => (extra.headers["Sec-Fetch-Site"] = "none"),
    ({ extra }) => (extra.headers["Sec-Fetch-Site"] = "cross-site"),
    ({ extra }) => (extra.headers.Authorization = "private-canary"),
    ({ extra }) => (extra.headers.Origin = "https://foreign.invalid"),
    ({ extra }) => (extra.headers["X-CSRF-Token"] = "wrong"),
    ({ extra }) => (extra.headers[":authority"] = "foreign.invalid"),
    ({ extra }) => (extra.headers.cookie = "duplicate-case"),
    ({ extra }) => (extra.headers.Host = "private-canary\r\nCookie: forged"),
    ({ paused }) => (paused.responseStatusCode = 302),
    ({ paused }) => (paused.request.method = "GET"),
    ({ paused }) => (paused.request.postData = '{"forged":true}'),
    ({ paused }) =>
      paused.responseHeaders.push({ name: "Content-Encoding", value: "gzip" }),
    ({ paused }) =>
      paused.responseHeaders.push({ name: "Content-Length", value: "999999" }),
    ({ paused }) =>
      paused.responseHeaders.push({ name: "Content-Length", value: "1" }),
    ({ paused }) =>
      paused.responseHeaders.push({
        name: "Set-Cookie",
        value: "private-canary",
      }),
    ({ paused }) =>
      paused.responseHeaders.push({
        name: "Content-Type",
        value: "application/json",
      }),
  ];
  for (const change of changes) {
    const f = fixture({ change });
    await assert.rejects(
      nativeWireResponse(
        f.page,
        target,
        () => f.protocol.dispatch(),
        f.actual,
        "preview",
      ),
      (error) => {
        assert.equal(error.message, "native browser wire observation failed");
        assert.ok(!String(error).includes("private-canary"));
        return true;
      },
    );
    assert.equal(f.calls.length, 0);
    assert.ok(f.protocol.detached);
    assert.ok(
      !f.protocol.commands.some((v) => v.method === "Fetch.fulfillRequest"),
    );
  }
});

test("oversized or empty nonfinal stream chunks fail with exact owned stream cleanup", async () => {
  for (const options of [{ oversizedRead: true }, { emptyRead: true }]) {
    const f = fixture(options);
    await assert.rejects(
      nativeWireResponse(
        f.page,
        target,
        () => f.protocol.dispatch(),
        f.actual,
        "preview",
      ),
    );
    assert.equal(f.calls.length, 0);
    assert.equal(f.protocol.streams.size, 0);
    assert.ok(f.protocol.detached);
    assert.equal(
      f.protocol.commands.filter((v) => v.method === "IO.close").length,
      1,
    );
  }
});

test("original recorded response cannot be changed by the recording callback", async () => {
  const f = fixture();
  await assert.rejects(
    nativeWireResponse(
      f.page,
      target,
      () => f.protocol.dispatch(),
      async () => ({ status: 200, body: '{"forged":true}' }),
      "preview",
    ),
  );
  assert.ok(
    !f.protocol.commands.some((v) => v.method === "Fetch.fulfillRequest"),
  );
  assert.ok(f.protocol.detached);
});

test("a cleanup RPC failure still detaches the owned session and cannot qualify the result", async () => {
  const f = fixture({ failDisable: true });
  await assert.rejects(
    nativeWireResponse(
      f.page,
      target,
      () => f.protocol.dispatch(),
      f.actual,
      "preview",
    ),
    (error) => {
      assert.equal(error.freightctlWirePhase, "cleanup");
      assert.ok(!String(error).includes("private-cleanup-canary"));
      return true;
    },
  );
  assert.ok(f.protocol.detached);
});

test("foreign targets and arbitrary attempt budgets refuse before acquiring a browser session", async () => {
  let acquired = 0;
  const page = {
    context: () => {
      acquired += 1;
      throw new Error("must not acquire");
    },
  };
  for (const url of [
    "http://127.0.0.1:9443/v1/test",
    "https://foreign.invalid/v1/test",
    "https://user:password@127.0.0.1/v1/test",
  ])
    await assert.rejects(
      nativeWireResponse(
        page,
        url,
        () => {},
        () => {},
        "preview",
      ),
    );
  await assert.rejects(
    nativeWireResponse(
      page,
      target,
      () => {},
      () => {},
      "preview",
      { attempts: 3 },
    ),
  );
  assert.equal(acquired, 0);
});

test("missing final network headers time out without a retry, invented headers or private errors", async (t) => {
  const delays = [];
  t.mock.method(globalThis, "setTimeout", (callback, milliseconds) => {
    delays.push(milliseconds);
    return originalTimeout(callback, 5);
  });
  const f = fixture({ missingExtra: true });
  await assert.rejects(
    nativeWireResponse(
      f.page,
      target,
      () => f.protocol.dispatch(),
      f.actual,
      "preview",
    ),
  );
  assert.equal(f.calls.length, 0);
  assert.equal(f.protocol.requests.size, 1);
  assert.ok(f.protocol.detached);
  assert.deepEqual(delays, [15000, 3000, 12000, 5000]);
});
