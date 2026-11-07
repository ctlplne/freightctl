// Qualification plumbing: original Chrome requests, bounded original responses.
// Never invent Sec-Fetch-Site, cookies, CSRF, operation keys or API responses.
import assert from "node:assert/strict";

export const nativeWireObservation = Symbol("freightctl-native-wire");
const BODY_MAX = 262144;
const REQUEST_MAX = 32768;
const HEADER_MAX = 16384;
const CHUNK = 65536;
const phases = new Set([
  "setup",
  "request",
  "headers",
  "response",
  "body",
  "record",
  "deliver",
  "action",
  "cleanup",
]);

function check(value) {
  assert.ok(value, "native browser wire evidence invalid");
}
function identifier(value) {
  check(typeof value === "string" && value.length > 0 && value.length <= 256);
  return value;
}
function boundedHeaders(value) {
  check(value && typeof value === "object" && !Array.isArray(value));
  const entries = Object.entries(value);
  check(entries.length <= 128);
  let bytes = 0;
  const result = {};
  for (const [name, body] of entries) {
    const key = name.toLowerCase();
    check(
      /^:?[a-z0-9-]+$/.test(key) &&
        !Object.hasOwn(result, key) &&
        typeof body === "string" &&
        !/[\x00-\x1f\x7f]/.test(body),
    );
    bytes += Buffer.byteLength(name) + Buffer.byteLength(body) + 4;
    check(bytes <= HEADER_MAX);
    result[key] = body;
  }
  return result;
}
function requestHeaders(raw, target, method, emptyCompletion) {
  const value = boundedHeaders(raw),
    url = new URL(target);
  const pseudo = {
    ":authority": url.host,
    ":method": method,
    ":path": url.pathname + url.search,
    ":scheme": "https",
  };
  for (const [name, body] of Object.entries(value)) {
    if (name.startsWith(":")) {
      check(Object.hasOwn(pseudo, name) && pseudo[name] === body);
      delete value[name]; // HTTP/2 framing, not an ordinary header field.
    }
  }
  check(!value.host || value.host === url.host);
  check(
    !Object.hasOwn(value, "authorization") &&
      typeof value.cookie === "string" &&
      value.cookie.length > 0,
  );
  check(value["sec-fetch-site"] === "same-origin");
  if (method === "POST") {
    check(
      value.origin === url.origin &&
        (emptyCompletion
          ? value["content-type"] === undefined &&
            (value["content-length"] === undefined ||
              value["content-length"] === "0")
          : value["content-type"] === "application/json") &&
        /^[0-9a-f]{64}$/.test(value["x-csrf-token"]),
    );
  } else check(value.origin === undefined || value.origin === url.origin);
  return value;
}
function responseHeaders(raw) {
  check(Array.isArray(raw) && raw.length <= 128);
  let bytes = 0;
  const result = [],
    seen = new Set();
  for (const item of raw) {
    check(
      item && typeof item.name === "string" && typeof item.value === "string",
    );
    const name = item.name.toLowerCase();
    check(
      /^[a-z0-9-]+$/.test(name) &&
        !seen.has(name) &&
        !/[\x00-\x1f\x7f]/.test(item.value),
    );
    seen.add(name);
    bytes += Buffer.byteLength(name) + Buffer.byteLength(item.value) + 4;
    check(bytes <= HEADER_MAX);
    result.push({ name, value: item.value });
  }
  const fields = Object.fromEntries(result.map((v) => [v.name, v.value]));
  check(/^application\/json(?:;|$)/i.test(fields["content-type"] ?? ""));
  check(
    fields["content-encoding"] === undefined ||
      fields["content-encoding"] === "identity",
  );
  check(fields["set-cookie"] === undefined); // Targeted workflow APIs never renew login.
  if (fields["content-length"] !== undefined)
    check(
      /^(?:0|[1-9][0-9]{0,5})$/.test(fields["content-length"]) &&
        Number(fields["content-length"]) <= BODY_MAX,
    );
  return {
    fields,
    headers: result.filter(
      (v) =>
        ![
          "connection",
          "transfer-encoding",
          "keep-alive",
          "proxy-connection",
        ].includes(v.name),
    ),
  };
}

export async function nativeWireResponse(
  page,
  target,
  action,
  actual,
  label,
  options = {},
) {
  return observeNativeResponse(
    page,
    target,
    action,
    actual,
    label,
    options,
    false,
  );
}

const canonicalID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

// Upload creation chooses the checkpoint UUID during the same user action.
// Pin exactly one original scoped completion, with its ordinary empty POST and
// checkpoint-derived key. This does not generalize the JSON workflow profile.
export async function nativeUploadCompletionResponse(
  page,
  scope,
  action,
  actual,
  label,
) {
  check(scope && typeof scope === "object" && !Array.isArray(scope));
  check(Object.keys(scope).sort().join(",") === "origin,partner,tenant");
  check(
    typeof scope.tenant === "string" &&
      typeof scope.partner === "string" &&
      canonicalID.test(scope.tenant) &&
      canonicalID.test(scope.partner),
  );
  const origin = new URL(scope.origin);
  check(
    origin.origin === scope.origin &&
      origin.protocol === "https:" &&
      origin.hostname === "127.0.0.1",
  );
  const prefix = `${scope.origin}/v1/tenants/${scope.tenant}/partners/${scope.partner}/uploads/`;
  return observeNativeResponse(page, prefix, action, actual, label, {}, true);
}

async function observeNativeResponse(
  page,
  target,
  action,
  actual,
  label,
  options,
  emptyCompletion,
) {
  const attempts = options.attempts ?? 1,
    dropFirst = options.dropFirst ?? false;
  check(
    (attempts === 1 && dropFirst === false) ||
      (attempts === 2 && dropFirst === true),
  );
  check(typeof label === "string" && /^[a-z0-9-]{1,128}$/.test(label));
  const url = new URL(target);
  check(
    url.protocol === "https:" &&
      url.hostname === "127.0.0.1" &&
      !url.username &&
      !url.password &&
      !url.hash,
  );
  let selectedTarget = emptyCompletion ? undefined : target;
  const matches = (value) => {
    if (!emptyCompletion) return value === target;
    if (
      typeof value !== "string" ||
      !value.startsWith(target) ||
      !value.endsWith("/complete")
    )
      return false;
    return canonicalID.test(value.slice(target.length, -"/complete".length));
  };
  const select = (value) => {
    check(
      matches(value) &&
        (selectedTarget === undefined || selectedTarget === value),
    );
    selectedTarget = value;
  };
  let phase = "setup",
    session,
    timer,
    active = true,
    processing = false,
    count = 0,
    queued = 0;
  let queue = Promise.resolve();
  const requests = new Map(),
    extras = new Map(),
    waiters = new Map(),
    paused = new Set(),
    streams = new Set(),
    used = new Set(),
    headersReceived = new Set(),
    requestTimers = new Map();
  let complete, fail;
  const completed = new Promise((resolve, reject) => {
    complete = resolve;
    fail = reject;
  });
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error("native browser wire deadline")),
      15000 * attempts,
    );
  });
  // Install a handler immediately: a failed setup must not leave a rejected
  // observation promise unhandled while the action has not started yet.
  completed.catch(() => {});
  deadline.catch(() => {});
  const send = (method, parameters = {}) =>
    Promise.race([session.send(method, parameters), deadline]);
  function available(id) {
    if (waiters.has(id) && requests.has(id) && extras.has(id))
      waiters.get(id)();
  }
  const onRequest = (event) => {
    if (!active || !matches(event.request?.url)) return;
    try {
      select(event.request.url);
      const id = identifier(event.requestId);
      check(
        !requests.has(id) &&
          requests.size < attempts &&
          !event.redirectResponse,
      );
      check(["GET", "POST"].includes(event.request.method));
      const timers = {
        // Conservatively bound the entire wait for response headers to the
        // old3second connection cap; this includes connection establishment.
        headers: headersReceived.has(id)
          ? undefined
          : setTimeout(
              () => fail(new Error("native response headers deadline")),
              3000,
            ),
        body: setTimeout(
          () => fail(new Error("native response body deadline")),
          12000,
        ),
      };
      requestTimers.set(id, timers);
      if (event.request.postData !== undefined)
        check(
          typeof event.request.postData === "string" &&
            Buffer.byteLength(event.request.postData) <= REQUEST_MAX,
        );
      requests.set(id, event.request);
      available(id);
    } catch {
      fail(new Error("native browser request evidence invalid"));
    }
  };
  const onExtra = (event) => {
    if (!active) return;
    try {
      const id = identifier(event.requestId);
      check(!extras.has(id) && extras.size < 64);
      extras.set(id, boundedHeaders(event.headers));
      available(id);
    } catch {
      fail(new Error("native browser header evidence invalid"));
    }
  };
  async function handle(event) {
    phase = "request";
    const fetchId = identifier(event.requestId),
      networkId = identifier(event.networkId);
    paused.add(fetchId);
    select(event.request?.url);
    check(
      active &&
        !processing &&
        !used.has(networkId) &&
        count < attempts &&
        event.request?.url === selectedTarget &&
        event.responseStatusCode === 200 &&
        !event.responseErrorReason,
    );
    processing = true;
    used.add(networkId);
    if (!requests.has(networkId) || !extras.has(networkId))
      await Promise.race([
        new Promise((resolve) => {
          waiters.set(networkId, resolve);
          available(networkId);
        }),
        deadline,
      ]);
    waiters.delete(networkId);
    const request = requests.get(networkId);
    check(
      request &&
        request.url === selectedTarget &&
        request.method === event.request.method,
    );
    phase = "headers";
    const headers = requestHeaders(
      extras.get(networkId),
      selectedTarget,
      request.method,
      emptyCompletion,
    );
    let post = request.postData;
    if (emptyCompletion) {
      check(
        request.method === "POST" &&
          !request.hasPostData &&
          !event.request.hasPostData &&
          (post === undefined || post === ""),
      );
      check(
        headers["idempotency-key"] ===
          "browser-complete-" + selectedTarget.split("/").at(-2),
      );
      post = "";
    } else if (request.method === "POST" && post === undefined) {
      if (!request.hasPostData) {
        check(
          !event.request.hasPostData &&
            (headers["content-length"] === undefined ||
              headers["content-length"] === "0"),
        );
        post = "";
      } else {
        post = (
          await send("Network.getRequestPostData", { requestId: networkId })
        ).postData;
      }
    }
    check(
      request.method === "GET"
        ? !post && !request.hasPostData
        : typeof post === "string" && Buffer.byteLength(post) <= REQUEST_MAX,
    );
    if (event.request.postData !== undefined)
      check(event.request.postData === post);
    const requestBytes = Buffer.from(post ?? "", "utf8");
    phase = "response";
    const response = responseHeaders(event.responseHeaders);
    phase = "body";
    const stream = identifier(
      (await send("Fetch.takeResponseBodyAsStream", { requestId: fetchId }))
        .stream,
    );
    streams.add(stream);
    let length = 0,
      reads = 0;
    const chunks = [];
    for (;;) {
      check(++reads <= 8192);
      const size = Math.min(CHUNK, BODY_MAX + 1 - length);
      check(size > 0);
      const part = await send("IO.read", { handle: stream, size });
      check(
        typeof part.data === "string" &&
          typeof part.eof === "boolean" &&
          (part.base64Encoded === undefined ||
            typeof part.base64Encoded === "boolean"),
      );
      check(Buffer.byteLength(part.data) <= Math.ceil(size / 3) * 4 + 4);
      const bytes = Buffer.from(
        part.data,
        part.base64Encoded ? "base64" : "utf8",
      );
      check(
        bytes.length <= size &&
          (!part.base64Encoded || bytes.toString("base64") === part.data),
      );
      length += bytes.length;
      check(length <= BODY_MAX && (bytes.length > 0 || part.eof));
      chunks.push(bytes);
      if (part.eof) break;
    }
    await send("IO.close", { handle: stream });
    streams.delete(stream);
    const timers = requestTimers.get(networkId);
    if (timers) {
      clearTimeout(timers.headers);
      clearTimeout(timers.body);
      requestTimers.delete(networkId);
    }
    const bytes = Buffer.concat(chunks, length);
    if (response.fields["content-length"] !== undefined)
      check(Number(response.fields["content-length"]) === length);
    const body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    JSON.parse(body);
    phase = "record";
    const intercepted = Object.freeze({
      request: () => ({
        url: () => selectedTarget,
        method: () => request.method,
        allHeaders: async () => ({ ...headers }),
        postDataBuffer: () => Buffer.from(requestBytes),
      }),
      [nativeWireObservation]: Object.freeze({ status: 200, body }),
    });
    const value = await actual(
      intercepted,
      attempts === 1 ? label : label + "-" + count,
      selectedTarget,
    );
    check(value.status === 200 && value.body === body);
    phase = "deliver";
    if (dropFirst && count === 0)
      await send("Fetch.failRequest", {
        requestId: fetchId,
        errorReason: "Aborted",
      });
    else
      await send("Fetch.fulfillRequest", {
        requestId: fetchId,
        responseCode: 200,
        responseHeaders: response.headers,
        body: bytes.toString("base64"),
      });
    paused.delete(fetchId);
    processing = false;
    count += 1;
    if (count === attempts) complete(value);
  }
  const onPaused = (event) => {
    if (!active) return;
    try {
      check(++queued <= attempts);
      paused.add(identifier(event.requestId));
      const networkId = identifier(event.networkId);
      headersReceived.add(networkId);
      clearTimeout(requestTimers.get(networkId)?.headers);
      // The browser can react before the previous CDP delivery RPC replies.
      // Hold at most the exact1/2 expected responses and process them in order.
      queue = queue.then(() => handle(event)).catch(fail);
    } catch {
      fail(new Error("native browser response count invalid"));
    }
  };
  let result, failure;
  try {
    session = await Promise.race([
      page.context().newCDPSession(page),
      deadline,
    ]);
    session.on("Network.requestWillBeSent", onRequest);
    session.on("Network.requestWillBeSentExtraInfo", onExtra);
    session.on("Fetch.requestPaused", onPaused);
    await send("Network.enable", {
      maxTotalBufferSize: 1048576,
      maxResourceBufferSize: BODY_MAX,
      maxPostDataSize: REQUEST_MAX,
    });
    await send("Fetch.enable", {
      patterns: [
        {
          urlPattern:
            target.replace(/[\\*?]/g, "\\$&") +
            (emptyCompletion ? "*/complete" : ""),
          requestStage: "Response",
        },
      ],
    });
    phase = "action";
    [result] = await Promise.race([
      Promise.all([completed, Promise.resolve().then(action)]),
      deadline,
    ]);
    check(count === attempts);
  } catch {
    failure = Object.assign(
      new Error("native browser wire observation failed"),
      { freightctlWirePhase: phases.has(phase) ? phase : "setup" },
    );
  } finally {
    active = false;
    clearTimeout(timer);
    for (const timers of requestTimers.values()) {
      clearTimeout(timers.headers);
      clearTimeout(timers.body);
    }
    if (session) {
      session.off("Network.requestWillBeSent", onRequest);
      session.off("Network.requestWillBeSentExtraInfo", onExtra);
      session.off("Fetch.requestPaused", onPaused);
      let cleanupTimer;
      const limit = new Promise((_, reject) => {
        cleanupTimer = setTimeout(
          () => reject(new Error("native browser cleanup deadline")),
          5000,
        );
      });
      try {
        for (const handle of streams)
          await Promise.race([session.send("IO.close", { handle }), limit]);
        for (const requestId of paused)
          await Promise.race([
            session.send("Fetch.failRequest", {
              requestId,
              errorReason: "Aborted",
            }),
            limit,
          ]);
        await Promise.race([session.send("Fetch.disable"), limit]);
        await Promise.race([session.send("Network.disable"), limit]);
      } catch {
        failure ??= Object.assign(
          new Error("native browser wire observation failed"),
          { freightctlWirePhase: "cleanup" },
        );
      } finally {
        try {
          await Promise.race([session.detach(), limit]);
        } catch {
          failure ??= Object.assign(
            new Error("native browser wire observation failed"),
            { freightctlWirePhase: "cleanup" },
          );
        }
        clearTimeout(cleanupTimer);
      }
    }
  }
  if (failure) throw failure;
  return JSON.parse(result.body);
}
