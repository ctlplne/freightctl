import { request } from "node:https";
import { X509Certificate } from "node:crypto";

export async function fetchPinnedBrowserRequest(
  original,
  expectedOrigin,
  certificateDER,
) {
  // Qualification transport only. A Chrome SPKI launch flag does not configure
  // a separate API/Node client's trust store. Use exactly this fixture CA and
  // ordinary hostname verification;never disable certificate checks or redirect.
  const target = new URL(original.url()),
    origin = new URL(expectedOrigin);
  if (
    origin.protocol !== "https:" ||
    origin.hostname !== "127.0.0.1" ||
    origin.origin !== expectedOrigin ||
    target.origin !== origin.origin ||
    target.username ||
    target.password ||
    target.hash ||
    original.method() !== "POST"
  )
    throw new Error("fixture HTTPS command scope refused");
  if (
    !(certificateDER instanceof Uint8Array) ||
    certificateDER.length < 1 ||
    certificateDER.length > 16384
  )
    throw new Error("fixture HTTPS certificate refused");
  const certificate = new X509Certificate(certificateDER);
  const body = original.postDataBuffer(),
    all = await original.allHeaders();
  if (!Buffer.isBuffer(body) || body.length > 32768)
    throw new Error("fixture HTTPS command body refused");
  const headers = {};
  for (const name of [
    "content-type",
    "cookie",
    "origin",
    "x-csrf-token",
    "idempotency-key",
  ]) {
    const value = all[name];
    if (
      typeof value !== "string" ||
      !value ||
      value.length > 16384 ||
      /[\r\n\0]/.test(value)
    )
      throw new Error("fixture HTTPS command headers refused");
    headers[name] = value;
  }
  if (
    headers.origin !== origin.origin ||
    !/^application\/json(?:;\s*charset=utf-8)?$/i.test(headers["content-type"])
  )
    throw new Error("fixture HTTPS command origin or type refused");
  return new Promise((resolve, reject) => {
    const req = request(
      target,
      {
        method: "POST",
        headers: { ...headers, "content-length": String(body.length) },
        ca: certificate.toString(),
        rejectUnauthorized: true,
        agent: false,
        signal: AbortSignal.timeout(30000),
      },
      (res) => {
        res.once("error", reject);
        const peer = res.socket.getPeerCertificate();
        if (!Buffer.isBuffer(peer.raw) || !peer.raw.equals(certificate.raw)) {
          res.destroy(new Error("fixture HTTPS peer certificate differs"));
          return;
        }
        const parts = [];
        let count = 0;
        res.on("data", (b) => {
          count += b.length;
          if (count > 32768)
            res.destroy(new Error("fixture HTTPS receipt exceeds bound"));
          else parts.push(b);
        });
        res.once("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(parts) }),
        );
      },
    );
    req.once("error", reject);
    req.end(body);
  });
}

// Preserve a routing exception for the journey's outer failure boundary. An
// asynchronous route handler must not terminate Node before private evidence
// and the failed summary can be written. The caller must refuse overall success
// whenever onFailure received an error.
export function guardBrowserCommandRoute(handler, onFailure) {
  return async (route) => {
    try {
      await handler(route);
    } catch (error) {
      onFailure(error);
      try {
        await route.abort("failed");
      } catch {
        /* keep the original failure */
      }
    }
  };
}
