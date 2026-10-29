// Browser cryptography boundary: standard platform randomness and the pinned
// noble SHA-256 implementation. No keys or file bytes enter model context.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export function operationKey(): string {
  return crypto.randomUUID();
}
export function digestBytes(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

export async function hashFileSlices(
  file: File,
  progress: (bytes: number) => void,
): Promise<string> {
  const hash = sha256.create();
  try {
    for (let offset = 0; offset < file.size; offset += 1048576) {
      const bytes = new Uint8Array(
        await file
          .slice(offset, Math.min(file.size, offset + 1048576))
          .arrayBuffer(),
      );
      try {
        hash.update(bytes);
      } finally {
        bytes.fill(0);
      }
      progress(Math.min(file.size, offset + 1048576));
    }
    return bytesToHex(hash.digest());
  } finally {
    hash.destroy();
  }
}

export function digestFile(
  file: File,
  progress: (bytes: number) => void,
  signal: AbortSignal,
): Promise<string> {
  if (signal.aborted)
    return Promise.reject(new DOMException("Canceled", "AbortError"));
  return new Promise((resolve, reject) => {
    const worker = new Worker("/assets/hash-worker.js", { type: "module" });
    const finish = () => {
      worker.terminate();
      signal.removeEventListener("abort", abort);
    };
    const abort = () => {
      finish();
      reject(new DOMException("Canceled", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
    worker.onmessage = (event: MessageEvent<unknown>) => {
      const value = event.data;
      if (typeof value !== "object" || value === null) {
        finish();
        reject(new Error("file_read_failed"));
        return;
      }
      const data = value as Record<string, unknown>;
      if (
        typeof data.progress === "number" &&
        Number.isSafeInteger(data.progress) &&
        data.progress >= 0 &&
        data.progress <= file.size
      )
        progress(data.progress);
      if (
        typeof data.digest === "string" &&
        /^[0-9a-f]{64}$/.test(data.digest)
      ) {
        finish();
        resolve(data.digest);
      }
      if (data.error === true) {
        finish();
        reject(new Error("file_read_failed"));
      }
    };
    worker.onerror = () => {
      finish();
      reject(new Error("file_read_failed"));
    };
    worker.postMessage(file);
  });
}
