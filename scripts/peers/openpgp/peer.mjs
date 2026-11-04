// Test-only independent implementation. This package is never imported by core
// or its browser bundle. The parent runs it offline in a bounded CI container.
import { lstat, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve, join, isAbsolute } from "node:path";
import assert from "node:assert/strict";
import * as openpgp from "openpgp";

const version = "6.3.2",
  profile = "seipd-v2-aes256-ocb";
let stage = "arguments";
const config = {
  aeadProtect: true,
  preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
  preferredAEADAlgorithm: openpgp.enums.aead.ocb,
  preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed,
  allowUnauthenticatedMessages: false,
  allowUnauthenticatedStream: false,
  maxDecompressedMessageSize: 1 << 20,
};
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function directory(path) {
  assert.ok(isAbsolute(path) && resolve(path) === path);
  const st = await lstat(path);
  assert.ok(
    st.isDirectory() && !st.isSymbolicLink() && (st.mode & 0o077) === 0,
  );
}
async function bounded(path, maximum) {
  const st = await lstat(path);
  assert.ok(
    st.isFile() &&
      !st.isSymbolicLink() &&
      (st.mode & 0o077) === 0 &&
      st.size > 0 &&
      st.size <= maximum,
  );
  const bytes = await readFile(path);
  assert.ok(bytes.length === st.size);
  return new Uint8Array(bytes);
}
async function generate(dir) {
  stage = "directory";
  await directory(dir);
  stage = "key-generation";
  const generated = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs: [{ name: "freightctl synthetic AEAD recipient" }],
    keyExpirationTime: 86400,
    format: "binary",
    config,
  });
  stage = "key-serialization";
  const key = await openpgp.readPrivateKey({ binaryKey: generated.privateKey });
  const encryption = await key.getEncryptionKey();
  const fingerprint = key.getFingerprint(),
    subkey = encryption.getFingerprint();
  assert.match(fingerprint, /^[0-9a-f]{40}$/);
  assert.match(subkey, /^[0-9a-f]{40}$/);
  stage = "fixture-write";
  await writeFile(join(dir, "recipient-public.gpg"), generated.publicKey, {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(join(dir, "recipient-private.gpg"), generated.privateKey, {
    flag: "wx",
    mode: 0o600,
  });
  const result = {
    schema_version: 1,
    state: "passed",
    peer: "OpenPGP.js",
    version,
    profile,
    primary_fingerprint: fingerprint,
    encryption_fingerprint: subkey,
    public_sha256: sha(generated.publicKey),
  };
  await writeFile(join(dir, "generation.json"), JSON.stringify(result) + "\n", {
    flag: "wx",
    mode: 0o600,
  });
  return result;
}
async function decrypt(fixture, work) {
  stage = "directory";
  await directory(fixture);
  await directory(work);
  stage = "read-inputs";
  const generation = JSON.parse(
    Buffer.from(
      await bounded(join(fixture, "generation.json"), 4096),
    ).toString(),
  );
  const key = await openpgp.readPrivateKey({
    binaryKey: await bounded(join(fixture, "recipient-private.gpg"), 128 << 10),
  });
  assert.equal(key.getFingerprint(), generation.primary_fingerprint);
  assert.equal(
    (await key.getEncryptionKey()).getFingerprint(),
    generation.encryption_fingerprint,
  );
  const ciphertext = await bounded(join(work, "cipher.pgp"), 1 << 20);
  async function authenticated(bytes) {
    stage = "packet-policy";
    const message = await openpgp.readMessage({ binaryMessage: bytes, config });
    const packets = message.packets.filter(
      (p) =>
        p.constructor.tag ===
        openpgp.enums.packet.symEncryptedIntegrityProtectedData,
    );
    assert.equal(packets.length, 1);
    assert.equal(packets[0].version, 2);
    assert.equal(packets[0].cipherAlgorithm, openpgp.enums.symmetric.aes256);
    assert.equal(packets[0].aeadAlgorithm, openpgp.enums.aead.ocb);
    assert.deepEqual(
      message.getEncryptionKeyIDs().map((id) => id.toHex()),
      [(await key.getEncryptionKey()).getKeyID().toHex()],
    );
    stage = "decrypt";
    const result = await openpgp.decrypt({
      message,
      decryptionKeys: key,
      format: "binary",
      config,
    });
    assert.ok(
      result.data instanceof Uint8Array && result.data.length <= 1 << 20,
    );
    return result.data;
  }
  const plaintext = await authenticated(ciphertext);
  stage = "integrity-refusals";
  const corrupt = ciphertext.slice();
  corrupt[corrupt.length - 1] ^= 1;
  const mustRefuse = async (bytes) => {
    try {
      await authenticated(bytes);
    } finally {
      stage = "integrity-refusals";
    }
  };
  await assert.rejects(() => mustRefuse(corrupt));
  await assert.rejects(() => mustRefuse(ciphertext.slice(0, -1)));
  stage = "result-write";
  await writeFile(join(work, "plain.csv"), plaintext, {
    flag: "wx",
    mode: 0o600,
  });
  return {
    schema_version: 1,
    state: "passed",
    peer: "OpenPGP.js",
    version,
    profile,
    primary_fingerprint: key.getFingerprint(),
    encryption_fingerprint: generation.encryption_fingerprint,
    seipd_version: 2,
    cipher: "AES-256",
    aead: "OCB",
    plaintext_bytes: plaintext.length,
    plaintext_sha256: sha(plaintext),
    ciphertext_sha256: sha(ciphertext),
    corrupt_refused: true,
    truncated_refused: true,
  };
}

try {
  const [operation, ...args] = process.argv.slice(2);
  assert.ok(
    (operation === "generate" && args.length === 1) ||
      (operation === "decrypt" && args.length === 2),
  );
  const result =
    operation === "generate" ? await generate(args[0]) : await decrypt(...args);
  console.log(JSON.stringify(result));
} catch {
  // Raw library errors may contain private packet values or filenames.
  console.log(
    JSON.stringify({
      schema_version: 1,
      state: "failed",
      peer: "OpenPGP.js",
      version,
      profile,
      stage,
    }),
  );
  process.exitCode = 1;
}
