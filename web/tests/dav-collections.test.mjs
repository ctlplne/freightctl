import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  entryPoints: ["src/collections-types.ts"],
  absWorkingDir: new URL("..", import.meta.url).pathname,
  bundle: true,
  write: false,
  format: "esm",
  target: "es2022",
});
const p = await import(
  "data:text/javascript;base64," +
    Buffer.from(bundle.outputFiles[0].contents).toString("base64")
);
const connection = () => ({
  id: "00000000-0000-0000-0000-000000000001",
  version: 1,
  definition_hash: "a".repeat(64),
  state: "active",
  revision: 1,
  address: "127.0.0.1:9443",
  user: "",
  directory: "/inbox",
  host_fingerprint: "",
  key_fingerprint: "",
  protocol: "webdav",
  dav: {
    profile: "freightctl-webdav-collection-source-v1",
    server_name: "localhost",
    ca_sha256: "b".repeat(64),
    ca_reference_sha256: "c".repeat(64),
    token_reference_sha256: "d".repeat(64),
    read_only: true,
  },
});
const source = () => ({
  kind: "webdav.collect",
  connection: { id: connection().id, version: 1, hash: "a".repeat(64) },
  manifest: "batch.ready.json",
  target_directory: "/received",
  completion_contract: "immutable-files-sha256-manifest-v1",
  max_files: 4,
  max_file_bytes: 1048576,
  max_total_bytes: 4194304,
});

test("DAV collection exposes exact read-only TLS metadata without credential inputs", () => {
  assert.deepEqual(p.asCollectionConnection(connection()), connection());
  assert.deepEqual(p.asCollectionSource(source()), source());
});

test("DAV review refuses mixed protocol,secret fields or implied write authority", () => {
  for (const mutate of [
    (c) => (c.dav.read_only = false),
    (c) => (c.dav.token_reference = "/private/token"),
    (c) => (c.dav.token_sha256 = "e".repeat(64)),
    (c) => (c.user = "unexpected-user"),
    (c) => (c.host_fingerprint = "unexpected-ssh"),
    (c) => (c.protocol = "ftps"),
    (c) => delete c.dav,
  ]) {
    const c = connection();
    mutate(c);
    assert.throws(() => p.asCollectionConnection(c));
  }
  const scheduled = source();
  scheduled.completion_contract =
    "immutable-files-sha256-scheduled-manifest-v1";
  scheduled.manifest = "batch-{due_utc}.ready.json";
  assert.throws(() => p.asCollectionSource(scheduled));
});

test("Basic DAV source review binds its explicit credential profile and public user", () => {
  const c = connection();
  c.user = "source-reader";
  c.dav.profile = "freightctl-webdav-basic-collection-source-v1";
  c.dav.authentication = "basic";
  c.dav.password_reference_sha256 = "e".repeat(64);
  delete c.dav.token_reference_sha256;
  assert.deepEqual(p.asCollectionConnection(c), c);
  for (const mutate of [
    (c) => (c.user = ""),
    (c) => (c.user = "bad:user"),
    (c) => (c.dav.token_reference_sha256 = "d".repeat(64)),
    (c) => (c.dav.password_sha256 = "f".repeat(64)),
    (c) => (c.dav.authentication = "bearer"),
    (c) => (c.dav.profile = "freightctl-webdav-collection-source-v1"),
  ]) {
    const changed = structuredClone(c);
    mutate(changed);
    assert.throws(() => p.asCollectionConnection(changed));
  }
});
