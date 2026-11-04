import { ApiError, object } from "./types";

export interface FTPSConnectionProof {
  mode: "explicit" | "implicit";
  server_name: string;
  ca_sha256: string;
  ca_reference_sha256: string;
  password_reference_sha256: string;
  staging_directory: string;
  receiver_contract: {
    schema_version: 1;
    document_sha256: string;
    staging_visibility: "receiver-private";
    rename: "may-replace";
    duplicates: "receiver-deduplicates-delivery-id";
    receipt: "exact-readback";
  };
}

const bad = (): never => {
  throw new ApiError("invalid_ftps_metadata", 502);
};
function exact(o: Record<string, unknown>, fields: string[]) {
  if (Object.keys(o).sort().join("\0") !== [...fields].sort().join("\0")) bad();
}
function text(
  o: Record<string, unknown>,
  key: string,
  maximum: number,
): string {
  const value = o[key];
  if (
    typeof value !== "string" ||
    !value ||
    new TextEncoder().encode(value).length > maximum ||
    /[\p{Cc}]/u.test(value)
  )
    bad();
  return value as string;
}
function hash(o: Record<string, unknown>, key: string): string {
  const value = text(o, key, 64);
  if (!/^[a-f0-9]{64}$/.test(value)) bad();
  return value;
}
export function ftpsMetadataPath(value: string): string {
  if (
    !value.startsWith("/") ||
    value.normalize("NFC") !== value ||
    new TextEncoder().encode(value).length > 1024
  )
    bad();
  if (value !== "/")
    for (const part of value.slice(1).split("/")) {
      if (
        !part ||
        part === "." ||
        part === ".." ||
        part === ".freightctl" ||
        /[\p{Cc}\\:]/u.test(part) ||
        /[. ]$/.test(part) ||
        new TextEncoder().encode(part).length > 255 ||
        /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)
      )
        bad();
    }
  return value;
}
export function asFTPSConnectionProof(
  value: unknown,
  directory: string,
): FTPSConnectionProof {
  const o = object(value),
    c = object(o.receiver_contract);
  exact(o, [
    "mode",
    "server_name",
    "ca_sha256",
    "ca_reference_sha256",
    "password_reference_sha256",
    "staging_directory",
    "receiver_contract",
  ]);
  exact(c, [
    "schema_version",
    "document_sha256",
    "staging_visibility",
    "rename",
    "duplicates",
    "receipt",
  ]);
  const serverName = text(o, "server_name", 253),
    stage = ftpsMetadataPath(text(o, "staging_directory", 1024));
  ftpsMetadataPath(directory);
  if (
    (o.mode !== "explicit" && o.mode !== "implicit") ||
    /[\/\\ ]/.test(serverName) ||
    stage === directory ||
    stage === "/" ||
    directory === "/" ||
    stage.startsWith(directory + "/") ||
    directory.startsWith(stage + "/") ||
    c.schema_version !== 1 ||
    c.staging_visibility !== "receiver-private" ||
    c.rename !== "may-replace" ||
    c.duplicates !== "receiver-deduplicates-delivery-id" ||
    c.receipt !== "exact-readback"
  )
    bad();
  return {
    mode: o.mode as FTPSConnectionProof["mode"],
    server_name: serverName,
    ca_sha256: hash(o, "ca_sha256"),
    ca_reference_sha256: hash(o, "ca_reference_sha256"),
    password_reference_sha256: hash(o, "password_reference_sha256"),
    staging_directory: stage,
    receiver_contract: {
      schema_version: 1,
      document_sha256: hash(c, "document_sha256"),
      staging_visibility: "receiver-private",
      rename: "may-replace",
      duplicates: "receiver-deduplicates-delivery-id",
      receipt: "exact-readback",
    },
  };
}
