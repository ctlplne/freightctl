// Known custody identities only;these values never grant byte or action access.
export function controlledArtifactPolicyHash(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return (
    /^intake-(?:csv-v1|json-records-v1|fixed-width-v1|xml-records-v1|xlsx-records-v1):([0-9a-f]{64})$/.exec(value)?.[1] ??
    null
  );
}
export function validArtifactPolicy(value: unknown): value is string {
  return (
    value === "integrity-only-v1" ||
    controlledArtifactPolicyHash(value) !== null
  );
}
