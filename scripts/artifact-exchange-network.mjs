// Browser-fixture network boundary;the server still checks the enrolled actor,
// checkpoint lease,offset and exact bytes on every ordinary upload request.
export function artifactExchangeRequestAllowed(
  target,
  method,
  origin,
  tenant,
  partner,
) {
  if (target.origin !== origin || target.username || target.password)
    return false;
  if (["GET", "POST"].includes(method)) return true;
  const id = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  if (
    method !== "PATCH" ||
    !id.test(tenant) ||
    !id.test(partner) ||
    target.search ||
    target.hash
  )
    return false;
  const prefix = `/v1/tenants/${tenant}/partners/${partner}/uploads/`;
  return (
    target.pathname.startsWith(prefix) &&
    id.test(target.pathname.slice(prefix.length))
  );
}
