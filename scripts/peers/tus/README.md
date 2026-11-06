# Native tus client qualification peer

This CI-only fixture uses unmodified tus-js-client4.3.1 with its documented
`uploadUrl`,chunking and HTTP-stack options. The adapter supplies verified TLS and
rejects any request outside the exact configured loopback resource. It never
provides a creation endpoint or allows a fallback POST. It is not shipped core
runtime,an inference service or a credential provider.

Upstream: https://github.com/tus/tus-js-client/releases/tag/v4.3.1
API: https://github.com/tus/tus-js-client/blob/v4.3.1/docs/api.md
License: MIT. The exact dependency graph and archive integrity are in
package-lock.json. CI must install with scripts disabled and audit the complete
production graph;no finding or package is suppressed. Real runtime results stay
owed until an exact native source/peer proof is observed.
