# Processing task discovery

`processing-workflow-catalog-v1` lists the authenticated actor's latest schema3
processing task version in each workflow family. It uses ordinary workflow
management/approval/execution permission and actor-private PostgreSQL RLS. A
reviewer's permission to inspect a disclosed review does not list its creator's
other tasks. No file grant, byte read, approval or execution follows from discovery.

Each entry fixes its workflow ID/version/hash, name, configuration state/revision,
task kind, source-policy hash, output kind/column count and exact output-policy
reference. `approval_current` independently observes the configuration's approved
state, current owner authority and any adopted independent review. Withdrawal,
expiry or reviewer revocation makes that fact false. `output_policy_current`
independently observes the active exact output policy. Neither flag checks an
input file or promises execution readiness. Ordinary run review must still check
the exact input, permissions, source protection, policy and durable effect bindings.

Latest means the newest version of the whole family, including an unapproved
draft or a change to another workflow profile. An older approved processing
version is never substituted as the latest result. Existing exact-version lookup
and receipt semantics remain unchanged. Discovery does not revoke older versions.

The API is `GET /v1/tenants/{tenant}/partners/{partner}/processing-workflows`,
with optional `after=UUID` and `limit` (default25, maximum100). Results include
the profile, authority revision, namespace-root digest, `workflows` and optional
`next`. The cursor names the last authorized returned family. A fresh first page
starts a new listing; concurrent changes are observations, not a frozen estate
snapshot. The service has the existing ten-second metadata deadline and reads at
most101 bounded definitions in the control service;database query cost and
latency remain unqualified. It does not contact a recipient or change a row.

CLI: `processing-workflow-list`, ordinary protected database/credential references,
`-tenant`, `-partner`, `-processing-workflow-after` and
`-processing-workflow-limit`. Browser Record processing exposes List my processing
tasks, independent approval/policy columns and Open task for an exact version.
Full rules load through the ordinary authorized configuration read before a
mutation. The [OpenAPI contract](../api/processing-catalog.openapi.json) fixes shapes.

MCP Catalog38/`exchange-tools-v15` adds `freightctl.list_processing_workflows`.
It uses the same service, with names, reasons, paths and full definitions omitted
from model output. Its result explicitly says metadata-only, no effects and
execution readiness not checked. This works with the optional receive adapter
unconfigured. No approval or release tool is added.

F179 retains observed missing-catalog red and focused Go/MCP/frontend/static green.
Prepared real PostgreSQL, verified-HTTPS/stock SDK, public CLI dispatcher and
sandboxed native Chrome cases cover actor isolation, latest unapproved/different
profiles, pagination, withdrawn approval, catalog entry and exact configuration
loading. The original six browser accessibility states remain selected, with a
seventh catalog audit added. Tagged compilation and stand-ins do not establish
those runtime outcomes. No schema, older migration, retained database, custody,
lease, resource allowance or isolation policy changes. Composition, processing
schedules, third-party author delegation and all full-product gates remain owed.
