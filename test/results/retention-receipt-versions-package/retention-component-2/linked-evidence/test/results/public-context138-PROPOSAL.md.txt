# ADR138: compose the existing public context endpoints

This package connects existing concrete, audited browser and MCP transports,
the built console, and ADR136's authenticated native-content handler under one
installed HTTPS origin. It does not add a public operation, authority source,
listener, fixture credential, or runtime-enablement switch.

The composition constructs one `NewHealthyAuditedOperations` owner from the
independently backed normal and resolution auditors. The exact same pointer is
passed to browser operations, MCP operations and native HTTP preflight. The
ordinary browser operation constructor cannot accidentally omit its concrete
POST refresh owner. Download content is constructed with the exact same session
service, origin, issuer and pause reader; MCP and content retain distinct pinned
bearer resource resolvers. Console files are immutable constructor inputs and
read through the existing bounded package reader.

A private exact-path router preserves handlers and response writers. It never
normalizes paths, redirects a POST, falls back to the app shell for API errors,
buffers download bodies, compresses evidence, logs credentials or treats
forwarded headers as transport authority. Only the existing authentication
routes may carry their protocol query parameters. Routing itself grants no
authority; native bytes still need ADR136's current preflight/session/transfer
checks and long-response fences. The router adds no shared semaphore that would
let ordinary requests exhaust the existing separate Stop lanes.

The composition requires preview, capture recovery/progress, case metadata,
preparation/status/cancellation and native content. Only the existing capture
operation decides whether collection is enabled; deliberately disabling new
capture must not remove retained-evidence access. The installed full-journey
qualification additionally requires enabled capture. No unaudited constructor
or disabled-capture partial fixture proves that installed journey.

Verification will include exact dispatch across all transports, real TLS/HTTP
routing without implicit redirects, encoded/absolute/cross-origin rejection,
OIDC callback-query preservation, missing/private paths, and response-writer
deadline/flush capability preservation. These tests prove routing and composition,
not that fixture services are production authority.

The following remain mandatory before public enablement: protected providers
and bearer resource configuration; accepted permission/retention/capability,
storage and audit sources; their supervisors; actual regional acquisition,
verification/publication and native runtime; bounded public listener and ingress;
the installed console/MCP/native-byte journey. The existing chart continues to
reject runtime enablement. This package will be integrated after ADR136 so that
it imports the actual content handler rather than defining a replacement seam.
