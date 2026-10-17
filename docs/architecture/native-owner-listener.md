# Private native owner serving

ADR-122 adds a separate h2/TLS1.3 receiver to the existing protected `hub-api` owner process. It is optional and installation-owned. The existing enrollment handler, Service port and protocol are unchanged; `NativeOwnerForwarder` selects the independently accepted `NativePort` on the same checked Pod addresses and exact process TLS name. It cannot fall back to enrollment or a caller-provided route.

`OwnerRuntime` supervises its activated server/client credentials, enrollment receiver, optional native receiver and readiness under one process root. Native shutdown closes the router and joins request-owned streams. A registration must name this exact runtime's installation, Pod UID and process epoch; it retains the actual hub caller callbacks. Registration creates no SQL admission and reconstructs no personal identity.

## Protected inputs and role separation

The audited `owner-pool.json` has an optional `nativePort`; omission and a zero-valued Go field preserve historical bytes. Nonzero values are 1024–65535 and distinct from the enrollment port. The public immutable startup `deployment.json` has optional `native` inputs:

- Connector issuer roots, independently pinned by installation and checked against actual peer TLS plus current fleet registration.
- One to 256 exact worker API projections, each with cluster UUID, control namespace name/UID and fixed HTTPS endpoint/CA roots. The token is read from `native-kube-<cluster UUID>-<namespace UUID>.token`; neither the wire nor a public request names a credential path.
- One to 1024 immutable topology ConfigMap pins, each with target cluster UUID, name, UID and canonical SHA-256. Their current contents feed the existing retention transaction guard. Topology pins are protected installation data; current arbitrary labels or ConfigMap status cannot replace them.
- Separate connection (1–64) and concurrent-operation (1–16, at most connections) limits.

All inputs must still fit the existing 256 KiB deployment document. Native inputs and an accepted nonzero native port must be present together. The loader requires a distinct `sql-native-read.json` username from the existing enrollment/audit/activation/registry/routing users, retains credential rotation without role changes, and imports no ambient PostgreSQL/Kubernetes settings.

`postgres.NativeReaders` is a read-only Go facet. Each call resolves the original exact worker/profile from current SQL under the installed permission root, then delegates existing worker/native/retention/recovery checks under the original earliest deadline. The profile is not selected from Hello and no profile cache extends authority. The SQL role needs SELECT on existing current fleet/peer, permission, catalog/context/custody, retention, download session/response/window and worker configuration/enrollment/certificate/native tables. Existing SELECT FOR UPDATE/SHARE checks additionally require only the immutable-key lock privileges used by those facets: installation ID on current fleet trust, IDs on permission/session/worker/response/window rows, retention root, worker-configuration source UID, and worker ID on the native owner row. It receives no authority-changing column or INSERT/DELETE privileges. Exact grants require real-service qualification before installation enablement.

The proof router first reads the actual admitted worker and selects only its matching installation-pinned cluster/control namespace client. It repeats existing TokenReview, live Pod/account/Job/source checks. A missing pin or changed namespace/source denies; no other cluster is tried.

## Lifetime and remaining composition

Accepted TCP sockets are bounded before TLS. The listener permits only TLS1.3/h2, one conversation per socket, one h2 stream, bounded headers and flow-control buffers, no session resumption, and an original ten-second socket deadline. Certificate expiry may only shorten the socket. Original operation/proof/SQL/identity observations remain at most five seconds; read/write deadlines and cancellation join the actual blocking calls. Positive final Done checks run before flush as specified by the native exchange; they do not prove remote global quiescence.

[ADR-139](../decisions/139-shared-native-context-start-listener.md) optionally
composes the fixed context-start handler on the same accepted port. The original
TCP acceptance instant anchors a two-second TLS/header prelude, ten-second native
exchange or thirty-second context standby. The two admitted purposes reserve
separate socket slots until their handlers and sockets join; the raw pre-TLS
ceiling remains shared, so unclassified connections can temporarily occupy that
capacity. Path selection grants no identity or operation authority. The existing
native-only entry point retains its original ten-second bound.

HTTP/2 can report an idle connection while its final response frames remain
buffered. The server disables keep-alives through Go's graceful GOAWAY handling
rather than closing the raw socket from an idle callback. The atomic first-request
guard still denies another conversation, and purpose capacity stays charged until
the socket and handler join. An actual listener/client regression covers delivery
of the exact authenticated no-command response and reuse of the released capacity.

Current I-13 `NativeFrameGate`, peer proof, original serving observation and route all retain the first deadline/sequence. They cannot support a conversation spanning multiple five-second authority intervals. The 4096-byte context path is the initial mechanism. Future larger artifacts need separately admitted finite segment conversations or a qualified renewal protocol that rechecks every authority and joins old pending data without quota reset or uncertain-operation replay. This work claims no large-file throughput or slow-reader qualification.

Remaining protected producers include the connector's process-owned client enrollment/renewal, a distinct worker-facing server certificate/identity source, their deployed supervisor, native SQL/API projection provisioning and positive joined native-history cleanup. Existing fixture certificates and synthetic Pod/bootstrap facts are qualification inputs only. No MCP/download route or hub unwrap is enabled by this receiver. Component and deployed qualification results must be recorded separately after actual execution.

## Qualification boundary

The staged actual Go HTTP/2 listener regression passes with joined cancellation and TLS1.3/server-purpose checks. An initial test reproduced HTTP/1-only ClientHello acceptance before the completed-handshake callback rejected it; the listener now rejects a ClientHello that does not offer h2 before server Finished and still verifies the final negotiated protocol. Seven affected package race suites and integration-test compilation passed. This uses synthetic serving/operation facts and is not deployed owner identity qualification.

The strict real SQL/S3 native-exchange fixture uses this listener and a separately credentialed NativeReaders adapter, requires all three worker conversations to return Joined, preserves exact native bytes/hash and SQL Completed checks, and explicitly denies operation retirement/key-slot consumption through the read credential. The [parent-owned run](../../test/results/native-owner-listener-qualified.log) passes, with 1,090 unchanged source hashes and complete cleanup in its [terminal report](../../test/results/native-owner-listener-qualified-check.log). Integrated vet/race, SQL generation, architecture and specification gates also pass; see [implementation progress](../implementation-progress.md). Human/Pod/issuer/bootstrap inputs remain synthetic. This result does not qualify deployed connector identity or the installed public workflow.
