# ADR-135: live outbound regional API context start

> Superseded in part by ADR-328 (2026-11-13): Pinned connector source UID/RV, Deployment/template/image comparison, namespace-guard additions and installer approval of whole Secrets defended against writers in the connector namespace and no longer apply. The live exchange, signed work reference, current identity round trips and budgets remain valid.

Status: accepted for implementation; public collection remains disabled pending the qualified composition described below.

The request-owning hub must reach the regional API runner without retaining a human identity snapshot or receiving collector keys. Existing native-download and node-work protocols authorize different operations. Collection uses the connector Pod's configured image and mounted startup inputs.

Use one connector-originated TLS 1.3/HTTP/2 conversation on the fixed private `/internal/v1/context/start-exchange` path. Before work, a standby holds no human authority and has an original maximum thirty-second residency. Each exchange accepts one purpose-separated Ed25519 `api-context-work/v1` reference, at most eight sequential live identity round trips, one finite result and one terminal acknowledgement. The actual current connector leaf/process and current hub owner route must agree at both ends. No capture caller supplies an address, credential, callback, key identifier or connector.

The hub retains the original request-owned `CurrentIdentity`. Every regional identity resolution asks that same handle through the live exchange, using a fresh challenge and next sequence. Neither groups nor scopes are persisted or signed into the work reference. Their original verification deadline, unchanged principal/client/policy and exact groups/scopes remain binding. EOF, cancellation, changed identity or any original deadline terminates and joins the conversation. A fresh observation can narrow an interval but never extend the signed work or an earlier observation used by that invocation.

Use the existing regional `APIContextRunner`, accepted SQL52 capture-intent receipt, current permission/retention/recovery/capability checks and local CapacityReservation CAS. The signed work additionally binds capture/attempt, exact scope/expectation/intent/budget digests, protected capability/projection, actual connector leaf and both process epochs. Only the first positively acknowledged execution preparation may prepare keys. Unknown preparation and historical replay never become a new acquisition. Explicit ADR-134 continuation remains a separate fresh-current request; it cannot renew the original capture, writer or prepared execution interval.

An additive connector API profile names the connector configuration revision and local-start identities. RBAC grants the capacity account CREATE and the capacity/execution accounts status UPDATE on CapacityReservation. Omission leaves the legacy profile unchanged.

RBAC grants this API role only the exact named startup/pull Secrets it needs, never namespace-wide credential reads. No public input exposes this choice.

Connection and capture budgets are separate, with reserved per-cluster shares and fixed whole-process ceilings. Closing work remains charged until its sockets/readers/owners join. Complete owner enumeration is candidate discovery only; current accepted routing and peer checks still select each exact destination. Every owner has its own bounded standby lifetime so one stalled owner cannot prevent replacing a completed standby for another.

This decision adds no durable dispatch queue, migration, public operation, broker, inbound regional listener or change to node work. Dedicated work-key/trust provisioning, Helm-rendered configuration/RBAC, deployed regional composition, actual combined same-request timing, independent publication and the public native-download path remain required. A stored result is `StoredPendingVerification`, never catalog success.

Implementation and measured scope: [regional context start](../architecture/regional-context-start.md).
