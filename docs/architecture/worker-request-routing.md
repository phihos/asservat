# Worker request routing and delivery lifetime

[ADR-074](../decisions/074-worker-request-routing.md) refines the [credential channel](worker-credential-channel.md) under REQ-DEP-003, REQ-DLD-003 and REQ-CAP-003. C-14 owns the process-local active request registry and response lifetime. C-20's private handler consumes that lifetime; C-15 remains authoritative for worker identity, activation and spend. This is part of I-13, with no new public endpoint or serialized capability.

## Register an active owner

`WorkerEnrollmentRouter.Register` accepts a concrete `WorkerEnrollmentOperation` created by trusted control. The operation already owns the human credential, exact download scope and original worker target. Registration checks current download authority, including installation, and reads the admitted worker through `WorkerEnrollmentBindings`. Session, worker, Pod, original creation/deadline and exact actor/client/artifact scope must match. Repeat freshness and cancellation checks after external work and before publishing the route. No registry observation is an authorization cache for later effects.

The owner lifetime intersects registration context, original authenticated request, router shutdown and the operation's original deadline of at most thirty seconds. A duplicate live owner is rejected, never silently replaced. Failed or slow registration cannot extend authority. A fresh authenticated operation may later register the same worker and retrieve an already audited current certificate through the ordinary issuance coordinator. It cannot choose a new worker key, replace original timing or repeat signing merely because routing changed.

Router Close signals cancellation for callbacks and reentrant callers. Process
shutdown uses CloseAndJoin before releasing dependency pools; it also waits for
already admitted Claim, locator-read and restrictive-release wrappers. Their
original deadlines remain unchanged. Once closed, the router admits no new SQL
wrapper work; an unissued release leaves the stored lease occupied until its
original expiry. This lifetime accounting grants no request authority.

## Bound concurrent work

The configured process limit is one through sixteen and includes registration I/O, registered owners and closed owners with work or a response still outstanding. Prune expired idle owners before admitting another registration. Only one enrollment/delivery may be active for a route at once; distinct workers can proceed concurrently with independent token readers and human scope. No external call runs under the registry mutex.

Closing a handle removes it from lookup and cancels its context immediately. Capacity remains charged until its active call or delivery closes. This prevents cancellation/re-registration churn from bypassing the bound when a provider or socket is slow. Cleanup of an old handle checks object identity and cannot remove a new owner with the same session/worker key. Dropping the completed operation releases its credential reference; it is not a guarantee of Go heap erasure.

These are local memory/I/O bounds. Deployment-wide endpoint, proof-provider and PKI admission/fairness remain separate requirements; adding replicas does not establish a global rate limit.

## Keep ownership through the response

`WorkerEnrollmentExchange.BeginWorkerEnrollment` returns a `WorkerEnrollmentDelivery` with certificate, bounded context and mandatory idempotent `Close`. It is private in-process ownership, never a bearer token or a wire field. The operation and router retain their cancellation bridges until delivery closes, including certificate replay without another signing operation.

The handler closes every returned delivery on success and error. Its write deadline is the earliest of the HTTP operation, owner and certificate deadlines. Owner cancellation interrupts a blocked response write; the handler joins an already running cancellation callback before resetting the socket deadline, so a late callback cannot corrupt a reused connection. A certificate already received cannot be recalled by closing this handle. Activation/revocation, current authorization and independently owned native transports retain their own checks and shutdown obligations.

## Qualification and remaining composition

Race tests cover exact owner/worker binding, two concurrent developers' separate token readers, duplicate owners, registration expiry/cancellation after I/O, shutdown, capacity retention through blocked work and old-handle isolation. A controlled blocked response writer covers cancellation/expiry through write and deadline cleanup. This writer is a transport test, not a kernel/socket throughput measurement.

The real SQL/S3 case uses the production router, current authorizer and SQL worker reader with the actual TLS handler/client. It checks route retirement, held delivery capacity and same-key certificate replay without another signing call. Its Pod proof and CA are explicitly synthetic. The independent Kubernetes/OpenBao suite runs the compiled credential-phase worker in a restricted Pod, with real token and issuer behavior but synthetic dispatch/issuance authority. Actual results and cleanup/source reports belong in [implementation progress](../implementation-progress.md).

[ADR-075 shared locators](worker-owner-locator.md) now add finite SQL ownership and an exact-local-owner receiver. Still required: protected listener/issuer bootstrap; authenticated browser/MCP owner registration; trusted hub process discovery/forwarding and the configured outbound connector path; renewal handoff to fresh current human authority; and actual native work/byte relay. No sticky-session requirement, arbitrary worker callback, persisted personal token, public enrollment route or disabled authority check is introduced to fill those gaps.
