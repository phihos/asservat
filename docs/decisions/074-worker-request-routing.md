# ADR-074 — Active worker request ownership

Date: 2026-10-10. Status: implemented component refinement; focused race, full SQL/S3 and Kubernetes/OpenBao regressions pass. Distributed routing and public runtime remain pending.

The private enrollment handler previously served one authenticated control operation. Concurrent developers need exact routing to their own current operation, and cancelling that operation must remain effective while its certificate response is being written. Returning a certificate alone releases that lifetime too early.

Use a bounded process-local `WorkerEnrollmentRouter`, owned by C-14, and a private `WorkerEnrollmentDelivery` that retains cancellation/deadline ownership through response close. Registration accepts only the existing concrete request-bound operation. Check current human download authority and the actual admitted worker registry before publishing the route. Bind installation, session, worker, Pod, original worker times and exact actor/client/artifact scope. Never accept a credential, principal, callback or deadline supplied by the worker as control authority.

Count registration I/O, live owners and closing in-flight operations against one limit of at most sixteen. Permit one enrollment/delivery per owner at a time. Closing removes lookup immediately and cancels work, but retains the capacity charge until delivery or blocked work actually returns. An old handle cannot close a replacement owner. Original operation deadlines remain at most thirty seconds; registration and reconnect cannot renew them.

The handler retains the delivery context through write/flush, narrows the socket deadline to the original owner/certificate bounds, interrupts blocked writes on cancellation and joins the cancellation callback before resetting the connection deadline. Closing a route is not certificate revocation, worker termination or permission to refund durable SQL spend. Every actual effect still requires the existing current proof, authority, audit and activation checks.

No JSON field, public API, SQL migration, library, service or developer approval changes. The process-local router is not the distributed owner locator or connector/hub relay. Protected listener/issuer bootstrap, cross-replica routing and native transfer remain required before public downloads. Contract and verification boundaries are in [worker request routing](../architecture/worker-request-routing.md); actual results are in [implementation progress](../implementation-progress.md).
