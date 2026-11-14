# Regional API context execution

The connector runs the [Kubernetes API context](api-context-execution.md) for
its cluster. It captures only the fixed Pod status projection (bounded by the 2 MiB API
response cap, see [the API context](api-context-execution.md)) and
needs no Node, exec, Secret, log or container access.

## Flow

1. The hub records one `context_execution` row with an operation ID, the
   accepted expectation, the Pod/owner pin and the `plan_digest`, together with
   the per-workload storage charge and an audit row, in one SQL transaction
   (ADR-330 D6/D7). Concurrent requests with the same idempotency key receive
   the same row.
2. The hub sends `runAction` as a stream on the connector's single hub
   connection (ADR-330 D2). The connector is authenticated by its
   ServiceAccount token (ADR-334); no per-start proof, guard read or start
   object is created.
3. The connector reads the pinned Pod, rejects a substitute Pod, encrypts the
   projection with the wrap-only producer and writes the attempt objects under
   keys derived from the operation ID with conditional create. A retry of the
   same operation ID finds the existing objects instead of capturing again.
4. The connector reports completion with the object receipts. The hub records
   the outcome and publishes the artifact as described in
   [context publication](context-publication.md).

Native bytes stay in bounded memory and are cleared on return.

## Lost replies and failures

If the completion report is lost, the connector resends it with the same
operation ID after reconnecting, and the hub returns the stored outcome. If
the connector cannot complete, it reports failure; the hub releases the
storage charge once the outcome is known. An operation with no report by its
deadline is marked `Indeterminate`; looking up its operation ID on reconnect
resolves it, and the charge is released when the outcome is known.

Artifact access after acquisition does not depend on the workload Pod or the
connector still existing.
