# Federation and events

Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md): one outbound connector connection, standard certificate bootstrap, pushed cluster state and SQL-signalled work.

## REQ-FED-001 — Enrollment and trust

A cluster MUST enroll with a one-use, expiring bootstrap token issued by an Asservat administrator. Issuing a token is an administrator operation separate from workload access. The connector generates its key pair, presents the token with a certificate signing request and receives a cluster UUID and a client certificate from the installation CA. The private key never leaves the connector; the hub never stores a cluster kubeconfig or a reusable bearer credential. No callback URL, inbound node service exposure or hub-stored cluster-admin credential is required.

The connector renews its certificate with a new CSR authenticated by its current certificate when two thirds of the lifetime have passed (default lifetime one hour, a Helm value). A connector that missed renewal re-enrolls with a new bootstrap token. Issuance and renewal are idempotent by cluster UUID and CSR public key; a retry returns the existing certificate. Each issuance writes its audit row in the same transaction as the cluster record (REQ-DB-004). Revoking a cluster sets its SQL `revoked` flag; the hub checks the flag at TLS handshake and renewal and closes the cluster's open connection when the flag is set. Precedent: kubelet TLS bootstrapping, Open Cluster Management cluster registration.

Local cluster configuration pins the hub CA and a maximum collection policy. Hub commands are versioned and expiry-bound, travel over the authenticated connection and are checked against that local ceiling. In-cluster Asservat workloads (node collectors, regional readers) authenticate to the connector with an audience-bound projected ServiceAccount token checked by TokenReview once per connection. Work is bound to the Kubernetes node UID; a new node does not inherit an old node's work. Regional Pods receive no hub SQL credentials.

### SC-FED-001

Given an enrollment token used once or a connector from another cluster, when registration or connection is attempted, then replay and identity substitution are rejected. A hub request cannot widen a locally denied namespace. After an administrator revokes a cluster, its next handshake or renewal fails and its open connection is closed.

## REQ-FED-002 — Durable outbound work and compatibility

Each connector holds one outbound, multiplexed HTTP/2 (or gRPC) connection to the hub with mutual TLS. Commands, cluster-state pushes, events, results, live rows and download bytes are streams on that connection. A SQL row names the hub replica that holds a cluster's connection; other replicas route to it. Internal payloads use versioned JSON contracts; this is an implementation protocol, not a new external agent interface.

The connector pushes the cluster state the hub needs (namespaces, workloads, Pods, EndpointSlices, AccessBindings, permission sources) from its informers when it changes. After a reconnect it compares a digest with the hub and resends only on mismatch.

The hub stores active work in SQL and signals the connection-holding replica with `NOTIFY` in the writing transaction; that replica sends the work on the connection. Each work item binds `workID`, `operationID`, cluster UUID, target and plan digests, the authorizing grant/reservation and an expiry. Delivery is at least once. Work transitions are `Queued → Sent → Running → terminal`. After a reconnect the hub resends every non-terminal item. The connector records each accepted `workID` in its bounded local state before any intrusive start, deduplicates resent work against it and reports the current state. Intrusive work that may have started stays `Indeterminate` until the connector reports the outcome for that start. Result references survive reconnects.

Liveness is the open connection. The hub records `connected_since` and `disconnected_at` on connection events and a last-seen time at most once per minute. A cluster is offline when its connection has been closed for the grace period (default 60 seconds, tunable). Policy acknowledgements are visible as `status.observedGeneration`.

Support hub/connector N and N-1 minor compatibility within the same API major, with capability negotiation. Unknown required actions or fields fail explicitly.

### SC-FED-002

Given work resent after a network break, when the connector reconnects, then it returns the prior operation state and does not rerun the intrusive action. An older connector rejects an unknown required recipe capability.

## REQ-FED-003 — Locality and partial availability

Each storage/analysis profile MUST declare its region/locality boundary. Raw artifacts and decryption remain local by default. The hub may broker only currently authorized bounded query results and permitted metadata. A hub database outage denies new central authorizations and disclosures; local execution under the connector's budget lease and unexpired permits, and deletion, continue within their limits. A disconnected cluster remains visible with stale-data indicators; the hub cannot claim fresh capability, completed collection or a current query from it.

Metadata events MAY queue in a bounded local queue; full evidence never enters CRD status. Hub and local APIs apply backpressure, bounded queues and explicit drop/gap counters. Intrusive grants obey the permit expiry rules in [authorization](authorization.md). Disconnected work spends only the budget lease under [capacity isolation](capacity.md); an upload retried after reconnect reuses its operation's object key and cannot create a second charged copy.

### SC-FED-003

Given a hub outage during collection, when regional S3/KMS and local control remain healthy, then already authorized local evidence is committed and later synchronized. A remote raw query reports `ClusterOffline`, and expired permits cannot start new dumps.

## REQ-EVT-001 — Content-free CloudEvents

Emit CloudEvents 1.0 structured JSON over configured HTTPS webhooks. Event types include:

```text
io.asservat.case.opened.v1
io.asservat.case.recurred.v1
io.asservat.case.analysis.completed.v1
io.asservat.capture.partial.v1
io.asservat.grant.requested.v1
io.asservat.grant.revoked.v1
io.asservat.share.created.v1
io.asservat.share.revoked.v1
io.asservat.evidence.expired.v1
```

`source` identifies the producing hub/cluster, `id` is stable across retries, and `subject` is an opaque case/signature/grant/share identifier. `dataref` is an authenticated `asservat://case/<id>` reference for a case event, or `asservat://grant/<id>`, `asservat://share/<id>` or `asservat://capture/<id>` for a transition without a case yet. Propagate `traceparent`. Data contains only an administrator-approved identifier allowlist. Default external payloads omit namespace/workload names, arbitrary labels, reasons, usernames and matched text; these can disclose information even without raw evidence.

Sign exact request bytes with Standard Webhooks `webhook-id`, `webhook-timestamp`, `webhook-signature` headers and operator-managed rotating secrets. Enforce recipient-specific cluster/workload event scope, destination allowlist, HTTPS, bounded DNS resolution/redirect behavior and SSRF restrictions. Do not accept a webhook URL from a capture request. [CloudEvents](https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md), [dataref extension](https://github.com/cloudevents/spec/blob/main/cloudevents/extensions/dataref.md), [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).

### SC-EVT-001

Given a case containing a token in its log/filename/reason, when events are delivered, then that content is absent from the payload and headers. Retries preserve the CloudEvent ID and verify with the rotated webhook key.

## REQ-EVT-002 — Delivery outbox

Events MUST be SQL outbox rows committed with their hub case/grant/share transition. Only the hub emits CloudEvents: connectors forward event facts over their connection and the hub records them in its outbox. Delivery workers are woken by `NOTIFY` and follow [persistence](persistence.md). Deliver at least once with exponential backoff/jitter, maximum 24 hours by default, then dead-letter an opaque reference for operator replay. Rate-limit recurrence events without losing aggregate counts. Consumers deduplicate by `(source,id)`. A failed webhook does not roll back evidence collection or grant revocation. Avoid promising exactly-once delivery.

### SC-EVT-002

Given a receiver that acknowledges then drops its connection before the sender sees the response, when Asservat retries, then the event ID is unchanged. Evidence remains committed and the outbox accurately reports the uncertain delivery.

The [internal interfaces](../docs/architecture/interfaces.md) refine these rules into the hub/connector and collector-to-connector protocols, strict purpose-bound control DTOs and separate transient live exchange. Work and start identities follow [REQ-ARC-003/004](implementation-architecture.md); protocol acceptance is not proof of action start or evidence commit.
