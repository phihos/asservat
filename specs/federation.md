# Federation and events

Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md): one outbound connector connection, pushed cluster state and SQL-signalled work. The hub maintains a standing registration per cluster. Connectors authenticate using their own cluster's projected ServiceAccount tokens. [ADR-334](../docs/decisions/334-connector-workload-identity.md).

## REQ-FED-001 — Registration and trust

An Asservat administrator registers a workload cluster in the hub's values with public data only: a unique `name`, the cluster's ServiceAccount token `issuer`, optionally its public `jwks` when the hub cannot reach the issuer, and optionally the connector's namespace/ServiceAccount (default: the release namespace and `<name>-connector`). The hub generates the cluster UUID from the name (ADR-335 D4); operators, policies and the console refer to clusters by name. Registering, changing or removing a cluster takes effect on `helm upgrade` of the hub without reinstall, and the number of clusters is bounded only by the installation's sizing (each cluster costs a connection and its pushed state), not by an install-time count. Nothing is copied from the hub to the workload cluster; the hub never stores a cluster kubeconfig or a reusable bearer credential, and no callback URL, inbound node service exposure or hub-stored cluster-admin credential is required.

For each registered cluster the hub sizes its listener from the connector's concurrent exchanges and reserves that cluster's configured capture capacity. Operators supply a cluster registration once. Routing, permission reconciliation and download-path selection cover every registration, including clusters sorted last. Each rendered configuration must fit in its Kubernetes object. [ConfigMap limits](https://kubernetes.io/docs/concepts/configuration/configmap/#motivation).

The connector authenticates every request on its hub connection with a projected, kubelet-rotated ServiceAccount token whose audience is the hub URL. The hub verifies its signature (through OIDC discovery of the issuer, cached and refreshed on an unknown `kid`, or the static JWKS), `iss`, `aud`, expiry and `sub = system:serviceaccount:<namespace>:<account>`, and attributes the connection to that cluster; any other subject, issuer or audience is refused. The hub needs no access to the member cluster. The hub's values are the only registration path: there is no console page, API operation, CLI command or join token. Where the hub is exposed by TLS passthrough, connectors may additionally use client certificates the hub signs for a CSR authenticated by the ServiceAccount token (ADR-334, optional). A restarted or re-installed connector reconnects with a new token at any time; a failed first connection does not consume the cluster's registration. Removing or revoking a cluster rolls out a federation that refuses its tokens. Before serving, federation deletes the withdrawn cluster’s last AccessBinding delivery and suspends its permission stream in the same transaction. The permission reconciler resumes with the current deliveries. A later registration under that name supplies its own AccessBindings. Precedent: Vault/OpenBao JWT auth with a Kubernetes issuer, cloud workload identity federation.

Local cluster configuration names the hub URL (`hub.url`), trusts the hub's certificate through the system roots or a public `hub.caBundle`, and sets a maximum collection policy. The hub's settings the connector needs (installation and cluster IDs, protocol capabilities, limits) arrive on connect. On each authenticated work-stream reconnection the running connector refreshes the evidence and history credentials together before handling work. Hub commands are versioned and end at the admission's original hard end (ADR-311/312; no separate TTL), travel over the authenticated connection and are checked against the local ceiling. In-cluster Asservat workloads (node collectors, regional readers) authenticate to the connector with an audience-bound projected ServiceAccount token checked by TokenReview once per connection. Work is bound to the Kubernetes node UID; a new node does not inherit an old node's work. Regional Pods receive no hub SQL credentials.

The hub-worker accepts each distinct owner configuration generation and records its audit event in one PostgreSQL transaction. The event identifies the installation, cluster, source UID and generation, and carries the SHA-256 digest of the accepted snapshot. A failed insert rolls back the revision. Re-observing the same generation records no duplicate event. Startup and enrollment use the committed revision under its original source identity and generation. An initial named ConfigMap list and subsequent watch events drive acceptance. Confirmed removal or invalidation fences the head. Each operation retains its caller deadline and five-second owner observation window, capped by the original issuer certificate expiry. Historical object receipts remain immutable in SQL; migration records whether each revision had been acknowledged.

### SC-FED-001

Given a token from another cluster's issuer, another ServiceAccount or another audience, when a connection is attempted, then it is refused and no identity is substituted. A hub request cannot widen a locally denied namespace. A connector restarted hours after the install reconnects without operator action. After an administrator removes or revokes a cluster, its next request fails and its open connection is closed. Registering one more cluster with `helm upgrade` works without reinstall.

## REQ-FED-002 — Durable outbound work and compatibility

Each connector holds one outbound, multiplexed HTTP/2 connection to one HTTPS hub URL, the console's public endpoint or a separate host name, through any Ingress or Gateway, including one that terminates TLS. Commands, cluster-state pushes, events, results, live rows, evidence uploads and download bytes are streams on that connection; the hub writes uploaded evidence, already encrypted on the node, to the object store. A SQL row names the hub replica that holds a cluster's connection; other replicas route to it. Internal payloads use versioned JSON contracts; this is an implementation protocol, not a new external agent interface.

The connector pushes the cluster state the hub needs (namespaces, workloads, Pods, EndpointSlices, AccessBindings, permission sources, namespace CaptureProfiles and local retention policies) from its informers when it changes. It also runs the trigger detectors on those informers, `pods/log?follow=true` streams and its Alertmanager webhook receiver, and pushes only occurrences ([triggers](triggers.md)). After an authenticated reconnect, executor and delivery-only connectors compare the current AccessBinding digest with the hub. A missing or changed digest transfers the complete delivery, including when the regional bindings themselves stayed unchanged through withdrawal and re-registration.

The hub stores active work in SQL and signals the connection-holding replica with `NOTIFY` in the writing transaction; that replica sends the work on the connection. Each work item binds `workID`, `operationID`, cluster UUID, target and plan digests, the authorizing grant/reservation and an expiry equal to the admission's original hard end. Delivery is at least once. Work transitions are `Queued → Sent → Running → terminal`. After a reconnect the hub resends every non-terminal item. The connector records each accepted `workID` in its local state before any intrusive start and keeps it until the hub acknowledges the item's terminal state; it deduplicates resent work against it and reports the current state. In-flight work is bounded by the concurrency limits (ADR-335 D8), so this state needs no count cap. Intrusive work that may have started stays `Indeterminate` until the connector reports the outcome for that start. Result references survive reconnects.

Liveness is the open connection. The hub records `connected_since` and `disconnected_at` on connection events; there is no periodic last-seen write, and a crashed replica's connection rows are released with its Lease. The console shows a cluster as offline once its connection has been closed for twice the connector's maximum reconnect backoff, which suppresses flapping; this is a display status, not an authority bound. Started sources run to their admitted hard ends while disconnected, and pending stops are delivered on reconnect. Policy acknowledgements are visible as `status.observedGeneration`.

The hub and workload clusters can upgrade in either order. The hub checks the connector's wire protocol major on every lifecycle opening, including binding delivery and unchanged-digest confirmation. It checks the connector's advertised capabilities before sending each request. A missing or different major returns HTTP 426 identifying both protocol versions. New capabilities may be advertised within the Hello frame's byte limit. An unsupported request fails explicitly and other supported work continues. A new optional field can be ignored. A field that changes required behavior needs an advertised capability. The release qualification matrix covers adjacent minor releases in each direction within one protocol major.

An idle connector subscribes for work over its outbound HTTP/2 connection.
When a hub request needs a regional exchange, the connector opens one to the
requesting hub replica. Federation resolves the registered owner to its ready
endpoint addresses within the original deadline, and the connector authenticates
that owner. Waiting for an exchange and using it share the original caller deadline. A replica that sees demand from another replica releases its exchange after its current query, including when the exchange is still opening. Sequential queries share the exchange's existing time and byte bounds. Reconnection announces only work whose caller is still
waiting. Notifications carry routing information. Each operation retains its
original identity, authorization and deadline.

### SC-FED-002

Given work resent after a network break, when the connector reconnects, then it returns the prior operation state and does not rerun the intrusive action. When the connector omits a capability a request needs, the hub refuses that request before sending it. A newer connector advertising additional capabilities can still receive supported work.

## REQ-FED-003 — Locality and partial availability

Each storage/analysis profile MUST declare its region/locality boundary. Evidence is encrypted on the node before it leaves; it is stored in its region's object store (by default the hub's, which receives uploads over the connector connection) and decrypted only by that region's readers. The hub may broker only currently authorized bounded query results and permitted metadata. A hub database outage denies new central authorizations and disclosures; local execution under the connector's local budget and unexpired permits, and deletion, continue within their limits. A disconnected cluster remains visible with stale-data indicators; the hub cannot claim fresh capability, completed collection or a current query from it.

While disconnected, metadata events queue in memory (connector memory request ÷ event size) with drop/gap counters, and encrypted evidence waits in the local spool volume (`emptyDir.sizeLimit` or PVC). Disconnected work spends only the connector's local budget ([capacity](capacity.md)) under unexpired permits ([authorization](authorization.md)); an upload retried after reconnect reuses its operation's object key.

### SC-FED-003

Given a hub outage during collection, when local control remains healthy, then already authorized evidence is kept encrypted within its local spool reservation and uploaded after reconnect under its original operation key; evidence that does not fit is reported as a gap. A remote raw query reports `ClusterOffline`, and expired permits cannot start new dumps.

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

Sign exact request bytes with Standard Webhooks `webhook-id`, `webhook-timestamp`, `webhook-signature` headers and operator-managed rotating secrets. Enforce recipient-specific cluster/workload event scope, destination allowlist, HTTPS, no redirects, a pinned DNS resolution per delivery and SSRF restrictions (Standard Webhooks practice). Do not accept a webhook URL from a capture request. [CloudEvents](https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md), [dataref extension](https://github.com/cloudevents/spec/blob/main/cloudevents/extensions/dataref.md), [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).

### SC-EVT-001

Given a case containing a token in its log/filename/reason, when events are delivered, then that content is absent from the payload and headers. Retries preserve the CloudEvent ID and verify with the rotated webhook key.

## REQ-EVT-002 — Delivery outbox

Events MUST be SQL outbox rows committed with their hub case/grant/share transition. Only the hub emits CloudEvents: connectors forward event facts over their connection and the hub records them in its outbox. Delivery workers are woken by `NOTIFY` and follow [persistence](persistence.md). Deliver at least once with exponential backoff/jitter, maximum 24 hours by default (the Standard Webhooks reference retry schedule; administrator-configurable; outbox rows grow with it), then dead-letter an opaque reference for operator replay. Rate-limit recurrence events without losing aggregate counts (storm protection, default derived from cluster size, ADR-335 D8). Consumers deduplicate by `(source,id)`. A failed webhook does not roll back evidence collection or grant revocation. Avoid promising exactly-once delivery.

### SC-EVT-002

Given a receiver that acknowledges then drops its connection before the sender sees the response, when Asservat retries, then the event ID is unchanged. Evidence remains committed and the outbox accurately reports the unknown delivery outcome.

The [internal interfaces](../docs/architecture/interfaces.md) refine these rules into the hub/connector and collector-to-connector protocols, strict purpose-bound control DTOs and separate transient live exchange. Work and start identities follow [REQ-ARC-003/004](implementation-architecture.md); protocol acceptance is not proof of action start or evidence commit.
