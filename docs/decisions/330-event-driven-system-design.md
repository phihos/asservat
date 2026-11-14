# ADR-330 — Event-driven system design

Date: 2026-11-14. Status: accepted (maintainer decision: "No polling if
avoidable! Highly dynamic environments are event driven for a reason";
"audit the spec for shoddy systems design and fix it"). Implements the
verdicts of [the security evidence review](../reviews/security-evidence-2026-11-13.md)
and supersedes every earlier ADR, specification or architecture passage
that contradicts the decisions below. The audit behind it is in
[the system design review](../reviews/system-design-review-2026-11-14.md).

The product capabilities the maintainer selected (see AGENTS.md "Authority
and invariants") are unchanged. This record changes how they are built.

## Decisions

### D1 Events instead of polling

- Kubernetes state comes from shared informers (LIST once, then WATCH) in
  the process that needs it. A cache stays valid until the watch replaces
  or invalidates it; it does not expire merely because time passed. A
  watch failure marks the cache unavailable until the relist completes.
  Precedent: client-go informers; every Kubernetes controller.
- Remote cluster state the hub needs (namespaces, workloads, Pods,
  EndpointSlices, AccessBindings, permission sources) is pushed by the
  connector over its hub connection when it changes; after a reconnect the
  connector compares a digest and resends only on mismatch. Precedent:
  Open Cluster Management work/status agents, Karmada agents, Argo CD agent.
- Hub processes signal each other with PostgreSQL `LISTEN/NOTIFY` issued in
  the writing transaction; after a reconnect a listener catches up with one
  query. A slow safety resync needs a stated reason.
- Trigger detectors use watch events, `pods/log?follow=true` streams and the
  Alertmanager webhook receiver. Only sources without events
  (metrics.k8s.io) are sampled, at their configured interval.
- Browsers receive progress, status and live rows over one Server-Sent
  Events stream per page. MCP status tools wait server-side (bounded, at
  most 30 s) and return on the first change instead of being re-called in
  a loop. Polls are never charged.

### D2 One connector connection

Each connector holds one outbound, multiplexed HTTP/2 (or gRPC) connection
to the hub with mutual TLS. Commands, cluster-state pushes, live rows and
download bytes are streams on that connection; the hub routes to whichever
replica holds the connection through a SQL row naming that replica, or the
connection is opened to every replica. No standby socket pools, owner relay
protocol, per-process routing proofs or signed (JWS) work envelopes.
Precedent: Kubernetes konnectivity, OCM cluster-proxy, Rancher
remotedialer.

### D3 Standard identity

- One installation CA (cert-manager or Helm-generated) issues the hub
  replicas' serving/client certificates; replicas use plain mTLS.
- Each cluster has one connector identity: a bootstrap token issues the
  first certificate, then the connector rotates it with a certificate
  signing request before expiry. Precedent: kubelet TLS bootstrapping, OCM
  cluster registration.
- In-cluster Asservat workloads (collector, download/query readers)
  authenticate with an audience-bound projected ServiceAccount token
  checked once per connection by TokenReview, then mTLS or the established
  session. Precedent: Vault/OpenBao Kubernetes auth method.
- Removed: per-process enrollment, registration and activation tables,
  certificate audits, signing budgets, process self-proofs.

### D4 Long-running readers instead of a Job per request

Downloads and stored-evidence queries are served by a scaled, long-running
regional reader Deployment (a hub Deployment in combined mode). It receives
work over its connection, streams the bytes and can be scaled by replicas.
No Kubernetes Job, certificate or key slot per download or query.
Precedent: Loki/Tempo/Pyroscope queriers, Thanos store gateway.

### D5 Authorization once per operation

One authorization per public operation, reused for at most
`identity.AuthorityRecheckInterval` (30 s; 60 s for the shared policy
observation) and never past the original deadline (ADR-311). A started
stream runs to its original bounds (ADR-312); Stop, revocation and
retention cut-offs reach it as events (D1). No five-second windows, no
per-hop, per-chunk, per-frame or per-window rechecks, no proof bundles
re-verified inside each effect transaction. Five seconds remains only as
an I/O timeout.

### D6 Audit as a database row

A security-relevant operation writes one append-only audit row in the same
PostgreSQL transaction as its effect; the operation fails if the row
cannot be written. Rows are exported in batches to the object store or a
SIEM, and retention drops whole time partitions. No per-event envelope
encryption, intent/outcome object pairs, acknowledgement roles, audit
prepayment or deletion certificates. Precedent: Kubernetes audit backends,
GitLab `audit_events`, PostgreSQL partitioning.

### D7 Idempotency instead of spent-on-uncertain

Every effect carries a client- or hub-generated operation ID stored with
it. A retry with the same ID returns the existing outcome; an unknown
outcome is resolved by looking the ID up, and charges are released when
the outcome is known. Quotas are per-workload counters changed with
conditional updates that lock only the affected workload row (plus one
pool row only when burst limits apply). No never-refunded charges,
prepaid renewals, WAL/backup prepayment, or second charge ledgers in
object storage or Kubernetes objects. Precedent: Stripe and IETF
`Idempotency-Key`, Kubernetes ResourceQuota.

### D8 Small metadata in SQL

Plans, settings, reasons, filters, previews and other small metadata are
ordinary SQL rows under the existing authorization (encrypted at rest by
volume/backup encryption). Evidence bytes stay envelope-encrypted in the
object store (maintainer requirement). No per-record object-store
envelopes for metadata, no CRDs per attempt or delivery
(CapacityReservation, DeliveryWork).

### D9 Stateless previews

A preview is a dry run that returns the resolved plan and its digest.
Submitting it with an idempotency key and the digest either accepts that
plan or reports what changed. No server-side preview handles, handle caps,
expiry or close/accept recovery tools.

### D10 Kubernetes-native status

Policies and other CRDs use `metadata.generation`/`status.observedGeneration`
and conditions; changes are attributed by the Kubernetes audit log. No
hub-signed submission envelopes, intent versions or source-intent digests.
The execution digest that lets approvals survive label or sharing edits
stays.

### D11 Simple permission continuity

Audiences and share managers are recorded as stable identity-provider
group IDs (and subjects). No assignment-ID continuity, A→B→A proofs or
suspension after a relist. AccessBindings follow ADR-329.

### D12 Retention as stored deadlines

Each artifact row stores its effective deletion deadline. A retention
policy change applies the shorter deadline with one SQL update per affected
set when the policy event arrives (D1); deletion runs from those
deadlines. No watch watermarks, checkpoints, catch-up pages, topology
pins or retention proofs inside effect transactions.

### D13 No installer-era machinery

Specifications and architecture describe the Helm-native installation
(ADR-327/328): no installer Pods, journals, witnesses, UID pins, dry-run
or access-review probes, guard qualification or historical-value review.

## Consequences

- The specifications and architecture documents are rewritten to these
  decisions; obsolete architecture documents are deleted.
- The code does not yet implement most of this. Implementation proceeds in
  slices tracked in docs/implementation-progress.md, starting with the
  hottest paths (connector transport and pushes, downloads/readers, audit
  rows, authorization windows).
- Every new timer loop, periodic full resend or expiry-driven refresh must
  justify in its PR why no event source works (AGENTS.md).

## Complexity gate

1. Problem: measured — 1.2 MiB/s downloads, 28+6 API calls and 1.4 s per
   remote metadata read, ≤512 GETs/64 MiB per trigger cycle per cluster,
   5 s/20 s deadline failures in installed runs.
2. Not previously accepted by the maintainer; the maintainer asked for it.
3. Typical deployments benefit (all hot paths).
4. Precedents named per decision.
5. No new privileges; fewer credentials and SQL logins.
6. Fewer failure states (removes standby, expiry and uncertain-spend states).
7. No new configuration.
8. Standard Kubernetes/PostgreSQL behavior only.
9. Costs fall from per-interval × objects to per-change.
10. Unreleased product; no compatibility layer.
11. A smaller fix (tuning intervals) would keep the scaling problem.
