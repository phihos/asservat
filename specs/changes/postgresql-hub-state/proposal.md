# PostgreSQL for hub operational state

Date: 2026-10-09. Status: **accepted by the user; integrated into the specifications, not implemented**. ADR-023 supersedes ADR-004's prohibition on a mandatory database. ADR-018's Kubernetes-only permission-configuration interface remains applicable. The following records the reassessment; [hub persistence](../../persistence.md) defines the accepted state and recovery contracts. Where this record conflicts with [ADR-329](../../../docs/decisions/329-accessbindings-in-application-namespaces.md) or [ADR-330](../../../docs/decisions/330-event-driven-system-design.md), those decisions apply; the ownership table below is updated accordingly.

## Recommendation and scope

Accepted recommendation: use one PostgreSQL database for the hub's transactional operational state and catalog indexes, Kubernetes CRDs for declarative configuration and bounded local execution control, and regional object storage for encrypted evidence, manifests and durable audit records. Require PostgreSQL for the production hub; do not build two interchangeable production state backends. Workload clusters and node collectors do not connect to PostgreSQL and do not need their own database server. No message broker is required.

The engineering recommendation is to switch before implementation. There is no deployed datastore or evidence migration to perform in this greenfield repository. A database adds operational work, but the expanded quota, grant, sharing, lifecycle and discovery requirements make the current application-level coordination more complex than the original dependency-saving decision suggests. This is a design assessment, not a measured claim that Kubernetes cannot handle the proposed load.

## Evidence behind the reassessment

Kubernetes describes CRDs as a fit for small, relatively infrequently updated declarative objects, especially where cross-object transactions are unnecessary. It discourages application/end-user/monitoring data storage in the Kubernetes API. This supports keeping policy configuration there while reconsidering application runtime records. Those guidelines are not universal performance limits. [Kubernetes custom-resource guidance](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

Kubernetes supplies optimistic concurrency for individual resources, but its ordinary create/update/patch APIs do not provide a transaction across multiple resources. The existing plan correctly accounts for that with staged reservations, fencing and reconciliation; it does not put core bytes or unbounded historical cases in CRDs. The cost is the amount of Asservat-specific coordination needed for one admission or sharing decision. [Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/#single-resource-api).

PostgreSQL can commit related records together. Correct concurrency still requires deliberate isolation and locking: its default Read Committed isolation is insufficient for some cross-record invariants, and Serializable transactions can abort and require whole-transaction retries. Use short transactions, conditional updates/constraints and documented row-lock order, with Serializable where predicate invariants require it. Do not hold database locks while uploading evidence or running a debugger. [Transaction isolation](https://www.postgresql.org/docs/18/transaction-iso.html), [explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html).

A durable SQL work table can use SKIP LOCKED to let workers claim different jobs. That mechanism is appropriate for queue consumption, not a substitute for consistent quota/authorization reads. Notifications may reduce polling latency, but a disconnected listener cannot be the durable work record. Work remains recoverable from committed rows. [SELECT locking clauses](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE), [LISTEN](https://www.postgresql.org/docs/18/sql-listen.html).

## Workflows driving the decision

The [capacity model reassessed here](../../capacity.md#req-cap-005--durable-hub-and-local-accounting) reserves pool/cluster/namespace/workload slices, plus separate grant limits, before execution. Parent allocation, attempt identity, grant spend and work creation are related facts. A SQL transaction can enforce the hub portion without leaving half-completed hub reservations for a reconciler to finish.

The [sharing model](../../authorization.md#req-shr-006--concrete-publication-and-approval-boundaries) relates owners, recipient groups, selected outputs, approvals, registered captures, artifact limits, child shares and revocations. SQL relationships and uniqueness constraints make these records easier to query and update consistently. A late publication still needs current owner/approval checks; a relational schema does not itself authorize it.

Before this switch, the [operations plan](../../../docs/operations.md) proposed up to 10,000 hub control objects, including 1,000 active shares, 500 sharing intents, quota accounts and reservations. Its separate audit sizing example is about 7.8 million calls over 90 days at one call/second, before intent/result splitting. These are planning numbers, not measured traffic or proof of overload. The concern is the combined coordination, indexing and recovery work, even if the initial Kubernetes load is manageable.

Case discovery also joins occurrences, artifact classes, expiry, retained audiences, live shares and query grants. PostgreSQL provides one relational catalog for those joins and structured pagination. Authorization must be applied before returning results, facets or counts. Full-text evidence search is separate: moving a catalog to SQL does not authorize centralizing user-bearing extracts or dropping their expiry rules.

## Accepted ownership of state

| State | Authoritative location after this decision |
| --- | --- |
| DebugPolicy, EvidenceRecipe, presets, PermissionSource, EvidenceRetentionPolicy, EvidenceStoragePool and EvidenceBudgetPolicy configuration | Kubernetes CRDs; ordinary RBAC, admission, kubectl, server-side apply and GitOps |
| AccessBinding | Kubernetes CRD in the application namespace it grants; namespace RBAC writers; observed by the regional connector through an informer (ADR-329) |
| Local CollectionCeiling and sensor readiness | Workload-cluster Kubernetes configuration and status |
| Accepted work and capacity budget held by a connector | Connector memory keyed by operation ID, rebuilt from hub work state after reconnect; no per-attempt or per-delivery CRDs (ADR-330 D8) |
| User-authored DebugCapture | Kubernetes request envelope and projected status; accepted immutable execution in PostgreSQL, keyed by cluster/request UID and generation; browser/MCP can submit through the existing authenticated capture path |
| Hub capture executions, action outcomes, cases/occurrences, content-minimized artifact catalog, lineage/copy references and lifecycle work | PostgreSQL rows with indexed identities, versions, deadlines and idempotency keys |
| Hub AccessGrant, EvidenceShare, SharingIntent, SharingRegistration, quota accounts/reservations and DeliveryWork | PostgreSQL records; controller-owned hub CRDs for these runtime records become unnecessary |
| Cluster registration and connector certificate state | PostgreSQL runtime records; locality policy stays in Kubernetes configuration |
| Encrypted cores, packet captures, profiles, files/logs, derived evidence and full manifests | Existing regional object storage and KMS boundaries |
| Content-minimized audit records | Append-only PostgreSQL rows written in the effect's transaction, exported in batches to the object store or a SIEM (ADR-330 D6) |
| Logs, packets, samples, protocol reassembly, trigger counters and rings at observation frequency | Node-local bounded pipelines, not database writes for every observation |

A field has one authority. Configuration rows in PostgreSQL are reconciled projections, not a second writable configuration store. CRD statuses are projections of accepted runtime state, not an independent runtime ledger. Deleting a request namespace must not delete historical evidence or erase outstanding quota charges.

Content-minimized catalog rows may be rebuilt from verified manifests/outcomes; live grant spend, revocations, pending reservations and consumed permits cannot safely be reconstructed from artifact bytes alone. PostgreSQL therefore becomes essential authoritative state with its own tested backup/recovery process, not merely another disposable cache.

## One concrete transaction and its boundaries

For an eligible capture, a hub transaction can check the accepted configuration revision, lock the applicable grant and allocation rows, reserve bytes/object slots/action starts, register a bounded sharing capture if eligible, insert the immutable operation and durable outbound work, then commit together. A sharing dependency that is unavailable may instead record a visible sharing failure without preventing independently authorized collection, as already specified. Unique operation keys make a request retry find the original transaction result.

The transaction does not perform the intrusive action; its audit row commits in the same transaction. A connector receives the work item with its operation ID and checks local ceilings and its capacity budget. Ambiguous execution remains Indeterminate; database commit does not imply a dump happened exactly once.

PostgreSQL does not create a transaction across itself, Kubernetes, an IdP, S3 and a process on another node. Evidence upload/manifest commit, audit persistence, verified deletion, local reservations and connector acknowledgements still need the existing idempotent state machines. Quota is released only after verified deletion. Parent allocation batching/prepaid slices remain useful to reduce central contention and tolerate short outages; a database is not placed on the natural-core pipe path.

## Configuration and permission freshness

Keep the administrator's workflow: provisioners/GitOps manage CRDs through the Kubernetes API. The reconciler records source cluster/namespace/resource UIDs, generation and normalized digest. New configuration is Ready only after the corresponding accepted state is committed and relevant collectors acknowledge it. Reject authority inferred from a stale database mirror.

Cached Kubernetes state comes from informers and stays valid until a watch event replaces it; a watch failure marks it unavailable until the relist completes (ADR-330 D1). Do not invent a global ordering across different Kubernetes resource versions. PostgreSQL does not replace the Kubernetes or identity-provider evaluators.

Application maintainers continue using the hub UI/MCP without database credentials or a management-cluster kubeconfig. The existing capture/approval/sharing service remains the application interface; adding PostgreSQL does not imply a new permission-configuration HTTP API.

## Costs, failure behavior and privacy

Operators gain a database to provision, secure, monitor, back up, restore and upgrade, plus application schema migrations and connection limits. Prefer an existing qualified PostgreSQL service with a dedicated database/role, or a documented self-hosted HA deployment. CloudNativePG is an optional integration candidate, not another mandatory product dependency or an automatic Helm installation. Its documented failover mechanisms still need qualification with Asservat's invariants. [CloudNativePG overview](https://cloudnative-pg.io/docs/current/).

For production, require a tested replication/failover profile that preserves acknowledged security/accounting transactions within its declared failure model, fences the old primary and promotes only an eligible durable replica. PostgreSQL streaming replication is asynchronous by default; asynchronous failover can lose committed work. Synchronous replication changes the durability/availability tradeoff, but does not guarantee survival of every disaster or make an arbitrary failover controller safe. Do not silently downgrade durability when a synchronous replica is unavailable. [PostgreSQL standby and replication behavior](https://www.postgresql.org/docs/18/warm-standby.html).

Authorization, revocation and quota decisions use the authoritative primary; stale replicas are not a safe shortcut. Database unavailability denies new central authorizations and evidence disclosures. Already-authorized local collection/upload continues only within existing unexpired permits, capacity and audit rules, and expires closed. Local retention enforcement must continue. Co-locating PostgreSQL with the hub does not eliminate shared infrastructure or Kubernetes-dependent failover risks.

Database backups introduce another retention boundary. Store minimal control/catalog data, not dumps, packet bytes, logs, arbitrary analysis snippets or full evidence manifests in PostgreSQL. Identity/control fields still need finite retention and protected storage. Keep payload-derived search content under its existing regional evidence deadlines; initially retain the bounded rebuildable evidence-search cache where required, while SQL serves structured catalog queries.

A DELETE does not remove information from prior base backups/WAL archives; point-in-time recovery intentionally permits reconstructing earlier state. Backup encryption alone does not shorten retention. Minimize database contents, configure compatible finite backup/WAL retention, and gate restore on current configuration, lifecycle tombstones, revocations and accounting reconciliation. Disaster recovery must fence or invalidate pre-restore execution authority before new issuance. Never promise that restoring an older database safely recreates the latest authorization state by itself. This follows PostgreSQL's recovery mechanism and Asservat's existing privacy requirements, not a new legal-compliance claim. [Continuous archiving and recovery](https://www.postgresql.org/docs/18/continuous-archiving.html), [existing copy/restore requirements](../../privacy.md#req-prv-004--delete-every-managed-copy-and-report-failures).

## Alternatives

| Option | Assessment |
| --- | --- |
| Kubernetes + object storage only | Retains the smallest dependency count. Feasible with strict bounds, CAS protocols and reconciliation, but makes Asservat own more transaction coordination and catalog/index recovery. Reasonable for a materially smaller product. |
| Kubernetes configuration + PostgreSQL runtime state + object storage | Recommended for the comprehensive central platform. Adds database operations while simplifying related hub-state updates and queries. |
| PostgreSQL for configuration and runtime state | Loses the existing Kubernetes-native provisioning workflow unless a second authoring layer is built. No need to make this additional change. |
| Optional Kubernetes/PostgreSQL production backends | Two concurrency, authorization and recovery implementations plus twice the failure-testing burden. Not recommended. Development should use the same PostgreSQL state model. |

The proposal preserves the absence of a mandatory broker, external search service, workflow engine or SaaS. It does not remove admission quotas, row/history limits, fair scheduling or measured scale envelopes merely because database storage is available.

## Integration and remaining implementation gates

Affected existing requirements: REQ-CAP-005; REQ-AUT-004 and REQ-AUT-005; REQ-SHR-004, REQ-SHR-005, REQ-SHR-006 and REQ-SHR-007; REQ-EVD-002, REQ-EVD-004 and REQ-EVD-006; REQ-PRV-004; REQ-PER-006, REQ-PER-007 and REQ-PER-008; REQ-FED-001, REQ-FED-002, REQ-FED-003 and REQ-EVT-002; REQ-API-001 and REQ-API-002. Preserve their security/resource outcomes while replacing the applicable hub persistence mechanism.

Integrated in this specification revision: the resource inventory and runtime DTO/CRD split; [logical SQL tables and transaction/recovery contracts](../../persistence.md); schemas/examples/traceability; agent guidance, technology, operations and privacy documentation; TASK-02/03/07/08/11. Active application limits remain until measurements justify changes. Production SQL migrations, query implementation and all runtime mechanisms remain unchecked implementation work.

The revised validation plan extends EXP-10/11/12/18/19 with concurrent final-capacity races, grant revocation against delivery, duplicate work, partial S3/audit commits, watch outages/deleted sources, database partitions/failover, old backup restore and lost/ambiguous connector acknowledgements. The chosen failover profile must not reopen revoked access, replay intrusive actions or create unbacked capacity. Test under the existing initial envelope (10 clusters, 100 nodes, 1,000 selected containers, 200 policies; 1 occurrence/second sustained and burst 100 over 10 seconds) and report admission latency, transaction retries/locks, API traffic, recovery behavior and operator effort. No benchmark, PostgreSQL deployment or failover test has been run for this reassessment.
