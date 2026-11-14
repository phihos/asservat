# Hub persistence and recovery

PostgreSQL is the single production hub state backend (ADR-023). Kubernetes remains the configuration API; regional object storage holds encrypted evidence and exported audit batches. Mechanisms follow [ADR-330](../docs/decisions/330-event-driven-system-design.md). Isolated [transaction experiments](../docs/research/feasibility-control-crash.md) support selected invariants.

## REQ-DB-001 — One authority for each field

Configuration authority stays in Kubernetes: recipes, policies, presets, permission bindings/sources, retention policies, storage pools, budget policies and collection ceilings. SQL stores accepted projections with source cluster/namespace/resource UIDs, opaque resourceVersion, generation, canonical digest and deletion marker. Projections are maintained from informer events (hub cluster) or connector pushes (workload clusters). A projection stays valid until a later event replaces it; a source becomes available once its informer has synced, and a watch failure marks it unavailable until the relist completes. Never compare resourceVersions numerically or across resources. SQL projections are not writable configuration APIs.

A DebugCapture CRD is a request envelope. Its accepted execution lives in SQL, uniquely keyed by source cluster/request UID/generation. Browser/MCP submissions use the existing authenticated request service and a principal/client-scoped idempotency key. CRD status projects acceptance and progress through `status.observedGeneration` and conditions; deleting the request or namespace does not delete evidence, outstanding charges or revocations. Disconnected work uses the connector's local budget and unexpired permits, never a second hub database.

AccessGrant, EvidenceShare, policy acceptances, capacity accounts and reservations, cluster records and work items are SQL runtime records, not CRDs. Their portable DTOs use `schemaVersion`, `kind`, `id`, `spec` and `status`; `spec` describes accepted scope and does not make them kubectl resources. No CRD exists per attempt, reservation or delivery; each connector keeps one local checkpoint object, bounded by the Kubernetes object size limit and its budget contents (REQ-FED-002, REQ-CAP-005). Secrets are references, not database content.

Audiences and share managers are recorded as group names and subjects of the installation's issuer (ADR-335 D4). AccessBindings are keyed by object UID and generation and recomputed on relist ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)); bindings that exist before the hub's first start take effect from its first list like any later relist, with no separate initial review.

### SC-DB-001

Given a namespace is recreated or the hub restores an old configuration projection, when authorization resumes, then informers have relisted and current source UIDs and deletions are applied first. An old accepted request is not executed again and namespace deletion does not release charges.

## REQ-DB-002 — Relational state and invariants

Use PostgreSQL 18 as the initial qualification baseline, supported patch releases pinned in release metadata. No mandatory extensions, broker, SQLite production mode or interchangeable Kubernetes state backend. Use ordinary typed columns and foreign keys for authority/accounting; JSONB is only for versioned, validated plan/configuration shapes, which come from CRDs and are bounded by the Kubernetes object size limit (1.5 MiB). Plans, settings, reasons, filters and previews are ordinary SQL rows under the existing authorization, protected at rest by volume and backup encryption; reasons are bounded by the HTTP request body limit. They are deleted at their control-data deadline, which is the owning capture's evidence retention (ADR-335 D9: result handles last as long as the evidence). Evidence, full manifests and extracted text stay in the encrypted object store; full plaintext evidence hashes remain in protected manifests. Runtime DTOs are not literal table dumps.

The following logical schema is normative. TASK-02 must produce migrations and query contracts implementing it before any feature writes runtime state. UUID primary keys, bigint monotonic revisions, timestamptz deadlines and nonnegative bigint byte/object/count fields are standard. System IDs and durable uniqueness keys never depend on display names.

| Table family | Keys and relationships | Invariant / query index |
| --- | --- | --- |
| `config_projection`, `cluster` | Unique source cluster/resource UID; cluster UUID generated from the unique cluster name | Accepted digest/generation, deletion marker; cluster `revoked` flag, connection-holding replica, connection times |
| `operation`, `capture`, `action_attempt` | Unique caller/client/idempotency-key digest; unique source request UID/generation; unique capture/action/target/attempt | Request digest mismatch returns Conflict; immutable execution; never retry an ambiguous intrusive start as a fresh attempt |
| `capture_history` | Unique accepted capture ID; selector/settings digests; optional repeated-from ID | Settings snapshot in the row; selector/time/capture-ID listing with cursor pagination and current and retained audience checks; expires with the capture's case-metadata retention; never cascade-delete execution state |
| `case_record`, `occurrence` | Case UUID; unique cluster/occurrence UUID | Content-minimized signature and time/scope indexes; occurrence association does not authorize every artifact in a case |
| `artifact`, `artifact_parent`, `artifact_copy` | Artifact UUID+digest; unique parent/child; copy ID+store/version | Class, capture/action/plan, region, native size/SHA-256/format/completeness, stored effective deletion deadline; no raw paths/log text; lineage traversal is a recursive query over the acyclic derivation graph |
| `artifact_audience` | Artifact ID; issuer-qualified group name or subject | Retained access provenance; requires current entitlement, not a static SQL ACL alone |
| `access_grant`, `grant_reservation` | Grant UUID; unique grant/operation/action | Approved scope digest/revision, reserved/spent counters, expiry; concurrent use is bounded by those counters and the per-workload concurrency limits (ADR-335 D8) |
| `capacity_account`, `capacity_reservation`, `connector_budget` | Account UUID hierarchy; unique operation/attempt/dimension; one budget per cluster | Protected/burst separation, reserved+committed <= allocation; assigned amounts charged until reported or the cluster is removed |
| `policy_acceptance` | Unique policy UID/generation | Immutable creator, sponsoring group names, sharing instruction, claimed-capture counter and end; the capture row carries its own sharing instruction |
| `evidence_share`, `share_artifact`, `share_recipient` | Share UUID; unique origin (acceptance or capture)/artifact; unique share/artifact/recipient | Snapshot only, parent denial checked, no reshare; explicit artifact/class/operation coverage |
| `revocation`, `lifecycle_work`, `deletion_tombstone` | Subject UUID+revision; unique artifact/copy/action | Deny before deletion; retention never extended by replay; tombstones are retained for the backup retention, so they outlive every restorable backup |
| `audit_event` | Event ID; operation ID | Append-only, time-partitioned; written in the effect's transaction; export position |
| `outbox` (webhooks, CloudEvents), `work` | Unique event ID; work ID | Immutable payload digest; state, sent connection epoch, due_at, retry fields; no raw evidence |
| `artifact_download` | Unique actor/client/idempotency key | Exact artifact version, state, `AccessUntil`, emitted bytes ([REQ-DLD-003](artifact-downloads.md)); no filename, checksum or bytes |
| `live_watch` | Watch ID; unique opening idempotency key | Viewer/client, scope digest, display filter, idle and hard deadlines, counters ([live watch](live-watch.md)); no rows or replay queue |
| `grant_result_registration` | Unique parent grant/artifact | Verified artifact/digest and action provenance of a combined investigation grant's results; child raw grants reference the parent |

Foreign keys must not cascade away grants, revocations, charges or historical evidence when a config/capture row is removed; teardown is a lifecycle operation after dependent deadlines close. Time partitioning is used for `audit_event` retention only. Runtime-only rows of other specifications (watch state, ongoing-source sessions, assessment reason codes) live in the owning service's work/accounting rows and follow the same rules; their content is defined by the owning specification.

### SC-DB-002

Given duplicate requests, publications and completion notifications arrive concurrently, when committed, then one operation, one registration and one artifact slot exist. A reused idempotency key with another request digest is rejected; deleting configuration cannot cascade-delete accounting.

## REQ-DB-003 — Admission and publication transactions

An operation is authorized once before its transaction: identity, eligibility and recovery are observed once and carried as an immutable value valid until `min(observedAt + identity.AuthorityRecheckInterval, original deadlines)` ([ADR-311](../docs/decisions/311-operation-authority-recheck.md)). Hub admission then atomically checks SQL-native facts (revocation rows, fences, expiries), reserves grant action starts/bytes and capacity, inserts the immutable capture/action work with its optional sharing instruction (a policy capture claims a sharing slot of its acceptance), and writes its `audit_event` row and any outbox row. A pending raw-sharing approval does not block otherwise valid collection.

Use short Read Committed transactions with conditional counter updates on locked rows, in one global lock order (config/cluster, grants, pool then workload accounts, policy acceptance, shares/artifacts, operation/work), so revocation and publication cannot deadlock or interleave. No transaction holds a lock across a Kubernetes, IdP or S3 call, upload or process pause. Retry an aborted transaction until the request deadline; never retry an external side effect. An unknown COMMIT outcome is resolved by the original operation ID. Admission never reads an asynchronously lagging replica.

Check grant and permit expiry with `clock_timestamp()` **after the last lock the decision needs**: `now()` is the transaction start and would accept a grant that expired during a lock wait. Delivery reuses the operation's authority value within its validity; a started stream runs to its original bounds ([ADR-312](../docs/decisions/312-started-downloads-run-to-original-bounds.md)). Transaction success does not extend a deadline.

Publication creates the sharing instruction's concrete shares in the catalog transaction after checking current manager authority (REQ-SHR-004). Parent revocation commits a denial before child cleanup; a new delivery checks parent, child and grant revocation rows when it starts. No transaction spans PostgreSQL, Kubernetes, the IdP, object storage and a target process.

### SC-DB-003

Given two captures race for the last grant execution and protected capacity, or revoke races with publication, when transactions commit, then quotas do not overdraw and revoked scope cannot be newly disclosed. Serialization retry and lost COMMIT response neither duplicate an action nor release a reservation.

A test holds a later capacity/artifact lock until the relevant grant has expired. Admission and result publication that then acquire it must reject without spending or publishing a child; an implementation that checks expiry only at transaction start or before the later lock fails.

## REQ-DB-004 — Outbox, audit and delivery

A security-relevant operation writes one append-only `audit_event` row in the same transaction as its effect; the operation fails if the row cannot be written. A revocation or denial commits with its audit row and never waits for export. An exporter, woken by `NOTIFY`, ships committed rows in batches to the object store (encrypted per batch, Object Lock where the backend supports it) or a SIEM and records its export position; retention drops whole time partitions after export. Precedent: Kubernetes audit backends, GitLab `audit_events`.

Work and outbox writers issue `NOTIFY` in the writing transaction. Each consumer holds one `LISTEN` connection; after (re)connecting it runs one catch-up query for ready rows ordered by `due_at`. A timer exists only for the earliest known future `due_at` or claim expiry. Webhook delivery workers claim due rows with FOR UPDATE SKIP LOCKED in short transactions, set a claim expiry and release locks before side effects; existing weighted fair workload scheduling selects eligible work before claiming it, since SKIP LOCKED alone promises no fairness. Connector work follows REQ-FED-002: the replica marks it `Sent` with the connection epoch and resends non-terminal work on reconnect; the connector deduplicates by `workID`. Fencing rejects stale results but cannot undo a command already started; unknown starts become Indeterminate and stay charged until their outcome is known.

Each deployed process type uses one non-administrator SQL login and one connection pool; schema changes use a separate migration owner (ADR-335 D11). setup creates the logins with an administrator credential only the setup Job mounts, or the operator pre-creates them. A transaction never takes a second pool connection. The chart sets pool sizes; the defaults total at most 30 connections. Online requests use a 5-second statement timeout including lock waits (the I/O timeout of ADR-330 D5); exhaustion returns actionable pressure, never an unbounded queue. A work row is deleted once it is terminal and acknowledged.

### SC-DB-004

Given a hub replica dies after committing work and before sending it, when the connector reconnects to another replica, then that replica resends the non-terminal work, the connector returns the existing state for a known `workID` and an ambiguous dump is not rerun. A notification missed during a listener disconnect is recovered by the catch-up query. An audit row that cannot be written fails its operation; no action starts and no evidence is delivered.

Concurrent preparation creates one immutable execution, and a revocation committed while preparation waits for a lock prevents its effect.

## REQ-DB-005 — Durability, outage and disaster recovery

Production requires a qualified primary/replica/failover profile preserving acknowledged security/accounting commits within its declared failure model, synchronous commit where required, durable storage and fencing of the old primary. Never silently fall back to asynchronous acknowledgement. Managed PostgreSQL or an operator-managed service is supported after qualification; CloudNativePG is optional. A single-instance evaluation deployment must clearly lack the production availability claim. No per-node or workload-cluster database is required. A PostgreSQL restart without restore needs no recovery step.

Primary unavailability denies new central authorizations, share publication and evidence disclosures. Already authorized local work continues only under the connector's local budget and unexpired permits; retention deletion continues locally.

Restore uses the chart's `recovery` value and the [restore runbook](../docs/installation/helm.md#restore) (ADR-335 D10). With `recovery.enabled: true` and a `recovery.restorePoint`, `helm upgrade` scales hub-api, hub-worker and the local connector to zero, restores bundled PostgreSQL from pgBackRest to that point (an external database is restored with its provider's tooling first) and runs setup's recovery step. The step:

1. re-applies the revocations, cluster removals and deletions recorded in exported audit batches after the restore point;
2. deletes all browser and MCP sessions, so everyone signs in again;
3. recomputes committed usage per workload from the bucket inventory and marks artifacts whose objects are gone as deleted.

It is idempotent; setup records its completion, and a following `helm upgrade` without `recovery` starts the workloads only after that record exists. Workloads never run during restore, so they need no recovery flag of their own. Connectors report their usage on reconnect as after any disconnect and receive a replacement budget (REQ-CAP-005). Stored deletion deadlines keep expired evidence unavailable.

SQL backups/WAL contain no evidence payload, extracted text or full manifests. Control rows are protected by volume and backup repository encryption (pgBackRest repository encryption), access limits, approved finite metadata retention and the backup retention (`services.postgres.bundled.backup.retention`, default 14 days). Deleting a row cannot erase old backups; privacy notices state the backup retention as the time deleted control data may persist (REQ-PRV-008). Restore excludes expired information before serving it, and expired backup sets are deleted by the repository's retention; do not claim GDPR compliance from encryption. Exported audit batches are retained at least as long as the backup retention, within their own approved finite purpose. Payload search stays in region under evidence expiry, outside ordinary PostgreSQL backups. Restore gating prevents disclosure but does not itself delete bytes from old backups.

Migrations run in the Helm `setup` Job as the migration owner under an exclusive lock; runtime roles have no DDL rights. Migrations are expand/contract so the previous minor release runs on the current schema and `helm rollback` to it works (REQ-DEP-004). Readiness rejects an unsupported schema version. Database connections use TLS 1.2 or newer (RFC 8996) verified against the system trust store or the optional `caBundle`. Monitor connection pressure, lock waits, queue age, backup age and disk headroom, without evidence-bearing SQL logs.

### SC-DB-005

Given a restore from an older backup, when recovery runs, then revocations recorded in exported audit after the restore point are re-applied, old sessions no longer work, connector budgets are reconciled from reported usage, accounting matches the bucket inventory and deleted or expired evidence stays unavailable. Serving resumes only after the recovery step completed and `recovery` is unset; a failover without restore needs no recovery step.

## Projections owned by other specifications

[Capture history](capture-history.md) and [capture profiles](capture-profiles.md) are access-controlled SQL projections of accepted executions and Kubernetes sources, not second authorities. A history snapshot is written in the capture's admission transaction and expires with the capture's case metadata; expiry cannot remove active accounting, approvals or required audit, and repeat lineage never cascades from an expiring history row. A restore never revives an old watch, ongoing source or expired authority.
