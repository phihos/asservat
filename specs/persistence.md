# Hub persistence and recovery

PostgreSQL is the single production hub state backend (ADR-023). Kubernetes remains the configuration API, with bounded cluster-local execution control; regional object storage holds encrypted evidence and durable audit. This is a design contract; isolated [transaction experiments](../docs/research/feasibility-control-crash.md) support selected invariants. Initial [custody transactions](../docs/architecture/custody-transactions.md) now implement protected storage backing, copy registration, unpublished receipts and deletion fencing. Full capture admission, durable object audit, catalog publication and the production recovery profile remain unqualified.

## REQ-DB-001 — One authority for each field

Configuration authority stays in Kubernetes: recipes, policies, presets, permission bindings/sources, retention policies, storage pools, budget policies and collection ceilings. SQL stores accepted projections with source cluster/namespace/resource UIDs, opaque resourceVersion, generation, canonical digest, deletion marker and freshness deadline. Reconcile a complete watch/relist boundary before marking an uncertain source Ready. Never compare resourceVersions numerically or across resources. SQL projections are not writable configuration APIs.

A DebugCapture CRD is a request envelope. Its accepted execution lives in SQL, uniquely keyed by source cluster/request UID/generation. Browser/MCP submissions use the existing authenticated request service and a principal/client-scoped idempotency key. CRD status projects acceptance and progress; deleting the request or namespace does not delete evidence, outstanding charges or revocations. Local accepted execution/permit records remain bounded and fenced; disconnected work uses prepaid authority, never a second hub database.

AccessGrant, EvidenceShare, SharingIntent, SharingRegistration, central CapacityAccount/CapacityReservation, cluster enrollment and hub DeliveryWork are SQL runtime records, not CRDs. Their portable DTOs use `schemaVersion`, `kind`, `id`, `spec` and `status`; `spec` describes accepted scope and does not make them kubectl resources. Cluster-local permits, capacity slices, analysis work and local DeliveryWork remain bounded Kubernetes records. Secrets are references, not database content.

For permission audience assignments, a relist cannot prove that no intervening ownership change occurred. Reconciliation must establish continuous trusted history or invalidate uncertain assignment IDs under REQ-PER-008; current value/digest equality is insufficient. The [initial Kubernetes reader](../docs/architecture/permission-observation.md) supplies observations only, not those accepted SQL records.

### SC-DB-001

Given a namespace is recreated or the hub restores an old configuration projection, when authorization resumes, then current source UIDs/deletions and freshness are reconciled first. An old accepted request is not executed again and namespace deletion does not release uncertain charges.

## REQ-DB-002 — Relational state and invariants

Use PostgreSQL 18 as the initial qualification baseline, supported patch releases pinned in release metadata. No mandatory extensions, broker, SQLite production mode or interchangeable Kubernetes state backend. Use ordinary typed columns and foreign keys for authority/accounting; bounded JSONB is only for versioned, validated non-secret plan/configuration shapes. Sensitive resolved commands, free-text reasons and full plans use encrypted, scope-bound object records with explicit control-data deadlines; SQL keeps their references/digests. SQL content lookup digests are keyed or ciphertext digests; full plaintext evidence hashes remain in protected manifests. Do not put evidence, full manifests, raw commands/arguments, arbitrary user reasons or extracted text in SQL. Store protected object references and digests for sensitive fields. Runtime DTOs can join authorized encrypted records; they are not literal table dumps.

The following logical schema is normative. TASK-02 must produce migrations and query contracts implementing it before any feature writes runtime state. UUID primary keys, bigint monotonic revisions, timestamptz deadlines and nonnegative bigint byte/object/count fields are standard. System IDs and durable uniqueness keys never depend on display names.

| Table family | Keys and relationships | Invariant / query index |
| --- | --- | --- |
| `config_projection`, `cluster` | Unique source cluster/resource UID; cluster UUID; enrollment epoch | Accepted digest/generation, deletion/freshness; identity revocation and current fence |
| `operation`, `capture`, `action_attempt` | Unique caller/client/idempotency-key digest; unique source request UID/generation; unique capture/action/target/attempt | Request digest mismatch returns Conflict; immutable execution; never retry an ambiguous intrusive start as a fresh attempt |
| `capture_history`, `capture_settings_reference` | Unique accepted capture ID; scope-keyed selector/settings digests; protected object reference and content digest; optional repeated-from ID | Bounded selector/time/capture-ID listing with current and retained audience checks; independent summary/settings expiry; never embed full parameters in SQL or cascade-delete execution state |
| `case_record`, `occurrence` | Case UUID; unique cluster/occurrence UUID | Content-minimized signature and time/scope indexes; occurrence association does not authorize every artifact in a case |
| `artifact`, `artifact_parent`, `artifact_copy` | Artifact UUID+digest; unique parent/child; copy ID+store/version | Commit state, class, capture/action/plan, region, access cutoff, deletion deadline; no raw paths/log text; bounded lineage traversal |
| `audience_assignment` | Artifact/assignment ID; issuer-qualified subject reference | Retained access provenance and source digest; requires current entitlement, not a static SQL ACL alone |
| `access_grant`, `grant_reservation` | Grant UUID; unique grant/operation/action | Approved scope digest/revision, reserved/spent counters, expiry; <=64 active reservations |
| `capacity_account`, `capacity_reservation`, `allocation_slice` | Scope UUID hierarchy; unique operation/resource dimension; unique parent/child/fence | Protected/burst separation, reserved+committed <= allocation; prepaid slices charged at parent until reconciled |
| `sharing_intent`, `manager_assignment`, `selection_approval` | Intent UUID; stable manager assignment; unique intent/selection | Immutable creator and scope digest, pinned managers, revisions/expiry, current authority; raw approval distinct human |
| `sharing_registration`, `publication_slot` | Unique intent/capture; unique registration/artifact; unique registration/selection/artifact | Capture slot once; distinct artifact counted once across selections; child snapshot bounds |
| `evidence_share`, `share_artifact`, `share_recipient` | Share UUID; unique intent/capture/selection for automatic children; unique share/artifact/recipient | Snapshot only, parent denial checked, no reshare; explicit artifact/class/operation coverage |
| `revocation`, `lifecycle_work`, `deletion_tombstone` | Subject UUID+revision; unique artifact/copy/action | Deny before deletion; retention never extended by replay; finite tombstone retention covers restore/replay horizon |
| `audit_reference`, `outbox`, `work_lease` | Unique operation/event/phase; work ID+generation/fence | Durable intent/result references; immutable payload digest; ready/lease/deadline/retry fields, no raw evidence |

Foreign keys must not cascade away grants, revocations, charges or historical evidence when a config/capture row is removed. Referential teardown is a lifecycle operation after dependent deadlines close. Counters enforce local CHECK constraints and transactional parent aggregates; a CHECK cannot alone enforce a cross-row sum. Partitioning is optional after measurement, not a way to drop live authorization rows. Index due work by state/due_at/id and catalog by scope/time/id, artifact/capture and intent/capture. Query plans, cardinality and bounded history retention are release evidence.

### SC-DB-002

Given duplicate requests, publications and completion notifications arrive concurrently, when committed, then one operation, one registration and one artifact slot exist. A reused idempotency key with another request digest is rejected; deleting configuration cannot cascade-delete accounting.

## REQ-DB-003 — Admission and publication transactions

Hub admission atomically validates accepted configuration/freshness and authorization revisions, reserves grant action starts/bytes and central capacity, inserts the immutable capture/action work and optional sharing registration, and inserts durable outbox/audit references. Existing SHRs still allow independently authorized collection to proceed with explicit SharingUnavailable when sharing registration cannot be obtained. A pending raw-sharing approval does not block registration of otherwise valid collection.

Use short transactions and conditional counter updates. Lock in this order: relevant config/cluster fence rows; grants by UUID; capacity ancestors root-to-leaf and same-level UUID; intent/approval rows by UUID; registration, share and artifact rows by UUID; operation/work rows. Revocation and publication use the same order on overlapping rows. Runtime transactions must not hold a lock across a Kubernetes/IdP/S3 call, upload, analysis or process pause. External checks produce bounded-freshness evidence before the transaction, with source revisions/fences rechecked inside it. Expiry uses database time with the documented clock-skew policy; local deadlines remain monotonic.

The sole installer exception is ADR-140’s separate post-activation native guard bridge. One compiled administrator operation may retain SHARE locks on current recovery and the exact original independently acknowledged activation across its fixed native resource/journal or guard-policy CAS work. Its original at-most-five-second interval starts before pool acquisition, remains bounded after all locks and native reads, and cancellation must join the callback before releasing the lock. The facet exposes no transaction or SQL writer to the callback, performs no activation/recovery/source mutation, accepts no caller-selected code or object operations, and supplies no collection or disclosure authority. Current administrator, schema/incarnation, original activation and native enforcement checks still apply before effects and after blocking work. An unknown native result permits only the original claim’s exact lookup; SQL rollback cannot undo a completed Kubernetes operation. This exception does not change the runtime no-remote-I/O rule or imply atomic SQL/Kubernetes commit.

Use Read Committed with explicit locks/conditional writes for known-row invariants, Serializable for predicates not protected by a designated locked parent row. Retry an entire aborted transaction, bounded to three attempts with jitter within the request deadline. Retry no external side effects. An unknown COMMIT outcome is resolved by the original operation key, never a new key. Aggregate admission cannot use SKIP LOCKED or an asynchronously lagging replica. A transaction failure leaves no partial hub reservation; local/S3 effects still use reconciliation.

Evaluate grant/configuration/permit expiry against current database time **after all potentially blocking locks needed for the decision**, including later capacity or artifact locks. PostgreSQL `now()`/`CURRENT_TIMESTAMP` are transaction-start timestamps, and `statement_timestamp()` precedes a statement's lock wait; they do not establish current eligibility after contention. Use a post-lock current-time check such as `clock_timestamp()` under the qualified clock-skew policy. If additional blocking work is unavoidable after a check, revalidate before publication/permit issuance. Dispatch and delivery independently recheck current authority; transaction success does not extend a deadline.

Materialization locks the intent/approval and registration, checks current manager authority and provenance, reserves publication capacity, updates a concrete child snapshot and its revision, and enqueues audit atomically. Newly expanded scope is not readable until its durable audit commit is acknowledged. Parent revocation commits a denial/revision before child cleanup; final delivery rechecks current parent/child/grant revisions. No claim of an atomic transaction across PostgreSQL, Kubernetes, IdP, object storage and a target process is permitted.

### SC-DB-003

Given two captures race for the last grant execution and protected capacity, or revoke races with publication, when transactions commit, then quotas do not overdraw and revoked scope cannot be newly disclosed. Serialization retry and lost COMMIT response neither duplicate an action nor remove a spent reservation.

Also hold a later capacity/artifact lock until the relevant grant expires. Admission and result publication must reject after acquiring it, without spending or publishing a child. A check made only at transaction start or before the later lock is a failing implementation.

## REQ-DB-004 — Outbox, audit and delivery

SQL outbox rows are durable work, not proof of durable evidence audit. Work remains AwaitingAudit until the encrypted append-only audit intent is durably written to the qualified object backend and its reference acknowledged in SQL. Only then dispatch sensitive actions. Result disclosure also requires a durable result digest and a final current authorization check. A fail-closed revoke/deny is effective even during an audit outage; record its pending audit work durably and reconcile it, without permitting new access. Do not undo denial because audit publication failed.

Claim bounded work batches using FOR UPDATE SKIP LOCKED, then release locks before side effects. Leases include worker ID, expiry and monotonically increasing fence; completion updates require that fence. Fencing rejects stale results but cannot undo a command already started. Receivers use durable operation deduplication and local permits; unknown starts become Indeterminate and stay charged. NOTIFY is optional wake-up only; polling recovers missed notifications. Existing weighted fair workload scheduling selects eligible work before claiming it; SKIP LOCKED alone promises no fairness.

Initial tuning budgets: <=100 work items per claim, <=30-second claim lease with bounded renewal, <=5-second SQL statement timeout and <=1-second lock wait for online requests, <=32 pooled connections per hub replica with an installation-wide allocation leaving maintenance headroom. Different lifecycle batches require explicit bounded profiles. Exhaustion returns actionable pressure and does not grow queues without limits. Ordinary completed work rows expire after the replay window; authoritative denial/accounting rows have dependency-aware retention.

Same-process API execution read, preparation and recording MUST share the
fixed `api-execution` credential and cold pool under
[ADR-217](../docs/decisions/217-api-execution-role.md). Grant exactly the former
three-facet union, preserve the typed ports and current transaction checks, and
retain `MaxConns=3` under the unchanged 32-connection process governor. Keep
capture audit, connector/capacity identity pins and distinct acquisition, key,
publication and deletion duties separate. Refuse unsupported retained development
credential layouts before effects, without adoption or implicit migration.

Before provisioning the promoted installed graph, the continuation MUST compare
its compiled process/purpose allowance, including retained workers, simultaneous
installer pools, verifier and maintenance reserve, with the actual server's
ordinary connection capacity. Installer administrator pools are additional to
the migration, backup and operator reserve; early administrator connections
also consume the headroom needed for later ordinary admission. Count a shared
allowance only when the preceding pool has closed. Close the continuation's
single passive history reader before opening its administrator bridge.
Subtract both superuser and other reserved connections. Refuse an insufficient
server with fixed required/configured counts; never raise settings, broaden SQL
roles or pool limits, or infer capacity from an idle snapshot. The check remains
read-only under the original activation/incarnation and deadline checks.

### SC-DB-004

Given a worker dies after object audit upload or remote dispatch, when another claims the expired lease, then it resumes the same operation, verifies audit by digest and never blindly reruns an ambiguous dump. Missing notifications do not lose work; audit failure prevents action start and evidence delivery.

With the compiled shared API execution login, concurrent preparation still
creates one immutable execution. Current revocation committed while preparation
waits for a lock prevents its effect; a fourth concurrent pool acquisition
stays within its original caller deadline. Unrelated audit, publication, unwrap
and deletion statements remain denied.

## REQ-DB-005 — Durability, outage and disaster recovery

[ADR-098](../docs/decisions/098-first-installation-activation.md) supplies first-installation preparation/activation only. Migration 00032 retains one immutable attempt and independently acknowledged encrypted audit receipt. SQL loss after witness consumption MUST NOT create a new attempt. Final eligibility, incarnation, witness/source freshness and receipt checks precede an atomic initial activation; original deadlines remain binding after all locks. Retry of a completed attempt is read-only and must preserve later recovery blocks. No first-installation method may serve as an automatic restart/restore shortcut.

The [one-use installation witness](../docs/architecture/installation-witness.md) MUST distinguish an unused protected installation record from missing/restored SQL state. Its exact persisted claim is an irreversible prerequisite, not database activation authority. Preserve consumption after uncertain writes, expiry or downstream failure; never recreate it because SQL is empty. Its placement outside PostgreSQL does not independently protect against rollback of the entire Kubernetes control plane. Qualify retained pins/checkpoints and recovery before enabling activation.

Production requires a qualified primary/replica/failover profile preserving acknowledged security/accounting commits within its declared failure model, synchronous commit where required, durable storage and fencing of the old primary. Never silently fall back to asynchronous acknowledgement. Managed PostgreSQL or an operator-managed service is supported after qualification; CloudNativePG is optional. A single-instance evaluation deployment must clearly lack the production availability claim. No per-node or workload-cluster database is required.

Primary unavailability denies new central authorizations, share publication and evidence disclosures. Already authorized local work continues only under valid prepaid slices/permits and audit rules; retention deletion continues locally. Restore starts in RecoveryBlocked. Fence old connector epochs/primary, revoke or let every old execution permit expire, reconcile current CRDs and IdP/source freshness, replay independently retained revocation/deletion checkpoints and audit outcomes, reconcile reserved/spent slices conservatively, and then issue a new epoch. If the backup omits changes and completeness cannot be proved, invalidate all restored grants/shares/intents and require new review; unknown consumption remains charged. Never reconstruct live spend solely from stored artifacts.

An enabled flag restored from SQL is not recovery acceptance. Bind activation to the accepted database incarnation, and check that binding in ordinary authority reads and final effects. A changed or missing binding blocks authority even after current configuration is refreshed; ordinary observers MUST NOT renew activation. [ADR-096](../docs/decisions/096-database-incarnation-fence.md) supplies the initial PostgreSQL process/database fence and its explicit failure model. Its migration also blocks stored flags for already-running legacy readers; reactivation requires fencing older binaries/credentials. Supported restore tooling must fence service and restart the database server or restore into a newly created database. Independent checkpoints and old-primary fencing remain mandatory. Automate lossless-restart activation after qualified durability checks; do not require repetitive human approval merely because PostgreSQL restarted.

SQL backups/WAL contain no evidence payload, extract text or full manifests. Control identities, digests and relationships still require encrypted storage, access limits, approved finite metadata retention and bounded backup/WAL horizons. Deleting a row cannot erase old backups. Restore gates exclude expired information before serving it and eventually delete expired backup sets; do not claim GDPR compliance from encryption. Payload search stays in region under evidence expiry, outside ordinary PostgreSQL backups.

Migrations use a dedicated bounded job/role with an exclusive migration lock; runtime roles have no DDL/superuser rights. Use expand/backfill/validate/contract, resumable bounded batches and N/N-1 compatible reads during rollout. Destructive contraction follows the rollback window and verified backups. Readiness rejects an unsupported schema version. TLS verifies the database endpoint; credentials rotate through Secrets. Monitor connection pressure, lock waits, queue age, WAL/backup lag, replication durability, dead rows and database disk headroom, without evidence-bearing SQL logs.

### SC-DB-005

Given primary failover, an older backup or WAL archive replay, when recovery is attempted, then acknowledged revocations cannot silently vanish, old connectors cannot spend again, unknown reservations remain charged and deleted/expired evidence stays unavailable. Simulated missing checkpoints keep recovery blocked or force the documented full authority invalidation, rather than reopening access.

Given an enabled stored root from before database restart/replacement, when the ordinary observer refreshes its configuration, then current authority remains blocked until independent activation accepts that incarnation. Upgrading a legacy root with no activation binding also leaves it blocked. A previously obtained recovery proof cannot bypass the final effect check. Real restart and logical-restore tests exercise this prerequisite separately from the still-required failover/checkpoint protocol.

The absolute control-data backup arithmetic and evidence-index deletion model in REQ-PRV-008 are part of database/storage profile admission. Before persisting longer-lived authority, reconcile the required grant/replay/restore horizon with each metadata maximum; an incompatible profile reports RetentionConflict. Audit/deny recovery checkpoints must outlive the restore horizon while staying within their own approved finite purpose. SQL restore gating prevents disclosure but does not itself delete bytes from old backups.

## Capture history projection

[History](capture-history.md) is an access-controlled projection of accepted capture executions plus encrypted parameter snapshots, not a second capture authority. Atomically link an available snapshot's digest/reference and source capture; otherwise mark settings unavailable and reconcile bounded pending writes without preventing incident acquisition. Index selector key, origin, accepted_at and capture ID for stable bounded pagination. The selector key includes namespace/workload incarnation; arbitrary labels and parameter equality use keyed lookup digests. Readable parameter DTOs are joined from scoped encrypted objects only after authorization.

History-only caps/eviction cannot remove active accounting, approvals, restore denials or required audit. When an original history projection expires, non-authorizing repeat lineage may remain only within its own finite metadata lifetime; it cannot expose the source. Avoid a cascading foreign key from repeatedFromCaptureID to an evictable history row. Immutable snapshots retain dependency digests and privacy lineage independently of mutable recipe CRDs; missing or disabled execution dependencies remain blockers. Object versions, partial uploads and expired snapshots enter the normal cleanup inventory.

## Capture-profile configuration and projections

Kubernetes is authoritative for CaptureProfile publication/availability; PostgreSQL stores bounded indexed source identity/digest/visibility/propagation projections and accepted-plan references. No second SQL editing API or runtime registry service is introduced. Cache catalog definitions only under configuration privacy rules; evidence-derived overrides/expanded snapshots use encrypted scoped objects, as capture history does. Accepted history retains profile composition provenance plus the expanded recipe; it cannot reconstruct authority from stale SQL availability after a restore. Reconcile source UID, current visibility and disablement before new permits.

## Ongoing source bookkeeping

Store bounded source-session identity/epoch, plan/action/pod identity, lease, readiness/coverage and active reservation references in existing service-owned work/accounting projections. Keep per-incident snapshot idempotency keys and references separate. Ring bytes remain on the collection node under privacy/resource limits, never in PostgreSQL or Kubernetes. Controller recovery reconciles attachment/session fences without creating one source per outstanding incident; uncertain snapshots retain their charges. Source and snapshot cleanup follow [action lifecycles](action-lifecycle.md) and existing restore denial rules.

## Assessment retention

Persist acceptance/review assessment ID, plan/rule digests and bounded generic reason codes with existing operation/action records. Protected full explanations use existing scope-bound encrypted records when needed. Metric samples, process facts and evidence-derived classifications are not copied into durable SQL/audit just to justify a forecast; their projections follow source/control-data deadlines and current audience checks. Artifact handling notices are current projections of authoritative lifecycle/classification decisions, not independent mutable retention promises. See [capture assessment](capture-assessment.md).

## Live-watch query state

The [live-watch contract](live-watch.md) adds a bounded `live_watch` runtime table, not a configuration CRD or evidence event log. Persist minimized viewer/client, exact scope digest/protected reference, revision/fence, hard/idle deadlines, terminal state, opening idempotency and conservative prepaid query/output spend. Source/profile selection and display-filter content stay behind an encrypted expiring reference. No per-row SQL write, row body, HTTP headers, syscall details or durable replay queue. Existing capacity transactions reserve independent view resources; replay/filter changes cannot reset spend. Source acquisition and incident reservations remain separate. Watch rows expire through bounded cleanup while required accounting/idempotency tombstones obey their replay horizon. Restore never revives an old watch, source or expired authority.

## Native artifact transfer state

`artifact_download` stores opaque session/artifact/actor-client references, immutable version, state/generation, authority revisions, deadline, output/read-work reservation references and conservative emitted/uncertain counters. Uniqueness is actor/client plus idempotency key/request digest; repeat preparation cannot allocate new budget. C-14 owns transitions under the existing canonical transaction lock order. Detailed filename/native checksum/coverage remain in the protected artifact metadata, not a copied evidence payload. No per-range CRD or persistent byte cache. Deletion/restore invalidates incomplete authority and never resurrects a transfer; external local files have no managed-copy verified-deletion state. [REQ-DLD-003](artifact-downloads.md) defines semantics.

## Combined investigation grants

AccessGrant retains optional accepted resultAccess (selected actions, operations, same-human registered clients, digest, finite output/count/operation pool, original expiry). Child rawQuery grants store resultOrigin and a parent foreign key. Add a bounded `grant_result_registration` relation keyed by parent, capture, artifact and client, referencing verified immutable artifact/digest and action provenance; distinct-artifact membership is unique at parent/artifact independently of client. This is an internal relation, not a new public aggregate or CRD. Parent resultAccessCounters and ordinary acquisition counters are separate.

Within the canonical transaction order, C-03 locks the parent decision/scope, validates trusted commit and current eligibility, registers/reuses the output, publishes exact child scope and records audit/outbox. Downloads/queries reserve parent disclosure and child operation limits in the same authorization/capacity transaction. Never allocate an independent full parent allowance per child. Revocation/read checks consult the parent synchronously; cleanup delivery may lag. Restore does not recreate expired authority. Runtime concurrency, duplicate publication, interrupted delivery and parent revocation tests remain required under REQ-INV-002.
