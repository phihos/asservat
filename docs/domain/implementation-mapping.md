# From domain concepts to implementation

Use separate domain types, persistence rows, Kubernetes types and protocol DTOs. No domain aggregate embeds a database handle, Kubernetes client, HTTP request or MCP transport. Application services accept an authenticated execution context and typed commands; repositories persist minimized records; adapters perform authorized effects.

## Ownership of data

| Concept | Canonical write authority | SQL representation | Kubernetes representation | Object / runtime representation |
| --- | --- | --- | --- | --- |
| Cluster registration | Hub cluster registration (Helm-generated bootstrap token, connector CSR) | `cluster`, connection state, revisions | Connector deployment/config references | Certificates in Secrets; no raw secrets in rows |
| Profiles / recipes / policies | Kubernetes writers under RBAC | Accepted config projection pushed by the connector | CaptureProfile / EvidenceRecipe / DebugPolicy spec + Conditions, `status.observedGeneration` | Resolved definition and plan digest in SQL |
| Permission / retention / capacity configuration | Kubernetes RBAC (AccessBindings per application namespace; administrator-only PermissionSources and policies) | Config projection, valid until replaced by the next watch event | AccessBinding, PermissionSource, CollectionCeiling, EvidenceRetentionPolicy, EvidenceBudgetPolicy, EvidenceStoragePool | None |
| Capture | Hub admission service | operation, capture, action_attempt, accepted scope, assessment | DebugCapture is optional request/status envelope | Encrypted evidence only |
| Source session | Node execution under admitted hub work | Bounded status through operation records | Local status projections | Live ring/maps in node memory; no source CRD |
| Snapshot | Accepted capture + source executor | Attempt identity/status and reservation | None | Frozen segment refs, coverage manifest, encrypted artifact |
| Case / occurrence / history | Hub catalog | Case/occurrence/history tables with labels, details and settings | None | None |
| Grants / shares / future sharing / owners | Hub authorized command services | Grant/share/instruction tables with review/selection scope | **None** | None |
| Capacity runtime | Hub workload counters; connector budget lease | Per-workload counters and reservations keyed by operation ID | None | Lease usage held by the connector and reported on reconnect |
| Analysis / delivery | Hub queued operation | operation, outbox, work | Analysis Jobs created by the connector | Encrypted input/output PVCs, result artifacts |
| Evidence / copies / privacy decisions | Publication/privacy services | Artifact with stored deadlines, lineage, copies, revocation/work/tombstones | No ownerReference to observed workload | Encrypted objects/manifests, bounded regional indexes |
| Audit | Operation's own transaction | `audit_event` (append-only, time-partitioned) | No per-event CRD | Exported batches in object store or SIEM |

The [catalog](model.yaml) uses `RecipeDefinition` for the domain content represented by an EvidenceRecipe or ad hoc plan. `Capture` is not a direct struct alias for DebugCapture. `SourceSession` is a runtime entity; PostgreSQL does not replace the node’s authoritative live-ring state. Configuration references identify their cluster; local and central records with similar names are explicitly separate authorities.

## Relational foundation

Use PostgreSQL UUID primary keys; typed foreign keys, `bigint` bounded counters with nonnegative checks, `timestamptz`, and monotonically increasing row revisions. Bounded JSONB is reserved for content-minimized typed metadata, never arbitrary CRD/evidence dumps. Protected text indexes remain regional and retention-aware, outside ordinary SQL backups.

The existing [logical table catalog and transaction rules](../../specs/persistence.md) are canonical. Required keys/indexes include:

- `operation`: unique `(principal_key, client_id, operation_kind, idempotency_digest)` plus request digest; keep deduplication/tombstone lifetime through the replay horizon. Mismatch is Conflict, not a second request.
- `config_projection`: unique cluster/resource UID, opaque source revision and accepted generation/digest. Delete/recreate is not an update.
- `action_attempt`: unique capture/action/attempt identity and durable start disposition. Retrying delivery cannot mint an extra authorized start.
- `case_record` / `occurrence`: versioned grouping key, unique enrolled-cluster occurrence identity; alias table/index preserves signature refinement without losing original references.
- `artifact_parent`: composite child/parent key, no self-parent, service-enforced cycle rejection; index both directions for authorization and deletion propagation.
- `artifact_copy`: unique copy identity including object version or analysis-volume generation; indexes on deadline, state and region. Never release all versions because the current object was deleted.
- sharing: concrete `(share_id, artifact_id)` and `(share_id, subject_key)` uniqueness; publication inserts each share once per instruction/capture/selection; revision-checked manager changes do not modify creator or original deadlines.
- capacity/grants: reservation operation-ID uniqueness and conditional counter updates on the affected workload row (plus the pool row when burst applies). Prevent committed+reserved from exceeding the limit.
- history: scope-key/time index and settings row; independent expiry from active capture/accounting. Emptying history does not delete live reservations.

Partition `audit_event` by time; other partitioning is an implementation choice after measured volume; do not partition away referential integrity or reuse IDs across partitions. Do not enable cascade deletion from clusters, namespaces, captures, principals or CRDs into grants/copies/audit. Use explicit lifecycle work, retained minimum tombstones and backup horizon accounting. Schema/migration reviews must classify each new column’s privacy and backup effect.

## Go foundation (illustrative, not runtime code)

```go
// Distinct types prevent substituting a display name, grant or source ID.
type CaptureID uuid.UUID
type SourceSessionID uuid.UUID
type Revision uint64
type Digest [32]byte

type CaptureScope interface { isCaptureScope() } // sealed, typed union
// CollectionScope contains normalized actions and pinned targets.
// RecordingSaveScope contains existing source identities and positive lookback only.

type AcceptedCapture struct {
    ID CaptureID
    ScopeID AcceptedScopeID
    ScopeDigest Digest
    AcceptedAt time.Time
    FinalizeBy time.Time
    Revision Revision
}

type CaptureService interface {
    Preview(context.Context, ActorContext, PreviewCommand) (CapturePreview, error)
    Submit(context.Context, ActorContext, SubmitCommand) (CaptureView, error)
    Cancel(context.Context, ActorContext, CancelCommand) (CaptureView, error)
}
```

Actors, permission decisions, accepted scopes and confirmed starts are not caller-editable DTO fields. Constructors/validators establish bounded values; services authorize once per operation (ADR-311). Nullable values model known absence; separate Unknown/Unavailable reasons model insufficient knowledge. Bytes are not float64. A generic `map[string]any` is not a replacement for a tagged typed action/query union.

The canonical package layout and dependency rules are in [code organization](../architecture/code-organization.md). Domain types live under `internal/domain`, use-case services and consumer-owned ports under `internal/application`, concrete implementations under `internal/adapters`, and protocol/rendering adapters under `internal/transport` and `internal/console`. Only `internal/bootstrap` wires concrete dependencies. The [architecture catalog](../architecture/catalog.yaml) maps each entity to its lifecycle owner; it does not introduce a service per entity.

## CRD / DTO evolution

Generate structural CRDs and deep-copy code from reviewed Kubernetes Go types after TASK-01. Map domain fields explicitly into `spec` and controller-owned `status`. Use Conditions with observedGeneration; web/API views expose authored and accepted generation separately. Schema conversion must not silently widen limits or rewrite a pinned profile version. CEL handles same-object constraints; current external authority remains a service check.

Protocol DTOs use existing snake_case MCP fields, Kubernetes lowerCamelCase fields, and explicitly versioned domain records. Do not round-trip a display projection into an accepted plan. Browser operation bodies reuse MCP schemas where the command is the same; browser-only human review uses separate strict contracts. Repository rows and Go class names are private and never an API compatibility promise.

## Live-watch storage and Go mapping

`live_watch` is a minimized hub row keyed by WatchId: viewer/client, state/revision, source sessions, display filter, accepted/absolute/idle deadlines, scope digest and output/resource charges. Index viewer/client/state/expiry and the unique opening idempotency key. Delivery rows and row payloads never enter PostgreSQL, CRDs, outbox or audit. Charges settle when the watch ends; a replica loss resumes from current source heads with an explicit gap.

Live row buffers are bounded memory inside qualified regional/hub delivery boundaries; no evidence broker or stream CRD. Keep Go `LiveWatch`, `LiveRow` tagged projection union, `LiveCursor`, `SourcePosition` and `LiveGap` distinct from capture/artifact/query-result types. Application LiveWatchService implements inventory/open/read/update/close with the same access evaluator as browser/MCP, authorized once and reused within ADR-311. Source projection adapters implement nonblocking bounded reads.

ArtifactDownload is a C-14-owned minimized SQL row with artifact/version, actor/client, authority, deadline and budget. It is not a CRD, analysis run or stored plaintext copy. The regional reader streams the native bytes over the connector connection; laptop copies remain outside the managed copy inventory. See [download contract](../../specs/artifact-downloads.md).

## Investigation approval scope

AccessGrant gains optional ResultAccessScope and ResultAccessCounters value objects; no new top-level entity is needed. Map the resolved instruction and counters to hub SQL; artifacts used count once through a unique (grant, artifact) row. DebugCapture authored resultAccess is an instruction only; it cannot set issued decisions. MCP uses result_access with the same strict nested DTO. Case/Artifact identity and C-14 ownership are unchanged. See [REQ-INV-002](../../specs/investigation-approval.md#req-inv-002--result-access-applies-to-exact-published-artifacts).

BrowserSession belongs to C-02; the login challenge is a short-lived part of it. SQL stores encrypted provider credentials and minimal principal/session metadata. They are not CRDs, evidence, grants or recurring-policy executors. See [browser sessions](../architecture/browser-sessions.md).

## Hub process credentials

Hub replicas, connectors and in-cluster readers use the installation CA, one connector identity per cluster and audience-bound projected ServiceAccount tokens ([ADR-330](../decisions/330-event-driven-system-design.md) D3). No per-process enrollment, registration, activation or certificate-audit entities exist.
