# From domain concepts to implementation

Use separate domain types, persistence rows, Kubernetes types and protocol DTOs. No domain aggregate embeds a database handle, Kubernetes client, HTTP request or MCP transport. Application services accept an authenticated execution context and typed commands; repositories persist minimized records; adapters perform authorized effects.

## Ownership of data

| Concept | Canonical write authority | SQL representation | Kubernetes representation | Object / runtime representation |
| --- | --- | --- | --- | --- |
| Cluster registration | Hub enrollment service | `cluster`, key refs, revisions | Connector deployment/config references | Credentials in secret provider; no raw secrets in row |
| Profiles / recipes / policies | Kubernetes publisher/maintainer | Read-only accepted config projection | CaptureProfile / EvidenceRecipe / DebugPolicy spec + Conditions | Protected resolved definition, immutable plan digest |
| Permission / retention / capacity configuration | Kubernetes administrators | Freshness-bounded config projection | AccessBinding, PermissionSource, CollectionCeiling, EvidenceRetentionPolicy, EvidenceBudgetPolicy, EvidenceStoragePool | Guard/qualification evidence references |
| Capture | Hub admission service | operation, capture, action_attempt | DebugCapture is optional request/status envelope | Immutable scope/assessment and outcomes encrypted |
| Source session | Fenced node execution, bounded by accepted activation | Bounded status/checkpoint references through operation/projection records | ExecutionPermit, local status projections | Live ring/maps and signed source checkpoints; not a hub source controller CRD |
| Snapshot | Accepted capture + source executor | Attempt identity/status and reservation references | Existing bounded work/permit | Frozen segment refs, coverage manifest, encrypted artifact |
| Case / occurrence / history | Hub catalog | Existing case/occurrence/history tables | None | Protected labels/details/settings; key-based selector index |
| Grants / shares / future sharing / owners | Hub authorized command services | Grant/share/intent/registration/manager tables | **None** | Encrypted detailed review/selection scope |
| Capacity runtime | Hub, delegated fenced local slices | Central accounts/reservations/allocation slices | Local CapacityAccount / CapacityReservation | Conservative usage reconciliation; no second central authority |
| Analysis / delivery | Hub queued operation, local fenced worker | operation, outbox, work_lease | AnalysisRequest / DeliveryWork / ExecutionPermit | Encrypted input/output PVCs, protected query/results |
| Evidence / copies / privacy decisions | Commit/privacy services | Artifact, lineage, copy ledger, revocation/work/tombstones | No ownerReference to observed workload | Encrypted objects/manifests, bounded regional indexes |
| Audit | Durable minimized audit | audit_reference, transaction link | No per-event CRD | Append-only protected audit record |

The [catalog](model.yaml) uses `RecipeDefinition` for the domain content represented by an EvidenceRecipe or protected ad hoc plan. `Capture` is not a direct struct alias for DebugCapture. `SourceSession` is a runtime entity with a recoverable projection; PostgreSQL does not replace the node’s authoritative live-ring state. Configuration references identify their cluster; local and central records with similar names are explicitly separate authorities.

## Relational foundation

Use PostgreSQL UUID primary keys; typed foreign keys, `bigint` bounded counters with nonnegative checks, `timestamptz`, and monotonically increasing row revisions. Bounded JSONB is reserved for content-minimized typed metadata, never arbitrary CRD/evidence dumps. Protected text indexes remain regional and retention-aware, outside ordinary SQL backups.

The existing [logical table catalog and transaction rules](../../specs/persistence.md) are canonical. Required keys/indexes include:

- `operation`: unique `(principal_key, client_id, operation_kind, idempotency_digest)` plus request digest; keep deduplication/tombstone lifetime through the replay horizon. Mismatch is Conflict, not a second request.
- `config_projection`: unique cluster/resource UID, opaque source revision, accepted generation/digest, freshness and revocation fence. Delete/recreate is not an update.
- `action_attempt`: unique capture/action/attempt identity and durable start disposition. Retrying delivery cannot mint an extra authorized start.
- `case_record` / `occurrence`: versioned grouping key, unique enrolled-cluster occurrence identity; alias table/index preserves signature refinement without losing original references.
- `artifact_parent`: composite child/parent key, no self-parent, service-enforced cycle rejection; index both directions for authorization and deletion propagation.
- `artifact_copy`: unique copy identity including object version or analysis-volume generation; indexes on deadline, state and region. Never release all versions because the current object was deleted.
- sharing: concrete `(share_id, artifact_id)` and `(share_id, subject_key)` uniqueness; `(intent_id, publication_slot)` prevents overpublication; revision-checked manager changes do not modify creator or original deadlines.
- capacity/grants: reservation operation uniqueness, account revisions and fences; lock declared accounts in canonical order. Prevent committed+reserved+uncertain from exceeding applicable slices.
- history: scope-key/time index and protected settings reference; independent expiry from active capture/accounting. Emptying history does not delete live reservations.

Partitioning is an implementation choice after measured volume; do not partition away referential integrity or reuse IDs across partitions. Do not enable cascade deletion from clusters, namespaces, captures, principals or CRDs into grants/copies/audit. Use explicit lifecycle work, retained minimum tombstones and backup horizon accounting. Schema/migration reviews must classify each new column’s privacy and backup effect.

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
    ScopeRef ProtectedRef
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

Actors, permission decisions, accepted scopes and confirmed starts are not caller-editable DTO fields. Constructors/validators establish bounded values; services recheck current authority before effects. Nullable values model known absence; separate Unknown/Unavailable reasons model insufficient knowledge. Bytes are not float64. A generic `map[string]any` is not a replacement for a tagged typed action/query union.

The canonical package layout and dependency rules are in [code organization](../architecture/code-organization.md). Domain types live under `internal/domain`, use-case services and consumer-owned ports under `internal/application`, concrete implementations under `internal/adapters`, and protocol/rendering adapters under `internal/transport` and `internal/console`. Only `internal/bootstrap` wires concrete dependencies. The [architecture catalog](../architecture/catalog.yaml) maps each entity to its lifecycle owner; it does not introduce a service per entity.

## CRD / DTO evolution

Generate structural CRDs and deep-copy code from reviewed Kubernetes Go types after TASK-01. Map domain fields explicitly into `spec` and controller-owned `status`. Use Conditions with observedGeneration; web/API views expose authored and accepted generation separately. Schema conversion must not silently widen limits or rewrite a pinned profile version. CEL handles same-object constraints; current external authority remains a service/worker check.

Protocol DTOs use existing snake_case MCP fields, Kubernetes lowerCamelCase fields, and explicitly versioned domain records. Do not round-trip a display projection into an accepted plan. Browser operation bodies reuse MCP schemas where the command is the same; browser-only human review uses separate strict contracts. Repository rows and Go class names are private and never an API compatibility promise.

## Live-watch storage and Go mapping

Add a minimized `live_watch` hub record keyed by WatchId, viewer/client, state/revision/fence, accepted/absolute/idle deadlines, scope digest/protected reference and conservative output/resource spend. Index viewer/client/state/expiry and unique opening idempotency identity. Source bindings/display-filter content use a short-lived encrypted scope object; delivery rows and row payloads never enter PostgreSQL, CRDs, durable outbox or audit. Counters/reservations use bounded prepaid slices, not a SQL transaction per event. Recovered uncertain spend remains charged; failover ends a watch or declares a replay gap.

LiveBatch/replay buffers are bounded memory inside qualified regional/hub delivery boundaries; no evidence broker or stream CRD. Keep Go `LiveWatch`, `LiveRow` tagged projection union, `LiveCursor`, `SourcePosition` and `LiveGap` distinct from capture/artifact/query-result types. Application LiveWatchService implements inventory/open/read/update/close, with the same access evaluator and per-delivery check used by browser/MCP. A session repository stores control state only; source projection adapters implement nonblocking bounded reads. Local permits enforce both source acquisition authority and finite per-view processing/fanout budget.

ArtifactDownload is a C-14-owned minimized SQL transfer aggregate with artifact/version, actor/client, authority, deadline and budget references. It is not a CRD, analysis run or stored plaintext copy. Native bytes use a transient authenticated relay; laptop copies remain outside the managed copy ledger. See [download contract](../../specs/artifact-downloads.md).

## Investigation approval scope

AccessGrant gains optional ResultAccessScope, ResultGrantOrigin and ResultAccessCounters value objects; no new top-level entity is needed. Map the resolved parent instruction/counters to hub SQL, and exact child origins to a parent FK plus unique output registrations. DebugCapture authored resultAccess is an instruction only; it cannot set issued decisions or child handles. MCP uses result_access with the same strict nested DTO. Case/Artifact identity and C-14 ownership are unchanged. See [REQ-INV-002](../../specs/investigation-approval.md#req-inv-002--materialize-exact-grants-after-verified-commit).

BrowserLogin and BrowserSession belong to C-02. Migration 00020 stores bounded encrypted operational credentials and minimal principal/session metadata. They are not CRDs, evidence, grants or recurring-policy executors. See [browser sessions](../architecture/browser-sessions.md).

## Private hub process credentials

[ADR-082](../architecture/owner-registration.md) maps `OwnerEnrollment` to `hub_owner_enrollment` and `OwnerCertificateAttempt`/`IssuedOwnerCertificate` to `hub_owner_certificate`. These C-04 operational values are independent of evidence owner teams, ordinary user permissions and CRDs. The unique retained binding includes installation, cluster, issuer epoch, Pod UID, process epoch and server/client purpose. Public-key digests, minimized workload provenance, bounded public certificate chains, encrypted audit receipts and monotonic signing/retirement state are private SQL fields. No private keys, bearer tokens, CSR bodies or workload specs enter these rows. Current registry observations are finite values; they do not replace actual TLS, workload routing or request/developer authority. Expired SQL history is pruned only after all possible leaves and request locators expire; durable encrypted audit uses unique registration/attempt IDs.

[ADR-083](../architecture/owner-authentication.md) keeps `OwnerProtection` and `AuthenticatedOwner` transient. They project current protected workload and exact TLS/registration/Ready-route identity through original deadlines; no SQL table, CRD or public DTO stores them. They remain separate from evidence owner teams and authenticated human request state.

[ADR-084](../architecture/owner-credentials.md) reuses the existing owner binding/certificate values. `OwnerCredentialStatus` is an advisory C-04 process-local pair, without SQL, CRD or wire representation. Private keys belong only to the C-21 credential owners; CSR/key state is not persisted. No evidence ownership entity is added.
