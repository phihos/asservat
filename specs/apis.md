# Kubernetes and internal API contracts

## REQ-API-001 — Resource model

The CRD table uses namespaced `asservat.io/v1alpha1` resources unless explicitly stated; SQL runtime records below are a separate interface. CRDs are installed cluster-wide, while instances are scoped as below. Full schemas are generated from future Go types; the portable [contracts](contracts/common.schema.json) in this repository are executable design examples, not deployable CRDs.

| Kind | Location / writer | Spec and status |
| --- | --- | --- |
| `EvidenceRecipe` | Workload namespace; service owner | Typed action DAG, limits, runtime hints; validated digest/capabilities |
| `CaptureProfile` | Protected builtin/organization catalog or workload namespace; authorized publisher | Immutable versioned expanded recipe and editable fields; mutable enable/deprecate state, validation/propagation conditions; [contract](capture-profiles.md) |
| `DebugPolicy` | Workload namespace; service owner | Preset, profileComposition or expanded target/detectors/recipe/budgets, optional bounded future-result sharing; accepted immutable plan/digests, generation and per-node readiness |
| `DebugCapture` | Workload namespace; requester/controller | Preset, profileComposition or expanded request with optional result sharing, immutable after acceptance; status projects SQL accepted execution and bounded progress/artifact references |
| `EvidenceStoragePool` | Hub control namespace; capacity administrator | Backed capacity, protected workload slots, shared burst, system/headroom reserves and transfer ceiling; allocation readiness/usage |
| `EvidenceBudgetPolicy` | Hub control namespace; capacity administrator | Eligible scope, namespace envelope, per-workload protected/hard/context capacity, dump/rate/queue limits and full-account policy |
| `CapacityAccount` | Local control namespace; capacity controller only | Parent allocation/fence, bounded child slices and committed/reserved aggregate counters; reconciliation state |
| `CapacityReservation` | Local control namespace; capacity controller only | Operation/attempt IDs, exact resource slices and deadline; Pending → Ready → Spent/Committed → Released or Indeterminate |
| `CollectionCeiling` | Collector admin namespace; cluster admin | Namespace opt-in/deny, action types, maximum budgets, storage/analysis profiles; readiness |
| `AccessBinding` | Hub control namespace; authorized permission administrators/provisioners | Subjects, fixed roles, cluster/namespace/workload scope, optional expiry; service-owned status |
| `EvidenceRetentionPolicy` | Hub/collector control namespace; retention administrator | Scope, finite default/max ages, privacy/type rules, deletion budget, legal-exception mode; observed revision/propagation and storage conflicts |
| `PermissionSource` | Hub control namespace; permission administrators | Typed derivation rule, scope, trusted mapping, guard qualification and freshness; readiness |
| `ExecutionPermit` | Local collector namespace; connector only | Prepaid grant slice and signed immutable plan; bounded reservations and fencing epoch |
| `AnalysisRequest` | Local collector namespace; controller only | Artifact digest, approved recipe/query, authorization reference; job IDs and bounded results |
| `DeliveryWork` | Local control namespace; reconciler only | Immutable record/event reference, attempt/deadline; lease and delivery state |

Hub runtime records are PostgreSQL rows: ClusterRegistration, AccessGrant, SharingIntent, SharingRegistration, EvidenceShare, central CapacityAccount/CapacityReservation and DeliveryWork, cases, occurrences and accepted executions. Their versioned runtime DTOs are service-owned and cannot be applied through Kubernetes. The [persistence contract](persistence.md) defines tables, keys, transactions and recovery.

The implemented initial local [CapacityReservation start profile](contracts/local-start.schema.json) fixes one immutable on-trigger attempt and original object UID. Its internal status Ready → StartCommitted consumes the prepaid start before the effect; it does not replace the public capture state machine. Only the capacity writer prepares Ready, and only execution consumes it. Missing, replaced or uncertain state cannot authorize a retry. Other reservation profiles and proven-spend retirement remain pending; see the [local journal contract](../docs/architecture/local-start.md).

Case history is **not** a `Case` CRD; SQL supplies the content-minimized catalog and object storage supplies evidence/full manifests and immutable outcomes. Case IDs resolve through current authorization. Secrets hold credential references/material; no secret values in these resources.

### SC-API-001

Given an attempted direct grant/share record write by a workload user or a CRD containing raw log bytes, when service authorization or Kubernetes admission/RBAC runs, then it is rejected. Grants/shares have no writable CRD endpoint. Completed case history can grow without growing one Kubernetes object indefinitely.

## REQ-API-002 — Validation and immutable execution

CRDs MUST use structural schemas with bounded arrays/strings/maps, known enums and explicit defaults. CEL validates same-object invariants. A ValidatingAdmissionPolicy supplies administrator ceilings that can be expressed locally; an admission webhook or reconcile-time execution check handles external grant/recipe references. Admission alone is not authorization for privileged execution.

Portable JSON Schema branches for preset, composition and expanded authoring are not copied verbatim into CRDs: generated structural schemas declare the union of properties at the structural level and express branch exclusivity/required combinations through supported validation/CEL. Check all three forms against the real API server before publishing CRDs. Controller-owned resolved plans remain in protected status/immutable work records; no round-trip conversion may replace the user's authored form or manufacture acceptance.

`CaptureProfile` identity/definition fields use transition validation to reject in-place edits; disable/deprecate remains mutable. Publication Conditions distinguish Validated, CatalogVisible and Propagated; stale or unauthorized dependencies block acceptance. `DebugCapture.spec` is immutable after acceptance. Policy/recipe revisions compile to immutable plan digests; `status.observedGeneration` never advances until actual validation/activation. Use Conditions with type/status/reason/message/observedGeneration/lastTransitionTime. Keep sensitive values out of messages. SQL runtime rows enforce expected revisions and idempotency keys separately from Kubernetes resourceVersion; neither version token substitutes for the other. Deletion/finalizer logic has bounded retries and documented operator recovery; evidence retention never depends on a workload ownerReference.

Target and recipient identities bind immutable UIDs or issuer-scoped IDs; names alone never establish ownership. Exact resource names are used where the Kubernetes authorization API requires them, under the UID and source checks in [permission management](permissions.md). Require RFC3339 timestamps, integer byte counts, explicit duration strings, lowercase SHA-256 digests, and UUIDs for system-generated record IDs. Unknown API versions fail clearly. `grantRef` in a request is a hub grant UUID, not a namespace-relative CRD name; the normal resolver/UI selects an eligible grant, while expanded forms may use an explicit handle. Allocate the capture identity and freeze its collection scope before requesting approval. Bind a grant handle separately to that exact scope; choosing or renewing a matching grant does not change the collection digest. Keep original submission and sharing digests separate under [execution identity](execution.md); never accept an empty approval scope. Conversion cannot widen permissions or turn omitted bounds into unlimited bounds.

### SC-API-002

Given a schema-valid request with an expired grant or a recipe digest mismatch, when it reaches execution, then it is denied. A spec update cannot mutate an accepted capture's target, action list or byte budget.

## State machines

```text
Policy: Pending → Validating → AwaitingApproval? → Arming → Ready | Degraded
                                      ↘ Rejected
        Ready → Updating | Suspended | Expired | Deleting

Capture: Pending → Validating → AwaitingApproval | Armed | Queued | Running
         → Finalizing → Succeeded | Partial | Failed | Cancelled | Indeterminate
         Per-action approval is independent: eligible context may run while another action waits.

Artifact: Reserved → Receiving → Encrypted → Uploaded → Committed
          ↘ Aborted                     ↘ Quarantined
          Committed → ExpiredDeletionPending → DeletedVerified
                        ↘ DeletionOverdue → DeletedVerified
          RetentionHold and ProcessingRestricted are independent conditions.

Grant: Pending → Approved | Denied
       Approved → Exhausted | Expired | Revoked

Share: PendingApproval? → Active | Denied
       Active → Expired | Revoked

SharingIntent: PendingApproval → Active | Denied
               PendingApproval | Active → Draining → Completed
               PendingApproval | Active | Draining | Completed → Suspended | Revoked | Expired
               Suspended → prior operational state only after explicit authorized resume
               Per-selection approval is independent; approved extracts need not wait for raw.

Analysis: Pending → Acquiring → Staged → RunningOffline → Publishing
          → Succeeded | Partial | Failed | Cancelled
```

Terminal capture status does not imply every artifact is analyzable. Case state includes `Collecting`, `EvidenceReady`, `AnalysisPartial`, `AnalysisReady`, `Expired`; analysis-ready means only that requested supported analysis jobs reached their declared terminal states, with failures still visible.

## Internal hub/connector endpoints

| Endpoint | Auth | Contract |
| --- | --- | --- |
| `POST /internal/v1/enroll` | One-use enrollment credential | Cluster identity request; certificate/trust bundle response |
| `POST /internal/v1/heartbeat` | Cluster mTLS | Capabilities, local ceiling digest, version, bounded health |
| `POST /internal/v1/work:poll` | Cluster mTLS | Cursor/capabilities; bounded work batch and lease/fence |
| `POST /internal/v1/work/{id}:ack` | Cluster mTLS | Operation state/digest, no arbitrary target change |
| `POST /internal/v1/records` | Cluster mTLS | Idempotent immutable catalog/event references |
| `POST /internal/v1/query-results` | Cluster mTLS + work binding | Bounded authorized result or encrypted result reference |

Internal request body maximum 256 KiB, records/work batches maximum 100 items, long poll maximum 30 seconds. The endpoint validates the enrolled cluster identity from mTLS, never from a trusted request-body assertion. These endpoints are private and not agent-accessible. A versioned OpenAPI document and wire fuzz tests are implementation deliverables in TASK-02; this table defines their required operations.

## User HTTP interface

The case browser, approval page and sharing page use a same-origin HTTP API with OAuth/OIDC sessions and CSRF protection. Read endpoints project the same data as MCP. Mutation endpoints cover capture requests, grant requests/approve/deny/revoke, share create/approve/revoke and sharing-intent stop/revoke/resume, retention holds, restricted-processing decisions and early-erasure requests. Responses include revision/ETag; mutations require the expected revision and an idempotency key. Intrusive/raw approvals are browser-only in the initial product; MCP provides request/poll but no approve tool. Permission configuration uses only the [Kubernetes API](permissions.md). The existing browser backend supplies read-only effective-access explanation and impact preview; it does not proxy configuration CRUD.

## Schema scope

The checked-in JSON contracts cover the high-risk public shapes: target, detectors, actions/recipes, capture profiles, typed composition, syscall actions/results, and policy/capture preset/composition/expanded forms, administrator capacity pools/budget policies, administrator retention policy, artifact privacy/deadlines, artifact manifest/acquisition provenance, access grant, share and protected sharing intent, optional collection-time sharing declarations, permission bindings/sources, access provenance and MCP results/tools. SharingIntent is a SQL-backed runtime DTO, not a CRD or an extra permission CRUD API. SharingRegistration uses transactional reservations under REQ-SHR-006 and REQ-DB-003; migrations enforce capture/artifact uniqueness and bounded counters. Runtime DTO spec/status envelopes must not be mistaken for Kubernetes resources. Capability tables above define remaining controller resource semantics. Generated production CRDs, OpenAPI routes, Helm values schema and API compatibility fixtures must be completed before their implementation phase is declared done.

## Action execution modes and status

The action contract exposes executionMode, default ongoing for packetCapture/syscallTrace and onTrigger for other kinds. Only the two recorder kinds allow an explicit onTrigger variant, with before: 0s. Structural CRD/CEL validation rejects unsupported modes, contradictory history and dependsOn edges on ongoing sources. Resolved plans include modes even when users omit them.

The [lifecycle contract](contracts/action-lifecycle.schema.json) covers the shared preview plan and acquisition provenance. Source sessions are service-owned runtime work under existing leases/reservations, not user-configured CRDs. Policy status distinguishes detector readiness, armed/warming/ready/blocked source counts and action-specific coverage; capture status describes saved incidents. Ongoing source states and their finite manual behavior are specified in [action lifecycles](action-lifecycle.md).

## Capture assessment projections

[capture-assessment.schema.json](contracts/capture-assessment.schema.json) defines the service-owned assessment and scoped artifact handling notice. UI/MCP use the same resolver; Kubernetes submissions publish bounded assessment identity, reason codes and authenticated navigation in protected status before execution. Full assessment details use the authorized query projection, not broadly readable CRD status. Neither publisher-written risk labels nor a submitted assessment is authoritative. No extra CRD or public configuration API is introduced.

## Recording saves and analysis storage

DebugPolicy's preset/composition/expanded forms accept `recordingSaves: {enabled: true|false}`. Omitted is false; policy authoring may put true visibly into drafts with ongoing actions. Bind it in accepted policy scope, validate that an ongoing action exists, and require normal grant renewal on enablement. This is policy configuration, not a new role or permission CRUD API.

Save operations use a protected recording-save/v1 DTO and existing SQL accepted executions/local work. They are not a new public CRD and cannot be submitted by forging controller-owned status. The existing browser capture API adds passive recording inventory/preview and routes submit-by-preview to its typed executor; MCP adds only the matching passive tools. Poll/cancel, expected revisions, idempotency, optional sharing and audit are shared with ordinary captures. Capture status/history must explicitly label operation=recordingSave; source/policy references never make it a full policy trigger.

Analysis profiles reference an operator-qualified encrypted scratch StorageClass and bounded input/output/aggregate capacity. Missing readiness is AnalysisScratchUnavailable, with collection readiness separately reported. TASK-03/11 must generate and validate the Helm/configuration fields, CSI qualification evidence and independent cleanup reconciliation before claiming a supported profile; no assumed default StorageClass.

## Live-view configuration and runtime boundary

`CollectionCeiling` may narrow `liveRead.enabled`, allowed approved projections and per-scope view limits without granting new collection rights. Hub/connector deployment values configure finite installation/node/principal defaults and reserve incident processing/transfer ahead of live work. Initial design defaults are 128 installation watch slots, two per principal, four per workload, 16 source subscriptions per node, 1 MiB replay per watch, 64 KiB/s and 16 MiB total output per watch, 10-minute default / 60-minute maximum lifetime, 30-second idle and row lifetime, and five-second replay. Administrator maxima can only narrow effective admission; setting zero supported projections disables live views. Enablement also requires per-mechanism qualification and source entitlement, so a boolean alone cannot expose content.

Before enabling a projection, operators must supply finite CPU-time and examined-event/byte ceilings for the qualified node/profile, with measured supported-environment guidance. No universal parser-throughput default is claimed. Keep these fields typed and bounded in generated Helm/CRD schemas; they belong to existing configuration resources, not a new permission role or live-watch CRD. The hub SQL LiveWatch row is runtime state and cannot be authored with kubectl. Config revision/freshness and local deny invalidate live delivery using existing propagation bounds.
