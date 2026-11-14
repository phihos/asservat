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
| `CollectionCeiling` | Collector admin namespace; cluster admin | Namespace opt-in/deny, action types, maximum budgets, storage/analysis profiles; readiness |
| `AccessBinding` | Application namespace it grants; namespace RBAC writers ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)) | Subjects, fixed roles, namespace/workload scope, optional expiry; observed by the regional connector through an informer; status Conditions with `observedGeneration` |
| `EvidenceRetentionPolicy` | Hub/collector control namespace; retention administrator | Scope, finite default/max ages, privacy/type rules, deletion budget, legal-exception mode; `observedGeneration`, propagation and storage-conflict Conditions |
| `PermissionSource` | Hub control namespace; permission administrators | Typed derivation rule, scope and trusted mapping; Ready Condition with `observedGeneration` |

Hub runtime records are PostgreSQL rows: ClusterRegistration, AccessGrant, SharingIntent, SharingRegistration, EvidenceShare, capacity accounts and reservations, delivery work, cases, occurrences, accepted executions and audit rows. Their versioned runtime DTOs are service-owned and cannot be applied through Kubernetes. The [persistence contract](persistence.md) defines tables, keys, transactions and recovery.

Per-attempt and per-delivery state is not a Kubernetes object ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D8). The connector receives accepted work and a capacity budget over its hub connection, keeps per-attempt state in memory keyed by operation ID, and rebuilds it from hub work state after a restart or reconnect; the hub de-duplicates by operation ID. Analysis runs as a Kubernetes Job created directly from hub work and labeled with its operation ID; results return over the connector connection.

Case history is **not** a `Case` CRD; SQL supplies the content-minimized catalog and object storage supplies evidence/full manifests and immutable outcomes. Case IDs resolve through current authorization. Secrets hold credential references/material; no secret values in these resources.

### SC-API-001

Given an attempted direct grant/share record write by a workload user or a CRD containing raw log bytes, when service authorization or Kubernetes admission/RBAC runs, then it is rejected. Grants/shares have no writable CRD endpoint. Completed case history can grow without growing one Kubernetes object indefinitely.

## REQ-API-002 — Validation and immutable execution

CRDs MUST use structural schemas with bounded arrays/strings/maps, known enums and explicit defaults. CEL validates same-object invariants. A ValidatingAdmissionPolicy supplies administrator ceilings that can be expressed locally; reconcile-time execution checks handle external grant/recipe references. Admission alone is not authorization for privileged execution.

Portable JSON Schema branches for preset, composition and expanded authoring are not copied verbatim into CRDs: generated structural schemas declare the union of properties at the structural level and express branch exclusivity/required combinations through supported validation/CEL. Check all three forms against the real API server before publishing CRDs. Controller-owned resolved plans remain in protected status/immutable work records; no round-trip conversion may replace the user's authored form or manufacture acceptance.

`CaptureProfile` identity/definition fields use transition validation to reject in-place edits; disable/deprecate remains mutable. Publication Conditions distinguish Validated, CatalogVisible and Propagated; stale or unauthorized dependencies block acceptance. `DebugCapture.spec` is immutable after acceptance. Policy/recipe revisions compile to immutable plan digests; `status.observedGeneration` advances only after validation/activation of that generation, and the Kubernetes audit log attributes changes. Use Conditions with type/status/reason/message/observedGeneration/lastTransitionTime. Keep sensitive values out of messages. SQL runtime rows enforce expected revisions and idempotency keys separately from Kubernetes resourceVersion; neither version token substitutes for the other. Deletion/finalizer logic has bounded retries and documented operator recovery; evidence retention never depends on a workload ownerReference.

Target identities bind immutable UIDs; recipients and audiences bind issuer-scoped subjects or stable identity-provider group IDs. Names alone never establish ownership. Exact resource names are used where the Kubernetes authorization API requires them. Require RFC3339 timestamps, integer byte counts, explicit duration strings, lowercase SHA-256 digests, and UUIDs for system-generated record IDs. Unknown API versions fail clearly. `grantRef` in a request is a hub grant UUID, not a namespace-relative CRD name; the normal resolver/UI selects an eligible grant, while expanded forms may use an explicit handle. Allocate the capture identity and freeze its collection scope before requesting approval. Bind a grant handle separately to that exact scope; choosing or renewing a matching grant does not change the collection digest. Keep original submission and sharing digests separate under [execution identity](execution.md); never accept an empty approval scope. Conversion cannot widen permissions or turn omitted bounds into unlimited bounds.

### SC-API-002

Given a schema-valid request with an expired grant or a recipe digest mismatch, when it reaches execution, then it is denied. A spec update cannot mutate an accepted capture's target, action list or byte budget.

## State machines

```text
Policy: Pending → Validating → AwaitingApproval? → Arming → Ready | Degraded
                                      ↘ Rejected
        Ready → Updating | Suspended | Expired | Deleting

Capture: Pending → AwaitingApproval | Armed | Running
         → Succeeded | Partial | Failed | Cancelled | Indeterminate
         Conditions: Accepted, Collected, Verified, Published (each with reason).
         Per-action approval is independent: eligible context may run while another action waits.
         Indeterminate applies only when an intrusive action's effect cannot be established.

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

A capture has one phase plus Conditions; storage, verification and publication are Conditions of that phase, not separate public state machines. Hub work-queue leases are internal. Succeeded requires Published=True for every required action output. Terminal capture status does not imply every artifact is analyzable. Case state includes `Collecting`, `EvidenceReady`, `AnalysisPartial`, `AnalysisReady`, `Expired`; analysis-ready means only that requested supported analysis jobs reached their declared terminal states, with failures still visible.

## Internal hub/connector connection

The connector holds one outbound, multiplexed mutual-TLS connection to the hub ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D2). Commands, receipts, cluster-state pushes, live rows and download bytes are streams on that connection; [I-01](../docs/architecture/interfaces.md) defines the private wire contract. The hub authenticates the cluster from the TLS peer certificate, never from a request-body assertion. Commands are pushed when the hub writes them; a hub replica learns of new work through PostgreSQL `LISTEN/NOTIFY` and resynchronizes with one query after reconnect or cursor mismatch. An open connection is liveness; there is no separate heartbeat request. Work and receipts carry operation IDs and are idempotent. The connection is private and not agent-accessible.

## User HTTP interface

The case browser, approval page and sharing page use a same-origin HTTP API with OAuth/OIDC sessions and CSRF protection. Read endpoints project the same data as MCP. Mutation endpoints cover capture requests, grant requests/approve/deny/revoke, share create/approve/revoke and sharing-intent stop/revoke/resume, retention holds, restricted-processing decisions and early-erasure requests. Responses include revision/ETag; mutations require the expected revision and an idempotency key. Intrusive/raw approvals are browser-only in the initial product; MCP provides request and status tools but no approve tool. The console receives progress, status and live rows over one Server-Sent Events stream per open page. Permission configuration uses only the [Kubernetes API](permissions.md). The existing browser backend supplies read-only effective-access explanation and impact preview; it does not proxy configuration CRUD.

## Schema scope

The checked-in JSON contracts cover user-authored CRDs and public DTOs: target, detectors, actions/recipes, capture profiles, typed composition, syscall actions/results, and policy/capture preset/composition/expanded forms, administrator capacity pools/budget policies, administrator retention policy, artifact privacy/deadlines, artifact manifest/acquisition provenance, access grant, share and protected sharing intent, optional collection-time sharing declarations, permission bindings/sources, access provenance and MCP results/tools. SharingIntent is a SQL-backed runtime DTO, not a CRD or an extra permission CRUD API. SharingRegistration uses transactional reservations under REQ-SHR-006 and REQ-DB-003; migrations enforce capture/artifact uniqueness and bounded counters. Runtime DTO spec/status envelopes must not be mistaken for Kubernetes resources. Helm renders installation-internal configuration; it has no public contract. Capability tables above define remaining controller resource semantics. Generated production CRDs, OpenAPI routes, Helm values schema and API compatibility fixtures must be completed before their implementation phase is declared done.

## Action execution modes and status

The action contract exposes executionMode, default ongoing for packetCapture/syscallTrace and onTrigger for other kinds. Only the two recorder kinds allow an explicit onTrigger variant, with before: 0s. Structural CRD/CEL validation rejects unsupported modes, contradictory history and dependsOn edges on ongoing sources. Resolved plans include modes even when users omit them.

The [lifecycle contract](contracts/action-lifecycle.schema.json) covers the shared preview plan and acquisition provenance. Source sessions are service-owned runtime work under existing capacity budgets, not user-configured CRDs. Policy status distinguishes detector readiness, armed/warming/ready/blocked source counts and action-specific coverage; capture status describes saved incidents. Ongoing source states and their finite manual behavior are specified in [action lifecycles](action-lifecycle.md).

## Capture assessment projections

[capture-assessment.schema.json](contracts/capture-assessment.schema.json) defines the service-owned assessment and scoped artifact handling notice. UI/MCP use the same resolver; Kubernetes submissions publish bounded assessment identity, reason codes and authenticated navigation in protected status before execution. Full assessment details use the authorized query projection, not broadly readable CRD status. Neither publisher-written risk labels nor a submitted assessment is authoritative. No extra CRD or public configuration API is introduced.

## Recording saves and analysis storage

DebugPolicy's preset/composition/expanded forms accept `recordingSaves: {enabled: true|false}`. Omitted is false; policy authoring may put true visibly into drafts with ongoing actions. Bind it in accepted policy scope, validate that an ongoing action exists, and require normal grant renewal on enablement. This is policy configuration, not a new role or permission CRUD API.

Save operations use a recording-save/v1 DTO and existing SQL accepted executions. They are not a new public CRD and cannot be submitted by forging controller-owned status. The existing browser capture API adds passive recording inventory/preview and routes submit-by-preview to its typed executor; MCP adds only the matching passive tools. Status/cancel, expected revisions, idempotency, optional sharing and audit are shared with ordinary captures. Capture status/history must explicitly label operation=recordingSave; source/policy references never make it a full policy trigger.

Analysis profiles reference an operator-qualified encrypted scratch StorageClass and bounded input/output/aggregate capacity. Missing readiness is AnalysisScratchUnavailable, with collection readiness separately reported. TASK-03/11 must generate and validate the Helm/configuration fields, CSI qualification evidence and independent cleanup reconciliation before claiming a supported profile; no assumed default StorageClass.

## Live-view configuration and runtime boundary

`CollectionCeiling` may narrow `liveRead.enabled`, allowed approved projections and per-scope view limits without granting new collection rights. Hub/connector deployment values configure finite installation/node/principal defaults and reserve incident processing/transfer ahead of live work. Initial design defaults are 128 installation watch slots, two per principal, four per workload, 16 source subscriptions per node, 64 KiB/s and 16 MiB total output per watch, 10-minute default / 60-minute maximum lifetime, 30-second idle and row lifetime, and a five-second / 1 MiB Server-Sent Events resume window. Administrator maxima can only narrow effective admission; setting zero supported projections disables live views. Enablement also requires per-mechanism qualification and source entitlement, so a boolean alone cannot expose content.

Before enabling a projection, operators must supply finite CPU-time and examined-event/byte ceilings for the qualified node/profile, with measured supported-environment guidance. No universal parser-throughput default is claimed. Keep these fields typed and bounded in generated Helm/CRD schemas; they belong to existing configuration resources, not a new permission role or live-watch CRD. The hub SQL LiveWatch row only accounts slots and cannot be authored with kubectl. Configuration changes and local deny reach active streams as events and end them.
