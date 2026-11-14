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
| `CollectionCeiling` | Collector admin namespace; cluster admin | Optional. Narrows the default (every non-system namespace collectable): namespace deny, action types, maximum budgets, storage/analysis profiles, live reads; readiness |
| `AccessBinding` | Application namespace it grants; namespace RBAC writers ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)) | Subjects and groups by name, fixed roles, namespace scope or workloads by kind/name, optional expiry; observed by the regional connector through an informer; status Conditions with `observedGeneration` |
| `EvidenceRetentionPolicy` | Hub/collector control namespace; retention administrator | Scope, finite default/max ages, privacy/type rules, deletion budget, legal-exception mode; `observedGeneration`, propagation and storage-conflict Conditions |
| `PermissionSource` | Hub control namespace; permission administrators | Typed derivation rule, scope and trusted mapping; Ready Condition with `observedGeneration` |

Hub runtime records are PostgreSQL rows: ClusterRegistration, AccessGrant, EvidenceShare, per-workload capacity counters and reservations, work rows, cases, occurrences, accepted executions (with their sharing instructions) and `audit_event` rows. Their versioned runtime DTOs are service-owned and cannot be applied through Kubernetes. The [persistence contract](persistence.md) defines tables, keys, transactions and recovery.

Per-attempt and per-delivery state is not a Kubernetes object ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D8). The connector receives accepted work and a capacity budget over its hub connection, keeps per-attempt state in memory keyed by operation ID, and rebuilds it from hub work state after a restart or reconnect; the hub de-duplicates by operation ID. Analysis runs as a Kubernetes Job created directly from hub work and labeled with its operation ID; results return over the connector connection.

Case history is **not** a `Case` CRD; SQL supplies the content-minimized catalog and object storage supplies evidence/full manifests and immutable outcomes. Case IDs resolve through current authorization. Secrets hold credential references/material; no secret values in these resources.

### SC-API-001

Given an attempted direct grant/share record write by a workload user or a CRD containing raw log bytes, when service authorization or Kubernetes admission/RBAC runs, then it is rejected. Grants/shares have no writable CRD endpoint. Completed case history can grow without growing one Kubernetes object indefinitely.

## REQ-API-002 — Validation and immutable execution

CRDs MUST use structural schemas with bounded arrays/strings/maps, known enums and explicit defaults. CEL validates same-object invariants. A ValidatingAdmissionPolicy supplies administrator ceilings that can be expressed locally; reconcile-time execution checks handle external grant/recipe references. Admission alone is not authorization for privileged execution.

Portable JSON Schema branches for preset, composition and expanded authoring are not copied verbatim into CRDs: generated structural schemas declare the union of properties at the structural level and express branch exclusivity/required combinations through supported validation/CEL. Check all three forms against the real API server before publishing CRDs. Controller-owned resolved plans remain in protected status/immutable work records; no round-trip conversion may replace the user's authored form or manufacture acceptance.

`CaptureProfile` identity/definition fields use transition validation to reject in-place edits; disable/deprecate remains mutable. Publication Conditions distinguish Validated, CatalogVisible and Propagated; stale or unauthorized dependencies block acceptance. `DebugCapture.spec` is immutable after acceptance. Policy/recipe revisions compile to immutable plan digests; `status.observedGeneration` advances only after validation/activation of that generation, and the Kubernetes audit log attributes changes. Use Conditions with type/status/reason/message/observedGeneration/lastTransitionTime. Keep sensitive values out of messages. SQL runtime rows enforce expected revisions and idempotency keys separately from Kubernetes resourceVersion; neither version token substitutes for the other. Deletion/finalizer logic has bounded retries and documented operator recovery; evidence retention never depends on a workload ownerReference.

Authored references use names ([ADR-335](../docs/decisions/335-usable-by-default.md) D4): clusters by their registered name (the hub generates the cluster ID from it), namespaces and workloads by kind/name, recipes and profiles by name (the hub records the digest), people by issuer-scoped subject or user name and groups by their name in the standard OIDC `groups` claim. A workload named in an AccessBinding or policy keeps its access when the Deployment is recreated. The hub resolves names to UIDs and digests at decision time and records those as provenance; an accepted capture pins the UIDs it resolved. Require RFC3339 timestamps, integer byte counts, explicit duration strings, lowercase SHA-256 digests, and UUIDs for system-generated record IDs. Unknown API versions fail clearly. Requests carry no grant reference: the hub selects the eligible grant, and an approval attaches itself to the policy or capture it was requested for. Allocate the capture identity and freeze its collection scope before requesting approval; choosing or renewing a matching grant does not change the collection digest. Keep original submission and sharing digests separate under [execution identity](execution.md); never accept an empty approval scope. Conversion cannot widen permissions or turn omitted bounds into unlimited bounds.

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

Sharing instruction (on an accepted capture or policy acceptance):
               Active → Stopped | Revoked | Expired
               Raw selections need independent approval; approved extracts need not wait for raw.

Analysis: Pending → Acquiring → Staged → RunningOffline → Publishing
          → Succeeded | Partial | Failed | Cancelled
```

A capture has one phase plus Conditions; storage, verification and publication are Conditions of that phase, not separate public state machines. Hub work-queue leases are internal. Succeeded requires Published=True for every required action output. Terminal capture status does not imply every artifact is analyzable. Case state includes `Collecting`, `EvidenceReady`, `AnalysisPartial`, `AnalysisReady`, `Expired`; analysis-ready means only that requested supported analysis jobs reached their declared terminal states, with failures still visible.

## Internal hub/connector connection

The connector holds one outbound, multiplexed HTTP/2 connection to the hub's one HTTPS endpoint, through any Ingress or Gateway including one that terminates TLS ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D2, ADR-334). Commands, receipts, cluster-state pushes, live rows, evidence uploads and download bytes are streams on that connection; [I-01](../docs/architecture/interfaces.md) defines the private wire contract. The connector holds a standing identity, not a per-connection enrollment (ADR-332): it authenticates every request with a projected ServiceAccount token of its own cluster, and the hub attributes the connection to the cluster whose registered issuer, audience and ServiceAccount subject the token matches, never to a request-body assertion. Nothing is copied from the hub to the workload cluster. Commands are pushed when the hub writes them; a hub replica learns of new work through PostgreSQL `LISTEN/NOTIFY` and resynchronizes with one query after reconnect or cursor mismatch. An open connection is liveness; there is no separate heartbeat request. Work and receipts carry operation IDs and are idempotent. The connection is private and not agent-accessible.

## User HTTP interface

The case browser, approval page and sharing page use a same-origin HTTP API with OAuth/OIDC sessions and CSRF protection. Read endpoints project the same data as MCP. Mutation endpoints cover capture requests, grant requests/approve/deny/revoke, share create/approve/revoke, stopping and revoking capture or policy sharing instructions, retention holds, restricted-processing decisions and early-erasure requests. Responses include revision/ETag; mutations require the expected revision and an idempotency key. Intrusive/raw approvals are browser-only in the initial product; MCP provides request and status tools but no approve tool. The console receives progress, status and live rows over one Server-Sent Events stream per open page. Permission configuration uses only the [Kubernetes API](permissions.md). The existing browser backend supplies read-only effective-access explanation and impact preview; it does not proxy configuration CRUD.

## Schema scope

The checked-in JSON contracts cover user-authored CRDs and public DTOs: target, detectors, actions/recipes, capture profiles, typed composition, syscall actions/results, and policy/capture preset/composition/expanded forms, administrator capacity pools/budget policies, administrator retention policy, artifact privacy/deadlines, artifact manifest/acquisition provenance, access grant, share and protected sharing intent, optional collection-time sharing declarations, permission bindings/sources, access provenance and MCP results/tools. SharingIntent is a SQL-backed runtime DTO, not a CRD or an extra permission CRUD API. SharingRegistration uses transactional reservations under REQ-SHR-006 and REQ-DB-003; migrations enforce capture/artifact uniqueness and bounded counters. Runtime DTO spec/status envelopes must not be mistaken for Kubernetes resources. Helm renders installation-internal configuration; it has no public contract. Capability tables above define remaining controller resource semantics. Generated production CRDs, OpenAPI routes, Helm values schema and API compatibility fixtures must be completed before their implementation phase is declared done.

### Bounds in the contracts

A contract bound needs a stated reason (maintainer rule, 2026-11-14): otherwise it is removed. Capture, policy, recipe, target, trigger, composition, sharing, grant and capacity contracts keep only these kinds of bound:

- **External formats and APIs:** Kubernetes names (63/253 characters, port names 15), OIDC `sub` (255), Linux `PATH_MAX` (4096), `NAME_MAX` (255), `MAX_ARG_STRLEN` (131072 per argument), PID, port, exit-code, signal and snaplen ranges, PSI trigger windows, the classic BPF instruction limit for compiled packet filters, and the JSON exact-integer range (2^53 − 1) that RFC 8785 hashing needs. Duration strings are length-bounded so their value fits int64 nanoseconds.
- **Memory and storage:** packet/syscall ring and segment sizes, frozen-snapshot bytes and concurrent snapshots, HTTP parser memory, retained events, tracked threads, argument bytes per event, log record bytes and per-node ring/frozen memory protect collector memory; free-text reasons and descriptions bound stored record size.
- **Maintainer decisions:** storm-protection rate and concurrency limits (policy `budgets`, budget-policy dump, queue, upload and source limits), the administrator retention maximum and expiring grants for automatic intrusive actions.

Lists have no item caps: detectors, expressions, recipe actions, composition components and edits, ordinals, label selectors, sharing recipients and outputs, grant artifacts and allocations are bounded by the resources they consume (capacity admission, the compiled filter) or by pagination. Result pages keep their page size. Expression nesting stays at depth 8 to bound evaluator recursion.

## Action execution modes and status

The action contract exposes executionMode, default ongoing for packetCapture/syscallTrace and onTrigger for other kinds. Only the two recorder kinds allow an explicit onTrigger variant, with before: 0s. Structural CRD/CEL validation rejects unsupported modes, contradictory history and dependsOn edges on ongoing sources. Resolved plans include modes even when users omit them.

The [lifecycle contract](contracts/action-lifecycle.schema.json) covers the shared preview plan and acquisition provenance. Source sessions are service-owned runtime work under existing capacity budgets, not user-configured CRDs. Policy status distinguishes detector readiness, armed/warming/ready/blocked source counts and action-specific coverage; capture status describes saved incidents. Ongoing source states and their finite manual behavior are specified in [action lifecycles](action-lifecycle.md).

## Capture assessment projections

[capture-assessment.schema.json](contracts/capture-assessment.schema.json) defines the service-owned assessment and scoped artifact handling notice. UI/MCP use the same resolver; Kubernetes submissions publish bounded assessment identity, reason codes and authenticated navigation in protected status before execution. Full assessment details use the authorized query projection, not broadly readable CRD status. Neither publisher-written risk labels nor a submitted assessment is authoritative. No extra CRD or public configuration API is introduced.

## Recording saves and analysis storage

DebugPolicy's preset/composition/expanded forms accept `recordingSaves: {enabled: true|false}`, defaulting to true when the policy has an ongoing action and rejected without one. It is shown on the policy grant review but is not part of the collection execution digest, so changing it needs no grant renewal ([REQ-SAV-001](recording-saves.md)). This is policy configuration, not a new role or permission CRUD API.

Save operations use a recording-save/v1 DTO and existing SQL accepted executions. They are not a new public CRD and cannot be submitted by forging controller-owned status. Browser and MCP use the shared recording inventory and the recording-save branch of the capture preview, and submit the previewed request with `expected_plan_digest` and an idempotency key to its typed executor. Status/cancel, expected revisions, idempotency, optional sharing and audit are shared with ordinary captures. Capture status/history must explicitly label operation=recordingSave; source/policy references never make it a full policy trigger.

Analysis profiles reference an operator-qualified encrypted scratch StorageClass and bounded input/output/aggregate capacity. Missing readiness is AnalysisScratchUnavailable, with collection readiness separately reported. TASK-03/11 must generate and validate the Helm/configuration fields, CSI qualification evidence and independent cleanup reconciliation before claiming a supported profile; no assumed default StorageClass.

## Live-view configuration and runtime boundary

`CollectionCeiling` may narrow `liveRead.enabled`, allowed approved projections and per-scope view limits without granting new collection rights. Hub/connector deployment values configure finite installation/node/principal defaults and reserve incident processing/transfer ahead of live work. The shipped defaults of [REQ-LIV-004](live-watch.md) (watch slots, fanout, delivery rate, replay buffer, per-node projection CPU and examined events/bytes) apply without operator input; a watch closes after 10 idle minutes. Administrator values can only narrow effective admission; setting zero supported projections disables live views. A projection also requires its per-mechanism qualification and the viewer's evidence-read rights, so a boolean alone cannot expose content.

The CPU-time and examined-event/byte limits are typed and bounded in generated Helm/CRD schemas, with the shipped defaults; they are configuration limits, not measured parser throughput. They belong to existing configuration resources, not a new permission role or live-watch CRD. The hub SQL LiveWatch row only accounts slots and cannot be authored with kubectl. Configuration changes and local deny reach active streams as events and end them.
