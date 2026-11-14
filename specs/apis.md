# Kubernetes and internal API contracts

## REQ-API-001 — Resource model

Configuration is Kubernetes resources in `asservat.io/v1alpha1`, namespaced unless stated. The portable [contracts](contracts/) are design examples, not deployable CRDs.

| Kind | Location / writer | Content |
| --- | --- | --- |
| `EvidenceRecipe` | Workload namespace; service owner | Typed action DAG, limits, runtime hints |
| `CaptureProfile` | Builtin/organization catalog or workload namespace; publisher | Immutable versions with editable fields ([capture profiles](capture-profiles.md)) |
| `DebugPolicy` | Workload namespace; service owner | Preset, profile composition or expanded target/detectors/recipe/budgets; optional bounded future-result sharing |
| `DebugCapture` | Workload namespace; requester | Preset, composition or expanded request with optional result sharing; immutable after acceptance |
| `AccessBinding` | Application namespace it grants; namespace RBAC writers ([ADR-329](../docs/decisions/329-accessbindings-in-application-namespaces.md)) | Subjects/groups by name, roles, namespace or named workloads, optional expiry |
| `ClusterAccessBinding` | Cluster-scoped; cluster administrators | AccessBinding for every matching namespace, or named clusters from the hub cluster ([permissions](permissions.md)) |
| `PermissionSource` | Hub control namespace; administrators | Typed derivation rule, scope and trusted mapping |
| `CollectionCeiling` | Collector namespace; cluster admin | Optional narrowing of the default (every non-system namespace collectable) |
| `EvidenceStoragePool` | Hub control namespace; administrator | Backed capacity and reserves ([capacity](capacity.md)) |
| `EvidenceBudgetPolicy` | Hub control namespace; administrator | Per-workload capacity and storm limits ([capacity](capacity.md)) |
| `EvidenceRetentionPolicy` | Hub/collector control namespace; administrator | Default/maximum ages ([privacy](privacy.md)) |

Every resource reports Conditions with `observedGeneration`. Runtime records (cluster registrations, grants, shares, capacity counters, work, cases, accepted executions and audit rows) are PostgreSQL rows defined by [persistence](persistence.md); they have no Kubernetes endpoint. Per-attempt and per-delivery state is not a Kubernetes object: the connector keeps it in memory keyed by operation ID and rebuilds it from hub work after a reconnect ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D8). Secrets hold credentials; no other resource contains secret values or evidence bytes.

### SC-API-001

Given an attempted direct grant/share record write by a workload user or a CRD containing raw log bytes, when service authorization or Kubernetes admission/RBAC runs, then it is rejected. Grants/shares have no writable CRD endpoint. Completed case history can grow without growing one Kubernetes object indefinitely.

## REQ-API-002 — Validation and immutable execution

CRDs MUST use structural schemas, known enums and explicit defaults; CEL validates same-object invariants. Generated CRDs express the preset/composition/expanded branches as one structural union with CEL exclusivity; check all three forms against a real API server before publishing. Admission is not authorization for privileged execution.

`DebugCapture.spec` and published `CaptureProfile` versions are immutable. Policy and recipe revisions compile to immutable plan digests; `status.observedGeneration` advances after the generation is validated, and the Kubernetes audit log attributes changes (ADR-330 D10). Finalizers retry with standard controller backoff; evidence retention never depends on a workload ownerReference.

Authored references use names ([ADR-335](../docs/decisions/335-usable-by-default.md) D4); the hub resolves them to UIDs and digests at decision time and records those as provenance. Requests carry no grant reference: the hub selects the eligible grant ([execution identity](execution.md)). Timestamps are RFC3339, byte counts integers, durations explicit strings, digests lowercase SHA-256, system IDs UUIDs. Unknown API versions fail clearly; conversion cannot widen permissions or turn omitted bounds into unlimited ones.

### SC-API-002

Given a schema-valid request with an expired grant or a recipe digest mismatch, when it reaches execution, then it is denied. A spec update cannot mutate an accepted capture's target, action list or byte budget.

## State machines

A capture has one phase plus Conditions: `Pending → AwaitingApproval | Armed | Running → Succeeded | Partial | Failed | Cancelled | Indeterminate`, with Conditions Accepted, Collected, Verified and Published. Succeeded requires Published for every required output; derivation rules are in [REQ-EXE-002](execution.md). Other lifecycles have one owner:

| Object | Owner |
| --- | --- |
| Policy | Conditions with `observedGeneration`; grant expiry in [authorization](authorization.md) |
| Ongoing source | [REQ-LIF-002](action-lifecycle.md) |
| Artifact deletion | [REQ-PRV-004](privacy.md) |
| Grant | [grant contract](contracts/grant.schema.json) |
| Share | [REQ-SHR-001](authorization.md) |

## Internal hub/connector connection

One outbound, multiplexed HTTP/2 connection per connector to the hub's one HTTPS endpoint (ADR-330 D2, [ADR-334](../docs/decisions/334-connector-workload-identity.md)); [I-01](../docs/architecture/interfaces.md) defines the wire contract. It is private and not agent-accessible.

## User HTTP interface

The console uses a same-origin HTTP API with OIDC sessions and CSRF protection, projecting the same data as MCP ([interfaces](interfaces.md)). Mutations require the expected revision and an idempotency key. Intrusive and raw approvals are browser-only. Permission configuration uses only the [Kubernetes API](permissions.md).

## Bounds in the contracts

A contract bound needs a stated reason (maintainer rule, 2026-11-14); otherwise it is removed. The bounds that stay and their reasons:

- **Kubernetes object size:** a CRD object is at most 1.5 MiB (etcd request limit). Array, string and map bounds in generated CRDs exist only so CEL rules fit the per-expression cost budget within that size.
- **Identifier formats:** Kubernetes names (63/253 characters, port names 15), UUIDs, lowercase SHA-256 digests, 32-byte CSRF/state tokens and S3 version IDs (1024 bytes) have their external formats; duration strings have no length cap (their pattern fixes the form), and counts stay within the JSON exact-integer range (2^53 − 1) that RFC 8785 hashing needs.
- **Linux and protocol limits:** `PATH_MAX` (4096), `NAME_MAX` (255), `MAX_ARG_STRLEN` (131072 per argument), PID, port, exit-code, signal and snaplen ranges, PSI trigger windows. A compiled packet filter has at most 4,096 classic-BPF instructions (`BPF_MAXINSNS`); the filter text has no separate cap because the compiled bound is authoritative. HTTP header extraction keeps at most 32 KiB of headers per message, the common server header limit.
- **Hub/connector frames:** data frames are 1 MiB (connector and hub memory per stream); command/control frames are at most 64 KiB, enough for a 4,096-instruction BPF program (32 KiB) plus its envelope.
- **MCP results:** one tool result is at most 96 KiB, derived from the common MCP client tool-output limit (Claude Code `MAX_MCP_OUTPUT_TOKENS`, 25,000 tokens ≈ 100 KB); results aim at 24 KiB by default to leave room in the model context. Page sizes derive from this result bound minus the fixed envelope; the client may request smaller pages. The browser has no client-side response byte ceiling: server pages and the SSE stream bound it.
- **Memory and storage:** packet/syscall ring and segment sizes, frozen-snapshot bytes and HTTP parser memory are maintainer-approved bounds for recorders (ADR-335 D6: rates and ring sizes); their defaults derive from the node collector's memory request. Argument bytes per event and log record bytes protect collector memory. The framed artifact layout fixes 8 MiB frames and 256-frame index pages (reader memory per frame, [artifact format](../docs/architecture/artifact-format.md)).
- **Maintainer decisions:** storm-protection rate and concurrency limits (policy `budgets`, budget-policy dump, queue, upload and source limits; ADR-335 D8), the administrator retention maximum (D7), expiring grants for automatic intrusive actions (D6), finite manual requests, reviewed observation budgets for syscall arguments and the finite parent disclosure pool.

Lists have no item caps beyond fixed structures (a classic-BPF program, the six syscall arguments, the PSI trigger kinds, a framed index page). Detectors, expressions, recipe actions, composition components and edits, ordinals, label selectors, sharing recipients and outputs, grant artifacts and allocations are bounded by the resources they consume (capacity admission, the compiled filter, the Kubernetes object size); list-shaped results use cursor pagination instead of caps. Expression nesting stays at depth 8 to bound evaluator recursion. `scripts/check-limits.py` (run by `make spec-check`) fails on any contract bound without one of these reasons.
