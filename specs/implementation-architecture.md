# Implementation architecture boundaries

The [architecture package](../docs/architecture/README.md) maps requirements to applications, components and internal interfaces. `make architecture-check` verifies that every requirement in [traceability](traceability.yaml) and every domain entity has one owning component and that dependencies follow the declared rules. Feature behavior stays in the feature specs: receiver deduplication in [federation](federation.md), unknown outcomes and recovery in [persistence](persistence.md).

## REQ-ARC-001 — Explicit runtime authority

Each scheduled role MUST have a defined entry point, image, ServiceAccount, network/storage privileges and scaling owner; one role-selecting Go binary is allowed. Hub, node collector, regional reader and analyzer keep separate authority. The regional reader is a long-running, scaled Deployment serving downloads, stored-evidence queries and publication verification; offline analysis keeps separate acquisition, analyzer and publication Jobs ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D4). hub-api runs replicated with rolling updates and hub-worker is leader-elected with a standby (ADR-335 D13). Node collectors connect to their local connector; the hub needs no inbound node access or workload kubeconfig. Optional capabilities fail independently.

### SC-ARC-001

Given a control-plane-only install and an analysis-enabled cluster, when their manifests are generated, then the control roles have no CRI/raw unwrap authority, the analyzer has no network/service token and receives its input only through qualified encrypted scratch (ADR-036). Missing analysis qualification does not disable authorized context reads.

## REQ-ARC-002 — One owner and enforceable dependencies

The architecture catalog MUST name one owning component per domain entity and requirement, and the allowed dependencies. Application services depend on consumer-owned ports, never on concrete persistence, transport or collector adapters; only composition roots wire implementations. Cross-component transactions use narrow Go interfaces in the canonical lock order; a process uses one SQL login and one pool (REQ-DB-004).

### SC-ARC-002

Given a change that adds an entity, imports a concrete adapter into an application service, or creates a component dependency cycle, when design/code architecture checks run, then missing ownership or the invalid dependency fails. Legitimate multi-owner-row admission is a declared transaction with named participating facets, not independent per-component commits.

## REQ-ARC-003 — Versioned internal contracts

Internal messages MUST carry purpose, operation ID, target, plan digest and deadline, and negotiate versions; authority stays on the hub and is referenced by operation ID. Unknown required fields are rejected; a negotiated version never reinterprets an accepted plan. Control messages carry references, never evidence or arbitrary command strings. Size caps apply before decompression or allocation (frame sizes: [bounds](apis.md#bounds-in-the-contracts)); evidence travels as streamed chunks. Live rows never enter the durable work outbox.

### SC-ARC-003

Given an older connector, an unexpected work purpose, a live projection disguised as a capture, or an over-limit body, when decoding/negotiation occurs, then execution is rejected before side effects. A supported N/N-1 peer receives only compatible schemas and preserves operation identity across retries.

## REQ-ARC-005 — Qualified collector and analyzer extension ports

An adapter MUST declare action kinds, lifecycle modes, prerequisites, projections, target binding, impact and data class, resources, cancellation and partial-output behavior. Ongoing sources expose separate arm, snapshot, stop and live operations; a save cannot invoke on-trigger acquisition. No user-supplied plugin, generic host exec or unconstrained tool output. A new mechanism needs contract fixtures, isolation tests and measured impact before it reports ready.

### SC-ARC-005

Given a new profiling or tracing adapter, when it is registered, then unsupported modes/projections fail validation, a preview performs no acquisition, and timeout/target loss yields bounded partial or unavailable output. A recording-save request reaches only the existing-source snapshot port and cannot invoke a dump or command adapter.
