# Implementation architecture boundaries

The [architecture package](../docs/architecture/README.md) maps the accepted product to applications, components, modules and internal interfaces. It refines the existing behavior; it does not authorize production deployment or waive qualification gates.

## REQ-ARC-001 — Explicit runtime authority

Each scheduled role MUST have a defined entry point, image/tool set, service identity, network/storage privileges, lifecycle and scaling owner. Share source code and a role-selecting Go binary where appropriate, while retaining separate API/worker, node, acquisition, analyzer and publication authority. Node control is collector-initiated to the local connector; the hub cannot require inbound node access or workload kubeconfigs. Evidence-bearing caches remain within approved regional boundaries. Optional capabilities degrade independently.

### SC-ARC-001

Given a control-plane-only install and an analysis-enabled cluster, when their manifests are generated, then the control roles have no CRI/raw unwrap authority, the analyzer has no network/service token, and acquisition/publication use different credentials and fenced encrypted-volume handoffs. Missing analysis qualification does not disable authorized context reads.

## REQ-ARC-002 — One lifecycle owner and enforceable dependencies

Maintain the architecture catalog with one primary component owner per domain entity and requirement, application composition, planned package families and explicit allowed dependencies. Domain types are distinct from SQL rows, Kubernetes objects and transport DTOs. Application services depend on typed consumer-owned ports, never concrete persistence/transport/collector adapters. Cross-component transactions use narrow facets in the canonical lock order; no component obtains a generic database or Kubernetes handle through an escape hatch. Only composition roots wire concrete implementations.

### SC-ARC-002

Given a change that adds an entity, imports a concrete adapter into an application service, or creates a component dependency cycle, when design/code architecture checks run, then missing ownership or the invalid dependency fails. Legitimate multi-owner-row admission is a declared transaction with named participating facets, not independent per-component commits.

## REQ-ARC-003 — Bounded versioned internal contracts

Internal network/IPC contracts MUST identify peers, supported versions/capabilities, exact purpose, immutable operation identity, source/target and scope digest, deadline, fence, resource authority and bounded outcomes. Strict schemas reject unknown required semantics; negotiated versions do not reinterpret an accepted plan. Control work carries minimized references rather than evidence or arbitrary command strings. Transient live batches have separate privacy/size/expiry rules and never enter a durable control outbox. HTTP/IPC caps apply before decompression or allocation can escape the budget.

### SC-ARC-003

Given an older connector, an unexpected work purpose, a live projection disguised as a capture, or an over-limit body, when decoding/negotiation occurs, then execution is rejected before side effects. A supported N/N-1 peer receives only compatible schemas and preserves operation identity across retries.

## REQ-ARC-004 — Receiver deduplication and effect fencing

Separate delivery lease, accepted execution, individual start identity and evidence commit. The receiving executor MUST persist the authorized start disposition before an intrusive effect; hub/controller retries query or redeliver that same identity. Kubernetes/SQL leases alone do not fence a process. Unknown starts stay Indeterminate and charged; loss of spend/boot identity invalidates reuse. No effect is executed inside a retried SQL callback. Natural cores consume an already durable, single-use local allocation without synchronous remote preparation.

### SC-ARC-004

Given the response is lost immediately after a dump starts and then a connector leader changes, when work is redelivered under a newer delivery fence, then the start identity is unchanged and no second dump occurs. If the original result cannot be established, it remains Indeterminate; a returned lease does not refund capacity.

## REQ-ARC-005 — Qualified collector and analyzer extension ports

An adapter MUST declare action kinds, lifecycle modes, environment prerequisites, supported projections, process/target binding, impact/data classification, resource dimensions, cancellation and partial-output semantics. Acquisition requires framework-validated execution authority and bounded output writers. Ongoing sources expose separate arm/snapshot/stop/live operations; save-only dispatch cannot call onTrigger acquisition. No dynamic user-supplied plugin, generic host exec, raw live projection or unconstrained tool output interface. New mechanisms require contract fixtures, isolation tests and qualified impact/loss evidence before advertising readiness.

### SC-ARC-005

Given a new profiling or tracing adapter, when it is registered, then unsupported modes/projections fail validation, a preview performs no acquisition, and timeout/target loss yields bounded partial or unavailable output. A recording-save request reaches only the existing-source snapshot port and cannot invoke a dump or command adapter.

## REQ-ARC-006 — Failure, resource and privacy ownership

Every critical runtime flow MUST assign the next transition, retry policy, residual charge/copy, current-rights check and deletion obligation to a component. Preserve separate installation/workload/node budgets, protected snapshot priority over live delivery, denial/cleanup during outages and bounded local authority. Expose recovery state and gaps. Database restore must not revive past approvals or watches; object/volume deletion is verified before the relevant charge is released.

### SC-ARC-006

Given hub/database failure and saturated live readers during a triggered save, when the system degrades, then eligible prepaid work and local deletion remain bounded, live delivery sheds before protected saving, expired reads are denied and uncertain reservations/copies remain tracked. Recovery revalidates authority instead of trusting restored cache state.

## REQ-ARC-007 — Traceable implementation slices

Each implementation slice MUST identify owned components, existing requirements/tasks, interfaces and observable acceptance/fault tests. The first end-to-end slice includes authorized bounded collection, encrypted evidence, approved UI/MCP retrieval, expiry and verified deletion. Subsequent slices preserve the same services and state authority; feasibility spikes may reject an adapter without creating a parallel production path. Keep documentation checks, simulated contract checks and real runtime qualification results distinct.

### SC-ARC-007

Given an agent implements a slice, when its handoff is reviewed, then component ownership and dependency rules locate the change, API/contract examples agree, required negative/failure checks are reported with actual results, and no successful static validator is presented as proof of runtime security or performance.
