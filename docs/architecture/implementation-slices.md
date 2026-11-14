# Implementation slices and architecture acceptance

These slices refine [TASK-01–11](../implementation-plan.md); they do not replace those IDs or remove product scope. Slice status is in [implementation progress](../implementation-progress.md). Implement shared authority, privacy and capacity foundations before enabling effects.

The [technology selection experiments](../../experiments/technology-selection/README.md) and the feasibility labs are S-00 evidence, not S-00 completion. The [build/reuse matrix](build-or-reuse.md) names reusable pieces and ownership for every component. Mechanisms follow [ADR-330](../decisions/330-event-driven-system-design.md).

## Sequence

| Slice | Components and existing tasks | Deliverable and acceptance |
| --- | --- | --- |
| S-00 — Contract and feasibility baseline | C-04/11/12/14/18/21/22/23; TASK-01/11 | Review architecture and exact versions. Run already planned high-risk spikes in disposable authorized environments: receiver dedup/spend, Gadget private transport/ABI and atomic filter updates, encrypted storage/analysis handoff, key lifecycle and host core bounds. Unsupported mechanisms stay unavailable. No feature-wide readiness inferred from one successful sample. |
| S-01 — Typed core and role composition | C-01/02/03/04/07/08/15/19/20/21/24; TASK-02/03/07 | Go role entrypoints/composition roots, domain conversions, actual SQL migrations/query contracts, local CRD types, connector bootstrap-token/CSR identity, mounted configuration, SQL audit rows and the database-incarnation fence. Two connectors negotiate/reconnect under N/N-1 fixtures. Real authority/capacity concurrency tests, not only mocks. |
| S-02 — First complete context investigation | C-05/06/09/11/14/15/16/20/21/23; TASK-02/03/05/07/08/11 | A maintainer selects an authorized workload, previews and submits one bounded low-impact context snapshot. It is encrypted, committed, visible as an approved extract in UI and MCP, downloadable in its native format, then expires and is verified deleted. Exercise a second workload cluster through the same hub. No intrusive adapter enabled yet. |
| S-03 — Automatic bounded collection | C-06/07/09/10/11/16/19; TASK-04/05/07/11 | Policy activation and all-replica observation with separate incident cap. Log/resource/probe triggers produce deduplicated occurrences. Storm tests prove cooldown/coalescing, fair capacity and no per-match acquisition queue explosion. Executor provenance and policy grant controls exist before sensitive policy actions. |
| S-04 — Continuous recording and explicit save | C-05/06/07/11/12/14/15/23; TASK-05/06/07/08/11 | Qualified packet/syscall metadata sources, segmented rings, dynamic peers, source warming/loss, automatic snapshots and Save existing recordings now. Save-only dispatch demonstrably cannot start other actions. Ring/frozen/upload budgets remain separate. |
| S-05 — Profiles, analysis and deeper inspection | C-06/14/15/18/23; TASK-03/05/08/11 | Named pprof endpoint acquisition and offline profile/network/file queries, qualified bounded Go projections in the regional reader (ADR-286), approved extracts and independent bounded raw-query review. Native tools and evidence-supplied execution retain encrypted separate-Job staging (ADR-036). Fuzz hostile inputs/outputs; reject wrong symbols, incompatible sample units and unconfirmed writer termination. |
| S-06 — Sharing, reuse and administration | C-01/03/06/09/15/16/17/20; TASK-07/08/11 | Multiple manager teams, concrete/future sharing, recipient-only views, revocation, recent-selector history, repeat with fresh checks, profile publication/adaptation, permission/retention/capacity previews. Group/namespace churn and expiry never widen audience or reset spend. Basic privacy/admin controls already exist in S-01/02; this completes their UX. |
| S-07 — Live observation | C-07/12/13/19/20/23; TASK-06/08/10/11 | Finite approved live projections in UI/MCP, direct display filters, pause/resume/gaps, connection failover and fresh save flow. Measure maximum-viewer overhead and prove protected incident saves win under contention. No per-row SQL write or durable live payload. |
| S-08 — Intrusive and native crash mechanisms | C-03/07/08/11/14/22/23; TASK-05/09/11 | Independent ad hoc approval, reviewed finite automatic grants, stable multi-process selectors and live dump serialization. Native crash helper with preprepared encryption/capacity, ownership/uninstall and bounded remote-outage behavior. Actual PID reuse, process pause, kernel/runtime and privilege tests required. |
| S-09 — Production qualification and release packaging | All applicable; TASK-10/11 plus earlier exits | Recovery/failover, two-cluster partitions, version skew, resource/retention scale, parser robustness, privacy leakage review, offline dependency/image provenance, supported browser/accessibility/user studies and operator runbooks. Publish support only for measured qualified profiles. |

S-05 endpoint profiling can proceed alongside S-04 after S-02 where independent; S-06 sharing logic can progress alongside collectors after its authority/commit foundations. These are code dependencies, not authority to skip the existing tests or begin privileged experiments now. S-08's risk experiments happen early in S-00 even though enabling the product mechanisms comes later.

S-01/S-02 also require [complete-path availability qualification](../validation.md#complete-path-availability): count the full installed call graph by actual shared client, then measure useful completion with original deadlines and normal background activity. Separate component passes and expected-denial regressions do not establish an available installed workflow.

## S-02 exit in detail

A release-like synthetic fixture runs an opted-in Deployment in two workload clusters. An unrelated principal cannot enumerate or collect it. An allowed principal submits through browser and MCP into the same C-09 service, with identical normalized scope and current authorization. The node returns a bounded approved pod-status/file-field extract; it cannot read an arbitrary path from an unauthenticated request. Operator qualification enables that exact adapter only.

The test must demonstrate:

1. Duplicate submit/receipt with the same idempotency key yields one operation and one effect, with a stable deadline. Conflicting idempotency content is rejected.
2. Lost target, denied field, object/KMS failure and exhausted workload capacity produce useful Partial/Unavailable states without plaintext fallback.
3. Before an artifact exists, copies and worst-case capacity are recorded. Artifact commit is verified; the SQL catalog contains minimized metadata, not the evidence text.
4. Retrieve the authorized approved context artifact through UI/MCP and download its native file for a compatible local tool. Verify exact bytes/checksum, bounded resume and expired/revoked denial. Retained audience and current rights are checked once per read operation (ADR-311); full raw evidence and raw-query paths remain unavailable without their covering grants.
5. Read cutoff denies access; all managed copies in this slice are deleted or explicitly overdue, and the corresponding capacity is released only after verified cleanup. Test a failed deletion with the charge retained.
6. Hub disconnect/reconnect never repeats collection: after a reconnect the hub resends non-terminal work and the connector returns the existing outcome for a known operation ID, including a completion whose reply was lost, which is then verified and published. A superseded collector connection cannot start work.
7. The browser and MCP show the same scope, impact uncertainty, gaps, audience and effective deletion information. No optional live/core/parser feature is advertised as ready.

The slice may use a qualified node-produced approved context projection; it does not need to pretend the later general offline analyzer has been implemented. Include the production encryption, SQL audit and locality path rather than an in-memory shortcut. Passing these tests validates that slice in its tested environment, not every planned mechanism.

## Architecture acceptance and open qualifications

| Boundary | Design decision fixed here | Runtime evidence still required |
| --- | --- | --- |
| Hub decomposition | API and worker roles share modular application code, separate scheduling/credentials | Replica races, queue fairness, connection budgets, connection failover |
| Transport | One multiplexed connector connection; collectors connect to the connector with TokenReview then mTLS | Certificate rotation, superseded collector exclusion, lost-response lookup by operation ID |
| Persistence | SQL hub authority and audit rows; Kubernetes configuration; object-store evidence | Real transaction/recovery tests, idempotent replay after lost commits |
| Gadget | Pinned private adapter behind bounded lifecycle ports | Supported transport/ABI, runtime/kernel feature probing, loss/overhead and peer updates |
| Analysis | Separate acquisition/offline/publish identities and encrypted PVCs | CSI encryption, stage ordering on Job completion, hostile output, deletion under failure |
| Live | Rows routed from the replica holding the connector connection, one authorization per operation, SSE delivery | Regional routing, slow readers, no incident starvation |
| Host crash | Local bounded helper with prepared envelopes | Kernel-global behavior in disposable VMs, process reaping delay |
| Compatibility | Strict versioned DTOs over mTLS, N/N-1 minors | Malicious input, canonicalization and version-skew tests |

Changes that require a new architecture decision include a new always-on service, broker, state backend, regional frontend topology, dynamically supplied executable plugin, weakened authority boundary, raw live evidence, or a new polling loop where an event source exists. Normal module splits within the allowed dependency graph and qualified adapter additions do not require repeated user permission.

## Handoff template

For each slice, record requirement/task/component/interface IDs; implementation paths; schema/version and migration changes; default/negative/failure results with real command exits; tested environment/digests; unresolved limitations; and the next dependent slice. Preserve pending qualification as pending. Use the [architecture checker](../../scripts/check-architecture.py) for design consistency and add real Go/import/runtime gates as the code is introduced.

Native downloads extend S-02 with download of the first approved context artifact, S-04 with Wireshark-ready packet evidence, S-05 with runtime-profile/analysis output and S-08 with native core plus exact available companion downloads. S-09 must qualify real local-tool open/checksum/resume, revoked/expired/recipient cases, relay locality and incident priority. REQ-DLD-001–004 are mandatory for every newly enabled artifact type, not a later optional export milestone.
