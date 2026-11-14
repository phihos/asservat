# Trigger storms, workload impact and capacity isolation

Read with [triggers](triggers.md), [actions](actions.md), [privacy](privacy.md) and the [feasibility notes](../docs/research/capacity-isolation.md). Resource protection is independent of permissions: an approved action can still be refused for lack of safe capacity. Storm protection and protection against cross-workload storage exhaustion are maintainer decisions; operators configure them with the few values of [ADR-335](../docs/decisions/335-usable-by-default.md) D2 and D8. Everything else is derived.

## Operator values

| Value | Default | Meaning |
| --- | --- | --- |
| `capacity.evidenceStorage` | the bundled object store's volume size; required for an external store | Usable evidence bytes, after the backend's full threshold and replication overhead |
| `capacity.workload.share` | usable capacity ÷ max(eligible workloads, 8) | Each workload's protected allocation (quantity or percentage) |
| `capacity.workload.limit` | 10 % | Hard maximum per workload (protected share plus burst) |
| `capacity.capturesPerCluster` | max(8, node count) | Concurrent captures per cluster |
| retention values | [REQ-EVD-006](evidence.md#req-evd-006--retention-holds-and-deletion) | Maximum evidence age |

The full set is [capacity.schema.json](contracts/capacity.schema.json); every field is optional. The hub reads these values from its configuration, and changes apply on `helm upgrade`. Sizes accept Kubernetes quantities. They cover every namespace except system namespaces, the release namespace and namespaces labelled `asservat.io/evidence: disabled`; access still requires an AccessBinding. Workload maintainers may narrow a limit in a policy's `budgets`, never raise it or select another account. Capacity is not a CRD: there is one evidence store per installation, and ordinary users need no quota YAML.

## REQ-CAP-001 — Workload-wide storm control

Observe signals continuously within sensor budgets, but admit evidence collection separately. The tightest of the policy, workload, node, cluster and pool limits wins. A workload account is keyed by cluster, namespace and workload name (ADR-335 D4) and covers every selected Pod, manual capture, policy and trigger source. Creating another policy, changing a signature, restarting a Pod or recreating a Deployment of the same name does not reset it. Unowned Pods are charged to a namespace account; clients cannot choose an account.

Storm control is two limits per workload, both `capacity` values ([ADR-335](../docs/decisions/335-usable-by-default.md) D8):

- **Rate limit:** one token bucket (`workload.dump.burst`, default 1; `workload.dump.minimumIntervalSeconds`, default 900) shared by every policy, manual save and trigger source. An occurrence spends one token for its whole action batch, whatever number of processes it covers.
- **Concurrency limit:** `workload.maxConcurrentExpensive` (REQ-CAP-002).

Classify cores, heap dumps and dump-producing diagnostics by their actual operation; unclassified custom acquisition gets the dump envelope. A start with an unknown outcome stays charged until its outcome is reported ([REQ-FED-002](federation.md#req-fed-002--durable-outbound-work-and-compatibility)). A failed dump is not retried automatically.

Coalesce related signals into the existing occurrence. A refused occurrence is suppressed, never queued: suppression is a saturating count per (workload, policy, reason) with first/last times, never one row, object or webhook per hit. Report why collection was skipped and when it can next be admitted.

### SC-CAP-001

Given 10,000 matches/minute across 20 replicas and three policies for one Deployment, when all request a core, then workload-wide admission permits only the available dump budget, records bounded suppression summaries and never creates a queue of 10,000 future dumps. Pod restart, policy edit and a different signature cannot refill the bucket.

## REQ-CAP-002 — Admit before causing impact

Before an expensive action begins, reserve its workload start and bytes, workload/node concurrency, memory/scratch and an upload slot in one operation. A raw-query grant or policy approval cannot override a resource limit. Refuse unavailable optional actions before pausing the application, and keep independently admitted cheap context. Never generate a core first and discover afterwards that storage is full.

Expensive concurrency defaults to one per workload and one per target process (Linux allows one ptrace tracer per tracee; the Go runtime one CPU profile or trace per process), intersected with the node limit (default two). Profiles, commands and dumps share this envelope. At most one expensive request per workload waits; it waits only until its own deadline and must pass the process-start identity check, so a stale trigger yields a gap, not a dump of whatever process now holds the PID. Policies and sessions are not counted beyond Kubernetes object limits and rate limits.

Natural kernel cores cannot wait. They spend from the connector's local budget under an unexpired local policy permit with immediate node admission, or are rejected promptly; the connector reports usage by crash ID, so a repeated report charges once. The host helper never contacts a remote service while holding the crashed process and never drains a rejected core to compute a signature. The kernel's `core_pipe_limit` is a node-wide last resort, not fairness. Asservat cannot prevent crashes or the kernel's own coredump overhead.

Live diagnostics have an action-specific watchdog and safe detach. Cancellation cannot reverse a started command or in-application profiling; an uncertain timeout is `Indeterminate`. Never force-stop a healthy process repeatedly to satisfy a policy.

The [assessment panel](capture-assessment.md) explains expected effects and limits before admission; forecasts reserve nothing. Admission reads the current SQL accounts (REQ-CAP-005); an account whose source is unavailable refuses with `CapacityUnavailable`.

### SC-CAP-002

Given no available storage/scratch reservation, when a live dump is requested, then no ptrace stop, application heap request or custom dump command begins. A natural core without local budget is rejected promptly. A retry with the same operation ID after a lost acknowledgment returns the existing outcome; it neither starts a second dump nor releases a reservation whose outcome is unknown.

## REQ-CAP-003 — Fair scheduling and workload health

Bound collector, compression, encryption, upload and helper resources independently; collector cgroup limits do not bound work inside the target runtime, the kernel or a helper outside the cgroup. Never depend on an optimistic compression ratio for admission or buffer unlimited plaintext behind a throttled uploader.

Key-service load is three wraps per artifact attempt, independent of payload size (REQ-EVD-001). With OpenBao, a saturated provider delays or refuses new acquisition within the request deadline instead of queueing. The crash helper uses keysets wrapped in advance and never waits for a key service. Never fall back to plaintext or reuse another attempt's keys.

Schedule uploads per workload with weighted deficit round robin over bounded byte quanta, never one global FIFO. The connector holds each workload's token bucket (upload rate and burst, default 32 MiB/s and 64 MiB per node, ADR-335 D8) and grants nodes token leases small enough that outstanding leases never exceed the workload burst, so spreading across nodes does not multiply the limit. A restarted uploader forfeits unused tokens. Retries are charged. Expensive work never takes every worker, buffer or I/O slot; each replica keeps one for context and control.

Preflight checks that the largest artifact can be transferred within the action's deadline at the admitted upload share (2 GiB at 32 MiB/s needs 64 s) and reports a mismatch with a smaller dump or longer deadline as remedy. Never raise limits, stop time or workload resources automatically.

A circuit breaker refuses new expensive work on events, not samples: Linux PSI triggers, cgroup `memory.events`, scratch write errors and backlog counters crossing their limits. It recovers after four PSI trigger windows without a new event. A failed health probe alone is not a breaker trip, since it may be the intended trigger. A heap diagnostic during low memory is admitted only when its runtime's headroom requirement is met.

### SC-CAP-003

Given workload A continuously requests large cores while B requests one capture, when both are authorized and fit capacity, then A cannot consume B's scheduler allocation or protected context workers. A full spool, insufficient heap headroom or unsafe transfer deadline prevents the expensive start. Restarting an uploader or node collector does not refill the workload's token bucket.

## REQ-CAP-004 — Protected storage plus hard limits

Protected capacity is allocated when a workload is enrolled for collection, never lent to another workload, and must fit:

```text
sum(protected allocations) + system reserve <= usable pool capacity
```

The system reserve (catalog, index and deletion work) is derived from the pool size. Whatever is not protected or reserved is shared burst. Usage within a workload's allocation consumes its own protected capacity; usage above it consumes burst, up to the workload's hard limit. Charges are committed bytes plus outstanding maximum reservations. A small context reserve inside each allocation, derived from the context record size, keeps pod-status capture possible when dumps have filled the rest. Lowering a capacity value below allocated usage reports over-limit and blocks new allocations; it never retracts an allocation with usage. Recomputing the default share shrinks only allocations without usage.

Example: a 128 GiB usable pool with a derived 8 GiB reserve and `workload.share: 16Gi` protects six workloads (96 GiB) and leaves 24 GiB of burst. With a 32 GiB workload limit, A may use its 16 GiB plus 16 GiB of burst; B–F keep their protected 16 GiB however often A triggers.

The guarantee is admission within a workload's **remaining** protected capacity on healthy, provisioned storage, not unlimited history. A bucket or prefix reserves no physical disk: `storageAssurance: qualifiedReservedBackend` requires dedicated or backend-enforced capacity; shared physical storage is `bestEffort` and cannot satisfy the isolation claim.

Node limits for ring memory, frozen-snapshot memory and upload rate are the collector's Helm values ([ADR-246](../docs/decisions/246-node-collector-role.md)). Ring and frozen memory derive from the collector's memory limit (ring + frozen + baseline ≤ limit, half the remainder each). A reservation that does not fit fails without partial effect.

### SC-CAP-004

Given the 128 GiB example with A at its 32 GiB hard limit, when B requests evidence within its unused allocation, then storage admission succeeds independent of A's trigger rate. A is refused before acquisition and cannot evict B's evidence. More protected allocations than the pool can back are rejected at enrollment, rather than silently overcommitted.

## REQ-CAP-005 — Durable hub and local accounting

PostgreSQL holds the quota accounts and reservations. The hub applies each change of the `capacity` values to `capacity_account` rows when it reloads its configuration. A raised limit admits more at once; a lowered one blocks new admissions above it without invalidating evidence. The pool invariant is checked when allocations change.

Each reservation is keyed by its operation and attempt ID. Admission within a protected allocation is one conditional update of the workload row; only burst also locks the pool row, before the workload row ([persistence](persistence.md)). No database write occurs per packet, log line or byte.

Reads (queries, downloads) are bounded by reader concurrency and query bounds, not workload storage; downloads have no request-count cap (ADR-335 D9).

The hub assigns each connector a local budget (bytes and starts) over its connection and charges it to the hub accounts. The budget has no expiry and stays valid until the hub replaces it ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1, [ADR-332](../docs/decisions/332-standing-connector-identity.md)). The connector keeps it in memory plus one small local checkpoint object; natural cores and disconnected work spend from it. On reconnect the connector reports its usage and receives a replacement; the hub releases the unused remainder. Removing the cluster from the hub's values releases its remainder.

Reserve worst-case stored ciphertext (format overhead, compression expansion, retries and planned derivatives) before upload, using a qualified format bound, never expected compressibility. Uncompressed input, transfer bytes and local scratch are separate limits. If a derivative cannot be reserved, report partial analysis. Committing a reservation never double-charges or briefly releases bytes.

Object keys are deterministic (`…/<workload account>/<operationID>/<attemptID>/…`), so a retry writes or HEADs the same key. An attempt with an unknown outcome is resolved by listing its prefix; buckets carry an `AbortIncompleteMultipartUpload` rule. Stored objects, noncurrent versions and deletion-pending artifacts stay charged until the store confirms deletion. Shares reference the original bytes without a second charge; a new derivative charges its source workload, split explicitly across workloads for multi-workload results. After a database restore, usage is recomputed from the bucket inventory (REQ-DB-005).

### SC-CAP-005

Given two 8 GiB attempts racing for 8 GiB remaining capacity, when both reserve, then only one becomes Ready. A crash after multipart start keeps the charge until listing the attempt's prefix resolves it; the lifecycle rule removes the incomplete upload. A failed DELETE or hidden version does not free space for another reservation. A retry with the same operation ID reuses its reservation and cannot double-charge.

## REQ-CAP-006 — Exhaustion and visibility

A full account rejects new expensive work (`RejectNewExpensive`, the default): prior evidence stays, context continues within its reserve, and the status names `WorkloadStorageFull`, `PoolBurstFull` or `CapacityUnavailable`. Other workloads keep their protected capacity. An administrator may set `capacity.workload.onFull: DeleteOldestEligibleInAccount`, which deletes only the same workload's oldest unheld evidence, verifies removal and then reconsiders a still-fresh request; it never evicts another workload or waits while a process is stopped. Retention is a maximum, not a promise to keep every artifact. Held artifacts keep consuming capacity.

`capacity.namespaceLimit` caps a namespace's total bytes, so many small workloads cannot monopolize enrollment. Automatic onboarding allocates from that namespace capacity; when it cannot, the workload reports `CapacityNotAllocated`. Deleting or renaming a workload does not erase its charges.

Show usage per workload: retained, in flight, deletion pending, protected remaining, burst use, upload pressure, suppression count and next eligible start. A skipped action names the limiting scope and remedy without exposing another team's inventory. MCP and case results distinguish evidence missing because of limits from evidence that never existed.

### SC-CAP-006

Given A fills its account, when another trigger arrives, then it records suppression and available context without deleting B's evidence. If own-account rolling deletion is enabled but an object is held or deletion fails, its charge remains and no dump starts. A newly enrolled workload without backed capacity is visibly pending, not falsely protected.

## Shared limits for other features

- [Guided surveys](guidance.md) are ordinary admitted captures under the same accounts and rate limits; incident capture takes priority.
- A [composed capture](capture-profiles.md) reserves its whole expansion under one workload account. Rings, frozen copies and parser state stay separate reservations; a duplicate expensive acquisition is a preview conflict. A separate namespace or catalog cannot obtain a second allocation.
- Syscall event, rate and thread caps bound acquisition work separately from output bytes (reviewed observation budgets, [syscalls](syscalls.md)); dropped events do not refund the rate.
- [Execution modes](action-lifecycle.md): steady ring, parser and CPU resources are reserved for every armed Pod before attach; frozen segments, output and upload are reserved per admitted trigger. Ongoing sources are bounded by ring sizes and rates; only intrusive automatic recorders have a grant expiry (ADR-335 D6). Upload congestion never turns a bounded source into unlimited storage.
- [Recording saves](recording-saves.md) spend the same occurrence rate and snapshot reservations as automatic saves; extra request paths get no extra budget. A save that cannot be admitted is refused with a retry time, not queued.
- [Live views](live-watch.md#req-liv-004--protect-collection-and-workload-resources) charge viewer slots, scan work, replay memory and output to the existing workload account, with per-principal caps across tabs. Slow clients drop rows rather than block acquisition.

### Ongoing source limits

The node collector's Helm values set `maxActiveSources`, `inputBytesPerSecond` and `inputBurstBytes` (all positive, or all zero to deny ongoing sources). Defaults derive from the collector's resources: ring-memory ceiling ÷ minimum per-source ring, and CPU limit ÷ qualified CPU per input byte (burst one second). Sources share slices of these totals rather than each receiving the full allowance. These defaults need native performance qualification before ongoing collection is enabled.
