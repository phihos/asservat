# Trigger storms, workload impact and capacity isolation

Read with [triggers](triggers.md), [actions](actions.md), [privacy](privacy.md) and the [feasibility notes](../docs/research/capacity-isolation.md). These requirements add resource protection independently of permissions: an approved action can still be refused for lack of safe capacity.

## REQ-CAP-001 — Workload-wide storm control

Observe signals continuously within sensor budgets, but admit evidence collection separately. Apply all relevant limits across policy, workload, namespace, node, cluster and storage pool; the tightest limit wins. The workload account includes every selected pod and its runtime sources, manual capture, policy, trigger source and policy generation. Creating another policy, changing a signature, restarting a pod or rolling a Deployment does not reset its counters. Unowned pods/direct selectors remain charged to a namespace envelope and a controller-assigned account; clients cannot choose an account to escape limits. Workload identity includes cluster/namespace/workload UIDs. Replacement workloads cannot shed retained charges or bypass parent limits.

Keep existing context-capture cooldowns and hysteresis. Add a stricter dump bucket: proposed defaults are burst 1, minimum 15 minutes between dump episodes, at most 2 individual process starts and 4 GiB of uncompressed input reservations in any rolling hour per workload. These are configurable starting budgets, not universal safe values. The interval/burst limits gate a dump episode (one immutable action batch for one occurrence); rolling-hour starts/bytes count every individual process. maxProcessesPerEpisode defaults to one and may be raised through an administrator budget profile for explicit multi-process recipes. An episode freezes its process set and reserves all starts before dispatch; it cannot append reloads/workers or remain open beyond its original action deadline. This allows bounded serial multi-process snapshots without treating unrelated triggers as the same episode. The initial contract keeps episode burst fixed at one and configures the interval/hourly ceilings. Classify kernel cores, live cores, heap dumps and dump-producing diagnostics by their actual operation. Unclassified custom acquisition receives the conservative expensive/dump envelope unless an administrator-qualified recipe proves a narrower class. Reject relabeling to bypass limits. Failure after a possible start consumes the start and conservatively reserves bytes until outcome is known; a failed dump does not trigger an immediate retry loop.

Coalesce related signals into the existing occurrence and aggregate further suppression by workload, policy/source and reason in bounded 30-second windows. Preserve first/last times, saturating counts and gaps, not raw matched text or one CRD/object/webhook per hit. Report why collection was skipped and when it can next be admitted. New signatures may influence selection within the budget; they cannot bypass it. No queued dump is automatically started merely because cooldown expired: the original request must still be fresh and its process identity valid. An ongoing condition needs an explicitly enabled bounded resampling policy to collect again. The ADR-228 restart trigger keeps one suppression row per policy and reason for the policy's lifetime (no 30-second window): its occurrences are already admission-bounded, so the row count is fixed and only first/last times and the saturating count change.

### SC-CAP-001

Given 10,000 matches/minute across 20 replicas and three policies for one Deployment, when all request a core, then workload-wide admission permits only the available dump budget, records bounded suppression summaries and never creates a queue of 10,000 future dumps. Pod restart, policy edit and a different signature cannot refill the bucket.

## REQ-CAP-002 — Admit before causing impact

Before an expensive action begins, reserve authorization, a workload start/byte budget, workload/node concurrency, memory/scratch, storage bytes/object count and an upload service slot. The immutable operation binds every reservation and the resolved action limits. A raw-query grant or policy approval cannot override any resource ceiling. Reject or skip unavailable optional actions before pausing the application; preserve independently admitted cheap context. Do not generate a core first and discover afterward that storage is full.

Default expensive concurrency is one per workload and one per target process, intersected with the node's configured limit (proposed two expensive actions/node). Profiles, commands and dumps share this expensive-work concurrency envelope unless a qualified recipe has a lower class; conflicts inside one runtime serialize as before. Queued requests are bounded (proposed one expensive request/workload, ten/node), expire after at most 30 seconds or their earlier request/target deadline, and carry no unbounded retained data. Expired triggers produce a gap, not a dump of whichever process now occupies that PID.

Natural kernel cores cannot wait in this queue. Use a small preallocated, short-lived local capacity permit plus fresh policy/authorization and immediate node admission, or reject the stream promptly. The host helper must not contact a remote service while holding the crashed process open. It must not drain a rejected core just to compute a signature. `core_pipe_limit` is a qualified node-wide last-resort bound, not per-workload fairness; helper invocation/kernel work can still occur during a crash storm. Disable Asservat acquisition when local readiness is lost and report missed cores. This platform cannot prevent crashes or all kernel coredump overhead caused by the application itself.

Use an action-specific watchdog and safe detach/stop procedure for live diagnostics. Cancellation cannot guarantee reversal of a command, synchronous kernel I/O, or work started inside an application by HTTP profiling. Do not repeatedly force-stop a healthy process to satisfy a debugging policy. A timeout with uncertain completion remains Indeterminate.

The [assessment panel](capture-assessment.md) explains expected effects, limits and uncertainty before admission. Forecasts do not reserve capacity or weaken a ceiling. Aggregate only compatible scoped quantities, distinguish declared buffers from total memory and show shared pressure without revealing other teams' plans. Current local admission and circuit breakers remain authoritative when a preview becomes stale.

For the bounded context profile, a readiness hint cannot replace the final
authoritative storage check. One owned readiness operation may wait for an
independently refreshed binding with the same selected storage and at least
one second remaining, using at most one refresh demand and 250 ms polling.
All original caller, identity/recovery, preview, target, eligibility,
capability, retention/proof and reason deadlines remain binding. Do not
refresh those facts, change selection, extend observation timestamps or
retry admission. Invalid observations, read errors, cancellation and expired
retained facts refuse the operation before any new admission effect.

### SC-CAP-002

Given no available storage/scratch reservation, when a live dump is requested, then no ptrace stop, application heap request or custom dump command begins. A natural core without a ready local permit is rejected promptly. A lost acknowledgment cannot authorize a second start or release an uncertain reservation.

Given a context readiness hint for binding A whose remaining margin is
consumed by the ordered target/facts reads, when independently refreshed B
for the same selection becomes available within all original authority
deadlines, then the one owned wait may consume B with its unchanged timestamps
and admit once. If a retained fact expires or B changes the selected storage,
then no admission occurs; retained non-storage facts are not refreshed and
target resolution, the demand attempt and effects are not retried.

## REQ-CAP-003 — Fair scheduling and workload health

Bound collector, compression, encryption, upload, analyzer and host-helper resources independently. CPU/memory limits on the collector do not bound work performed inside the target runtime, kernel, or a helper outside its cgroup. Qualify helper/worker cgroup placement, memory/scratch limits and cleanup. Prefer low-cost compression settings with a CPU budget; never depend on an optimistic compression ratio for capacity admission. Do not compensate for a throttled uploader by buffering unlimited plaintext or extending process-stop time.

Key-provider load is bounded operations, not evidence bytes: [envelope encryption](evidence.md#req-evd-001--encryption-and-integrity) keeps payloads off that service. Admission MUST still bound provider request rate, concurrency, wait time and retry work across replicas, preserving capacity for current authorization, audit and existing reads. Charge distinct artifact attempts and separate audit/authentication calls; three storage key wraps are not the total cost of an investigation. Reuse the workload fairness and finite authority deadlines; a saturated provider suppresses/delays new acquisition within those deadlines rather than creating an unbounded retry queue. Natural-core readiness requires already wrapped, uniquely assigned keys and prepaid capacity; the crash helper never waits for a remote key service. Never fall back to plaintext or reuse a different attempt's keys. Actual combined provider/authentication/audit burst capacity is a release qualification, not implied by a codec unit test or a per-process semaphore.

Schedule uploads by workload using bounded byte quanta and weighted deficit round robin; never one global FIFO dominated by the first noisy Deployment. Impose workload, node and storage-profile byte-rate/burst and request-rate limits, with aggregate hierarchical leases so spreading across nodes does not multiply the workload limit. Charge retransmitted bytes and retries to transfer budgets. Use a fair bounded queue for analysis/acquisition as well. Keep a small protected context/control service class so large dumps cannot consume every worker, buffer or I/O request. Fairness does not promise a real-time deadline on a saturated or failed network.

Administrator resource profiles define effective upload service and finite CPU/memory/scratch caps. Preflight checks that the maximum artifact can plausibly fit the acquisition/stop/deletion deadlines at the currently admitted service share. For example, 2 GiB at 32 MiB/s already needs 64 seconds without compression or setup; a 30-second streaming plan cannot promise a complete dump. Report the mismatch and suggest an explicitly smaller dump, longer permitted deadline or pre-reserved encrypted local spool. Never automatically increase caps, process-stop time or workload resources. Local spools have separate per-workload/node reservations and privacy deadlines; an upload backlog is not unlimited disk space.

Add a circuit breaker for new expensive work when collector/node pressure, scratch headroom, transfer backlog, deletion backlog or runtime-specific memory-headroom checks fail. Proposed hysteresis: three unhealthy 5-second samples to trip, at least 60 seconds healthy to recover; acute allocation/space failures trip immediately. Thresholds are administrator profiles tested per node/runtime. Already paused work uses its safe cancellation/watchdog path. Lower-cost context may continue within its protected budget. A failed health probe alone is not a breaker, since it may be the intended trigger. Admit a heap diagnostic during low memory only when its runtime profile's additional headroom requirement is satisfied; otherwise preserve lower-impact evidence and explain the skipped heap.

### SC-CAP-003

Given workload A continuously requests large cores while B requests one capture, when both are authorized and fit capacity, then A cannot consume B's scheduler allocation or protected context workers. A full spool, insufficient heap headroom or unsafe transfer deadline prevents the expensive start. Killing/restarting an uploader does not reset its byte-rate lease.

## REQ-CAP-004 — Protected storage plus hard ceilings

An administrator configures an `EvidenceStoragePool` over a qualified storage profile, with finite accounted capacity, object count, system reserve, safety headroom and shared burst allowance. An `EvidenceBudgetPolicy` supplies protected bytes/object slots per eligible workload, hard maxima, context reserve within that protected allocation, storm limits and upload/queue settings. Both are protected Kubernetes CRDs, not a new HTTP administration API. Local collection ceilings can tighten limits. Workload maintainers inherit the applicable profile and may narrow it; they cannot raise it or select another charge account.

The first contract requires exactly one matching hub budget policy per enrolled workload, using protected namespace metadata and cluster identity. No match gives `CapacityNotAllocated`; multiple matches give `AmbiguousBudgetProfile` until administrators resolve them. Changing a selector never creates a second account or detaches retained charges. Namespace envelopes apply to all workloads in that namespace; pool allocation slots bound the total across every namespace matched by the profile. Node limits are intersected with the local administrator's collector-wide ceiling, not independently multiplied for each policy/workload. [ADR-246](../docs/decisions/246-node-collector-role.md): the collector-wide ceilings are the collector's Helm values for source-ring memory, frozen-snapshot memory awaiting upload, and upload rate/burst per node (defaults 256 MiB, 256 MiB, 32 MiB/s, 64 MiB); a budget policy's optional `node.maxRingBytes` and `node.maxFrozenBytes` (at most 4 GiB) and its `node.upload` can only lower them. A reservation that does not fit fails without partial effect, and refused upload never consumes the bucket.

Every parent envelope preserves unused protected allocations of its children when admitting burst usage. Namespace/cluster limits cannot be configured below their already allocated protected total. Merely checking current used bytes against a parent maximum is insufficient: it must also subtract outstanding and unused protected commitments before granting any shared allocation.

Protected capacity is allocated when a workload is enrolled for collection, not on its first crash. It is **not lent** to another workload. Shared burst comes only from an explicitly separate pool slice and is best effort, bounded by workload maxima. Allocation must satisfy:

```text
sum(workload protected allocations) + shared burst allowance
  + system reserve + safety headroom <= configured usable pool capacity
```

Apply the equivalent invariant to object slots. Workload charges include committed bytes plus outstanding maximum reservations. Usage within its allocation consumes its own protected capacity; usage above it consumes only shared burst. The allocator reserves those portions atomically and checks the workload hard limit before admission. A single workload may consume its permitted share of burst capacity, but cannot consume another's unused protected allocation. Context reserve is included in a workload's protected allocation and is unavailable to dump/heap/payload actions. System reserve covers bounded catalog/audit/deletion work and is not writable through evidence requests.

Preserve context capacity at the hard ceiling too: expensive evidence must fit `hardLimit - contextReserve`, alongside any already occupied non-context bytes/object slots. Unused context capacity is never lent to expensive actions. Allocation moves or pool resizing cannot retract a slice with committed or uncertain reserved usage; drain/verify it or provide replacement backed capacity first. Slot size and profile protected values must agree before the allocation is Ready.

Example: a 128 GiB accounted pool allocates 16 GiB safety headroom, 8 GiB system capacity, four protected workload allocations of 16 GiB and 40 GiB shared burst. A workload ceiling of 32 GiB allows A to use its 16 GiB and up to 16 GiB of burst. B, C and D retain their protected capacity even if A has triggered continuously. Each workload can use 1 GiB of its 16 GiB for context that its dumps cannot occupy. Object-count accounting protects against many small artifacts as well as a few large ones.

The guarantee is admission within a workload's **remaining** protected capacity, provided the backing storage is healthy and provisioned. It is not unlimited history or an unconditional new core after that workload fills its own allocation. A logical prefix or S3 bucket does not reserve physical disk. Qualification requires an administrator-assigned backend capacity envelope, replication/erasure-coding overhead accounted by the operator, monitoring of free capacity and protection from unrelated writers (dedicated capacity or a backend-enforced equivalent). Shared physical storage without such a boundary is explicitly `BestEffortCapacity` and cannot satisfy the isolation release claim.

### SC-CAP-004

Given the 128 GiB example with A at its 32 GiB hard limit, when B requests evidence within its unused allocation, then storage admission succeeds independent of A's trigger rate. A is refused before acquisition and cannot evict B's evidence. More protected allocations than the pool can back are rejected at enrollment, rather than silently overcommitted.

## REQ-CAP-005 — Durable hub and local accounting

For the fixed context profile, preview and new admission must reject a known
processing-history horizon shorter than the resolved original deletion date.
Validate initialized current root coverage and every applicable retained rule's
original horizon. Keep the selected retention unchanged; expected renewal is
not prepaid coverage. Repeat this check atomically with managed admission before
new charges, using the same serialization as processing configuration and rule
writers. An unavailable or malformed read cannot be treated as an empty rule
set. A preview does not reserve a lineage slot or promise future publication.
Accepted same-key history remains passive and an uncertain earlier attempt must
be resolved under its original key. See
[ADR-146](../docs/decisions/146-processing-coverage-before-collection.md).


PostgreSQL holds authoritative hub quota accounts, reservations and aggregate committed counters. CapacityAccount/CapacityReservation rows bind immutable operation/attempt IDs, fence, byte/object/scratch/transfer slices and state. Grant approval and capacity remain distinct eligibility checks; a hub transaction commits the applicable reservations and work together under [persistence](persistence.md). Long-term immutable charge/copy outcomes also live in encrypted object storage. No database write occurs per packet, log line or byte.

Allocate pool → cluster → namespace → workload slices in fixed lock order using short SQL transactions and conditional aggregate updates. Explicitly bound account counts, child allocations and active reservations. Hub rows do not require staged multi-CRD reservation. Local Kubernetes slices remain bounded (128 KiB per object), use resourceVersion CAS and fences, and are prepaid against every hub ancestor. Hub and local state do not share a transaction: persist the delegated maximum before delivery; reconcile only proven-unused slices. During disconnection use only valid unexpired authority and allocated capacity. Expiry/restart alone is not proof that an action/upload never started. No replica-lagged authorization or capacity decisions.



Before upload, reserve worst-case stored ciphertext size, compression expansion, manifest/index overhead, multipart/retry allowance, required replicas and bounded planned derivatives; reserve object slots as well. Separately cap uncompressed input, transfer bytes and local scratch: they are different resources. No unknown-size/unbounded reservation. Use a qualified format/backend bound, not expected compressibility. If a necessary derivative cannot be reserved, report partial analysis rather than bypassing quotas. New attempts/copies need additional capacity until previous ones are confirmed gone; transfer of a reservation to committed usage must never double-charge or temporarily release occupied bytes.

Committed/partial objects, noncurrent versions, retained copies, multipart remnants and deletion-pending artifacts remain charged until verified removal. Expiring a manifest or inserting a delete marker does not return capacity. Durable deletion results drive idempotent ledger release. Shares reference the original bytes without duplicate storage charge; newly materialized results charge the source workload, with an explicit bounded split for multi-workload results. All required workload accounts must authorize/reserve the split, so a comparison cannot charge another team by choosing their baseline. Restore the authoritative SQL ledger and reconcile conservatively with manifests, intents, copy inventory and lifecycle journal; artifact listing alone cannot reconstruct consumed permits or revocations. After recovery, freeze new affected admissions while accounting is unknown. An external bucket listing/cached backend quota metric is a cross-check, not the serialization point.

The first protected context producer uses one fixed root backing plan and three
purpose-separated phases: reserve general backing, install capture-intent backing,
then publish fully verified readiness. All managed readers must reject the
incomplete/paused state even when physical rows or a context binding already
exist. A fresh protected observation may continue exact compatible committed SQL
configuration after an earlier phase expires, retaining original IDs and charges.
It cannot replay an expired effect permit or adopt legacy rows.

Managed renewal preserves every original session/window/native/Stop cutoff,
policy digest and consumed counter in a closed immutable snapshot. Missing or
malformed managed provenance is unavailable, never permission to substitute the
current parent configuration. Finite configuration history remains charged until
qualified positive settlement and deletion conditions hold; configured retention
or elapsed time alone cannot return it. [ADR-141](../docs/decisions/141-protected-capacity-production.md)
describes the private producer and outstanding installed/backend qualification.
The provisional sixteen-account test envelope is not a product-wide workload
limit or a measured operating capacity.

Approved context queries require a separate original-installation qualification
and additive reservation under the same protected root. Preserve the base
capture/download graph's exact totals; use only its unreserved SQL/backup/WAL,
audit and key-service envelope. Bind measured report/source/profile provenance
and independently enforced numeric worker, hub, key-service and provider limits.
A report digest, administrator struct, unique capacity ID or existing download
qualification alone is insufficient. Bound root queries, aggregate principals,
workload allocations, polls, control and source-observation work, including
uncertain workers and history. Source work requires an acknowledged irreversible
claim before native guards, with separate prepaid joined completion after all
outer checks. Unknown replies/replay authorize no work; expiry alone never frees
an unresolved claim. Exhaustion denies before guard I/O and retains one terminal
negative, including a reserved root that never acquired positive backing.
Delayed restrictive negatives retain their original watermark; persisting them
uses a separate at-most-five-second write interval that preserves caller
cancellation and any earlier deadline, never renewed positive freshness.
Retain original hard/effect/cleanup/retirement
dates; no poll, root renewal or expiry replenishes the finite allocation. An
installation without the original extension remains unavailable until a separate
audited upgrade protocol exists. See the
[protected query-capacity contract](../docs/architecture/context-query-capacity.md).

### SC-CAP-005

Given two 8 GiB attempts racing for 8 GiB remaining capacity, when both reserve, then only one becomes Ready. A crash after multipart start retains the uncertain charge. A failed DELETE or hidden version does not free space for another reservation. A retry after leadership loss cannot reuse a spent prepaid slice.

## REQ-CAP-006 — Exhaustion, onboarding and visibility

Default full-account behavior is `RejectNewExpensive`: retain prior evidence, continue only context that still fits its reserve, and report `WorkloadStorageFull`/`PoolBurstFull`/`CapacityUnavailable` as appropriate. A fair scheduler must still admit other workloads' available protected capacity. Do not pause unrelated accounts merely because A reached its cap. Scope a deletion-related profile pause as narrowly as reliable inventory permits; a backend-wide deletion failure or physical pressure still affects the shared backend.

An administrator may enable `DeleteOldestEligibleInAccount`: delete only the same workload's oldest unheld eligible evidence and derivatives, explain the shorter effective availability, verify removal, then reconsider a still-fresh request. Never evict another workload, override preservation, wait indefinitely while a process is stopped or assume deletion has completed. Retention is a maximum, not a promise to keep every artifact until then; the default avoids unrequested eviction. Holds continue consuming capacity and require preview of the account impact. The pending legal-exception preference is unchanged.

Apply namespace/cluster allocation envelopes and account-count limits so creating many workloads cannot monopolize enrollment or evade parent budgets. Automatic onboarding allocates from an administrator's already assigned namespace capacity without a per-app ticket; if it cannot supply the selected protected profile, report `CapacityNotAllocated` before calling the policy Ready. Workload deletion/name reuse does not erase charges. Release its protected allocation only after retained charges are safely accounted in a backed residual account or all copies are deleted. Raising an allocation or moving retained evidence requires checked backing capacity; lowering below usage blocks new admissions and reports over-limit rather than deleting other workloads' data.

Show maintainer-friendly usage: retained, reserved/in-flight, deletion-pending, protected remaining, burst use, object slots, upload pressure, suppression count and next eligible start. Every skipped action names the limiting scope and remedy without exposing another team's inventory. Defaults come from one reusable budget profile; ordinary users need no quota YAML. Administrative views show overcommit prevention, orphan reservations, physical/backend pressure and allocation readiness. MCP/case results distinguish missing evidence because of resource limits from evidence that never existed.

### SC-CAP-006

Given A fills its account, when another trigger arrives, then it records suppression and available context without deleting B's evidence. If own-account rolling deletion is enabled but an object is held or deletion fails, its charge remains and no dump starts. A newly enrolled workload without backed capacity is visibly pending, not falsely protected.

## Discovery shares the same limits

[Guided surveys](guidance.md) are ordinary admitted capture episodes, charged to the same workload/node/storage/transfer accounts. Initial extra discovery ceilings are one concurrent survey per workload, a 30-second start interval and ten starts per hour across users and clients, configurable downward. They cannot consume protected context reserve by masquerading as free previews. Existing incident capture takes priority; wait/refuse visibly when budgets conflict. Passive recommendation reads never reserve acquisition capacity, but retain bounded query/cache quotas.

## Composed collectors and syscall event pressure

Reserve the whole expanded composition under one workload/capture account. Context deduplication removes only identical independent snapshot acquisitions; packet/syscall rings, frozen copies, parser/thread maps and observation budgets remain separate reservations. Concurrent policies/captures contribute to the same workload totals. Qualified coexistence or a feasible serial schedule is required for exclusive profilers and process-stopping actions; a duplicate expensive acquisition is a preview conflict. A profile may not use a separate namespace/catalog to obtain a second protected workload allocation.

Syscall event/rate/thread caps bound acquisition work separately from output bytes. Argument reads consume cumulative grant events and bytes before processing; dropped/error-filtered events and ring rotation cannot refund observations. Loss/overflow and impact circuit breakers are visible under [syscalls](syscalls.md). These specifications do not yet demonstrate acceptable production overhead.

## Admission at source activation and at trigger

[Execution modes](action-lifecycle.md) split capacity admission. Reserve steady ring/parser/CPU/event resources for every armed observation pod before any source attach. At an admitted trigger, separately reserve frozen segments plus replacement writable memory, output/object slots, encryption/spool/upload and onTrigger impact for the selected incident pods. Copy-on-write is not free memory; bytes pinned by multiple snapshots remain accounted until references settle. Coalescing cannot extend an accepted window indefinitely. Source/session lifetimes and per-incident action deadlines have separate finite limits. No-trigger recordings still consume observation budgets; upload congestion cannot turn a bounded source into unlimited retained storage.

## Saving existing recordings

Recording saves spend the same policy/workload occurrence cooldown/rate and per-source snapshot/encryption/storage/upload reservations as automatic saves. Multiple initiators and request paths cannot allocate independent budgets. Existing observation charges stay with their source; only incremental frozen/output resources are added, and no dump allowance is consumed without a dump. Sensitive save/action counts remain under the applicable reviewed policy grant. Refuse unavailable immediate admission with a bounded reason/retry time; do not queue a new t0 after cooldown. An ambiguous started snapshot retains its charge until reconciled. Cancel only its snapshot references; keep an independently authorized live recorder running.

## Live-view isolation

[REQ-LIV-004](live-watch.md#req-liv-004--protect-collection-and-workload-resources) defines independent viewer slots, scan/CPU, replay memory and output/transfer counters within existing hierarchical accounts. A filter that returns few rows can still scan many events; enforce both. Charge retries and preserve counters through edits/pause/reconnect. Source rings, frozen snapshots and protected incident uploads are separate reservations; no per-view ring pin or optimistic resource refund. Apply workload and principal caps across tabs/clients, with node/installation aggregate limits. Slow clients drop/stop rather than block acquisition; retain explicit unknown/lost coverage. Operator metrics/capacity views report counts/bytes/reason enums without live content or high-cardinality row labels.
