# Dynamic triggers

## Trigger catalogue

| Detector | Initial source | Semantics and limits |
| --- | --- | --- |
| Log pattern | Node CRI log tail; Kubernetes `pods/log` degraded fallback | Literal/RE2-compatible regexp or structured JSON field predicate, stream filters and pod-scoped attribution, count within window, bounded multiline assembly |
| CPU | cgroup v2 `cpu.stat` deltas | Cores consumed, fraction of CPU quota where finite, fraction of throttled scheduling periods; requests are not capacity |
| Memory | cgroup `memory.current`, `memory.max`, `memory.events` | Absolute bytes, fraction of finite limit, growth rate, OOM/high counters; no ratio when limit is unlimited |
| Pressure | cgroup CPU/memory/I/O PSI | Sustained stall fraction over configured windows, only where available |
| Probe failure | Kubelet probe metrics where allowed; Kubernetes Events/status fallback | Liveness/readiness/startup distinguished; Event aggregation/loss explicitly reported |
| Exit/restart | Pod status and local runtime/kernel observation | Signal, exit code, OOMKilled, restart delta, CrashLoopBackOff; no inference that an exit code proves a core |
| Crash artifact | Core agent or approved runtime-file watcher | Verified artifact/stream occurrence; merge with related exit rather than collecting twice |
| External alert | Authenticated Alertmanager webhook | Fingerprint, firing/resolved status, explicit mapping to an enrolled target |
| Manual | `DebugCapture` | Authorized bounded recipe execution |
| Scheduled | Controller schedule | Periodic baseline snapshots with jitter, disabled unless configured |
| File condition | Approved container file watcher/poll | Created/changed/size threshold on declared paths; poll reports missed intervals |
| Network condition | Optional Gadget/Hubble metrics adapter | Connect failures, retransmit rate, DNS errors where observed; metadata is not full packet history |
| Deployment/node condition | Kubernetes watches | Rollout stalls, eviction, node pressure, volume/mount warnings; node-wide evidence requires separate scope |

Initial implementation order: log/resource/probe/exit/external/manual, then crash artifact, followed by optional detectors. Every unavailable detector is represented as a capability gap, not silently ignored.

## REQ-TRG-001 — Bounded expression language

Policies MUST define named typed detectors and a `when` expression combining detector states through `all`, `any`, `not`, `for`, count/window, or ordered sequence. Implement a constrained typed AST with CEL for leaf predicates, not arbitrary scripts. No network, file, process or unbounded iteration functions exist in expressions. Admission MUST reject unknown fields, impossible units, invalid regular expressions, excessive depth and expressions over the evaluation budget.

Default ceilings: 16 detectors/policy, nesting depth 8, 64 KiB policy text, 64 KiB per assembled log record, 1 MiB buffered log data per pod, fairly split across its sources, 5-minute maximum correlation window, 5-second metric interval. Overlong records are dropped and counted by default. Explicit matchPrefix mode may match a truncated literal/regexp prefix, tagged incomplete; structured JSON predicates never evaluate incomplete JSON. Regular expressions use Go's linear-time engine; no backreferences or look-around.

### SC-TRG-001

Given an invalid nested expression or a regexp requiring unsupported syntax, when the policy is submitted, then admission rejects it with a field path. A pathological input record cannot allocate beyond the record/buffer limits.

## REQ-TRG-002 — Time, missing data and edge semantics

Evaluation MUST use monotonic time locally and preserve source and observed wall timestamps. Missing/stale detector data has state `Unknown`, not false or zero. `not Unknown` remains Unknown. Sustained conditions reset on missing samples by default; an explicit gap tolerance may be configured and is bounded by the sample period budget.

A trigger fires once on a qualified false/Unknown→true activation after its hold condition, not every sample. Initial true may fire by default; evaluation.fireOnActivation=false instead waits for a proven false state before arming. Re-arm requires a continuous false interval (evaluation.rearmFor, default 10 seconds); Unknown never constitutes recovery. Record policy generation, detector values/units, source freshness, threshold and observation gaps. Never place raw matched log text in Events, CRD status or webhook data.

### SC-TRG-002

Given memory usage above 85% for 20 seconds, when a sample is missing halfway through, then the default hold resets. An unlimited memory limit produces `UnknownRatio` and cannot satisfy the ratio detector.

## REQ-TRG-003 — Log completeness

The node reader MUST handle CRI partial/full records, rotation, truncation, reconnects and container restarts with bounded checkpoint state. Record stream, inode/file generation or source cursor, timestamp and container identity. Deduplicate replayed records over a bounded window. Detector evaluation requires an armed sensor. An onTrigger logs action may retrieve preexisting runtime log history even if that sensor was not armed; it cannot reconstruct unobserved detector transitions. Report missing history after restart or rotation loss, and never equate available log bytes with complete trigger coverage.

A Kubernetes log fallback MUST report its reduced coverage and API load budget. It does not guarantee access to every rotated log segment. [Kubernetes logging architecture](https://kubernetes.io/docs/concepts/cluster-administration/logging/).

### SC-TRG-003

Given a matching CRI record split across partial entries and followed by rotation, when the collector restarts and replays its overlap window, then at most one occurrence is attributed to the same record identity, with explicit uncertainty if a reliable source cursor was unavailable.

## REQ-TRG-004 — Deduplication and budgets

Each trigger occurrence MUST have an idempotency key derived from cluster, policy UID/generation, pod/correlation identity, contributing source IDs, detector transition ID and source epoch. Enforce per-policy, per-workload, per-node and installation-wide budgets. Defaults: one occurrence per workload per 5 minutes, burst 2; one invasive action per pod at once; two artifact streams per node; ten active actions per node. Budget changes cannot retroactively authorize a previously denied action. The [capacity rules](capacity.md) add stricter workload-wide dump limits, staged admission, bounded suppression summaries and shared counters across every replica/policy/generation. Context burst capacity never authorizes a dump burst.

Related crash-agent, exit, probe and alert signals within a 30-second correlation window MAY append to one occurrence. Preserve each signal's provenance. A signature used before analysis MUST be marked provisional. Rate-limited occurrences keep content-free counts and gap reasons instead of pretending evidence was collected. Aggregate suppressed signals in bounded windows rather than creating a control object or durable event per raw match.

### SC-TRG-004

Given duplicate Alertmanager deliveries and a local crash for the same process, when they arrive across a controller restart, then the same occurrence is recovered and no invasive action is automatically repeated after an ambiguous start.

## REQ-TRG-005 — Dynamic policy activation

Policy updates MUST compile and validate as a new immutable generation before activation. Each generation retains an authenticated submission and approved execution identity under [permission management](permissions.md); every resolved target must remain within that identity's current derived or explicit scope. Intrusive policy grants bind the collection execution scope and recipe digests under [execution identity](execution.md); changes to that scope invalidate approval. Display, sharing, pause and grant-reference changes have separate effects and cannot broaden collection. Preset authoring binds both submitted input and the immutable resolved catalog/plan as specified in [ergonomics](ergonomics.md). A node switches generation atomically and acknowledges it. Status reports desired/observed generation, armed targets, failed targets and reason. Removing a policy cancels observations and future actions; already uploaded evidence follows retention.

### SC-TRG-005

Given an approved policy collecting stacks, when someone changes its recipe to a heap dump or broadens the target, then the previous approval does not authorize the new generation. Existing nodes report the transition and do not execute a mixture of old/new action definitions.

## REQ-TRG-006 — Probe and external-source honesty

Probe Events MUST be described as best-effort; Kubernetes may aggregate or omit them, and pod readiness can change for reasons other than a readiness-probe failure. Prefer typed kubelet probe metrics if permitted, while reporting scrape freshness. External alert receivers MUST authenticate the sender, limit body size, validate target mapping against the sender's configured cluster/workload scope and deduplicate alert occurrences as defined below. A webhook cannot introduce an arbitrary command or selector.

### SC-TRG-006

Given an Event series with count increasing from 4 to 9, when it is observed twice, then five new failures are counted once. A webhook naming an unconfigured cluster or a workload outside the sender's allowed scope is rejected without target discovery.

## REQ-TRG-007 — Correlation, events and schedules

The default evaluation key is pod UID, with internal source/restart identities retained. No log from replica A can combine with a resource condition on B unless evaluation.scope explicitly selects workload and the larger contributor set is approved. Pod scope deliberately includes sidecars: do not claim that two signals necessarily came from the same process. Record contributors for collection selection and explanation.

A detector is either a fresh level (resource/network/Kubernetes condition) or an event source (log/exit/alert/crashArtifact/schedule/file). Event leaves are true while at least one deduplicated event remains in eventWindow (default 30 seconds, maximum five minutes), false only while the source is fresh and its window is empty, Unknown on coverage loss. Probe threshold is a level over deduplicated failure events. count counts distinct source occurrences or qualified rising transitions for level detectors, never every true sample. sequence consumes distinct ordered occurrences, compares local observed time with stable source-ID tie breaks, does not reuse one event for multiple sequence positions, and expires incomplete prefixes at within. Each completed sequence is a one-evaluation pulse. for requires continuous known true; not uses three-valued logic (not Unknown is Unknown), all is false if any operand is false and otherwise Unknown if any is unknown; any is the dual. Temporal windows use (now-window, now]. Replays do not advance event counts. Reset correlation state on source epoch changes with an explicit gap, without resetting workload budgets.

Absolute pod CPU/memory values use qualified aggregate accounting without double-counting parent/child cgroups. Limit/quota ratios and PSI are evaluated on each available runtime component and combined with any under the same pod; no user container selector exists. A component without a finite limit is Unknown for that ratio, not zero; preserve each contributor/unit and partial coverage. CPU requests are never a denominator. Admission rejects unsupported metric/runtime combinations. All sample/poll intervals are at least one second (default five); correlation/hold/probe windows are at most five minutes. Invalid Go regex and CEL types require the actual Go compiler in production; the Python checker is not a substitute.

Schedules use five-field minute cron and explicit IANA timeZone (preset default Etc/UTC), no embedded TZ macros or second field. Persist the last admitted nominal UTC slot; deterministic jitter is less than the minimum interval and charged to the original slot. No replay/catch-up after downtime, suspension or expiry; report missed slots. Nonexistent DST local times are skipped; repeated local minute runs once per policy/local date-minute, identified with the first UTC occurrence. Distinct policies still share workload budgets. A file sizeAbove detector requires sizeBytes; a stable-size observation never proves an application finished writing a dump.

### SC-TRG-007

Given replica A logs an error while B is under memory pressure, when default pod-scoped all evaluates, then no combined trigger fires. A true condition at initial arming fires once after its hold; repeated samples do not increment an event count. Restarting at a missed schedule or during a repeated DST hour cannot queue duplicate dumps.

## Restart counter triggers (ADR-228)

The first implemented detector is the API-read restart counter of the exit detector, for a hub-held
DebugPolicy (`spec.target.cluster`) that runs the pod-status context recipe on the triggering Pod
(`maxPods: 1`, `selection: triggeringPod`). The hub polls every active policy every 15 seconds
with one bounded regional Pod LIST of the named workload. Its semantics refine REQ-TRG-002/004/007
for this counter only:

- The first observation of a Pod UID is its baseline and never fires; activation never fires
  (`evaluation.fireOnActivation: true` is rejected with its field path). A counter has no level, so
  there is no re-arm interval.
- One occurrence per (policy, Pod UID, restart count) whose latest termination matches the reasons
  (OOMKilled, Error, CrashLoopBackOff) and optional exit codes. Restarts between two polls coalesce
  into one occurrence and are counted as suppressed `coalesced`; their individual reasons are not
  observed. Replay and duplicate polls are no-ops. Kubernetes reports exit codes, not signals.
- A truncated, incomplete or unavailable observation is Unknown and fires nothing.
- The shared workload budget (one occurrence per five minutes, burst two) holds for every policy
  on the workload; a policy's own cooldown and hourly bound only tighten it. Executions are spent
  at admission against the accepted ceiling and never refunded. Suppression is a saturating count
  per policy and reason, never a durable record per restart; capacity shortfalls are suppressions,
  never queued.
- Not applicable to this counter trigger and not implemented: the 30-second correlation append
  (REQ-TRG-004 MAY) and per-node budgets (no node agent runs). Every other detector, expression,
  recipe or option is rejected at activation with its field path.

### SC-TRG-008

Given an activated restart policy on a three-replica Deployment, when one container is killed, then
exactly one pod-status capture of that Pod runs under the policy executor and its team's audience
can download it; when all three replicas crash repeatedly for 150 seconds, then at most the shared
workload budget is admitted, every other observed restart is counted as suppressed, the ledger
holds at most one watermark per Pod and one suppression row per reason, and no capture follows
once the restarts stop.

### SC-TRG-009

Given an activated restart policy that has already captured, when a current maintainer of its
delegating team deactivates it (ADR-229), then the next poll cycle no longer observes the workload:
a further container kill changes no watermark, occurrence, suppression count or execution spend;
the existing capture and its evidence remain; repeating the deactivation is a replay; status
reports `deactivated`; and activating the unchanged revision again is refused, so its spend and
expiry cannot be reset.

## Probe-failure triggers (ADR-230)

The second implemented detector is `probe` with `source: events` (`auto` selects events), on the
same hub-held policy shape, recipe, budgets, suppression reasons and capture path as the restart
counter. `kubeletMetrics` is rejected with its field path (it needs node access). A probe policy's
poll adds one namespace core/v1 Event LIST (`involvedObject.kind=Pod,reason=Unhealthy`, at most 512
items) to the Pod LIST. The region matches the message prefix `<probeType> probe failed` or
`<probeType> probe errored` and returns, per owned Pod, only the newest failure second and a proven
lower bound of failures within `window`; no Event text leaves the region. Its semantics refine
REQ-TRG-002/006/007 for this source:

- `window` is 30 s to 5 min (two polls to the correlation ceiling) in whole seconds;
  `minimumFailures` 1–1000; `evaluation.rearmFor` must not exceed `window`.
- Failures within the window are a lower bound from Kubernetes Event series: a series (one Event
  object with `count`, or `series.count`) that started inside the window counts all its failures; one
  that started earlier counts only its latest. A burst inside a long-running identical-message
  series is therefore undercounted, never overcounted. `minimumFailures: 1` fires on any failure.
- The detector is a level: a Pod fails while at least `minimumFailures` failures fall in the
  window. One occurrence fires on a rising edge only, keyed (policy, Pod UID, newest failure
  second). The first observation of a Pod is its baseline and is armed only if its window is
  empty; a Pod already failing at activation waits for a proven recovery. After an occurrence,
  admitted or suppressed, the Pod re-arms at the first poll with an empty window, which proves
  `window` seconds without a recorded failure. An Unknown poll (denied, continued, truncated or
  malformed Event LIST) neither fires nor re-arms.
- Kubernetes Events are best-effort (REQ-TRG-006): the kubelet may aggregate, rate-limit or drop
  them and they expire (default one hour). Readiness can also change without an Event; the
  detector reports only recorded probe failures. A liveness or startup failure that restarts the
  container is also visible to an exit detector.
- Changing a policy's detector (exit ↔ probe) re-baselines every Pod: a watermark of another
  detector is never compared.

Log and resource detectors remain rejected at activation (`spec.detectors[0].kind`): the
[ADR-230](../docs/decisions/230-s03-detectors.md) complexity gate paused both for a maintainer
decision.

### SC-TRG-010

Given an activated probe policy (Readiness, two failures within one minute) on a workload whose
replicas pass their readiness probe, when one Pod's readiness probe starts failing every few
seconds, then exactly one pod-status capture of that Pod runs under the policy executor, further
failures of the same failing period create no occurrence, and no Event text appears in status,
occurrences, logs or the capture request. A Pod already failing when the policy is activated fires
only after a minute without failure followed by a new failure.

## Trigger-to-action lifecycle

A detector firing is an occurrence signal, not a request to restart every collector. [Action lifecycle](action-lifecycle.md) resolution produces already armed ongoing sources and onTrigger actions. After ordinary admission, preserve matching source windows and dispatch independent onTrigger work. Cooldowns/deduplication suppress saves and actions while admitted continuous observation can continue. A late event or pending dump approval never shifts an existing window forward. Source readiness/coverage is separate from detector freshness and per-incident selection; missing required source history is visible while permitted context proceeds.

## Resource units and reset behavior

These definitions refine REQ-TRG-002/007; reported values always name the metric, unit, sample interval and contributing cgroup identities.

| Metric | Canonical calculation |
| --- | --- |
| cpuCores | Delta cpu.stat usage_usec divided by monotonic elapsed microseconds, using qualified nonoverlapping cgroup accounting |
| cpuQuotaRatio | Consumed cores divided by the component's qualified finite effective quota/period in cores; never CPU requests |
| cpuThrottledRatio | Delta nr_throttled / delta nr_periods, fraction 0..1; this is scheduling periods, not a wall-time percentage or latency estimate |
| memoryBytes / memoryLimitRatio | memory.current bytes / those bytes divided by a qualified finite effective memory limit |
| memoryGrowthBytesPerSecond | Signed change in memory.current / elapsed seconds; a real decrease is valid |
| memoryPSI / cpuPSI / ioPSI | Delta of the resource's some.total / elapsed microseconds, fraction 0..1; do not substitute avg10 percentages |
| Network rates | Adapter-declared event counts per second over qualified intervals; a packet fraction needs a separately named, qualified metric |

A boot/source/cgroup replacement, counter decrease/reset, zero elapsed time, absent denominator or unavailable controller produces Unknown and a new two-sample baseline; it must not look like a recovery or a burst. Memory gauges are not monotonic counters. Zero scheduling periods means UnknownRatio. Preserve partial coverage for missing components and ancestor limits; a direct cgroup throttle counter is not proof of every ancestor-induced stall. Unsupported effective-limit resolution is a capability gap. Throttling/PSI thresholds cannot exceed one; quota/memory utilization can transiently exceed one and must not be silently clamped. [Kernel cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), [PSI](https://docs.kernel.org/accounting/psi.html).

## Alert delivery and incident identity

REQ-TRG-004/006 use the authenticated configured receiver identity plus each alert's fingerprint and startsAt as its episode identity, with one transition identity for firing and one for resolved. Retries/HA copies with the same identity do not start another action; a later startsAt is a new episode even if labels/fingerprint are identical. Ordinary expression rearm and workload budgets still apply. Within an episode resolved is terminal; an out-of-order firing delivery cannot resurrect it. Changing endsAt on a firing update never creates a new episode. Use each alert's status, not the enclosing group's status, and report truncated batches. Reject custom webhook bodies that omit required identity/status fields; the supported adapter is the standard version-4 webhook. [Alertmanager webhook format](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config).

Keep validated source startsAt/endsAt alongside local receipt time. Local monotonic receipt governs freshness/eventWindow; a long-running alert's startsAt does not manufacture months of requested capture history. Clock-skew/invalid-future timestamps have explicit rejection/uncertainty bounds, and delayed delivery reports the missed source interval. Never fetch generatorURL/externalURL or execute content from annotations. Maintain bounded durable episode deduplication/tombstones across receiver restart, charged to control metadata limits. If that bound forces forgetting an unresolved episode, mark the gap and suppress ambiguous intrusive replay until fresh state is established; do not gain exactly-once guarantees from an expiring cache.

## Explain a policy that did not capture

REQ-TRG-005 status and existing policy/capture views MUST expose a compact content-free explanation: desired/observed generation; authorized, observed and capped pod counts; detector freshness/Unknown reason; hold/rearm state; ongoing-source readiness/history; last admitted occurrence; and latest suppression reason/count/time. Distinguish cooldown, missing approval, expired authority, lack of capacity, no eligible process, stopped source and unsupported adapter. Link to the authorized existing policy/action view and a relevant correction. Scope every projection to current caller rights; no matched log text, private labels, argv or hidden target names. Reading status never samples traffic, runs commands or collects evidence. Detailed replay/test-event tooling remains a separate feature proposal.
