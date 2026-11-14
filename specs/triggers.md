# Dynamic triggers

## Trigger catalogue

| Detector | Initial source | Semantics and limits |
| --- | --- | --- |
| Log pattern | Node CRI log tail where a node collector runs; otherwise followed `pods/log` streams from the connector | Literal/RE2-compatible regexp or structured JSON field predicate, stream filters and pod-scoped attribution, count within window, bounded multiline assembly |
| CPU | cgroup v2 `cpu.stat` deltas; without a node collector, cores and quota fraction from the `metrics.k8s.io` API | Cores consumed, fraction of CPU quota where finite, fraction of throttled scheduling periods; requests are not capacity |
| Memory | cgroup `memory.current`, `memory.max`, `memory.events`; without a node collector, working-set bytes and limit fraction from the `metrics.k8s.io` API | Absolute bytes, fraction of finite limit, growth rate, OOM/high counters; no ratio when limit is unlimited |
| Pressure | cgroup CPU/memory/I/O PSI | Sustained stall fraction over configured windows, only where available |
| Probe failure | Kubelet probe metrics where allowed; otherwise watched Kubernetes Events | Liveness/readiness/startup distinguished; Event aggregation/loss explicitly reported |
| Exit/restart | Watched Pod status and local runtime/kernel observation | Signal, exit code, OOMKilled, restart delta, CrashLoopBackOff; no inference that an exit code proves a core |
| Crash artifact | Core agent or approved runtime-file watcher | Verified artifact/stream occurrence; merge with related exit rather than collecting twice |
| External alert | Authenticated Alertmanager webhook received by the connector | Fingerprint, firing/resolved status, explicit mapping to an enrolled target |
| Manual | `DebugCapture` | Authorized bounded recipe execution |
| Scheduled | Controller schedule | Periodic baseline snapshots with jitter, disabled unless configured |
| File condition | Approved container file watcher (inotify; sampling only where no watch works) | Created/changed/size threshold on declared paths; sampling reports missed intervals |
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

Followed Kubernetes `pods/log` streams MUST report their reduced coverage: segments rotated before a stream started are not read, and a reconnecting stream is a gap. [Kubernetes logging architecture](https://kubernetes.io/docs/concepts/cluster-administration/logging/).

### SC-TRG-003

Given a matching CRI record split across partial entries and followed by rotation, when the collector restarts and replays its overlap window, then at most one occurrence is attributed to the same record identity, with explicit uncertainty if a reliable source cursor was unavailable.

## REQ-TRG-004 — Deduplication and budgets

Each trigger occurrence MUST have an idempotency key derived from cluster, policy UID/generation, pod/correlation identity, contributing source IDs, detector transition ID and source epoch. Enforce per-policy, per-workload, per-node and installation-wide budgets. Defaults: one occurrence per workload per 5 minutes, burst 2; one invasive action per pod at once; two artifact streams per node; ten active actions per node. Budget changes cannot retroactively authorize a previously denied action. The [capacity rules](capacity.md) add stricter workload-wide dump limits, staged admission, bounded suppression summaries and shared counters across every replica/policy/generation. Context burst capacity never authorizes a dump burst.

Related crash-agent, exit, probe and alert signals within a 30-second correlation window MAY append to one occurrence. Preserve each signal's provenance. A signature used before analysis MUST be marked provisional. Rate-limited occurrences keep content-free counts and gap reasons instead of pretending evidence was collected. Aggregate suppressed signals in bounded windows rather than creating a control object or durable event per raw match.

### SC-TRG-004

Given duplicate Alertmanager deliveries and a local crash for the same process, when they arrive across a controller restart, then the same occurrence is recovered and no invasive action is automatically repeated after an ambiguous start.

## REQ-TRG-005 — Dynamic policy activation

Policy updates MUST compile and validate as a new immutable generation before activation. Each generation retains an authenticated submission and approved execution identity under [permission management](permissions.md); every resolved target must remain within that identity's current derived or explicit scope. Intrusive policy grants bind the collection execution scope and recipe digests under [execution identity](execution.md); changes to that scope invalidate approval. Display, sharing, pause and grant-reference changes have separate effects and cannot broaden collection. Preset authoring binds both submitted input and the immutable resolved catalog/plan as specified in [ergonomics](ergonomics.md). A node or connector switches generation atomically and acknowledges it. Status reports `metadata.generation` and `status.observedGeneration`, armed targets, failed targets and reason. Removing a policy cancels observations and future actions; already uploaded evidence follows retention.

### SC-TRG-005

Given an approved policy collecting stacks, when someone changes its recipe to a heap dump or broadens the target, then the previous approval does not authorize the new generation. Existing nodes report the transition and do not execute a mixture of old/new action definitions.

## REQ-TRG-006 — Probe and external-source honesty

Probe Events MUST be described as best-effort; Kubernetes may aggregate or omit them, and pod readiness can change for reasons other than a readiness-probe failure. Prefer typed kubelet probe metrics if permitted, while reporting scrape freshness. External alert receivers MUST authenticate the sender, limit body size, validate target mapping against the sender's configured cluster/workload scope and deduplicate alert occurrences as defined below. A webhook cannot introduce an arbitrary command or selector.

### SC-TRG-006

Given an Event series with count increasing from 4 to 9, when it is observed twice, then five new failures are counted once. A webhook naming an unconfigured cluster or a workload outside the sender's allowed scope is rejected without target discovery.

## REQ-TRG-007 — Correlation, events and schedules

The default evaluation key is pod UID, with internal source/restart identities retained. No log from replica A can combine with a resource condition on B unless evaluation.scope explicitly selects workload and the larger contributor set is approved. Pod scope deliberately includes sidecars: do not claim that two signals necessarily came from the same process. Record contributors for collection selection and explanation.

A detector is either a fresh level (resource/network/Kubernetes condition) or an event source (log/exit/alert/crashArtifact/schedule/file). Event leaves are true while at least one deduplicated event remains in eventWindow (default 30 seconds, maximum five minutes), false only while the source is fresh and its window is empty, Unknown on coverage loss. Probe threshold is a level over deduplicated failure events. count counts distinct source occurrences or qualified rising transitions for level detectors, never every true sample. sequence consumes distinct ordered occurrences, compares local observed time with stable source-ID tie breaks, does not reuse one event for multiple sequence positions, and expires incomplete prefixes at within. Each completed sequence is a one-evaluation pulse. for requires continuous known true; not uses three-valued logic (not Unknown is Unknown), all is false if any operand is false and otherwise Unknown if any is unknown; any is the dual. Temporal windows use (now-window, now]. Replays do not advance event counts. Reset correlation state on source epoch changes with an explicit gap, without resetting workload budgets.

Absolute pod CPU/memory values use qualified aggregate accounting without double-counting parent/child cgroups. Limit/quota ratios and PSI are evaluated on each available runtime component and combined with any under the same pod; no user container selector exists. A component without a finite limit is Unknown for that ratio, not zero; preserve each contributor/unit and partial coverage. CPU requests are never a denominator. Admission rejects unsupported metric/runtime combinations. All sample intervals are at least one second (default five); correlation/hold/probe windows are at most five minutes. Invalid Go regex and CEL types require the actual Go compiler in production; the Python checker is not a substitute.

Schedules use five-field minute cron and explicit IANA timeZone (preset default Etc/UTC), no embedded TZ macros or second field. Persist the last admitted nominal UTC slot; deterministic jitter is less than the minimum interval and charged to the original slot. No replay/catch-up after downtime, suspension or expiry; report missed slots. Nonexistent DST local times are skipped; repeated local minute runs once per policy/local date-minute, identified with the first UTC occurrence. Distinct policies still share workload budgets. A file sizeAbove detector requires sizeBytes; a stable-size observation never proves an application finished writing a dump.

### SC-TRG-007

Given replica A logs an error while B is under memory pressure, when default pod-scoped all evaluates, then no combined trigger fires. A true condition at initial arming fires once after its hold; repeated samples do not increment an event count. Restarting at a missed schedule or during a repeated DST hour cannot queue duplicate dumps.

## Connector detectors

The first implemented detectors run in each region's connector, for a hub-held DebugPolicy
(`spec.target.cluster`) that runs the pod-status context recipe on the triggering Pod
(`maxPods: 1`, `selection: triggeringPod`). No node agent is needed. They are event-driven
([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1):

- The connector keeps shared informers (LIST once, then WATCH): one Pod informer per namespace
  with an active policy and, for probe policies, one Events informer per such namespace with field
  selector `involvedObject.kind=Pod,reason=Unhealthy`. It evaluates each policy's detector in
  process on watch events and pushes only occurrences over its hub connection.
- Detector state (per-Pod baselines and last seen counters) lives in connector memory. A connector
  restart or informer relist re-baselines every Pod: the first observation never fires, and the
  gap is reported in policy status. While an informer is not synced the detector is Unknown and
  neither fires nor re-arms.
- The hub stores one row per occurrence with a unique constraint on its idempotency key; the
  occurrence ID is the capture idempotency key, so duplicate deliveries and retries never start
  another capture. Policy activation, deactivation and changes reach the connector as events; the
  connector starts or stops evaluating the workload when they arrive.
- Timers that end a window (re-arm after `window`/`eventWindow` without a failure) are local timers
  started from observed event times, not polls.

Shared refinements of REQ-TRG-002/004/007 for these detectors:

- Every occurrence fires on a rising edge, keyed (policy, Pod UID, detector-specific instant). The
  first observation of a Pod is its baseline and is armed only when its condition is false; a Pod
  already failing at activation waits for a proven recovery. A source time later than the
  connector's clock counts as now.
- The shared workload budget (one occurrence per five minutes, burst two) holds for every policy
  on the workload; a policy's own cooldown and hourly bound only tighten it. An execution is
  charged at admission by the occurrence idempotency key and released on a definite refusal before
  start. Suppression is a saturating count per policy and reason, never a durable record per
  signal; capacity shortfalls are suppressions, never queued.
- Not applicable and not implemented: the 30-second correlation append (REQ-TRG-004 MAY) and
  per-node budgets (no node agent runs). Every other detector, expression, recipe or option is
  rejected at activation with its field path.
- Changing a policy's detector re-baselines every Pod: state of another detector is never compared.
- Only per-Pod levels, counts and instants leave the region. Event text, log text, alert labels,
  annotations, fingerprints, `generatorURL` and metric labels stay in the connector and are never
  logged, stored or followed.

### Restart counter

The exit detector's restart counter evaluates Pod update events of the named workload:

- A counter has no level, so there is no re-arm interval, and activation never fires
  (`evaluation.fireOnActivation: true` is rejected with its field path).
- One occurrence per (policy, Pod UID, restart count) whose latest termination matches the reasons
  (OOMKilled, Error, CrashLoopBackOff) and optional exit codes. When one update raises the count by
  more than one, the additional restarts are counted as suppressed `coalesced`; their individual
  reasons are not observed. Kubernetes reports exit codes, not signals.

### SC-TRG-008

Given an activated restart policy on a three-replica Deployment, when one container is killed, then
exactly one pod-status capture of that Pod runs under the policy executor and its team's audience
can download it; when all three replicas crash repeatedly for 150 seconds, then at most the shared
workload budget is admitted, every other observed restart is counted as suppressed, the hub holds
one occurrence row per admitted occurrence and one suppression counter per reason, and no capture
follows once the restarts stop.

### SC-TRG-009

Given an activated restart policy that has already captured, when a current maintainer of its
delegating team deactivates it, then the connector stops evaluating the workload when the
deactivation event arrives: a further container kill creates no occurrence, suppression count or
execution charge; the existing capture and its evidence remain; repeating the deactivation is a
replay; status reports `deactivated`; and activating the unchanged revision again is refused, so its
charges and expiry cannot be reset.

### Probe failure

`probe` with `source: events` (`auto` selects events) evaluates Unhealthy Event add/update events.
`kubeletMetrics` is rejected with its field path (it needs node access). The connector matches the
message prefix `<probeType> probe failed` or `<probeType> probe errored` for Pods of the workload.
These semantics refine REQ-TRG-002/006/007 for this source:

- `window` is 30 s to 5 min in whole seconds; `minimumFailures` 1–1000; `evaluation.rearmFor` must
  not exceed `window`.
- Failures within the window are a lower bound from Kubernetes Event series: each `count` or
  `series.count` increase observed on an Event update adds that many failures at the update's time;
  a series first seen with an earlier start counts only its latest failure. A burst inside a
  long-running identical-message series is undercounted, never overcounted. `minimumFailures: 1`
  fires on any failure.
- The detector is a level: a Pod fails while at least `minimumFailures` failures fall in the
  window. The occurrence instant is the newest failure second. After an occurrence, admitted or
  suppressed, the Pod re-arms when `window` seconds pass without a recorded failure.
- Kubernetes Events are best-effort (REQ-TRG-006): the kubelet may aggregate, rate-limit or drop
  them and they expire (default one hour). Readiness can also change without an Event; the
  detector reports only recorded probe failures. A liveness or startup failure that restarts the
  container is also visible to the exit detector.

The `alert` detector remains the route for conditions that the operator's Prometheus and log-stack
rules already express.

### SC-TRG-010

Given an activated probe policy (Readiness, two failures within one minute) on a workload whose
replicas pass their readiness probe, when one Pod's readiness probe starts failing every few
seconds, then exactly one pod-status capture of that Pod runs under the policy executor, further
failures of the same failing period create no occurrence, and no Event text appears in status,
occurrences, logs or the capture request. A Pod already failing when the policy is activated fires
only after a minute without failure followed by a new failure.

### External alert

The `alert` detector receives the standard Alertmanager version-4 webhook (see
[alert delivery](#alert-delivery-and-incident-identity)). The connector serves the receiver on an
in-cluster Service; the operator adds it as a `webhook_configs` receiver with
`send_resolved: true` and a bearer credential from a Helm-generated Secret
(`http_config.authorization`). A policy cannot name an address. These semantics refine
REQ-TRG-002/004/006/007 for this source:

- Options: `receiverRef: alertmanager` (the cluster's configured receiver; any other value is
  rejected), `status: firing`, optional `matchLabels` (at most 16 exact label values; `namespace`
  and `pod` are rejected because the mapping below sets them). `eventWindow` is rejected: the
  alert is a level. A longer hold belongs to the rule's `for` and `keep_firing_for`.
- Mapping: an alert counts for a Pod when its `namespace` label is the policy's namespace, its
  `pod` label names a current Pod of the workload and every `matchLabels` value matches. Alerts
  without a `pod` label (workload- or node-level rules) are ignored, since the policy captures the
  triggering Pod only. An Alertmanager shared by several clusters needs a cluster label in
  `matchLabels`.
- Level: a Pod is failing while at least one matching alert is firing and not resolved. The
  occurrence instant is the newest matching `startsAt` second; Alertmanager HA copies carry the
  same identity and never start another capture. After an occurrence the Pod re-arms when its last
  matching alert resolves; a later `startsAt` after the re-arm fires again, subject to budgets.
- Unknown (fires nothing, never re-arms): after a connector restart until the next notification
  for the group (Alertmanager resends at `group_interval`/`repeat_interval`). A request without the
  credential, over 1 MiB or more than 1024 alerts, or malformed is rejected. A region without a
  configured receiver refuses activation (`DetectorUnavailable`).

### SC-TRG-011

Given an activated alert policy (`alertname: HighErrorRate`) on a workload whose cluster's
Alertmanager sends to the receiver, when Alertmanager reports a matching alert labelled with one
Pod's namespace and name, then exactly one pod-status capture of that Pod runs under the policy
executor; repeated notifications while the alert stays active, a second matching alert on the same
Pod and alerts in another namespace, on another Pod or without a pod label create no occurrence;
no alert label or annotation appears in status, occurrences, logs or the capture request; and a
resolved notification re-arms the Pod.

### Log pattern

The `log` detector follows each container of each observed Pod with one
`GET pods/<pod>/log?container=<c>&follow=true&timestamps=true&sinceTime=<t>` stream made by the
connector (`get` on `pods/log`). A stream for a new container instance starts at that instance's
start time; a reconnect resumes at the last record time and deduplicates by record time and content
digest. These semantics refine REQ-TRG-001/002/003/004/007 for this source:

- Options: `stream: both` only (`stdout`/`stderr` are rejected: the log API's stream filter is a
  feature-gated parameter that is silently ignored where the gate is off); `match` literal
  (substring) or regexp (Go's RE2 engine, Perl syntax, no backreferences or look-around, at most
  4096 compiled instructions); `pattern` 1–1024 bytes; optional `jsonField`, a dotted path of at
  most 8 object keys whose value (a string's text, a number's or boolean's literal) is matched
  instead of the record; `maxRecordBytes` 1–65536 (default 65536); `overlong` drop (default) or
  matchPrefix, which is rejected with `jsonField` (incomplete JSON is never evaluated);
  `eventWindow` 30 s–5 min (default 30 s). `evaluation.rearmFor` must not exceed `eventWindow`.
- Bounds: at most 32 followed containers per Pod (more makes the Pod Unknown); buffered log data
  is bounded per Pod by REQ-TRG-001.
- Level: a Pod is failing while at least one record within (now − eventWindow, now] matches. The
  occurrence instant is the newest matching record second. After an occurrence the Pod re-arms
  when `eventWindow` passes without a match.
- Unknown (per Pod; neither fires, re-arms nor sets a baseline): a stream that is denied, failed
  or reconnecting, or a malformed timestamp, unless another container of the Pod matched.
- Overlong records are dropped (or their prefix matched with matchPrefix) and counted under the
  content-free suppression reason `overlong`.
- Reduced coverage (REQ-TRG-003): segments rotated before a stream started are not read, and
  multi-line records beyond kubelet's CRI partial-line joining are not assembled. Each followed
  stream is one long-lived API server connection; status reports the stream count.

### SC-TRG-012

Given an activated log policy (regexp `SYNTHETIC-PANIC [0-9]+`, eventWindow 30 s) on a workload
whose replicas log only non-matching lines, when one Pod writes a matching line, then exactly one
pod-status capture of that Pod runs under the policy executor; the line staying in the window
creates no further occurrence; no log text appears in status, occurrences or the capture request;
the Pod re-arms after the window passes without a match; and a Pod whose log stream fails without
a match neither fires nor re-arms.

### Resource

The `resource` detector reads the Kubernetes resource metrics API (`metrics.k8s.io`, served by
metrics-server). That API has no watch, so it is the one sampled source: the connector lists
`/apis/metrics.k8s.io/v1beta1/namespaces/<ns>/pods` once per 15 seconds (metrics-server's default
resolution) for all resource policies of the namespace together (`list` on `pods.metrics.k8s.io`;
at most 1024 items). These semantics refine REQ-TRG-002/006/007 and the resource units below for
this source:

- Options: `metric` cpuCores, cpuQuotaRatio, memoryBytes or memoryLimitRatio; `operator`
  gt/gte/lt/lte; `threshold` ≥ 0 (ratios may exceed one); `sampleInterval` 30 s–5 min, the oldest
  sample still evaluated. cpuThrottledRatio, memoryGrowthBytesPerSecond and the PSI metrics need
  the node-local cgroup reader and are rejected with their path. `evaluation.rearmFor` may be at
  most 15 s.
- Value: the Pod's sum over its containers of CPU usage in cores or memory working set in bytes; a
  ratio divides it by the Pod's finite effective limit (the Pod-level limit if set, otherwise the
  sum of the limits of every container and sidecar init container). A Pod without a finite limit
  refuses a ratio policy as an unsupported capability (no ratio when the limit is unlimited).
- Level: a Pod is failing while its fresh sample satisfies the condition. The occurrence instant
  is the sample second; the Pod re-arms at a fresh sample that does not satisfy it.
- Unknown (per Pod): no sample, a sample older than `sampleInterval` or older than the Pod's start
  (an earlier Pod of the same name), or a sample missing a running container. A malformed or
  unavailable (503) metrics API makes the sample Unknown. The metrics API being absent (404)
  refuses activation (`DetectorUnavailable`) and leaves later samples Unknown: absence is never
  read as zero.

### SC-TRG-013

Given an activated resource policy (cpuQuotaRatio gt 0.5, sampleInterval 60 s) on a workload with
CPU limits whose replicas are idle, when one Pod's CPU stays at its limit, then exactly one
pod-status capture of that Pod runs under the policy executor and further samples while it stays
busy create no occurrence; while metrics-server is unavailable no occurrence is created and no Pod
re-arms; and a cluster without the metrics API refuses the policy's activation.

## Trigger-to-action lifecycle

A detector firing is an occurrence signal, not a request to restart every collector. [Action lifecycle](action-lifecycle.md) resolution produces already armed ongoing sources and onTrigger actions. After ordinary admission, preserve matching source windows and dispatch independent onTrigger work. Cooldowns/deduplication suppress saves and actions while admitted continuous observation can continue. A late event or pending dump approval never shifts an existing window forward. Source readiness/coverage is separate from detector freshness and per-incident selection; missing required source history is visible while permitted context proceeds.

## Resource units and reset behavior

These definitions refine REQ-TRG-002/007; reported values always name the metric, unit, sample interval and contributing cgroup identities. The metrics-API resource detector provides cpuCores as the API's CPU usage rate over its scrape window (kubelet's rate of the cumulative usage counter) and memoryBytes as the memory working set (`memory.current` minus inactive file pages, never above `memory.current`), each summed over the Pod's containers; the other metrics of this table need the node-local reader.


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

Keep validated source startsAt/endsAt alongside local receipt time. Local monotonic receipt governs freshness/eventWindow; a long-running alert's startsAt does not manufacture months of requested capture history. Clock-skew/invalid-future timestamps have explicit rejection/uncertainty bounds, and delayed delivery reports the missed source interval. Never fetch generatorURL/externalURL or execute content from annotations. Deduplicate episodes by the occurrence idempotency key (receiver, fingerprint, startsAt) as a SQL unique constraint; the key lives as long as its occurrence row. No separate tombstone store exists.

## Explain a policy that did not capture

REQ-TRG-005 status and existing policy/capture views MUST expose a compact content-free explanation: desired/observed generation; authorized, observed and capped pod counts; detector freshness/Unknown reason; hold/rearm state; ongoing-source readiness/history; last admitted occurrence; and latest suppression reason/count/time. Distinguish cooldown, missing approval, expired authority, lack of capacity, no eligible process, stopped source and unsupported adapter. Link to the authorized existing policy/action view and a relevant correction. Scope every projection to current caller rights; no matched log text, private labels, argv or hidden target names. Reading status never samples traffic, runs commands or collects evidence. Detailed replay/test-event tooling remains a separate feature proposal.
