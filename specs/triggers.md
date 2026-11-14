# Dynamic triggers

A trigger turns observed signals into **occurrences**. An admitted occurrence saves windows from already running recorders and starts onTrigger actions ([action lifecycles](action-lifecycle.md)); it is not a request to start collectors. One path serves every origin: policy → occurrence → saved windows and onTrigger actions → capture. Storm protection is one rate limit and one concurrency limit, owned by [capacity](capacity.md#req-cap-001--workload-wide-storm-control) ([ADR-335](../docs/decisions/335-usable-by-default.md) D8).

## Trigger catalogue

| Detector | Source | Semantics |
| --- | --- | --- |
| Log pattern | Node CRI log tail where a node collector runs; otherwise followed `pods/log` streams | Literal/RE2 regexp or JSON field predicate, count within window |
| CPU | cgroup v2 `cpu.stat`; without a node collector, `metrics.k8s.io` | Cores, quota fraction, throttled fraction; requests are not capacity |
| Memory | cgroup `memory.*`; without a node collector, `metrics.k8s.io` | Bytes, fraction of a finite limit, growth rate, OOM/high counters |
| Pressure | cgroup PSI | Stall fraction, where available |
| Probe failure | Watched `Unhealthy` Events; kubelet probe metrics where the node collector runs | Liveness/readiness/startup; Events are best-effort |
| Exit/restart | Watched Pod status | Exit code, OOMKilled, restart count, CrashLoopBackOff |
| Crash artifact | Core agent or approved runtime-file watcher | A verified core/artifact; merged with the related exit occurrence |
| External alert | Alertmanager webhook received by the connector | Firing/resolved, mapped to the policy's workload |
| Scheduled | Cron | Periodic baseline captures, off unless configured |
| File condition | Approved container file watcher (inotify) | Created/changed/size threshold on declared paths |
| Network condition | Optional Gadget/Hubble metrics adapter | Connect failures, retransmits, DNS errors |
| Deployment/node condition | Kubernetes watches | Rollout stalls, eviction, node pressure |

Manual captures have no detector; they enter the same path as an occurrence with origin `manual`. Implementation order: log/resource/probe/exit/alert, then crash artifact, then the optional detectors. An unavailable detector reports `DetectorUnavailable` with its field path; it is never silently ignored.

## REQ-TRG-001 — Bounded expression language

Policies MUST define named typed detectors and a `when` expression combining them with `all`, `any`, `not`, `for`, count/window or ordered `sequence`. Leaves are CEL predicates in a typed AST; there are no scripts and no network, file, process or unbounded iteration functions. Admission MUST reject unknown fields, impossible units, invalid regular expressions, expressions deeper than cel-go's recursion limit (250) and expressions above Kubernetes CEL's `PerCallLimit` (1,000,000). Production validation uses the Go compilers; the Python checker is not a substitute.

Policy size is bounded by the Kubernetes object size. Per-Pod detector state is a count plus at most `minimumFailures` timestamps, so windows need no maximum. Log buffers cost connector memory: buffered log data per Pod defaults to `connectorMemoryLimit × logShare / followedPods`, at least 1 MiB; an assembled record defaults to 64 KiB (containerd splits at 16 KiB and kubelet rejoins). Overlong records are dropped and counted; `matchPrefix` may match their truncated prefix. JSON predicates never evaluate incomplete JSON. Regular expressions use Go's linear-time RE2 engine.

### SC-TRG-001

Given an invalid nested expression or a regexp with unsupported syntax, when the policy is submitted, then admission rejects it with a field path. A pathological record cannot allocate beyond the record/buffer limits.

## REQ-TRG-002 — Time, missing data and edges

Evaluation uses monotonic local time and records source timestamps. Missing or stale data is `Unknown`, never false or zero; `not Unknown` is Unknown. A sustained condition resets on a missing sample.

A trigger fires once on a rising edge, after its hold, not on every sample. A condition already true at activation fires by default; `evaluation.fireOnActivation: false` waits for a proven false state first. Re-arm needs a continuous false interval (`evaluation.rearmFor`, default the detector's window); Unknown never counts as recovery. Raw matched text never enters Events, CRD status or webhooks.

### SC-TRG-002

Given memory above 85% for 20 seconds, when a sample is missing halfway, then the hold resets. An unlimited memory limit makes the ratio Unknown, which cannot fire.

## REQ-TRG-003 — Log completeness

The node CRI reader MUST handle partial/full records, rotation, truncation and container restarts, keep a bounded checkpoint and deduplicate replayed records. A followed `pods/log` stream does not read segments rotated before it started, and a reconnect is a gap; both are reported as reduced coverage ([Kubernetes logging](https://kubernetes.io/docs/concepts/cluster-administration/logging/)). An onTrigger `logs` action may read history the runtime retained even without an armed detector; it cannot reconstruct missed detector transitions.

### SC-TRG-003

Given a matching CRI record split across partial entries and followed by rotation, when the collector restarts and replays its overlap, then the record is attributed at most once, or explicitly uncertain if no reliable cursor existed.

## REQ-TRG-004 — Occurrence identity and storm limits

Each occurrence has one idempotency key: policy, Pod UID and a detector-specific instant (the restart count, the newest failure second, or the alert's receiver/fingerprint/`startsAt`). The hub stores one row per key under a unique constraint, and the key is the capture's idempotency key, so duplicate deliveries, HA copies and retries never start another capture. A crash artifact and the exit of the same container restart belong to one occurrence.

Admission applies the [capacity](capacity.md#req-cap-001--workload-wide-storm-control) rate limit (a token bucket per workload, shared by every policy and manual save on it) and its concurrency limit. A policy's `budgets` can only tighten them for that policy. An admitted occurrence is charged by its key and released on a definite refusal before start. An occurrence that does not fit is suppressed, never queued: suppression is a content-free saturating count per policy and reason. Budget changes never authorize a previously refused occurrence.

### SC-TRG-004

Given duplicate Alertmanager deliveries for one firing alert, when they arrive across a connector restart, then one occurrence exists and no intrusive action is repeated after an ambiguous start.

## REQ-TRG-005 — Policy changes

A DebugPolicy takes effect when applied. An update compiles into a new generation before it runs; re-applying an unchanged spec keeps acceptance, approval, counters and expiry ([execution identity](execution.md)). An intrusive approval binds the execution scope and recipe digests; changing them needs a new approval, which attaches itself to the policy by namespace and name. Display, sharing and pause changes cannot broaden collection. A connector or node switches generation atomically. Status uses `metadata.generation`, `status.observedGeneration` and conditions with armed and failed target counts. `spec.suspend: true` or deletion stops observations and future actions; uploaded evidence follows retention. Resuming continues counters and the original grant expiry.

### SC-TRG-005

Given an approved policy collecting stacks, when its recipe changes to a heap dump or its target broadens, then the old approval does not cover the new generation, and no node runs a mixture of old and new actions.

## REQ-TRG-006 — Best-effort sources

Probe Events are best-effort: Kubernetes aggregates, drops and expires them, and readiness can change without a probe failure. External alert receivers MUST authenticate the sender, limit the body and map alerts only to workloads within the sender's configured scope. A webhook cannot introduce a command or selector.

### SC-TRG-006

Given an Event series whose count rises from 4 to 9, when it is observed twice, then five new failures are counted once. A webhook naming an unconfigured cluster or a workload outside the sender's scope is rejected.

## REQ-TRG-007 — Correlation and schedules

Detectors evaluate per Pod UID by default. Signals from different replicas combine only when `evaluation.scope: workload` is set and approved. Pod scope includes sidecars; two signals in one Pod need not come from one process.

A detector is a level (resource, network, Kubernetes condition) or an event source (log, exit, alert, crash artifact, schedule, file). An event leaf is true while a deduplicated event lies in its `eventWindow` (default 30 s) and Unknown on coverage loss. `count` counts distinct occurrences or rising edges, never samples. `sequence` consumes distinct ordered occurrences and expires incomplete prefixes at `within`. `all` is false if any operand is false, otherwise Unknown if any is Unknown; `any` is the dual. Windows are `(now − window, now]`. A source restart resets correlation state with a reported gap.

Ratio detectors use a finite limit; a component without one is Unknown, and CPU requests are never a denominator. Schedules use five-field cron with an explicit IANA `timeZone` (default `Etc/UTC`) and optional jitter below the interval. Missed slots (downtime, suspension, DST gaps) are reported and never replayed; a repeated DST minute runs once.

### SC-TRG-007

Given replica A logs an error while B is under memory pressure, when a pod-scoped `all` evaluates, then nothing fires. A condition true at arming fires once after its hold. A restart during a missed slot or a repeated DST hour queues no duplicate capture.

## Connector detectors

A team writes its DebugPolicy in the workload's namespace, like a PrometheusRule; Kubernetes RBAC decides who may write it (ADR-335 D14). The connector watches DebugPolicies and delivers them to the hub; cluster and namespace follow from where the policy lives. A policy may run any recipe or profile composition a manual capture may run (ADR-335 D15). The detectors below run in the connector, so triggering needs no node collector; actions that need the node collector end `Unsupported` (`NodeCollectorUnavailable`) on nodes without it while other actions proceed. Options that need node data (`kubeletMetrics`, cgroup-only metrics, PSI, file and network conditions) report `DetectorUnavailable` without it.

The detectors are event-driven ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1):

- The connector keeps shared informers: Pods per namespace with a policy and, for probe policies, Events filtered to `involvedObject.kind=Pod,reason=Unhealthy`. It evaluates detectors on watch events and pushes only occurrences to the hub.
- Detector state lives in connector memory. A connector restart, informer relist or detector change re-baselines every Pod: a first observation never fires, a Pod already failing waits for recovery, and the gap is reported. An unsynced informer is Unknown.
- Window ends are local timers from observed event times, not polls.
- Only per-Pod levels, counts and instants leave the region. Event and log text, alert labels and annotations, `generatorURL` and metric labels are never logged, stored or followed.

### Restart counter

The exit detector evaluates Pod updates of the workload. One occurrence per (policy, Pod UID, restart count) whose last termination matches the configured reasons (OOMKilled, Error, CrashLoopBackOff) and optional exit codes. A counter has no level, so it has no re-arm interval and `fireOnActivation: true` is rejected. When one update raises the count by more than one, the extra restarts are counted as suppressed `coalesced`. Kubernetes reports exit codes, not signals.

### SC-TRG-008

Given an applied restart policy running the pod-status recipe on a three-replica Deployment, when one container is killed, then exactly one pod-status capture of that Pod runs under the policy executor and its team can download it; when all three replicas crash repeatedly for 150 seconds, then only what the workload rate limit admits runs, every other restart is counted as suppressed, and no capture follows once the restarts stop.

### SC-TRG-009

Given an applied restart policy that has captured, when its team sets `spec.suspend: true`, then a further container kill creates no occurrence, suppression count or charge; the existing evidence remains; and status reports `Suspended`. Re-applying the same YAML changes no generation, counter or expiry; resuming keeps the rate-limit state and the original grant expiry.

### Probe failure

`probe` with `source: events` (the default) evaluates `Unhealthy` Events whose message starts with `<probeType> probe failed` or `errored`. `kubeletMetrics` needs the node collector.

- `window` is whole seconds, default 30 s, at most the cluster's Event TTL (default 1 h); `minimumFailures` is positive.
- Each observed `count` or `series.count` increase adds that many failures at the update's time; a series first seen late counts only its latest failure. Bursts inside one series are undercounted, never overcounted.
- A Pod fails while at least `minimumFailures` failures fall in the window. The instant is the newest failure second; the Pod re-arms after `window` without a failure.
- A liveness or startup failure that restarts the container is also visible to the exit detector.

### SC-TRG-010

Given an applied probe policy (readiness, two failures within one minute), when one Pod's readiness probe fails every few seconds, then exactly one capture of that Pod runs, further failures of that period create no occurrence, and no Event text appears in status, occurrences or the capture. A Pod already failing at apply fires only after a minute without failure followed by a new failure.

### External alert

The `alert` detector receives the standard Alertmanager version-4 webhook on a connector Service; the operator adds it as a `webhook_configs` receiver with `send_resolved: true`. The sender authenticates with a bearer credential from a Secret named in Helm values, or, inside the cluster, with its projected ServiceAccount token checked by TokenReview (ADR-334). A policy cannot name an address. Other webhook bodies are rejected ([format](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)).

- Options: `receiverRef: alertmanager`, `status: firing`, optional exact `matchLabels` (not `namespace`, `pod` or the workload labels, which the mapping sets). `eventWindow` is rejected: an alert is a level; holds belong to the rule's `for`.
- Mapping: the alert's `namespace` label is the policy's namespace and either a `pod` label names a current Pod of the workload, or a `deployment`, `statefulset` or `service` label names the workload. A workload-level alert collects the Pod chosen by `target.selection` (default: the most recently started ready Pod) and records that no Pod was named. Other alerts are ignored. An Alertmanager shared by clusters needs a cluster label in `matchLabels`.
- Level: failing while a matching alert fires. The episode identity is receiver, fingerprint and `startsAt`; a later `startsAt` is a new episode. Resolved is terminal for its episode, and the Pod re-arms when its last matching alert resolves. Each alert's own status counts, not the group's. Annotations and URLs are never fetched or executed.
- Unknown after a connector restart until the next notification. The body limit derives from the receiver's memory share, default 1 MiB; Alertmanager's `max_alerts` truncation is reported.

### SC-TRG-011

Given an applied alert policy (`alertname: HighErrorRate`), when Alertmanager reports a matching alert for one Pod, then exactly one capture of that Pod runs; an alert naming only the Deployment captures the Pod chosen by selection; repeated notifications, a second alert on the same Pod and alerts for other namespaces or Pods create no occurrence; no alert label reaches status, occurrences or the capture; and a resolved notification re-arms the Pod.

### Log pattern

The `log` detector follows each container of each observed Pod with one `GET pods/<pod>/log?container=<c>&follow=true&timestamps=true&sinceTime=<t>` stream. A reconnect resumes at the last record time and deduplicates by time and content digest.

- Options: `stream` (default `both`; `stdout`/`stderr` need the node collector's CRI tail because the log API's stream filter is feature-gated); `match` literal or regexp (RE2, program memory 8 MiB); `pattern`; optional `jsonField` path; `maxRecordBytes` (default 64 KiB); `overlong` drop (default) or `matchPrefix` (not with `jsonField`); `eventWindow` (default 30 s).
- A connector follows at most `connectorMemoryLimit × logShare / perStreamBuffer` streams, reported in status; streams beyond that are a reported gap.
- A Pod fails while a matching record lies in `eventWindow`; it re-arms when the window passes without a match. A denied, failed or reconnecting stream is Unknown unless another container of the Pod matched.

### SC-TRG-012

Given an applied log policy (regexp `SYNTHETIC-PANIC [0-9]+`, eventWindow 30 s), when one Pod writes a matching line, then exactly one capture of that Pod runs; no log text appears in status, occurrences or the capture; the Pod re-arms after the window passes without a match; and a Pod whose stream fails neither fires nor re-arms.

### Resource

The `resource` detector reads `metrics.k8s.io`. That API has no watch, so it is the one sampled source: the connector lists the namespace's Pod metrics once per the API's reported `window` (metrics-server default 15 s) for all resource policies of the namespace.

- Options: `metric` (cpuCores, cpuQuotaRatio, memoryBytes, memoryLimitRatio), `operator`, `threshold`, `sampleInterval`. The minimum interval is twice the API window (30 s with metrics-server); the node cgroup reader defaults to 5 s, at least 1 s. Throttling, growth and PSI metrics need the node collector.
- Value: the Pod's summed container CPU cores or memory working set; a ratio divides by the Pod's finite effective limit. A Pod without a finite limit cannot use a ratio.
- A Pod fails while a fresh sample satisfies the condition and re-arms at a fresh sample that does not. A missing, stale or malformed sample is Unknown; an absent API (404) reports `DetectorUnavailable`, never zero.

### SC-TRG-013

Given an applied resource policy (cpuQuotaRatio gt 0.5, sampleInterval 60 s), when one Pod stays at its CPU limit, then exactly one capture of that Pod runs; while metrics-server is unavailable nothing fires or re-arms; and without the metrics API and a node collector the policy reports `DetectorUnavailable`.

## Resource units

Reported values name metric, unit and interval. The metrics API supplies cpuCores (usage rate over its scrape window) and memoryBytes (working set); the rest need the node cgroup reader ([cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), [PSI](https://docs.kernel.org/accounting/psi.html)).

| Metric | Calculation |
| --- | --- |
| cpuCores | Δ `cpu.stat` usage_usec / elapsed µs, without double-counting parent/child cgroups |
| cpuQuotaRatio | Cores / finite effective quota in cores; never requests |
| cpuThrottledRatio | Δ nr_throttled / Δ nr_periods (0..1) |
| memoryBytes / memoryLimitRatio | `memory.current` / divided by the finite effective limit |
| memoryGrowthBytesPerSecond | Signed Δ `memory.current` / elapsed seconds |
| memoryPSI / cpuPSI / ioPSI | Δ `some.total` / elapsed µs (0..1) |

A counter reset, cgroup replacement, zero elapsed time or missing denominator is Unknown with a new baseline, never a recovery or burst. Quota and memory ratios may exceed one and are not clamped.

## Explain a policy that did not capture

Policy status and policy views MUST explain, without content: desired/observed generation; authorized and observed pod counts; detector freshness or Unknown reason; hold/re-arm state; recorder readiness; last admitted occurrence; latest suppression reason, count and time. Reasons distinguish rate limit, concurrency limit, missing approval, expired grant, no capacity, no eligible process, stopped source and unsupported adapter. Projections follow the caller's current rights. Reading status never collects anything.
