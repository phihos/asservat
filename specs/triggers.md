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

Policies MUST define named typed detectors and a `when` expression combining detector states through `all`, `any`, `not`, `for`, count/window, or ordered sequence. Implement a constrained typed AST with CEL for leaf predicates, not arbitrary scripts. No network, file, process or unbounded iteration functions exist in expressions. Admission MUST reject unknown fields, impossible units, invalid regular expressions, expressions deeper than the CEL parser recursion limit (cel-go default 250) and expressions over the per-expression cost limit (1,000,000, as Kubernetes CEL validation's `PerCallLimit`).

The number of detectors and the policy text are bounded by the Kubernetes object size (≈1.5 MiB etcd request limit). Log buffers cost connector memory: buffered log data per Pod defaults to `connectorMemoryLimit × logShare / followedPods`, at least 1 MiB, fairly split across its sources; an assembled record defaults to 64 KiB (containerd splits lines at 16 KiB and kubelet rejoins partials) and may not exceed the per-Pod buffer divided by its followed containers. Temporal windows have no fixed maximum: per-Pod state is a count plus at most `minimumFailures` timestamps or the newest match instant, so memory does not grow with window length. Node-local cgroup samples default to a 5-second interval; their minimum is derived from the collector CPU budget (CPU per sample × observed Pods) and is at least one second. The metrics-API resource source samples at the API's reported resolution (see [Resource](#resource)). Overlong records are dropped and counted by default. Explicit matchPrefix mode may match a truncated literal/regexp prefix, tagged incomplete; structured JSON predicates never evaluate incomplete JSON. Regular expressions use Go's linear-time engine; no backreferences or look-around.

### SC-TRG-001

Given an invalid nested expression or a regexp requiring unsupported syntax, when the policy is submitted, then admission rejects it with a field path. A pathological input record cannot allocate beyond the record/buffer limits.

## REQ-TRG-002 — Time, missing data and edge semantics

Evaluation MUST use monotonic time locally and preserve source and observed wall timestamps. Missing/stale detector data has state `Unknown`, not false or zero. `not Unknown` remains Unknown. Sustained conditions reset on missing samples by default; an explicit gap tolerance may be configured and is bounded by the sample period budget.

A trigger fires once on a qualified false/Unknown→true activation after its hold condition, not every sample. Initial true may fire by default; evaluation.fireOnActivation=false instead waits for a proven false state before arming. Re-arm requires a continuous false interval (evaluation.rearmFor, default one `eventWindow`/`window` of the detector, or two sample intervals for a sampled level); Unknown never constitutes recovery. Record policy generation, detector values/units, source freshness, threshold and observation gaps. Never place raw matched log text in Events, CRD status or webhook data.

### SC-TRG-002

Given memory usage above 85% for 20 seconds, when a sample is missing halfway through, then the default hold resets. An unlimited memory limit produces `UnknownRatio` and cannot satisfy the ratio detector.

## REQ-TRG-003 — Log completeness

The node reader MUST handle CRI partial/full records, rotation, truncation, reconnects and container restarts with bounded checkpoint state. Record stream, inode/file generation or source cursor, timestamp and container identity. Deduplicate replayed records over a bounded window. Detector evaluation requires an armed sensor. An onTrigger logs action may retrieve preexisting runtime log history even if that sensor was not armed; it cannot reconstruct unobserved detector transitions. Report missing history after restart or rotation loss, and never equate available log bytes with complete trigger coverage.

Followed Kubernetes `pods/log` streams MUST report their reduced coverage: segments rotated before a stream started are not read, and a reconnecting stream is a gap. [Kubernetes logging architecture](https://kubernetes.io/docs/concepts/cluster-administration/logging/).

### SC-TRG-003

Given a matching CRI record split across partial entries and followed by rotation, when the collector restarts and replays its overlap window, then at most one occurrence is attributed to the same record identity, with explicit uncertainty if a reliable source cursor was unavailable.

## REQ-TRG-004 — Deduplication and budgets

Each trigger occurrence MUST have an idempotency key derived from cluster, policy UID/generation, pod/correlation identity, contributing source IDs, detector transition ID and source epoch. Enforce per-policy, per-workload, per-node and installation-wide budgets. Defaults: occurrences that start an expensive action (dump, command, intrusive profile, recording save) are limited to one per workload per 5 minutes, burst 2 (storm protection, ADR-335 D8; the interval matches kubelet's maximum CrashLoopBackOff back-off); occurrences with only context, log, non-intrusive profile or recorder-window actions are limited by each policy's own `cooldown` (default 1 minute, storm protection); one intrusive action per pod at once (D8 concurrency limit). Per-node concurrency (artifact streams, active actions) defaults from the node collector's resource limits, at least 4 artifact streams and 16 active actions per node; these are tuning values in Helm, not fixed caps. There is no limit on the number of policies; their cost is the watched workloads, bounded by the connector's shared informers. Budget changes cannot retroactively authorize a previously denied action. The [capacity rules](capacity.md) add stricter workload-wide dump limits, staged admission, bounded suppression summaries and shared counters across every replica/policy/generation. Context burst capacity never authorizes a dump burst.

Related crash-agent, exit, probe and alert signals MAY append to one occurrence when they share its identity (Pod UID plus container restart count or process identity); there is no time window. Preserve each signal's provenance. A signature used before analysis MUST be marked provisional. Rate-limited occurrences keep content-free counts and gap reasons instead of pretending evidence was collected. Aggregate suppressed signals in bounded windows rather than creating a control object or durable event per raw match.

### SC-TRG-004

Given duplicate Alertmanager deliveries and a local crash for the same process, when they arrive across a controller restart, then the same occurrence is recovered and no invasive action is automatically repeated after an ambiguous start.

## REQ-TRG-005 — Dynamic policy application

A DebugPolicy takes effect when it is applied; there is no separate activation step. Policy updates MUST compile and validate as a new immutable generation before they run. Re-applying an unchanged spec is idempotent: a generation whose resolved execution digest is unchanged keeps its acceptance, approval, counters and expiry ([execution identity](execution.md)). Actions that need an approval wait for an approval of the current scope; the approval links to the policy by namespace and name and attaches itself, so no grant identifier is copied into the policy. Each generation retains an authenticated submission and approved execution identity under [permission management](permissions.md); every resolved target must remain within that identity's current derived or explicit scope. Intrusive policy grants bind the collection execution scope and recipe digests under [execution identity](execution.md); changes to that scope invalidate approval. Display, sharing and pause changes have separate effects and cannot broaden collection. Preset authoring binds both submitted input and the immutable resolved catalog/plan as specified in [ergonomics](ergonomics.md). A node or connector switches generation atomically and acknowledges it. Status reports `metadata.generation` and `status.observedGeneration`, armed targets, failed targets and reason. Suspending (`spec.suspend: true`) or removing a policy cancels observations and future actions; already uploaded evidence follows retention. Resuming the same scope continues its counters and an intrusive grant's original expiry.

### SC-TRG-005

Given an approved policy collecting stacks, when someone changes its recipe to a heap dump or broadens the target, then the previous approval does not authorize the new generation. Existing nodes report the transition and do not execute a mixture of old/new action definitions.

## REQ-TRG-006 — Probe and external-source honesty

Probe Events MUST be described as best-effort; Kubernetes may aggregate or omit them, and pod readiness can change for reasons other than a readiness-probe failure. Prefer typed kubelet probe metrics if permitted, while reporting scrape freshness. External alert receivers MUST authenticate the sender, limit body size, validate target mapping against the sender's configured cluster/workload scope and deduplicate alert occurrences as defined below. A webhook cannot introduce an arbitrary command or selector.

### SC-TRG-006

Given an Event series with count increasing from 4 to 9, when it is observed twice, then five new failures are counted once. A webhook naming an unconfigured cluster or a workload outside the sender's allowed scope is rejected without target discovery.

## REQ-TRG-007 — Correlation, events and schedules

The default evaluation key is pod UID, with internal source/restart identities retained. No log from replica A can combine with a resource condition on B unless evaluation.scope explicitly selects workload and the larger contributor set is approved. Pod scope deliberately includes sidecars: do not claim that two signals necessarily came from the same process. Record contributors for collection selection and explanation.

A detector is either a fresh level (resource/network/Kubernetes condition) or an event source (log/exit/alert/crashArtifact/schedule/file). Event leaves are true while at least one deduplicated event remains in eventWindow (default 30 seconds, no maximum), false only while the source is fresh and its window is empty, Unknown on coverage loss. Probe threshold is a level over deduplicated failure events. count counts distinct source occurrences or qualified rising transitions for level detectors, never every true sample. sequence consumes distinct ordered occurrences, compares local observed time with stable source-ID tie breaks, does not reuse one event for multiple sequence positions, and expires incomplete prefixes at within. Each completed sequence is a one-evaluation pulse. for requires continuous known true; not uses three-valued logic (not Unknown is Unknown), all is false if any operand is false and otherwise Unknown if any is unknown; any is the dual. Temporal windows use (now-window, now]. Replays do not advance event counts. Reset correlation state on source epoch changes with an explicit gap, without resetting workload budgets.

Absolute pod CPU/memory values use qualified aggregate accounting without double-counting parent/child cgroups. Limit/quota ratios and PSI are evaluated on each available runtime component and combined with any under the same pod; no user container selector exists. A component without a finite limit is Unknown for that ratio, not zero; preserve each contributor/unit and partial coverage. CPU requests are never a denominator. Admission rejects unsupported metric/runtime combinations. Node-local sample intervals default to five seconds with a minimum derived from the collector CPU budget (REQ-TRG-001); the metrics-API source is described under [Resource](#resource). Correlation and hold windows have no fixed maximum; a probe window is bounded by the Event TTL ([Probe failure](#probe-failure)). Invalid Go regex and CEL types require the actual Go compiler in production; the Python checker is not a substitute.

Schedules use standard five-field minute cron (hence minute granularity) and explicit IANA timeZone (preset default Etc/UTC), no embedded TZ macros or second field. Persist the last admitted nominal UTC slot; deterministic jitter is less than the minimum interval and charged to the original slot. No replay/catch-up after downtime, suspension or expiry; report missed slots. Nonexistent DST local times are skipped; repeated local minute runs once per policy/local date-minute, identified with the first UTC occurrence. Distinct policies still share workload budgets. A file sizeAbove detector requires sizeBytes; a stable-size observation never proves an application finished writing a dump.

### SC-TRG-007

Given replica A logs an error while B is under memory pressure, when default pod-scoped all evaluates, then no combined trigger fires. A true condition at initial arming fires once after its hold; repeated samples do not increment an event count. Restarting at a missed schedule or during a repeated DST hour cannot queue duplicate dumps.

## Connector detectors

A team writes its DebugPolicy in the workload's own namespace of the workload cluster, like a
PrometheusRule or a Kyverno `Policy`; Kubernetes RBAC on that namespace decides who may write it
([ADR-335](../docs/decisions/335-usable-by-default.md) D14). The connector watches DebugPolicies
and delivers them to the hub over its connection; the policy names no cluster or namespace, both
follow from where it lives. A policy may run any recipe or capture-profile composition that a
manual capture may run ([ADR-335](../docs/decisions/335-usable-by-default.md) D15), within each
action's [lifecycle](action-lifecycle.md). The detectors below run in each region's connector, so
no node collector is needed to trigger. Actions that need the node collector (packets, syscalls,
eBPF profiles, dumps, file reads) run where it is installed; on a node without it that action ends
`Unsupported` with reason `NodeCollectorUnavailable` while the policy's other actions proceed.
The detectors are event-driven ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1):

- The connector keeps shared informers (LIST once, then WATCH): one Pod informer per namespace
  with a policy and, for probe policies, one Events informer per such namespace with field
  selector `involvedObject.kind=Pod,reason=Unhealthy`. It evaluates each policy's detector in
  process on watch events and pushes only occurrences over its hub connection.
- Detector state (per-Pod baselines and last seen counters) lives in connector memory. A connector
  restart or informer relist re-baselines every Pod: the first observation never fires, and the
  gap is reported in policy status. While an informer is not synced the detector is Unknown and
  neither fires nor re-arms.
- The hub stores one row per occurrence with a unique constraint on its idempotency key; the
  occurrence ID is the capture idempotency key, so duplicate deliveries and retries never start
  another capture. Applying, suspending, changing and deleting a policy reach the connector as
  watch events; the connector starts or stops evaluating the workload when they arrive.
- Timers that end a window (re-arm after `window`/`eventWindow` without a failure) are local timers
  started from observed event times, not polls.

Shared refinements of REQ-TRG-002/004/007 for these detectors:

- Every occurrence fires on a rising edge, keyed (policy, Pod UID, detector-specific instant). The
  first observation of a Pod is its baseline and is armed only when its condition is false; a Pod
  already failing when the policy is applied waits for a proven recovery. A source time later than
  the connector's clock counts as now.
- Workload budgets (REQ-TRG-004) hold for every policy on the workload; a policy's own cooldown only
  tightens them. An execution is charged at admission by the occurrence
  idempotency key and released on a definite refusal before start. Suppression is a saturating
  count per policy and reason, never a durable record per signal; capacity shortfalls are
  suppressions, never queued.
- The identity-based correlation append (REQ-TRG-004 MAY) is not applied to connector detectors.
  Options that need node-local data (`kubeletMetrics`, cgroup-only metrics, PSI, file and network
  conditions) are evaluated by the node collector where it runs; without it the policy reports
  `DetectorUnavailable` with the field path.
- Changing a policy's detector re-baselines every Pod: state of another detector is never compared.
- Only per-Pod levels, counts and instants leave the region. Event text, log text, alert labels,
  annotations, fingerprints, `generatorURL` and metric labels stay in the connector and are never
  logged, stored or followed.

### Restart counter

The exit detector's restart counter evaluates Pod update events of the named workload:

- A counter has no level, so there is no re-arm interval, and applying the policy never fires
  (`evaluation.fireOnActivation: true` is rejected with its field path).
- One occurrence per (policy, Pod UID, restart count) whose latest termination matches the reasons
  (OOMKilled, Error, CrashLoopBackOff) and optional exit codes. When one update raises the count by
  more than one, the additional restarts are counted as suppressed `coalesced`; their individual
  reasons are not observed. Kubernetes reports exit codes, not signals.

### SC-TRG-008

Given an applied restart policy running the pod-status recipe on a three-replica Deployment, when
one container is killed, then exactly one pod-status capture of that Pod runs under the policy executor and its team's audience
can download it; when all three replicas crash repeatedly for 150 seconds, then at most the shared
workload budget is admitted, every other observed restart is counted as suppressed, the hub holds
one occurrence row per admitted occurrence and one suppression counter per reason, and no capture
follows once the restarts stop.

### SC-TRG-009

Given an applied restart policy that has already captured, when its team sets
`spec.suspend: true`, then the connector stops evaluating the workload when the update event
arrives: a further container kill creates no occurrence, suppression count or execution charge; the
existing capture and its evidence remain; and status reports `Suspended`. Re-applying the same YAML
is a no-op that changes no generation, counter or expiry. Resuming continues the cooldown and
hourly counters and an intrusive grant's original expiry; neither suspension nor re-apply resets
them.

### Probe failure

`probe` with `source: events` (`auto` selects events) evaluates Unhealthy Event add/update events.
`kubeletMetrics` is rejected with its field path (it needs node access). The connector matches the
message prefix `<probeType> probe failed` or `<probeType> probe errored` for Pods of the workload.
These semantics refine REQ-TRG-002/006/007 for this source:

- `window` is whole seconds, default 30 s, at most the cluster's Event TTL (kube-apiserver
  `--event-ttl`, default 1 h), because expired Events are no longer recorded; `minimumFailures` is a
  positive integer; `evaluation.rearmFor` must not exceed `window`.
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

Given an applied probe policy (Readiness, two failures within one minute) on a workload whose
replicas pass their readiness probe, when one Pod's readiness probe starts failing every few
seconds, then exactly one capture of that Pod runs under the policy executor, further
failures of the same failing period create no occurrence, and no Event text appears in status,
occurrences, logs or the capture request. A Pod already failing when the policy is applied fires
only after a minute without failure followed by a new failure.

### External alert

The `alert` detector receives the standard Alertmanager version-4 webhook (see
[alert delivery](#alert-delivery-and-incident-identity)). The connector serves the receiver on an
in-cluster Service; the operator adds it as a `webhook_configs` receiver with
`send_resolved: true`. The receiver authenticates the sender with a bearer credential
(`http_config.authorization`) read from a Secret the Helm values name: an existing Secret that
Alertmanager already mounts, or one the chart generates. An Alertmanager in the same cluster may
instead present its projected ServiceAccount token (`http_config.authorization.credentials_file`)
with the connector audience, checked by TokenReview as for connectors
(ADR-334). A policy cannot name an address. These semantics refine
REQ-TRG-002/004/006/007 for this source:

- Options: `receiverRef: alertmanager` (the cluster's configured receiver; any other value is
  rejected), `status: firing`, optional `matchLabels` (exact label values; `namespace`,
  `pod` and the workload labels below are rejected because the mapping sets them). `eventWindow` is rejected: the
  alert is a level. A longer hold belongs to the rule's `for` and `keep_firing_for`.
- Mapping: an alert counts when its `namespace` label is the policy's namespace, every
  `matchLabels` value matches and it names the workload: a `pod` label naming a current Pod of the
  workload makes that Pod the triggering Pod; otherwise a `deployment` or `statefulset` label
  equal to the policy's workload name (or a `service` label naming a Service whose selector
  selects the workload's Pods) makes it a workload-level occurrence. A workload-level occurrence
  collects the pods chosen by `target.selection` (REQ-TGT-005); with the default `triggeringPod`
  it collects the most recently started ready Pod of the workload, ordered by start time then UID,
  and the capture records that the alert named no Pod. Alerts naming neither are ignored. An
  Alertmanager shared by several clusters needs a cluster label in `matchLabels`.
- Level: a Pod (or, for workload-level alerts, the workload) is failing while at least one matching
  alert is firing and not resolved. The
  occurrence instant is the newest matching `startsAt` second; Alertmanager HA copies carry the
  same identity and never start another capture. After an occurrence the Pod re-arms when its last
  matching alert resolves; a later `startsAt` after the re-arm fires again, subject to budgets.
- Unknown (fires nothing, never re-arms): after a connector restart until the next notification
  for the group (Alertmanager resends at `group_interval`/`repeat_interval`). A request without the
  credential, with a body over the receiver limit, or malformed is rejected. The body limit costs
  connector memory and is derived as the receiver's memory share divided by its concurrent requests,
  default 1 MiB. A batch is never rejected for its alert count; Alertmanager's own `max_alerts`
  truncates and reports `truncatedAlerts`. A region without a
  configured receiver reports `DetectorUnavailable`.

### SC-TRG-011

Given an applied alert policy (`alertname: HighErrorRate`) on a workload whose cluster's
Alertmanager sends to the receiver, when Alertmanager reports a matching alert labelled with one
Pod's namespace and name, then exactly one capture of that Pod runs under the policy executor; a
matching alert labelled only with the Deployment's name captures one Pod chosen by the policy's
selection; repeated notifications while the alert stays active, a second matching alert on the same
Pod and alerts in another namespace, on another Pod or naming no Pod or workload create no occurrence;
no alert label or annotation appears in status, occurrences, logs or the capture request; and a
resolved notification re-arms the Pod.

### Log pattern

The `log` detector follows each container of each observed Pod with one
`GET pods/<pod>/log?container=<c>&follow=true&timestamps=true&sinceTime=<t>` stream made by the
connector (`get` on `pods/log`). A stream for a new container instance starts at that instance's
start time; a reconnect resumes at the last record time and deduplicates by record time and content
digest. These semantics refine REQ-TRG-001/002/003/004/007 for this source:

- Options: `stream` (default `both`; `stdout`/`stderr` need the node collector's CRI log tail,
  which records the stream, because the log API's stream filter is a feature-gated parameter that
  is silently ignored where the gate is off; without a node collector they report
  `DetectorUnavailable` with the field path); `match` literal
  (substring) or regexp (Go's RE2 engine, Perl syntax, no backreferences or look-around; matching costs record bytes ×
  program size, so the compiled program is bounded by RE2's default program memory budget of 8 MiB,
  and Go's parser already rejects repeat counts above 1000); `pattern` nonempty, its length bounded
  by the compiled program and the object size; optional `jsonField`, a dotted path of object keys whose value (a string's text, a number's or boolean's literal) is matched
  instead of the record; `maxRecordBytes` positive (default 65536, at most the per-Pod buffer divided by its followed
  containers, REQ-TRG-001); `overlong` drop (default) or
  matchPrefix, which is rejected with `jsonField` (incomplete JSON is never evaluated);
  `eventWindow` in whole seconds, at least 1 s (default 30 s, no maximum). `evaluation.rearmFor` must not exceed `eventWindow`.
- Bounds: each followed stream costs an API server connection and a buffer, so a connector follows
  at most `connectorMemoryLimit × logShare / perStreamBuffer` streams in total, reported in status;
  streams beyond that budget are a reported capability gap, never a reason to make a Pod with many
  containers Unknown. Buffered log data is bounded per Pod by REQ-TRG-001.
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

Given an applied log policy (regexp `SYNTHETIC-PANIC [0-9]+`, eventWindow 30 s) on a workload
whose replicas log only non-matching lines, when one Pod writes a matching line, then exactly one
capture of that Pod runs under the policy executor; the line staying in the window
creates no further occurrence; no log text appears in status, occurrences or the capture request;
the Pod re-arms after the window passes without a match; and a Pod whose log stream fails without
a match neither fires nor re-arms.

### Resource

The `resource` detector reads the Kubernetes resource metrics API (`metrics.k8s.io`, served by
metrics-server). That API has no watch, so it is the one sampled source: the connector lists
`/apis/metrics.k8s.io/v1beta1/namespaces/<ns>/pods` once per the API's reported `window`
(metrics-server's default resolution is 15 seconds) for all resource policies of the namespace
together (`list` on `pods.metrics.k8s.io` with the policies' label selectors; no item cap, the
namespace's Pods bound it). These semantics refine REQ-TRG-002/006/007 and the resource units below for
this source:

- Options: `metric` cpuCores, cpuQuotaRatio, memoryBytes or memoryLimitRatio; `operator`
  gt/gte/lt/lte; `threshold` ≥ 0 (ratios may exceed one); `sampleInterval` (no
  maximum), the oldest sample still evaluated. On the metrics API the default and effective minimum
  are twice the API's reported `window` (30 s with metrics-server's 15 s), so two scrapes back each
  sample; a shorter value is evaluated at that minimum and status reports the effective interval.
  The node-local cgroup reader accepts the minimum of REQ-TRG-001. cpuThrottledRatio, memoryGrowthBytesPerSecond and the PSI
  metrics need the node-local cgroup reader; without it they report `DetectorUnavailable` with
  their path.
- Value: the Pod's sum over its containers of CPU usage in cores or memory working set in bytes; a
  ratio divides it by the Pod's finite effective limit (the Pod-level limit if set, otherwise the
  sum of the limits of every container and sidecar init container). A Pod without a finite limit
  refuses a ratio policy as an unsupported capability (no ratio when the limit is unlimited).
- Level: a Pod is failing while its fresh sample satisfies the condition. The occurrence instant
  is the sample second; the Pod re-arms at a fresh sample that does not satisfy it.
- Unknown (per Pod): no sample, a sample older than `sampleInterval` or older than the Pod's start
  (an earlier Pod of the same name), or a sample missing a running container. A malformed or
  unavailable (503) metrics API makes the sample Unknown. The metrics API being absent (404)
  reports `DetectorUnavailable` and leaves later samples Unknown: absence is never read as zero.

### SC-TRG-013

Given an applied resource policy (cpuQuotaRatio gt 0.5, sampleInterval 60 s) on a workload with
CPU limits whose replicas are idle, when one Pod's CPU stays at its limit, then exactly one
capture of that Pod runs under the policy executor and further samples while it stays
busy create no occurrence; while metrics-server is unavailable no occurrence is created and no Pod
re-arms; and in a cluster without the metrics API and without a node collector the policy reports
`DetectorUnavailable`.

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
