# ADR-230 — Probe-failure trigger; log and resource detectors paused

Date: 2026-10-26. Status: accepted for the probe detector (implemented; qualification below);
log and resource detectors await a maintainer decision. The recommended alert detector is
implemented by [ADR-231](231-alert-detector.md) as an Alertmanager API pull.
Requirements: REQ-TRG-001/002/004/006/007, S-03 (TASK-04). Extends
[ADR-228](228-restart-triggered-policy-captures.md) and [ADR-229](229-policy-deactivation-and-console.md).

## Problem

S-03 acceptance needs "Log/resource/probe triggers produce deduplicated occurrences" (with the
storm, coalescing and fair-capacity rules ADR-228 established for exit triggers). ADR-228 implements
only the exit detector. Every other detector of [triggers](../../specs/triggers.md) is rejected at
activation with its field path.

The only recipe is still `builtin-pod-status-v1` (one whole-pod Kubernetes status projection,
4096 bytes). Intrusive actions (dumps, profiles, packet/syscall recorders) and their policy grants
are S-08. Every benefit below is therefore measured against what a pod-status capture shows today.

## Mechanism per detector

The reusable pattern is ADR-228's: hub-api polls each active policy every 15 s with one regional
`observe-workload-restarts` query (one bounded Kubernetes read, answer ≤ one 32 KiB frame), and
migration 00082's ledger keeps one watermark per (policy, Pod), unique occurrences, the shared
workload budget, the policy budget, the execution ceiling and saturating suppression counts. The
cheapest mechanism that fits this pattern was chosen per detector:

| Detector | Spec source | Cheapest poll-pattern mechanism | Extra Kubernetes reads per poll |
| --- | --- | --- | --- |
| probe | kubelet probe metrics; Events/status fallback | one namespace core/v1 Event LIST, field selector `involvedObject.kind=Pod,reason=Unhealthy`, in the existing query | 1 (only for probe policies) |
| resource | node-local cgroup v2 (`cpu.stat`, `memory.*`, PSI) | `metrics.k8s.io` PodMetrics LIST (metrics-server) | 1 |
| log | node-local CRI tail; `pods/log` degraded fallback | one `pods/log` GET per container per Pod (`sinceSeconds`, `limitBytes`, `timestamps`) | Pods × containers |
| alert | authenticated Alertmanager webhook | none (push; an inbound route) or an Alertmanager API pull | not a poll of the workload |
| kubernetesCondition | Kubernetes watches | Evicted from the existing Pod LIST; RolloutStalled from the existing Deployment GET; NodePressure needs Node reads; VolumeWarning needs Events | 0–1 |
| schedule | controller cron | hub clock only | 0 |
| crashArtifact, file, network | core agent, container file watcher, Gadget/Hubble | none: they need a node-local or in-container agent | — |

## Complexity gate (AGENTS.md), per detector

Answers: 1 frequency/harm · 2 accepted risk · 3 typical deployments · 4 precedent · 5 privileges
added · 6 failure/degraded states added · 7 own configuration · 8 outside dependencies ·
9 aggregate cost · 10 upgrade/rollback/disable · 11 smaller alternative.

### probe (Events) — passes; implemented

1. Frequent in typical operation: readiness/liveness failures precede most restarts and are the
   main symptom without a restart (readiness). Harm: endpoints drop out, then restarts. A
   readiness failure is not visible to the exit detector; a liveness kill is, but only after the
   restart.
2. No.
3. Yes: almost every Deployment has a readiness probe.
4. Robusta's API-server trigger `on_kubernetes_warning_event_create` fires on Warning Events
   (filters on reason/message), with rate limits, without Prometheus
   ([Robusta triggers](https://docs.robusta.dev/master/playbook-reference/triggers/kubernetes.html)).
   kube-state-metrics exposes no probe failures; Prometheus alerting on kubelet
   `prober_probe_total` needs a kubelet scrape. Kubernetes aggregates repeated identical Events
   into one object with `count`/`lastTimestamp` (`kubectl describe` "x5 over 2m").
5. The regional connector's ClusterRole gains `list` on core `events` (cluster-wide, as its existing
   Pod `get`/`list`). Event messages can contain exec-probe output; the region reads only the
   reason, the probe-type prefix of the message, the involved Pod UID, counts and timestamps, and
   never returns, logs or stores message text. Nothing is added on workers, collectors or the hub.
   kubelet probe metrics (`source: kubeletMetrics`) are rejected: they need `nodes/metrics` and
   network access to every kubelet.
6. 0 new states: a truncated, denied or unavailable Event LIST is the existing Unknown (fires
   nothing). Event loss/aggregation by Kubernetes is documented best-effort (REQ-TRG-006).
7. No.
8. kubelet's Event reason `Unhealthy` and message prefix `<Liveness|Readiness|Startup> probe
   failed`/`errored` (stable kubelet format, not an API contract), Event TTL (default 1 h).
9. Probe policies only: one Event LIST per policy per 15 s (pages of 512, at most 4; field-selected, namespace
   scoped). At the ADR-228 cap of 16 active policies per cluster: ≤ about 1.1 LIST/s per cluster (4.3 in a namespace past 512 Unhealthy Events) on
   top of the existing Pod LIST; answer grows by ≤ about 40 bytes per Pod (128 Pods stay within one
   frame). SQL: one boolean column per watermark row, no new rows or tables.
10. Additive migration 00084 (floor stays 81); disabling is deactivating the policy (ADR-229).
11. Documenting "use the exit detector" misses readiness failures and the pre-restart state.

### resource (metrics API) — paused for a maintainer decision

1. Saturation is frequent, but its most harmful outcome (OOM kill) is already caught by the exit
   detector (`OOMKilled`). A pod-status capture does not contain CPU or memory usage, so a capture
   at 90 % memory shows nothing the trigger did not already know. Benefit today: weak.
2. No.
3. Yes as a condition; not as useful evidence with the current recipe.
4. kube-prometheus alert rules (`container_memory_working_set_bytes` against limits,
   `CPUThrottlingHigh`) via Prometheus/Alertmanager; Robusta acts on resource conditions through
   Prometheus alerts. HPA/KEDA read the metrics API for scaling, not for deduplicated triggers.
5. `get`/`list` on `pods.metrics.k8s.io` cluster-wide on the regional connector (numbers only).
6. +1: metrics API absent or stale → Unknown (a capability gap that has to be reported at
   activation and in status).
7. No.
8. Yes: metrics-server (not installed on kind or by default on EKS; its scrape resolution and
   averaging window belong to the operator). It cannot provide the specified metrics: no
   `cpuThrottledRatio`, PSI, `memoryGrowthBytesPerSecond` or `memory.current` (it reports working
   set), so the spec's cgroup semantics (REQ-TRG-002/007, "Resource units") would have to be
   redefined.
9. Cheap: one PodMetrics LIST per policy per poll (served from metrics-server memory).
10. Additive, but the installed qualification needs metrics-server in the kind fixture (image and
    about 60 s warm-up).
11. The `alert` detector covers resource conditions from existing Prometheus rules; OOM kills are
    covered now.

Weak benefit (no resource evidence in the only recipe; OOM already covered) with questionable cost
(an outside component, redefined metric semantics, fixture dependency): not implemented.

### log (`pods/log` polling) — paused for a maintainer decision

1. Log patterns are a common alert source, but a pod-status capture contains no log line, so the
   capture adds only Pod state to a fact the user's log stack already has.
2. No.
3. Typical deployments already run a log pipeline with alerting.
4. Robusta has no log-pattern trigger (it attaches logs as enrichment); log alerting is done by
   the log stack (Loki ruler, Elasticsearch watchers) and delivered to Alertmanager. The spec
   itself selects a node-local CRI tail and calls `pods/log` a degraded fallback with a reported
   load budget (REQ-TRG-003).
5. `get` on `pods/log` cluster-wide on the regional connector: continuous reads of application
   output (user data, possibly secrets or personal data) whether or not anything is captured.
6. ≥ 3: `limitBytes` truncation, rotation between polls, container restart (previous instance),
   overlap/duplicate records at the `sinceSeconds` boundary.
7. It needs its own load budget (bytes per poll).
8. kubelet log rotation (`containerLogMaxSize`), API-server proxying to every kubelet.
9. One GET per container per Pod per 15 s: 128 Pods × 1 container × 16 policies ≈ 136 requests/s
   per cluster through the API server to kubelets, up to `limitBytes` each (64 KiB → about
   8 MiB per poll per policy).
10. Additive.
11. The `alert` detector (log-stack alert rules) or a future node-local reader (spec source).

Weak benefit with questionable cost (sensitive privilege, API load proportional to Pods ×
containers × policies, several gap states): not implemented.

### alert (Alertmanager) — benefit passes; not this increment

Strong benefit: it lets existing Prometheus and log-stack alert rules trigger captures and is the
cheaper route for both paused detectors. It does not fit the poll pattern: the spec's webhook adds
an inbound authenticated hub route, a receiver credential and episode deduplication with bounded
tombstones (item 5 exposure, items 6–7); pulling the Alertmanager API instead adds an outside
endpoint and its credential per cluster (items 5, 8). The choice between push exposure and pull
dependency is a maintainer decision; it is the recommended next increment.

### Others — deferred by item 11

The spec orders "log/resource/probe/exit/external/manual, then crash artifact, followed by optional
detectors". S-03 does not need them; doing nothing satisfies the actual requirement.

- **kubernetesCondition.** Evicted and RolloutStalled would cost no new privilege, but S-03 does
  not require them, a stalled rollout is caused by Pods the probe/exit detectors already observe,
  and RolloutStalled needs a new Pod-selection rule. NodePressure needs Node reads and node-wide
  scope; VolumeWarning needs Event message text the region does not keep.
- **schedule.** Periodic pod-status baselines duplicate kube-state-metrics history; a correct cron
  with IANA zones, DST and jitter rules is a dependency or a parser of its own.
- **crashArtifact, file, network.** Need node-local or in-container agents (S-08 and later).

## Decision (probe detector)

1. **Compile.** A DebugPolicy may carry exactly one detector, `exit` (ADR-228) or `probe`.
   `probe` options: `probeType` Liveness, Readiness or Startup; `minimumFailures` 1–1000;
   `window` 30 s–5 min (shorter than two polls could miss a failure between polls); `source`
   `auto` or `events` (`kubeletMetrics` is rejected with its field path). `evaluation.rearmFor`,
   when present, must not exceed `window`; `fireOnActivation: true` is rejected as for exit.
2. **Observation.** `observe-workload-restarts` takes an optional probe type and window. With them,
   the region adds one Event LIST of the namespace (`involvedObject.kind=Pod,reason=Unhealthy`,
   pages of 512, at most 4 pages since the selector also matches neighbouring workloads; more,
   truncated or malformed → Unknown) to its Pod LIST and reports for each owned Pod the
   newest matching failure time (`lastTimestamp`, `series.lastObservedTime` or `eventTime`, unix
   seconds) and a proven lower bound of failures within the window: an Event series that started
   inside the window counts its `count` (or `series.count`), one that started before counts one.
   Message text never leaves the region. Kubelet aggregates identical failures into one Event
   whose `firstTimestamp` stays fixed, so a series that began before the window counts one:
   `minimumFailures` above one only fires for failures that began inside the window. Per-poll
   count deltas would lift this at the cost of per-Pod count state; `minimumFailures: 1` is the
   reliable setting. An Event time later than the observation (node clock skew) counts as the
   observation time, so it cannot raise the watermark above later real failures.
3. **Level with re-arm.** The detector is a level: a Pod is failing while at least
   `minimumFailures` failures fall in the window. One occurrence fires on a rising edge only, keyed
   (policy, Pod UID, newest failure second). The first observation of a Pod is its baseline: armed
   only if its window is empty, so a probe already failing at activation waits for a proven
   recovery. After an occurrence (admitted or suppressed) the Pod re-arms at the first poll whose
   window is empty, which proves `window` (≥ `rearmFor`) seconds without a failure; Unknown polls
   never re-arm. Watermark: the newest failure second (only rises) plus the armed flag.
4. **Ledger.** Unchanged budgets, spend, suppression reasons and capture path. Migration 00084 adds
   `detector` to watermarks and occurrences (default `exit`) and `armed` to watermarks; a watermark
   of another detector is treated as unknown (baseline) and replaced, so changing a policy's
   detector never compares a restart count with a timestamp.
5. **Status/console.** `get_policy_status` reports the current DebugPolicy's detector (kind and its
   options) and each occurrence's detector with its restart count or failure time; the console
   shows both.

## Agent-authored restrictions revised (recorded as such)

None beyond ADR-228's. The probe semantics deliberately differ from the spec's sliding-window count
where Events cannot prove it (decision 3; see [triggers](../../specs/triggers.md)).

## Recommendation to the maintainer (paused detectors)

- **Observed problem.** S-03 names log and resource triggers; neither exists. No user report or
  incident in this repository needs them yet; the only recipe (pod status) shows neither log lines
  nor resource usage, and OOM kills are already captured by the exit detector.
- **Cumulative cost if built on the poll pattern.** Log: cluster-wide `pods/log` read of all
  application output on the regional connector, about 136 API-server-proxied kubelet requests per
  second per cluster at the 16-policy cap, three or more gap states and its own byte budget.
  Resource: a hard dependency on metrics-server, a new `pods.metrics.k8s.io` read, a capability-gap
  state, and redefinition of the specified cgroup metrics to what the metrics API offers.
- **Cheaper alternatives.** (a) The `alert` detector: operators keep log/resource rules in their
  existing Prometheus/Loki stack and Asservat maps an authenticated alert to the workload — one
  mechanism instead of two, no workload data read by Asservat. (b) Documenting that OOM kills
  (exit) and probe failures are the supported automatic triggers until intrusive recipes exist.
  (c) Doing nothing until S-08 adds recipes (heap/profile dumps) whose evidence makes a resource
  trigger worthwhile; at that point a metrics-API resource detector (cpuCores, memory working set,
  limit ratios only) is a small extension of this query.
- **Recommendation.** Accept (b) now and schedule (a) as the next S-03 increment, choosing between
  an inbound Alertmanager webhook (exposure) and an Alertmanager API pull (outside endpoint per
  cluster). Revisit a metrics-API resource detector with S-08; do not build `pods/log` polling.

## Qualification

- Unit: compiler field paths (probe options, window bounds, `kubeletMetrics`, `rearmFor`, paused
  `log`/`resource`, other kinds); `ProbeDelta` (failing baseline disarmed, re-arm on an empty
  window, rising edge once, replay, stale re-arm never refires the same second, healthy baseline);
  exit watermarks through `TriggerDelta`; policy/observation validity (probe data only on probe
  observations, failure seconds above the restart-count range); regional Event LIST (field
  selector and limit, lower bound per series, other probe types/foreign Pods ignored,
  `events.k8s.io` series fields, continued/denied/malformed LIST, no Event text in the answer);
  connector ClusterRole; real-TLS query (128 Pods with 63-character names and probe data fit one
  frame); status operation output against the schema for both occurrence kinds; console vitest.
- Custody (real PostgreSQL, compiled hub-runtime grants): new
  `probe-trigger-rising-edge-rearm-detector-switch-and-shared-budget` (exit → probe re-baseline,
  disarmed failing baseline, re-arm, one occurrence per edge under four concurrent polls, shared
  workload budget with spend, CHECK on probe keys, probe → exit re-baseline) and the schema 84
  upgrade test: PASS. `--initial-installation`: 85 PASS.
- Installed (`ASSERVAT_JOURNEY_FOCUS=policy`, new probe phase before the restart phases): three
  runs PASS (go test 753 s, 752 s, 692 s). In the final run the probe policy was activated 6 s
  after the scenario start and its capture of the surge Pod (readiness probe failing after 30 s)
  linked 57 s after start, with one occurrence and the Pod disarmed while it kept failing; the
  restart phases then passed with a 60-second storm (was 90 s), because the probe occurrence and
  the first exit capture already hold the shared workload burst. Details in
  [implementation progress](../implementation-progress.md).
