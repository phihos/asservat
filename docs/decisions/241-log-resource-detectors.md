# ADR-241 — Log and resource triggers from the Kubernetes log and metrics APIs

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-TRG-001/002/003/004/006/007, S-03 (TASK-04). Extends
[ADR-228](228-restart-triggered-policy-captures.md), [ADR-230](230-s03-detectors.md) and
[ADR-231](231-alert-detector.md).

## Problem

ADR-230 paused the direct log (`pods/log` polling) and resource (metrics-server) detectors behind
the complexity gate and ADR-231 substituted the `alert` detector. Maintainer decision 2026-10-26:
every specified feature ships in the first release, so the [trigger catalogue's](../../specs/triggers.md)
log-pattern and CPU/memory detectors must be implemented. The gate still governs *how*: the
smallest mechanism that meets the specification. The decision is a maintainer requirement, not an
agent-added restriction; it reverses ADR-230's pause (items 1–2 below) without reopening the
probe or alert decisions.

The specification names node-local sources (CRI log tail, cgroup v2 files) and calls the Kubernetes
log API a degraded fallback. A node-local reader needs a host agent with hostPath access, which
this release does not run (no privileged host collectors). Both detectors therefore use the
Kubernetes APIs on the existing ADR-228 regional poll, and the specified semantics they cannot
meet are rejected with a field path (capability gaps), not approximated.

## Decision

Both detectors are levels on the probe/alert path (`ProbeDelta`): one occurrence per rising edge,
keyed (policy, Pod UID, second), a first observation as a baseline armed only when false,
re-arm at a known-false poll, and the shared workload budget, policy budget, spend ceiling and
suppression of ADR-228. One addition to that path: a Pod may be reported **Unknown** for one poll
(a failed or truncated read without a match, a missing, stale or partial sample). An Unknown Pod
keeps its watermark: it neither fires, re-arms nor becomes a baseline (REQ-TRG-002: Unknown never
constitutes recovery).

### Log (`kind: log`)

1. **Compile.** `stream: both` (stdout/stderr filters are rejected: the log API's `stream`
   parameter is behind the `PodLogsQuerySplitStreams` feature gate and is silently ignored where the
   gate is off), `pattern` 1–1024 bytes of UTF-8, `match` literal (substring) or regexp (Go's RE2
   engine, Perl syntax, no backreferences or look-around, compiled program at most 4096
   instructions), optional `jsonField` (a dotted path of at most 8 object keys, 128 bytes),
   `maxRecordBytes` 1–65536 (default 65536), `overlong` drop (default) or matchPrefix (rejected
   with `jsonField`: incomplete JSON is never evaluated), `eventWindow` 30 s–5 min (default 30 s,
   at least two polls). `evaluation.rearmFor` must not exceed `eventWindow`.
2. **Observation.** After its Pod LIST the region reads, for every container of every observed Pod
   that can have written into the window (running, or terminated after the window started; init
   containers included, never-started containers skipped), one
   `GET pods/<pod>/log?container=<c>&sinceSeconds=<eventWindow>&timestamps=true&limitBytes=<n>`,
   eight at a time. `n` = min(1 MiB ÷ the Pod's read containers, 4 MiB ÷ all read containers)
   (REQ-TRG-001's 1 MiB per Pod, fairly split). More than 32 containers fail the poll (Unknown,
   `ErrLimit`); a denied read fails it (`ErrDenied`). Each line is `<RFC 3339 timestamp> <record>`;
   records at or before the window start are ignored, a record time later than the region clock
   counts as now (node clock skew cannot raise the watermark). The matcher runs on the record, or on
   the JSON value at `jsonField` (a string's text, a number's or boolean's literal). A record longer
   than `maxRecordBytes` is dropped (or its prefix matched with matchPrefix) and flags the Pod
   `overlong`. The region returns per Pod only the number of matching records in the window, the
   newest match second and the flag; no record text is returned, logged or stored.
3. **Unknown.** A read that failed (any status but 403), a body cut at `limitBytes` (the read
   starts at the window start, so the newest records are the ones missing) or a malformed
   timestamp, without a match in another container of the Pod, makes the Pod Unknown. A match is
   proof of the level even if another container's read failed.
4. **Coverage limits** (REQ-TRG-003 fallback, reported here and in the specification): only the
   current instance of a container is read, so lines written by an instance that restarted inside
   the window are not seen (the exit detector covers the restart itself); rotated log segments
   are not read (kubelet `containerLogMaxSize`); multi-line assembly beyond kubelet's CRI partial
   records is not performed.
5. **Overlong.** Every Pod observation with the flag adds one to the content-free suppression
   reason `overlong` (migration 00094): a saturating count of polls, not of records, since the
   window is re-read on every poll.

### Resource (`kind: resource`)

1. **Compile.** `metric` cpuCores, cpuQuotaRatio, memoryBytes or memoryLimitRatio; `operator`
   gt/gte/lt/lte; `threshold` 0–1e18 (ratios may exceed one and are never clamped);
   `sampleInterval` 30 s–5 min: the oldest metrics sample still evaluated (older is Unknown).
   cpuThrottledRatio, memoryGrowthBytesPerSecond, memoryPSI, cpuPSI and ioPSI are rejected with
   their path: they need cgroup files the metrics API does not expose. `evaluation.rearmFor` is at
   most one 15 s poll, as for alerts.
2. **Observation.** One `GET /apis/metrics.k8s.io/v1beta1/namespaces/<ns>/pods?labelSelector=<the
   workload's selector>` (at most 1024 items, 2 MiB). Per observed Pod: the sum over its
   containers of CPU usage (cores) or memory working set (bytes); a ratio divides by the Pod's
   finite effective limit (the Pod-level limit if set, else the sum of every container's and
   sidecar init container's limit). The region returns per Pod only a level (one when the
   condition holds) and the sample second (clamped to its clock). Labels never leave it.
3. **Unknown.** No sample for the Pod, a sample older than `sampleInterval` or than the Pod's
   start (an earlier Pod of the same StatefulSet name), or a sample missing a running container:
   the Pod is Unknown. A malformed answer, 503 or a timeout makes the poll Unknown. The metrics API
   being absent (404) is `unsupported` (activation refuses with `DetectorUnavailable`, later polls
   are Unknown), never zero; a ratio on a Pod without a finite limit is `unsupported` too ("no
   ratio when the limit is unlimited").
4. **Semantics revised** (REQ-TRG-002/007 "Resource units", recorded in the specification):
   cpuCores is the metrics API's CPU usage rate over its scrape window (kubelet's rate of the
   cumulative `usage_usec`), not a delta the region computes; memoryBytes is the working set
   (`memory.current` minus inactive file pages), which is what kubelet eviction and OOM-adjacent
   alert rules use, and is at most `memory.current`.

### Shared

- **RBAC.** The regional connector ClusterRole gains `get` on `pods/log` and `list` on
  `pods.metrics.k8s.io`; the chart's cluster-installer role gains the same (the escalation check
  requires the installer to hold what it grants). Nothing is added on the hub, workers or
  collectors.
- **Ledger.** Migration 00094 (schema 94, floor 81) widens the watermark/occurrence detector CHECKs
  to `log` and `resource`, requires their occurrence keys to be seconds (≥ 1000000000) and adds
  the `overlong` suppression reason. No new table, row kind or column.
- **Status/console.** `get_policy_status` reports `detector.kind` log (match mode, whether a JSON
  field, window) or resource (metric, operator, threshold, sample interval) and each occurrence's
  second as `failed_at`; the pattern itself is not repeated. The console names both.

## Complexity gate (AGENTS.md)

Answers: log / resource.

1. **Frequency/harm:** a log pattern (panic, fatal error, a dependency refusing connections) and
   CPU/memory saturation are the most common first symptoms of an incident and precede restarts;
   without a log stack or Prometheus no trigger sees them. Required by the maintainer's
   2026-10-26 decision; not test-induced. / Same.
2. **Accepted risk:** ADR-230 had paused both; the maintainer reversed the pause. No other risk
   is reopened. / Same.
3. **Typical deployments:** yes: every workload writes container logs, and no log pipeline is
   needed. / Yes where metrics-server runs (managed GKE/AKS clusters ship it, EKS and kubeadm
   install it as an add-on); without it activation is refused with a named reason.
4. **Precedent:** `kubectl logs --since --limit-bytes --timestamps` and Robusta's log enrichment
   read `pods/log`; log agents (Fluent Bit, Promtail) tail node files, the specification's
   preferred source. / HPA, `kubectl top` and KEDA's cpu/memory scaler read `metrics.k8s.io`;
   kube-prometheus rules compare working set with limits.
5. **Privileges/exposure:** `get pods/log` cluster-wide on the regional connector: it can read any
   container's output (user data, possibly secrets or personal data). It reads only the Pods of
   active log policies' workloads, keeps text in process memory for one poll and returns counts and
   one second per Pod. / `list pods.metrics.k8s.io` (numbers only). No credential, endpoint or hub
   exposure for either.
6. **New states:** one shared representation, the per-Pod Unknown, which the existing poll-level
   Unknown already defined (it now applies to one Pod instead of the whole poll); truncation,
   failed reads, staleness and partial samples all map to it. `overlong` is a suppression count,
   not a state. Absent metrics API reuses the existing `unsupported` refusal. Total: 1.
7. **Own tuning configuration:** no. `eventWindow`, `maxRecordBytes`, `overlong` and
   `sampleInterval` are specified policy options; the 32-container, 4 MiB, 8-reader and 1024-item
   bounds are fixed.
8. **Outside dependencies:** kubelet's log endpoint through the API server, its rotation and node
   clocks. / metrics-server (or another `metrics.k8s.io` provider), its 15 s default resolution
   and working-set semantics.
9. **Aggregate cost** (per active policy and 15 s poll, on top of the existing Pod LIST): log ≤ 32
   GETs (typically replicas × containers, e.g. 3) and ≤ 4 MiB (typically the window's lines, KiB);
   at the 16-policy cluster cap ≤ 512 GETs per cycle, which the connector's fixed 20 requests/s
   client limiter spreads over ≥ 26 s (the sequential cycle then stretches beyond 15 s; nothing
   overlaps or queues), i.e. ≤ 20 requests/s and ≤ 64 MiB per cycle per cluster through the API
   server to kubelets, worst case. Region memory ≤ 8 × (`maxRecordBytes` + 64) bytes of line
   buffers. / One LIST, served from metrics-server memory, ≤ 2 MiB; ≤ 1.1 requests/s at the cap.
   Both: answer frame +≤ 31 bytes per Pod (128 Pods with 63-character names fit one 32 KiB frame);
   SQL unchanged (one watermark per Pod, one row per occurrence, one per suppression reason).
10. **Upgrade/rollback/disable:** additive migration 00094 (floor stays 81: an older binary treats
    the new watermarks as another detector's baseline and rejects these policies at compile);
    the request and answer fields are optional (`omitempty`); a connector installed before this
    release lacks the RBAC and answers denied (Unknown) until reinstalled; disabling is
    deactivating the policy (ADR-229).
11. **Smaller alternatives:** the `alert` detector (ADR-231) stays the recommended route where a
    log stack or Prometheus exists and is unchanged. Documenting the gap no longer satisfies the
    requirement; a node-local CRI/cgroup reader is the specified source but needs a host agent.
    The Kubernetes API polls are the smallest mechanisms that meet the requirement; the cgroup-only
    metrics and stream filters remain explicit capability gaps.

Benefit is now a maintainer requirement and the cost is bounded per policy and per cluster with
one new privilege each and no new state machine: proceed.

## Agent-authored restrictions revised (recorded as such)

- ADR-230's pause of both detectors (an agent recommendation) is reversed by the maintainer's
  decision.
- ADR-230 estimated the log cost as 136 requests/s per cluster and 8 MiB per poll per policy; the
  implementation bounds a log policy at 32 containers and 4 MiB per poll and inherits the
  connector's 20 requests/s limiter, so the worst case is lower and is stated above.

## Qualification

- Unit: compiler field paths (stream filters, match modes, non-RE2 and oversized patterns,
  `maxRecordBytes`, overlong with `jsonField`, `jsonField` shape, `eventWindow`/`sampleInterval`
  bounds, cgroup-only metrics, operator, threshold, `rearmFor`, `fireOnActivation`) and unchanged
  exit-policy JSON; `ProbeDelta` with Unknown (no baseline, no re-arm, no fire, watermark kept);
  observation and request validity; regional log reads against a fake API server (query
  parameters and byte split, never-run and long-finished containers skipped, the window start,
  future record times, JSON field, matchPrefix, overlong flag, truncated/failed/malformed →
  Unknown, denied, 33 containers, non-RE2 pattern, no record text in the answer); regional
  metrics reads (ratio with container and Pod-level limits, cores, memory, absent → unsupported,
  503 and malformed → Unknown poll, denied, no finite limit → unsupported, stale, earlier-Pod and
  partial samples → Unknown, future sample time); connector ClusterRole; real-TLS regional query
  (maximal pattern and 128 Pods with flags in one frame); status output against the schema;
  console vitest.
- Custody (real PostgreSQL): new `log-resource-trigger-unknown-overlong-and-detector-switch`
  (Unknown leaves an exit watermark untouched, armed log baseline, rising edge with an `overlong`
  suppression, Unknown and continuing matches neither re-arm nor fire, the occurrence-key CHECK,
  log → resource re-baseline and the second token of the shared burst).
- Installed (`ASSERVAT_JOURNEY_FOCUS=logresource`, CI suite `continuation-logresource`, metrics-server
  v0.8.0 pinned by digest, synthetic signal workload): PASS, go test 573 s, harness wall 11 m 36 s;
  log capture 37 s and resource capture 1 m 51 s after start. Details in
  [implementation progress](../implementation-progress.md).
