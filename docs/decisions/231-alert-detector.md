# ADR-231 — Alert trigger from the in-cluster Alertmanager API

Date: 2026-10-26. Status: accepted; implemented; qualification below.
Requirements: REQ-TRG-002/004/006/007, S-03 (TASK-04). Extends
[ADR-228](228-restart-triggered-policy-captures.md) and [ADR-230](230-s03-detectors.md).

## Problem

S-03 acceptance needs "Log/resource/probe triggers produce deduplicated occurrences". ADR-230
implemented probe and paused direct log (`pods/log` polling) and resource (metrics-server)
detectors, recommending an `alert` detector so that the operator's existing Prometheus and
log-stack alert rules (kube-prometheus `CPUThrottlingHigh`, memory-limit rules, Loki ruler, ...)
drive captures. ADR-230 left one choice to the maintainer: an inbound authenticated Alertmanager
webhook (exposure) or an Alertmanager API pull (outside endpoint per cluster). The maintainer
delegated it; this record chooses the pull.

## Decision

The regional connector reads the cluster's in-cluster Alertmanager v2 API on the existing ADR-228
15-second `observe-workload-restarts` poll. There is no new inbound hub endpoint, no receiver
credential on the hub and no episode tombstone store.

1. **Configuration.** One optional Alertmanager base URL per workload cluster, owned by the
   installation: Helm `cluster.alertmanager` → `installer-cluster --alertmanager` →
   `RegionalAPIContext.alertmanager` in the immutable regional inputs. http or https (system
   roots), optional path prefix, no credentials, query or fragment; regional executor only. A policy
   cannot name an address. Changing it uses the existing connector reinstall path, like every other
   regional input.
2. **Compile.** `kind: alert` with `receiverRef: alertmanager` (the only receiver),
   `status: firing` (`resolved` rejected: the v2 API drops resolved alerts), optional
   `matchLabels` (≤ 16 exact values; `namespace`/`pod` rejected with their path). `eventWindow` is
   rejected (the alert is a level). `evaluation.rearmFor` (required by the canonical schema
   whenever `evaluation` is present) may be at most the 15-second poll interval: the Pod re-arms at
   a poll without a matching alert and the next occurrence can follow one poll later; a longer hold
   belongs to the rule's `for` and `keep_firing_for`. `fireOnActivation: true` stays rejected.
3. **Observation.** For an alert request the region, after its Pod LIST, sends one
   `GET <base>/api/v2/alerts?active=true&silenced=false&inhibited=false&filter=namespace="<ns>"`
   (no redirect, no proxy, no credential, 5-second request bound). An alert counts for a Pod when
   its `namespace` label is the policy's namespace, its `pod` label names an observed Pod of the
   workload and every `matchLabels` value matches; state `active`/`unprocessed` counts, `suppressed`
   does not. The region returns per Pod only the number of matching alerts and the newest `startsAt`
   second (clamped to its clock), in the probe fields of the existing answer (`alert: true`).
   Labels, annotations, fingerprints, `generatorURL` and alertnames stay in the region; nothing is
   logged. The silenced/inhibited exclusion respects the operator's maintenance silences.
4. **Pod mapping.** `namespace` + `pod` labels, the convention of kube-state-metrics/cAdvisor
   based rules and of Robusta's alert-to-Pod mapping. Alerts without a `pod` label in the workload's
   namespace are ignored rather than attributed to an arbitrary or every Pod: the policy shape is
   `maxPods: 1, selection: triggeringPod`, and fanning one workload-level alert out to every replica
   would spend the whole shared workload budget on one fact. Operators who want such alerts keep
   (or add) a `pod` label in the rule. A Pod name is resolved to its current UID; a StatefulSet Pod
   recreated under the same name while the alert still fires is a new UID whose first observation
   is a disarmed baseline, so the old episode cannot fire on the new Pod.
5. **Level, dedup and re-arm.** The probe code path (`ProbeDelta`) unchanged except for a minimum
   of one: a Pod is failing while a matching alert is active; one occurrence per rising edge keyed
   (policy, Pod UID, newest `startsAt` second), and that key is the capture idempotency key.
   Episode identity (fingerprint, startsAt) of the spec therefore collapses to the per-Pod newest
   startsAt: HA copies and retries carry the same startsAt; a second alert on an already failing
   Pod is the same level; a later startsAt after re-arm is a new episode. First observation is a
   baseline (armed only without a matching alert); re-arm at the first poll with no matching alert.
6. **Unknown.** Alertmanager unreachable, non-200 or redirect, > 1 MiB or > 1024 alerts of the
   namespace (the API has no paging), malformed JSON, an unknown state or an invalid `startsAt` of
   a matching alert: the existing Unknown (the poll fails, fires nothing, re-arms nothing). A
   region without a configured Alertmanager answers `unsupported`, so activation is refused
   (`DetectorUnavailable`) instead of leaving the policy permanently Unknown. No new degraded state.
7. **Ledger.** Migration 00085 (schema 85, floor 81) widens the `detector` CHECKs to `alert` and
   requires an alert occurrence key ≥ 1000000000 like a probe second. Budgets, spend, suppression
   and the capture path are unchanged. Status reports `detector.kind: alert` and an alert
   occurrence's start as `failed_at`; the console names the detector.

## Complexity gate (AGENTS.md)

1. **Frequency/harm:** frequent. Every S-03 log and resource condition is today expressed by
   operators as an alert rule; without this detector no log or resource condition can trigger a
   capture (ADR-230 paused both). Not test-induced.
2. **Accepted risk:** no. ADR-230 recommended this route; the maintainer delegated the push/pull
   choice.
3. **Typical deployments:** yes. kube-prometheus-stack (Prometheus Operator) ships Alertmanager and
   rules carrying `namespace`/`pod`; Loki/Mimir rulers deliver to Alertmanager too.
4. **Precedent:** Robusta's `on_prometheus_alert` maps alerts to Pods by the `pod` and `namespace`
   labels and filters by alert name and namespace/pod prefixes, delivered by an Alertmanager webhook
   ([Robusta triggers](https://docs.robusta.dev/master/playbook-reference/triggers/prometheus.html),
   [alert enrichment](https://docs.robusta.dev/master/user-guide/alerts.html)). Pulling the v2 API
   is how HolmesGPT (`holmes investigate alertmanager --alertmanager-url`,
   [repository](https://github.com/robusta-dev/holmesgpt)) and the karma dashboard (polling
   `interval`, [Arch wiki](https://wiki.archlinux.org/title/Karma)) read alerts. Keptn v1 used the
   push (an Alertmanager webhook receiver). The v2 `GET /api/v2/alerts` handler drops resolved
   alerts, supports `active`/`silenced`/`inhibited`/`filter` and has no paging
   ([alertmanager api/v2/api.go](https://github.com/prometheus/alertmanager/blob/main/api/v2/api.go)).
5. **Privileges/exposure:** no Kubernetes privilege, credential or hub endpoint. One outbound
   in-cluster HTTP(S) connection from the regional connector to an installation-chosen address.
   The connector reads alert labels/annotations of one namespace (operator metadata that may
   name application facts); only counts and a timestamp leave it. Nothing on workers or collectors.
6. **New states:** 0. Unreachable/oversized/malformed are the existing Unknown; an unconfigured
   region is the existing activation refusal (new code `DetectorUnavailable`, same refusal path).
7. **Own tuning configuration:** no. The single URL selects the source; the body/alert bounds are
   fixed.
8. **Outside dependencies:** yes: an Alertmanager ≥ 0.16 (v2 API, stable since 2019) and rules
   that label `namespace`/`pod`. Missing labels are documented, not guessed.
9. **Aggregate cost:** alert policies only: one GET per policy per 15 s, served from Alertmanager
   memory, namespace-filtered; at the 16-policy cluster cap ≤ 1.1 requests/s per cluster and ≤ 1 MiB
   per answer (typically a few KiB). Hub: unchanged answer size (the probe fields), no new rows or
   tables; region memory bounded by the 1 MiB read.
10. **Upgrade/rollback/disable:** additive migration 00085 (floor stays 81; an older binary treats
    an `alert` watermark as another detector's baseline and rejects alert policies at compile);
    the regional field is optional (`omitempty`); disabling is deactivating the policy (ADR-229)
    or omitting the URL.
11. **Smaller alternatives:** documenting "use exit/probe" leaves S-03's log/resource requirement
    unmet. The webhook would add an inbound authenticated route, a receiver credential and durable
    episode tombstones (≥ 2 new states). Polling `pods/log` or metrics-server was rejected by ADR-230.

Benefit is strong (one mechanism replaces two paused detectors, using rules operators already
run) and cost is small (no privilege, no new state, one bounded GET per alert policy): proceed.

## Agent-authored restrictions revised (recorded as such)

The spec's alert section assumed a webhook receiver (sender authentication, body limit, bounded
durable tombstones). With the pull these become: an installation-owned address instead of sender
authentication, the 1 MiB/1024-alert bound instead of the body limit, and the occurrence key plus
level instead of tombstones. A clear poll followed one poll later by a firing poll is not a
proven continuous false interval; `rearmFor` is therefore capped at the poll interval (decision 2)
rather than claimed for longer holds.

## Qualification

- Unit: compiler field paths (receiverRef, status, namespace/pod/invalid label names,
  eventWindow, rearmFor above 15 s) and exit-digest stability; `TriggerDelta` for alerts (firing baseline,
  re-arm on resolution, one occurrence per episode, duplicate polls, second alert of the same
  period); policy/request/observation validity; regional alert read against a fake Alertmanager
  HTTP server (query parameters, no Authorization header, two alerts on one Pod, label mismatch,
  foreign namespace, foreign Pod, Pod of another ReplicaSet, no pod label, suppressed state,
  future startsAt, unconfigured → unsupported, unreachable, 503, redirect, > 1 MiB, > 1024 alerts,
  malformed, non-array, unknown state; no label/annotation/fingerprint text in the answer);
  Alertmanager URL validation; installer plan (executor only, no credentials); chart rendering;
  real-TLS regional query (alert labels across the exchange, 128 Pods in one frame, unsupported
  error); status output against the schema; console vitest.
- Custody (real PostgreSQL): new `alert-trigger-episode-rearm-and-detector-switch`.
- Installed: not extended. The fast fixture has no Alertmanager image, the regional install would
  need the new input, and the policy focus's shared workload burst is already spent by its probe
  occurrence and first exit capture (ADR-230), so an alert phase on the same workload would change
  the restart phases' expectations. This is an explicit gap: no installed run reads a real
  Alertmanager. Results in [implementation progress](../implementation-progress.md).
