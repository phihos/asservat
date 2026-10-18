# ADR-200 — On-demand capacity refresh

Date: 2026-10-17. Status: accepted; implementation in progress.
Requirements: REQ-CAP-001/002/003, REQ-FED-001, S-02; TASK-03.
Follows [ADR-197](197-regional-capacity.md) (regional capacity) and
[ADR-190](190-capacity-readiness-and-promoted-owner.md) (hub capacity).

## Context

Capture preview, capture admission and download preparation need the target
workload's `context_storage_binding` to have been refreshed within the last
five seconds (`capacity_managed_admission_until`). The five-second bound is an
authority invariant: the physical mapping needs its own current workload and
namespace observation, and a source heartbeat cannot stand in for it.

Only the hub-worker's capacity reconciler refreshes bindings, and only while
its discovery cursor walks every Deployment, StatefulSet and Pod in every
namespace of every cluster, one step at a time. On the hub cluster a step is
fast. A regional step is one v2 exchange (about 2.2 s) plus a 2 s pace, so one
pass takes minutes. A regional binding is fresh for a few seconds every few
minutes, and ADR-197 continuation runs 17–21 passed only when the test's poll
landed in that window (five of twelve). A real capture request would almost
always be refused.

## Options

1. **Continuous refresh of every enrolled workload.** A lane keeps all
   enrolled workloads (at most sixteen per root) fresh. Simple, but each
   regional workload costs an exchange about every 2.5 s for as long as it is
   enrolled, and a serial lane cannot keep more than one or two regional
   workloads continuously fresh.
2. **Refresh on demand (chosen).** The admission path records a short-lived
   refresh demand for the exact enrolled workload. The hub-worker refreshes
   demanded workloads first, back to back, while the demand lasts. Admission
   waits for a fresh binding within its original deadline. Idle workloads cost
   nothing; cost follows open previews, requests and downloads.
3. **Relax the five-second bound.** Rejected: it would weaken the authority
   invariant.

## Decision

- **Demand record.** Migration 00066 adds `capacity_refresh_demand`, keyed by
  root, cluster, namespace UID and workload UID, carrying the namespace name
  and the workload kind and name the worker needs to observe it, with a
  `not_after` at most sixty seconds after the request. `demand_capacity_refresh`
  (SECURITY DEFINER) records or extends a demand only for an enrolled, ready
  `capacity_workload`; otherwise it does nothing. A root therefore holds at
  most sixteen demands.
- **A demand confers no authority.** It names a workload; the worker still
  performs the full guarded observation, source, recovery and permission checks,
  and every SQL fence. Wrong names fail the worker's exact UID checks.
- **Who may demand.** Only the `capture-preview` role gets EXECUTE, because
  preview and request share the investigation facts step. The SELECT-only
  `storage-read` role stays read-only.
- **Worker demand lane.** The capacity reconciler gains a lane that reads active
  demands (`read_capacity_refresh_demands`, capacity role) and reconciles one
  demanded workload per step, round robin, with no pace, through the same path
  as discovery: the regional guarded read first (ADR-197), then the current
  source, then reconciliation, which refreshes a ready workload. It runs beside
  discovery, which still enrolls new workloads.
- **Admission waits, bounded.** When the storage read finds no fresh binding,
  the investigation records a demand and rereads every 250 ms until the
  binding is fresh or its original deadline passes. No deadline is extended
  and no check is skipped; a timeout reports the existing retryable outcome.
- **Downloads** re-arm the demand (migration 00067): demand rows keep their
  names after they expire, and download preparation, which knows only its
  download allocation, calls `demand_capacity_refresh_for_download`
  (`download-session` role) when the session reservation is refused as
  unavailable, then retries the idempotent reservation every 250 ms within its
  original deadline. A workload without an earlier capture demand has no names
  to re-arm and still relies on discovery.

## Consequences

- A regional capture preview may take a few seconds longer the first time a
  workload is viewed; later steps find the binding fresh while the demand lasts.
- Demands are durable but short-lived rows; expired rows are removed when new
  demands are recorded.
- The native continuation test checks that a recorded demand makes the
  regional binding fresh, rather than polling for a discovery window.

## Progress

- **Implementation** (unit tests pass): migration 00066 with the demand table
  and two functions, schema 66, the role grants (`capture-preview`: demand;
  `capacity`: read), the Postgres adapter, the reconciler's demand lane with
  `capacity demand refresh` logging, and the investigation's bounded wait,
  which wants a binding with at least one second of freshness left so the
  remaining facts and the final storage read fit inside one refresh. The SQL
  stage `refresh-demand-names-only-ready-workloads` and the native
  continuation's three consecutive fresh reads after a demand are pending
  qualification. Downloads still use discovery refreshes.
- [CI continuation runs 22a–22c](../../test/results/adr200-continuation-ci-22a/native-continuation-1/context-storage-environment.json)
  (39068539505, 39068545264, 39068550936) all failed. In 22a and 22c the
  demand lane refreshed the regional binding (`ok` after 2.6–3.6 s), but other
  attempts stopped at `guarded-read`, `source`, `enroll/read` or
  `refresh-fresh` (the read's window ran out during the SQL steps), and while
  the lane held the regional standbys, discovery's claims failed at `locate`.
  22b never enrolled. The test's three consecutive fresh reads a second apart
  cannot hold anyway: a refresh leaves at most about 2.3 s of freshness and the
  next one commits about three seconds later. The test now samples the binding
  every 250 ms for 15 s after the demand and requires three refreshes and one
  sample with a second left, and each demand outcome is logged with the
  guarded read's freshness left on return.
- [CI continuation runs 23a/23b](../../test/results/adr200-continuation-ci-23a/native-continuation-1/context-storage-environment.json)
  (39070667782, 39070672636) failed before the demand check: the regional
  workload never enrolled. The hub-worker's permission reconciler stopped
  repeatedly (`permission reconciler stopped: unavailable`, retried every 31
  s); without a renewed permission stream PostgreSQL refused
  `accept_capacity_source` (40 times in 23a), so no capacity source was
  current and every workload attempt ended at `source`. The same chain explains
  run 18b. The reconciler now names the phase that stopped it (`start`,
  `watch`, `watch-next`, `apply`, `accept`, and inside `refresh`: `trust`,
  `snapshot`, `confirm-expired`, `renew`, `accept`).
- [CI continuation runs 24a–24c](../../test/results/adr200-continuation-ci-24a/native-continuation-1/context-storage-environment.json)
  (39072929605, 39072934693, 39072939641): **24a passed the demand check**:
  after one refresh demand the regional binding had five distinct
  observations and seven samples with at least one second of freshness left in
  15 s. 24b and 24c never enrolled, again because the permission reconciler
  stopped, at `refresh/confirm-expired`, `refresh/accept` and `start`. The
  reconciler's `start` and `accept` phases are now labelled one level deeper,
  with `trust-expired` separating an expired trust window from a store
  refusal.
- [CI continuation runs 25a–25c](../../test/results/adr200-continuation-ci-25a/native-continuation-1/context-storage-environment.json)
  (39075218716, 39075224097, 39075229161): 25a and 25c **passed** (five and
  six refreshes, eight and nine samples with a second left, in 15 s). 25b
  failed earlier: the promoted owner's native port never became reachable
  after a 1 min 44 s owner installation step. Three of the last six runs pass.
- **Downloads** (migration 00067, schema 67): demand rows outlive their expiry,
  `demand_capacity_refresh_for_download` re-arms the demand behind a download
  allocation, and the download coordinator retries, within its deadline, only
  a reservation the database refused for a stale binding
  (`ErrDownloadBindingStale`, mapped from the session trigger's refusal). The
  first version retried on the retention-policy sentinel, which the SQL
  adapter never returns, so it would not have retried at all. Unit tests pass;
  the extended SQL stage passed on CI (fleet run 39077437536).

