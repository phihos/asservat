# ADR-200 — On-demand capacity refresh

Date: 2026-10-17. Status: accepted; implemented; SQL and installed demand-refresh checks pass.
Requirements: REQ-CAP-001/002/003, REQ-FED-001, S-02; TASK-03.
Follows [ADR-197](197-regional-capacity.md) (regional capacity) and
[ADR-190](190-capacity-readiness-and-promoted-owner.md) (hub capacity).

Current qualification (2026-10-20): the capture readiness wait overlaps
independent facts work and joins before the authoritative storage read. Both
retain the one-second selection margin and original deadlines. Download demand
rearming is implemented and SQL-tested. In
[resumed native47](../../test/results/resumed-c62e02ac-native47/result.json),
the demand lane supplied six distinct observations and 37 usable samples over
15 seconds, but a later request was refused at the final storage margin.
Refresh sampling does not guarantee sufficient freshness at a later read.
[ADR-213](213-storage-readiness-at-consumption.md) adds bounded readiness at
consumption within the same owned wait. Its implementation and
[complete capture race checks](../../test/results/resumed-c62e02ac-storage-consumption/verification.json)
pass. [Resumed native48](../../test/results/resumed-c62e02ac-native48/result.json)
included that change, passed demand readiness with six distinct observations
and 25 usable samples over 15 seconds, and reached acquisition and publication.
The evidence does not establish that consumption polling caused that success.
The overall test failed before fresh public status/case retrieval and download;
the complete installed lifecycle remains unqualified.

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
  The investigation owns one joined readiness wait per call. It overlaps
  exact-Pod resolution for a request and the unchanged ordered
  eligibility/capability/retention checks, then joins before the authoritative
  storage read. Under [ADR-213](213-storage-readiness-at-consumption.md), a valid
  result for the same selected storage with less than the existing one-second
  margin may continue into a consumption phase of that same owned wait.
  With refresh configured, it polls every 250 ms and may use the call's single
  demand attempt if it has not already been spent. Each candidate retains its
  own original timestamps; only a separately observed result with sufficient
  margin may be consumed. The original caller, initial identity/recovery,
  preview, target, eligibility/identity, capability, retention/proof/expiry and
  optional reason cutoffs bound this phase. Missing refresh or an earlier
  failed demand refuses a thin result that would require polling; an already
  valid result with sufficient margin may still pass. Read errors, invalid or
  changed storage, cancellation and expired original facts refuse the
  operation. No second owned wait, target selection, facts refresh or
  side-effect retry is added. The margin remains a check at selection, not a
  guarantee of time remaining after later SQL waits.
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

Historical checkpoints recorded before the 2026-10-20 status refresh above:

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


## Revision (2026-10-23)

Option 3 is now taken for the binding alone, under the maintainer's
authorization of relaxed, bounded recheck intervals. Migration 00072
(schema 72) makes `refresh_capacity_enrollment` store
`fresh_until = observed_at + 30 seconds` and lets
`capacity_managed_admission_until` accept a binding observed at most
30 seconds earlier (the table CHECK and Go `StorageBinding.Valid` already
allowed 30 seconds). Installed runs native64 and native68 showed demand
refreshes taking 2 s or more, or failing, so the five-second window lapsed and
query, capture and download admission flapped between refused and admitted.
The refresh receipt returned to the caller keeps its original interval; the
root source, trust, permission, recovery and request bounds are unchanged, and
a workload or namespace change still takes effect at the next refresh, within
30 seconds. Demand refresh stays as described above.

Migration 00073 (schema 73) applies the same 30-second lifetime to the root
`capacity_source` observation that `capacity_managed_root_until` requires for
every capture, query and download admission. `accept_capacity_source` stores
`fresh_until = observed_at + 30 seconds` for an accepted observation and the
table CHECK accepts at most 30 seconds; installed runs showed the separate
hub-worker source refresh failing under load (`capacity demand refresh:
guarded-read (unavailable)`), so the five-second source window lapsed even
when the binding was current. The acceptance receipt keeps its original
five-second interval (Go `CapacitySourceInterval` is unchanged), negative and
invalidating observations keep their original intervals and take effect
immediately, and trust, permission-stream, recovery and request bounds are
unchanged. A capacity source change still takes effect at the next accepted
or invalidating observation.

Migration 00074 (schema 74) applies the 30-second lifetime to the two remaining
observations that `capacity_managed_root_until` intersects: the accepted
`permission_stream` observation and the positive fleet trust observation
(`fleet_observation`, read through `fleet_current_trust`). Both were written for
five seconds by hub-worker refresh loops that run late under load, so every
capture, approved query and download admission still lapsed whenever either
refresh missed its window. The Go permission store writes
`fresh_until = observed_at + 30 seconds` and keeps the stream lease at least
that long; `observe_fleet_administration` stores the positive row for
30 seconds. The permission_stream CHECK, the SQL capacity readers/locks, the
Go stream fences and the ordinary/automation deny-snapshot bound
(`authorization.PermissionObservationInterval`) accept 30 seconds; fleet trust
consumers already accepted 30 seconds. Batch and caller receipts keep their
original five-second intervals. Suspension, newly accepted denies or retired
assignments, recovery blocking, database incarnation checks and the fleet
failure fence still take effect immediately; only a missing refresh is
tolerated for up to 30 seconds. Down narrows stored rows back to five seconds.

Migration 00075 (schema 75) applies the 30-second lifetime to the accepted
`retention_source` observation. Retained-policy resolution
(`AcceptedRetentionReader`, used by approved-query projection, downloads,
catalog listing and the retention transaction guard) intersected it with a
five-second bound, and the hub-worker retention follower runs late under
load, so installed `get_query_result` was refused at
`current/authority/retention` (native74) even with every other input
current. `ObserveRetention` still requires the original LIST and guard proof
to be inside their five seconds when it writes, then stores
`fresh_until = observed_at + 30 seconds` and keeps the source lease at least
that long; the table CHECK, the Go source/snapshot readers
(`privacy.RetentionSourceInterval`) and the derived `RetentionProof`
(`artifact.RetentionProofInterval`) accept 30 seconds. Raw Kubernetes LIST
snapshots, guard proofs and protected selector facts keep five seconds. A data
event, a LIST with changed policy state, suspension, takeover and recovery
blocking still clear the observation at once, bookmarks still never renew it,
and an unchanged LIST awaiting watch progress keeps only the original
deadline. Down narrows stored rows back to five seconds.

Revision 2026-10-23 (maintainer decision, migration 00076, schema 76):
download preparation and approved queries no longer need a fresh workload
binding, so the download demand path is removed: `demand_capacity_refresh_for_download`,
its `download-session` grant, the coordinator's stale-binding retry and the
`binding-stale` diagnostic. `artifact_download` no longer carries the
`zzz_capacity_new_admission` trigger, and its session snapshot records the
workload's immutable enrollment identity without checking the binding.
Operation audit outside the `capture` lane is no longer gated by
`capacity_managed_root_until`. Capture preview and admission keep the demand
lane and the binding/root freshness described above.


## First Ready projection correction (2026-10-28)

Migration 00103 (schema 103) corrects the same-observation first refresh.
The initial Ready phase publishes the binding with its original short phase
cutoff. The worker immediately refreshes using that same observation; the old
`observed_at >= observed` no-op retained the short projection. A strictly newer
observation received the accepted 30-second projection, so initial readiness
and subsequent readiness had different lifetimes.

Refresh now projects an equal short observation to **its original observation
plus 30 seconds**, once, under the existing current proof, exact backing and
post-lock deadline checks. An equal already projected observation is a no-op;
a newer persisted observation is retained. The receipt keeps its original short
interval. No observation is restamped to now, expired proof revived, account
identity changed or caller deadline extended. Down restores the previous no-op
rule without shortening already accepted projections. Schema floor 102 remains:
no table, parameter, privilege or returned wire shape changes.

This source defect is independently actionable under the accepted ADR-200
projection. It is **not an established cause** of Native 40767389365, whose
approved failure occurred after roughly 120 seconds. That run retained neither
binding row times nor target-correlated demand completion times. The existing capacity producer fixture now has a passing real SQL RED/GREEN
regression. This qualifies the projection correction, not that installed failure.

Complexity gate (engineering correction, not a new maintainer requirement):

1. Concrete initial-Ready inconsistency; frequency/installed impact unmeasured.
2. The 30-second projection is already accepted; no new tolerated window.
3. Applies to every newly enrolled workload's first same-observation refresh.
4. Reuses the existing projection and transactional idempotency, no new pattern.
5. Added credentials/privileges/network endpoints: 0.
6. Added runtime states: 0; one existing short-projection case reaches the
   existing update branch.
7. Added configuration: 0.
8. Uses the existing PostgreSQL transaction/locks, no added dependency.
9. Same existing SQL call. At most three existing UPDATEs and one configuration
   credit on the first short projection; duplicate debit 0. Added API calls,
   watches, timers, goroutines and durable rows: 0. CPU/WAL bytes unmeasured.
10. One additive function-only migration; Down retains stored rows and restores
    the old branch. Actual SQL upgrade/Down/Up passes; installed mixed rollout
    remains outside this component result.
11. Adjusting the existing refresh branch is smaller than replacing the shared
    enrollment phase finisher; documenting unequal initial lifetime would not
    meet the already accepted projection.


### Measured SQL result (2026-10-28)

The frozen old-production test checkpoint
`62be37b25666cc60199a4c1c74cb4fcf191138f8` failed the intended first-Ready
property: the same-observation refresh retained its **4.665197-second** stored
interval and configuration spend **6 → 6**. The three selected setup children
passed. The first failing child stopped dependent cases.

The tested correction is
`4d8d72d8972d65a710852b7d7a6ef0a7761782a1`. Its initial binding interval was
**4.670076 seconds**; explicit refresh projected it to **original observation
plus 30 seconds**, with configuration debit **1**. The exact duplicate spent
**0**, the returned receipt stayed within the original short proof, and an
older current observation retained the newer binding. After real original
proof expiry, both adapter and direct SQL refresh refused with **0 effects and
0 configuration debit**. All six selected producer children passed.
`TestCustodyUpgradeSchemaWithRealPostgres` also passed: 102 → 103, floor **102**,
idempotent upgrade, exact prior function restoration on Down, Up again, and
unknown-history refusal. The fixture activation/recovery row stayed unchanged.

Both runs used the existing owned PostgreSQL/S3/OpenBao fleet fixture, Go **300s**,
harness **360s**, and an outer **1100s** with a **10s** hard-kill bound; no quota,
provider deadline or privilege changed. RED outer/Go/test exits were **1/1/1**
(60.776s outer, 4.643s Go package). GREEN exits were **0/0/0** (51.461s outer,
13.909s package; producer 10.12s, upgrade 2.73s). Original reports retain all
**3352/3353** respective runtime/test source hashes, `sourceUnchangedDuringTest`
true and empty cleanup failures. Each owned three-container set and network was
independently absent after cleanup, before generated copies were removed.

Immutable local evidence is under
`/home/phil/.cache/asservat-build/codex-bf86-resume/capacity-initial-binding/`:
`red-owned-1/verification.json` (SHA-256
`110666450fb36911c0d73763f4e5ffeb1b24f31b8545d89cfab88747356f7349`)
and `green-owned-1/verification.json` (SHA-256
`45f91dc46ed4acbb20d4bc04e798492caa1f84263e181c087d662508d9f7922d`),
with original logs/environment reports and actual terminal exits alongside.
The final documentation follow-up leaves tested code byte-identical. Guard,
source, workload and history inputs remain synthetic; this is actual SQL/role,
adapter, enrollment and migration evidence, without collector execution,
installed Native cause attribution, physical backing or measured CPU/WAL claims.


## Closed demand-lane boundary diagnostics (2026-10-29)

Native 40794688705 on frozen `fc0a4491` failed before capture/history: the exact
selected binding had a complete 30-second interval but was expired by
115.911311s, while its persisted current demand was 4.008091s old. No matching
fresh publication reached the final authoritative read. All 3,400 source hashes
matched, Go/test exited 1 (594.875s; approved child 126.05s), and cleanup reported
no failures. The retained worker dump contained no demand-refresh outcome line.
That does not establish a joined-slot, permission, locator or pool-contention
cause. The repeated permission denial is the deliberate fixture reader probe.

The pre-candidate boundary previously returned silently on demand-reader error
or original-step expiry and when a selected demand matched no configured cluster.
A local test reproduces those missing reports, with an empty-success control
remaining quiet (RED exit 1, 0.404s). The existing callback now receives only
`read`, `read-deadline` or `cluster-unmatched`, generic unavailable and elapsed
wall time with zero read-left; no provider error text, namespace/workload/cluster
identity or source body is passed. A blocked read retains its original context
cutoff. Known clusters still reconcile; unknown clusters cause no observation.
This is diagnostic correction, not an availability fix or new retry policy.

No provider/API/SQL request, SQL grant, connection, timer, watch, service,
persistent state or public setting is added. New Report invocations can add logging I/O. The reader returns
at most sixteen demands, but each iteration selects exactly one round-robin
candidate, scans for its cluster and then returns after at most one callback.
It does not report once per demand in the batch or once per configured cluster.
Read failure returns immediately after its single report; empty success stays
quiet. The existing serial loop pauses 250ms after each completed iteration.
Consequently, with iteration duration L, the long-run rate is at most
`1 / (L + 0.25s)`: four reports/second/root for immediate errors or unmatched
clusters, or about 0.19/second for a full five-second read expiry. Over a finite
T-second interval, the ceiling is `floor(T / 0.25s) + 1`, including an initial
report. Batch size sixteen does not multiply these limits. Before-read clock
sampling has the same four/second long-run ceiling. Normal reconciliation,
priority publication, original authority intervals and SQL checks are unchanged.
Degraded reader/cluster states can thus produce additional log lines compared
with the formerly silent path, bounded by this existing single-lane cadence.
No sampler, counter or new reporting state is introduced.

The installed pool is intentionally `MaxConns=1`. Source tracing rules out
self-nesting inside the demand reader: its generated SQL call is one
`pool.QueryRow(...).Scan`; pinned pgx v5.11.0 `pgxpool.poolRow.Scan` releases that
connection before the adapter decodes/filters the result. The pool's only
BeforeConnect hook rereads a mounted credential, not SQL; no current-config,
recovery or owner callback borrows the pool inside this reader. Inspected
capacity source/root/enrollment transactions use their transaction-bound queries
and local decoding/MAC checks. Other concurrent facets still share the single
pool and can wait; a later idle SQL snapshot cannot establish or exclude earlier
contention. No real-SQL production-composition or Native self-blocking experiment
is claimed. SQL row selection, decoding keys, role/connection limit, cluster
wiring, original ownership and bounded batch order showed no functional mismatch
in this source review. Functional cold-readiness causation remains unresolved.


Local GREEN passes the focused boundary/known-cluster controls (race exit 0,
3.612s), then full capacity races (9.444s) and bootstrap races (62.517s).
Integration compilation (0.013s), affected vet, specification and design/import
architecture gates pass. Error/deadline/cluster conditions are intentionally
supplied test controls, not reconstructed Native facts. No SQL/Kubernetes
fixture, hosted run or collector was started for this diagnostic checkpoint;
functional evidence is still required before another installed attempt.
