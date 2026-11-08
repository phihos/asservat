# Test runtime plan (2026-11-08)

The maintainer said that 20 minutes per test run is still too long. This
review measures where hosted CI wall time goes and ranks ways to cut it. It
changes no product code, harness or workflow; every option below is a proposal
with an estimated saving, not a measured result.

Baseline: `origin/main` at `447ea64f`. Sources:

- GitHub Actions job and step timings of the last 300 successful
  `native.yml` runs and 100 successful `ci.yml` runs (`gh api
  repos/phihos/asservat/actions/runs/<id>/jobs`). Medians below use jobs
  started on or after 2026-11-01 unless a suite had no success since then.
- Downloaded artifacts of 18 successful native runs (2026-11-04 to
  2026-11-08): `context-storage-timing.log` (seconds since `go test` start),
  `context-storage-environment.json` `phaseSeconds` (present only in runs after
  #175), and the `installer continuation: <step> done in <d>` lines from the
  continuation Pod log.
- Two full job logs (`continuation-manual-logs` job 128656127446 and
  `test (0/10)` job 128657024888) for sub-step timings of the setup action and
  per-package Go times.

## 1. Measured breakdown

### 1.1 Installed suites (`continuation-*`, 36 of the 65 native suites)

Every installed suite runs the same sequence: job setup, harness setup, the
unified bootstrap runner, the installer continuation, one focus, then the
administrator-removal check and cleanup. Only the focus differs.

| Segment | Median (s) | Range (s) | n | Notes |
| --- | ---: | ---: | ---: | --- |
| Runner start, checkout, Docker on `/mnt`, start background image pulls | 7 | 6–9 | 3 | pulls run in the background |
| Setup action | 85 | 73–98 | 16 suites | `setup-go` 19, Go module/build cache restore 34 (1.8 GB: 10 download, 24 extract), Python + pip 6, Node 5, `node_modules` 2, `make sql-tools` 4.5 (cache key changes with every Makefile edit), kind/Helm 1 |
| tshark (`apt-get`), Playwright shell, libpcap cache | 4–17 | | | tshark 12–15 s on collector focuses only |
| Harness: product binary, provider proxy, console, image | 13–43 | | 2 | 13 s with a warm Go cache, 43 s when the cache missed the commit |
| Harness: PostgreSQL, OpenBao, SeaweedFS | 3 | | 2 | |
| Harness: two kind clusters (concurrent) | 41 | 41–42 | 2 | |
| Harness: cluster preparation (image load, CRDs, Keycloak) | 25 | 22–27 | 2 | Keycloak already ready when clusters are |
| Go test: operator prerequisites | 9 | 9–66 | 16 | 9 s since #175 compiles the test package during harness setup; 31–66 s before |
| Go test: unified runner (`produce` 29, `schema` 87, `prepare` 38, `retire` 39, sequential) | 197 | 178–198 | 16 | |
| Go test: installer continuation Pod | 181 | | 4 | see 1.2 |
| Go test: test side after the Pod (capacity `ReadyAt`, join, regional enrolment, standby reopening) | 88 | 75–99 | 16 | ReadyAt 30 (19–41), join + enrolment 40, standby 13 (8–18) |
| **Continuation total (to focus start)** | **259** | 235–278 | 16 | |
| Focus | 145 | 77–307 | 16 | live-manual 80, incident 95, heap 106, live 145, logs 155, mixed 286, raw 290 |
| Removal check + Go fixture cleanup | 27 | 26–28 | 16 | |
| Harness cleanup, artifact upload, post steps | 7 | | 2 | |
| **Job total** | **~900** | 760–1190 | | per suite: share 760, incident 853, live 949, raw 962, http 1032, ongoing-save 1116 |

Fixed cost before any focus starts: about 100 s job setup + 80 s harness +
9 + 197 + 259 s Go test = **about 645 s (10.8 min)**, plus 34 s after the
focus. A focus is 15–35 % of its own job.

The critical path is strictly sequential: setup → harness → runner →
continuation → focus. Nothing in the bootstrap overlaps with anything else
except the background image pulls, the concurrent cluster creation and the
compile-ahead of the test package.

Queueing: dispatches with many suites wait for runners. The public repository
gets at most 20 concurrent hosted jobs; jobs of the larger dispatches in the
sample queued for median 1.5–13 min (maximum 28 min in a 29-job dispatch on
2026-10-27). An `all` dispatch is now 65 jobs (about 13 runner-hours), so it
needs at least four waves of 20.

### 1.2 Installer continuation Pod (181 s)

The continuation runs about 90 named steps; 16 of them take ≥ 1.5 s and sum to
about 165 s. The durations are almost identical across runs, which points to
fixed intervals rather than load:

| Step | Median | Variation |
| --- | ---: | --- |
| `capacity/initialize` | 37–52 s | 34–52 s, the only variable one |
| `public/roles-provision` | 26.4 s | ± 0.02 s |
| `resources/advance` | 26.1 s | ± 0.04 s |
| `owner/installation` | 22.3 s | ± 0.01 s |
| `bridge/settle` | 9.0 s | 8.0–9.0 s |
| `owner/accepted-source` | 6.05 s | |
| `owner/selection-complete` | 4.2 s | |
| `owner/inbox` | 4.0 s | |
| `worker/roles-provision` | 3.4 s | |
| `worker/launch`, `worker/inputs-complete` | 3.1 s each | |
| `worker/inbox`, `downloads/accepted`, `federation/settle`, `key-service/settle`, `publisher/settle` | 2.0 s each | |

Causes per step are in section 2.1.

### 1.3 Other native suites (component fixtures, no installation)

| Suite | Job median | Setup action | Test step |
| --- | ---: | ---: | ---: |
| `custody-1`…`4` | 362 / 442 / 489 / 322 s | 77–87 s | 270 / 359 / 401 / 226 s |
| `context-1`, `context-2` | 725 / 690 s | | |
| `collector-*` | 136–353 s | 69–87 s | 177–243 s |
| `helm-bootstrap`, `direct-observation`, `initial-schema-handover`, `permission` | 442 / 388 / 342 / 333 s | | |
| all other native suites | 150–300 s | | |

These are below the installed suites; `context-1`/`-2` (12 min) are the next
longest.

### 1.4 Unit CI (`ci.yml`)

| Job | Median | Setup action | Main step |
| --- | ---: | ---: | ---: |
| `test (0/10)` | **996 s** | 66 s | 928 s: every package except the Kubernetes adapter, `-race`, `-p=2` |
| `test (1–9/10)` | 368 s | 64 s | 170–348 s (Kubernetes adapter, weight-balanced) |
| `go` | 378 s | 66 s | compile-everything 197, `go vet` 45, pcap 40, cache save 28 |
| `console` | 337 s | 72 s | 246 s `console-check console-browser-check` |
| `checks` | 109 s | 68 s | 22 s gates |

CI wall time for a code push: median **1023 s** (690–1550, n = 78). The
critical path is `test (0/10)`: it is 2.7× the next-longest job. Inside it,
`internal/transport/presentation` alone takes 367 s under `-race` and finishes
last; the other heavy packages are `transport/native` 138 s,
`bootstrap` 114 s, `transport/mcp` 89 s, `adapters/mtls` 66 s,
`test/integration` 63 s, `application/capture` 56 s and `transport/browser`
53 s (sum of all package times 1156 s, run two at a time).

Shards 1–9 are imbalanced (170–348 s), because their weights come from a
recorded local gate rather than CI.

## 2. Causes and options

### 2.1 What bounds the bootstrap waits

A code trace (file:line as of `447ea64f`) found no long fixed sleep in the
continuation. The constant steps are fixed counts of guarded operations run
back to back. The variable steps wait for the kubelet. The seconds per
request below are inferred from step time ÷ operation count; they were not
measured separately.

| Wait | Bounding cause | Kind | Shortenable by | Est. saving |
| --- | --- | --- | --- | ---: |
| `capacity/initialize` 19–52 s and test-side capacity `ReadyAt` 19–41 s | The hub-worker sees the permission and capacity projection Secrets only after the kubelet refreshes the projected volume on its Pod resync: kind's default `syncFrequency` 1 m with up to 1.5× jitter (`internal/bootstrap/capacity_projection_wait.go:17-26`, `permission_worker.go:67-92`) | Condition (kubelet) | **Test-only**: a kind `KubeletConfiguration` patch with `syncFrequency` of about 5 s in the harness cluster config | 35–65 s |
| unified runner `schema` 87 s | 146 migrations, each about 0.6 s: per migration about five guarded root reads (two full `InitialPreparer.current` proofs via `lease()`, three `checkRoot()`), two `verifyOriginal`, two catalog inventory queries, a new goose provider and a new TLS + SCRAM connection (`internal/adapters/postgres/initial_schema.go:54,68-91`, `SetMaxIdleConns(0)`) | Request count | Product: apply all pending versions under one lease and proof bracket, or a squashed baseline migration for fresh installs (the project is unreleased) | about 70 s |
| `resources/advance` 26.1 s | 19 items, each `Advance` runs five full handover proofs (`internal/adapters/kubernetes/initial_runtime_resources.go:473-571`, `initial_preparer_handover_current.go:83-170`). About 1300 requests at the one-shot client's 50 QPS (`owner_inputs.go:256-257`), so the rate limiter may be the bound; ADR-188 forbids raising it | Request count | Product: one proof per item instead of five | 15–20 s |
| `public/roles-provision` 26.4 s | 43 roles in sequence, each a guarded claim, `CREATE ROLE`, fresh SCRAM/TLS login check and guarded completion (`internal/adapters/postgres/public_runtime_roles.go:186-265,428-450`) | Request count | Product: batch claims/completions under one operation proof, or provision independent roles concurrently | 15–20 s |
| `owner/installation` 22.3 s | Up to 22 sequential transitions plus 8 read-only finalizations, each a guarded five-second operation (`owner_installation_driver.go:128-298`) | Request count | Product: merge transitions | 5–10 s |
| hub-api standby wait 8–18 s | The test waits until hub-api has run 35 s since its last start (`installer_continuation_native_test.go:517,1633-1661`), because `openingRetry` waits 30 s after a TLS refusal (`context_regional_start.go:525-535`; derived from installed native 66, not an ADR interval) | Fixed wall clock | Short retry backoff (for example 5 s) or wait for the actual standby registration | 8–18 s |
| removal check + cleanup 27 s | Namespace deletion waits out Pod grace periods of 15–40 s (`federation_workload.go:93`, `publisher_workload.go:118`) and polls until gone (`initial_bootstrap_chain_test.go:698-785`) | Condition (termination) | Skip namespace-gone waits when the kind cluster is deleted next anyway, or exit promptly on SIGTERM | about 20 s |
| `bridge/settle` 8–9 s | Deployment controller's exponential retry after the initial guard denied its status writes (ADR-188 decision 4), then two equal resource versions 1 s apart (`kubernetes/installer_continuation.go:401-445`) | Condition (controller backoff) | Product: admit the controller's status-subresource writes through the initial guard from the start | 6–7 s |
| join + regional enrolment 40 s | hub-api restart on the catalog change, 15 s capacity-cluster ticker (`bootstrap/capacity_worker.go:57`), 5 s regional retry (`regional.go:87`), 1–2 s test polls | Cadences | Trigger the cluster re-read on the join; 250 ms test polls | 7–10 s |
| inbox, download, retention and `*/settle` polls (2.0 s, 3.1 s, 4.0 s, 6.05 s) | 2 s inbox/acceptance polls (`installer_continue.go:526,1110`, `installer_downloads.go:353`), 1 s operator outbox poll (`installer_continuation_native_test.go:330`), 1 s settle confirmation tick | Poll quantization | 250 ms polls or watches; create federation/key-service/publisher and settle once | 5–8 s |

None of these waits is a documented freshness or fence invariant: the original
five-second windows bound each operation's deadline, not how many run in
sequence. `scripts/test-context-storage.py` adds no meaningful fixed sleep
(its readiness loops poll at 0.1–1 s).

### 2.2 Ranked options

Savings are per installed-suite job unless stated; all are estimates.
"Qualification" says whether the run still proves what it proves today.

| # | Option | Est. saving | Cost / risk | Qualification |
| ---: | --- | --- | --- | --- |
| 1 | **Unit CI: split `test (0/10)`.** Give `transport/presentation` its own test-name-balanced shards (as the Kubernetes adapter has) and spread the other heavy packages over separate shards; take weights from CI timings, which also fixes the 170–348 s imbalance of shards 1–9 | Unit CI wall 17 min → about 7 min (then bounded by `go`, `console` and the Kubernetes shards at 340–380 s plus setup) | Low: `check-go-tests.py` already has the balanced partition and its completeness checks; two to four more parallel jobs | None |
| 2 | **Kind `syncFrequency` about 5 s** in the harness cluster config | 35–65 s, and removes most run-to-run variance | Low: one harness config change | Production kubelets default to 1 m; the product's projection waits (up to 2–3 min) stay unchanged. Keep `continuation-chain` on the default so the slow-resync path stays qualified |
| 3 | **Batch the initial schema** (one lease/proof bracket for all versions, or a squashed fresh-install baseline) | about 70 s, also in every component suite that runs the initial schema | Medium: product installer code under ADR-098/101; proof per migration becomes proof per batch, which keeps the guard and the original deadline per operation | Same schema, same guard; per-migration interleaving of root checks is dropped — a deliberate contract change to record |
| 4 | **Fewer guarded proofs per installer step** (`resources/advance`, `public/roles-provision`, `owner/installation`) | 35–50 s | Medium–high: authority-layer change; fits the authority-window simplification already planned (#178, #181) | Same final proofs; fewer repeated intermediate proofs, recorded as a contract change |
| 5 | **CI setup trims.** Native jobs restore the full 1.8 GB module + race build cache (34 s) although they build only the static product binary and `test/integration`; a separate native cache and a cached Go toolchain cut `setup-go` + restore from 53 s to about 15 s. Key `sql-tools` on its pinned versions instead of the whole Makefile hash | 35–45 s per native job, about 30 s per unit job | Low | None |
| 6 | **Several focuses per installed job** after one bootstrap (`ASSERVAT_JOURNEY_FOCUS=a,b,c`), grouped to ≤ 15 min, using the per-run inputs pattern that `manual-logs` has for kept reruns (#176) | No change to one focus's latency; −11 min runner time per merged focus; 36 installed jobs → about 10–12, which removes the queue waves of an `all` dispatch (estimated −20 to −30 min wall) | Medium: one focus can leave state that hides or causes a later failure; failures must name the focus; groups must not share quota-limited resources | Later focuses no longer start on a pristine installation; `chain` keeps the full fresh check |
| 7 | **Short waits and polls**: `openingRetry` backoff, 250 ms inbox/test polls, settle-once, join-triggered cluster re-read, controller status writes through the guard | 25–45 s | Low–medium; product changes to retry cadences are routine, the guard exception needs an ADR-188 amendment | None |
| 8 | **Cleanup tail**: skip namespace-gone waits before the cluster is deleted | about 20 s | Low | Termination is still checked in `chain` |
| 9 | **Harness overlap**: create the kind clusters while images build (both independent, run in sequence today) | 13–40 s | Low | None |
| 10 | **Build once per commit** (product binary, console, provider proxy, `go test -c` of `test/integration`, image tarball) in a build job; suites download it | 10–40 s, removes the 43 s cache-miss case | Low–medium: suites wait for the build job unless setup overlaps it | None: same bytes, hashes recorded as today |
| 11 | **Pre-baked installed snapshot** (PostgreSQL dump, kind node containers/etcd, OpenBao and SeaweedFS volumes) restored per run | up to about 8 min | High: fixture roots and tokens are time-bound (two-hour connector/worker roots, ten-minute account tokens), restored Pods carry stale service-account tokens and node identities, and the snapshot must be rebuilt on every migration or installer change | Stops qualifying installation for every focus and breaks the "fresh state only" rule for protected roots (docs/development-workflow.md). Not recommended: options 2–4 and 6 recover most of the time without stale state |

Options considered and rejected:

- **Larger hosted runners**: the installed bottleneck is sequential requests
  and kubelet cadence, not CPU, and larger runners cost money.
- **Self-hosted or persistent runners**: excluded by
  docs/development-workflow.md and unsuitable for privileged collector suites.
- **Docker layer cache for the worker image**: the image is `FROM scratch`
  with a few copied files; the cost is compiling, not layering.

### 2.3 Projected installed-focus job

Projection with options 2–5 and 7–9 applied (option 6 changes runner time,
not one job's latency). Each projected figure is today's median minus the
named option's estimated saving, using a value inside its range from section
2.2; none is measured.

| Segment | Today (measured) | Projected | Derived from |
| --- | ---: | ---: | --- |
| Job setup | 100 | 60 | −40 option 5 (35–45) |
| Harness | 80 | 55 | −25 option 9 (13–40) |
| Operator prerequisites | 9 | 9 | unchanged |
| Unified runner | 197 | 127 | −70 option 3 (schema batching) |
| Continuation (Pod 181 + test side 88, measured separately, median 259) | 259 | 140 | −50 option 2 (35–65), −40 option 4 (35–50), −29 option 7 (25–45) |
| Focus | 77–307 | unchanged | |
| Tail | 34 | 14 | −20 option 8 |
| **Fixed part** | **679** | **about 405 (6.8 min)** | sum of the rows above |

Section 1.1's "about 645 s before the focus" is the same 679 s without the
34 s tail.

## 3. Targets and order

| Suite type | Today (median) | Target |
| --- | ---: | ---: |
| Unit CI, code push wall time | 17 min | ≤ 7 min after step 1; ≤ 5 min after step 2 plus test-level speedups in `transport/presentation` |
| Installed focus, one job | 13–19 min | ≤ 10 min for every focus; ≤ 8 min for focuses under 1.5 min |
| Installed `all` dispatch, wall | 65 jobs, ≥ 4 queue waves | ≤ 25 min after step 6 |
| Component native suites | 2.5–12 min | ≤ 8 min (re-shard `context-1/2`) |

Ordered steps, each its own PR with before/after medians recorded:

1. **Split unit `test (0/10)`** (option 1). Cheapest large win: about −10 min
   on every code push, no qualification change, existing partition code.
2. **CI setup trims and kind `syncFrequency`** (options 5 and 2): one
   workflow PR and one harness line, about −1.5 min per installed job.
3. **Harness overlap, cleanup tail and short polls** (options 9, 8, 7 without
   the guard exception): about −1 min.
4. **Batch the initial schema** (option 3), with its contract note: about
   −70 s in installed and schema-running component suites.
5. **Fewer guarded proofs per installer step** (option 4), inside the
   authority-window simplification.
6. **Multi-focus installed jobs** (option 6), then re-shard `context-1/2`.
7. Build-once job (option 10) if job setup is still above 60 s.

The savings above are estimates from the measured medians in section 1, not
results.

## 4. Results

### Step 1: unit test shards (PR #183)

`check-go-tests.py` now plans 14 shards over small packages plus the
top-level tests of nine split packages, weighted by CI records and charging
about 4 s per `go test` run; `console-check` runs without Go beside the browser
check. Measured on PR runs (job durations from the Actions API):

| Job | Before (main `447ea64f`, run 42458467070) | Run 42460940268 (first plan) | Run 42461755736 (run charge, CI weights) |
| --- | ---: | ---: | ---: |
| `test` slowest shard | 1183 s (`0/10`) | 537 s (`12/14`, 40 near-empty groups) | 401 s |
| `test` other shards | 209–366 s | 281–410 s | 286–397 s |
| `go` | 201 s | 149 s | 142 s |
| `console` | 369 s (check + browser) | 72 s (check only) | 71 s |
| `console-browser` | — | 264 s | 276 s |
| Run wall (created → completed) | 1226 s | 559 s | 423 s |

The shards' test steps are now 210–340 s; the rest is setup (48–86 s, mostly
the 1.8 GB Go cache restore) and test-time noise. Step 2's setup trims are the
next lever toward ≤ 5 min.

### Step 5: installer step brackets (ADR-316)

Per-step request counts showed the repeated proofs were round trips, not
limiter waits (no waits ≥ 100 ms). `resources/advance` 26.2 s → 1.4 s and
`public/roles-provision` 26.3 s → 4.7 s; the continuation's step sum fell
from 145 s to 92 s (`continuation-manual-logs` 42482871889 → 42483849394).
`owner/installation` (22.3 s, 2452 requests) remains the largest step.
