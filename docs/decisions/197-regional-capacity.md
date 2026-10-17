# ADR-197 — Regional capacity

Date: 2026-10-17. Status: accepted; spike done (parts A and B, below); implementation code complete, SQL and native qualification in progress.
Requirements: REQ-CAP-001/002/003, REQ-FED-001/002, REQ-DEP-003, S-02; TASK-03.
Gap 4 of [ADR-196](196-regional-cluster-join.md). Builds on
[ADR-190](190-capacity-readiness-and-promoted-owner.md) (hub capacity),
[ADR-150](150-operation-owned-native-observation-proof.md) (the v2 observation path) and
[ADR-193](193-installed-federation-and-regional-enrollment.md).

## Context

Capture admission needs a `context_storage_binding` for the target workload.
Only capacity enrollment creates one, and installed capacity covers only the
hub cluster. A regional cluster joins later (ADR-193: its cluster ID exists
only after bootstrap issuance), and three pinned facts stop it from joining
capacity:

- **The stored qualification is immutable.** There is one `capacity_source`
  row per permission root, and DELETE is refused. `capacity_lock_observation`
  requires the observed cluster to be among the root's `NamespaceGuards`.
- **The pool plan is frozen at the first enrollment.** Enrollment and reads
  require the stored pool plan to equal the pool compiled from the current
  policies. Adding a regional budget policy would therefore also stop the
  hub's bindings from refreshing.
- **The capacity projection is immutable**, and the hub-worker's cluster set
  must equal the qualification's guards.

The observation path also differs. The hub's own cluster uses the v1 local
handler. For a remote cluster, ADR-150 measured that v1 cannot meet five
seconds, and selected the v2 path: hub-worker, then the exact owner holding
the standby, then the regional connector. v2 passed a native two-cluster run
in 2.4–2.8 seconds, but with synthetic setup roots and no installed
composition. Its handlers and clients are fixture-only.

## Decision

1. **Append-only cluster qualifications.** A new migration adds
   `capacity_cluster_qualification`: one write-once row per regional cluster,
   bound to an activated connector peer of the same root. There are at most
   16 rows per root, together with the hub. `capacity_lock_observation` reads
   the original guards plus these rows. The stored qualification and the
   projection stay unchanged.
2. **An additive pool revision.** A new regional budget policy may extend
   the pool when existing policies and clusters stay byte-identical and the
   total stays within the operator's capacity. Existing hub bindings keep
   refreshing. A regional budget policy cannot be declared ahead of time,
   because the cluster ID does not exist yet.
3. **v2 for regional clusters only.** The hub cluster keeps its qualified v1
   local path. Regional clusters use the v2 path, on the promoted owner's
   own operation port 9448 (amended in decision 7).
4. **The region installs before ungating.** `installer-cluster` creates:
   - a restricted probe namespace with a `capacity-probe` account;
   - the namespace selector guard with the hub's keys (a new offer field);
   - the connector's metadata reads, the guard reads and the probe account's
     TokenRequest right;
   - a local proof of the guard.

   The staged protection digest then covers them (ADR-196 decision 4).
5. **The join command writes the extension.** `installer-cluster-join`
   writes the region's capacity assertion into the guarded catalog entry;
   the hub-api inserts the write-once qualification row through a narrow
   SECURITY DEFINER function (amended under Progress: the join command has
   no SQL access). The join record
   carries the guard pin, digest and keys, the probe references and the
   connector template digest.
6. **The hub-worker's cluster set** is the projection's hub cluster plus the
   extension rows. A change stops the child with a fixed message, and the
   restart reads the new set.

The hub cannot prove the regional guard live: its digest is the region's
assertion, checked against SQL at runtime. That is weaker than for the hub
cluster (ADR-144), and is stated here. The five-second deadlines are fixed.
If regional observation does not fit them, it fails closed; no deadline is
extended.

7. **Corrections from the path research.** These were found after
   ADR-196 qualified natively, and the recommended choices were taken.
   - *Claim route.* The v2 claim POST reaches the holder on the exact
     owner name. The promoted router sends that name to the native server,
     which requires client certificates, and the claim presents none.
     - The owner therefore serves a separate exact observation name for
       the claim on its observation server.
     - The native server keeps requiring client certificates.
     - *Amended during implementation:* a separate name would add a SAN
       to the owner's strict server-certificate profile, which issuance and
       every verifier check. The v2 operation server was designed as its
       own listener. It gets its own port instead: the owner pool's new
       `OperationPort`, 9448 in the installed layout.
       - The v2 server owns both its common and exact names on that port.
       - The hub-worker dials the holder's Pod at that port.
       - The owner's L4 Service exposes it for the regional standby.
       - The native and v1 observation servers on 9444 are unchanged.
   - *The holder's leaf read.* The holder's registry needs
     `read_connector_activated_leaf`. Only the federation's `connector-read`
     login has it. The hub-api gets one new read-only login for it.
   - *The region's owner reads.* In the fixture, the regional connector
     reads owner candidates and registrations from SQL; an installed region
     has no SQL.
     - The lifecycle channel gains two read-only purposes, owner
       observation candidates and owner registration.
     - The spike must measure whether one lifecycle conversation fits:
       ADR-199 found that one registration conversation alone was
       expensive.
   - *The five-second budget.* `ReconcileWorkload` runs a guard
     observation and then a workload observation inside one capacity
     source window of at most five seconds.
     - One v2 observation measured about 135–143 observer and 24–27 probe
       calls across hub-worker, holder and connector, with idle limiters
       ([direct-observation-native-6](../../test/results/direct-observation-native-6/direct/context-storage.log)).
     - Two of them cannot fit at 20 QPS per client. A combined
       guard-and-workload v2 purpose (an ADR-150 amendment) is the
       expected fix, decided by the spike's measurements.
     - Deadlines stay fixed, and no limit is raised.
   - *What covers the regional capacity objects.* They are not covered by
     the source digest staged at generation 1. `regional.json` covers them
     as a pinned settings input, inside the StartupDigest the catalog pins.
     The SQL row covers the guard digest and keys.
   - *Observation format per cluster.* The hub cluster keeps v1. The
     extension row and the catalog entry select v2 for the regional
     cluster.
   - *The migration is 00065.* The pool extension must also accept an
     existing workload's PoolDigest from the pool's revision chain while
     its policy entry is unchanged. Otherwise adding the regional policy
     would stop hub bindings from refreshing.

## Consequences

Captures in a regional cluster still need the installed key service
(ADR-198). The first profile keeps 16 workload accounts per root and one
regional slot.

## Implementation

1. Spike (decision 7). Two parts:
   - **(A) The direct v2 fixture** (`TestDirectHolderObservationWithRealKubernetes`).
     Measure guard then workload under one five-second parent deadline;
     standby turnover; the holder behind the server-name router with the
     separate observation name; and the connector's owner reads with
     injected per-read latency.
   - **(B) The installed continuation.** Measure the elapsed time and calls
     of one real lifecycle conversation (the executor's
     `ReadContextStartOwners`), to calibrate part A's injected latency.
2. Contracts: the offer's namespace keys, the join record's capacity
   section and the catalog's capacity and observation pins.
3. Migration: the qualification extension, the additive pool revision and
   the read grant.
4. `installer-cluster`: the regional capacity objects and their proof.
5. Connector: the v2 client and producer and the regional metadata reader.
6. The join command's extension write.
7. hub-api: one serve function for v1 local and v2 regional observation;
   regional handlers from the catalog.
8. hub-worker: the effective cluster set and its restart.
9. Native run: a regional workload reaches `ready_at` with a fresh binding.

## Progress

- **Spike part A** ([run 2](../../test/results/adr197-spike-direct-2/environment.json);
  [run 1](../../test/results/adr197-spike-direct-1/environment.json) is
  retained: its subtest stopped before logging). The direct v2 fixture was
  rebuilt; it had not compiled since ADR-193 changed `connectorlifecycle.Runners`.
  - The four single observations took 2.48–2.73 s each.
  - **Guard then workload in one five-second window, standby turnover
    between them:**

    | Owner-read delay | Guard | Turnover | Workload | Window |
    |---|---|---|---|---|
    | 0 | 2.89 s | 0.26 s | timed out after 1.46 s | 4.98 s, does not fit |
    | 100 ms | 3.25 s | 0.38 s | timed out after 1.01 s | 5.00 s, does not fit |
    | 250 ms | failed at 4.24 s | — | — | — |

  - **Conclusions:**
    - Two sequential v2 observations cannot share a window even with SQL
      owner reads, so the combined guard-and-workload purpose is required.
    - About four owner reads sit on one observation's critical path, and
      one more on a standby turnover: +0.37 s at 100 ms per read, against
      +0.13 s.
    - A single observation fails with owner reads of about 250 ms. A
      combined observation of about 3 s therefore allows about 100–150 ms
      per owner read.
    - Part B measures what one lifecycle conversation actually costs.
- **Spike part B** ([ADR-196 continuation run 9](../../test/results/adr196-continuation-native-9/environment.json),
  passed with exit 0, all four tests, no cleanup failures, source unchanged).
  The first lifecycle conversation of each purpose in the installed
  region:

  | Purpose | Elapsed | Regional observer calls |
  |---|---|---|
  | owner-candidates (read-only, answered from hub SQL) | 60 ms | 0 |
  | registration | 1.38 s | 28 |
  | client-sign, server-sign | 3.4 s each | 68 each |
  | enroll | 3.96 s | 82 |

  - A conversation that has the region run its own process proofs costs
    seconds. A read-only conversation answered from hub SQL costs about
    60 ms, inside part A's per-read budget.
- **Decisions settled by the spike** (decision 7's recommended choices):
  1. **Owner reads.** The region's owner-observation candidates and owner
     registration come through two read-only lifecycle purposes, answered
     from hub SQL like `owner-candidates`, with no delegated phase reads.
  2. **Combined purpose.** Regional capacity uses one combined
     guard-and-workload v2 purpose per reconcile (an ADR-150 amendment).
     One observation of about 3 s plus about four 60 ms owner reads fits
     the unchanged five seconds. Two sequential observations do not.
  3. **The rest of decision 7 stands:** the claim route on a separate
     observation name, the holder's leaf-read login, migration 00065, and
     the hub-worker's effective cluster set.
- **Implementation, step 1** (unit tests pass):
  - **The combined purpose.** `capacity-guarded-workload` carries exactly
    a guard and a workload; the guard's keys must equal the requested
    keys.
    - The routing claim accepts it.
    - The cluster metadata producer observes the guard, then the workload
      under those keys.
    - `CapacityClusterReaders.Guarded` makes `ReconcileWorkload` use one
      combined observation. The hub-worker's remote adapter implements it.
      The hub cluster's v1 readers do not set it, so their qualified path
      is unchanged.
  - **The owner reads.** The lifecycle channel gains
    `owner-observation-candidates` and `owner-registration`.
    - The latter takes one server owner certificate, and its answer must
      name exactly that certificate.
    - The federation answers both from its existing
      `connector-owner-read` registry.
    - `RegionalLifecycle` implements `ReadOwnerObservationCandidates` and
      `ReadOwnerRegistration` through them.
- **Implementation, steps 2–8** (code complete; compiles, vets and the
  affected unit suites pass; real-PostgreSQL and native runs below).
  Choices taken while implementing, recorded as amendments:
  - *Decision 5, who writes the SQL row.* `installer-cluster-join` runs
    from an operator's machine with a kubeconfig. It has no SQL connection,
    and the administrator SQL credential lives only in the in-cluster
    installer. So the join command writes the region's capacity assertion
    (selector guard digest and keys, connector template and workload guard
    digests) into the guarded catalog entry, and the hub-api records it at
    start through one new purpose-fixed login, `regional-capacity`
    (ordinal 85). That login executes only `qualify_capacity_cluster` and
    the activated-leaf read that decision 7 already required. The row is
    write-once: an exact replay is read-only, a different value is refused,
    and the hub's own pin cannot be shadowed. The catalog's admission guard
    is what makes the entry an administrator assertion, as for the rest of
    the join.
  - *The row's peer binding.* The row records the connector peer and issuer
    epoch from the catalog's staged source. It is not foreign-keyed to the
    connector profile, because the hub-api may start before the connector
    stages. Every v2 observation still requires that peer's activated leaf.
  - *Decision 2, when the pool extends.* The stored pool row must equal the
    compiled pool for every capacity effect, and the extension needs Go's
    canonical pool bytes. `read_capacity_root`, which the hub-worker's root
    reconcile calls every cycle, therefore adopts a pending additive
    revision under its exclusive root locks, spending one prepaid
    configuration transaction. Reservation adopts it too. Until then,
    root and enrollment checks accept a stored plan that the current plan
    additively extends.
  - *Existing enrollments.* A workload row keeps its original plan. A read
    accepts a plan that differs only in the selected-source and pool
    digests and the pool generation, when the original pool digest is the
    stored plan's or one of its superseded revisions
    (`capacity_pool_revision`, at most 16). The receipt then names the
    presented plan's digests, so the Go side is unchanged. A non-additive
    change (any existing policy or cluster entry edited) keeps the earlier
    frozen behaviour.
  - *Hub-api scope.* The v2 server holds one regional capacity cluster, the
    first profile's one slot. A second needs one standby handler per cluster.
  - *Regional clients.* The region's standby uses its own observer and probe
    client instances at the same fixed 20 QPS, so capacity observation never
    spends the executor's proof budget (ADR-199). No limit is raised.
  - *Restart.* The hub-worker rereads the qualifications every 15 seconds; a
    different set ends the capacity child with "capacity clusters changed",
    and the hub-worker restarts like the hub-api on a catalog change.
- **Native runs** (two clusters, installed composition, `scripts/test-context-storage.py
  --initial-bootstrap-chain --runtime-provider-pair --installer-continuation`):
  - [Run 1](../../test/results/adr197-continuation-native-1/exit.txt) was
    interrupted by a host power outage while its kind clusters were being
    created; no test ran.
  - [Run 2](../../test/results/adr197-continuation-native-2/environment.json)
    and [run 3](../../test/results/adr197-continuation-native-3/environment.json)
    failed at the last check. The hub-api recorded the qualification, the
    region's standby composed and the operator stage applied, but the
    regional workload never got a capacity row. Run 3's added diagnostics
    found the cause: the hub-worker restarted its **whole process** on the
    cluster set change. Its configuration reconciler, which keeps fleet trust
    fresh, then waited about 19 seconds for its Lease. Trust expired, so the
    hub-api failed its accepted-configuration check (`sql=fleet-interval
    expired-interval`) and crashlooped, and the region's renewals failed with
    it. Decision 6 now restarts **only the capacity child** inside the
    running process. Run 2 also exposed an unpaced standby retry loop;
    failed standbys now retry at most once per second.
  - [Run 4](../../test/results/adr197-continuation-native-4/environment.json):
    the child-only restart works ("capacity restarts with the new set") and
    the fleet-trust lapse is gone. The regional workload still got no row.
    Hub-worker claims reach the holder but fail at locate or claim after
    about 4 s. The hub-api restarted once more in its identity supervisor
    (`run-identity`). The region's own source reads and the federation's
    registration conversations fail. ADR-196 runs 8 and 9 showed neither.
    Run 5 adds step, elapsed-time and call-count diagnostics on all three
    sides.
  - Run 5 was stopped during its image build because another session had
    raised the host load to 5.8; timing-bound results there would not be
    valid.
  - [Run 6](../../test/results/adr197-continuation-native-6/environment.json)
    failed before the regional stage: the existing check that the owner's
    native port is reachable timed out, with no diagnostics on that path.
    Run 7 passed the same check. That path now prints the owner's
    diagnostics.
  - [Run 7](../../test/results/adr197-continuation-native-7/environment.json)
    measured the regional side: each claimed standby's native open, reads and
    metadata finish in about 0.3 s with 28 API calls. The region's failing
    source reads are a symptom: the hub's conversations reach them with
    10 ms to 1.4 s of their deadline left. The hub side is the bottleneck:
    - claims and locates fail at 2.8–4.6 s;
    - the hub-api's identity renewal fails (`run-identity`);
    - the loop retried a regional (v2) cluster every iteration, about every
      4.5 s on failure, and continuously on success;
    - each attempt costs about a hundred hub-side calls, on the hub-api
      observer shared with owner identity and the hub cluster's local
      observation.

    Two corrections, neither raising a limit:
    - **Pacing.** A regional cluster's iteration starts no sooner than 2 s
      after its previous one ended (`CapacityClusterReaders.Pace`); the
      local cluster keeps its cadence.
    - **Isolation.** The holder's v2 proofs in the hub-api, and the v2
      client's proofs in the hub-worker, use their own client instances of
      the same identities, each at the fixed 20 QPS, as the region's
      standby already did. A capacity observation can no longer spend owner
      identity's budget. If a v2 observation still does not fit its own
      20 QPS within five seconds, the fix is consolidating its proofs, as
      ADR-199 did for the executor, not a higher limit.
  - [Run 8](../../test/results/adr197-continuation-native-8/environment.json):
    with pacing and isolation, regional discovery observations succeed
    (namespaces and workloads in 2.2–2.9 s), and the hub-api restarts only
    for the join. The guarded-workload observation still failed. Successes
    alternated with claims refused after about 0.55 s for want of a standby.
    The v2 client holds one standby, and the previous connection releases
    it asynchronously, so the region's immediate reopen was refused and
    paced for a full second. The reconcile that follows a successful
    discovery therefore always landed in that gap. After a served standby,
    up to five failed opens now retry at 100 ms each before the one-second
    pacing applies.
  - [CI run 1](../../test/results/adr197-continuation-ci-1/native-continuation-1/context-storage-environment.json)
    (GitHub Actions run 39026237800, fresh runner): the quick retries
    restore most discovery reads, and one guarded-workload observation
    succeeded, but no enrollment row appeared within five minutes. The
    reconciler discarded `ReconcileWorkload`'s error; each refusal now
    names its fixed stage and regional clusters log one line per change.
  - [CI run 2](../../test/results/adr197-continuation-ci-2/native-continuation-1/context-storage-environment.json)
    (run 39028306118): every guarded-workload attempt stopped at `claim`,
    logged as `guarded-read (unavailable)`. Discovery still alternated
    between success and a refused claim, and the guarded read always
    follows a successful discovery, so it always met the gap: replacing a
    served standby (local checks, TLS, Hello, hub authentication) outlasts
    the 2 s pace plus five quick retries. The region now keeps two
    standbys open and the hub holder admits three entries (two live, one
    served entry in joined cleanup), so a ready standby remains while the
    other is replaced. Request deadlines and claim checks are unchanged.
  - [CI run 3](../../test/results/adr197-continuation-ci-3/native-continuation-1/context-storage-environment.json)
    (run 39030184231): two standbys did not change the pattern, which
    corrects the run-2 reading. `locate` finds a ready standby; the
    exchange behind `claim` fails, and the region reports `serve
    (unavailable)`, sometimes right after its first native read. The
    hub-worker's claim sub-steps, the hub-api's claim handler and the hub
    coordinator's operation steps now each log their fixed refusal stage.
  - [CI run 4](../../test/results/adr197-continuation-ci-4/native-continuation-1/context-storage-environment.json)
    (run 39032137482): failures are `claim/post` on the hub-worker and
    `observe` in the hub-api's claim handler. The region completed 13
    full serves (all four native reads), and several hub failures take
    about 2.3 s, a whole exchange, so the hub rejects completed exchanges
    at the end. The holder's claim replaced every inner error with a bare
    unavailable; it now keeps the coordinator's step, and the step labels
    compose across layers. The direct-observation suite (CI run
    39032139352) measured about 135 Kubernetes API calls per regional
    observation across hub-worker, hub-api and region, with 51 requests
    spending 76 ms in the API server: most of each 2.4–2.8 s observation
    is client-side 20 QPS limiting.
  - [CI run 5](../../test/results/adr197-continuation-ci-5/native-continuation-1/context-storage-environment.json)
    (run 39033973438): the refusals are `observe/conversation/registration-1`
    and `registration-3`, occasionally `exchange`: the hub's SQL registry
    read of two consecutive native values around the activated-leaf check.
    The region completed read 3 fifteen times but read 4 only nine times,
    so registration-3 often stops between the reads (value check or SQL);
    registration-1 fails after both reads. The registry now names each
    check, distinguishing expired values from mismatches.
  - [CI run 6](../../test/results/adr197-continuation-ci-6/native-continuation-1/context-storage-environment.json)
    (run 39035890980): the hub's refusals are transport reads over the
    standby (`registration-1/first-read`, `registration-3/last-read`,
    `exchange`, `receipt`), not registry checks. About nine of the
    region's fourteen failed serves ended before its native open, so the
    region refused while answering the first probe, which first re-reads
    the hub's owner candidates and verifies the hub owner's proof through
    its own lifecycle reads. The region's probe answer, producer setup and
    serve loop now carry fixed steps, and its standby log prints the chain.
  - [CI run 7](../../test/results/adr197-continuation-ci-7/native-continuation-1/context-storage-environment.json)
    (run 39037953153): the region names `serve/answer` in ten failed
    serves. In the event order, most follow a successful native read 4
    (510–600 ms for its 22 calls) or read 3, so the region refuses after
    its reads, about two seconds into the exchange, in the answer's
    window or key check. That matches window exhaustion under the 20 QPS
    limiters. The connection layer had flattened the channel's step; it
    now passes it through, the answer distinguishes `window` from `keys`,
    and each failed serve logs its elapsed time.
  - [CI run 9](../../test/results/adr197-continuation-ci-9/native-continuation-1/context-storage-environment.json)
    (run 39040224004) names the cause: the region's dominant refusal is
    `serve/answer/channel/candidates (hub-channel)`. Each probe answer
    re-reads the hub's owner candidates over the lifecycle channel, and
    the installed federation admits two conversations at once and answers
    429 beyond that. Those reads take about 20 ms, but registration
    conversations take 1.4 s or more and failed repeatedly (`federation
    registration failed`), so they held both slots. The installed
    federation now admits four conversations; its SQL pools stay at one
    connection each. The window hypothesis is not supported: the failures
    are channel refusals, not expired bounds.
  - [CI run 10](../../test/results/adr197-continuation-ci-10/native-continuation-1/context-storage-environment.json)
    (run 39042349815): with four federation slots the `hub-channel`
    refusals are gone and failed exchanges fell from about fourteen to
    four. Discovery observations now always succeed; every guarded-workload
    observation still fails. The one that reached the region did its
    guarded metadata (14 calls) and read 3, then its final native read
    failed after 12 of its 22 calls. The metadata client was a copy of the
    native reader's client and shared its 20 QPS limiter, so the guarded
    metadata spent the final bracket's budget. The metadata now has its
    own observer instance at the same fixed limit.
  - [CI run 11](../../test/results/adr197-continuation-ci-11/native-continuation-1/context-storage-environment.json)
    (run 39044413471): with separate limiters the first guarded-workload
    observation succeeded (2.12 s), and enrollment then refused at its
    `enroll` stage about 20 ms later without a reservation row. The
    enrollment coordinator's steps (observation, read, reserve, mismatch,
    account, capture, publish) are now labelled and the cause is passed
    through.
  - [Direct-observation CI run](../../test/results/adr197-direct-ci-2/native-direct-observation-1/context-storage-environment.json)
    (run 39046711116, 6.5 minutes): the focused suite now runs every
    capacity purpose, including the combined guarded workload, against
    real Kubernetes in two clusters with the v2 holder path. All passed;
    the guarded exchange took 2.99 s with 2.0 s of its window left. The
    measurement-only spike that motivated decision 3 is removed.
  - [Local SQL runs 8–9](../../test/results/adr197-custody-9/environment.json)
    reproduce the enrollment step in 78 s instead of a 28-minute native
    run. The reservation's refusal is `capacity qualified account or
    protocol ceiling reached`. In the native test the operator's regional
    policy reserved 1 GiB and 1000 objects of context, which needs
    min(1 GiB/1,544,192 B, 1000/4, 512) = 250 context records per
    workload, while the installed root is qualified for 3 records per
    account. The refusal is correct; the test's regional policy now
    reserves exactly three records. The SQL stage asserts that a regional
    workload spends the root's qualified accounts like any other and is
    refused without a row when they are exhausted. Follow-up: a policy
    above the root's qualified protocol is only refused at reservation;
    source acceptance should report it to the operator.
