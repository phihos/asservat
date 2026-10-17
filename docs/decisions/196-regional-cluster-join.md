# ADR-196 — Regional cluster join

Date: 2026-10-17. Status: accepted; decision 5 and steps 1–5 implemented and
natively qualified ([continuation run 8](../../test/results/adr196-continuation-native-8/environment.json): the region installs
the executor layout and join record, the executor composes, and the hub joins
the slot and restarts to accept it). Regional capacity (ADR-197) and the
capture run remain.
Requirements: REQ-FED-001/002, REQ-DEP-001/003/005, S-02; TASK-03, TASK-11.
Completes [ADR-193](193-installed-federation-and-regional-enrollment.md)
step 7 and [ADR-185](185-public-sources-and-cluster-catalog.md) step 5.
Builds on [ADR-194](194-promoted-owner-inputs.md) and
[ADR-195](195-installed-hub-retention-source.md).

## Context

A regional cluster installed by `installer-cluster` enrolls its connector
(generation 1), but the promoted hub-api cannot start a capture there. The
hub-api reads the guarded cluster catalog at process start, and that catalog
stays empty. A catalog entry (`OwnerPublicCluster`) needs values from both
sides:

- **Hub-known:** the capability document (root, installation, issuer epoch,
  cluster, collector version and image digest, projection digest) and the
  work trust (the ADR-194 work-signing key read back by the continuation).
- **Region-known:** the connector source bytes, UID and workload-guard
  protection digest, and the executor pin: namespace and account UIDs, the
  startup digest and the image digest.

Several other gaps also stop a regional capture:

1. Nobody writes the entry, its per-cluster sources or the topology.
2. The region's connector runs without its API-context executor layout.
3. The owner's port 9444 is not reachable from another cluster.
4. The region has no capacity: admission needs a `context_storage_binding`
   for the target workload, and only capacity enrollment creates one.
5. The connector wraps artifact keys through a hub key service that has no
   installed deployment.
6. Each regional topology names the hub retention source. That source
   exists now (ADR-195), but the topology itself has no producer.

Native run 7 of ADR-195 showed one more constraint. The namespace guard
refuses API Pod deletion to everyone but the controllers and the kubelet,
and a template change breaks the hub-api's pinned template digest. So
ADR-185's "write the catalog, then replace the hub-api Pod" cannot work as
written.

## Decision

1. **A hub-side join command.** `asservat installer-cluster-join` runs as an
   installation administrator (the chart's bootstrap runner, as a Helm hook
   or from the CLI). For one regional cluster it creates, create-only and
   with exact-spec reopen:
   - the slot's capability and work-trust sources, immutable, each with its
     guard (the installation administrators);
   - the slot's retention topology, immutable, naming the hub source from
     the continuation's guard digest;
   - the catalog entry, which is an update of the mutable catalog.

   Neither the continuation (which has finished) nor the hub-worker (not an
   administrator, and it cannot know the startup digest) writes the entry.
2. **A public join record.** `installer-cluster` writes a `RegionalJoin`
   record to an immutable ConfigMap in the region and prints it. It
   carries:
   - the bootstrap slot (cluster, peer, issuer epoch);
   - the connector `FederationPeer` (source UID, bytes, protection digest);
   - the executor pin.

   The operator copies it into the hub's join input, as the offer travels
   the other way. The join command checks it against the offer and the
   issued slot, decodes the source, and requires the executor image digest
   to equal the offer's. The startup digest stays an administrator
   assertion, as do all catalog values: a wrong entry starts and then fails
   closed at the first connection, because entries are verified against the
   activated connector leaf.
3. **The hub-api restarts its own process on a catalog change.** The
   hub-api already rereads its worker-control catalog every second. It now
   also rereads the cluster catalog's digest. On a change it stops with the
   fixed message `cluster catalog changed`, and the kubelet restarts the
   container in the same Pod. The new process reads the catalog at start, as
   ADR-185 requires. No Pod, template or pin changes, and no live reload is
   introduced.
4. **The regional executor layout before ungating.** `installer-cluster`
   installs the connector with its `APIContext` settings: the capacity
   account, the workload guard's `APIContextStarts` section, the settings
   source and the start guard. The protection digest staged at generation 1
   then already covers them. Changing the guard later would change the
   staged digest and need restaging.
5. **Owner native exposure.** The continuation creates an L4 Service for
   the owner's port 9444, with the same choices as the federation's (a
   pinned NodePort or a LoadBalancer). The offer gains that endpoint and the
   owner issuer roots. The server-name router (ADR-190 step 6) already
   separates connector traffic from observation traffic on that port.
6. **Separate decisions for the two remaining services.** Regional capacity
   (gap 4) and the installed key service (gap 5) are each large enough for
   their own decision record:
   - ADR-197, regional capacity: the regional observation handler, the
     namespace guard and an extension of the capacity qualification. This is
     the least-designed piece and starts with a spike.
   - ADR-198, the installed key service: an ADR-176 key-service Deployment
     whose connectors come from the catalog. *Amended by ADR-198:* the
     key service resolves connectors from their staged SQL profiles, as the
     federation does, so a join needs no key-service change.

   *Corrected during implementation:* step 2 depends on ADR-198 and on a
   regional evidence credential. The connector's `RegionalAPIContext`
   requires the hub key-service endpoint and an evidence store with a
   write-only regional credential, as well as the owner endpoint (decision
   5) and the regional work trust. The order is therefore:
   1. the owner exposure (decision 5);
   2. the installed key service (ADR-198);
   3. the regional evidence credential, supplied by the operator like the
      bootstrap record;
   4. the executor layout and the join record;
   5. the join command;
   6. regional capacity (ADR-197);
   7. the capture run.

7. **Corrections from the layout research.** These were taken as the
   recommended choices.
   - *Which digest is staged.* Generation 1 stages the source guard's
     protection digest (`configMapProtectionDigest`), not the workload
     guard's. The workload guard, including `APIContextStarts` and the
     configuration probes, is pinned by the immutable `regional.json` and
     by the settings' `WorkloadProtectionDigest`, which the StartupDigest
     covers. Both must be in place before ungating, because the connector
     enrolls as soon as it is ungated.
   - *The settings are read by name.* The executor requires every mounted
     ConfigMap or Secret except its own settings to be pinned in the
     settings' `Inputs`. `regional.json` embedded those settings, so the
     regional inputs ConfigMap and the settings would each need the other's
     UID. `RegionalAPIContext` therefore names the settings ConfigMap only.
     The process reads the settings at startup from that guarded, immutable
     ConfigMap. The hub's pinned StartupDigest binds the settings' UID,
     version and content, so a replaced ConfigMap fails at the first
     connection. The regional inputs become an ordinary pinned input, and
     no new exception to the pin rule is added.
   - *The offer carries the rest of the hub-known values.* These are the
     work-trust public key (`WorkKey`, the ADR-194 signing key) and the
     evidence store (endpoint, roots, region, bucket and store ID). The
     installer installs the API context only when the offer names the
     owners, the key service, the work key and the evidence store, and
     refuses a partial offer. An offer that names none of them installs the
     plain ADR-193 connector.
   - *The regional evidence credential.* The operator supplies it to
     `installer-cluster` (`--evidence-credential`, or the chart's
     `cluster.evidenceSecret`). It is an S3 identity allowed only
     `PutObject` under `v1/<regional cluster ID>/`, with an explicit delete
     denial and no read or list. The region keeps it in an immutable Secret
     dedicated to the executor. Rotating it changes the StartupDigest, so
     the region must join again.
   - *Digest helpers.* The installer computes the StartupDigest and the
     source guard digest with the functions the runtime uses, so the
     printed join record cannot drift from the checks.
   - *The topology pin is in the catalog entry.* The hub-api pins its
     retention topologies from its startup input. Adding a joined slot's
     topology there would change the Pod template, which decision 3 rules
     out. The catalog entry therefore carries the slot's topology pin.
     The hub-api reads the guarded catalog before it builds its native
     configuration, and unions those pins with the input's. The restart
     on a catalog change (decision 3) picks the new pin up.

## Consequences

Adding a cluster becomes: install the region, copy the join record, run the
join command. The hub-api restarts its process once. The first installed
profile stays at one regional slot (ADR-185's probe cap). A capture becomes
possible only once ADR-197 and ADR-198 are also implemented.

## Implementation

1. Contracts: `RegionalJoin`, the join input, the topology slot name and the
   offer's owner endpoint.
2. `installer-cluster`: the API-context layout before ungating, and the join
   record.
3. The join command: sources, guards, topology and catalog entry.
4. hub-api: catalog digest watch and the fixed restart.
5. The owner's L4 Service and the offer fields.
6. Native run: join the regional cluster; the hub-api restarts and accepts
   the entry; a connector start reaches the owner and is refused only for
   missing capacity.

## Progress

- **Decision 5, owner exposure.** Natively qualified in
  [continuation run 1](../../test/results/adr196-continuation-native-1/environment.json).
- **Step 4, the executor layout and join record.** In code with unit
  tests.
  - `InstallRegionalConnector` installs the executor when the offer names
    the complete section, and refuses a partial one. It creates:
    - the capacity account and its reservation role;
    - the API audience pin;
    - the settings, trust and start guards, with the settings and trust
      probes and `APIContextStarts` in the workload guard;
    - the dedicated immutable evidence Secret and the trust ConfigMap;
    - `regional.json`, which names the settings by name;
    - the settings, which pin `regional-inputs` and the evidence Secret.
  - It then proves the source, settings and trust guards with the
    connector account's token, writes the immutable `regional-join` record
    and ungates.
  - The StartupDigest and source guard digest come from the runtime's own
    functions (`ConnectorAPIStartupDigest`, `Proven`).
  - `installer-cluster --evidence-credential` and the chart's
    `cluster.evidenceSecret` supply the credential, and `check-helm`
    covers both branches.
- **Step 5, the join command, and the hub-api's catalog read.** In code
  with unit tests.
  - `installer-cluster-join` reads the offer and the installed owner
    input, and checks the record with the hub-api's own connector profile
    decoding.
  - It writes the slot's guarded capability and work-trust sources and the
    retention topology, which names the hub source through the exactly
    reopened retention guard's digest (`RetentionGuardDigest`). It then
    appends the entry to the catalog by resourceVersion CAS.
  - The hub-api reads the catalog in a new `cluster-catalog` phase before
    its native configuration, and unions each entry's topology pin. Its Role
    reads the fixed slot topology names.
- **[Continuation run 2](../../test/results/adr196-continuation-native-2/environment.json)
  failed and is retained.** It passed:
  - all ADR-198 key-service checks;
  - the regional connector's enrollment at generation 1 with the full
    executor layout;
  - the join record check: printed and stored, with a connector protection
    digest equal to the hub's staged generation 1.

  The executor never logged its start line, and its stop line carried
  only an error class. The executor's proof now names fixed stages, the
  stop line prints them, and the test captures `regional` lines and still
  runs the join when the executor check fails.
- **[Continuation run 3](../../test/results/adr196-continuation-native-3/environment.json)
  natively qualified step 5.**
  - `installer-cluster-join` wrote the slot's sources, topology and catalog
    entry, and its rerun was exact.
  - The hub-api restarted its process in the same Pod on the catalog change,
    and its startup accepted the entry: connector profile, SQL registry,
    guarded capability and work-trust sources, topology pin and router
    limits. It is Ready again.
  - The continuation replay after the bridge left the key service and the
    executor offer unchanged.

  The run failed only on the executor check. Its stop line read
  `execution-process (unavailable)`, because the proof-reuse wrapper
  replaced the producer's error. The wrapper now keeps the cause; callers
  still see unavailable. The process attestation's checks are labelled too.
- **[Continuation run 4](../../test/results/adr196-continuation-native-4/environment.json)
  failed and is retained.**
  - Step 5 passed natively a second time.
  - The executor's stop lines named a different check on each attempt:
    attestation source re-read, settings guard, settings snapshot,
    execution account and token review.
  - The pattern fits the proof running out of its original five seconds
    at whichever check it had reached, not one wrong value.
  - An earlier fixture run measured the cold proof at 71 calls in 1.8 s,
    dominated by the 20 QPS limiter.
  - **Freeze broken.** The run records `sourceUnchangedDuringTest: false`.
    An instrumentation edit (elapsed time in the stage labels) was made
    before its exit notification. The test binary had already been built
    from the frozen sources, so the run's diagnostics stand. Its freeze
    evidence does not.
- **[Continuation run 5](../../test/results/adr196-continuation-native-5/environment.json)
  failed and is retained.** It confirmed the budget hypothesis: every
  executor stop came at 4.4–5.0 s of the proof's original five seconds.
  The attestation alone took up to 4.4 s; the fixture's whole proof took
  1.8 s. Step 5 passed a third time. The stop line now also reports the
  attempt's API calls and transport time per shared client, separating
  slow responses from limiter waits.
- **[Continuation run 6](../../test/results/adr196-continuation-native-6/environment.json)
  measured the cause.** Each executor attempt made 100–120 observer calls,
  with only 80–150 ms of transport time between them, so the time is all
  waiting on the limiter. The ADR-173 fixture's 71 calls used a synthetic
  connector source. The installed proof reads the guarded source six
  times, about 145 calls, which needs at least 6.25 s at 20 QPS.
  [ADR-199](199-executor-proof-source-reads.md) reads it once at each end
  of the proof instead. Step 5 passed a fourth time.
- **[Continuation run 7](../../test/results/adr196-continuation-native-7/environment.json)
  ran the first ADR-199 change.** The proof now reached its closing source
  read, but still at 4.45–5 s. The closing process observation's hub
  registration conversation was the remaining cost. ADR-199 decision 5
  makes the close local. Step 5 passed a fifth time.
- **[Continuation run 8](../../test/results/adr196-continuation-native-8/environment.json) passed.** Exit 0, all four tests,
  no cleanup failures, source unchanged.
  - The ADR-198 key service passes every check.
  - The regional connector enrolls with the full executor layout, and the
    join record matches the staged generation 1.
  - The executor's first cold proof fits its five seconds, and it composes
    from the settings it reads by name.
  - `installer-cluster-join` writes the slot exactly, and the hub-api
    restarts its process and accepts the entry.
  - The continuation replay after the bridge is unchanged.
- **Deferred.** The connector start reaching the owner and being refused
  for missing capacity needs a public preview request. It moves to the
  capture run with ADR-197. The publisher's topology pins must also gain
  the regional pin before a regional capture is published.
