# Validation and feasibility gates

**Current evidence:** documentation/source/release/licence inspection, local specification/dependency validation, isolated [packet/storage experiments](research/feasibility-packet-downloads.md), and [SQL/crash-path experiments](research/feasibility-control-crash.md). These include actual Gadget/K3s capture, selected filter/map/ring checks, S3/native downloads up to 2 GiB, PostgreSQL races/restart and a disposable-VM core helper with native debugger verification. **No complete EXP release gate, production performance, managed-cloud, GPU or no-egress qualification has passed.** The table below defines the full remaining acceptance scope.

## Phase-0 investigations

Implemented console component gates are `make console-install`,
`make console-check`, `make console-build` and `make console-browser-check`.
The browser gate uses actual packaged React and Go HTTPS handlers with an
explicitly synthetic session service; the separate `make identity-integration`
qualifies Keycloak/SQL/KMS session and current-request behavior. Neither is the
complete developer capture/investigation journey or a participant study. Exact
results and remaining scope are in [implementation progress](implementation-progress.md).

| ID | Experiment and setup | Required measurements / pass condition | If it fails |
| --- | --- | --- | --- |
| EXP-01 | Core interception in disposable Linux VMs running Kind and k3s; then two authorized managed services with ordinary managed workers | Read original core_pattern, kernel config/version, Yama, runtime limits and LSM; install/restore helper; SIGSEGV; nonzero pipe limit; crash storms; restart/upgrade/replacement; measure coverage gap and helper exit bound | Disable transparent cores on that node profile; keep cooperative recipes. Never change workstation/global sysctls through Kind. |
| EXP-02 | Pinned Gadget packet stream on Cilium with WireGuard + kube-proxy replacement and one other CNI | Checked pcap compiler, Service/Deployment/StatefulSet follow-map swaps, update continuity, segmented/frozen pressure, pod/veth/loopback/hostNetwork, dual stack, NAT, IP reuse, duplicate packets, node-local delivery, loss/counters and 1/10 Gbit/s overhead | Block production packet claim for profile; investigate upstream API/adapter before changing engine |
| EXP-03 | Network-header sanitizer and plain HTTP/1 reassembly corpus | IPv4 options/fragments, IPv6 extensions, VLAN, truncated/malformed frames, unknown protocols; network payload/body/credential markers never retained in their respective profiles; split headers, same-packet bodies, overlaps, malformed framing, upgrades, TLS/HTTP2 rejection; bounded parser CPU/memory | Affected profile cannot ship; do not relabel snaplen as safe HTTP |
| EXP-04 | Node files and commands against Restricted/distroless/userns pods | Path/magic-link races, PID reuse, blocking proc files, CRI exec credentials/cgroup/seccomp, timeout descendants, denied secret paths | Report unsupported adapter; no host-root fallback |
| EXP-05 | 2/8/100+ GiB synthetic cores and heaps on isolated nodes | Compression ratio, peak RAM/scratch, throughput, backpressure, probe/reaping/stop time, KMS/S3 outage, byte cap, incomplete-core analyzability | Reduce caps, disable large profile, document completeness tradeoff |
| EXP-06 | Native + Go + .NET runtime matrix | Exact image/build symbols; stripped/optimized variants; diagnostic-port/TMPDIR namespace; matching DAC; missing symbols; no internet | Gate runtime pack individually; preserve unknown stack details |
| EXP-07 | Python/JVM/Node/CUDA packs, GPU on authorized vendor-managed driver | Per-version crash/live capture, pause/memory overhead, optional env/flags, seekable scratch, CUDA dump open with matching debugger | Experimental/unsupported pack; no universal runtime claim |
| EXP-08 | Keycloak plus second qualified provider (proposed Dex with external step-up only if capable, otherwise another full OAuth provider) | Discovery, access-token audience, preregistered clients, workload federation, issuer/client mapping, MFA assurance, fresh group membership | Disable unsupported auth/share mode; no weak MFA/group fallback |
| EXP-09 | Official Go MCP SDK + two revision-specific generic clients | Same endpoint, load-balanced requests, auth challenges, outputSchema/text fallback, cancellation, explicit handles, private caches | Keep protocol compatibility gate open; no claim from release notes alone |
| EXP-10 | S3 reference backend + second S3 implementation + OpenBao | Streaming tamper/truncation vectors, wrap-only node policy, multipart fault/retry, conditional create, object versions, lifecycle/hold, deletion/tombstone restore | Backend unsupported for affected guarantee; never generalize AWS semantics to all S3 stores |
| EXP-11 | Hub + PostgreSQL primary/standby and two workload clusters, no broker | Enrollment, rollout to 1,000 target containers simulated/real mix, hub/API/SQL outages, duplicate delivery, SQL quota/serialization races, stale leases, lost COMMIT response, primary fencing, PITR, same operation recovery, index rebuild | Block production state/durability claims until transaction, recovery and failover invariants pass |
| EXP-12 | Sharing/authorization adversarial matrix including collection-time instructions | Sharing with otherwise ineligible colleagues works; unapproved issuers and identities outside the organization are denied; no neighbor counts/search leaks; raw still requires grant; pinned source/projection, bounded recurring registration, partial/raw-pending publication, lineage/counter races, parent/child revocation, membership removal/cursors/restores, multiple manager teams and creator departure | Block release; sharing is a security boundary |
| EXP-13 | Malformed evidence and hostile analysis images/files | Disabled script loading; no credentials/network; scratch isolation, escape attempts, decompression bombs; RuntimeClass qualification | Require stronger sandbox or disable affected parser |
| EXP-14 | Exact release images with public egress denied and attempted connections observed | Startup, timers, failure paths, symbol/registry fallback, all runtime packs; zero unexpected third-party requests; repeat after upgrades | Remove/disable offending feature/dependency; firewall denial alone is not success |
| EXP-15 | Go pprof CPU/heap/allocs/goroutine/block/mutex and optional runtime profile packs | Correct localhost netns/target, missing endpoint, disabled sampling, busy profiler, cancellation, GC off by default, units/mapping/label redaction, baseline identity and authorization | Gate the affected profile type; no fake zero-contention result or cross-artifact authorization bypass |
| EXP-16 | Automated permission management with real Kubernetes/IdP controls | Kubernetes apply/dry-run/conflicts/status and GitOps health; delegated writer escape; namespace/workload metadata guards and bootstrap review; namespace recreation/ownership changes; named pod exec SAR/create vs get; admission/container restrictions; exact subject mapping; source outages/freshness; forged submission/GitOps actor; historical evidence audiences | Disable unqualified source; no inheritance claim from schemas or mock authorizers |
| EXP-17 | Task-based usability and accessibility | Unfamiliar admins/maintainers complete enrollment diagnostics, new-namespace inheritance, preset capture/policy, partial-result recovery, grant renewal, share/revoke and MCP handoff; measure active effort/errors, keyboard and screen-reader behavior | Fix mandatory workflow blockers; no production ergonomics claim from a developer demo |
| EXP-18 | Privacy/retention fault matrix | Global/local caps; unknown/special-category classification; acquisition/ring age; slow upload; derivative lineage; clock skew; tightening/hold rules; versions/replicas/offline spools; immutable-lock conflicts; early erasure/restriction; PostgreSQL backup/WAL and restore gating; HTTP/ring copy deadlines; external-client disclosure boundaries | Block affected sensitive collection; report overdue/unknown deletion and processing restrictions, never a false compliance guarantee |
| EXP-19 | Storm admission, resource fairness and quota recovery | Multi-replica/multi-policy trigger flood; workload rate counters across roll/restart; helper prompt rejection; CPU/scratch/runtime impact; fair upload and context service; protected allocations; SQL transaction/local CAS race, deadlock/retry/failover; uncertain multipart/deletion; full account and namespace proliferation | Block expensive collection or capacity-isolation claim until invariant, fairness and failure tests pass |
| EXP-20 | Guided diagnostic selection and finite reconnaissance | Process reload/reuse/ambiguity; profile prerequisites; protocol-on-unusual-port/TLS/unknown; PID/socket and Service/NAT ambiguity; empty/truncated/bursty samples; retained-rate ring arithmetic; survey storms; permissions/revocation/expiry; untrusted evidence and UI/MCP parity | Disable unqualified inference/classifier; report uncertainty, never widen capture or claim complete coverage |
| EXP-21 | Capture-profile publication, composition and reuse | Real CRD immutability/identity/availability, namespace isolation, typed edits, endpoint rewrites, context deduplication, expensive conflicts, aggregate quotas/schedules, browser/MCP parity, version-pinned history and usability | Block affected composition/publication feature; never silently substitute versions or omit expensive actions |
| EXP-22 | Qualified syscall tracing and analysis | Pinned engine/kernel/ABI, fork/exec/reuse and mixed runtimes, no-read metadata secret corpus, bounded event/map/ring overhead, loss/error pairing, pre-read grants, argument limits, raw share/query/expiry and packet coexistence | Disable affected mode/node profile; no ptrace fallback or payload-bearing metadata |

These investigations require maintainers to approve paid cloud/GPU resources before creation. Prefer GKE Standard and an EKS managed node group or AKS standard pool for the two managed-provider tests, then assess Autopilot/Auto Mode separately. Do not claim support based only on a managed brand name. Region, budget, shutdown owner and spending cap must be concrete before provisioning.

## Test layers

1. **Contract validation:** local links, schema metaschemas, examples, IDs, state-machine invariants and tool catalog. Run in this documentation phase.
2. **Unit/property/fuzz:** selector ownership, CRI log assembly, expression budgets/Unknown states, path parsing, packet sanitization, canonical digesting, manifest parser, grant budget arithmetic, share projections, cursor tamper, event sanitization. No network required.
3. **Controller integration:** real API-server/etcd test environment for admission, resourceVersion races, status ownership, leader/fence behavior, finalizers and restore handling. Mocking client-go alone is insufficient for concurrency claims.
4. **Component integration:** real PostgreSQL 18 with transaction isolation/constraint/migration/failover tests (not SQLite), local S3/KMS/IdP services, exact SDK clients, encryption vectors, conditional writes, outbox retries and raw-query isolation.
5. **End-to-end:** disposable VM-backed clusters, synthetic Deployment and StatefulSet, external trigger → evidence → analysis → hub → MCP → share → revoke → expire; assert namespaces remain Restricted.
6. **Fault/security/performance:** kill/restart each service at commit boundaries, corrupt evidence, revoke during result delivery, break clocks/network, flood detectors, fuzz binaries/pcaps, measure resource/latency budgets and no-egress behavior.

## Complete-path availability

The `go-check` gate runs every non-Kubernetes package once and discovers the
Kubernetes package's complete top-level test, fuzz-seed and example inventory.
It runs sequential groups of at most forty whole parents, retaining subtests,
`-race`, `-count=1` and the original fifteen-minute aggregate limit for each group.
Actual run/terminal events must cover the selected names exactly once. Existing
skips are reported; omitted or duplicate execution fails. This avoids an aggregate
timeout as the package grows, without extending any runtime authority deadline.

GitHub Actions (`.github/workflows/ci.yml`) runs the same gate on every push as
ten jobs: `check-go-tests.py --shard 0/10` runs every non-Kubernetes package,
shards 1–9 a deterministic, duration-balanced partition of the discovered
Kubernetes inventory (`scripts/go-test-durations.json`, measured on CI; unknown
tests weigh five seconds). Pushes that change only documentation outside
`docs/interfaces/`, recorded results, the design prototype or root Markdown run
only the documentation and schema gates. Each shard keeps the flags, groups and exact event checks above; the
partition is unit-tested to cover the inventory exactly once. The documentation,
schema, SQL, Helm and console gates run as parallel jobs. Native suites run only
on dispatch (`native.yml`, suites from `scripts/ci-native.sh --list`), each on a
fresh runner; their `test/results` output is uploaded as a run artifact. A CI run
is recorded like a local run: run URL, exit, selected tests and the harness's
source hashes.

`main` accepts changes only through squash-merged pull requests (repository
ruleset `protect-main`: no direct push, force push or deletion; review threads
must be resolved). The ruleset requires the `ci-ok` job, which passes only when
every CI job passed or was skipped as documentation-only. Native suites can be
dispatched on a pull request branch with `gh workflow run native.yml --ref <branch>`.

For local debugging, `scripts/test-context-storage.py --keep-on-failure` leaves
a failed run's own clusters and labelled containers (and the Go fixtures'
objects) running and records them in a manifest under the build cache;
`--cleanup-kept MANIFEST` later removes exactly those resources after checking
each name or label against the run, and writes
`test/results/kept-cleanup-<run>.json` as the cleanup evidence. A kept run is
never a qualification result. The direct-observation suite
(`scripts/ci-native.sh direct-observation`, about eight minutes) covers every
regional capacity purpose, including the combined guarded workload, without
the full installation replay.

S-01/S-02 qualification includes the actual installed constructor and every
nested authority/provider read on its successful path. Passing isolated
components does not establish that their composition can finish. The recorded
[native observation failure](../test/results/regional-observation-native-cost-test.log)
is an expected-denial regression, not a successful routing result.

Before an expensive native run, count requests by the actual shared API client
and rate limiter, including shallow copies, probes, source reads, retries and
background observers. Keep source-derived lower bounds separate from measured
latency. A full token bucket needs at least `max(0, requests - burst) / rate`
seconds to admit that request count; aliased clients share one bucket. Provider
calls, SQL waits, decoding and transport time still consume the same original
operation interval. A constructor which substitutes another client or bypasses
these reads cannot qualify the installed path.

Run successful installation, readiness and two-cluster investigation paths with
the production limits and original deadlines, first at startup and then with
normal reconciliation, renewals and shared-client activity present. Record
per-leg elapsed time, remaining original validity, actual request counts and
pool acquisition waits. A single idle/full-burst success is not sustained
availability. Classify unsupported load separately; do not present ordinary
work as supported if its required prerequisites perpetually expire.

When reorganizing checks, verify actual current reads before and after blocking
locks, the independent final native check, changes at each effect boundary,
cancellation, and unknown write disposition. An operation-owned observation
retains its original end; a returned correlation ID, later ordinal or repeated
method call cannot renew it. Partial effects remain accounted for after final
validation fails. Qualification must demonstrate both useful completion and
safe refusal; increasing test-only rates or replacing real checks with fresh
fixture timestamps proves neither.

## Reference acceptance runs

- Native SIGSEGV preserves encrypted core and metadata; exact symbols produce a bounded backtrace. No core after SIGKILL is an expected, explicit result.
- Log regexp match plus CPU/memory/PSI condition triggers a file/log/network snapshot and pre-authorized diagnostic once.
- Probe failure under Event loss reports detector uncertainty and preserves available context.
- Packet capture intersects pcap syntax with IP/label/Service/workload peers, follows generations without restarting healthy hooks, bounds segmented snapshots and retains only the selected network/HTTP/raw representation.
- Distroless workload reports unavailable tools while generic `/proc` evidence succeeds where supported.
- Second cluster disconnects: local allowed evidence remains durable; hub shows stale state; intrusive permit expiry is enforced.
- A normally ineligible user/group within the organization reads only shared artifacts; an external identity request fails; raw access requires separate approval; revoke invalidates cursor and in-flight delivery.
- An administrator-created namespace automatically assigns its configured owner group; a forged annotation or copied ownerReference does not.
- An exec-authorized user can collect only from approved pods, with intrusive grants still enforced; no admission-policy bypass or historical evidence expansion occurs.
- Storage/KMS/audit failures never cause plaintext fallback or falsely complete evidence. Restored backups do not resurrect expired/shared access.

## Required evidence format

Every run records repository SHA/tree, dependency/image/gadget digests, kernel/provider/node/CNI/runtime versions, cluster ownership, command and actual exit status, configuration, dataset generator seed, timestamps, pass/fail/unsupported findings, raw counters and cleanup status. Logs contain synthetic data only. Keep a capabilities result per node profile; do not collapse mixed results into a single green badge.

An environment-support label requires a fresh end-to-end run and all applicable gates. A documentation assertion, a mocked test, a cached image or passing traffic alone is not deployment/feasibility proof.

## Collection-time sharing acceptance (EXP-12)

Use two clusters, synthetic recipient/owner/approver identities and controllable time. Exercise browser, preset/expanded Kubernetes and enabled MCP capture paths. Verify collection-only users cannot attach sharing, submitters cannot forge owners/status, default approved extracts exclude raw, and exact plan/projection changes require a new decision. A pending raw selection must not block approved extracts or imply that raw is shared; recipient raw-query approval remains separate.

Race duplicate capture registrations against the last available recurring slot and child publications against the artifact/global share limits. Restart SQL workers around each transaction commit, audit write, lease claim and local staged handoff. Failed/ambiguous accepted captures consume their slot; retries and overlapping selections do not double-charge artifacts. Require unambiguous limits and visible SharingCapacityUnavailable, with independently authorized collection still usable. Inject foreign-capture parents, unavailable/cyclic lineage, wrong projection/configuration digests, classification mismatches, case re-grouping and analysis requested after the plan was accepted; reject automatic disclosure.

Exercise late approved analysis during Draining, outputs after expiry, individual child tombstones, instruction/approval revocation concurrent with delivery, suspended owner authority, explicit resume, policy edit/pause/delete, GitOps reapply and old backup restore. Stop preserves registered output publication within expiry; Revoke denies dependent access before child cleanup. No empty-case discovery, neighboring occurrence/count leak, plaintext export, retention extension or permission escalation is permitted. Test SQL active-row/cardinality ceilings, bounded GC/replay state and the separate 128 KiB local CRD ceiling. These are planned runtime checks; the local validator checks fixture shape/provenance and selected invalid cases only.

## Usability acceptance protocol (EXP-17)

Recruit at least three administrator and three application-maintainer participants unfamiliar with the implementation. Use synthetic clusters/accounts and allow the shipped documentation, not an implementation engineer guiding every action. Record the denominator and unsuccessful attempts; six participants is formative coverage, not statistical proof of usability.

Measure active task time, total elapsed time, required inputs, administrator handoffs, errors, documentation visits, abandonment and whether the participant correctly identifies target scope, privacy impact and expiry. Separate infrastructure install time, human approval waiting and background collection. Goals after prerequisites: first context capture <=3 minutes active effort; extract share and agent handoff <=2 minutes each; no administrator ticket per eligible new workload and no manual digest/UID entry. Report distribution and failures, not only an average of successful attempts.

Include capture-time sharing with delayed extracts, a pending raw selection, explicit recurring limits, and the participant explaining Stop versus Revoke. The owner should not need to return after analysis to finish an already authorized share.

Test both browser and kubectl/GitOps paths, a Deployment and StatefulSet, a pod with app, sidecar and ephemeral sources, partial evidence, stale source, denied grant, expired artifact and failed deletion. Check keyboard-only completion, accessible names, focus restoration, form error association, non-color-only status and screen-reader announcements. A profile endpoint suggestion must not start a profiler. A retry must not repeat an uncertain intrusive action.

## Privacy acceptance protocol (EXP-18)

Use controllable clocks and synthetic user markers. Verify maximum/read-cutoff/delete-deadline arithmetic independently of upload completion. Exercise copy registration failure, slow multipart completion, expired pre-trigger data, derivatives with multiple parents, a query straddling expiry, deadline shortening during disconnection, and a longer replacement policy. Deny delivery on expiry or restriction even if a job/result cache already exists.

Inspect current/noncurrent versions, replicas, object inventories, node spools, tmpfs/encrypted staging, indexes, query caches and configured backups. Keep one node/replica unavailable and prove the UI cannot report DeletedVerified. Inject deletion failures until deleteBy passes; assert alerting and affected-profile collection pause. Restore old control/catalog snapshots and fail access closed until the authoritative lifecycle journal/current policy is applied.

Test ordinary holds against hard caps, disabled legal exceptions, independent legal review when enabled, and Object Lock/backup conflicts before and after policy tightening. Verify generic commands/file imports cannot downgrade known dumps and that unknown evidence uses conservative limits. External agent fixtures demonstrate delivery auditing and no claim of downstream erasure. These are required runtime tests; the current schema checker only validates example shapes and selected arithmetic invariants.

## Storm and quota acceptance protocol (EXP-19)

Flood workload A with 10,000 trigger matches/minute across 20 replicas and multiple policies while B/C submit fresh captures within their remaining protected allocations. Assert exact workload dump limits, bounded summaries/queues/API writes, no reset on rollout/policy edit, and no loss of B/C's protected storage. Test the same identities across node changes and a deleted/recreated workload under a finite namespace envelope.

Race reservations against the last bytes/object slots, interrupt every stage of parent allocation/dispatch/commit/deletion, and reconnect stale leaders/connectors. Assert conservation of pool allocations and committed-plus-reserved usage, no released unknown writes, no lost charges for old versions or multipart parts, and no reliance on eventually refreshed backend statistics. Induce hold/retention/deletion conflicts and verify only affected allocations pause unless backend health is globally unsafe.

Measure collector/helper CPU, target stop time, workload latency/probe impact, memory/scratch, bytes uploaded/retried and B/C service delay under overload. At equal weights and otherwise equal service constraints, continuously backlogged workloads should receive byte service within 20% over a 60-second healthy-network window; record packet/request overhead separately. Evaluate context/metadata latency separately and test that a large analysis does not block all workers. These are test targets, not established performance. Repeat with storage outage, a full spool, runtime profiler cancellation uncertainty and native crash storms in disposable VMs; never run kernel-global tests on the workstation.

## SQL recovery and team-management additions (EXP-10/11/12/18/19)

Use the proposed real PostgreSQL version, primary/standby and independent audit backend. Race grant/capacity/registration admission, revoke during publication/final delivery, duplicate operation keys with changed digests, transaction serialization/deadlock retries and lost COMMIT acknowledgment. Kill workers after SQL commit, object audit write and remote execution. No lock may span remote action/upload; SQL outbox alone cannot authorize dispatch. Drop NOTIFY, expire worker leases, fence the old primary and reconnect stale connectors; uncertain starts stay charged and are not blindly repeated.

Restore a backup before a revocation/consumed permit/deletion, replay finite WAL, and deliberately withhold independent checkpoints. Verify RecoveryBlocked/full authority invalidation, retained uncertainty, current config relist including deletions and no resurrection through stale CRD status. Inspect SQL and backups for synthetic evidence/body/reason/command markers that should exist only in protected evidence. Exercise finite backup expiry and migration expand/backfill/contract interruption. Record the failover durability model and measured recovery, not an unconditional RPO-zero label.

For team sharing, use two issuer-qualified owner groups, an outsider and the creator in two clients. Verify continued team management after creator departure, one-source loss versus all-manager loss, live group freshness, management-only minimal views, no recipient reshare, no forged assignment proof, raw self-approval rejection and explicit historical transfer with unchanged remaining counters/deadlines. Include a valid independent approver who belongs to a managing team.

## Packet update, ring and HTTP additions (EXP-02/03/17)

Run continuously numbered synthetic traffic while rotating Service slices, Deployments and StatefulSets. Compare healthy existing-hook sequence loss before/during generation swaps, measure new-hook attach gaps and per-node activation lag, and assert no ring reset. Cover dual stack, NAT, ready/terminating endpoints, shared backends, same-name recreation, IP reuse, selectorless/ExternalName rejection, watcher compaction/disconnection and map overflow. Verify filters are intersected, DNS operands rejected and unsupported compiler syntax fails without broad fallback.

Freeze rings repeatedly during a stalled upload; account all pinned/replacement segments, parser state and output slots. Inspect plaintext stages and decrypted retained outputs for unique synthetic HTTP body/credential markers. Include split headers, header+body coalescing, retransmits/overlaps/out-of-order packets, chunking/trailers, keep-alive/pipelining, upgrades, CONNECT, malformed Content-Length/Transfer-Encoding, midstream capture, gaps, oversized headers, HTTP/2 and TLS. Invalid/unsupported flows emit bounded loss/partial metadata, never raw fallback. CPU/state limits must hold during fuzzing.

Usability participants select an HTTP-header profile and live Service peer without typing YAML, describe actual vs configured ring history, and find the reason an unsupported hook/parser was refused. Administrators configure a database once and manage owner teams through their existing namespace/binding workflow.

## Full review regression matrix

The [ranked design review](reviews/design-review.md) and [tabletop walkthroughs](reviews/use-case-walkthroughs.md) are planning evidence only. Add these cases to the existing experiments before claiming the corrected behavior works:

| Gate | Added runtime checks |
| --- | --- |
| EXP-04/06/16 | Whole-pod sources with app/sidecar/init/ephemeral members; no container configuration; hostNetwork/hostPID rejection unless attributed; shared PID namespace sandbox exclusion; same-path files across roots; partial-container exec rights cannot become pod authority |
| EXP-11/17/19 | 20-replica workload with an unready failing 17th replica; observation overflow/scale-up/attach gaps; capture maxPods independent; rings/parser budgets do not disable cheap sensors silently |
| EXP-08/11/12 | Manual capture with no policy; foreign capture UID denial; grant renewal/pause/sharing edit preserve only collection scope; source/executor/recipe/action changes invalidate it; longer approval periods do not lengthen leases or future sharing |
| EXP-05/06/19 | Logical executable/runtime and descendant selectors across reload, PID reuse, parent exit and overlapping roots; multi-process pre-start reservation, too-many/no-match refusal, total stop deadline, mid-batch failure and distinct snapshot times; no extra worker added after resolution |
| EXP-11/19 | Pod/workload correlation, true-at-activation, Unknown/reset, level sample versus transition counts, replayed events, correlation boundaries and contributor selection; DST repeated/skipped minutes and no catch-up |
| EXP-02/03/19 | Sensitive observation wire-byte/session budgets before parsing, sensor restart/lease renewal cannot refill; raw predicate on sanitized output still needs authority; before/after zero, output versus frozen caps, quiet watch and independent progress failure |
| EXP-09/17 | Generic agent discovers target/diagnostic, previews without collection, requests by handle, polls partial/approval outcomes and cancels; foreign/stale handle, duplicate-key-after-expiry, differing request Conflict and recipient-only inventory denial |
| EXP-10/11/18 | Absolute metadata maximum minus residual backup/WAL horizon and cleanup margin; overlapping backup chains/slots; no expired bytes in managed index snapshots/segments; early deletion destroys/rebuilds affected cohorts; unknown copies cannot report verified deletion |
| EXP-06/07/15/17 | Mounted/writable-layer/deleted binary differs from OCI image; companion bundle authority/quota/deadline; exact private symbols unavailable after target deletion; expired baseline and analysis-only retry |
| EXP-17 | Approval waiting preserves independent context; pod-wide fanout cost is understandable; configured readiness is distinguishable from actively verified qualification; longer collection approval and independent sharing expiry are visible |

Canonical scope normalization needs shared Go/admission/client vectors for set ordering, duration/quantity normalization, unknown fields and included/excluded control fields. The offline Python scope fixtures validate a deliberately explicit subset; do not advertise cross-language canonicalization from them. Trigger regexp/CEL, cron/timezone and pcap compiler tests use the exact production libraries, not a Python regex approximation.

## Guided diagnostic acceptance protocol (EXP-20)

Status: **NOT RUN**. Use synthetic workloads and evidence only. Run SC-GDE-001–006 in addition to the existing packet/process/permission/retention gates. Assert identical evaluator output for equivalent browser and MCP requests, stable catalog/dependency binding, no acquisition by passive planning, and idempotent survey submission. Verify flow/process pagination and each source permission independently.

Exercise two interpreter applications with identical executable names; worker reload/PID reuse; qualified versus missing pprof; native OOM without a core; shared/inherited sockets; a preexisting TCP connection; UDP; HTTP on a nonstandard port; TLS with absent/client-only handshake; two Services selecting one backend; NAT and supported loopback; hidden peer metadata. Wrong or absent evidence must yield specific uncertainty, not a misleading confirmed label.

Replay the same sample under raw/header/HTTP projections and narrower filters to validate sizing inputs. Check the 36 MiB versus 16 MiB/12 s example, zero rate, incomplete samples, saturated output/observation rates, many replicas on one node and burst-after-survey gaps. Attempt repeated starts from multiple users/agents and loss of cancellation connectivity. Validate encrypted copies and cleanup deadlines for samples, analysis outputs, pages and recommendations; expired/revoked inputs and malicious evidence strings cannot disclose data or start tools.

Under EXP-17, an unfamiliar eligible maintainer should reach a useful preview for each initial goal within three minutes of active effort, without entering a PID, hash or filter expression. Measure classification correctness and uncertainty labeling on a labeled fixture corpus; publish per-protocol coverage/false-positive results and block any confirmed-protocol path that fails its qualified corpus. These targets and experiments are not implied by passing spec-check.

## Capture history and repeat acceptance

Status: **NOT RUN**. SC-HIS-001–004 extend EXP-11/12/17/18/19. Test the same workload across replica rolls; recreated namespaces/workloads; equivalent matchLabels ordering and different selectors matching the same pods; several recipe/filter variants; failed/partial/pending requests; policy/discovery origin filtering and storm volume. Check SQL query plans and bounded authorization-filtered pagination at the history caps without hidden counts.

Restore settings after a mutable recipe update/deletion and verify exact pinned versions or an explicit blocker. Exercise expired selectedPID/Pod, triggeringPod conversion for manual repeats, changing peer UIDs, current retention/budget clamping, revocation between list/preview/submission, new maintainers versus retained audience, and share-only access. Repeating a capture must not copy its ad hoc grant, sharing authority, credentials or counter capacity. Lost responses/double clicks yield one new operation; another intentional repeat is new and remains storm-limited. Indeterminate old execution is never auto-retried.

Delete evidence before configuration expires, then expire configuration before the summary; prove independent availability without retrieving expired copies. Test evidence-derived settings lineage across repeated requests, snapshot write timeout, history-cap eviction, object versions/cleanup and backup restore. None may delete live charges or extend source retention. MCP large-settings handling retains normal byte limits while repeat-by-reference remains usable. Measure the EXP-17 target of a repeated context preview within 30 seconds of active effort; it is not established by offline fixture checks.

## Capture-profile and syscall acceptance (EXP-21/22)

Status: **NOT RUN**. Local schema/example/fixture expansion checks are separate from these runtime and participant gates.

- Publish builtin/organization/namespace profiles; attempt name shadowing, duplicate version, in-place definition mutation, UID replacement, unavailable/deleted source, forged publisher and stale/disconnected catalog. Verify current source/permit rules and no implicit grants.
- Compose eight components with typed overrides; exercise at/over sixteen expanded actions, endpoint rewrite collisions, dependency cycles, duplicate independent snapshots, duplicate profilers with renamed bindings, incompatible serial deadlines and combined ring/parser/fanout pressure. Compare browser/MCP expanded digests and sharing aliases; inspect actual SQL/local reservation spend.
- Replay pinned composition history after upgrades, source disablement and parameter expiry. Publication must not persist captured values or credentials into Kubernetes. Saving a derivative retains no execution/share grant.
- Trace synthetic all-pod workers across fork/exec/reload/reuse/termination and ABI variants. Verify metadata does not read a credential buffer, not merely that output redacts it. Measure CPU/RAM/maps, rate admission before argument reads, failed-read charging, timeout/revocation, rolling/frozen memory, cross-workload fairness and loss counters under overload.
- Inspect raw and projected artifacts through browser/MCP with share/cursor/revocation/retention changes. Summary/events omit arguments and pointer returns; raw queries have scan/output/grant caps, no code execution and no new live reads. Exercise failed/nonreturning/unpaired calls without invented duration or success.
- Run the profile usability tasks in [ergonomics review](ergonomics-review.md), including incompatible components, unavailable HTTP/TLS/pprof capability and namespace publication without an administrator ticket.

## Action lifecycle acceptance (EXP-02/17/19/21/22)

Status: **NOT RUN**. Contract classification checks are not proof of running source behavior.

- Before any trigger, verify packet/syscall hooks are armed on the admitted observation pod set; no core/command/live profiler has run. Sensitive sources stay blocked until acquisition approval. A one-pod incident cap does not limit recording to one replica.
- Trigger while a source is warming, ready, lost, out of observation budget or at snapshot capacity; preserve correct t0 windows/coverage and independent context/dump outcomes. Delay event delivery, approval and upload without extending post-windows.
- Send duplicate and rapid distinct triggers; prove stable source identities, bounded snapshot counts/copy-on-write memory, one saved operation per admitted occurrence and no repeated process stop after ambiguous dispatch.
- Run beyond an incident action timeout with no trigger; an ongoing source remains under its separate finite source permit, whereas a finite session stops at its own bound. Exhaust a sensitive grant with no uploaded evidence; it must still stop.
- Pause/delete/revoke the policy versus cancel one incident; verify different stop scopes and cleanup of unsaved rings. Roll pods/nodes/controllers and ensure fresh source epochs and honest Warming/history gaps.
- Exercise manual Collect now, explicit post-trigger-only surveys, history repeat, a natural crash with local permit and an unrelated health event with no core. Measure whether unfamiliar users correctly distinguish ongoing cost from trigger-time cost.

## Impact and handling assessment acceptance (EXP-17/18/19/21/22)

Status: **NOT RUN**. REQ-ASM-001–005 add the following runtime/participant gates; schema/fixture arithmetic is not production impact evidence.

- Compare matching, mismatched and missing benchmark/runtime/kernel/CNI records and fresh/stale/missing metrics. Preview must perform zero application reads, attaches, surveys or mutation. Qualification records retain workload-rate/parameter/environment applicability; do not report a fixed CPU/latency estimate for arbitrary commands or environments.
- Measure baseline, individual mechanisms and permitted combinations under controlled load. Record application pause/CPU/latency/probe effects separately from collector/kernel resources, buffers, disk and upload. Assess repeatability and uncertainty; publish numeric ranges only for qualified conditions. Verify warning calibration and retire misleading rules; production before/after correlation alone is not causal evidence.
- Use 20 observed pods with a one-pod incident cap, memory versus disk rings, shared per-node buffers, concurrent versus serial schedules and existing authorized aggregate pressure. Compare scoped preview quantities with actual reservations; configured caps are not total-resource or expected-use claims. Known conflicts remain blocked; missing coexistence measurements remain visible.
- Change scope, options, capability rules, headroom and retention between preview/submission/arming/dispatch; check stale-material-warning refresh and current admission without recurring policy approval churn. Repeat history after workload growth; never restore an old safety verdict.
- Use synthetic raw cores, sampled pprof heap/CPU, approved HTTP headers, network/syscall metadata/arguments and unknown files/commands. Confirm retained/transient distinctions, no scanner-derived nonpersonal claims, shorter requested expiry, mixed deadlines, pre-trigger anchors, overdue cleanup and preservation restrictions. Sharing one extract reveals no hidden parent's notice. Direct agent queries still return handling reminders.
- In EXP-17, ask participants to explain combined impact/unknowns, ongoing versus incident scope, limits versus estimates, possible user data, access cutoff versus verified deletion and external-copy limits. Offer one less disruptive alternative with stated coverage loss. Failure to understand a consequential warning is a usability defect to fix and retest, not solved with more repeated checkbox dialogs. Check browser/MCP/GitOps parity and accessible, bounded rendering.

## Final review regressions

Status: runtime cases below **NOT RUN**. Offline schema/semantic results are recorded separately. These extend existing experiments rather than create a new test framework.

| Experiments | Additional required evidence |
| --- | --- |
| EXP-01/05/11/19 | Natural-core pipe helper has bounded refusal with SQL/API/KMS/object-store outages; pool depletion, reboot and uncertain consume cannot wait remotely, reuse a data key or refund unknown spend. |
| EXP-04/11/16 | Approval wait plus pod replacement/node boot; production resolver/controller/worker agree on podBindings canonical bytes; manual grants cannot authorize replacement while dynamic policy semantics remain intact. |
| EXP-02/19/22 | Exit-event delay, source grace, replacement churn, revocation/pause, node loss, capacity pressure and history eviction. Separate full prehistory from partial post-window. |
| EXP-11/13/18 | Under accepted ADR-036, prove encrypted scratch handoff with old writer stuck, node partition, malicious output links/special files, failed CSI deletion/snapshots, expiry and restart. No concurrent writers, plaintext untracked backups or premature verified-deletion claim. |
| EXP-13/18 | Synthetic canaries in child stdout/stderr, error/termination/panic paths, worker core/swap and hostile analyzer output. None reach ordinary logs/events/catalog; protected diagnostics inherit deadlines. Inspect host-handler behavior, not only RLIMIT_CORE. |
| EXP-04/11 | Resource formulas with known synthetic counters; reset/zero denominator/partial ancestor coverage; standard webhook repeats, distinct startsAt episodes, mixed group statuses, out-of-order resolution, truncation and bounded dedup state after restart. |
| EXP-17/19 | Users can explain absent captures and choose scoped suspension without deleting evidence or disabling privacy cleanup; report disconnected stop deadlines and actual node acknowledgments. |

Save existing recordings now has an accepted contract under REQ-SAV-001–004, but remains unimplemented. Trigger replay UI and a storage-free sandbox remain outside the first-release contract. No documentation test advertises runtime support.

## Recording-save and encrypted-analysis acceptance

Status: **NOT RUN**. These extend EXP-02/11/12/13/16/17/18/19/22 and do not authorize a live collector on the local workstation.

- Prove policy opt-in participates in the real resolved digest/defaulting and cannot retroactively authorize old sessions. Validate preset/composition/expanded structural CRDs, current requester scope plus original policy executor/grants, share-only denial, metadata-only generation changes and immediate connected revocation.
- Instrument dispatcher calls: saving a mixed packet/syscall/liveCore/command recipe must make only snapshot calls. Reject alternate preview kinds, arbitrary parameters, source IDs, future windows, mixed policies, duplicate epochs, cap excess and stale handles before new collection.
- Exercise ring rotation, warming, stopped-source grace, pod/node boot replacement, old t0 during delay, bounded clock uncertainty, source permission expiry, cancellation, exhausted workload budgets, concurrency and crash-recovery with uncertain admission. Retries never reset windows, charge twice or restart a recorder.
- Verify original source acquisition/deadlines and retained-audience intersections, newly joined/removed teams, per-principal raw reads, optional per-capture sharing and exclusion from policy recurring SharingIntents. No new creator grants evidence access.
- Browser/MCP use one evaluator; test inventory/preview disclosure, existing submit/poll/cancel, metadata byte limits, scoped history/settings, and repeat with fresh selection. A shared recipient cannot enumerate live recordings. Measure task completion with unfamiliar maintainers; no manual digest entry or per-click approval when reviewed scope covers it.
- Qualify accepted encrypted StorageClass configuration per region: separate input/output PVCs, fenced writer termination/unmount, read-only mounts, bounded aggregate capacity, CSI key/reclaim/snapshot behavior and independent deletion during worker/controller/node failures. Verify secondary log/core/swap handling. Ordinary collection remains available when analysis readiness fails, with actionable status and no silent unencrypted fallback.

The offline checker validates schema shapes, cross-fixture identities, window/budget constraints and prohibited argument classes. It does not prove any live grant, Kubernetes admission, storage provider, source identity race or exact deletion guarantee.

## UX and interface design checks

`make design-check PYTHON=<development-validator-python>` checks screen/domain/journey links, implemented prototype routes, no network/storage APIs in the mockup, complete browser operation inventory, exact input/output parity with all MCP tools, local schema references and JSON Schema validity. The [OpenAPI](interfaces/browser-openapi.yaml) is a design contract; this gate alone is not a production HTTP conformance test.

`make ui-check` uses development-only `playwright-core`, `axe-core` and Chromium. Set `ASSERVAT_QA_NODE_MODULES`, `ASSERVAT_CHROMIUM` and optionally `ASSERVAT_UI_URL`; serve the static repository on loopback as described in the [UX entrypoint](ux/README.md). The script checks all screens/states, desktop/390px/320px layout, representative user journeys, role-negative views, modal focus return, hidden-by-default prototype controls, essential review facts with optional sharing disclosure, contextual navigation, state-specific live controls, stable focused live rows, no external requests, and WCAG-tagged automated scans. It records [prototype results](ux/prototype-validation.json) and screenshots. These tools are not product dependencies.

Manual supported-browser and screen-reader testing, authentic role enforcement, OIDC, Kubernetes writers, product collector/deletion/encryption qualification, integration performance and user task studies remain **NOT RUN**. Separate packet/core/storage mechanism samples are recorded below; they do not qualify these product workflows. An automated accessibility scan is not certification or proof of task usability.

Optional full OpenAPI validation: install `openapi-spec-validator` in a development-only environment and run `make openapi-check PYTHON=<that-python>`. The script bundles canonical references locally for validation without fetching schema URLs. This checks the OpenAPI document format and schema relationships, not an implemented HTTP server.

## Live-watch design and runtime verification

`make live-check PYTHON=<development-validator-python>` checks the approved-only schemas and synthetic timeline/source/revision/expiry/accounting constraints, including rejected raw body/bytes/arguments, unsupported filter fields/operators, oversized selection/batches, changed lifetimes and stale scope. `make spec-check`, `make design-check` and `make openapi-check` include the new canonical schema, fixtures, domain mappings and five shared operations. The prototype browser gate additionally checks real local row updates, pause/filter/resume, close/access-loss clearing, source selection, explicit gaps and mobile live-view layout. It remains synthetic data with no collector.

Runtime qualification remains **NOT RUN**: multiviewer/sensor storms and rare-match scan work; protected incident upload under viewer saturation; precise cursor retry/empty-heartbeat progression, source rotation and source identity replacement; authorization revocation between projection and delivery; paused/offline row expiry; region restrictions; output spend and per-client quotas across hub failover; no sensitive bytes in SQL/logs/metrics/browser storage; API and both MCP-profile conformance. Verify an empty fully observed interval is distinguished from a disconnected/unknown interval. Measure overhead against no-viewer and maximum-viewer baselines before publishing support.

## Implementation architecture checks and qualification

Native downloads add `make download-check`: strict preparation/status/cancellation fixtures, unknown-destination rejection, safe filenames/authenticated paths, local-copy notices, terminal-session handling and multi-GiB raw-grant requests without widening query-only limits. These are synthetic DTO checks. SC-DLD-001–004 additionally require real native files opened in Wireshark, compatible debuggers with exact companions and other relevant local tools; authenticated range/resume, corruption, expiry/revocation, no plaintext spill, transfer fairness and user task studies. The isolated lab opened a real Gadget PCAPNG in tshark after encrypted S3/TLS delivery and tested bounded 2 GiB ranges plus local corruption/authority failures. A later VM core experiment encrypted/decrypted actual generated cores and opened them in GDB with the exact fixture executable. Production OIDC/SQL/relay paths, complete core/profile transfer workflows, GUI/local-tool user journeys and fair scheduling remain **NOT RUN**. See [packet/download scope](research/feasibility-packet-downloads.md), [core scope](research/feasibility-control-crash.md) and [the missed-workflow correction](reviews/local-investigation.md).

`make architecture-check PYTHON=<development-validator-python>` checks the [architecture catalog](architecture/catalog.yaml): unique role/component/interface IDs, allowed acyclic dependencies, layer restrictions, complete primary ownership of domain entities and requirements, and linked contracts. It validates strict internal-work DTO examples, rejected invalid inputs and a small synthetic model of ambiguous starts and stale receipts. The report is [architecture/validation.json](architecture/validation.json). Run it with `spec-check` and `design-check` when changing these boundaries.

These checks do not inspect production Go imports, authenticate a peer, verify a signature, exercise Kubernetes CAS or prove distributed fencing. The [implementation slices](architecture/implementation-slices.md) assign those runtime gates. Before enabling a mechanism, qualify real role credentials, peer/boot identity, receiver deduplication, cancellation and unknown starts, protected capacity, object verification, deletion, and the relevant kernel/runtime or encrypted-volume path. Add the actual Go import-graph gate when production code exists. All these runtime checks remain **NOT RUN**.

## User-outcome regression protocol

The [user-task review](reviews/user-task-review.md) is expert inspection, not participant evidence. Extend EXP-17 with non-lead developers, on-call engineers and evidence recipients: finish a local Wireshark/GDB investigation, wait for a rare failure, locate a support timestamp, repair missing symbols, correlate two services and read evidence after the failed pod disappears. Record unassisted final outcome, total wall time (including reviews/queues), active effort, handoffs, missed evidence and recovery; active-time targets cannot excuse an unfinished investigation. Participant trials remain NOT RUN.

`make investigation-check` validates paired synthetic request/grant/result examples and rejects inconsistent scope/parent/client/deadline bindings. Combined approval must additionally pass full product result registration, shared-budget consumption across clients, commit-before-access recovery and revocation-during-download tests. `make ui-check` exercises relevant optional settings and immediate recording save. Separate labs tested a bounded ring model, in-memory transfer authority, native tshark/GDB opening and simplified real-SQL child registration/shared counters. Complete product latency/ring preservation, combined approval/audit/identity and participant outcomes remain NOT RUN. No schema or screenshot count substitutes for these outcomes.


## Technology-selection evidence and pending gates

The [isolated dependency experiments](../experiments/technology-selection/README.md) record actual Go tests, frontend build, TypeScript generation and failed Go-generation/version-resolution attempts. They do not replace EXP gates. The [technology research](research/technology-selection.md) adds explicit pre-freeze qualification for large native-range artifact layout, parser/schema parity, real libpcap-to-Gadget filter integration and the React dependency set. Use the [build/reuse matrix](architecture/build-or-reuse.md) when assigning implementation/qualification owners; all 24 components retain their existing requirements.

## First mechanism spikes: partial evidence, 2026-10-09

The [lab and reproduction instructions](../experiments/feasibility/README.md) retain final command exits, source hashes, failed assumptions and cleanup records. Eleven ordinary Go tests passed with the race detector; three explicitly opt-in measurement tests each passed separately. The VM kernel filter corpus passed all 11 libpcap-generated cases. Gadget's own compiler rejected one valid IPv6 case, so a successful comparison-test exit is not compiler parity.

| Gate | Measured subset | Still required |
| --- | --- | --- |
| EXP-02 | Real Gadget pod PCAPNG and explicit VM loopback; standalone endpoint map replacement without reattachment; sampled native compiler/kernel behavior | Integrated Gadget bytecode/maps/event generations, supported CNI/IPv6/loopback/hostNetwork profiles, loss/impact and production watch freshness |
| EXP-05 | Incrementally generated 2 GiB stream; encrypted staging, peak RSS and native high-offset/full retrieval | Actual core capture, 8/100+ GiB, diagnostic-shaped compression, workload pause/reaping, pressure/outage and completeness |
| EXP-10 / SC-DLD-003 | Real S3 multipart/ranges; Tink/zstd authenticated frames/index; TLS native PCAPNG; tamper/cancellation, local grant expiry/revoke and final-checksum regression | Ceph/second qualified backend/OpenBao, conditional commit/restore/copy ledger, real SQL/OIDC, relays, slow readers and native core/profile files |
| EXP-19 / REQ-NET-003 | Bounded payload/framing ring model under 100,000 writes and 10,000 refused overlapping saves, with race checks | Real source/queue/metadata accounting, node/workload fairness, SQL reservations, capture overhead and upload/deletion failure recovery |

The storage fixture is SeaweedFS for testing, not a replacement production selection. That first lab does not qualify HTTP sanitization, syscall collection, files/commands, crash interception or SQL concurrency. Subsequent SQL/core evidence follows; all full EXP gates remain open.

## SQL and crash-path spikes: partial evidence, 2026-10-09

The [second lab](../experiments/control-crash/README.md) retained 14 passing race-tested Go tests, one separately passing post-restart test, and 14 passing VM crash cases. It preserved the intentionally unsafe SQL baseline, the publication-expiry regression before its fix, the initial fault-wrapper race and the corrected PID-1 signal fixture. See [findings, environment, timings and limitations](research/feasibility-control-crash.md).

| Gate | Measured subset | Still required |
| --- | --- | --- |
| EXP-11/19, SC-DB-002/003/004 | Real PostgreSQL last-grant/capacity contention, protected/context/object counters, duplicates, lock-wait expiry, revoke, ambiguous COMMIT, aborted transaction, Serializable conflict and claim fencing | Full schema/roles, hierarchy scale, Kubernetes CAS, complete audit/outbox effects, authenticated current rights and fair scheduling |
| SC-INV-002 | Simplified committed-artifact/client publication and four children sharing one parent pool; post-artifact-lock expiry rejection | Complete digest/action/identity/retained-audience scope, real audit/commit, UI/MCP/download integration and distributed spends |
| EXP-11, SC-DB-005 | Single-primary abrupt restart retained an acknowledged denial/charge marker | Primary/standby failover, old-primary fence, PITR, rollback/restore invalidation and checkpoint reconciliation |
| EXP-01/05, SC-ACT-005 | Static helper under separate cgroup limits; real native/nested-PID fault; encrypted stream and matching GDB opening; missing/full/stalled receiver, identity/expiry denial, input cap, SIGKILL absence, consumed-entry restart and crash burst | Prewrapped durable keys, real prepaid/audited authority, K8s/runtime/LSM/managed-node matrix, process churn, helper upgrade/uninstall failures, pressure/large-core recovery and whole-workload impact |

Add mandatory regressions for transaction-start timestamps and expiry during **later** capacity/artifact locks. Use current database time after all blocking locks, and recheck again on dispatch/delivery. For cores, distinguish initial admission from final authenticated evidence, test explicit completion versus EOF/truncation, bound every IPC phase under one absolute monotonic deadline, and check resource placement independently of collector limits. Short local timings are not production SLOs. The experiment's memory-only keys do not satisfy durable evidence recovery.

No additional hard dependency or production format was selected. Next prepare the persistent artifact-format/commit contract and the S-01/S-02 context investigation; enable more intrusive adapters only after their outstanding runtime gates.

## Initial product component gates

`make initial-schema-handover-integration` selects one owned Kubernetes cluster
and an empty PostgreSQL database without fixture migrations or runtime grants.
It runs the actual protected schema loader from separate DDL projections, checks
the original completed bundle/database binding and unchanged read-only replay,
then runs preparation and the original activation Pod through encrypted audit,
ordered cleanup and passive reopening. The schema loader itself runs in the test
process; this is not an in-Pod `initial-schema` executable or automatic bootstrap
qualification. Provider roots, the initial manager and administrator inputs are
explicit fixture setup. A passing result must include the exact selected parent
test, unchanged Go/SQL/embedded-migration source hashes and complete lab cleanup.

`make go-check` checks the embedded schema bundle, then runs vet and race tests; `make go-architecture-check` checks real Go package ownership/imports; `make go-vuln-check` scans reachable Go vulnerabilities with pinned govulncheck v1.8.0. `make context-integration` creates two owned Kind clusters and private S3/OpenBao/PostgreSQL fixtures, tests the context/encryption/native-read adapters and complete pod-status verification into unpublished SQL custody, then removes its resources. `make custody-integration` separately tests the SQL/storage concurrency and cleanup facet; `make sql-check` checks pinned generated query output. `make manifest-schema-check` can check the offline schema bundle independently. These are implemented commands. Use a development TMPDIR with sufficient space and the Python spec virtual environment for YAML-based gates. They do not replace S-01/S-02 acceptance, full EXP gates or production backend qualification. See the [artifact](research/artifact-foundation.md), [custody](research/custody-foundation.md) and [manifest](research/manifest-foundation.md) records for actual evidence and remaining work.

`make database-recovery-integration` tests migration 00031 against an enabled legacy root, an actual owned PostgreSQL restart, and an actual logical restore into a new database. Each phase uses scoped product configuration/authority adapters. Only the missing independent activation protocol is synthesized by an explicit administrator fixture. Reported process timestamps/database OIDs distinguish real restart from database replacement; source hashes, phase exits and cleanup are checked. This does not establish physical-backup recovery, replicated failover, checkpoint completeness, or protection against arbitrary in-place superuser rewrites. See [ADR-096](decisions/096-database-incarnation-fence.md).

`make connector-retirement-integration` explicitly selects the real-time connector retirement case in the owned PostgreSQL/S3 fixture. It configures a thirty-second ordinary admission interval before acceptance, keeps the thirty-minute process/certificate lifetime and original 2100-second retention, and waits for actual object, history and ticket cleanup. It does not backdate state. The Go process has a forty-minute budget, with a separate one-minute harness margin. The environment report records the exact subtest, its Go duration, process wall time, source hashes and cleanup; a missing exact pass or either interval shorter than thirty-one minutes fails qualification. Compilation and startup time cannot satisfy the required Go subtest duration. Ordinary custody runs clear the opt-in environment switch and retain their existing budgets. Protected source/proof inputs remain synthetic. The separate maximum-duration ordinary admission boundary requires approximately 65 minutes and remains unimplemented and unrun; this shorter configuration does not qualify it. This gate also does not establish an installed connector, provider migration or a complete investigation workflow. Actual results belong in [implementation progress](implementation-progress.md).

The ordinary Go gate now includes [identity/eligibility tests](research/identity-foundation.md): actual RSA-signed access tokens and a local verified-TLS JWKS fixture, key rotation/freshness, token-purpose confusion, current organization/client policy, deny precedence and retained audience changes. Config/catalog projections remain test-only; no actual IdP or Kubernetes permission source is qualified. Browser sessions, provider group refresh, signed accepted execution, durable audit and public authorization/disclosure remain NOT RUN. A passing eligibility value is not an execution permit.

The [permission observation continuation](research/permission-foundation.md) adds `make permission-schema-check` (included in `go-check`) and `make permission-integration`. The latter owns a disposable Kind cluster and tests bounded paginated reads, real read-only service-account RBAC, dry-run/update conflicts, malformed-deny rejection and identity pinning. Its permissive test CRDs do not qualify admission, protected namespace ownership, SQL assignments, SAR or publication. The ordinary evaluator separately enforces complete deny freshness of at most five seconds. Accepted configuration and source continuity remain required; no raw API observation authorizes collection.

## Official Helm installation gate

`make helm-check` validates chart values, all topology modes, canonical CRD packaging and rejection of unavailable runtime enablement. `make helm-integration` owns a pinned disposable Kind cluster and exercises packaged installation, structural validation, explicit CRD update, upgrade/rollback and uninstall with preserved custom-resource identities. Its recorded Kubernetes/Helm versions bound this qualification. The present chart installs configuration foundations only; production role isolation, migrations, Keycloak sign-in, enrollment, air-gap image bundles and end-to-end collection still require their runtime slice tests. See the [installation guide](installation/helm.md).
