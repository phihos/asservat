# ADR-150 — Operation-owned native observation proof

Date: 2026-10-13. Status: accepted implementation direction; operation, SQL, framed-stream, pending-receiver and direct HWORK-to-holder components are integrated with passing component checks. Installed selection and complete native qualification remain pending. The source-backed amplification below is established from concrete adapters. The real receiver counterexample below is native-qualified. It establishes an availability defect, not a usable observation route.

## Problem and existing contract

ADR-144's closed observation purpose uses the same original at-most-five-second request interval across local caller admission, owner discovery, locator, one selected claim, four same-channel regional proof ordinals, metadata, terminal completion and return. Kubernetes clients retain 20 QPS and burst 20. Repeatedly composing standalone full native checks cannot meet that contract even with zero network/server latency. The current component tests use synthetic authority ports and do not qualify availability of the installed concrete graph.

The following counts are structural lower bounds for a stable one-page native view without admission-CAS conflict, not measured latency. An observer request is a real call on the configured native reader's limiter; independent probe traffic is additional.

| Complete graph | Observer requests | Independent probe requests | Concrete expansion |
|---|---:|---:|---|
| Local HWORK selected-server checks | 94 | 24 | two authentications plus two installed workload observations; separate existing HWORK client |
| Serving hub local-HWORK caller checks | 52 | 12 | two caller proofs, each with two guards, two online TokenReviews and two exact live chains |
| One full owner authentication | 23 | 6 | two workload guards (14) and one Ready endpoint chain (9) |
| One installed owner workload observation | 24 | 6 | two guards (14) and two exact live chains (10) |
| One owner routing pair | 94 | 24 | two owner authentications and two workload observations |
| Forwarder successful locator and claim | 399 | 96 | four pairs (376), two extra exact route chains (18), one complete Ready intersection (5) |
| Receiver locator and claim | 376 | 96 | one pair before and after each HTTP leg; excludes holder/regional work |
| Hub own-peer proof for each regional ordinal | 70 | 18 | two owner authentications and one installed workload observation |
| Four hub own-peer proofs | 280 | 72 | four genuine calls in `hubConnectorObservationProofs.ReadConnectorObservation` |
| One regional numbered producer reply | 78 | 18 | two protected source reads (28), process attestation outside those reads (26), installed workload (24) |
| Four regional numbered producer replies | 312 | 72 | four calls to `ConnectorObservationProducer.observe`; excludes selected metadata work |

A full protected connector source read is 14 observer requests: source guard six, two namespace-bracketed ConfigMap snapshots six, final policy/binding check two. The process attester adds two workload guards (14), two live chains (10) and two online TokenReviews (2). Configuration/source and workload guard identities remain distinct. These counts assume the intended shared clients for the same protected source/workload. Creating extra clients to evade the rate limit is not a correction.

The guards/workloads alone already require 304 forwarding observer calls, at least 14.2 seconds with a full burst and zero latency. Four hub own-peer proofs alone require at least 13 seconds. Four regional replies require at least 14.6 seconds on their shared observer. Even an aggregate 32-request pair would require 128 forwarding requests for four full pairs, before discovery and regional work. A local aggregation alone cannot qualify the complete path.

## Measured counterexample

The exact `^TestOwnerObservationReceiverOriginalBudgetWithRealServices$` owned context selector passed on 2026-10-13 as an expected-denial test. The wrapper exited 0 after 194.9 seconds, all 1,946 source hashes were unchanged, and cleanup was empty. The named Go case took 7.70 seconds. This is the original implementation's failure evidence; a passing counterexample is not a successful locator/claim exchange.

The first concrete owner pair succeeded after 3.715292 seconds with 94 observer and 24 independent-probe requests. The second pair failed unavailable after another 1.198731 seconds, at a total 4.914030 seconds with approximately 80.7 milliseconds left on the original query. The first proof's original interval also remained binding. Totals were 118 observer and 30 probe requests, six registry-port calls, six configuration-port calls, six registry-pool acquisitions and ten shared-configuration-pool acquisitions. Four separate source-owner refreshes explain why that shared pool count is not just the timed reader's work. Pool acquisition wait was about 15 and 22 microseconds respectively; observed RoundTrip-to-headers time was about 283.9 milliseconds. These measurements do not isolate server lock/CPU time or full response-body consumption. Ten HTTP failure-status counts include the expected independently denied 403 probes, not ten unexpected faults.

Evidence: `test/results/regional-observation-native-cost.json`, `regional-observation-native-cost-test.log` and `regional-observation-native-cost-environment.json`; the exact fixture package is archived by `regional-observation-native-cost-integration.json`. Actual Kubernetes/SQL/mTLS and the production 20-QPS/burst-20 clients were used. Initial recovery/source/issuer facts remain explicit synthetic fixture roots. Neither the installed producer nor the complete two-cluster route was exercised.

## Decision

Introduce a purpose-fixed, operation-owned proof composition for this closed observation conversation. It is a private process-local state machine, not a generic source cache, a new SQL authority root, a caller-supplied callback or a background observation service. Existing public owner authentication, ordinary connector source/attestation, enrollment, retirement, context and evidence ports keep their current full checks.

Each participating process holds one original operation context and two actual independent complete native boundary observations: one before read-only routing/delegation and one before releasing its final result. Each boundary verifies the native guard and exact current object chain; a shared complete observation may support both authentication and installed-template assertions without rereading the same objects through nested standalone adapters. It is explicitly one observation, not two independent checks.

Both boundaries retain all original source/workload/namespace/account/Pod/controller/template/image/Service/selected Ready identity checks. The first observation's dates stay visible and can only shorten the operation. The final observation must agree with those original identities and behavioral facts and suppress output on mutation, absence, incomplete discovery or native denial. A current native observation is not historical absence of unobserved A-to-B-to-A changes, nor a claim of instantaneous remote revocation.

The local HWORK caller is a different account, Pod and Deployment from the serving owner; sharing namespace protection never substitutes the owner chain for that caller. HWORK independently brackets the selected server before reading/sending its projected token and before accepting output. The receiving hub independently brackets the actual online TokenReview and exact HWORK chain around the request. These checks belong to the same request-owned composition as forwarding when they use the same existing native client, rather than nesting a second operation whose dates or guard reads restart. The regional target metadata reader and its namespace-selector protection remain separate from connector identity protection.

Every actual network admission and every metadata/claim/reply boundary still checks the exact current SQL registration, accepted configuration/root, recovery state, actual TLS leaf and process-owned key/closure. TLS handshakes remain real, hostname/root verified and purpose-specific. The second exact-SNI connection must match the selected original holder and server leaf; an earlier common-SNI handshake cannot authenticate it. The direct local caller presents its same original dedicated HWORK token to that holder, never an owner client leaf. Neither the first native proof nor a locator can authorize a peer by itself. Known native changes, cancellation, expiry and key renewal immediately veto further work. No interval is renewed at an ordinal, new connection, page, read or reply.

### Direct HWORK-to-holder receiving state

The selected topology is HWORK H → exact holder A → regional connector R.
The intermediate owner B is removed. H already has the scoped role70 current
owner-registry reads and the installed local native readers; A already has
online TokenReview and exact HWORK account/controller/Pod readers. This adds no
credential, SQL grant, Kubernetes grant, rate limiter or cross-cluster Pod-IP
assumption. R opens its original outbound standby through the reachable Service.
Only the same-cluster H locates and dials a current owner Pod.

H reads the complete current SQL set with the original opted limit-plus-one
query, intersects it with one complete same-RV Ready EndpointSlice sequence,
and retains every original process member for each present Pod. The selected
native addresses are only dial hints. Normal common-SNI TLS identifies one
actual leaf from that complete group. Current SQL/configuration/roots and one
genuine initial native observation must match that leaf, address and original
Pod/controller/template/guard before H reads or sends its dedicated projected
token. No unused SQL candidate is relabeled current or Ready without proof.

A's initial native boundary covers its own owner workload and the distinct
HWORK workload, with two online dedicated-audience TokenReviews. The caller pin
comes from the original acknowledged account receipt 1, Deployment 11/full
configuration template/image, guards 17/18, positive configuration launch and
OwnerBootstrap PermissionRootID. The runtime observes actual Pod/ReplicaSet
UIDs under that controller; an installer cannot preallocate or adopt them.
A trusted authorized Pod remains a Pod-wide bearer principal. This is not a
proof against a compromised authorized observer or installation administrator.

A reserves a pending slot before native admission. The positive locator spends
one exact local R standby/registration sequence before exposing output. The
retained record binds original query/root/cluster/challenge, HWORK Pod and
original token, A server leaf/process, original native state, accepted SQL
identity and the earliest original query/socket/source bound. One exact claim
POST consumes it before I/O. A checks fresh direct HWORK objects and two online
TokenReviews inside the retained original guard interval; it does not restart
that guard. Final owner native observation includes HWORK again before ordinal 4.
H independently performs final native observation and current SQL before output.

Use only `/internal/cluster-observation/local/locator/v2` with common SNI and
`/internal/cluster-observation/local/claim/v2` with exact SNI. Actual TLS ServerName
and HTTP authority must match each purpose. Token bytes occur only in the fixed
Authorization header and bounded private memory, never URLs, JSON, SQL, audit,
errors or regional frames. Local requests have no owner client certificate.
Existing owner-mTLS locator/claim paths and v1 full-check behavior stay unchanged
and remain unselected by this direct composition. No format negotiation occurs.

A locked, current `LookupAvailable` can report no claimable local standby. That
is a bounded routing observation, never a global empty result. Closed/cancelled,
expired, malformed or uncertain reads remain errors. Only an authenticated
absence can advance to another original candidate. An unavailable candidate ends
only its bounded worker; it does not cancel an independently admitted candidate
that can still return a positive within the same original bound. If all workers
finish without a positive, the result remains unavailable. Multiple parallel positive
locators spend their separate original standby slots even though H chooses one.
No loser or lost reply is refunded; no uncertain selected POST is retried.

The pending context descends from the process root with the original GET socket
end. It is deliberately not a child of the completed GET handler. Setup
cancellation remains linked and joined until the possible-delivery boundary.
The original finite context then survives GET completion without renewal.
POST cancellation joins actual native/SQL/frame/output work. Spent markers stay
until the original end, and delayed cleanup compares the exact entry pointer.
The active-call versus retained-marker accounting revision below supersedes
counting a fully joined marker as active concurrency. Process restart, missing state, changed token/leaf/sequence or
unknown previous claim cannot create or adopt a replacement operation.

H retains its compiled active-operation and transport ceilings, shared across
operations and losing candidates. The original single-region ceiling is two;
current installed composition scales it with regional clusters as recorded in
the accounting revision below. A retains that active-request ceiling and the
separate finite total-marker bound. Active slots include admitted work and
joined cleanup.
The original listener accept-time two-second prelude and five-/thirty-second
finite/standby bounds remain separate additional caps, not new time at dispatch.

### Four regional ordinals remain real observations

The existing sequence remains ordinal 1, ordinal 2, one selected metadata operation, ordinal 3, ordinal 4, exact receipt and joined EOF. Each ordinal performs a genuinely new direct read of the exact protected connector source object, validates the complete canonical source/profile/roles/backing and original UID, and compares the current value with earlier ordinal values. No captured value is returned as a fresh source read. Source/body/role/backing changes deny the entire request. The two SQL49 current-leaf checks remain independent and continue to bracket the metadata operation with those four reads.

The regional process acquires its configuration-source guard and workload/token/template bracket as explicit operation-owned native proof. The four ordinal reads retain that proof's original expiry rather than recursively reacquiring full standalone guards and the same workload chain. The final independent native bracket runs before the last source reply can let the hub accept the result. Original process/key/CSR/actual leaf, current online token identity and cancellation remain checked at the applicable read/effect boundary; neither the process snapshot nor source value grants SQL activation. Distinct source and workload guards cannot substitute for one another.

The hub's own-peer side similarly binds its actual same-channel exporter/leaf and current registry to an explicit operation-owned native proof. Each ordinal still creates its own correctly numbered challenge-bound reply and checks current SQL/leaf/private-key state, but does not relabel one native bracket as four newly acquired full owner guards. The holder's final native bracket and regional final native bracket must both complete before exposing the metadata result. A shared final check may satisfy two composed callers only when it is literally the same complete observation under the same operation, not a memoized callback pretending to execute twice.

### Explicit source-port boundary

Add closed observation-purpose types/methods for the retained native bracket and separately read source value. A source-value result contains its actual read interval and the original bracket bound; it cannot mint or extend that bound. The only constructor is the concrete native operation owner, pinned by installed input. The SQL observation adapter consumes that explicit purpose-bound composition; ordinary `ReadConnectorIdentitySource`, `ReadConnectorProcessProof`, `ObserveConnectorProcess` and the public owner authenticator remain unchanged.

Do not implement this by passing a caching closure into their existing general interfaces. Method and type names must distinguish native boundary observation from a source-value read. The original four remote attempts remain spent before I/O; unknown delivery cannot repeat an ordinal, metadata read or claim. The semantic capability uses the existing fixed `owner-observation/v2` and matching `connector-observation/v2` literals. New local/routing/conversation envelopes, paths and media types use v2; own-owner and numbered connector replies also use v2. Old v1 constructors, parsers, paths, replies and full-check behavior remain unchanged. Neither side negotiates, retries or downgrades to v1. An old peer rejects the new format before source/metadata use rather than accepting a retained bracket as a newly acquired complete proof.

The original public metadata request/result payload, its canonical digest/domain separator, request IDs/challenge, exact uint64 locator sequence, twelve-frame count and four ordinal numbers remain unchanged inside the new purpose envelopes. V2 adds explicit native bracket identity/start/end and phase (initial or final) to the private proof reply. A bracket identity is a request/channel-bound identifier, not authority by itself. All four source-value replies name the same original bracket and deadline; ordinal 4 additionally carries successful final native validation. The owner proof in the fourth question similarly requires the hub final native boundary. A late final check cannot move the bracket's original dates.

The one console-owned fresh installed-v2 carrier must require the existing `Observation.Format` field to equal the fixed `owner-observation/v2` literal for this exact capability and propagate it through original owner input, HWORK LocalOwner and the independently installed regional pin. `NativeCandidateLimit` alone does not select it. Existing claimed layout/pin bytes are never promoted or inferred. There is no second layout variant, rollout claim or file-presence activation. Component constructors can be tested before this producer exists, but cannot enable a runtime route.

## Qualification and scope

Before coding, map the complete native request graph for all involved processes, including HWORK caller proof, candidate/Ready discovery, forwarding and receiving owner pairs, hub own-peer proofs, four regional source values, target metadata/guard reads, final brackets and shutdown. Count configured clients separately without creating new limiter instances. A projected count below a theoretical ceiling is only a design screen, not evidence of practical five-second availability.

Keep the original real receiver counterexample. Component regressions must prove independent initial/final native I/O, preserved original dates, no cached source-value reads, changes at every intervening boundary, wrong/new TLS leaf, SQL revocation/recovery, key closure/renewal, source roles/backing changes, terminal ordinal failure, holder sequence replacement, abandoned locator, concurrent duplicate claim, cancellation during native/SQL/network work and exact joined slot release. No deadline, QPS/burst, pool or candidate bound increases are permitted.

The acceptance gate is the complete concrete direct HWORK client, receiver, holder and four-ordinal regional exchange with actual Kubernetes, SQL and mutual TLS under the same original at-most-five-second interval. Measure actual API categories/SQL port work and per-leg timings, including cancellation/partition/revocation negatives. Synthetic loopback success or an isolated pair timing result cannot qualify the installed topology. Keep runtime listener selection disabled until this full native gate passes.

## Scope of the first implementation checkpoint

The first checkpoint adds only the concrete Kubernetes owner-operation proof: actual initial and final native I/O, one exact original request and fixed owner participant set, shared native object validation within each boundary, terminal mutation/expiry/cancellation and joined Close. It implements no old general authority interface and cannot grant SQL activation, authenticate a TLS connection or enable a route. Public `OwnerAuthenticator`, `OwnerEndpoints`, `OwnerWorkloadProtection.Current` and general connector source/attester methods keep their semantics. Any pure object-validation extraction must preserve their checks and original regression tests.

Later separately reviewable checkpoints add the purpose-fixed regional source-value proof, explicit v2 codecs/channel binding, local HWORK composition, receiver pending-locator state and forwarder integration. These are all required before selecting the installed route. The current direct composition, source identities, count worksheet and regression boundary are recorded below; projected request counts are a design screen, not measured performance.

## Direct critical-path accounting and qualification

The source estimate assumes one complete EndpointSlice page and one contacted
holder. It counts existing actual native clients separately, without additional
limiters. Counts are implementation assertions pending execution, not timing.

| Process | Observer / independent probe calls | Other serial work |
|---|---:|---|
| HWORK H | 33 / 6: discovery5, initial14, final14 | Complete SQL candidates, six exact current-owner reads, common then exact TLS, joined losing candidates and result. |
| Holder A | 51 / 6: initial21, claim9, final21 | Eighteen current own-registration ports, two SQL49 pairs, original pending and standby claims, four proof frames, metadata, Receipt/EOF and joined closure. |
| Regional R | 50 / 12 plus selected metadata | Four actual protected source-value reads, seven current candidate/owner registry checks, current key/leaf checks and original standby lifetime. |

A's 21 is the single-owner14 plus HWORK account, Deployment, Pod, ReplicaSet,
second exact Pod and two online reviews. Its9 at claim is the seven direct
caller reads bracketed by namespace reads, under the original retained guard.
No source value or final bracket moves the first interval's start or end.
The role70 MaxConns1 pool is reused; all candidate/current-owner reads finish
before a capacity transaction. Registry port counts are not SQL query counts.

The complete path is H discovery/TLS/SQL/native → A SQL/native/token/reservation
→ H new exact TLS/current SQL → A direct caller/claim → R four actual source
values and A's two SQL49 pairs around metadata → final A and R native checks →
Receipt/EOF/joins → A current output check → H final native/SQL/result. All
stages share the earliest original caller, accepted source/recovery, token,
certificate and socket cutoff. There is no positive minimum remaining freshness
in a valid accepted source; near-expiry requests fail, without renewal or retry.

An extra contacted candidate adds at least 14/3 on H and 21/3 on that A, plus
actual SQL/TLS. All original candidate rows/pages must remain complete even when
time permits only a few contacts. Other processes' buckets can refill during a
leg, while source supervision consumes the same clients. Counts divided by 20
therefore prove neither elapsed latency nor sustained availability. The
previous unimplemented B100/B51 wrappers are superseded by removal of the hop.

The complete native gate must measure consecutive and concurrent H→A→R work,
a losing candidate, all four metadata purposes, supervised original source and
recovery ages, aged standbys, actual API/SQL acquisition counts and fixed-label
phase durations. Missing original time still denies. Loopback synthetic source
success, the real native primitive's 28/6 result or the passing SQL49 test cannot
qualify this graph. Installed caller/backend receipts, fresh-format consumer
selection and the final fixed listener composition remain separate missing
boundaries until their actual qualification passes.


## Joined active capacity and bounded replay markers (2026-10-28)

This revises an agent-authored throughput restriction, not a maintainer security
requirement. The installed single-region composition supplies two concurrent
observation slots. Previously, two distinct completed operations retained both
slots until their original five-second ends, even after all native/claim/GET
work joined and tokens were cleared. A local regression reproduces the next
fresh demand's refusal with both original markers still live. It does not prove
this caused Native 40776231613's locator failure; that run instead establishes
an expired full-30-second binding and a current demand, with no matching fresh
publication before the request's unchanged readiness cutoff. The SQL permission
denial in that run is the intentional fixture privilege probe.

Use the existing pending map with two separate admission conditions:
`active <= maximum` and `retained entries <= 2 * maximum`. Every admitted entry
counts as active through preparation, possible delivery, claim, native/reservation
closure, joined GET/claim owners and token clearing. Only the end of `closeWork`
releases its active count. Entering the Spent phase, cancellation or an unknown
reply does not release it. The same root/request marker remains until the exact
original end; no replay, replacement, refund or authority extension follows.
The store counter is released outside the entry mutex to preserve store-before-
entry lock order. Shutdown still joins all retained entries.

A separate spent-marker ceiling of only `maximum` would still reject a fresh
third request after two joined calls. The chosen total ceiling allows bounded
headroom without an unbounded completed-request ledger. Fast distinct calls can
still fill that total and must refuse until natural expiry; this is not an
availability or throughput guarantee. Existing caller/proof five-second ends,
active HTTP/native ceilings, demand pacing, input grants and budgets are unchanged.
No public setting, SQL/API request, credential, privilege, watch or service is added.

Measured amd64 value sizes are entry 832 bytes, key 32 bytes and claim 104 bytes;
these are not retained-heap or CPU measurements. With one region, active remains
2 and total entries become at most 4 (3,328 entry-value bytes). With the current
maximum eight regional clusters, active remains 9 and total at most 18 (14,976
entry-value bytes; +7,488 over the previous ceiling). Active token capacity stays
9 * 16 KiB = 144 KiB and joined markers retain no token. Map buckets, original
contexts, callbacks and referenced graphs are additional. The store also adds one 8-byte active counter. Each admitted entry
uses the existing retention deadline/context and callbacks, so the larger total
can retain up to nine additional such timer/context instances; there is no new
timer kind or background loop. Runtime/SQL/native-provider qualification remains
separate from these local lifecycle checks.


The local lifecycle regression reproduces RED with unchanged runtime (race exit
1, package 0.082s), then passes after the accounting change (all LocalPending
race cases, exit 0, 1.388s). Controls include blocked native Close plus possible
delivery, same-ID denial, total retained saturation, natural original expiry,
concurrent admission and joined shutdown. Full affected races pass: bootstrap
62.841s, mTLS 66.762s, cluster-observation transport 3.214s and native transport
98.965s. Integration compilation, affected vet, specification and architecture
gates pass. Fixture authority/native facts remain synthetic; these checks do not
establish an installed locator cause, real-provider throughput, collection or
an end-to-end history result. No external run was performed for this revision.
