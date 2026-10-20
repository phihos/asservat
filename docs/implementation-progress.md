# Sustained implementation progress

## Resumed review and installed qualification (2026-10-20)

The [latest frozen installed run `context-cqjvthn6`](../test/results/resumed-c62e02ac-native50/result.json)
on `b4fbd37d` again completes installed acquisition, verification, publication and
authorized capture/case retrieval. The request eventually receives an acknowledged
success for its original capture. The corrected deletion fixture also establishes
the exact cleaner inventory denial while preserving the independent-prefix control.
The first `prepare_artifact_download` then returns acknowledged unavailable after
4.433 seconds. The test exits 1 after 1,226.986 seconds.

The [read-only download state](../test/results/resumed-c62e02ac-native50/postmortem-download.log)
contains one `Preparing` session, created at `19:24:29.457101Z`, with its original
`19:29:29.374261Z` deadline and reserved output/read/session allocation. There is
no worker, batch, response or native owner, and no emitted bytes. Failure is after
reservation and before successful worker reservation; the public response does
not identify the exact failed check. Its generic retry flag does not acknowledge
pending preparation or authorize automatic continuation. Deliberate same-key
recovery is a separate supported user action.

All 2,763 source hashes match and stayed unchanged. The 33-command postmortem
collection and extra bounded read-only queries pass. Independent read-back confirms
the original bucket policy was restored exactly. Cleanup exits 0, all twelve owned
Docker resources are absent, and build scratch/private control files are removed.
Native download, revocation/expiry and failed-deletion recovery remain unqualified.
Current work isolates the pre-worker preparation path; another installed run must
follow a focused defect/reproduction, not a larger retry or authority interval.

The [preceding frozen installed run `context-sagzb681`](../test/results/resumed-c62e02ac-native49/result.json)
on `62bfc0bb` reaches installed acquisition, independent publication and fresh
authorized public capture/case retrieval. Bootstrap, exact regional join replay,
console processing initialization and capacity readiness pass; the demand lane
supplies six distinct observations and 26 usable samples over 15 seconds.
Test and harness still exit 1 after 1,211.891 seconds. All 2,762 source hashes
match and stayed unchanged. Cleanup exits 0, all twelve owned Docker resources
are independently absent, and build scratch and private postmortem kubeconfigs
are removed.

The first review is acknowledged closed before a second review admits one
capture. Its accepted identity survives an unknown continuation reply: fresh
`get_capture` reads recover progress without another resolution record.
Preparation retains 1.858338 seconds, and start, acquisition and stored completion
precede its original cutoff. Verification, audit acknowledgement and publication
complete independently; a fresh `get_case` succeeds and returns the one artifact.
The [operation audit](../test/results/resumed-c62e02ac-native49/postmortem-requests.log)
records three successful capture reads and one successful case read. These
ordinary reads do not renew acquisition or infer success from `OutcomeUnknown`.

The next failure is in the deletion fixture's setup, before download or fault
injection. Its original writer, four current/versioned objects and retained
allocation checks pass, but strict bucket-policy equality rejects the provider's
JSON representation. The
[read-only policy response](../test/results/resumed-c62e02ac-native49/postmortem-bucket-policy.json)
returns `DenyEvidenceWrite.Action` as `"s3:PutObject"`; the fixture builder emits
the one-element array `["s3:PutObject"]`. All other policy fields match.
The correction emits the provider's scalar form and adds strict PUT/GET
read-back qualification; generic equality, permission scope and fault restoration
remain unchanged. There are zero download sessions. Native download, revocation,
expiry, failed-cleanup recovery and deletion charge release remain unqualified
in the installed journey.

The [bucket-policy regression](../test/results/resumed-c62e02ac-bucket-policy/result.json)
uses the exact provider response retained above. It fails with the original
builder (exit 1, 0.015 seconds), then passes the focused race selection after
the one-action scalar correction (exit 0, 1.068 seconds). The combined in-process
integration race suite also passes (exit 0, 6.262 seconds), covering both fixture
corrections. All 2,582 recorded Go/module hashes stay unchanged during each
phase. Strict scalar/array distinction, scope and uncertain restoration controls
remain passing. Independent review found no blockers.

The [exact real-provider qualification](../test/results/resumed-c62e02ac-bucket-policy-native/result.json)
on frozen `ddfcbd0f` now passes: the selected
`TestInstalledEvidenceDeleteCredentialWithRealServices` test takes 0.26 seconds
(race package 1.321 seconds), and the harness exits 0. Strict policy PUT/GET
read-back and the existing deletion credential controls pass against the pinned
S3 provider. All 2,735 source hashes match and stay unchanged; both owned
containers and their network are independently absent after cleanup.
The complete installed journey still needs a passing rerun.

Read-only review also found that the fixture ends its terminal wait too early
when `Succeeded` omits its independently authorized case link. The service
intentionally permits that response when current navigation is unavailable.
The [separate regression](../test/results/resumed-c62e02ac-case-link/README.md)
fails on the original immediate refusal (exit 1, 0.016 seconds), then passes
the focused race suite with the correction (exit 0, 1.063 seconds). Capture and
case waits share one original five-minute deadline. Exact identity, cancellation,
fresh decoding and independent case authorization remain required. Independent
review found no blockers; source hashes stayed unchanged during the passing
selection. Native49 did receive an authorized link, so it does not reproduce
that separate fixture defect. Installed qualification of the correction is next.

The [preceding frozen installed run `context-siix2l2z`](../test/results/resumed-c62e02ac-native48/result.json)
on `d6dabdab` passed bootstrap, exact regional join replay, capacity readiness
and console processing initialization. Capacity supplied six distinct
observations and 25 usable samples over 15 seconds. The first reviewed request
admitted one capture; two explicit continuations retained that same capture.
Test and harness still exited 1 after 1,242.527 seconds. All 2,762 source hashes
match the frozen commit and stayed unchanged. Owned cleanup exited 0, all
twelve recorded Docker resources were independently confirmed absent, and
build scratch was removed.

The first continuation refused preparation at the new headroom check. Its
outer request still had at least two seconds, but that diagnostic does not
include the earlier retained target, eligibility, capability, retention,
recovery or process cutoff used by preparation. The exact winning observation
was not recorded. The second continuation became the first preparation winner
with 1.095163 seconds remaining, committed the regional start, acquired and
stored the artifact before its original cutoff. Its
[execution row](../test/results/resumed-c62e02ac-native48/postmortem-execution.log)
is `stored`, and the exact
[CapacityReservation](../test/results/resumed-c62e02ac-native48/postmortem-regional-capacity.json)
is `StartCommitted`. No preparation was renewed or repeated.

Independent publication also completed. The
[read-only SQL transaction](../test/results/resumed-c62e02ac-native48/postmortem-publication.log)
records verification at `18:09:05.706456Z`, acknowledged audit at
`18:09:05.728939Z` and catalog publication at `18:09:06.234647Z`, matching the
installed publisher's log. Generic custody remains `stored_unpublished`;
the separate verification/audit/catalog rows establish semantic publication.
There were no download sessions. This is evidence of installed acquisition
and publication, not a completed public retrieval or lifecycle test.

All three outward request replies remained `OutcomeUnknown`. The last outcome
was recorded about 3.3 ms after the execution's original cutoff, although its
outer caller was still live. Stored completion preceded that cutoff by
166.710 ms. The remaining current-source/peer checks and final stream exchange
retain their own original bounds; these timestamps do not prove the exact
last failing frame or winning cutoff. The unavailable outward reply cannot
erase completed work or authorize its repetition.

The fixture then required a third admission-resolution record, exceeding its
unchanged two-record reservation. Both earlier resolutions had already
acknowledged the same accepted capture. Re-resolving admission cannot determine
execution progress. The product retains that accepted ID and offers a fresh,
independently authorized `get_capture` read; the fixture must use that path
before considering another explicit continuation.

The [known-capture recovery regression](../test/results/resumed-c62e02ac-known-capture-recovery/verification.json)
reproduces the third redundant resolution before correction (exit 1), then
passes the focused race suite (1.068 seconds) and the full in-process integration
race suite (6.250 seconds), both exit 0. The corrected fixture retains the
first accepted identity and acknowledgement time, reads fresh same-capture
progress after unknown replies, and permits another explicit continuation
only from `Pending`, within the unchanged four-call bound. `Running`,
`Finalizing` and `Succeeded` enter the existing independent terminal/publication
checks; this recovery helper does not declare success. Failed progress reads,
replacement identities, uncertain spent preparation and cancellation stop it.
Independent review found no blockers. The source hashes stayed unchanged
during the full suite. Native49 subsequently qualifies this correction through
terminal success and an authorized case read, as recorded above. Native bytes,
revocation, expiry and independent deletion checks remain required.

The preceding [frozen installed run `context-4b2d6czv`](../test/results/resumed-c62e02ac-native47/result.json)
on `f7d3fe14` passed bootstrap, exact regional join replay, capacity readiness
and console processing initialization. Capacity supplied six distinct
observations and 37 usable samples over 15 seconds. Test and harness exited 1
after 1,263.415 seconds; all 2,758 source hashes match the frozen commit and
stayed unchanged. Owned cleanup subsequently exited 0, independent read-back
confirmed all twelve recorded Docker resources absent, and build scratch was
removed.

The first request's new private diagnostic identifies
`request/facts/storage/margin`: the final authoritative storage selection had
less than one second remaining. Its early readiness hint did not preserve
headroom through the intervening work. The second request failed at target
query routing. Both original reviews were resolved closed, using the unchanged
two-record resolution reservation. [ADR-213](decisions/213-storage-readiness-at-consumption.md)
defines a bounded consumption phase for the same owned storage wait. Its
implementation and component checks now pass; native47 did not test it.

The third request admitted one capture and acknowledged its intent. Its
[SQL postmortem](../test/results/resumed-c62e02ac-native47/postmortem-execution.log)
shows `intent_audited`, one reserved custody row, zero execution rows and no
regional CapacityReservation. The original intent interval was 1.370169 seconds,
with 1.095886 seconds remaining after acknowledgement. Execution stopped under
an inherited deadline before preparation. The old `ReadAPIContextWork` diagnostic
also covered subsequent current-authority checks, so it cannot identify the
specific dependency. This run did not reach ADR-212's preparation floor.
The next resolution exceeded the already-spent two-record reservation;
same-capture continuation was not reached. No quota or deadline was enlarged.
Acquisition, publication, native download, revocation and deletion remain
unqualified in the complete installed journey.

The [execution diagnostic regression](../test/results/resumed-c62e02ac-api-check-diagnostics/result.json)
first reproduces the ambiguous check labels, then passes the full execution
package under race detection (1.169 seconds, exit 0). Actual SQL reads retain
`ReadAPIContextWork`; subsequent checks distinguish exact target, eligibility,
capability, retention, compilation, recovery, process, validity and cancellation.
Later checks keep their preparation/start boundary prefixes. Original error
chains, ordered reads, deadlines and effect counts remain unchanged.
Independent review found no blockers. These synthetic component cases do not
identify the specific dependency that failed in native47.

The [storage consumption regression](../test/results/resumed-c62e02ac-storage-consumption/verification.json)
first fails against the old immediate margin refusal, then passes with the
same owned hint transferring into consumption. It retains the one demand
attempt, 250 ms cadence, exact storage selection and all original non-storage
authority bounds. Tests cover independent binding timestamps, every original
cutoff, invalid or changed storage, failed demands, joined cancellation and
the exact one-second margin. Successful Request retains its existing final
eligibility recheck; no extra facts refresh or admission retry is introduced.
The full capture race suite passes in 10.066 seconds, and the integration
package compiles with no tests selected. Independent review found no blockers.
[Specification, architecture, design and Go vet checks](../test/results/resumed-c62e02ac-storage-consumption-gates/result.json)
pass. Native48 above includes the correction and reaches admission; its timing
logs do not establish whether a consumption-phase poll was required.

The [scoped storage-reader SQL regression](../test/results/resumed-c62e02ac-storage-diagnostic-sql/result.json)
on `f7d3fe14` passes with the actual compiled read-only role: original binding
freshness is preserved, a missing exact workload emits the closed diagnostic,
and writes remain denied. Test and harness exited 0 in 1.989 seconds; all 2,730
source hashes match and stayed unchanged. Both owned containers and their
network were independently confirmed absent. Synthetic authority in this
component fixture does not qualify the installed lifecycle.

The preceding [frozen installed run `context-hsp75ign`](../test/results/resumed-c62e02ac-native46/result.json)
on `8b153eb2` includes the preparation and pool-cleanup corrections below.
Bootstrap, exact regional join replay, capacity readiness and processing
initialization passed. Capacity supplied six distinct observations and 30 usable
samples over 15 seconds. The installed test and harness exited 1 after
1,257.556 seconds; all 2,755 source hashes match the frozen commit and stayed
unchanged.

Three original capture requests, each following a fresh review, returned
`OutcomeUnknown`. Their [retained audit outcomes](../test/results/resumed-c62e02ac-native46/postmortem-requests.log)
are acknowledged `authority_unavailable` results. The first two resolutions
acknowledged closure of their reviews; the third resolution exhausted the
unchanged two-record audit reservation. These were not same-capture
continuations. [SQL inspection](../test/results/resumed-c62e02ac-native46/postmortem-sql.log)
found no capture, execution or custody rows, so this run did not reach
preparation or exercise its new floor/passive replay.

The [first request's timing](../test/results/resumed-c62e02ac-native46/context-storage.log)
reaches the final storage read, then stops before processing/admission. Its
private error stage was not reported, so storage-read failure and insufficient
remaining storage margin cannot be distinguished. The second request failed
earlier at target-query closing route lookup. The third request's timing was
suppressed by the existing sampling. Successful capacity refresh samples do
not establish the remaining interval at any later authoritative request read.
No new deadline, quota or refresh relaxation follows from these observations.

[Closed diagnostic regressions](../test/results/resumed-c62e02ac-request-route-diagnostics/result.json)
reproduce the missing request and route labels, then pass under race detection.
Request distinguishes storage-read failure, insufficient margin and stale
current facts while retaining the existing preview stages and error causes.
Optional storage-read detail accepts only fixed query/clock/observation/
transaction labels; SQL errors remain sanitized. Route diagnostics distinguish
the first configuration read, endpoint read, final configuration read and
current-result/cancellation checks without changing their order or result.
The full capture and fleet race packages pass in 3.078 and 15.961 seconds.
The PostgreSQL adapter, Go vet, specification, architecture and SQL generation
checks also pass. The existing scoped SQL-reader regression now requires the
missing-target diagnostic; its subsequent real-service pass is recorded above.

The fixture was retained for read-only SQL and Kubernetes inspection, then its
owned cleanup exited 0 with no failures. Independent read-back confirmed all
12 recorded Docker resources absent, and build scratch was removed. Acquisition,
publication, native download, revocation and deletion remain unqualified.

The preceding [frozen installed run `context-boqlf6my`](../test/results/resumed-c62e02ac-native45/result.json)
on `a6546de8` passed bootstrap, exact regional join replay, processing
initialization and preview. The demand lane produced six distinct observations
and 32 usable samples in 15 seconds. [CI on this commit](https://github.com/phihos/asservat/actions/runs/39446523599)
passed all 15 jobs, including ten Go test shards and console browser checks.
The installed test and harness nevertheless exited 1 after 1,222.530 seconds.
All 2,752 source hashes match the commit and stayed unchanged.

The first capture reached execution preparation and `ReadyStart`. Its
[read-only SQL postmortem](../test/results/resumed-c62e02ac-native45/postmortem-execution.log)
shows only 433.731 ms remained between the preparation insert and its immutable
`NotAfter`. The exact regional
[CapacityReservation](../test/results/resumed-c62e02ac-native45/postmortem-regional-capacity.json)
reached `Ready`, with no `StartCommitted` status; SQL remained `prepared` with
no start, acquisition or completion timestamps. The first invocation's inherited
cutoff was preserved. Its equality with the capture-intent deadline reflects a
shared original bound, not proof that storage was the limiting observation.
The capture intent and all three request audit outcomes were acknowledged.

Both continuations failed at `PrepareAPIExecution/effect/expired/client`:
the existing preparation had expired. The final `client` label comes from
generic SQL error normalization; it does not identify a network failure.
Rejecting this historical row before the runner can observe its no-create
result bypasses the existing `PreparationUncertain` classification. The next
resolution exhausted the unchanged two-record audit reservation. The separate
correction and its qualification follow; existing preparation must never acquire a new
deadline, key attempt or start authority.

The [real PostgreSQL/S3 preparation regression](../test/results/resumed-c62e02ac-api-preparation-red/result.json)
on `815c42db` reproduces both defects with the compiled narrow runtime grants.
Both observation and caller deadlines started above one second; an independently
observed capture-row lock consumed headroom, yet the old code inserted a
preparation below that floor. A short-caller runner also reached its first
effect port. An expired preparation failed exact passive replay and the real
runner's uncertainty classification. All four cases failed in 5.971 seconds;
all 2,726 source hashes match the frozen commit, cleanup reported no failures,
and independent inspection confirmed both containers and their network absent.
The first attempted run failed only on duplicate fixture role names; it is
retained separately and supplies no defect evidence. Current authority inputs
remain synthetic, and the later runner ports refuse effects. ADR-212 defines
the new first-insert floor and the unchanged no-create replay contract.

The correction checks database time immediately before a first insert and
returns exact existing `prepared` rows without creation, including after their
stored interval. Current authority and exact identity/scope checks still run
before and after that result. The [local race suites](../test/results/resumed-c62e02ac-preparation-local/result.json)
pass for PostgreSQL (2.454 seconds), execution (1.146 seconds) and the in-process
integration package (6.488 seconds); independent review found no blockers.
The final real-service green result is recorded below; installed qualification
remains pending.

The first [real-service correction run](../test/results/resumed-c62e02ac-api-preparation-classification/result.json)
on `e19738c8` passed expired-row uncertainty, zero-effect headroom refusal
and both compiled execution/publication role cases. Three assertions still
failed because custody normalized the new
headroom refusal to its own unavailable sentinel rather than the execution
contract's sentinel. Test and harness exited 1 after 12.368 seconds; all 2,726
source hashes matched and stayed unchanged, and owned teardown was verified.
The follow-up preserves only that explicit headroom refusal across the adapter
boundary; it does not change generic SQL error handling or the regression tests.
The post-lock classification assertions stopped those cases before their fresh
first-winner and exact-replay checks in that failed run.
Review also identified cancellation during rollback as a distinct normalized
deadline cause. A focused failing regression now requires that original cause
and error chain to survive; only the explicitly recorded headroom/client
combination becomes execution-unavailable. The full PostgreSQL race suite
passes in 2.466 seconds with identical before/after source hashes.

The [final real PostgreSQL/S3 run](../test/results/resumed-c62e02ac-api-preparation-green/result.json)
on `899f6433` passes all four preparation-boundary cases, including a fresh
first winner and unchanged replay after each post-lock refusal, and both
compiled verifier/publisher execution and historical-publication lifecycles.
Go and harness exits are 0 (13.645 seconds); all 2,727 source hashes match the
commit and stayed unchanged. Cleanup reported no failures, and independent
read-back confirmed both owned containers and their network absent. This
qualifies the affected SQL composition with synthetic current authority; it
does not replace the full installed journey.

The installed fixture also spent a redundant resolution record after a
successful continuation. A deterministic regression reproduced a third
resolution exceeding its unchanged two-record reservation after the second
continuation succeeded. It now uses the accepted receipt for that exact request
and the successful same-capture response; immediate success still performs
its separate resolution. Closure, replacement-ID and cancellation checks remain.
The focused race suite passes in 1.065 seconds, and independent review found
no blockers. This changes neither product budgets nor continuation authority.

The new SQL activity diagnostic captured 30 installation-scoped rows before
owner removal, with no lock wait in that snapshot. It cannot establish earlier
waits or client-side pool state. The fixture was retained for read-only SQL and
Kubernetes inspection, then owned cleanup exited 0 with no failures.
Independent Docker read-back confirmed all 12 recorded resources absent;
private postmortem kubeconfigs and build scratch were removed. Acquisition,
publication, native download, revocation and deletion remain unqualified.

An independent [TCP/TLS protocol regression](../test/results/resumed-c62e02ac-sql-governor/result.json)
reproduced a separate SQL pool cleanup defect. pgx's asynchronous cancellation
attempted another governed socket while the failed connection retained its
sole dedicated slot. All four explicit-cancellation/deadline cases failed the
next transaction's unchanged one-second deadline on the original code.
The conditional `BeforeClose` correction closes only a connection already
marked discarded by pgx, after any existing hook and before joining driver
cleanup. Physical slot accounting, default cancellation/error behavior,
healthy reuse and graceful closure remain unchanged. The corrected regression
passes under race detection in 1.402 seconds, and the full PostgreSQL adapter
race suite passes in 2.493 seconds. Independent review found no blockers.
These are actual pgxpool tests against a synthetic PostgreSQL protocol server,
not a native PostgreSQL or installed lifecycle qualification. Native44 has a
plausible initiating cancellation path, but its logs cannot prove attribution;
native45's preparation-expiry failure is separate.

An independent deterministic regression reproduced admission with only 50 ms
left on the final storage observation after the early readiness hint succeeded.
The authoritative read now requires the existing one-second margin, refusing
before admission when it is insufficient. It adds no read, refresh demand or
deadline extension. The exact one-second boundary, original identity/target
expiry and joined cancellation pass; the full capture race suite passed in
3.038 seconds. This selection-time readiness correction is not an attribution
of native43 or native44.

The MCP diagnostic regression also reproduced an audit-begin failure being
hidden when the final identity check found the original deadline expired.
The existing private, closed failure is now reported before that check;
the public response, current identity read, socket deadlines and single audit
attempt are unchanged. Both supported protocol revisions pass the focused
race tests, including private-error redaction; the full MCP race suite passed
in 12.214 seconds. A separate fixture-only SQL activity snapshot now runs
before journey Pod diagnostics and owner removal. It reads the existing
administrator pool under the original context capped at two seconds, selects
only this installation's runtime roles and emits at most 64 rows of state,
wait type/event and ages. It emits no query text, credentials or provider
errors and creates no pool or retry. Its focused race tests passed in
1.065 seconds. Such a server snapshot cannot show client-side pool waiters
and is supporting evidence only.

Start diagnostics now distinguish the inherited caller cutoff from the
start's own five-second cap. Native protection failures retain closed
namespace/guard/probe phases and the original error class; the authenticator
separates read failure, invalid proof, pool mismatch and changed digest.
An actual TLS/HTTP2 regression composes successful attachment with refusal at
the work-send check's closing protection read, preserving the inherited
deadline, one connection, zero execution effects and joined cancellation.
Its injected proof failure is component evidence, not native API performance
qualification. The complete fleet and mTLS race suites passed in 15.962 and
35.028 seconds; focused Kubernetes/bootstrap race checks passed in 7.775 and
1.057 seconds. Independent review found no blockers. Specification,
architecture, embedded contracts and `go vet ./...` gates passed, as did the
full in-process integration race suite (6.286 seconds). Native45 above
qualifies these sources only to its recorded failure; local limiter versus
network failure and client-side SQL contention are not established causes.

The [frozen diagnostic run `context-5ngvkl2b`](../test/results/resumed-c62e02ac-native44/result.json)
on `ccdde1a3` passed bootstrap, regional join/replay, processing initialization
and preview. The demand lane produced six distinct observations and 27 usable
samples in 15 seconds. Unlike native43, capture-intent persistence completed.
The retained fixture's [read-only SQL postmortem](../test/results/resumed-c62e02ac-native44/postmortem-sql.log)
shows its original intent interval was 1.578494 seconds from capture insertion,
the encrypted intent was stored after 157 ms, both audit phases were acknowledged,
and the capture remained `intent_audited` with one reserved custody attempt and
no execution row.

The first start failed the closing local protection check during dispatch with
less than 0.5 seconds left. That diagnostic still represents positive remaining
time; it does not identify expiry as the underlying cause. The original
`bound=start` label also conflates an inherited earlier request cutoff with
the start's own five-second cap. After one acknowledged resolution, the next
same-identity request and its resolution ended in HTTP/2 transport errors.
Their SQL audit intents were started but never acknowledged. The visible
resolution timing spent at least three seconds reading the provider's current
configuration, before mounted credentials or provider access. Its single
registry SQL pool is under investigation; the logs do not establish pool
exhaustion or justify increasing connection limits. Acquisition, publication,
native download, revocation and deletion remain unqualified.

Test and harness exited 1 after 1,236.374 seconds. All 2,745 source hashes
match the commit and stayed unchanged. The failed fixture was retained only
for read-only inspection; subsequent owned cleanup exited 0 with no failures.
Independent Docker read-back confirmed both clusters, six service containers,
the owned volume, image and two networks absent. Build scratch was removed.
The first postmortem query used an incorrect table name and exited 3; the
corrected read-only query exited 0. Both outputs remain in the local full archive.

The [subsequent frozen run `context-mcw3di7n`](../test/results/resumed-c62e02ac-native43/result.json)
on `a565c2db` includes the canonical regional start CRD prerequisite and
corrected publication grants. Bootstrap, exact regional join replay, readiness,
processing initialization and preview passed. The regional demand lane returned
six distinct observations and 24 usable samples in 15 seconds. The original
capture and two acknowledged same-identity continuations returned
`OutcomeUnknown`; the next resolution exhausted the unchanged two-record audit
reservation. The visible continuation timing stops at capture-intent handling,
before the start call. Its underlying failure remains under investigation;
the unsampled first request's missing timing line is not evidence that admission
was skipped. No acquisition, publication, download, revocation or deletion is
qualified by this run.

Test and harness exited 1 after 1,223.896 seconds. All 2,742 source hashes match
the commit, sources stayed unchanged, cleanup reported no failures, build
scratch was removed and owned resources were absent. [CI on this exact candidate](https://github.com/phihos/asservat/actions/runs/39433014527)
passed all 15 jobs, including ten Go shards and browser checks. Independent
review found no further blockers in the regional prerequisite and publication
grant changes; this does not supersede the failed installed qualification.

The subsequent diagnostic regressions reproduced lost capture-intent failure
stages, absent submission diagnostics and discarded HTTP read status. Fixed
private labels now distinguish persistence stages, allowlisted dependency
results and the original phase call's live/cancelled/expired state. Actual TLS
read tests retain exactly one GET and no PUT for 403, 404 and 503 responses.
The partial-write regression preserves the spent claim and two finite
reconciliation reads; it never recreates a missing object or starts acquisition.
Focused race tests and the full audit/capture/objectstore race suites pass
(1.172, 3.026 and 4.516 seconds). Specification, architecture, dependency,
embedded schema/CRD and `go vet ./...` gates pass. These diagnostics do not fix
or establish the underlying native43 failure. Native44 above includes them
and its retained-fixture postmortem.

The [frozen run `context-thfmy2s8`](../test/results/resumed-c62e02ac-native42/result.json)
on `4110072f` progressed beyond the previous target-query failures. The preview
and exact-Pod request queries completed in 840 ms and 1.1 seconds. The request
reached SQL admission and capture-intent handling; two acknowledged original-key
resolutions retained the same accepted capture identity and permitted
continuation. The first dispatch failed its final local-route check with less
than 0.5 seconds left on the original start bound. A later continuation failed
`execute/PrepareStart` with at least two seconds left. The third resolution
exhausted the unchanged two-record audit reservation. Acquisition, publication,
native download, revocation and deletion remain unqualified.

The test failed after 1,287.109 seconds; test and harness both exited 1.
All 2,740 source hashes match the commit, sources stayed unchanged, cleanup
reported no failures, build scratch was removed and owned resources were absent.
The regional refresh lane produced six distinct observations and 31 usable
samples in 15 seconds. [CI on the same source](https://github.com/phihos/asservat/actions/runs/39426520951)
passed all checks, including all ten Go shards and console browser checks.

Read-only review also found that the compiled `context-verify` and
`context-publish` roles omit five retention-table reads required inside their
effect transactions. Existing fixture roles grant those reads separately,
masking this installed-role defect. The run did not reach publication.
A regression using the exact compiled roles and the new `PrepareStart`
failure investigation reproduced two independent defects. The
[real SQL/S3 regression](../test/results/resumed-c62e02ac-publication-grants-red/result.json)
on `67638285` failed both fresh compiled-role publication cases; PostgreSQL
reported `permission denied for table retention_source` at each transaction's
accepted-source read. Test and harness exited 1, all 2,713 source hashes
matched, sources stayed unchanged and cleanup reported no failures.
The grant correction adds only the five retention SELECTs to each purpose.
PostgreSQL package race checks (2.111 seconds) and SQL generation checks
(54 matching files) pass. The [corrected real SQL/S3 run](../test/results/resumed-c62e02ac-publication-grants-green/result.json)
on `45e509cc` passes both independent fresh compiled-role lifecycles, including
publication, historical replay, purpose isolation and deletion assertions.
The test package completed in 8.673 seconds; test and harness exited 0, all
2,714 source hashes matched, sources stayed unchanged, cleanup reported no
failures and owned containers were absent. Authority inputs remain explicit
synthetic fixtures; installed publication still requires native qualification.

The regional fixture also omitted the operator-installed
`CapacityReservation` CRD required by `PrepareStart`. The existing Helm
contract assigns CRDs to the operator in every cluster. A TLS CLI regression
confirmed that the installer previously attempted namespace creation without
checking this API. An executor-only bounded discovery preflight and canonical
regional fixture prerequisite are implemented. All 24 preflight race scenarios
pass, including oversized success/error bodies, retry suppression, original
caller bounds and unchanged connector-only behavior. Independent review found
no remaining production blockers. Discovery provides no
schema or execution authority, and the installer gains no CRD mutation rights.
Native42's closed `PrepareStart` error did not expose the underlying API status;
the prerequisite gap is established from the fixture and request path, not a
captured native 404 response.

The full bootstrap race suite (33.140 seconds), focused existing regional
Kubernetes race checks (1.056 seconds), integration compile check, `go vet ./...`,
specification, architecture, dependency and embedded schema/CRD gates pass.
An earlier combined bootstrap/Kubernetes race command was explicitly cancelled
with exit 143 before the Kubernetes tests began; it is not passing evidence.
The repository's full Kubernetes test sharding remains the CI gate.

The subsequent storage-wait regression reproduced blocked independent facts
reads and a duplicate request wait: Request performed two readiness reads
before its authoritative storage read. A single cancellable wait now overlaps
the unchanged eligibility/capability/retention sequence and joins before that
authoritative read. Barrier tests cover overlap, one request wait, original
target expiry and joined cancellation after early fact failure. The complete
capture package passed the race detector (3.030 seconds). This addresses
secondary latency pressure; native41's capture requests failed earlier, in
their target exchanges.

An actual HTTP/2 regression also reproduced a completed query's retained
socket deadline cancelling the next query with more than three seconds left
on its independent caller and a live original standby.
[ADR-211](decisions/211-completed-query-standby-transition.md) records the
implemented bounded phase transition and exclusive query reservation.
The native log alone cannot attribute every stream failure to this mechanism.
Only a complete matched answer under all original bounds restores both hub
socket deadlines to the original standby cutoff. Returned facts retain the
earliest contributing proof cutoff. A busy query excludes attachment and other
queries through joined completion; a terminal failure withdraws the standby
before publishing its result, without releasing closing capacity.

Actual HTTP/2 regressions pass for a delayed next peer check, an idle gap and
subsequent independently leased work. Negative component tests cover original
expiry/cancellation, malformed answers, unknown failures, peer revocation,
attempted work, failed deadline hooks and closure races. The full context-start
and mTLS packages passed `go test -race -count=1 -timeout=180s` (2.783 and
34.382 seconds); independent review found no remaining blockers. Specification,
architecture, Go dependency, embedded schema/CRD gates and `go vet ./...` pass.
These changes still require a fresh frozen installed qualification.

The [next owned run `context--pw-gu20`](../test/results/resumed-c62e02ac-native41/result.json)
on frozen `4db57af3` used the corrected 114 ordinary/118 total SQL connection
budget. The test failed after 1,313.476 seconds; test and harness both exited 1.
All 2,735 recorded source hashes match the commit, sources stayed unchanged,
cleanup reported no failures, build scratch was removed and owned resources
were absent afterward.

Bootstrap, cluster join/replay, hub restart, processing initialization and
multiple previews passed. The regional demand lane produced six distinct
binding observations and 22 samples with at least one second left in 15 seconds.
Three capture requests failed their target exchanges (`receive-call/canceled`,
`read/other` and `owner/canceled`). The first two original-key resolutions
acknowledged closure; the third resolution was refused at `audit-begin/reserve`.
No accepted capture, publication, download, revocation or deletion was qualified.
The earlier multi-second audit credential SQL reads did not recur, which does
not establish their previous cause. The subsequent stream phase/deadline
and storage-wait fixes above have component evidence only; original authority
cutoffs and finite audit budgets are unchanged.

Final composition review reproduced two additional diagnostic defects.
Processing refusal diagnostics detached from request cancellation and could
perform three new dependency reads after cancellation. They now retain the
original caller's deadline/cancellation and a five-second child cap, checking
cancellation between reads. Diagnostic timing values also became permanent
log-count keys: 32 timing variants emitted 32 first-occurrence lines. Stable
event keys now remain separate from timing payloads; each logger retains at
most 128 keys and one overflow counter, with finite text and saturating counts.
Focused failing-before regressions and affected diagnostic race tests pass.
These changes are separate from the frozen installed run on `4db57af3`.
The complete bootstrap, context-start and presentation packages subsequently
passed `go test -race -count=1 -timeout=3m` (31.562, 2.186 and 13.277 seconds).
Specification, architecture and Go dependency gates also passed.

[CI on `4db57af3`](https://github.com/phihos/asservat/actions/runs/39420452650)
passed every check except test shard zero and the aggregate gate. The sole
test failure was the bootstrap stop-message assertion still expecting 112
ordinary connections after the inventory correction to 114. That assertion
now matches the compiled budget; the focused bootstrap/contract tests pass.
The other nine test shards, console, build and static checks passed.

Ordinary [CI on `5675db4b`](https://github.com/phihos/asservat/actions/runs/39416417613)
passes all checks, including console browser tests and all ten Go test shards.
The first resumed CI exposed a stale pointer-equality assertion in the regional
diagnostic fixture: errors now carry a fixed stage while preserving their cause.
The assertion now uses `errors.Is`; the complete in-process integration package
passes under the race detector. This is not external fixture qualification.

Independent review found two composition defects. The processing route's
context timeout did not interrupt a stalled body read, and principal accounting
started only after that read. The handler now installs socket deadlines, owns
the principal slot before body parsing, joins cancellation before releasing
slots, and retains the earliest original request/session/receipt deadline
through response flush. Real TLS regressions first reproduced the stalled
body, duplicate principal and lost response-bound failures; the full browser
package passes with the race detector. The diagnostic nil-handler panic also
has a failing-then-passing regression and passing package tests.

The second defect omitted each worker's browser-settings connection from the
installed SQL inventory. The budget now derives its permission purposes from
the same selection as the worker: 20 purposes per worker, 114 ordinary product
connections, or 117 total with three superuser-reserved connections. The
unchanged fixture helper adds its independent observer and derives 118 total.
No role ceiling or individual pool limit changes. Contract/PostgreSQL race
tests, six fixture-selection tests and specification/architecture gates pass.
This corrects a declared maximum, not a measured connection leak.

The [owned two-cluster run `context-9vds9lz9`](../test/results/resumed-c62e02ac-native40/result.json)
failed at `534b0735`, before these review fixes, with its original
116-connection fixture budget. The test and harness both exited 1. All 2,731
recorded source hashes match the commit; sources stayed unchanged, build
scratch was removed, cleanup reported no failures, and owned containers and
clusters were absent afterward. It cannot qualify the corrected budget or
processing transport.

Bootstrap, cluster join, sustained regional capacity demand, console processing
initialization and preview succeeded. The preview's target exchange took
800 ms and its decoded result passed final validation. The capture request's
target exchange then failed at `read/other` after 100 ms. Its outcome audit and
the original-key resolution audit spent at least three seconds in
`credentials-configuration`, and both client calls ended with transport errors.
No accepted capture result was obtained. Capture, publication, native download,
revocation and deletion remain unqualified. The shared configuration SQL read
is under investigation; these timings alone do not establish its blocking
cause, and no authority interval has been extended.

The subsequent diagnostic regression reproduces lost SQL failure detail at
both audit credential reads and provider refresh. Closed labels now preserve
transaction-entry deadline, statement failure and rejected original-interval
distinctions. Focused failing-before tests and full PostgreSQL/KMS package race
tests pass. This instrumentation does not establish native40's blocking cause.

The router regression also reproduced selection of a cancelled stream while
socket cleanup remained blocked. Router selection/current checks now inspect
the stream's cancellation directly, and a joined callback cancels its standby.
Both standby and capture reservations stay charged until operation and socket
cleanup join. The original retained read deadline is unchanged. Full
context-start race tests and actual HTTP/2 context-start tests pass; independent
review found no blocker. This is a demonstrated lifecycle defect, not proof
that it caused native40's request failure.

## Recovered installed journey, hold 38 (2026-10-20)

Claude session `c62e02ac-2970-4821-8f4d-d584e5ea4d8c` stopped before
reading hold 38 on `007f1fb5`. The [recovered result](../test/results/resumed-c62e02ac-hold38/result.json)
records the actual test exit 1; the local shell wrapper incorrectly returned 0.
All 2,716 recorded source hashes match that commit. The harness retained its
owned resources; an empty cleanup-failure list does not mean those resources
were removed. The retained database had one preview, no capture and no
execution. The first request and four accepted-only continuation calls returned
`OutcomeUnknown`; no capture, publication, download or deletion was qualified.

The journey now resolves the original preview/key after an uncertain or changed
request. Only acknowledged closure permits another fixture review; only an
acknowledged accepted capture permits continuation. Unknown resolution,
changed accepted identity and spent preparation cannot create a replacement.
Focused journey race regressions pass, including cancellation and finite
continuation. This corrects the client fixture, not product acquisition authority.

The target-query diagnostic previously logged `ok` before checking the
decoded answer and its original receiver/target cutoffs. It now reports the
final validation result, distinguishing receiver expiry, regional target expiry
and an invalid result without exposing target metadata. The actual-router
regression passes under the race detector. Hold 38 does not establish which
cutoff expired; that remains a hypothesis until these diagnostics run natively.
No original deadline or authorization check has been relaxed.

PR #40's latest ordinary CI failed before Go tests because `gh pr diff` refused
more than 300 changed files. The bounded file-list lookup now runs all code
checks for a full page or any unavailable/incomplete result, and considers both
paths of a rename. Seven detector regressions and the complete 53-test harness
self-test step pass locally.

[PR #41](https://github.com/phihos/asservat/pull/41) merged at
`29a24582ebd46f66e4448ce48fb1d109a9e07690` after independent local review,
verification of its archived source hashes and successful ordinary CI.
That lands the scoped deletion composition; the installed end-to-end journey
and S-02 remain incomplete on PR #40.

## Local holds 11–24: processing initialization and console login (2026-10-20)

Hold 11 showed `processing_root.initialized_at` NULL: no installed path performs
ADR-127's operator initialization, so every preview refused at
`processing/read/root-invalid`. Holds 12–14 marked the root initialized by
direct fixture SQL (experiment only, not a product path). Coverage then refused
every preview as known insufficient coverage: the deletion date (600 s plus the
3600 s deletion budget) lay after the processing root's end, which 60 s
renewals keep about a minute ahead. With the journey profile's one-day
`AdmissionSeconds` (`75a51df`), hold 14 returned four of seven previews `ok`.
Hold 15 then ran the journey on to `request_capture`, which returned
`OutcomeUnknown`.

ADR-210 adds the installed path: the console route
`POST /api/v1/processing/changes`, the hub SQL purpose `processing-decision`
(ordinal 92, the component role's exact grants), the hub-api's guarded read of
the capacity processing source with the joined clusters' derived paths, and the
hub-worker's browser settings projection (ADR-184's open gap; no installed
console login was possible before). Holds 17–23 each found one composition
defect (nil paths, unmounted login, missing derived paths) or an intermittent
install failure. Hold 24 (`adf3ce0`) logged "the processing operator
initialized processing through the console".

Hold 24's capture requests then took 3 s or more outside every marked preview
step, one at the 5 s transport bound and one `OutcomeUnknown`. `1a09145`
marks target resolution, admission, the intent read, the regional start's
reads, attach, signing and run. Release changes and browser session cleanup
remain unimplemented. Longer retention than the remaining processing root
interval is refused by design (ADR-210 consequences).

## Local holds 7–10: regional limiter, then the processing root budget (2026-10-20)

Hold 7 (`bd2b244`) split the remaining time. The region's target answer spent
1–3 s in the connector's local proof (`r-local`), and every capacity refresh
spent 2.16–2.25 s in the claim (`c-post`, owner `observe`). The region's
kube-apiserver answered non-watch requests in about 1 ms on average, while one
regional capacity cycle makes about 63 calls on 20 QPS / burst 20 clients
(≈2.15 s of limiter waits). ADR-208 now covers the regional capacity and
lifecycle clients (`0c25531`). Hold 10 measured `r-local` under 100 ms,
`q-answer` about 0.9 s, every target query `ok`, and capacity refreshes of
1.9–2.3 s.

Hold 10's previews then refused at `processing/read/root-invalid` and
`processing/current`. Live SQL showed the cause: every sixty-second capacity
root renewal spends one processing `root_transitions` (lifetime, never
reclaimed) and one `configuration_spent`. The journey profile set
`MaxRootTransitions: 8` and `ConfigurationTransitions: 100`, so the ninth
renewal failed `processing_root_check3` (100 logged attempts) and the processing
root expired about nine minutes after install; `configuration_spent` was 81.
CI native 75 (`0c25531`, run 39336623616) refused at the same step. The journey
profile now sizes both for about 150 renewals (512 / 4096), and the root loop
logs its outcome per change (`capacity root:`); it was discarded before.

Holds 8 and 9 stopped during install (owner exit after `provider refresh:
audit-wrap final-proof`, and `public/roles-provision ... (changed)`) while
another session loaded the host; both are hub-side and unrelated to the
regional change. Each hold allows about seven previews: the installed
per-account audit record budget then refuses `audit-begin/reserve`.

## Local journey holds 4–6: claim and regional answer dominate (2026-10-19)

Hold 4 produced no previews: the collector read hold 3's stale `out` file
before the new run replaced it. After the 90-minute hold expired, the resumed
journey's Keycloak refresh returned 400 (expected after a long pause; holds are
ended with `stop`). Hold 5 stopped at `public/roles-projection` (unavailable,
23 attempts), earlier seen once in `adr183-continuation-native-14`; not on the
preview path and not yet explained.

Hold 6 (`edbb701`) ran eight previews: five `NotAvailable`, two 5 s transport
stream errors and one `audit-begin/reserve` 503. Measured, not inferred:

- hub target query `q-answer` (waiting for the region's answer) 2–2.4 s of a
  2.6–3.7 s query; `q-source`/`q-check` stay under 400 ms except one 1.04 s
  source pull. One region check failed at its local source protection probe
  (`source.probe-object-read` cancelled at its 960 ms bound).
- capacity demand refresh: `o-claim` under 3 s bucket of a 2.2–3.2 s guarded
  read; candidates/routes/locate stay under 250 ms (one locate under 2 s).
  Refreshes with no located owner fail fast in 50–100 ms.

`e0480b3`/`bd2b244` add region answer steps (`r-check` with `r-local`/`r-owner`,
`r-resolve`, `r-write`), hub claim steps (`c-open`, `c-before`, `c-post`,
`c-after`, `c-final`, `c-current`) and owner claim steps (pending,
registration, native-claim, select, observe, final). Hold 7 runs on `bd2b244`.

## Local journey hold 3: binding refresh is latency, not rate (2026-10-19)

With the regional observation clients on the opening limiter (frozen
`8ce7951`), eight live previews all failed on time. Demand refreshes were
steady at 2.3 s, 2.2 s of it the guarded regional read, so that read is path
latency rather than client throttling; each refreshed binding has about 2 s
left. Target queries took 1 to over 3 s and the region's query check failed in
its local process proof (`regional-query-local`). Other refusals
(`facts/current`, `processing/read/root-invalid`, retention `topology`,
`facts/storage`) are facts whose five-second windows lapsed during the
preview. Hub target queries now report source, check, answer and total
durations on every query, and the hub-worker's regional observation reports
its candidates, routes, locate and claim stages in the demand line.

## Local journey hold: live previews (2026-10-19)

`ASSERVAT_JOURNEY_HOLD` (local only) now pauses the installed journey with the
installation live and runs preview commands from a directory, so a preview
takes seconds instead of a 22-minute run. Native 72 stopped before preview at
the regional capacity demand check (`regional binding was not refreshed on
demand`), with only a diagnostic change; native 73 (`b6aab94`) showed the
capability read under 100 ms and refused at `processing/read/root-invalid`
twice. The processing root is renewed only in its last ten seconds; one
renewal landed at expiry, another 9 s before it.

Six live previews on frozen `c8ed270` all failed on time: target queries took
1–3 s and the region's current owner check during a query failed in about half
of them (`exchange/regional-query-owner/unavailable|denied`, seen by the hub
as `read/other`); the storage wait took 2–3 s because each demand refresh's
guarded regional read takes 2.6–3.7 s (the region's own read about 0.45 s)
and leaves the binding about 2 s of freshness. The region's check now names
the failing half (`regional-query-local` or `regional-query-owner-auth`), and
demand refreshes report their stage durations.

## Local run 3 and native 71: preview stage timing (2026-10-19)

Local run 3 (frozen `225444f`) and native 71 (`2c005fd`, preview `ErrChanged`
mapped to retryable) failed at preview. Stage timing in local run 3: identity,
recovery, storage wait, eligibility and storage under 100 ms; target 0.5–1 s;
retention under 500 ms; capability 1–2 s. The capability source and catalog
protection used the owner's shared 20/20 observer, so the public context now
gets its own clients with the ADR-208 opening limiter. Later attempts spent 3 s
or more in the audit credential read again; its configuration, mounted,
verify and final steps now report their durations too. Native 71 refused at
`processing/read`, at `router` after waiting, with a target query reaching its
deadline (`receive-bound/deadline`), and at eligibility.

## Installed native 70: retention passes; processing step lost in the ledger (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39279970394)
on frozen `0dd887c3a77217897264b52a71a6944578a73468` (separate retention
clients, before the preview `ReviewChanged` mapping) failed at preview without
a retention refusal: one attempt refused at `processing/read`, one ran out of
time at eligibility, and the third ended `ReviewChanged` from `facts/current`,
fixed in the following commit. The processing refusal carried no step because
the ledger transaction normalizes errors returned through it; the coverage read
now keeps its step beside the transaction and reports `tx` for pool, BEGIN or
COMMIT failures.

[Archive verification](../test/results/installed-journey-ci-70/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Local run 2: retention source current; previews still run out of time (2026-10-19)

The local run on frozen `0dd887c` (separate retention follower clients)
sampled the hub `retention_source` row once per second through installation
and the journey: 425 of 456 samples were current, against about half before
and about one in seven after a hub-worker restart. No preview refused at
retention. Previews instead ran out of their five seconds at
`facts/eligibility/authority` (twice), and the last call was refused with 401.
The preview's own stages (identity, recovery, target, storage wait,
eligibility, capability, retention, storage, processing, store) now add
bucketed durations to the `mcp timing` line. The local run is not archived as
CI qualification evidence.

## Installed native 69: a lapsed preview fact surfaced as ReviewChanged (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39277451723)
on frozen `3b91ab707435bbbdbb1c55b5f9e1a231751ca727` (router waits for a
standby) failed at preview. One attempt refused at
`facts/retention/read/source-hub`, one at `target` (`read/other`), and the
third at `facts/current`: an observation lapsed while the preview was being
assembled. That `ErrChanged` reached MCP as the non-retryable `ReviewChanged`,
which the journey rejects (the unexpected code in native 63 too). A preview has
no earlier review to resolve, so preview `ErrChanged` now maps to the retryable
`NotAvailable`; request and resolution keep `ReviewChanged`.

[Archive verification](../test/results/installed-journey-ci-69/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Local reproduction: hub retention source current only about half the time (2026-10-19)

A local `--keep-on-failure` run of the same suite (frozen `0480509`) sampled the
hub `retention_source` row once per second for 40 s during installation: each
observation was written with 2–3 s of its five seconds left and the next one
landed 3–6 s later, so `fresh_until` had passed for roughly half the samples
while the 30-second lease stayed live. That explains native 68's
`facts/retention/read/source-hub`. The retention follower shared the permission
worker's 20/20 observer and probe clients with the permission reconciler; it
now has its own clients with the ADR-208 opening limiter. Observation content,
cadence rules and freshness bounds are unchanged; whether this restores
continuous freshness is for the next run to show.

## Installed native 68: hub retention source not current; router waits for a standby (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39272153061)
on frozen `0480509c864b4e5f02416166e42f6a93c5543292` failed at preview. The
attempt that passed target and eligibility refused at
`facts/retention/read/source-hub`: the hub's accepted retention source was not
current when read. The others found no idle standby or a broken query stream.
A target query that finds no idle standby now waits for the next registration
within its original deadline, keeping 2.5 seconds for the query and the
preview's later checks; without that room it fails at once as before. The
harness's in-Pod build scratch now honours `TMPDIR` (CI is unchanged), so the
suite also runs locally with `--keep-on-failure` on disk-backed scratch.

[Archive verification](../test/results/installed-journey-ci-68/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 67: preview reaches processing coverage (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39265098434)
on frozen `825466ad4753c3e819659496afded02c5bbb5a27` failed at preview. With the
thirty-second retry after TLS refusals, openings refused at TLS fell from 32 or
more to under 8 and at `setup-begin` from 8 or more to under 4. The first
attempt passed target resolution, eligibility, retention and storage and was
refused at `processing/read` with a retryable `NotAvailable` (no PostgreSQL
error for the processing role, so an `ErrUnavailable` check rather than a
known coverage limitation). The others found no idle standby, a broken hub
query (`hub-query/unavailable`) or ran out of time at eligibility. Processing
coverage reads now name their failing step. The local Go gate passed.

[Archive verification](../test/results/installed-journey-ci-67/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 66: openings to unserved owners starve the live opening (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39257553144)
on frozen `0aa44cc03c4ee5fe1455a298cb52d26709e8af7d` failed at preview: one cold
attempt ran out of time at eligibility and three found no idle standby. Only
two regional exchanges opened. Openings to the live owner mostly refused at
`setup-begin` within 10 ms–2.4 s and without a setup trace, while openings to
registered owner processes the hub no longer serves (after the test's hub
restart) were refused at TLS 32 or more times (`unknown-name` on the hub). Each
of those runs a full connector setup proof first, and concurrent openings share
one coalesced proof whose failure or invalidation fails every waiter. After a
TLS refusal the region now waits thirty seconds before trying that owner again;
other ends keep the one-second retry, and every opening check is unchanged.
Retention steps for a failed accepted-policy read are also named now. The local
Go gate for this commit passed.

[Archive verification](../test/results/installed-journey-ci-66/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 65: ADR-209 withdrawn; retention refuses after eligibility (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39253398865)
on frozen `f6680d5cced3588664daced5cff2fa1b55203991` (ADR-209) failed at
preview. One attempt passed target resolution and eligibility in under 3 s and
refused at `facts/retention`, as in native 61; two found no idle standby.
ADR-209 rested on a wrong limit: the cluster join reserves one standby per
cluster by default, so the hub refused second exchanges at `standby` and the
concurrent setups refused each other at `setup-begin` (32 or more). ADR-209 is
withdrawn and its code reverted. Retention preview refusals now name a closed
class (`read`, `invalid`, `conflict`, `expired`, `unavailable`, `other`). The
local Go gate failed once in the browser test
`TestInvestigationFinalIdentityShorteningReachesSocket`, which passed five of
five isolated race runs on this commit and on the commit before the MCP timing
change.

[Archive verification](../test/results/installed-journey-ci-65/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 64: audits fast; previews wait for storage or find no standby (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39249314109)
on frozen `47067a747a5182d76332f249e3dd47a02e732d2d` failed at preview, all
attempts `NotAvailable` and retryable. Each operation audit now takes under
250 ms, so ADR-208's audit credential change took effect. The first preview
resolved its target and then spent the rest of its five seconds in
`awaitStorage`: a cold storage binding needs a capacity demand refresh, which
took about 2.5 s, before eligibility met an expired request. The other attempts
found no idle standby (`router`). The region held one exchange per hub owner;
over the journey window it had three standbys of at most 30 s, each reopened
one second after ending and often after several refused attempts. ADR-209 now
allows two exchanges per owner within the hub's existing per-cluster standby
limit. Native 63's unexpected public code did not recur.

[Archive verification](../test/results/installed-journey-ci-64/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 63: preview answers quickly with an unexpected public code (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39245953884)
on frozen `b6d9eace5eed35c0cb7cf2aac2a1ab5f817126fd` (opening limiter for the
audit credential reader) answered preview attempts in 3.5 s and then 410 ms.
The third attempt returned a schema-valid public error whose code was not
`NotAvailable`; the journey test failed on it without logging the code or
collecting hub diagnostics. The test now names the closed public code and
collects diagnostics before failing. The local Go gate failed once in
`TestConfigurationWorkerDiagnosticBlockedReadKeepsOriginalDeadline`, which
passed three of three isolated race runs and is in code this branch does not
change.

[Archive verification](../test/results/installed-journey-ci-63/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 62: audit credential reads take 1–3 s each (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39240209621)
on frozen `3103ae9c1586343def69a337f35ed0ac1f38d92c` failed at preview with the
same refusals. The audit step marks put the time in the installed audit
credential observation: 1–3 s before each of the two audit object writes, while
SQL reserve/claim/acknowledge, sealing, the PUT and verification each took under
100 ms. That read re-verifies the owner identity, the credential Secret and the
workload guard, about 50–70 sequential calls on clients limited to 20/20. Under
ADR-208 its two clients now use the opening limiter; the proofs and the
request's original five seconds are unchanged. The local Go gate for this
commit passed.

[Archive verification](../test/results/installed-journey-ci-62/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 61: operation audits take over three of the five seconds (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39234310862)
on frozen `4db57311e13ca977c280b81456ff589e095a7dd3` failed at preview. The new
`mcp timing` lines show the audited call's opening audit Begin at 1–2 s and its
closing Finish at 1–3 s; a call that failed at once still totalled over 3 s.
Calls that resolved a target took 2–3 s or more, so eligibility met an expired
request (`facts/eligibility/authority`); one attempt reached `facts/retention`.
Audit SQL logins are pooled (four connections per audit role over the run), so
the time is in the audit object path. Begin and Finish now also report bucketed
reserve/claim/object/acknowledge steps, and the installed object path
credential observation, seal, put and verify. The local Go gate for this commit
passed.

[Archive verification](../test/results/installed-journey-ci-61/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 60: targets resolve; preview runs out of its five seconds (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39227859804)
on frozen `0be9901ce98621162fe21a585570f6c2f785f4c4` (regional target reads)
resolved preview targets for the first time and then refused at
`facts/eligibility/authority`. That reason means the request context had
expired (permission stream failures report `PermissionUnavailable`). The
alternating attempts refused at `router` after exactly 3.34 s: the MCP
operation's original deadline (at most five seconds, set before its audit
Begin) covers the opening audit, an identity recheck, the preview and the
closing audit, and an earlier interrupted preview had consumed the standby.
Audited MCP calls now report fixed duration buckets for preparation, audit
Begin, the call and audit Finish (`mcp timing`) to locate the time; no
deadline changed.

The single `permission_stream` denial for `permission-read` recorded in earlier
runs is the regional journey's own negative probe
(`installedPermissionObserver` requires `42501` for `UPDATE ... WHERE false`),
not a product failure. After the test's deliberate hub-worker restart the
permission reconciler logs one `start/begin (changed)` while the crashed
process's 30-second lease is live and retries after 31 s, as designed.

The full local Go gate for this commit passed; an additional isolated rerun of
the three load-sensitive owner fixture tests failed once under a load average
of about 23.

[Archive verification](../test/results/installed-journey-ci-60/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 59: regional target resolution denied by RBAC (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39222603037)
on frozen `91e0cd02ea37ccdaf648cf0e5ae091f40206cbc7` passed capacity projection
and reached preview. Every target query now reached the region and got a closed
`answer/denied`; two previews were therefore non-retryable. The region resolves
the target through Pod → ReplicaSet → Deployment, but its installed ClusterRole
only allowed ReplicaSet reads in its own namespace, so the API returned 403
(ADR-179 had assumed this access existed for collection). The regional executor
ClusterRole now grants read-only get on namespaces, Deployments, StatefulSets
and ReplicaSets and get/list on Pods cluster-wide; a unit test failed before
the change and passes after it. The hub's context-start clients made about
1015 calls over the run (roughly 2–4 per second), well under the opening
limiter. A one-time `publisher/catalog-changed` service restart was also
logged.

[Archive verification](../test/results/installed-journey-ci-59/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 58: capacity projection claimed with 3 ms left (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39219349203)
on frozen `bb90c7d2b74a87db294b6eda73b700f5fd55cd6b` (50 QPS opening clients)
stopped before preview, at `capacity/projection`, which took about 3.4 s in
native 56/57. Its first attempt reached `claim-write` 155 ms in with 3 ms of
original validity left, so it wrote a claim it could not complete. An attempted
claim is lookup-only afterwards, so the remaining 33 attempts within the
minute failed (last at `local-owner`). `capacity/initialize` also took 1m18s
against about 35 s before. The hub's context-start clients had made no calls,
so the limiter change was not involved. Capacity and permission projection
claims now require at least one second of original validity before the claim
write (`projectionClaimUntil`, as the worker admission floor); declining starts
no effect and the original bounds are unchanged.

Local Go gates for native 56–58 commits failed each time in one or two
different timing-sensitive Kubernetes fixture tests while an unrelated build on
this host held the load average near 60 on 16 cores; each failure is in code
this branch does not change.

[Archive verification](../test/results/installed-journey-ci-58/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 57: target queries fail three ways; opening clients revised to 50 QPS (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39215209940)
on frozen `60e6d45c4bf0846ef973755e72e0537e6e7a41ee` failed before capture.
No target query succeeded. The new steps show `read/other` (stream broken,
start at least 2 s, end under 2 s), `receive-peer/denied` (waiting for the
regional answer until under 0.5 s remained) and `router` (no idle standby).
Regional exchanges ended `passive-call/deadline`. One attempt stopped earlier
at `audit-begin/reserve`. The restarted hub refused its own protection reads
with at least 2 seconds left after about eight openings, which matches a
drained 100-token bucket at 20 QPS. ADR-208 now gives the four opening clients
50 QPS/burst 100, and the hub reports their call count. The single
`permission_stream` denial for `permission-read` recurs once per run, as in
earlier runs; its statement is not logged and it is not yet tied to a step.

[Archive verification](../test/results/installed-journey-ci-57/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

The local Go gate failed once again in Kubernetes group 13
(`TestOwnerProjectionSplitExactGraphsAndPrivateAdmission/launch-receipt`,
`projection.provider-observe`), the same unmodified owner-projection fixture
family as before.

## Installed native 56: openings reach exchanges, preview target queries fail (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39211173709)
on frozen `9d074033fd6119d98fce9da4f44f16885a79b454` (ADR-208 burst-100 opening
clients) failed before capture. Hub ingress refusals fell from about 25 to 4
and regional standbys reached `exchange` for the first time, ending
`unavailable`. Three of four preview calls ran to the five-second request bound
(HTTP/2 `INTERNAL_ERROR`) and the fourth refused at `target` after 3.35 s. The
hub restart (`phase=full-runtime reason=changed`) and `unknown-name` router
counts were already present in native 54/55. Neither the hub target query nor
the regional exchange reported a step, so query failures now report the
stream's first fixed stage/reason (new `hub-query-source`, `hub-query-check`,
`regional-query-owner`, `regional-query-write`), a closed regional `answer`
label or `router`, with remaining-time buckets at start and end.

[Archive verification](../test/results/installed-journey-ci-56/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

The local Go gate for this commit failed once in
`TestOwnerProjectionFinalizationExactGraphsAndReadOnlyResults` (`unavailable
after 760ms`); the test passed three of three isolated race runs and in the
previous full gate. It is recorded as timing-sensitive under load, not fixed.

## Context-start opening clients get a burst of 100 (2026-10-19)

[ADR-208](decisions/208-context-opening-client-burst.md): the regional context
and hub ingress self-authentication observer/probe clients keep 20 QPS with a
burst of 100 instead of 20. Native 55 measured about 1.3 ms per API call while
setup steps took 150–350 ms each, matching token waits past the burst. Checks
and deadlines are unchanged. Not yet qualified by an installed run.

## Installed native 55: opening self-authentication passes, both sides run out of time (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39206342897)
on frozen `94798519bf9a4929c0de1f0cd32296a55a3e0ebb` (separate hub ingress API
clients) failed before capture at the same preview point. Opening
self-authentication refusals with time left are gone; every hub refusal is now
closing (`final-local`, `final-source`) with under 0.5 seconds left. Connector
setup marks show the opening source read at 540 ms, the process proof at 1.84 s
and each later guard/settings check 150–350 ms, reaching 3.39 s; openings reach
`headers` after 3.0–4.6 seconds. Individual API calls average about 1.3 ms, so
the time fits the fixed 20 QPS/burst-20 client bucket (about 50 ms per call
after the burst) rather than API latency. Changing that documented limit or the
five-second window is a maintainer decision; neither was changed.

[Archive verification](../test/results/installed-journey-ci-55/verification.json)
matched all 2702 source hashes to the frozen commit; sources were unchanged,
test exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Hub context-start self-authentication gets its own API clients (2026-10-19)

Native54's opening self-authentication refusals with at least 2 seconds left
fit client-go's token bucket: `x/time/rate.Wait` fails at once when the wait
for a token would pass the context deadline, and the owner's shared 20 QPS
observer also serves the request paths (3429 calls over the run, average call
about 1.3 ms). The context-start ingress now builds its owner authenticator
from separate observer/probe clients through `OwnerWorkloadProtection.WithClients`
with the same guard plan, pins, routes and registry, as ADR-173 did for
readiness. The `route` refusal step now distinguishes `route-read` (read
error) from `route` (mismatch or expiry). No deadline or check changed. Not
yet qualified by an installed run.

## Installed native 54: setup completes, hub self-authentication still refuses (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39179599368)
on frozen `b955ecb0a142b932a4cfea8097306c2db76c9587` (separate regional context
API clients) failed before capture at the same preview point. Setup-step
refusals no longer appear apart from one at `setup-begin`, so the separate
clients let setup complete; openings still reach `headers` after about 3.0–3.4
seconds. Hub refusals are unchanged in kind: opening self-authentication
`unavailable` with at least 2 seconds left (`route`, protection reads) and
closing self-authentication with under 0.5 seconds left. The hub's ingress
self-authentication may share the owner's API clients with its readiness and
observer loops, as the regional context did; that, and why `route` fails with
time remaining, are unmeasured.

[Archive verification](../test/results/installed-journey-ci-54/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 53: setup reads queue on a shared API limiter (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39177467147)
on frozen `f42341db029fa14ea05a2992ed461f07702d9ff6` failed before capture at
the same preview point, now with setup marks. Of the setup proof's own five
seconds, the opening source read took 1.04–1.39 seconds and the process proof
1.3–2.6 seconds; the owned-process check took about 10 milliseconds, the
execution account 50–100 milliseconds and the six later checks about 1.5
seconds together. The regional context start shared one fixed 20 QPS
Kubernetes client with the regional source, workload guard and lifecycle
readers, while regional capacity already uses its own client instances of the
same identities after the same starvation (ADR-197 run 10). Context start now
builds its own observer/probe instances and its own guard and source readers
from the same plans: same identities, rights and fixed limits, separate
buckets. That this removes the queueing is a hypothesis for the next run.

[Archive verification](../test/results/installed-journey-ci-53/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 52: setup marks dropped by the producer re-wrap (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39175416010)
on frozen `5295886ede94a8e4c55d5623ac87177890b01b84` failed before capture with
the same timing shape as native51 (`setup-settings-guard` at 3.3–4.3 seconds
with 10–70 milliseconds left). Marks were still absent: the setup producer's
re-wrap kept only the fixed code and cutoff. It now also keeps the completed
check marks, which the receiving diagnostic restricts again.

[Archive verification](../test/results/installed-journey-ci-52/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 51: setup trace missing, first setup checks take ~3 seconds (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39173419544)
on frozen `5d5e7bdd74b4b8ca97d690b2449d6a8c1194cda0` failed before capture at
the same preview point. No setup marks were printed: the extraction matched an
outer wrapper's fixed step instead of the setup proof error, now fixed with a
regression. Openings spend about 0.7 seconds before setup, and
`setup-settings-guard` refusals at 3.0–4.0 seconds with 20–60 milliseconds left
place about three seconds in the first four setup checks (source open, owned
process, process proof, execution account). Which of those dominates is not
yet measured.

[Archive verification](../test/results/installed-journey-ci-51/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 50: connector setup consumes the opening interval (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39171254007)
on frozen `d322af7680b20de04d6edb0bc8d330ead3918375` (concurrent independent
ingress reads) failed before capture at the same preview point. Closing hub
refusals still had under 0.5 seconds left, so the hub-side concurrency did not
recover enough time. Client timings place the cost before the hub: openings
reach `headers` after 3.1–4.4 seconds of a 4.4–4.7 second bound, and setup
steps fail at 3–4 seconds with 0–80 milliseconds left. The connector setup
proof's per-check marks were not forwarded; the timing line now carries them
(fixed names and durations only, outside the count key) to locate the slow
checks. Review follow-ups now always join the closing ingress read and stop
step reports from a deliberately abandoned opening read.

[Archive verification](../test/results/installed-journey-ci-50/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 49: closing hub check runs out of time (2026-10-19)

The [continuation](https://github.com/phihos/asservat/actions/runs/39168966828)
on frozen `b2d443b3328ac1c1405aa821d4739219656ac377` failed before capture at
the same preview point. Remaining-time buckets separate two refusals. Every
closing `final-local` refusal had under 0.5 seconds or no time left (mostly at
`route`), so the closing hub self-authentication exhausts the original bound.
Opening `local` refusals had at least 2 seconds left (`route`, protection and
registration reads), so they are not time exhaustion and remain unexplained.
The connector bound cannot grow: it follows the lent source's original
interval, about 3 seconds of which setup already used. The ingress now runs
the hub's opening self-authentication alongside the connector source,
certificate and registration reads, and the closing source and hub rechecks
together, after both opening results. Every read and check remains and every
result still narrows the bound.

[Archive verification](../test/results/installed-journey-ci-49/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. PR40/41 remain held.

## Installed native 48: leaf read passes, hub self-authentication refuses (2026-10-18)

The [continuation](https://github.com/phihos/asservat/actions/runs/39166806580)
on frozen `b2a5ddd40e315e40855817248134d5a99d6b458e` (native47 plus the
native-read leaf grant) failed before capture at the same preview point. The
`registration` refusals and the function permission errors no longer occur.
Remaining ingress refusals are the hub's own serving-identity authentication:
the closing `final-local` check (at least 16), and the opening check at
`protection-before`, `route` and `protection-after`, all `unavailable`. The
capacity standby, which uses the same pair of owner checks with less work in
between, still completed. A remaining-time shortage after narrowing to the
connector's lent source is a hypothesis, not established; refusals now carry a
coarse remaining-time bucket and closing-step detail for the next run.

[Archive verification](../test/results/installed-journey-ci-48/verification.json)
matched all source hashes to the frozen commit; sources were unchanged, test
exit was 1 and owned cleanup reported no failures. Capture and later steps were
not reached. PR40/41 remain held.

## Installed native 47: hub refusals named, native-read lacked the leaf read (2026-10-18)

The [continuation](https://github.com/phihos/asservat/actions/runs/39164409930)
on frozen `173961a4c0e97b4277a3b96030c816765ef539b6` (native46 plus hub
refusal stages) failed before capture at the same preview point. The hub now
names its refusals: every `authenticate` refusal came from the ingress at
either `local` (the hub's own serving-identity authentication) or
`registration` (the connector's activated-leaf read), interleaved from the
first attempt. PostgreSQL recorded 25 `permission denied for function
read_connector_activated_leaf` for the owner `native-read` role, the pool the
ingress registry uses. That role now holds EXECUTE on that one read-only
function, with a regression requiring it for native-read only. The `local`
refusals remain unexplained; the owner authenticator now reports its failing
step for the next run. A separate `permission denied for table
permission_stream` on one publisher login is not yet explained.

The [retained log](../test/results/installed-journey-ci-47/context-storage.log)
shows the passive-command and administrator-removal subcases passing; capture
and later steps were not reached. PR40/41 remain held.
[Archive verification](../test/results/installed-journey-ci-47/verification.json)
matched all 2,701 source hashes to the frozen commit; sources were unchanged,
test exit was 1 and owned cleanup reported no failures.

## Installed native 46: owner authentication passes, hub refuses the opening (2026-10-18)

The [continuation](https://github.com/phihos/asservat/actions/runs/39162007897)
on frozen `12c9473695c79f638db7a9ece2958c82ad9a7680` (native45 plus the exact
federation owner-account read grant) again failed before capture: four preview
requests returned unavailable after 3.30–3.36 seconds at target resolution.
The native45 `owner-first (denied)` refusals no longer occur. Regional openings
now fail later, at `headers`: four `denied` (the hub answered with its private
404) and four `unavailable`, alongside setup, settings-guard, dial and TLS
failures. The hub handler and ingress refuse silently, so the refusing check is
not identified; they now report fixed stage names to the owner log for the next
run. This does not establish the underlying cause.

The [retained log](../test/results/installed-journey-ci-46/context-storage.log)
records the continuation subtest failing after 963.46 seconds; passive-command
and administrator-removal subcases passed. Capture, publication, native
download, expiry/deletion and faulted cleanup were not reached. PR40/41 remain
held. [Archive verification](../test/results/installed-journey-ci-46/verification.json)
matched all 2,700 source hashes to the frozen commit; sources were unchanged,
test exit was 1 and owned cleanup reported no failures.

## Installed native 45: first owner-authentication refusal (2026-10-18)

The [diagnostic continuation](https://github.com/phihos/asservat/actions/runs/39157052161)
on frozen `73316a3618a88635350c7169959936efdbc1e746` failed before capture.
Four preview requests returned unavailable after 3.328–3.437 seconds, again at
target resolution. The new regional opening diagnostics distinguish repeated
`owner-first` refusals after 3.30–3.31 seconds, with 0.66–1.46 seconds remaining
on the original bound, from separate setup, dial and TLS failures. Some setup
and TLS attempts exhausted their bound. The first-owner stage includes the
delegated authentication call and validation of its returned owner; it does
not establish the underlying refusal cause. No successful owner-authentication
conversation timing was recorded. The independent capacity channel continued
to complete observations.

The [retained log](../test/results/installed-journey-ci-45/context-storage.log)
records a 1,281.73-second top-level failure and a 958.17-second continuation
failure (package 1,281.826 seconds). Passive-command and administrator-removal
subcases passed. Capture, publication, native download, expiry/deletion and
faulted cleanup were not reached. PR40/41 remain held.

[Independent archive verification](../test/results/installed-journey-ci-45/verification.json)
matched all 2,699 source hashes to the frozen commit. Sources remained unchanged,
test exit was 1 and owned cleanup completed with no failures. The environment
report SHA-256 is `cd7178b984c94ec75dd92d86177085166d20eadd4f6c2be1059a34b7836ced00`.
All fifteen ordinary CI jobs passed for that same source; they do not replace
the failed installed acceptance test. The next task is to reproduce the
delegated owner-authentication refusal with concrete composition before another
full run. Original deadlines, permissions and resource ceilings remain binding.

## Context opening diagnostic candidate (2026-10-18)

The installed client passes the concrete setup producer directly; its capability
is not lost through a wrapper. Native44 still does not identify the failed
opening boundary. The candidate now reports closed discovery/setup/process,
TLS/peer, first-owner, source, headers/Hello, native Finish, closing-owner/process
and joined-close stages. A cold setup can report its exact fixed source/proof or
settings/workload check. Numeric elapsed and remaining original time are separate
from the finite event-count key. No authority read, deadline, retry, public field
or error classification changes. Dependency text and identities are excluded.

Before instrumentation, all 14 actual TLS/HTTP2 refusal-stage cases failed for
missing diagnostic metadata. Corrected races passed 32 top-level / 78 named
tests across mTLS, Kubernetes and bootstrap, including exact owner/process/source
call counts, original cutoff, cancellation, joined-close timing and exponential
suppression across different timings. Independent review found the cold proof's
final freshness code missing from the closed list; its added source-bound and
logger regression passed a further two top-level / six named races.
Touched-package vet and Go architecture (58 packages / 338 edges) passed.
Spec check passed 11,379 assertions and design architecture passed 1,306 positive
/ 120 negative checks. These component tests use synthetic current authority; they do not
resolve native44 or qualify a complete installed opening. The next external
qualification remains one reviewed, frozen complete installed continuation.
The smaller-reproducer requirements and existing fixture limits are documented
in [ADR-207](decisions/207-context-setup-proof-bracket.md#installed-opening-diagnostics).

## Installed native 44: preview still unavailable (2026-10-18)

The [full continuation run](https://github.com/phihos/asservat/actions/runs/39152191972)
on frozen `fab45036f3cda153d06ea56898d92cae535e7d72` failed. Four independent
preview requests returned unavailable after 3.339–3.445 seconds; private
stage diagnostics again identify target resolution. The regional context
standby repeatedly refused opening with unavailable/denied outcomes, while
separate regional capacity observations succeeded. This does not establish
which context setup, owner or source boundary failed. The selected one-input
native setup pass above did not qualify this installed graph.

[The retained log](../test/results/installed-journey-ci-44/context-storage.log)
records the top-level failure after 1,346.49 seconds and the continuation failure
after 1,023.35 seconds (package 1,346.583 seconds). Passive command and final
administrator-removal subcases passed. Capture, publication, native download,
expiry/deletion and faulted-cleanup continuation were not reached. PR40/41
remain held; no complete installed user workflow is claimed.

[Independent archive verification](../test/results/installed-journey-ci-44/verification.json)
matched all 2,695 hashes to the frozen commit. Sources remained unchanged,
test exit was 1 and owned cleanup completed without failures. The environment
report SHA-256 is `8fe6447c666c2ad55f7ee06d4392a69587896897b79d097c57bd287508e615e5`.
The next step is to reproduce or instrument the failing installed context-open
boundary without changing original deadlines, permissions or retry ceilings.

## Context setup native 2: selected fixture passed (2026-10-18)

The [corrected owned run](../test/results/context-setup-native-2/context-storage-environment.json)
on frozen `0099e2295d3fdd63cb2892170a6152872e2e56b8` passed the selected
`TestConnectorAPIProcessWithRealKubernetes` and all five children: named whole
Secret/foreign denial, original setup bracket, actual start status under both
guards, capacity-token admission and changed-input metadata. Top-level time was
22.11 seconds; race-enabled package time was 23.174 seconds.

Cold setup took 1.804 seconds and current native close 0.699 seconds. Local
source/read reuse issued no API requests. The independent work, opened after CRD
readiness and the previous phase's original end, completed its native read,
CREATE, Ready and StartCommitted in 2.572 seconds within its original five
seconds. Changed-input refusal was checked before the opening proof expired.
There is no wait or renewed observation within an operation. These are actual
Kubernetes API/admission results with one startup input and synthetic connector
source, issuer and registry facts; they do not qualify the complete installed
source graph, owner authentication or investigation journey.

[Independent archive verification](../test/results/context-setup-native-2/verification.json)
matched all 2,695 source hashes, unchanged throughout the test. Test exit was
zero and cleanup reported no failures. Environment report SHA-256 is
`4fb2b6d2890ff4d7ff2448498b18be0f47deb5f1904c1d68432c0e747d07cc6e`.
The failed first run remains below. Installed native43 still failed before
collection; the context changes must be assembled and the full installed
journey qualified before PR40/41 can merge.

## Context setup native 1: setup passed, selected fixture failed (2026-10-18)

The [owned native run](../test/results/context-setup-native-1/context-storage-environment.json)
on frozen `b705387f600982903aec500e1cc9becc35eaf147` passed the new cold setup
case: complete opening proof took 1.805 seconds and current closing native
checks took 0.699 seconds. Local reads/source reuse performed no additional API
requests, retained the original interval and refused reuse after closure. This
fixture uses one approved input and synthetic connector source/issuer/registry
facts; these timings do not represent the installed complete source graph or
both remote-owner authentications.

The selected top-level test failed (12.78 seconds; package 12.842 seconds).
The following independent capacity-start case spent 2.014 seconds waiting for
new CRD admission readiness, then reused the setup case's nearly spent cached
observation. Ready refused a binding read with only 17 milliseconds remaining
in that original interval. The later input-change case could not open its proof,
so it did not qualify input-change denial. The full fixture is not a pass.

[Archive verification](../test/results/context-setup-native-1/verification.json)
matched all 2,695 source hashes; source bytes stayed unchanged and cleanup
reported no failures. The fixture now waits for the preceding independent
phase's recorded original end before opening a new operation, after CRD
readiness where applicable. It does not wait, refresh or retry within a work,
and changes no production deadline, limiter or guard. Input-change refusal must
occur before that new operation's original expiry. The corrected selected run
is recorded above.

## Context-start private setup bracket (ADR-207, component, 2026-10-18)

The concrete executor now lends one full native proof to one private opening,
with an atomically captured generation and exact process-owned credentials. Its
single source frame carries the actual initial closing source. After headers
and Hello delivery, Finish checks current native workload/settings/inputs and a
full current source; both owner authentications and a final local confirmation
remain. Close joins owned work before Open can return. The returned exchange's
later Check still takes the ordinary full current path.

The final affected race selection passed 30 top-level / 69 named cases (mTLS
8.543 seconds; Kubernetes 1.058 seconds), followed by mTLS/Kubernetes/integration
vet and integration compile-only (zero selected native tests). The earlier wider
selection passed 32 top-level / 90 named cases, including unchanged template
validation. Go architecture passed 58 packages / 338 edges. Removing setup
dispatch with the exact final limiter fixture reproduced both intended failures;
the original source bytes were restored before the passing selections.

Independent review found and reproduced two existing credential-confirmation
races: an active process/leaf change during chain verification, and caller expiry
before the cancellation timer fired. Confirmation now rechecks the exact active
process/leaf/root and original source/registration/caller cutoffs under its lock.
The new Finish path's shorter-caller cutoff is narrowed before final freshness
validation; its failing-first regression also passes. Closing retains all owned
work until it joins. Independent producer, transport and fixture reviews cleared
the changes.

The actual loopback HTTP/2 limiter model uses synthetic authority and counts 114
observer / 24 probe requests plus two owner checks. Its measured 4.706-second
opening at 20 QPS/burst 20 does not establish native or installed availability.
The added native fixture checks the complete setup close and an intervening
input metadata change; its selected passing run is recorded above. Installed
journey qualification remains pending; no collection result is claimed. Exact failure,
mutation, race/vet/compile logs and source hashes are retained in the session
cache under `context-start-combined-proof/`.

## Executor registration source bracket (ADR-207, 2026-10-18)

The executor's explicit `ObserveConnectorProcessAt` can now pass its original
opened source into the nested read-only registration conversation. A private
single-conversation reader allows exactly two copied source replies, retains
original cancellation/expiry and refuses configuration/lifecycle operations.
Known issued leaf/process checks and actual current SQL49 registration/recovery
checks remain; the outer native proof still closes the source independently.
Ordinary observations, enrollment and signing do not use this handoff.

The dispatch regression failed before the change. Corrected mTLS/bootstrap
selection passed nine top-level / 19 named races, both package vets and Go
architecture (58 packages / 338 edges). Real loopback TLS1.3/HTTP2 tests exercise
original cutoff, source copies, finite callbacks, foreign/unknown input,
revocation, cancellation, expiry and closed-reader refusal; source/SQL facts
are synthetic. Spec check passed 11,368 assertions; architecture passed 1,306
positive / 120 negative checks. Logs remain in the session cache under
`context-start-combined-proof/registry-at-*`.

Independent review requested preserving the original nonnil installed Local
composition invariant. The added pre-I/O refusal and final registration-focused
race selection passed two top-level / 13 named cases, followed by bootstrap vet.

This earlier step removed only the nested cold-proof source reads. At that
checkpoint the complete opening still could not fit by static call accounting.
The setup-owned native bracket is tracked above; no installed rerun or
collection pass is claimed.

## Context-start duplicate local proof regression (2026-10-18)

The installed native43 failure remains before target selection/collection:
context-start opening is unavailable despite the distinct capacity lane being
active. The whole opening invokes three local process proofs and two owner
authentications within the original discovery/setup deadlines. Each local read
previously observed the owned connector separately before invoking the concrete
executor, whose complete proof already observes that same connector.

The concrete combined reader removes that outer duplicate, requires the exact
credentials instance, preserves the native proof and original intervals, and
copies public CSR/profile buffers. The existing full/current proof, invalidation,
owner authentication and source frame checks remain. No setup lease or new
authority is introduced.

An explicit 20-QPS/burst-20 limiter model with synthetic authority reproduced
the duplicate-read failure inside a two-second caller interval. The unchanged
production path failed; the combined path passes with the same two source reads
already made inside the executor. The initial focused race selection passed
14 top-level / 20 named tests across mTLS and Kubernetes, followed by both
package vets and Go architecture (58 packages / 338 internal edges). Independent
local review found no blocker in the narrow change. The final focused race run
passed 15 top-level / 21 named tests, including concrete-reader credential-owner
rejection before proof access, copied public buffers, original caller cutoff,
cancellation and expired-proof refusal. Both vets and Go architecture passed
again. Spec check passed 11,367 assertions; architecture passed 1,306 positive /
120 negative checks. These are component/design results, not a native API or
whole-opening qualification; no installed rerun has been made for this change.

Next: account for and reproduce the remaining whole-opening call graph under
the original five seconds. No QPS,
freshness interval, admission proof or current effect check is relaxed.

## Installed journey native 43: target and context-start opening refusal (2026-10-18)

[Run 39143620577](https://github.com/phihos/asservat/actions/runs/39143620577)
tested frozen source `4ba2f4818ccee9a2c7297078f816bfc34a9ef1b7`. All four
`preview_capture` calls returned acknowledged, retryable `NotAvailable` replies
in 3.317–3.425 seconds. The new private diagnostic identifies `target`, before
eligibility, capability, retention, storage, processing or draft creation.
Regional diagnostics repeatedly report `context standby refused: open
(unavailable)`. Five capacity binding observations and four samples with at least
one second remaining in fifteen seconds establish only the independent capacity
lane; they do not establish an available context-start standby.

The initial execution-process proof also reached its original five-second
`source-close` bound after 102 observer and 30 probe calls, then subsequently
reported context-start active. Other source reads exhausted short original
observation tails. The complete opening path nests local native proof checks
before and after route/TLS work; these logs motivate a focused whole-open budget
regression but do not identify the exact failed open substage or establish a
semantic identity mutation. No SQL permission error is assigned as the cause.
Collection, publication, transfer, revocation, expiry and deletion were not reached.

The parent test failed after 1,318.12 seconds; the continuation failed after
994.37 seconds. Terminal exit is 1. All 2,688 recorded source hashes independently
match the frozen commit archive, tested sources were unchanged and cleanup
failures are empty. The [environment report](../test/results/installed-journey-ci-43/context-storage-environment.json)
has SHA-256 `b4cf399bdc683996049b76d1afa01c547254a789d10427a1ab563110c80f9121`;
the adjacent [archive verification](../test/results/installed-journey-ci-43/verification.json)
and original run, PostgreSQL and kubelet logs retain the failure. The next task
is the focused context-start opening investigation under unchanged original
five-second bounds and 20-QPS clients. There is no automatic full rerun or S-02
acceptance from this diagnostic result.

## Installed preview private diagnostics (2026-10-18)

Native42's schema-valid `NotAvailable` replies establish that those error
envelopes passed the public audit and final delivery boundary; they do not
identify which preview dependency refused. The installed C09 service now reports
one fixed private failure stage, preserving `errors.Is`, public response bytes,
audit classification and original deadlines. No provider/SQL error text, target
identity, credential or arbitrary nested diagnostic enters the log. The regional
context-start supervisor separately reports candidate/open/exchange failures
through the existing exponentially suppressed logger. Its channel is independent
of the capacity standby already observed by the fixture.

The fixture retains the original request ID, elapsed time and public retryable
flag on a refused preview, plus bounded regional process logs on journey failure.
Those observations change neither attempts nor current checks. Inspection found
no owner permission-read reconnection during the native42 preview interval;
refusal before that read is an inference, not a confirmed cause or a product fix.

The focused capture/presentation/bootstrap race selection passes (31 top-level,
142 named cases); the full capture race suite passes (39 top-level, 130 named
cases), including shared Request/replay callers of the wrapped facts/processing
helpers. Integration compilation selects no external tests and passes. Tests
cover closed labels, preserved causes, public wire parity, post-draft expiry,
foreign diagnostic suppression and missing optional reporters. Affected-package
vet and Go architecture checks pass; specification/architecture gates pass.
Native43 below exercises these diagnostics and identifies the target/open
boundary. Preview, collection and the later S-02 journey remain unqualified;
this diagnostic run establishes no product fix, increased limit or freshness
extension.

## Installed journey native 42: structured preview refusal (2026-10-18)

[Run 39139924613](https://github.com/phihos/asservat/actions/runs/39139924613)
tested frozen source `9130cb626fa7e0d8870cf0883814e8c94e9734b1`, including the
operation-owned audit credential and shared transport-slot corrections. Installed
services, regional enrollment and capacity binding reached their checks: six
distinct binding observations and twelve samples with at least one second left
in fifteen seconds. All four `preview_capture` calls returned schema-valid
`NotAvailable` envelopes. The earlier audit-begin credential diagnostic did not
recur in these logs, but this does not identify the remaining refusal or prove
successful preview availability. Collection, publication, native download,
revocation, expiry and deletion assertions were not reached.

The parent test failed after 1,332.72 seconds; the continuation failed after
1,009.47 seconds. Terminal exit is 1, all 2,684 recorded source hashes independently
match the frozen commit archive, tested sources were unchanged and cleanup
failures are empty. The [environment report](../test/results/installed-journey-ci-42/context-storage-environment.json)
has SHA-256 `3070b2188b0583535b89f4cd4ce6adcd92de930946523627b051e9127267d1a3`;
the adjacent run, PostgreSQL and kubelet logs preserve the failure. The next task
is bounded diagnosis of the structured refusal before another full campaign.
Original deadlines and current checks remain unchanged; S-02 remains incomplete.


## Installed public audit credential deadline correction (2026-10-18)

The installed public operation and capture-intent audit adapters now obtain one
current audit-store credential per finite create or lookup, preserving its
original deadline through seal, conditional PUT, exact-version GET, body close
and verification. The previous SDK credential adapter discarded that deadline
and repeated the complete native proof on each S3 request. No credential cache,
request extension, higher QPS or admission retry was added; SQL audit claims,
acknowledgements, recovery and final identity checks remain independent.

The blocked PUT and GET regressions failed against the old behavior: a 100 ms
credential proof allowed I/O to run until the 700 ms caller deadline. Both pass
with the operation-owned context. Actual loopback TLS/S3 SDK tests cover exact
version verification, expired credentials before sealing, cancellation, unknown
or conflicting writes, and lookup without another PUT. Native identity failures
now distinguish failed resource reads from changed security-relevant Pod state;
errors expose only closed labels.

The unchanged, separate 20-QPS/burst-20 native clients measured 51 API calls per
credential proof. A fresh five-second single-object SDK PUT/GET still passes with
the old behavior (two proofs, 102 calls, 3.203 s); it does not reproduce the whole
installed preview failure. With an original three-second remaining bound the old
sequence fails during its second proof, while one scoped proof completes in
2.101 s. A synthetic C08 Begin/Finish pair under one original five-second caller
bound exhausts the old sequence during its third proof; the scoped pair finishes
in 4.198 s with two proofs, 102 API calls and two PUTs/two GETs. This uses the real
coordinator, SDK and native readers with synthetic SQL acknowledgements, stored
bytes and API authority. It excludes real SQL, key-service, application and
identity latency and does not qualify installed preview availability or identify
the exact cause of native41's coarse final-Pod diagnostic.

Focused bootstrap/Kubernetes race tests and both-package vet pass. A subsequent
follow-up covers all remaining shared consumers: bootstrap issue audit and
download dispatch, enrollment/certificate, batch, window and stop audit. The
unsafe dynamic SDK credential store is removed from the installed layout;
legacy static-material layouts keep their original adapters. Stop/window original
cutoffs and the distinction between lookup and positive completion are preserved.

The follow-up uses one shared semaphore bounded by the installed owner concurrency
(one through sixteen), retaining each slot until actual verification/body/transport
closure even after expiry. This prevents private transport clones multiplying
the old shared connection ceiling. Focused tests cover ten writer paths with
success, blocked PUT/GET/body, late key verification, original write expiry,
lookup without another PUT/closure and historical stop lookup after its write
cutoff. A blocked verification regression confirms that expiry alone does not
release the slot. The full bootstrap race suite and vet pass; per-operation TLS
setup and the complete installed journey still need native qualification. No
S-02 acceptance follows from these component results.

## Installed journey native 41: public preview remains unavailable

[Run 39128220426](https://github.com/phihos/asservat/actions/runs/39128220426)
qualified frozen source `fa1080d73dfc3e71051306e5f82abe501d64ac37` only as far as
regional enrollment and current capacity binding. It observed six distinct
binding revisions and eleven samples with at least one second remaining during
fifteen seconds. The scoped permission observer constructed successfully.
All four installed `preview_capture` attempts then failed with HTTP/2 stream
errors or service unavailable. Owner diagnostics recorded
`audit-begin/object/closed/read/credentials-verify/identity/final-pod`; the exact
cause is under investigation. Collection, publication, native transfer, revocation,
expiry and faulted cleanup assertions were not reached.

The parent test failed after 1,344.97 seconds (continuation: 1,023.51 seconds).
The harness reports terminal exit 1, unchanged sources and no cleanup failures;
all 2,630 recorded hashes independently match the frozen commit archive.
Report: [`test/results/installed-journey-ci-41/context-storage-environment.json`](../test/results/installed-journey-ci-41/context-storage-environment.json),
SHA-256 `7b708a3ef8f7e45438b88fcc98f19a51cbc0c9eea9d62c0418701649f287e4ae`.
This supersedes native40's immediate permission-constructor blocker, not its
unqualified lifecycle outcome. Preserve the original five-second proof/request
intervals while diagnosing the public audit credential path; no automatic full
campaign retry or relaxed gate is justified by this failure.

## Installed investigation continuation (ADR-202–205, 2026-10-18)

The installer now provisions the public listener, publisher and hub-local
download workers under ADR-202–204. The installed two-cluster investigation
remains under qualification: collection, publication, native download,
revocation, expiry and deletion have not yet passed together. The journey test
is being completed on its own branch; no S-02 acceptance follows from the
component results below.

Native journey runs 35 and 36 reached running owner, publisher and capacity
processes, then failed a stale fixture check for the worker configuration
source. [PR #39](https://github.com/phihos/asservat/pull/39) checks the actual
download-worker namespace. Earlier installed failures exposed the download
content auditor rejecting the installed audit lane
([#37](https://github.com/phihos/asservat/pull/37)) and the owner startup proof
rejecting an installer journal change
([#38](https://github.com/phihos/asservat/pull/38)). Those fixes have merged.
Purpose-specific Kubernetes clients also isolate owner readiness, provider
refresh and audit credential reads; their original five-second bounds and
20-QPS client limits remain unchanged.

The subsequent [run 37](../test/results/installed-journey-ci-37/context-storage-environment.json)
and [run 38](../test/results/installed-journey-ci-38/context-storage-environment.json)
both failed before collection: the regional workload never reached `ready_at`.
Both exercised `179c376f752285a035de1ac8e4d939beb32cb6bc`, exited 1 with
unchanged source hashes and no cleanup failures. The retained logs show
permission reconciliation stopping, hub-worker restarts and unsuccessful
regional capacity composition; the root cause remains under investigation.
Neither run reached the MCP capture/download/expiry checks.

[Run 39](https://github.com/phihos/asservat/actions/runs/39122326430), at
`9ef1103f83fd8377d007de89cedbb4aef5855c6d`, stopped at the deletion credential's
positive multipart-abort probe: the owned S3 backend returned `AccessDenied`.
It did not reach regional collection or the user journey. The
[report](../test/results/installed-journey-ci-39/context-storage-environment.json)
records exit 1, unchanged sources, no cleanup failures, and the earlier
107-ordinary/110-total SQL profile. All 2,627 source hashes match that commit.
The subsequent complete inventory counts five additional installer pools;
neither its 112-ordinary plan nor the failed-deletion assertion is qualified by
this run. The abort-permission failure is under investigation; no broader
runtime storage permission has been granted.

[Run 40](https://github.com/phihos/asservat/actions/runs/39124983082), at
`7321bacbfb7da3cf50c8eebd81053c7bca3f2a78`, passed the deletion credential
probes and reached the regional workload's `ready_at`: six distinct binding
observations and fourteen samples with at least one second left in fifteen
seconds. It then failed before collection when the fixture passed its plaintext
administrator pool to `NewPermissions`. That constructor correctly requires
verified TLS and a restricted runtime role. The
[report](../test/results/installed-journey-ci-40/context-storage-environment.json)
records exit 1, the 112-ordinary/116-total fixture profile, all 2,629 hashes
matching the frozen commit and no cleanup failures. This run does not qualify
collection, native download or installed expiry/deletion.

The fixture now uses the installed `permission-read` credential through verified
TLS with one scoped monitoring connection, closed when the journey returns.
This fits the existing operator/monitoring reserve; no connection limit or
runtime grant was raised. Four issuance helper pools now close before regional
installation instead of remaining open until the parent test ends. The focused
[PostgreSQL regression](../test/results/installed-permission-observer-native-1/custody.log)
at `1b989271b572d5055230dea5ee00ea2efde65d97` passes: both administrator paths
are rejected, the projected scoped reader constructs and rejects authority
mutation, and its connection closes. Its
[report](../test/results/installed-permission-observer-native-1/custody-environment.json)
records exit 0, 2,602 matching hashes and no cleanup failures. The projection in
that focused check is synthetic; installed projection protection and the
complete journey still require the next frozen run. The subsequent probe also
requires PostgreSQL's exact insufficient-privilege SQLSTATE, not a generic error.

ADR-205's SQL purposes/due list and provider signing/delete-credential
components merged in [#35](https://github.com/phihos/asservat/pull/35) and
[#36](https://github.com/phihos/asservat/pull/36), after passing CI and current
Gitar review. The exact SQL candidate `22c19dae9588618545b5baf2312cb6a64235dc99`
passed [native run 39119394822](https://github.com/phihos/asservat/actions/runs/39119394822):
`TestContextAdmissionWithRealServices` and its `native-api-runner` subtest,
exit 0, unchanged sources and no cleanup failures. All 2,602 hashes in the
[retained report](../test/results/adr205-context-sql-ci-2/context-storage-environment.json)
match that candidate; the [test log](../test/results/adr205-context-sql-ci-2/context-storage.log)
records the selected execution. That context-harness branch does not run the
SQL deletion regression. The separate custody run 39122322616 on
`25c7195900dd2d323c6a848cdb0e19bc19d0016a` passes the actual
execution/publication/deletion case and its bounded paging regression, with
exit 0, all 2,593 source hashes matching and no cleanup failures. These are
component checks with fixture authority, not installed deletion scheduling.

The deletion-child composition now receives its settings through the installed
provider capacity path. The journey assertions use fresh real-user tokens,
request-owned preparation continuations, and independent checks of
object/version/upload absence, the exact retained audit ciphertext and the
storage refund. The new failed-cleanup branch denies only one attempt's cleaner
inventory, requires an unsuccessful installed lease with unchanged receipts,
deadlines and charges, restores the original policy, and requires a later purge
before the original deletion deadline. Focused race checks pass; the installed
journey, including that failure/recovery branch, remains unqualified.

## Delayed query negatives: reproduced and qualified correction (2026-10-18)

Review found that `SuspendQueryCapacity` derived its SQL deadline from the
negative observation's timestamp, preventing persistence after a five-second
delay. The restrictive write now gets at most five seconds from the current
call, preserving the caller's earlier deadline and cancellation. SQL receives
the unchanged original watermark; no positive freshness, source limit or
authority interval is renewed.

The exact owned `TestContextQueryCapacityWithRealPostgres` selection failed at
the new delayed-negative assertion on frozen
`f8d73a8810b84f97e9a02bfc82c3a6604fae0dd4` (13.47 seconds), then passed on
`e538a40306759cb13dec0e432ed3ea875410c589` (14.54 seconds). Each run matched all
2,644 frozen source hashes and completed cleanup. The final assembled selection
passed at `7fcc30fd0bd4d1896cbe843d555f37b2b211767c` (14.55 seconds; race package
15.603 seconds), with all 2,652 hashes matching its Git archive, unchanged source,
exit zero and no cleanup failures. The native test checks the original expired
negative watermark, older replay without new spend/freshness and a blocked
restrictive write under the caller's original 50 ms deadline. Existing source
claim, unknown reply, concurrency, joined completion and exhaustion assertions
remain selected.

The [failing report](../test/results/context-query-stale-negative-failing-1/fleet-environment.json),
[first passing report](../test/results/context-query-stale-negative-passing-1/fleet-environment.json)
and [final assembled report](../test/results/context-query-stale-negative-assembled-1/fleet-environment.json)
retain exact source manifests; their sibling logs and verification records
retain outcomes and independent archive comparisons. The final report SHA-256 is
`c535b51c280c3fdc747074d3d62caf66b2b247fca036223c8246ff1a2cebaaff`.

CI on the preceding `4157b8c` candidate failed its evidence-package shard because
one synthetic worker fixture omitted the newly mandatory ephemeral-storage
dimension. The final freeze adds that fixture's original 4 MiB value; it changes
no production limit. The complete evidence-package race suite then passed in
3.857 seconds ([log](../test/results/context-query-stale-negative-assembled-1/evidence-race.log)).
Touched PostgreSQL/integration vet and Go/specification/architecture gates also
passed for the correction. The full ledger qualification below remains evidence
for `51fd2e9`; it was not repeated for this restrictive adapter-only correction.

Query resource/history measurements and independent native deployment guards
remain synthetic. These component results do not qualify installed query
authority, protected issuer/runtime composition, public disclosure or a later
source tree. No public tool or Helm runtime capability is enabled.

## Query source attempts: native pre-I/O accounting qualification (2026-10-18)

Separate fresh PostgreSQL/S3 fixtures tested frozen
`51fd2e94d41d6ce5e9105b755e7e39671df5944e` after the source-accounting review fix.
`TestContextQueryCapacityWithRealPostgres` passed in 9.25 seconds, including
committed-but-unknown Begin, replay, concurrent outer guard work, expiry with an
unfinished claim, exhaustion and the reserved terminal negative transition.
`TestContextQueryLedgerWithRealPostgres` passed in 29.77 seconds, including its
20.54-second full ledger child. Both run the updated three-transaction source
protocol; the older reports below qualify only their earlier source.

Each report independently matches all 2,652 source hashes to the frozen commit
archive, records unchanged source and exit zero, and has no cleanup failures.
The [capacity report](../test/results/context-query-source-spend-capacity-1/fleet-environment.json)
has SHA-256 `2a545c3199e09790ea11f32c21cb62b09bc456e26d219f38d27b149c3ff6a017`;
the [ledger report](../test/results/context-query-source-spend-ledger-1/fleet-environment.json)
has SHA-256 `64cadc8209909a990398b861d017dee1254e9d98227e676b1e47441ad64921e5`.
Assembled gates passed: 54 generated SQL files, 58 Go packages/338 allowed edges,
11,375 specification assertions and 1,316 architecture positive/120 invalid cases.
Independent review cleared the exact source correction and final assembly.

Resource/history measurements and independent deployment guards remain synthetic;
the ledger also uses synthetic human authority and C-14 closure. This establishes
component SQL behavior, not installed query authority, protected issuer/runtime
composition or public disclosure. Missing completion and negative-raced claims
remain conservatively held; this component supplies no recovery bypass.


## Combined protected query capacity and ledger qualification (ADR-206)

Two separate owned PostgreSQL/S3 fixtures passed at frozen
`446eeb5e9ccb083b1919dee4f0cdd835df7e31e5`. The exact
`TestContextQueryCapacityWithRealPostgres` selection passed in 9.15 seconds;
`TestContextQueryLedgerWithRealPostgres` passed in 29.14 seconds, including the
19.86-second ledger child and the actual managed-context retention checks.
These runs compose original installation/root/workload acceptance, finite
query reservations, current C-03 environment and query accounting with encrypted
C-08 audit. The ledger includes one-use starts, uncertain closure, original
expiry after blocking locks, scoped-role denials and retained aggregate spend.
The final-bound regression fix is included in this frozen tree.

Each report independently matches all 2,651 recorded source hashes to the frozen
archive, records unchanged sources and exit zero, and has no cleanup failures.
The [capacity report](../test/results/context-query-capacity-assembled-1/fleet-environment.json)
has SHA-256 `66b1793afd9f6d37d89889274a1d2c898b75e6021ec86f4cc046352c6fb79608`;
the [ledger report](../test/results/context-query-ledger-assembled-1/fleet-environment.json)
has SHA-256 `b0d1002c6c2518d62b8adc09ee5c2918806e1cb5800d5bc125f4cd7bb4e11935`.
Combined capacity, authorization, analysis/domain and PostgreSQL package race
tests passed, along with scoped vet, SQL generation, Go architecture, specification
and architecture gates.

The earlier fixture lifetime failure remains recorded below; this run selects
the evidence lifetime and its covering base backing before original preparation.
It does not change query limits or renew any persisted deadline.

Measured resource/history qualification, native deployment guards, human
identity and C-14 worker/closure inputs remain synthetic in these component
fixtures. Query issuer/key/runtime composition and installed disclosure remain
pending; no public query or Helm capability is enabled.

## Protected approved-query backing component (ADR-206)

C-07 now has an optional original-installation query qualification, independent
resource/history compiler, private four-guard producer and separate SQL69 read/
write facets. The immutable reservation consumes only residual base-root and
system-pool capacity; all original root dates, finite principal/workload/query
allowances and uncertain charges remain fixed. Per-deployment numeric limits,
worker lifecycle/signing/observation history, child audits and finite source
refresh work require exact measured qualification. C-03 composes that current
query policy with current recovery and durable processing independently of
ordinary approved-read authorization. No query role, installer setting or
public tool is enabled. See [the contract](architecture/context-query-capacity.md).

Independent review found native source guards ran before their finite allowance
was charged. The follow-up reserves each attempt before guard I/O and holds its
exact claim until separate joined completion. Unknown/replay/exhaustion cannot
enter guards; expiry cannot release unfinished work. Declared WAL accounting now
covers all three source transactions without increasing the original limit.
The original guard-entry regression failed before the change. Full capacity and
PostgreSQL race tests, focused source-history/join regressions, integration
compilation, vet, SQL generation and design gates passed. The later frozen native runs above qualify the new protocol; older native
reports predate it and do not qualify it. [Component evidence](../test/results/context-query-source-spend-component.json)
records the exact commands and scope.

Full capacity/authorization/PostgreSQL race tests passed before the final history
and consumer-deadline tightening; the final capacity/authorization race, five-
package vet, integration compilation, SQL generation and Go architecture checks
also passed. Two regressions failed before their fixes: reader buffer reuse
changed the original accepted policy, and blocking guards/final source reads
outlived the first backing deadline. Their corrected race runs passed. Recorded
commands, exits and counts are in
[test/results/context-query-capacity-component.json](../test/results/context-query-capacity-component.json).
The duplicate-deployment regression also failed with its protection removed and
passed restored: four role names cannot pledge the same physical deployment
limits four times.

The selected owned fleet test
`TestContextQueryCapacityWithRealPostgres` passed on frozen commit
`896e491a3e7ceb610a3ce3a4fb228c9f34628933` (9.37 seconds). The
[first run](../test/results/context-query-capacity-first-run.log) reached original
acceptance but failed because a PL/pgSQL variable and digest byte-index alias
were ambiguous. The corrected explicit aliases passed the same bounded
[selection](../test/results/context-query-capacity-native-run.log). Both runs
preserved all 2,642 source hashes against their exact committed blobs and had
empty cleanup failures; see the
[first environment](../test/results/context-query-capacity-first-environment.json)
and [passing environment](../test/results/context-query-capacity-native-environment.json).
The fixture used the unchanged 48-connection component profile.

This composes actual original setup, role/audit/root/workload activation and
SQL69 reservation with explicitly synthetic query measurements and deployment
guards. Separate scoped runtime credentials prove missing anchor/allocation
denial, exact accepted positives and suspended-backing denial. Replay preserves
the original plan; finite observations exhaust without replenishment and the
terminal negative retains charges. SQL68 consumes the mandatory anchor lock and
checks current workload allocation at both final transaction fences. The full
ledger regression now uses `TestContextQueryLedgerWithRealPostgres`, a separate
pristine-installation selection with actual root/workload/query acceptance and
managed context publication. C-03 consumes the accepted query policy through
`CurrentProjectionEnvironment`; the normal audit pool and finite source budget
are reserved in the original setup. It retains every earlier ledger assertion,
including lock synchronization, unknown replies, original lease expiry and
cross-client aggregate charges. Its integration compilation, original
qualification race test and integration vet pass. The
[first native ledger run](../test/results/context-query-ledger-first-run.log)
on `1ca69f2592d40cb20b468e6097fa3569db0c34d2` reached the late poll assertions
but failed: the inherited 20-second evidence lifetime did not cover preparation
plus the 18.54-second ledger subtest. Its
[report](../test/results/context-query-ledger-first-environment.json) records
all 2,662 source hashes independently matched and empty cleanup failures.
The dedicated fixture now selects 60-second evidence retention and a covering
120-second base backing interval before original installation/submission;
existing callers retain 20 seconds. Query admission/maximum lifetime remain
60 seconds, current request authority remains at most five seconds, and no
persisted dates change. The corrected native selection is pending. The native69
fence-function probes do not qualify these ledger effects. No hook bypass or
skipped positive qualification is supplied.

Assembly review then found shorter final source/plan bounds were only checked
when read: outer guards could finish after those cutoffs and still report
success. Five regression cases failed before the correction, including an outer
source read retaining a longer deadline than a newly returned plan. The fix
rejects those shortened observations before effects/further reads or final
success. Full capacity race tests and vet pass; positive tests preserve a plan
when the caller already imposes an earlier bound. These followup checks are
unit evidence; the native report above remains tied to its original frozen
commit and does not qualify the later assembled candidate.

Production report acceptance, native guards, role provisioning, complete query
worker/key delivery, installed qualification and retirement remain unfinished.

## Approved pod-status console component (ADR-206)

The optional `web/src/projection` view now uses the canonical browser/MCP
contracts for fixed fourteen-line saved pod status. It performs no work before
an explicit inspection, and pending-result checks require a separate click.
Unknown replies never trigger a retry or invent a query handle. Request-start
monotonic timing conservatively preserves the earliest original cutoff through
network delay and subsequent checks; scope loss, closure and expiry clear the
managed result. The HTTP client enforces same-origin CSRF, a five-second request
bound and the 64 KiB complete-response limit; React renders evidence as text.

`make console-check console-browser-check` passed initially; after local review,
`npm run check` and `make console-browser-check` passed all 157 tests across eleven
files, canonical generation/native-ESM validation, production build, nineteen
existing browser journeys with fifteen accessibility scans, and four native
download restart boundaries with two accessibility scans. The scoped cleanup
regression failed before fixing an old effect cleanup that could erase a newly
attached scope. Local review also caught a replacement render showing the old
excerpt before passive effects. A failing-first layout observation reproduces
that commit; rendering and actions now require an exact active attachment to
the current session, scope, case and artifact. Build output retains the existing
large-bundle warning.
The [component report](../test/results/adr206-console-component/report.json)
records the exercised source hashes; the [gate log](../test/results/adr206-console-component/console.log)
retains the actual test output.

The new view is deliberately unregistered pending protected query runtime
composition and installed qualification. Its component fixtures are synthetic;
the actual Go HTTPS/built-console browser gate covers the existing registered
flows, not installed query disclosure. This does not complete S-02.


## Query ledger and catalog native qualification (ADR-206)

[Native run 39136964591](https://github.com/phihos/asservat/actions/runs/39136964591)
passed on `89eb9b7cc62a51a814389d757d6294ff2b353b77`: all six selected children
actually ran, covering the purpose-specific query ledger, ordinary private case
routing and missing/NULL capture and verification audit receipts. The parent
finished in 12.44 seconds; the query ledger child passed in 6.88 seconds.
PostgreSQL/S3 accounting, current healthy invocation lineage, scoped-role denials,
one-use starts, uncertain active generation and retained aggregate charges are
qualified for this component. C-07 resource qualification, C-14 worker/closure
proofs and human identity remain explicit synthetic inputs.

All 2,637 recorded source hashes independently match the frozen commit archive;
terminal exit is zero, sources stayed unchanged and cleanup failures are empty.
Report: [`test/results/context-query-ci-2/custody-environment.json`](../test/results/context-query-ci-2/custody-environment.json),
SHA-256 `9ea012bbf23fd60b34451adb83212d183f3a980c77399f5bf14963bddf90e8bd`.
This resolves the earlier migration syntax/fixture blockers and qualifies the
combined catalog changes. It does not qualify installed queries, worker dispatch,
key-service authority, positive remote closure or public runtime availability.
The protected query-capacity and worker continuation remain in progress.

## Query composition qualification in progress (ADR-206)

The coordinator, SQL ledger, verified regional reader and audited browser/MCP
reply boundary are assembled in PR #44. At frozen
`d37e2fa2fe7f1ae52bd64f618403992b667087e1`, combined race tests passed for eleven
domain/application/provider/transport packages; affected vet including integration,
Go architecture (58 packages, 337 edges), pinned SQL generation (53 files),
specification (11,346 assertions) and architecture gates passed.

The first owned native SQL/S3 run
[39129322393](https://github.com/phihos/asservat/actions/runs/39129322393) failed
while applying migration 00068 with PostgreSQL syntax error `42601`, before any
Go test ran. All 2,637 recorded source hashes independently match that frozen
commit's archive; the harness reports unchanged sources, terminal exit 1 and no
cleanup failures. The retained report is
[`test/results/context-query-ci-1/custody-environment.json`](../test/results/context-query-ci-1/custody-environment.json),
SHA-256 `f62f17dbbcd4c9dc2ff6953732f2a5934c7906a6660980fab737fd6c0ea9ffcc`.
This is a migration failure, not native query qualification. The subsequent
correction and passing combined run are recorded above.
Protected capacity, query worker/key producers and installed composition remain
in progress; neither public query operation is enabled.

## Approved context query SQL component (ADR-206)

Migration 00068 and `postgres.ContextQueries` add independent bounded query,
invocation, batch and key-slot accounting against accepted query-purpose backing.
SQL compares immutable profile/qualification/source/account/horizon facts under
recovery and permission locks; every effect requires the same current healthy
C-08 intent, and batch closure requires its acknowledged outcome plus the opaque
C-14 closure callback. Replays, unknown replies, expired leases and failed guard
returns retain spend. No installed query role, backing producer, worker/key
producer, retirement/refund facet or public query tool is enabled by this change.

Pinned SQL generation, focused PostgreSQL query/initial-schema race tests,
integration-package compilation, touched-package vet and Go architecture checks
passed. Two failing regressions reproduced loss of an earlier guard deadline and
success after that deadline expired; the guarded callback now preserves both.
The [selected native SQL/S3 ledger test](../test/results/adr206-context-query-local-2/custody.log)
passes in 7.33 seconds, including acknowledged audit lineage, actual SQL lock
synchronization, one-use starts, unknown closure and retained aggregate charges.
Its [report](../test/results/adr206-context-query-local-2/custody-environment.json)
records exit 0, all 2,615 source hashes independently matching its frozen
component revision `b959360e6c4055541750e1761b609c22b500d719`, and empty cleanup
failures. That branch differs from the combined implementation in 21 recorded
files; this local report qualifies that component revision only. The later
combined run `context-query-ci-2`, recorded above, separately verifies all 2,637
files against `89eb9b7cc62a51a814389d757d6294ff2b353b77` and passes the ledger
plus five catalog/case checks. The first combined native attempt stopped before tests at a PL/pgSQL
CASE parsing error; the next local attempt exposed the fixture's attempt to
replace its existing normal audit account. The correction parenthesizes CASE
and preserves the acknowledged processing audit policy/account and retained
spend while increasing explicitly synthetic capacity through the existing CAS
API. Its C-07 qualification and C-14 ownership inputs remain synthetic. The
constructor floors query timestamps conservatively to PostgreSQL microseconds;
the passing native fixture deliberately supplies a nanosecond clock. Installed
query composition and native public transport qualification remain separate.

## Initial approved pod-status projection foundations (ADR-206)

[ADR-206](decisions/206-bounded-context-projection.md) fixes the narrow approved
`get_file_excerpt`/`get_query_result` path over an existing committed pod-status
artifact. Typed scope and current-authority values, the strict native decoder,
deterministic fourteen-line `pod-status.txt` formatter and C-03 authorization
now exist. Ordinary `evidence:read` eligibility and complete denies precede the
protected catalog lookup; source version, original audience, retained policies,
recovery, processing and the query-purpose path remain binding. Every current
request retains its original five-second and earlier dependency deadlines.

Focused domain/application/authorization race tests, decoder regressions, vet
and specification/architecture gates pass. These are component results, not an
installed query read. Subsequent query accounting, regional reading and audited transport components
are recorded in the architecture contract. Protected resource-profile and
worker/key acceptance, runtime composition and installed qualification remain pending. No public tool is enabled
by these foundations; the canonical wire schemas and native artifact remain
unchanged.

## Regional capacity on demand (ADR-197, ADR-200)

The installed two-cluster continuation now enrolls a regional workload through
the v2 exchange and keeps its binding fresh on demand. Admission needs a binding
refreshed within five seconds, and a regional discovery pass takes minutes, so
[ADR-200](decisions/200-on-demand-capacity-refresh.md) adds a refresh demand
(migration 00066, schema 66) that the hub-worker's demand lane serves back to
back; capture preview and request wait for it within their original deadline.
The PostgreSQL stage passes on CI
([fleet run](../test/results/adr200-fleet-ci-4/native-fleet-1/fleet-environment.json)).
Native CI continuation runs [24a](../test/results/adr200-continuation-ci-24a/native-continuation-1/context-storage-environment.json),
[25a](../test/results/adr200-continuation-ci-25a/native-continuation-1/context-storage-environment.json) and
[25c](../test/results/adr200-continuation-ci-25c/native-continuation-1/context-storage-environment.json)
pass: after one demand the regional binding had five or six refreshes and seven
to nine samples with at least a second of freshness in 15 s. Three of the last
six runs pass. The failures are the hub-worker's permission reconciler stopping
(24b `refresh/confirm-expired`, 24c `refresh/accept` and `start`), which leaves
the permission stream stale so no capacity source is accepted, and a slow owner
start in 25b ("owner native port not reachable"). The reconciler's phases are
now labelled for the next failure. Hub-cluster capacity observation was
throttled past its window on a shared client (PR #8 gives it its own). Downloads
still rely on discovery refreshes; the installed S-02 journey is not complete.

Runs 26a–28b (eight, [26a](../test/results/adr200-continuation-ci-26a/native-continuation-1/context-storage-environment.json)
to [28b](../test/results/adr200-continuation-ci-28b/native-continuation-1/context-storage-environment.json)):
26a, 26c, 27c, 28a and 28b pass. 26b and 27a stop at "owner native port not
reachable"; 27b's regional workload never reached `ready_at` while the
connector's local source failed at `source-snapshot`. The owner diagnostics
printed only the first 4 KiB of each log, so the router events added for the
unreachable port never appeared; they now print the last 100 lines.

## Rotating cluster credential (ADR-168) and bounded streaming custody (ADR-166)

ADR-168 components are implemented: domain decision, Ed25519
exporter-bound signing, migration 00060, the SQL lineage/credential store,
transport over real TLS, the connector rotator and the single-Secret
compare-and-swap store. The SQL store passes on real PostgreSQL inside
`connector-identity-fast`
([1](../test/results/adr168-cluster-credential-sql-1/result.json),
[2](../test/results/adr168-cluster-credential-sql-2/result.json)). Implementation
removed a 10-minute replay cap from the draft design. That cap would have fenced
a connector that crashed after an unacknowledged rotation, and it added no
protection. Audit records, hub composition, the installer step and installed
qualification remain.

ADR-166 storage components are implemented (migration 00061) and pass the whole
`TestCustodyWithRealServices` on real PostgreSQL and SeaweedFS
([run 6](../test/results/adr166-streaming-custody-6/result.json)). The
migration renumbering, the five failed attempts and remaining composition are in
the ADR. Full gates passed after the 00060 schema bump
([log](../test/results/adr168-go-check-1/go-check.log)). They also pass at
schema 61 ([log](../test/results/adr166-go-check-1/go-check.log): 55 packages and
543 Kubernetes tests). An earlier 61 attempt
([retained](../test/results/adr166-go-check-1/go-check-failed-timeout.log))
exceeded Kubernetes group 6's 15-minute package timeout at host load ~11; the
alarm fired 0 s into an unrelated subtest, not a hang. The
[full custody suite](../test/results/custody-full-schema61-1/result.json) passed
437 named tests but failed `TestEnrollmentFleetFreshnessWithRealPostgres`. That
fixture migrated to exactly 59 and then built adapters that now pin the head
schema. After it migrates to head following its migration-59 checks, it
[passes](../test/results/fleet-freshness-schema61-1/result.json).
[Native38](../test/results/public-context-journey-native-38/result.json) passes
the full regional journey at schema 61, the third consecutive pass.

[ADR-169](decisions/169-delegated-regional-lifecycle-channel.md) adds the
delegated regional lifecycle channel. `TestDelegatedLifecycleChannelOverRealHTTP2`
passes over real TLS 1.3/h2. The regional port adapter (`bootstrap.RegionalLifecycle`)
and hub runner adapter (`connectorlifecycle.Runners`) exist;
`TestRegionalLifecyclePresentsCurrentGenerationOverRealHTTP2` passes with real
Ed25519/CSR verification. The channel also delegates source staging and
leaf-registration lookups. In the two-cluster direct observation fixture, the
regional Pod now enrolls through the owner Pod with no hub connector SQL
credential. [Run 4](../test/results/adr169-direct-native-4/result.json) passed
(exit 0, six required tests, empty cleanup, unchanged sources). Runs 1–3 are
retained failures: a start-order race and a 30-second context passed where the
regional reader requires the operation's own deadline; both are fixed. The
production processes do not compose this yet.

[ADR-170](decisions/170-federation-compartment.md) places those hub duties in
a separate federation compartment, because the hub replica already uses exactly
its 32 allowed connections. Eight connector duty roles (ordinals 48–55) join the
fixed public runtime layout. The initial-installation suite provisioned and
verified all 41 roles on real PostgreSQL
([result](../test/results/adr170-roles-1/result.json): exit 0, 87 tests, empty
cleanup). This qualifies grants, not yet the adapters running under them. The
connection plan adds the compartment, so one hub needs 63 ordinary connections
and four retained hubs need 159.

The product processes now exist: `asservat hub-federation` and the regional
`asservat connector`. Run 10 of
[the product test](../test/results/adr170-product-native-10/result.json) passed
as Restricted Pods in two owned clusters: product role grants, real OpenBao
PKI/transit and S3 audit, and no Secret mount in the regional Pod. The regional
Pod enrolled with both leaves activated in 21 s. Runs 1–9 are retained
test-side and diagnostic failures, listed in ADR-170. Installer provisioning
remains.

[ADR-171](decisions/171-hub-run-context-execution.md) moves the API context
runner and all its SQL and authority ports to the hub. The region answers only
cluster-local operations for a verified signed work, and captures, encrypts and
uploads in place, so plaintext evidence and data keys never leave it.
[The native public journey](../test/results/adr171-journey-2/result.json) passes
on this path with an unchanged first-request time (4.285 s).
[Run 1](../test/results/adr171-journey-1/result.json) is a retained failure: a
binding check compared two different budget digests.

The legacy identity-question protocol is removed (frame kinds 3/4 retired and
always rejected; transport properties now run on operation frames). The
[full Go gate after that removal](../test/results/legacy-removal-go-check-1/result.json)
passes: exit 0, 55 packages and 543 Kubernetes tests in seven groups, no
failures, unchanged source hashes; the one explicit skip is the pre-existing
group-4 skip. It is the complete rerun owed below.

The [full Go gate after ADR-172–174](../test/results/adr174-go-check-1/result.json)
passes: exit 0, 55 packages, 543 Kubernetes tests, no failures, unchanged
source hashes (only the pre-existing group-4 skip).

Researching the four open design questions led to ADR-175 to ADR-178.
ADR-176 corrects a defect in ADR-174: no unwrap path could read
OpenBao-wrapped artifact keys. ADR-177 records that the full S-02 hub needs
about 55 purposes against 32 connections, and that hub-api already opens two
unbudgeted owner pools. Implementation follows.

ADR-175 to ADR-178 are being implemented in this order:

- **ADR-177's governor** (`postgres.SQLConnectionGovernor`) caps each
  process's physical connections. hub-api's owner pools use it, and the budget
  plan counts the governor cap (32) with the owner `routing` and `native-read`
  pools included.
- **ADR-175 passes natively**
  ([run 4](../test/results/adr175-native-4/result.json)). The capacity token
  is an unbound 600-second token, because the API server refuses Pod binding
  for another account. A per-condition native diagnostic located the
  empty-reference admission detail.
- **The full Go gate passes over these changes**
  ([result](../test/results/adr178-go-check-1/result.json): exit 0, 55
  packages, 543 Kubernetes tests, unchanged sources).
- **ADR-178's source frames pass the native public journey**
  ([run 2](../test/results/adr178-journey-2/result.json), first request
  3.48 s). Run 1 failed intermittently in the unchanged download phase.
- **ADR-176's wrap authority and ADR-177's 22 hub extension roles pass on
  real PostgreSQL** ([wrap](../test/results/adr176-sql-1/result.json),
  [64 roles](../test/results/adr177-roles-1/result.json)). The
  [full custody suite at schema 62](../test/results/custody-full-schema62-1/result.json)
  passes: exit 0, 453 named tests in 13 top-level tests, empty cleanup,
  unchanged sources. That includes `TestEnrollmentFleetFreshnessWithRealPostgres`,
  which failed the schema-61 run.
- **ADR-179 keeps the first installed profile outbound-only.** The hub reads
  only its own cluster. Implemented so far:
  - `WorkerAPIs` and the legacy capacity observer are fenced to the hub
    cluster.
  - The context capability is hub-held.
  - Preview and request target resolution are pre-work queries on idle
    context-start standbys (frames 11/12, `Router.Query`,
    `contextstart.Targets`).

  The cluster observation channel was rejected for targets: the product does
  not compose its regional client and serves a different owner pool. A
  real-TLS test passes four queries, a closed failure, the budget cap and the
  following signed work on the same standby. The
  [full Go gate](../test/results/adr179-go-check-2/result.json) passes over
  ADR-176, 177 and 179: exit 0, 55 packages, 543 Kubernetes tests, unchanged
  sources, only the pre-existing group-4 skip. The
  [first attempt](../test/results/adr179-go-check-1-failed-vet/result.json)
  failed at `go vet`: an integration test still passed a ResolvePod-only
  resolver as the regional query targets.
- **ADR-180 hub-api public composition (P1–P5) is product code.** It is
  enabled only by the optional installer-owned `OwnerDeployment.Public`
  section and comprises:
  - governed, verified per-purpose pools;
  - Keycloak-profile identity and browser sessions;
  - investigation and regional start, with hub-held capability and work
    trust per cluster and context-start target queries;
  - downloads with the native runtime and stop;
  - audited operations, refresh owners and the HTTPS listener.

  Only unit tests cover it so far. It still needs the hub-worker duties
  (worker configuration acceptance, browser settings and cleanup) and
  installer producers for every input.
- **ADR-181 moves publication into an asynchronous `asservat publisher`.** It
  holds read-only evidence access and an attempt-scoped, bounded verification
  unwrap authority (migration 63, schema head 63). Both pass on real
  PostgreSQL:
  - the [authority and queue](../test/results/adr181-sql-2/result.json);
  - the [66-role layout](../test/results/adr181-roles-1/result.json): exit 0,
    87 tests.
- **The [full Go gate](../test/results/adr181-go-check-2/result.json) passes
  over ADR-180 and ADR-181:** exit 0, 55 packages, 544 Kubernetes tests,
  unchanged sources. The
  [first attempt](../test/results/adr181-go-check-1/result.json) failed in
  group 7, because the projection's outside-hub predicate did not yet include
  the publisher compartment.
- **ADR-182 is implemented in code, with unit tests.** The installed,
  provider-authenticated hub-api is promoted to backend and public layers:
  - The verified identity deployment input acts as the receipt.
  - Backend and public inputs come from their own projection roots.
  - A separate public provider recipe covers browser seal and open, work
    signing and worker PKI.
  - `composeOwnerIdentity` is shared with the observation deployment.

  An installer inventory found that no post-activation runtime producer has a
  product caller yet, which makes the installer the critical path. The
  [full Go gate](../test/results/adr182-go-check-1/result.json) passes over
  ADR-182: exit 0, 55 packages, 544 Kubernetes tests, unchanged sources.
- **ADR-183 is implemented in code, with unit and render checks.**
  `asservat installer-continue` runs phases 1–4 inside the original
  30-minute journal:
  - resources and the guard bridge;
  - the worker artifact, then roles, inputs and launch;
  - owner selection and its artifact, then projection and launch.

  It publishes the product's existing setup artifacts to an outbox in the
  release namespace. It consumes the operator's inbox, inspects the provider
  and fills the original empty audit Secrets.

  `asservat installer-provider-apply` applies only policies, auth roles and
  PKI roles, create-only. It mints a ten-minute inspection token and writes
  the inbox. The chart adds a weighted continuation hook Pod.

  The continuation ClusterRole holds exactly the runtime Roles' rules (no
  escalate or bind). The
  [full Go gate](../test/results/adr183-go-check-1/result.json) passes over
  ADR-183: exit 0, 55 packages, 547 Kubernetes tests, unchanged sources.
  Native qualification uses the bootstrap-chain harness
  (`--installer-continuation`): the actual continuation Pod under the
  runner account with the chart's rules, and the actual applier.
  - Runs [1](../test/results/adr183-continuation-native-1/result.json)–[4](../test/results/adr183-continuation-native-4/result.json)
    found and fixed:
    - a missing step name in the stop message;
    - an immutability assumption about the installer input;
    - two post-bridge handover reads.
  - [Run 5](../test/results/adr183-continuation-native-5/result.json)
    completed phase 1 in product code: outbox, applier, inbox, provider
    inspection and audit Secret. It then stopped at the configuration roles.
  - Runs 6–9 traced the stop to a role operation overrunning its original
    five-second window at 20 QPS after the role existed.
  - **[Run 10](../test/results/adr183-continuation-native-10/result.json)
    passed.** The fix replays role provisioning by lookup. From a completed
    product bootstrap, the actual continuation Pod and the actual applier
    did this:
    - two provider waits;
    - the configuration roles, worker inputs and launch;
    - owner selection, projection and launch.

    Worker and owner run on the compiled image, inside the original
    30-minute window (subtest 236.6 s), with unchanged sources and clean
    teardown.
  - The [full Go gate](../test/results/adr183-go-check-5/result.json)
    passes after the native fixes: exit 0, 55 packages, 547 Kubernetes
    tests.
    - Gates 2 and 4 failed on two timer-race tests: the code under test
      returns at its original deadline a moment before the caller context
      records expiry.
    - Their checks now test early return directly.
  - ADR-183 now records that no `ReadHandover` replay succeeds after the
    guard bridge.

  [ADR-184](decisions/184-promoted-owner-first-launch.md) decides that the
  first owner launch is already promoted.
- **ADR-184 steps 1–4 and 6 are in code, with unit tests.**
  - `routing` and `native-read` are owner identity purposes 4 and 5, with
    qualified read-only grant sets.
  - The worker-control catalog writer exists.
  - Public roles may precede the inert owner's launch.
  - The public root is a projected volume.
  - Native and Public sections are admitted only for the provider-installed
    layout.

  [ADR-185](decisions/185-public-sources-and-cluster-catalog.md) moves
  regional clusters into a guarded catalog read at hub-api start.
  [The producer map](architecture/installed-public-inputs.md) records every
  remaining promoted input. Today most exist only as test setup.
- **Native continuation run 18 passes with ADR-184/185/186**
  ([result](../test/results/adr183-continuation-native-18/result.json)).
  - The public sources were created.
  - All 66 public runtime roles were provisioned and the public projection
    published before the owner's one launch.
  - The owner provisioned six identity roles; worker and owner both run.
  - [ADR-186](decisions/186-operation-scoped-public-role-proof.md) scopes one
    proof to each public role operation. The unit fixture measured six full
    proofs, about 141 API requests, per role, which cannot fit the
    five-second claim window at 20 QPS.

  Runs 11–17 found and fixed these:
  - a plain journal read after the guard bridge; a retained reader is now
    exported;
  - the public role proof budget;
  - the verify-publish window;
  - a hard-coded identity file list in the `kms` adapter; all such lists
    now derive from `OwnerIdentityProjectionFiles`.
- **Native continuation run 23 passes with ADR-187 and ADR-188**
  ([result](../test/results/adr183-continuation-native-23/result.json)).
  - [ADR-187](decisions/187-replay-after-guard-bridge.md): after completion,
    the bootstrap hook replays passively and a second continuation exits as
    already complete. The guard generation and the resource journal stay
    unchanged.
  - [ADR-188](decisions/188-configuration-role-post-lock-proof.md): a
    configuration role's receipt write reuses the post-lock recheck (118 →
    83 API requests). After the bridge, the continuation also waits until
    the worker and owner Deployments settle.
  - Runs 19–22 are retained failures. The first configuration role's
    post-lock recheck saw a new worker Deployment resource version. The
    bridge releases the Deployment controller, whose backed-off status
    write lands inside that first role operation. The spent claim then
    stays lookup-only. Runs 21–22 found this through fixed check codes that
    the stop message now carries: the first `converge` attempt, the SQL
    role sub-step and the source recheck check.
- **Native continuation run 26 passes with the installed permission stream**
  ([result](../test/results/adr183-continuation-native-26/result.json)).
  - [ADR-189](decisions/189-installed-permission-stream.md): after the owner
    selection, the continuation applies the permission guard and publishes
    the permission projection. The hub-worker's new fourth child opens it,
    verifies the `permission-accept` and `permission-audit` logins, and runs
    the binding reconciler against the actual guard. It publishes the
    authority audits under `authority/v1/<root>/` through the provider-held
    audit credential. The stream was fresh with both audits acknowledged.
  - The public role count is now 68. The worker recipe's audit scope adds
    the fixed `authority/v1/` prefix.
  - [ADR-191](decisions/191-retained-bracket-projection-writes.md): runs
    24–25 showed that one journal read with two complete bridge proofs took
    about 3 s inside the verified role operation's five seconds. Worker
    projection writes now use one retained handover bracket with CAS writes
    and a closing policy read.
  - Open: authority outbox retention (ADR-189 decision 8).
- **Native continuation run 33 initializes capacity**
  ([result](../test/results/adr183-continuation-native-33/result.json)).
  [ADR-190](decisions/190-capacity-readiness-and-promoted-owner.md) steps
  1–4:
  - shipped `EvidenceStoragePool` and `EvidenceBudgetPolicy` CRDs
    (`scripts/capacity-crds.py`);
  - capacity, selector and processing guards, proved live, with a dedicated
    probe namespace;
  - a qualification built from the operator's capacity profile, plus
    installer-minted identities and derived values;
  - `InitializeCapacity` inside one role operation, after the permission
    stream is fresh.

  Runs 27–29 failed on the shared `kind` Docker network, which had lost
  egress. The harness now owns a labeled kind network per run. Runs 30–32
  found a CRD enum without a type, a missing required policy field and the
  setup's five-second budget; stage labels located each. Step 5, runtime
  audit profile selection in the hub-api, is in code with unit tests.
- **Regional capacity's SQL passes on real PostgreSQL**
  ([adr197-custody-7](../test/results/adr197-custody-7/environment.json):
  exit 0, 99 passed tests, no cleanup failures, source unchanged).
  [ADR-197](decisions/197-regional-capacity.md) migration 00065 runs under
  the whole existing capacity lifecycle (enrollment, sessions, renewal), then
  four new stages on the same root:
  - write-once regional qualification: exact replay, a changed digest, the
    hub cluster and a delete are all refused; the capacity login reads the
    pins;
  - a pending additive regional policy keeps the hub binding's read,
    refresh and managed admission;
  - the root read adopts the revision once (one chain row, the new
    cluster row, custody resized) and the hub enrollment still reads,
    refreshes and admits;
  - an edited hub policy is refused.

  Runs 1–6 are retained failures. Run 1 found the first-installation exact
  table inventory missing the two new tables. Runs 2–5 found the fixture's
  single five-second fleet observation expiring while eighty public roles
  were produced; production observes trust continuously, so the fixture now
  renews it during production (no product change, no limit raised). Run 6
  found two more exact-pool checks, the managed admission fence and the
  audit-profile reader, which now accept the same pending or adopted
  revision.
- **The installed key service and the regional join pass natively**
  ([continuation run 8](../test/results/adr196-continuation-native-8/environment.json):
  exit 0, all four tests, no cleanup failures, source unchanged).
  - [ADR-198](decisions/198-installed-key-service.md): the continuation
    installs the key service. Its configuration is accepted in SQL, it
    serves under the offered roots, refuses an unknown client chain, and no
    other Pod mounts the root key.
  - [ADR-196](decisions/196-regional-cluster-join.md) step 4:
    `installer-cluster` installs the regional executor layout and a join
    record whose connector protection is the staged generation 1. The
    executor composes from settings it reads by name.
  - Step 5: `installer-cluster-join` writes the slot's sources, topology
    and catalog entry, and the hub-api restarts its process and accepts the
    entry.
  - [ADR-199](decisions/199-executor-proof-source-reads.md): runs 4–7
    measured the cause of the executor's earlier failures. Its cold proof
    made about 145 rate-limited calls, against a five-second bound and
    20 QPS clients. ADR-199 reads the source once at each end of the proof
    and makes the close local. Runs 1–7 are retained failures.
  - Regional capacity (ADR-197) and the capture run remain.
  - **Full Go gate.**
    [adr196-go-check-1](../test/results/adr196-go-check-1/go-check.log) failed
    on one pinned privilege test. It still expected the hub-api's old
    get-only rule, without the slot topology names step 5 adds. After that
    test was updated,
    [adr196-go-check-2](../test/results/adr196-go-check-2/go-check.log)
    passed: 55 packages and 574 Kubernetes tests in 15 groups, source hash
    unchanged.
- **The owner's native port is reachable from another cluster**
  ([continuation run 1](../test/results/adr196-continuation-native-1/environment.json)).
  [ADR-196](decisions/196-regional-cluster-join.md) decision 5: the
  continuation creates an L4 Service (pinned NodePort) for the owner's port
  9444, and the regional offer names its address and the accepted owner
  configuration. From outside the cluster, a TLS 1.3 handshake under the
  owner's bootstrap server name reaches the observation server through the
  server-name router. Retention, the administrator edit, the crash restart
  and the promoted owner pass in the same run (exit 0, four tests, no
  cleanup failures, source unchanged). The join command, executor layout,
  catalog restart, regional capacity (ADR-197) and the installed key
  service (ADR-198) remain.
- **The hub retention source becomes Ready**
  ([continuation run 8](../test/results/adr195-continuation-native-8/environment.json)).
  [ADR-195](decisions/195-installed-hub-retention-source.md): the hub-worker
  runs the retention reconciler, acceptance publisher and catch-up pager
  from logins carried in the permission projection. The source accepts the
  empty set and then the operator's baseline, and reads Ready through the
  hub's `retention-read` login. It also accepts an administrator's baseline
  edit and returns to Ready after a hub-worker crash, under a new epoch. The
  Transit-backed lifecycle signer (step 5b) is deferred to the capture
  composition. The full Go gate passes on these sources
  ([adr195-go-check-1](../test/results/adr195-go-check-1/go-check.log): 55
  packages and 570 Kubernetes tests in 15 groups, source hash unchanged).
- **The continuation launches a promoted owner**
  ([continuation run 9](../test/results/adr194-continuation-native-9/environment.json)).
  The promoted owner is Ready, capacity reaches `ReadyAt` through its 9444
  observation handler, and the regional cluster still enrolls at generation
  1. Runs 1–8 are retained failures; run 6 found the cause of the
  intermittent owner installation failures (the administrator token's
  credential ID changes on kubelet refresh). The full Go gate passes on
  the same sources ([adr194-go-check-1](../test/results/adr194-go-check-1/go-check.log):
  55 packages and 568 Kubernetes tests in 15 sequential groups, source hash
  unchanged).
  [ADR-194](decisions/194-promoted-owner-inputs.md):
  - `public.promotion` opts in; it requires the capacity and federation steps.
  - The continuation creates the unconfigured worker configuration and the
    owner download environment, each with its guard. An unconfigured worker
    leaves the hub-api without downloads: prepare fails closed and the
    content paths answer 503.
  - The phase-3 artifact creates the four public roles, the session and
    work-signing Transit keys and the worker PKI role. The continuation reads
    them back with type checks, derives `Native` and `Public`, writes the
    empty worker-control catalog and the operator public Secret from the
    inbox, then projects and launches the promoted owner.
  - The owner checks its public runtime projection against the mounted root
    at startup.
  - The 9444 server-name router (ADR-190 step 6) serves observation and
    native from one server credential.
- **Helm `mode=cluster` installs a regional connector**
  ([Helm cluster run 4](../test/results/adr193-helm-cluster-native-4/result.json)).
  ADR-193 step 6: the packaged chart's post-install hook runs
  `installer-cluster --in-cluster` from the authenticated registry. The
  release's installer account administers both guards; the Deployment is
  ungated after the proof; an upgrade reruns unchanged; the cluster
  administrator's token request and source write are denied. Runs 1–3 are
  retained failures (missing `fsGroup`; the test's own denied token request).
- **Continuation run 53 installs a regional cluster**
  ([environment](../test/results/adr183-continuation-native-53/environment.json)).
  [ADR-193](decisions/193-installed-federation-and-regional-enrollment.md)
  step 5, with two owned clusters:
  - The hub comes from the continuation, and a fleet operator slot is issued
    with the product `fleet-bootstrap-*` logins. Only the operator authority
    is fixture setup.
  - `asservat installer-cluster` installs the second cluster from the offer
    and the operator's KV record. Both guards are proven with the connector's
    own token before the Deployment is ungated.
  - The connector enrolls generation 1 and both leaves. A restarted Pod is
    readmitted without an administrator, a rerun changes nothing and a
    non-administrator source write is denied.

  Runs 49–52 are retained failures of the new step:
  - 49: a fixture expected the wrong transit status.
  - 50: the intermittent owner check, in the identity-role phase.
  - 51: the installer gave both guard proofs one client.
  - 52: the continuation derived a connector backing too short for the
    regional deployment shape. The continuation now refuses that.

  The focused [installer run 2](../test/results/adr193-installer-native-2/result.json)
  isolates the installer.
- **Intermittent owner-launch check: instrumented (open).** Continuation
  [run 48](../test/results/adr183-continuation-native-48/context-storage.log)
  stopped at `projection.final-native (unavailable after 1.256s)` before
  reaching the new regional step: the fourth occurrence (runs 35, 41, 46,
  48). Those messages named no step, because the SQL facet replaced callback
  errors with a plain `unavailable` and the current-read path returned plain
  errors. Every such return now carries a closed code: the SQL finalization
  step, the first callback failure, the differing original field and the
  current-read cause (for example `current.accepted-valid`). Run 49 passed
  the owner installation and failed in the new step-5 fixture (a transit key
  status). Run 50 stopped at a sibling site,
  `owner/installation/audit/original-result-unverified`, the identity-role
  creation; that path now also reports its SQL step (`role-*`) and first
  native failure. The next failing run will identify the condition; no fix
  is claimed yet.
- **Fleet-operator bootstrap issuance with Keycloak**
  ([identity run 3](../test/results/adr193-identity-3/identity-provider-environment.json)).
  [ADR-193](decisions/193-installed-federation-and-regional-enrollment.md)
  step 4 as components:
  - Four hub SQL purposes keep reservation, credential recording, audit
    acknowledgement and activation separate.
  - A pinned `bootstrap-channel` provider role joins the phase-3 artifact.
    Its borrowed token reaches only one KV record per request.
  - `POST /api/v1/fleet/cluster-bootstraps` authorizes each request from its
    own current identity and the protected fleet settings.
  - With an actual Keycloak session: issued, replay stable, non-operator 403,
    ceiling 429.

  The continuation does not install the hub-api public layer yet, so the
  route is not installed. The fleet settings reader and trust row in this run
  are fixture setup. Identity runs 1–2 are retained fixture failures.
- **Federation run 3 enrolls generation 1 from a bootstrap**
  ([result](../test/results/adr193-federation-native-3/result.json)).
  [ADR-193](decisions/193-installed-federation-and-regional-enrollment.md)
  step 3, in two owned clusters with the product `hub-federation` and
  `connector` Pods:
  - A fleet operator slot comes from the product `BootstrapIssuer`: SQL
    reservation, KV delivery, encrypted issue audit and activation. The
    operator authority and the issuance logins are fixture setup.
  - The connector's Secret starts at generation 0 with only the envelope. It
    stores its pending key, then claims over the new `bootstrap` purpose.
  - In one conversation the hub claims the slot and audits the claim, stages
    the regional source under the hub-decided backing, writes and
    acknowledges the generation-1 audit, and activates (migration 00064).
  - The connector promotes its key, erases the envelope and enrolls both
    leaves.
  - The continuation derives the connector backing from the operator's
    settings and publishes it in the federation input and the offer.

  Run 2 is a retained failure. The regional workload guard refused the
  connector's Secret CAS write; it now admits exactly that UPDATE.

  Full Go gates [2](../test/results/adr193-go-check-2/go-check.log) and
  [3](../test/results/adr193-go-check-3/go-check.log) are retained failures
  with unchanged sources. In gate 3 the Kubernetes owner-projection group hit
  its 15-minute timeout while host load reached about 11 from another
  project's race tests. Its slowest tests ran 5–10 times their usual time;
  no test hung. A passing full gate is still owed.
- **Native continuation run 47 provisions the federation**
  ([result](../test/results/adr183-continuation-native-47/result.json)).
  [ADR-193](decisions/193-installed-federation-and-regional-enrollment.md)
  steps 1–2:
  - The federation resolves peers from staged SQL profiles, with no pinned
    peer list.
  - The continuation publishes the federation projection (six SQL logins and
    audit keys).
  - One phase-3 operator apply installs the federation's Kubernetes-auth roles,
    the installation-wide connector PKI roles and its audit key. The
    continuation then verifies them through the inspection token.
  - The federation runs with provider credentials that refresh only under the
    hub workload guard proof, and it starts with zero peers.
  - An immutable regional offer is published.

  Runs 45–46 are retained failures: a fixture TLS client, and the third
  intermittent owner-launch native-check failure (runs 35, 41, 46). The latter
  now reports its class and timing. Another project's race tests were running
  on the host during some runs.
- **Native continuation run 43 publishes capacity readiness**
  ([result](../test/results/adr183-continuation-native-43/result.json)).
  [ADR-192](decisions/192-capacity-before-download-paths.md):
  - Capacity identities derive from the public role setup, so replays match
    the committed claim.
  - After the owner launch the continuation publishes the capacity
    projection with an empty download path set.
  - The hub-worker's capacity child publishes the capacity root's `ReadyAt`.

  Runs 35–42 are retained failures, each fixed or classified:
  - owner provider prime now waits out its backoff;
  - the hub-worker stop message names the child and stage;
  - the capacity guard status users match the installed plan;
  - the native test reads the correct `ReadyAt` source.

  Still open: an intermittent owner launch finalization failure
  (`final-native`, runs 35 and 41), terminal by design.
  [Run 34](../test/results/adr183-continuation-native-34/result.json) launches
  the owner with step 7's `Observation.LocalCapacity` input composed (probe
  tokens, selector guard, caller admission); no request reached that path.

    [ADR-190](decisions/190-capacity-readiness-and-promoted-owner.md)
    resolves the capacity/promoted-owner cycle: capacity initializes before
    the launch, the hub-api reads its audit profiles at runtime, and the
    capacity projection follows the launch.

[ADR-174](decisions/174-regional-context-start-composition.md) composes
regional context start into `asservat connector`, behind an optional
`RegionalDeployment.APIContext`. It adds a delegated read-only `recovery`
federation purpose for the verify-only work-trust reader, encrypt-only OpenBao
Transit artifact wrapping and a fixed `kube-capacity.token`. How the installer
delivers that token is recorded as an open decision. Unit tests pass; native
qualification needs the hub-api route and work signer.

[ADR-173](decisions/173-work-scoped-process-observation.md) removes the
connector executor's start blocker. Each start check used to re-prove the whole
process (about 13 API calls each, 8 per execution) on top of a cold 71-call
proof, which cannot fit the original five seconds at 20 QPS. One verified work
now reuses its single complete process observation, never renewed; capacity,
start-guard and CAS checks stay current.
`TestConnectorAPIProcessWithRealKubernetes` passes natively for the first time
([run 6](../test/results/connector-api-timing-6/result.json): 2.57 s of 5 s).
Runs 1–5 are retained failures: a test-created CRD that admission refused for
about 2 s, the per-call rechecks, and a non-canonical test binding.

ADR-172's federation owner reads are composed: a read-only
`connector-owner-read` role (ordinal 56, exactly the owner `registry` grants),
the optional `FederationDeployment.Owner` copied from the hub-api input by
`OwnerDeployment.Guard()`, and the hub-api's unchanged registry, route and
guard readers built from that identical plan. Unit and race tests pass. The
initial-installation suite provisioned and verified all 42 roles on real
PostgreSQL ([result](../test/results/adr172-roles-1/result.json): exit 0, 87
tests, empty cleanup, unchanged sources). Native qualification follows with the
regional composition.

The earlier full Go gate after ADR-171/172
([log](../test/results/adr172-go-check-1/go-check.log)) failed, exit 2. All
non-Kubernetes packages and Kubernetes groups 1–6 passed; group 4's one
explicit skip is pre-existing. One group-7 test failed,
`TestPublicRoleStateRejectsIncompletePriorInventory`. It pinned the pre-ADR-170
role count (31 after removing two of 33) instead of deriving it from the layout
(now 41). The count is derived now, and the public-role Kubernetes tests pass;
a complete gate rerun is still owed. The earlier
[ADR-170 gate](../test/results/adr170-go-check-1/INCOMPLETE.txt) was interrupted
by a host reboot during group 7 and never reached this test.

## Original observation selection and SQL connection budget components

[ADR-165](decisions/165-original-observation-capability-selection.md)'s staged
17-file subset is integrated. Its [component gate](../test/results/installed-observation-selection-component-3/result.json)
passes compile, 64 race parents in six groups, vet and canonical checks. Two
earlier runs are retained as failures: a never-run staged test with a wrong
fixture premise, and a runner that used the system Python for spec checks.

`contracts.InstalledSQLConnectionPlan`/`Validate` now implement the specified
per-hub (≤32) and installation-allocation arithmetic against actual
non-reserved server capacity. They report the failed rule with required and
configured counts and supported remedies, and never raise limits. With the
purposes composed at that time, one hub process plus the hub worker needed 53
ordinary connections (63 with ADR-170's federation compartment). The worst case
of four retained hub processes needed 149 (now 159; 161 with ADR-172's owner-read role),
which PostgreSQL's default 97 ordinary slots cannot hold. That checkpoint was
unit-tested only. The [installed SQL budget correction](research/installed-sql-budget.md)
now wires the compiled one-hub plan into the promoted continuation before
runtime resource creation, against actual non-reserved server capacity. The
ADR-205 graph plus five overlapping installer pools, a separate verifier and
four maintenance slots required 112 ordinary slots. The continuation's passive
history reader closes before bridge opening and is limited to one connection.
At that checkpoint its installed fixture derived 116 total slots: 112 product, one independent
fixture observer, and three superuser-reserved. Ordinary component fixtures
remain at 48; early superuser sessions are not treated as isolated reserved
capacity. ADR-210's browser-settings observer adds two retained worker
connections; the corrected current plan requires 114 product slots and derives
118 total fixture slots, as recorded in the resumed review above.
Native installed qualification of this correction remains pending.

## Regional investigation journey passes end to end (native36/37)

The [thirty-sixth](../test/results/public-context-journey-native-36/result.json)
and [thirty-seventh](../test/results/public-context-journey-native-37/result.json)
native regional investigations pass. Each runs one shared operation factory,
browser- and MCP-shaped current requests, and the real first regional capture
(one collector call). It then covers accepted resolution, independent
publication, progress and case lookup, the phase-separated download
continuation, and authenticated h2 native bytes (362) checked against the
original capture's SHA-256 and ETag. It ends with prepaid Stop with a recorded
audit, then denial of metadata and bytes after current identity revocation.
Both runs record exact selected RUN/PASS names, an unchanged 3,121-file source
snapshot and reviewed payloads, joined process groups, and removal of owned
Docker/Kind/scratch resources. Go took 24.7–25.3 s; the wrappers took 107–120 s.

Two further corrections followed native31–35:

- **Regression in my own ADR-167 change.** Once activation committed, a
  continuation saw the new enrollment and closed its registration while the
  exchange was still delivering the certificate (native30). The new-enrollment
  return now also waits for `Delivering()` to end
  (`TestContextRuntimeNewEnrollmentWaitsForDeliveryToEnd`, failing before).
- **Two stale fixture compositions.** The journey wired the pre-migration-47 Stop
  objects without the writer's lifecycle completion. Its SQL guard correctly
  rejected the acknowledgement with 23514 (native33–35). The journey now uses
  `NewHealthyDownloadStopObjects` with the existing writer role. Separately,
  the Observe conversation removed by ADR-167 changed joined-conversation and
  native-transition expectations in four suites.

The changed real-service download modes pass:
[content/resume/interrupted](../test/results/adr167-native-content-modes-2/result.json)
and the complete [41-mode download-worker family](../test/results/adr167-download-worker-family-1/result.json),
in 202 s with no cleanup failures and unchanged sources.

This is a two-cluster *fixture* journey with explicit synthetic identity,
bootstrap, permission, retention and capacity inputs. It is not the installed
S-02 workflow, and two passes are not a sustained-availability qualification.
Installed provisioning, SQL connection admission, and Helm/public enablement
remain open.

## Download enrollment failure resolved into three phase defects

The staged continuation-outcome diagnostic passed its
[component gate](../test/results/public-context-continuation-outcome-component-1/result.json)
(nine race parents, compile, vet, unchanged sources). The
[fourteenth native investigation](../test/results/public-context-journey-native-14/result.json)
then recovered the decisive fact: enrollment was refused 5.6 ms after the original
continuation started, before that continuation could register. Native13's
refusal was a **fixture** defect. The one-shot owner-claim notification had been
consumed by the first preparation's own registration, which claims and releases
fence 1. The waiter now arms explicitly before the continuation and accepts only
the next fence (`TestPublicJourneyOwnerClaimArmIgnoresEarlierRegistration`).

[Native15](../test/results/public-context-journey-native-15/result.json) reached
proof and CSR, then reproduced native12's SQLSTATE 53300 on
`context_catalog_read_runtime`. The journey used the 16-connection fixture pool
profile with pgx's 30-minute idle default. It now uses the installed
one-connection profile (`installedSQLPoolProfile`, matching
`providerInputs.sqlConfig`), including its authority pool. The 48-slot server
and reserved slots are unchanged. That alone was not sufficient. Native25, 26, 28
and 34 still hit 53300 on `context_verify_runtime`: 44 of the 45 ordinary slots
were held when publication opened its gate and verification facets. (An earlier
version of this entry wrongly stated that no 53300 recurred after native19.) The
journey now retires the preview and resolution pools after their last call
(`publicJourneyPools.Retire`). Idle expiry is not claimed as admission control;
the aggregate connection-admission gap in the product SQL budget review remains
open, and this tight fixture margin is evidence for it.

Subsequent runs isolated three production phase defects, recorded in
[ADR-167](decisions/167-phase-bounded-download-continuation.md):

- [Native16](../test/results/public-context-journey-native-16/result.json)
  completed enrollment, then ran the native exchange out of the original
  five-second bound. A continuation that produced a new enrollment now returns
  Preparing.
- [Native20](../test/results/public-context-journey-native-20/result.json)
  joined the prepare conversation in the next continuation, but its Ready view
  needed a second Observe conversation with 0.62 s left. Acknowledged prepared
  facts are now handed once to the same process's metadata cache.
- Native21–23 showed the one-second arrival window closing a registration with
  an in-flight enrollment, cancelling it after CSR (the gate trace recorded a
  permission read cancelled with 2.7 s remaining). Such a registration is now
  kept until the exchange ends, within the original bound.

Each production change has a failing-before / passing-after component regression.
The evidence race suite, `go vet ./...`, Go architecture and spec checks pass.

The installed UI/MCP/download journey is **not** qualified. Native24–28 failed
intermittently in different phases: a refusal after activation (later traced to
the regression below), publication 53300 (above) and one first-request
OutcomeUnknown that has not recurred. Each run recorded joined cleanup. Native25–28 ran while an
unrelated local `haptic-e2e` Kind cluster used about thirteen of sixteen cores
(load average ~10). That cluster was not touched. These results are retained as
failures; an idle-host rerun with the new fixed-label gate/publication
diagnostics is next. The `context_native_content` transition expectations
changed with the handoff and need their own real-service rerun.

## Profile endpoint planning passes; download enrollment exhausts catalog connections

Passive Go profile endpoint planning now passes its
[second component gate](../test/results/runtime-profile-endpoint-component-2/result.json):
all 30 selected parents / 269 named race tests, compilation, vet and canonical
specification, architecture, Go architecture and design checks. The earlier
[failed gate](../test/results/runtime-profile-endpoint-component-1/result.json)
passed its tests but rejected domain imports. Bounded pure Host/port validation
replaces those imports without changing the architecture rule. Exact 3,116
sources, 36 archives, reviewed payloads and joined cleanup are independently
verified. This qualifies passive planning and synthetic API observation, not
protected catalog acceptance, node dialing or installed profile collection.

The [eleventh native investigation](../test/results/public-context-journey-native-11/result.json)
failed before enrollment: test instrumentation added a pgx tracer that the
production SQL constructor correctly rejects. That rejection remains intact.
The [corrected diagnostic component](../test/results/public-context-download-log-prefix-component-1/result.json)
passes five harness tests and three Go parents / 20 named race tests, integration
compilation and vet. It tests the actual constructor boundary and records only
the synthetic database role and SQLSTATE through the owned server's log prefix;
statement and bind-parameter logging remain disabled. Exact 3,116 sources,
174 archives and joined cleanup are independently verified.

The [twelfth native investigation](../test/results/public-context-journey-native-12/result.json)
again completes collection, publication and case lookup. Its original regional
request invokes the collector once in 4.270563878 seconds. Enrollment then fails
at the original current-authority check; PostgreSQL rejects a connection for
`context_catalog_read_runtime` with SQLSTATE `53300`. This identifies the
previously unknown rejected role and enrollment dependency. It does not yet
establish the required connection-lifetime correction. The test starts that
phase with 43 physical connections, including its administrator connection,
against the unchanged 48-slot fixture with three reserved slots. No request is
replayed or connection limit raised. Go exits 1 after 13.815 seconds; the wrapper
exits 1 after 114.389 seconds. Exact 3,116 outer / 2,364 native sources, nine
archives and owned process, Docker, Kind and scratch cleanup are independently
verified. The installed UI/MCP/download workflow remains unfinished. Next work
is the measured connection-concurrency correction and original installed
owner/regional/capacity composition; public runtime enablement remains closed.

## Original owner startup passes; regional collection reaches download enrollment

[ADR-164](decisions/164-owner-launch-receipt-convergence.md) now lets startup
passively await only the original launch receipt, pins the first complete receipt
and reruns the entire current native identity proof before credential use. The
preserved [before regression](../test/results/owner-launch-receipt-before-1/result.json)
rejects the valid pending launch while accepting its completed control. The
[corrected component gate](../test/results/owner-launch-receipt-component-1/result.json)
passes all 16 parents / 74 named race tests, compilation, vet and canonical
specification/architecture checks. Exact 3,105 sources, 22 archives and joined
cleanup are independently verified.

The [fourteenth installed-owner run](../test/results/runtime-provider-owner-native-14/result.json)
passes all four original required cases. It provisions the original roles and
projections, launches the original owner Pod and verifies both client/server
identities for the same process, including version-pinned encrypted enrollment
and certificate audit plus current registrations. Worker exit after original
Lease deletion and administrator-removal denial also pass. Go exits 0 after
574.528 seconds; the wrapper exits 0 after 615.974 seconds. Exact 2,550 outer /
2,353 native sources, five archives and owned process, Docker, Kind and scratch
cleanup are independently verified. Original five-second effect bounds,
twenty-QPS/burst-twenty clients and PostgreSQL fixture limits are unchanged.
This qualifies the named observation-mode startup path, not Ready/TLS backend
serving, full public runtime provisioning or the complete installed investigation.

[ADR-163](decisions/163-original-work-transport-observation-lease.md) retains one
original transport peer observation across correctly ordered identity frames,
with a separate complete final check and no extension of the original interval.
Human identity and application effect checks remain current. The
[before regression](../test/results/context-frame-lease-before-1/result.json)
reproduces seventeen full observations and failure under the original rate/time
budget. The [corrected component gate](../test/results/context-frame-lease-component-1/result.json)
passes 48 parents / 157 named tests, including actual HTTP/2, plus integration
compilation, vet and canonical checks. Exact 3,105 sources, 168 archives and
joined cleanup are independently verified.

The [tenth native investigation](../test/results/public-context-journey-native-10/result.json)
now completes the original regional exchange with one collector invocation in
4.267659428 seconds. Capture, publication and case lookup pass; download worker
enrollment then fails at the original enrollment call. PostgreSQL records a
reserved-connection-slot rejection during this phase, but the rejected role and
deciding enrollment dependency are not yet established. This remains a failed
gate: Go exits 1 after 14.841 seconds, the wrapper after 115.684 seconds. Exact
3,105 outer / 2,353 native sources, nine archives and owned cleanup are independently
verified. Earlier failures remain preserved. No request was replayed or limit
raised. Fixture-only enrollment/connection diagnostics are staged for the next
qualification; the full installed UI/MCP/download flow remains unfinished.

## Native startup refusal and transport read amplification isolated

The [thirteenth installed-owner run](../test/results/runtime-provider-owner-native-13/result.json)
passes activation, role/projection finalization and acknowledged original launch,
then the original owner process exits before identity. Its bounded diagnostic is
`phase=native-identity`, `native=initial-journal`, `detail=journal-state`.
This identifies a compound journal-validation refusal, not its individual
predicate or a timing cause. Native Go exits 1 after 532.724 seconds; the wrapper
exits 1 after 577.951 seconds. Passive commands and administrator-removal checks
pass. Exact 2,544 outer / 2,347 native sources, seven archives and owned cleanup
are independently verified. A focused producer/reader regression is next.

The [ninth native investigation](../test/results/public-context-journey-native-9/result.json)
refuses at the regional stream's original `receive-peer` check with `unavailable`;
the hub records `read/other`. The whole request takes 4.919341134 seconds and the
collector remains uncalled. This narrows the boundary to the connector/process
observation or final interval validation, without proving its exact failed
predicate. Native Go exits 1 after 10.989 seconds; the wrapper exits 1 after
105.481 seconds. Exact 3,097 outer / 2,347 native sources, nine archives and owned
cleanup are independently verified.

Source enumeration reveals a separate feasibility defect: seventeen regional
transport observations for seven identity round trips require 170 reads on the
bare-Pod reader's one 20-QPS/burst-20 executor client, excluding other consumers.
Even a fresh bucket needs at least 7.5 seconds, beyond the original five-second
work interval. Qualification of a work-scoped transport observation lease is
next; application effect checks, original expiry, frame limits and native client
rates must remain unchanged. No public workflow is enabled.

## Go profile acquisition and startup diagnostics pass component qualification

The bounded [Go runtime-profile acquisition](architecture/runtime-profiles.md)
now preserves native pprof/trace response bytes in the existing encrypted format.
It requires an independently admitted request, named qualified node connection
and current authority; it does not implement those producers or expose public
profile collection. A real Go CPU handler and bounded synthetic HTTP fixtures
exercise the mechanism. Current observations cannot extend the caller, action or
channel deadline, and uncertain starts remain spent.

The [before-fix regression](../test/results/runtime-profile-caller-deadline-before-1/result.json)
proves an admitted ten-second recording could begin under a three-second caller.
The production fit check now uses the earliest original deadline before dialing
and HTTP. The [first component gate](../test/results/runtime-profile-component-1/result.json)
passes all 28 parents / 97 named tests but fails vet on cancellation cleanup.
After separating the channel child context from the watched action context,
the [second gate](../test/results/runtime-profile-component-2/result.json) passes
all 97 named race tests, full vet, specification, architecture, Go architecture
and design checks. Exact 3,095 sources, 18 archives and process/scratch cleanup
are independently verified. Production endpoint resolution, profile-specific
admission, node routing, semantic publication, analysis and UI/MCP/native-download
composition remain pending.

The [owner startup diagnostic gate](../test/results/owner-startup-diagnostics-component-2/result.json)
passes 15 parents / 57 named race tests, full vet, specification and architecture
checks. Closed diagnostic fields identify the original startup stage without
rendering private provider errors. The fixture retains bounded current/previous
logs only from the original Pod. One earlier test expectation incorrectly named
the next native read after clock expiry; only that expectation was corrected.
Exact 3,089 sources, 26 archives and process/scratch cleanup are independently
verified. This provides failure evidence, not a startup correction.

The [context-stream diagnostic gate](../test/results/public-context-stream-diagnostics-component-1/result.json)
passes 31 parents / 92 named race tests, integration compilation and full vet.
It preserves original I/O, authority reads, deadline sampling and errors while
retaining the first observed local refusal at each endpoint. Its retained-read
socket-deadline regression demonstrates a possible mechanism, not the cause of
the separate native journey failure. Native qualification follows below.

## Owner projection finalization and regional investigation diagnostics

The [twelfth installed-owner run](../test/results/runtime-provider-owner-native-12/result.json)
passes all eight original execution SQL calls and all eight separate read-only
finalizations, crossing the previous second-call failure with unchanged deadlines
and 20-QPS/burst-20 clients. Their trace records no limiter refusal or expired
return; the complete role/projection/launch phase takes 87.164 seconds. Independent
launch-current readback also succeeds. The deployed owner process then exits 1
before paired identity is established, so the suite still fails (576.871 seconds
overall, native Go 532.723 seconds). Passive-command and administrator-removal
checks pass. Exact 2,532 outer / 2,335 native sources, seven archives and owned
process/Docker/Kind/scratch cleanup are independently verified. This is progress
through the original startup path, not installed-workflow completion. Continue
the process-start failure and the regional eligibility failure below.

[ADR-162](decisions/162-owner-projection-read-only-finalization.md) now separates
the original bounded owner projection effects from mandatory read-only
finalization. No effect deadline, rate limit, SQL connection ceiling or permission
is increased. Its original
[component run](../test/results/owner-projection-finalization-component-1/result.json)
reaches the fifteen-minute package limit after 101 passing parents and exposes
a whole-sequence test watchdog that incorrectly allowed only five seconds.
The [follow-up](../test/results/owner-projection-finalization-component-2/result.json)
runs all twelve unfinished/failed parents: eleven pass, including the corrected
three cancellation cases. One older private-read fixture still assumes a single
execution phase. That run also retains a runner bookkeeping/source-change failure;
its failed verdict is not relabeled.

After correcting the fixture to require zero private reads before execution and
two before independent finalization, the
[third component gate](../test/results/owner-projection-finalization-component-3/result.json)
passes the parent and all four cases, all 110 PostgreSQL parents (689 named
passes), full vet and Go architecture checks. Production code was unchanged by
these two fixture corrections. All 3,082 source paths/hashes, 35 archives and
owned process/scratch cleanup are independently verified. Original installed-owner
and full-Go qualification remain pending.

The regional investigation diagnostic fixture is now integrated with fixed,
content-free counters around the original verifier and pre-collection runner
ports. It preserves original calls, arguments, optional completion capabilities
and prepared handles; it adds no request replay or authority refresh. Its
[component gate](../test/results/public-context-regional-diagnostics-component-1/result.json)
passes integration compilation, six diagnostic parents (17 named passes) and
full vet. Exact 3,084 sources, 116 archives and owned process/scratch cleanup are
independently verified. Specification, architecture and design gates also pass.
The [seventh native journey](../test/results/public-context-journey-native-7/result.json)
exits 1 after 107.581 seconds (native Go 11.097 seconds). It verifies the signed
regional request and succeeds through the initial runner checks, SQL preparation
and key preparation. The second eligibility check refuses; the original collector
count remains zero. This locates the failure but does not yet establish whether
identity, permissions or expiry caused it. Exact 3,084 outer / 2,335 native source
paths, nine archives and owned process/Docker/Kind/scratch cleanup are independently
verified. No uncertain request was replayed. Continue that eligibility boundary
and the original installed-owner qualification; public runtime remains disabled.

The [eligibility diagnostic follow-up](../test/results/public-context-eligibility-diagnostics-component-1/result.json)
now retains only whitelisted reasons from the original result and observes the
original identity calls without adding reads or changing their bounds. Integration
compilation, seven diagnostic parents (24 named passes) and full vet pass. Exact
3,084 sources, 116 archives and owned process/scratch cleanup are independently
verified. No production cause or correction is claimed from this instrumentation.

The [eighth native journey](../test/results/public-context-journey-native-8/result.json)
exits 1 after 99.175 seconds. Its second eligibility evaluation returns
`IdentityUnavailable`: the first identity resolution in that evaluation fails
while receiving the original regional exchange reply. The original evaluator
context is canceled; this does not distinguish a peer-check refusal, socket/stream
failure or expiry of an original bound. No permission read in that evaluation or
collector invocation occurs. Exact 3,084 outer / 2,335 native sources, nine archives
and owned process/Docker/Kind/scratch cleanup are independently verified. Continue
the original exchange interruption; neither a new capture nor an extended deadline
is a correction for this failure.

## Fleet freshness passes focused qualification; installed workflows remain incomplete

[ADR-161](decisions/161-fleet-observation-separation.md) now passes its actual
PostgreSQL migration/producer/activation qualification: all 31 named cases in the
[native run](../test/results/fleet-freshness-native-1/result.json), exit 0 in
46.536 seconds. These cover unchanged renewal under retained SHARE locks,
restrictive serialization, original basis/deadline and incarnation checks,
explicit first activation, and migration privilege/hook refusals. Synthetic
protected source inputs remain explicit; this is not installed owner availability.

The [second component gate](../test/results/fleet-freshness-component-2/result.json)
passes 265 top-level race tests (1,428 named passes, no skips), SQL generation,
eight embedded schema checks and Go/specification/architecture/design gates.
Integration compilation and full vet passed separately. The
[first component failure](../test/results/fleet-freshness-component-1/result.json)
is preserved: three existing reconciler fixtures lacked the newly required
original observation basis. Only those fixed fixture inputs were corrected;
no timeout or production authority was relaxed. Exact source/archive inventories,
joined process groups and scratch cleanup are independently verified for both
component runs and the native qualification.

The [full initial-installation run](../test/results/fleet-freshness-initial-installation-1/result.json)
still exits 1, with 87 named executions, 84 passes and two failed leaf cases
(their parent also fails). Both retained pre-SQL59 expectations: a base-only source
change now projects unavailable authority until a coherent observation exists,
and unchanged positive observation now succeeds while the bridge holds SHARE.
The reviewed fixture correction preserves changed-source rejection, restrictive
writer blocking and the original in-flight deadline. The
[second full run](../test/results/fleet-freshness-initial-installation-2/result.json)
now passes all 87 named cases with no skips, including unchanged renewal under
bridge SHARE and the original 200ms deadline remaining binding. It exits 0 in
59.543 seconds. All 3,075 outer and 2,304 native source paths/hashes, seven archives
and owned process/Docker/scratch cleanup are independently verified. The first
failed run remains preserved. The
[full fleet run](../test/results/fleet-freshness-fleet-1/result.json) also passes
all 176 named tests in 66.950 seconds, with exact 3,075 outer / 2,304 native
source inventories, seven archives and owned cleanup independently verified.
The [database recovery run](../test/results/fleet-freshness-database-recovery-1/result.json)
passes all three actual phases—initial, restarted and restored—in 30.722 seconds.
The server-start identity changes on restart and the database OID changes after
restore. Its exact 3,075 outer / 2,304 native source inventories, seven archives
and owned cleanup are independently verified.
The [full custody run](../test/results/fleet-freshness-custody-1/result.json)
also passes, with 452 named passes in 716.417 seconds. Its three expected skips
are the separate owner PKI/provider suites and optional 31-minute connector
retirement; these are not claimed as custody coverage. Exact 3,076 outer / 2,305
native sources, seven archives and owned process/Docker/scratch cleanup are
independently verified. Full-Go qualification remains pending.

The [eleventh original installed-owner run](../test/results/runtime-provider-owner-native-11/result.json)
passes setup-free replay and administrator-removal rejection, but owner startup
still fails. Projection SQL call one succeeds; call two refuses at `final-native`
with one same-call source-client limiter refusal while its context remains live.
The permitted inspection also fails its final native check. The driver stops at
thirteen calls and one inspection, retaining uncertain spend. The wrapper exits 1
in 542.619 seconds; all 3,075 outer and 2,326 native source paths/hashes, nine
archives and owned process/Docker/Kind/scratch cleanup are independently verified.
Original flags, deadlines and 20-QPS/burst-20 clients are unchanged. The SQL split
repairs the qualified locking defect but has not completed startup availability;
these counters do not identify an individual refused HTTP request or prove a new
SQL predicate failure.

The [third combined investigation run](../test/results/public-context-journey-native-3/result.json)
gets beyond the prior connection-exhaustion failures after setup-only pool closure
and same-purpose reuse. It reaches the shared assembly with 43 observed database
connections under the unchanged 48-connection ceiling, then fails at browser
preview with `durable audit unavailable`; no connection-exhaustion error is
recorded in this run. This is not a passing capture/case/native-download journey.
Its failed result, exact frozen inputs and owned cleanup are preserved. The
[subsequent fixture component gate](../test/results/public-context-journey-component-7/result.json)
passes compilation, two selected race parents (seven named passes) and full vet
after the reviewed diagnostics and bridge-expectation corrections. The
[fourth journey run](../test/results/public-context-journey-native-4/result.json)
also exits 1 (96.392 seconds; native Go 5.557 seconds). Every instrumented audit
and preview dependency succeeds, including both eligibility reads and preview
creation; the frozen operation outcome is still unavailable. The generic outward
message therefore does not establish an audit dependency failure. Independent
verification confirms all 3,075 outer / 2,327 native source paths/hashes, nine
archives and owned cleanup. Source review identifies the API-only impact
explanation at 290 characters, exceeding the canonical output maximum of 256;
the existing unit fixture used shorter synthetic text. The actual compiler-to-wire
regression [reproduces](../test/results/context-assessment-wire-before-1/result.json)
those invalid output fields and the public preview failure while the node path
passes. Shorter product wording is integrated. The
[corrected component gate](../test/results/context-assessment-wire-component-1/result.json)
passes all 52 planning/presentation test parents (132 named passes), full vet,
specification and Go architecture checks. Exact 3,076 source paths/hashes, twelve
archives, joined processes and removed scratch are independently verified.
The canonical output limit is unchanged. The
[fifth native journey](../test/results/public-context-journey-native-5/result.json)
now returns a successful audited browser preview, then stops at the first capture
request with `OutcomeUnknown`. It does not repeat that uncertain request or select
another capture. The wrapper exits 1 after 139.042 seconds; native Go takes 11.887
seconds. Exact 3,076 outer and 2,328 native source paths/hashes, nine archives and
owned process/Docker/Kind/scratch cleanup are independently verified. The preview
defect is corrected; request-to-download completion remains unqualified.
The [reviewed first-request diagnostic fixture](../test/results/public-context-request-diagnostics-integration/integration.json)
now observes the original admission, capture-intent audit and regional-dispatch
calls once, after the preview has returned. It adds no production behavior,
dependency read or request replay. Its
[component gate](../test/results/public-context-request-diagnostics-component-1/result.json)
passes integration compilation, all three selected diagnostic race parents and
full vet; exact 3,077 sources, 91 archives and joined process/scratch cleanup are
independently verified. The
[sixth native journey](../test/results/public-context-journey-native-6/result.json)
still exits 1 (96.278 seconds; native Go 11.852 seconds), but establishes that
original admission, the complete paired capture-intent audit and regional
accepted-read/signing all succeeded. The original collector invocation count is
zero. No uncertain capture is repeated. Exact 3,077 outer / 2,329 native sources,
nine archives and owned process/Docker/Kind/scratch cleanup are independently
verified. Continue the original regional exchange and pre-collection boundary;
this is not a completed capture or download workflow.

A separate source review identifies missing **installation-wide SQL connection
admission** required by [persistence](../specs/persistence.md) and the selected
deployment profile. The known pool maxima already total 32 per hub (28 public
purposes plus four owner purposes) and eight per HWORK process: 40 for one of each,
or 144 across their maximum retained four-hub/two-HWORK overlap. Those are partial
configured maxima, not measured simultaneous connections or a complete product
budget; missing services, jobs, installers and maintenance headroom still need
accounting. Per-role limits, idle expiry and fixture pool fixes do not supply this
admission. Complete the selected graph and reject insufficient allocations before
runtime startup, without silently raising limits or merging purpose credentials.

Continue the actual output-boundary regression, installed startup correction
and remaining custody and full-Go qualification.
Public collection and Helm runtime remain disabled. Earlier chronological
checkpoints and failures below remain historical evidence.

## Fleet freshness split integrated; native journey still exceeds fixture connections

[ADR-161](decisions/161-fleet-observation-separation.md) and migration 00059 are
integrated with their focused and existing fixture adaptations: 70 source paths.
The [integration record](../test/results/fleet-freshness-integration/integration.json)
binds the reviewed payloads and preserved originals. Positive observations now
bind semantic authority and database incarnation separately from restrictive
locks. Review also closed trigger/reference privilege prerequisites and corrected
later-native-start ordering after an unknown commit. Component and production SQL
qualification have not run yet; no installed availability claim follows.

The combined shared capture/case/native-download fixture is integrated. Its first
owned two-cluster run failed on PostgreSQL connection exhaustion. Nine completed
setup pools now close earlier; compilation and full vet pass in the fifth
[component run](../test/results/public-context-journey-component-5/result.json).
The second [native run](../test/results/public-context-journey-native-2/result.json)
gets further but still exhausts the unchanged 48-connection service at operation
audit setup. It exits 1 after 112.190 seconds; Go exits after 6.343 seconds. Exact
3,063 outer and 2,316 native source sets/hashes, archived files, joined processes
and owned Docker/Kind/scratch cleanup are independently verified.

The remaining fixture correction is pool lifetime and same-purpose reuse, with
every assembled runtime service retained. The source census identifies three
separate pools for the same catalog role. This is not a passing investigation
journey, and the older installed-owner failure remains open. Continue the fixture
correction, real SQL freshness qualification and original installed-owner run;
public and Helm runtime remain disabled.

## Generated preview and resolution roles pass actual PostgreSQL checks

The unchanged `make initial-installation-integration` fixture returns exit 0
against its owned PostgreSQL, S3 and OpenBao services. All 87 named tests run
and pass, including preview/resolution authentication, column privileges,
permitted effects and independent SQL trigger denials under both normal role
creation and lost-completion recovery. The Go package takes 51.175 seconds;
the harness interval including compilation is 65.662 seconds. This uses the
existing explicitly synthetic protected Kubernetes inputs, not an installed
browser/MCP investigation.

The [original wrapper result](../test/results/public-context-assembly-initial-installation-1/result.json)
retains exit 1: its expected inventory omitted four existing historical-reader
subtests. Both wrapper errors come from that omission, not changed selection or
time bounds. The [independent verification](../test/results/public-context-assembly-native-verification/result.json)
derives all 87 names from the unchanged source, checks exact RUN/PASS counts and
zero skips/failures, and verifies 3,061 outer and 2,291 native source paths/hashes,
all six archives, terminated processes and fresh Docker/scratch absence. The
parent 180-second, Go 300-second and harness 360-second bounds are unchanged.
No native rerun or result rewrite was used to correct the wrapper inventory.

ADR-160's assembly and purpose-role qualification are now established at their
component boundaries. Complete original-artifact capture/case/native-download
composition and protected installed services remain next; public and Helm
runtime enablement remains disabled.

## Shared context services and passive SQL roles pass component checks

[ADR-160](decisions/160-public-context-service-assembly.md) now has an integrated
constructor for the shared browser/MCP investigation operations. It binds actual
submission and regional start, verified case navigation, native preparation and
the same active runtime for Stop. Separate preview and resolution credentials
complete the compiled purpose inventory without granting either capture or
custody writes. Existing ordinals and per-role connection limits are unchanged;
the two additional roles must be included in installation connection planning.

The [component gate](../test/results/public-context-assembly-component-1/result.json)
passes integration compilation, 300 exact top-level race tests (1,367 named
passes, no skips), full vet and SQL/Go-architecture/specification/architecture/
design checks. Exact 3,061 source/document paths and hashes, 31 archives, eleven
joined process groups and removed scratch are independently verified. These
tests establish constructor bindings, original identity/cancellation behavior,
purpose grants and unchanged surrounding use cases; they are not a positive
complete investigation journey.

Actual generated preview/resolution role authentication and SQL trigger effects
are next under the unchanged `initial-installation-integration` fixture. The
installed startup availability correction and combined regional capture-to-native
download composition remain in progress. No public or Helm runtime is enabled.

## First projection passes; the next phase still lacks sustained availability

The [tenth original installed scenario](../test/results/runtime-provider-owner-native-10/result.json)
passes activation, setup-free replay and administrator-removal rejection. The
first projection SQL call completes, including the previously failing final
SQL check, with zero limiter refusals across its six original clients. No final
SQL reason is logged because that call succeeds. The driver advances to thirteen
calls and one inspection, then stops at the next phase's
`projection.initial-native → native.source-branch → source.administrator → source.administrator-read`.
Its independent inspection fails at `projection.provider-observe`. The single
source-client live-context refusal in the whole 48.009749725-second phase is
outside SQL call one; aggregate counts do not identify its individual request.

The wrapper exits 1 after 570.329 seconds and Go after 492.510 seconds. Exact
2,508 outer and 2,311 native source inventories/hashes, seven archives, joined
processes, removed scratch and fresh owned Docker/Kind absence checks are
independently verified. The image is
`sha256:e306a8b91de4b0aaca11ecb4e3621f0f89a37e77556767f9e4b769bd462f9b8a`.
Original selection, flags, time bounds and rate limits are unchanged. This does
not reproduce the ninth run's deciding SQL failure and does not qualify startup.

Source review identifies a structural availability concern: projection phases
hold fleet SHARE locks while the observer requires UPDATE to publish positive
freshness, and the next phase immediately consumes the retained accepted
deadline. Separating freshness publication from restrictive authority fencing,
and reducing the remaining phase work, require review and regression evidence;
neither is implemented or established as the complete cause by this run. No
delay, replenished limiter, deadline extension or repeated uncertain effect is
introduced to obtain a pass. Continue this correction alongside the staged
shared public investigation assembly and missing preview/resolution role facets.

## Final projection SQL diagnostic passes component qualification

The [four-path diagnostic](../test/results/owner-projection-final-current-integration/integration.json)
now preserves the fixed reason from the existing `current-after-final` check.
It distinguishes the SQL prerequisite, context cancellation/deadline and final
local expiry without changing the query, short-circuit order, time samples,
original bounds or unavailable result. Unknown provider errors are neither
rendered nor unwrapped; the native fixture logs only the closed classifications.

The [component gate](../test/results/owner-projection-final-current-component-1/result.json)
passes integration compilation, all 109 PostgreSQL unit-test parents under the
race detector (685 named passes, no skips), full vet and Go/specification/
architecture/design checks. All 3,057 source/document paths and hashes, eleven
archives, joined process groups and removed scratch are independently verified.
The original installed scenario must now identify the deciding failure; this
diagnostic alone does not repair startup or enable public investigation.

## Projection completes the native graph, then fails the final SQL check

The [ninth original scenario](../test/results/runtime-provider-owner-native-9/result.json)
passes activation, setup-free replay and administrator-removal rejection. The
first projection SQL operation now completes its independent final native
graph. Its actual source-client wait count is 48 inside that SQL operation,
with zero refusals across all six original clients. It then refuses at
`current-after-final`. That compound checks SQL prerequisites, caller
cancellation and the original final deadline; its deciding reason is currently
normalized away. This is progress beyond the previous native guard-read failure,
not a passing installed startup or evidence of a specific expired interval.

The permitted separate inspection fails at
`projection.initial-native → native.source-branch → source.deployment-first-read`.
The driver stops after twelve calls and one inspection, preserving the original
attempt. Phase-wide cancelled-context refusal and expired transport-return
counts include that inspection and cannot be attributed to the earlier SQL call.

The wrapper exits 1 after 569.789 seconds and Go after 492.865 seconds. All 2,507
outer and 2,310 native source paths/hashes, seven archives, joined processes,
removed scratch and fresh owned Docker/Kind absence checks are independently
verified. The image is
`sha256:e92b2a3da24bc782122dcd6e21037fa89d54419c47803eeb86ab6be2f71a744a`.
Original selection, flags, deadlines and clients remain unchanged. Preserve the
actual deciding SQL prerequisite or cancellation/deadline reason before choosing
another correction; do not infer it from aggregate timing or repeat a spent
effect. Full-Go qualification of the final candidate and installed observation
and public investigation composition remain pending.

## Projection split passes component qualification

[ADR-159](decisions/159-owner-projection-split-preflight.md) completes the actual
first projection source bracket across the unchanged recovery bridge. The first
private role-journal read now follows complete native and accepted SQL checks
under that bridge. Its already-pinned UID remains mandatory; a valid same-UID
version may be selected at this later first read. All subsequent exact-version,
postclaim and independent final checks remain, along with original deadlines and
nonrefundable attempts. Other fresh owner paths retain ADR-158.

The [component gate](../test/results/owner-projection-split-component-2/result.json)
passes integration compilation, 99 top-level race tests in four bounded groups
(461 named passes, no skips), full vet and specification/architecture/design
checks. The actual fixture paths confirm thirteen fewer source-client requests:
82 for the parent projection and at most 87 for the tested ordinary phases,
with all six original clients retained. Twenty post-wait mutations deny before
private access or claims. Original deadline, replacement, postclaim spend,
copied/replayed prefix and joined cancellation cases also pass. These are
component results, not measured installed availability.

The first compile gate caught an unused import; its failed output is retained
and the import-only correction is archived with the
[integration record](../test/results/owner-projection-split-integration/integration.json).
The corrected run independently verifies all 3,056 source/document paths and
hashes, fourteen archives, seven joined process groups and removed scratch.
The new race group takes 288.253 seconds including compilation; the existing
projection, owner and source groups take 90.779, 121.389 and 93.292 seconds.
The ninth original installed-owner scenario is the next qualification. No rate,
deadline, permission, SQL schema or public-runtime enablement changed.

## Original projection reaches a final guard read and limiter refusal

The [eighth original scenario](../test/results/runtime-provider-owner-native-8/result.json)
passes activation, the corrected observation-account copy probe, setup-free
replay and administrator-removal rejection. Owner installation still fails at
the first projection SQL operation. Its retained deciding chain is
`projection.sql-operation → projection.final-native → native.source-branch → source.guards-final → source.guard-fleet → source.guard-policy-read`.
The same SQL call records one source-client limiter refusal with a live context;
none of its other five original client buckets refuses. These counters are
per-call evidence, not a per-request attribution. The separate permitted
inspection fails at `projection.outer-bridge`; the driver stops after twelve
calls and one inspection without replaying the original attempt.

The wrapper exits 1 after 551.701 seconds and Go after 493.428 seconds. All 2,504
outer and 2,307 native source paths/hashes, seven archive hashes, joined
processes, removed scratch and fresh owned Docker/Kind absence checks are
independently verified. The image is
`sha256:c468b7b650b548bd21d508ee7d959235dc7b88e17822d71399a50fa5e2139038`.
The original flags, operation deadlines and 20-QPS/burst-20 clients are unchanged.
This qualifies the earlier fixture identity correction and narrows the installed
availability defect; it does not qualify owner startup.

The [four-path projection correction](../test/results/owner-projection-split-integration/integration.json)
is now integrated for qualification. It completes the actual first native source
bracket across bridge acquisition and selects the already-pinned private role
journal only after complete native and accepted SQL checks under that bridge.
The postclaim and independent final graphs remain. Source-derived counts predict
thirteen fewer source-client API reads per projection; component counts and
installed availability still require execution. Original source/caller expiry,
request limits and uncertain-attempt spend are unchanged. The two independent
source reviews are not passing tests.

## Native rerun exposes a fixture identity error before owner startup

The [seventh original scenario](../test/results/runtime-provider-owner-native-7/result.json)
passes actual original activation, then fails the copy-closure marker assertion
before passive replay or owner startup. The fixture sends the marker's dry-run
UPDATE as an administrator. The bootstrap policy permits that probe only for the
original observation account; both it and the copy tombstone can deny the
administrator. Requiring the tombstone's reported cause on that request therefore
does not independently prove its enforcement. No owner projection or limiter
diagnostic is reached; this failure does not establish the earlier source cause.

The wrapper exits 1 after 327.926 seconds, Go after 274.095 seconds. All 2,504
outer and 2,307 native source paths/hashes, seven archives, terminal processes,
removed scratch and fresh owned Docker/Kind absence checks are independently
verified. Original flags and deadlines are unchanged. The built image is
`sha256:1af516de028e40784784be5e025fbe433b14c77ae18b509a83df576195df488a`.

The fixture correction uses the exact original account and immutable token
anchor to obtain a real observation-only token. A new client carries only that
token and API trust, verifies actual subject/UID and original marker UID, then
requires the same exact tombstone denial. No administrator credential is inherited
and no admission policy is relaxed. The original failing source is archived under
`test/results/bootstrap-copy-probe-fix/`. Independent review found no blocker.
The first compilation exposed three additional Helm fixture callers of the
shared helper; all five callers now pass their original connection. The
[corrected gate](../test/results/bootstrap-copy-probe-fix-component-2/result.json)
passes integration compilation, affected vet and canonical checks with unchanged
sources and removed scratch. This three-file fixture correction still requires
the eighth original native run; compilation is not enforcement qualification.

## Exact source and original limiter diagnostics pass component qualification

The [twelve-path diagnostic integration](../test/results/owner-source-limiter-diagnostics-integration/integration.json)
adds closed codes at the existing native source predicates and preserves their
original evaluation order, error classification and clock samples. Owner and
projection normalization clone only these codes, without raw causes or protected
values. The owned fixture observes each original standard 20-QPS/burst-20 bucket
through an exact once-only Wait delegate, recording context-state refusal counts
around the existing SQL call ordinal and phases. It creates no additional bucket,
native time sample, request, retry or token reservation.

Independent source reviews of both stages found no blocking defect. The
[component run](../test/results/owner-source-limiter-diagnostics-component-1/result.json)
passes integration compilation, all 41 source/shared-guard, 33 owner/projection
and four limiter top-level race tests (362 named passes), full vet and canonical
specification/architecture/design checks. No selected test is absent or skipped.
The six new source and four new limiter tests are included. All 2,810 source and
document paths/hashes, seven archives, terminal exit 0 and removed scratch are
verified. The source and owner race groups take 104.388 and 180.954 seconds.
The seventh unchanged native installation scenario is next. This is diagnostic
qualification, not a correction of the installed startup failure.

## Full fleet regression passes before the next source diagnostic

The [unchanged full fleet target](../test/results/fleet-regression-20261014-1/result.json)
passes all twelve required top-level scenarios and 130 named tests against
PostgreSQL, S3 and OpenBao. Go completes in 47.963 seconds and the wrapper exits
0 after 55.769 seconds. All 2,501 outer and 2,281 native source paths/hashes, five
archive hashes, joined execution, removed scratch and fresh positive Docker
cleanup checks are verified. Bootstrap/enrollment fixture inputs retain their
explicit synthetic authority scope; this regression does not qualify installed
owner startup. It precedes the finer source-reader diagnostic integration.

## Original projection fails inside its final native source check

The [sixth unchanged installation scenario](../test/results/runtime-provider-owner-native-6/result.json)
passes activation, setup-free replay, administrator-removal rejection, actual
worker launch and three advancing observations. Owner construction, original
selection and worker-caller verification pass again. The first projection SQL
operation reports `final-native`; its retained original error is
`projection.sql-operation → projection.final-native → native.source-branch`.
The separate inspection fails at `projection.outer-bridge`, before another
projection SQL call. Keeping both errors now prevents attributing the inspection
failure to the original operation.

The driver stops with twelve calls and one inspection after 49.310 seconds in
the four-role/projection sequence. The failing source branch contains multiple
API, protection, object-equality and original-deadline checks; its precise
predicate still requires diagnosis. The phase-wide HTTP header-return minimum
of 16.635 milliseconds does not establish that predicate or rule out a refusal
before HTTP dispatch. Do not infer expiry or select a timing correction from
those aggregate measurements.

The wrapper exits 1 after 573.230 seconds and Go exits 1 after 492.453 seconds.
All 2,501 outer and 2,304 native source paths/hashes, seven archive hashes,
joined processes, removed scratch and fresh positive Docker/Kind cleanup checks
are independently verified. The actual image is
`sha256:0263badce02fd2f9c36d77f170e516a248958a01d6ccab0d5654249027cfe892`.
The original four flags, fourteen-minute Go timeout, 720-second fixture interval,
five-second operation bounds and 20-QPS/burst-20 clients remain unchanged. The
original attempt and any acknowledged claim remain spent; no installed owner
startup or public investigation success is established.

## Original projection and inspection failures remain distinguishable

The [nine-path diagnostic integration](../test/results/owner-projection-diagnostics-integration/integration.json)
retains fixed original projection-stage/native-check codes through SQL error
normalization. The driver preserves the first failed Advance's codes when its
already-allowed independent Inspect also fails; only the inspection error remains
the unwrap and stop-disposition source. Invocation-owned slots contain no raw
error or protected value and cannot be changed through copied handles. The real
SQL adapter exposes fixed deciding-stage codes to the native fixture, which calls
the original operation exactly once. Queries, time samples, predicate order,
deadlines, claim/effect counts and error classifications remain unchanged.
The [component gate](../test/results/owner-projection-diagnostics-component-1/result.json)
passes integration compilation, 33 affected Kubernetes and all 106 PostgreSQL
top-level race tests (745 named passes), full vet and specification/architecture/
design checks. No selected test is missing or skipped. All 2,807 source/document
paths and hashes, six archive hashes, joined processes and removed scratch are
independently verified. The Kubernetes race phase takes 191.193 seconds. The
original native installation rerun above identifies the final native source
branch; these diagnostics do not repair or enable installed startup.

## Installed owner advances through selection, then stops at projection

The [fifth original native run](../test/results/runtime-provider-owner-native-5/result.json)
passes the previous selection failure with ADR-158. Original activation, passive
replay and administrator-removal rejection pass. The ordinary worker supplies
three advancing observations; owner construction completes in 2.416 seconds,
selection in 10.545 seconds across its separate original phases, and worker-caller
verification in 3.597 seconds. No native response lacks an original deadline or
returns after it. The source already has about one second of age when provider
setup begins; no fixture refresh is used.

The owner installation subsequently stops at `projection/original-result-unverified`
after twelve driver calls including one inspection. The four-role/projection
sequence takes 51.473 seconds. Its smallest measured remainder at HTTP
RoundTrip/header return is 4.645 milliseconds, before response-body processing.
This is a phase-wide minimum without an individual request identity; it does not
establish the deciding deadline, failed check or complete operation duration.
The current error is the normalized configuration
unavailable result. Projection/launch completion and sustained installed
availability remain unqualified. Inspect the exact original operation and
inspection failures without replaying any uncertain attempt.

The wrapper exits 1 after 553.787 seconds and Go exits 1 after 494.013 seconds.
All 2,497 outer and 2,300 native source hashes/file sets, seven archive hashes,
joined processes, removed scratch and fresh Docker/Kind absence checks are
independently verified. The built image is
`sha256:b402704b291ff0165415880cc831054b3a7a21270f79c9338298ffe8da6443fc`.
This run establishes progress beyond selection, not complete owner startup.

## Owner startup preflight precedes the retained recovery lock

[ADR-158](decisions/158-owner-startup-critical-sections.md) and the
[twenty-path integration](../test/results/owner-preflight-integration/integration.json)
move the first full native check of each fresh owner phase before the long SQL
bridge. The new source-bound bridge compares the exact independently observed
fleet identity and revision under the original recovery/activation locks. Current
native and accepted-configuration checks still precede effects, and the final
independent native bracket remains locked. Original deadlines, joined shutdown,
single-use attempts and the short SQL check before private-journal reads remain
binding. No migration, rate, pool or observation-cadence change is introduced.

The [component run](../test/results/owner-preflight-component-1/result.json) passes
integration compilation, 81 selected Kubernetes and 188 PostgreSQL/application
top-level race tests (1,391 named passes), full vet and canonical gates. The
Kubernetes portion takes 375.981 seconds, including the credential-reader test
that was active at the earlier aggregate timeout. All 2,801 source hashes/file
sets, six archives, joined processes and removed scratch are independently
verified. The native run above passes original selection but fails later at
projection. Eleven new real SQL modes additionally cover exact
post-lock source/expiry/recovery checks and owner reads/refreshes while a fleet
writer queues. The [native SQL run](../test/results/runtime-owner-bridge-sql-native-1/result.json)
passes all eleven legacy and eleven new owner modes plus the original parent in
34.870 seconds overall. The accepted reader and two owner-head refreshes succeed
while the bridge remains held; the queued fleet writer returns the exact existing
aborted-contention classification without changing its row or acknowledged audit.
All 2,497 outer and 2,277 native source hashes/file sets, five archive hashes,
removed scratch and fresh positive Docker cleanup checks are independently
verified. These are real SQL/S3/OpenBao component tests with synthetic initial
native authority, not the installed startup result.

The preceding [full Go baseline](../test/results/go-regression-20261013-1/result.json)
fails because the Kubernetes package reaches its fifteen-minute aggregate timeout.
The active top-level test had run for seventeen seconds and its current child
had just begun; this does not establish a deadlock or a full-suite pass. Other
package results are retained, and the architecture target was not reached.
All 2,491 source hashes/file sets, three archive hashes, joined processes and
removed scratch are independently verified. Qualify the affected components and
real SQL/startup next, then complete the broad gate with bounded full coverage.
The [gate correction](../test/results/go-shards-integration/integration.json)
preserves all packages and tests, race detection, count=1 and the fifteen-minute
timeout. It discovers Kubernetes tests, fuzz seeds and examples and runs exact
whole-parent groups of at most eighty sequentially, verifying actual run/result
sets. The [complete revised gate](../test/results/go-regression-sharded-20261014-1/result.json)
passes in 1,474.079 seconds: vet, four pure selection/parser tests, all other 52
packages and all 486 Kubernetes top-level names in seven groups. The independently
parsed Kubernetes events contain 2,675 named passes and one existing explicit
skip: `TestInitialRuntimeObjectRoundTripWithRealKubernetes` requires its separate
owned native harness. It is not newly qualified by this gate. Architecture checks
pass for 53 packages and 304 internal import edges. All 2,497 source paths/hashes,
three archive hashes, joined processes and removed scratch are independently
verified. This broad regression result precedes the diagnostic integration above.

## Installed startup refuses an expired fleet observation

The [fourth original installed-owner run](../test/results/runtime-provider-owner-native-4/result.json)
identifies the exact refusal at the accepted reader's original database clock:
`fleet-interval/expired-interval`. The second selection phase stops at its initial
native bracket. This is not a SQL query error, owner-configuration cutoff,
recovery flag or object-equality failure. Archived PostgreSQL logs also show
the ordinary fleet writer timing out on the recovery row held during startup.
The actual expired observation is established; the lock scheduling correction
and sustained startup availability still require qualification.

Original activation, passive command replay and administrator-removal rejection
pass. The configuration worker produces three advancing audited observations;
owner root construction passes in 1.631 seconds and SQL construction in 17.436
milliseconds. Selection fails in 6.527 seconds including its bounded inspection.
Every instrumented native response arrives within its original deadline, with
at least 310 milliseconds remaining. No original claim or deadline was replaced.

The wrapper exits 1 after 518.856 seconds and Go exits 1 after 434.008 seconds.
All 2,491 outer and 2,296 native source hashes and exact file sets, archive hashes,
joined processes, removed scratch and fresh Docker/Kind absence checks are
independently verified. The next correction must let independent observation
refresh coexist with startup while preserving semantic recovery fencing and
original operation deadlines. No public collection or installed workflow is
qualified by this diagnostic run.

## Accepted owner reads now identify their exact failed check

The [four-path diagnostic integration](../test/results/owner-accepted-read-diagnostics-integration.json)
adds fixed statement, predicate and failure-class enums from the original
accepted configuration read. It preserves the SQL statements, single database
clock sample, predicate order, locks, deadlines, retries and normalized errors.
Retryable failures deliberately discard detail that could otherwise be wrongly
attributed to a later transaction attempt. No raw driver message or row value is
rendered. The native fixture delegates once to the actual reader and logs only
these enums; production Kubernetes error normalization remains unchanged.

The [isolated component gate](../test/results/owner-accepted-read-diagnostics-package/checks/component-1/result.json)
passes integration compilation, all 101 top-level PostgreSQL adapter race tests
(636 named passes), affected vet and canonical gates. All 4,391 dependencies,
complete source/mirror sets, payloads and log hashes remain unchanged. Owned
process groups and scratch are absent. The original installed-owner rerun above
identifies fleet expiry; neither this diagnostic nor its tests repair startup.

## Finite owner audit snapshots have a qualified encryption codec

The [two-path codec integration](../test/results/owner-epoch-codec-integration.json)
adds purpose-bound sealing and exact original-snapshot verification for ADR156's
finite owner audit epochs. It enforces the original byte allowance and fixed
plaintext/envelope limits, uses one bounded key wrap, rejects malformed envelopes
before key access and preserves cancellation after key calls. Legacy configuration
audit bytes remain separate; this supplies no effect permit or current authority.

The [isolated component run](../test/results/owner-epoch-codec-package/checks/component-1/result.json)
passes compilation, all 42 top-level framed race tests (99 named passes), vet and
specification/architecture/design/import gates. All 4,387 dependency hashes,
complete source and mirror sets, payloads and log hashes are independently
verified. Owned process groups and scratch are absent; canonical validation
bytes are archived and restored. These tests use synthetic key providers.
Runtime selection, SQL effects, independent reserve/checkpoint production,
rollover and complete physical retirement remain unfinished.

## Installed owner failure is localized to accepted configuration read

The [third original installed-owner run](../test/results/runtime-provider-owner-native-3/result.json)
preserves the original selection, four flags, fourteen-minute aggregate timeout,
shared clients and individual operation deadlines. Activation, setup-free replay
and administrator-removal rejection pass. The actual configuration worker
produces three advancing audited observations. Owner root construction succeeds
in 1.622 seconds and SQL construction in 17.995 milliseconds.

Selection still fails after 6.536 seconds, now with the fixed diagnostic
`selection.phase-two: selection.initial-native: native.accepted-read`. The
failure is the accepted owner-configuration SQL read during the second phase's
initial native bracket; the precise SQL/recovery/freshness predicate is not yet
identified. It is not an original-object equality failure in this run. The
database log also records fleet observer lock timeouts, which are a correlation
to investigate, not proof of the deciding reader predicate. Original claims may
already exist and remain spent; no replacement or replay is permitted.

The wrapper and native test exit 1 after 489.993 and 434.404 seconds respectively.
All 2,487 outer and 2,292 native source hashes/file sets, archive hashes, joined
processes, removed scratch and fresh Docker/Kind absence checks are independently
verified. This remains an unresolved installed-startup failure. Trace the same
accepted-read decision and its current-source producer before changing freshness,
lock behavior or retry policy.

## Full custody regression passes after SQL and fixture corrections

The [second full custody run](../test/results/custody-regression-20261013-2/result.json)
passes the unchanged target: all eleven required top-level tests and 406 named
tests, including both capture-retirement cases and all five worker-identity
failures from the retained first run. Wrapper and native test exits are zero;
elapsed time is 711.527 seconds overall and 684.463 seconds in Go. The SQL58
deferred-validator correction and narrowly scoped fixture enrollment read are
now qualified against the real PostgreSQL/object-store fixture. The strengthened
role checks and stranded-retirement rejection also pass.

All 2,487 outer source hashes, the exact 2,269 native-source file set and the
archived outputs are independently verified. Owned processes have joined,
scratch is absent and fresh Docker container/network/volume/image queries find
no owned resources. The separate provider PKI and real-time retirement tests
remain outside this target. Installed owner startup, full fleet regression and
complete installed investigation remain unfinished; this result enables no
public collection. Earlier failure records below are historical evidence.

## Original owner selection has bounded diagnostic coverage

The [five-path integration](../test/results/owner-selection-diagnostics-integration.json)
adds fixed internal failure codes for the original selection phase, native reads,
accepted-source checks and exact identity comparisons. It preserves short-circuit
clock reads, one passive inspection after an uncertain result, original attempts
and error classification; driver values are never rendered. This identifies a
future native failure without relaxing the failed startup's checks.

The [component run](../test/results/owner-selection-diagnostics-package/component-1/result.json)
first reproduces the missing diagnostic against the original code, then passes
all 76 selected top-level race tests (376 named passes), compilation, vet and
canonical checks. All 4,378 dependencies and source sets remain unchanged; owned
process groups join and scratch is removed. The original installed-owner native
run has not yet been repeated, and its startup failure remains unresolved.

## Storage regression causes identified; qualification pending

The five worker failures in the retained full custody run come from the fixture
identity login missing SELECT on `download_worker_enrollment`, which the current
identity reader needs to verify the original enrollment audit. The fixture now
has that read permission alongside its existing certificate read. Tests require
the absent-enrollment result rather than accepting any error, and reject every
column write privilege plus no-op INSERT/UPDATE/DELETE. These two fixture changes
are integrated but have not yet passed native qualification.

The two capture-retirement failures expose SQL41's deferred validators running
as the restricted caller while reading shared lifecycle/history tables. PostgreSQL
records SQLSTATE 42501. The SQL58 correction keeps the original read-only
predicates, deferred timing and fixed relation resolution, using the existing
migration owner for those two checks. It grants no runtime shared-table access.
The migration and stronger role/stranded-transaction regressions passed independent
source review and are integrated for qualification;
the full custody gate remains failed until corrected qualification completes.

The [SQL58 component gate](../test/results/audit-retirement-validator-component-1/result.json)
passes integration compilation, the full Postgres adapter race package, affected
vet, sqlc comparison and canonical spec/architecture/design/import checks. Source
hashes and complete file sets stay unchanged; owned process groups join and
scratch is removed. [Integrated sources](../test/results/audit-retirement-validator-integration.json)
retain the seven-path correction and separately reviewed two-path worker fixture.
These component checks do not execute the real deferred SQL checks. The next
qualification is the unchanged full custody target, covering both corrected
paths, healthy/uncertain retirement and the remaining storage regressions.

## Finite owner audit epoch values pass component qualification

The [ADR156 value integration](../test/results/owner-audit-epoch-integration.json)
adds separate finite epoch/reserve/dependency values, conservative accounting and
current-versus-admitted reader ports. It preserves all selected legacy runtime
formats and introduces no schema, grant, installer selector or automatic rollover.

The [component run](../test/results/owner-audit-epoch-package/component-1/result.json)
passes 35 fleet-domain, 25 audit-domain and 84 application top-level race tests
(807 named passes), compilation, vet and canonical gates. A deliberately retained
unshipped draft reproduces its two elapsed-dependency boundary failures; that is
not an old-product defect claim. All 4,367 dependencies, payloads and complete
source/mirror sets remain unchanged, owned process groups join and scratch is
removed. Codec, SQL effects, protected reserve/restore checkpoint production,
rollover and physical retirement remain separate unfinished work.

## Full custody regression exposes retirement and worker-role gaps

The [full custody run](../test/results/custody-regression-20261013-1/result.json)
finishes with wrapper exit 1 after 681.892 seconds harness / 653.197 seconds Go.
It passes 396 named cases and ten of eleven required top-level cases. Seven leaves
fail: two capture-intent healthy-retirement cases (H0 and H2), and five download
worker cases whose identity read is denied access to `download_worker_enrollment`.
The precise retirement failure and correct purpose-specific permission correction
are under investigation; no permission, timeout or expected success was relaxed.
The separate provider-only and real-time retirement qualifications remain required.

All 2,476 outer source hashes and the exact 2,258 native-source file set remain
unchanged. Archived outputs, joined process, empty owned scratch and Docker
container/network/volume/image absence are independently verified. The narrow
objectstore completeness regression remains passed, but the whole custody gate
is failed. Diagnose and correct the actual failures, qualify those paths, then
repeat the full target before declaring it green.

## Shared deletion inventory rejects unknown completeness

The [six-path correction](../test/results/custody-inventory-completeness-integration.json)
requires an explicit completeness flag from all three object-store LIST APIs.
An omitted flag can no longer certify absence and allow a cleanup caller to
release its reservation. Malformed initial inventory causes no mutation;
malformed final inventory remains a failure after any completed exact effects.

The [component run](../test/results/custody-inventory-completeness-package/checks/component-1/result.json)
first reproduces all six failures against the original product, then passes the
full objectstore race suite: 34 top-level / 166 named cases. Compilation, vet,
Go architecture, spec, architecture and design checks pass. All 4,363 dependencies,
source sets and reviewed payloads stay unchanged; processes join and owned scratch
is removed. This is real TLS/AWS decoding component evidence; full real-service
custody and repository Go regression remain pending. Production writer closure
and complete physical audit retirement are separate unfinished work.

## Installed owner clears SQL prerequisite, then stops at original selection

The [second original installed-owner run](../test/results/runtime-provider-owner-native-2/result.json)
finishes with wrapper exit 1 after 477.299 seconds harness / 433.214 seconds Go.
Original activation and setup-free replay pass. The actual configuration worker
produces three advancing audited observations. The formerly failing SQL
constructor now succeeds in 18.393 milliseconds; the next original selection
fails after 6.540 seconds with `original-result-unverified`. The exact deciding
predicate is not yet known. Minimum remaining native-request time is about 321
milliseconds, with no observed request already expired on return; this does not
prove every later decision had a valid deadline. Selection claims may already
have been persisted and remain uncertain; the subsequent four-purpose identity,
projection and owner launch workflow does not run.

The administrator-removal negative passes. All 2,475 outer source hashes and the
exact 2,280 native-source file set remain unchanged; archive hashes and owned
service/scratch cleanup are independently verified. Docker label and exact Kind
node absence checks also pass. The original failed run remains preserved. The
next owner work identifies the actual selection predicate without widening
original deadlines, replacing the intended objects or repeating uncertain
creation. Shared object-store completeness hardening and full regression gates
remain separate pending work.

## Original cross-cluster observation path passes native qualification

The [sixth direct H/A/R run](../test/results/direct-observation-native-6/result.json)
returns terminal exit 0 in 227.398 seconds harness / 41.401 seconds Go. All four
original observation purposes pass, followed by rejection of a changed original
regional template. The operations complete in 2.398, 2.563, 2.502 and 2.780 seconds,
leaving 2.220–2.602 seconds of their original five-second deadlines. Original
holder/region identities and positive helper completion remain required.

The ordinary allocated NodePort now reaches the original TLS/service identity.
The new actual ignored-helper gate passes all seven required issuer cases before
helper build. The actual helper digest, all 2,312 runner sources, exact 2,280
harness sources and archive hashes are independently verified. Owned service
cleanup reports no failures; helper and outer build scratch are removed. Earlier
failed runs remain preserved. This is real Kubernetes/SQL/encrypted object-store/
TLS evidence with explicitly synthetic setup roots and fixture issuer; it does
not qualify an installed regional endpoint producer, actual issuer latency, full
background worker load, sustained availability or public collection. The original
installed owner startup and broader regression checks are next.

## Translated observation ports pass component qualification

The [ADR157 integration](../test/results/observation-dial-integration.json)
allows the installer-owned TCP connection port to differ from the original
service port. The original service identity, TLS roots/name/candidates and HTTP
authority remain fixed. No caller-selected endpoint, redirect or replay is added.

The [component result](../test/results/observation-dial-package/evidence/RESULT.json)
first reproduces the original constructor failure in all three client modes,
then passes five top-level / 44 named translated-port TLS race cases and fourteen
top-level / 45 named existing stream race cases. The explicit ignored-helper
gate passes two top-level / seven named issuer cases; six Python gate tests
reject missing, skipped, failed or unexpected results. Compilation, vet and
canonical gates pass. All 4,450 dependencies and both complete mirror file sets
remain unchanged, and owned scratch cleanup completes. The archive includes the
complete frozen source bundle. Native H/A/R observation, installed endpoint
production and full runtime availability remain separate qualification.

## Fleet contention and historical inventory pass scoped native checks

The [ADR155 integration](../test/results/fleet-persistence-contention-integration.json)
keeps an unchanged positive fleet observation at its original expiry after one
exact aborted SQL lock attempt. It never reports successful persistence or emits
a scheduling notice. Changed, expired, recovery-blocked and uncertain outcomes
retain fencing. The original shared recovery lock and all role grants remain.

The [component result](../test/results/fleet-persistence-contention-package/component-1/result.json)
reproduces both intended old-application failures, then passes 119 top-level /
605 named corrected race cases, compilation, vet and canonical gates. The
[real SQL run](../test/results/fleet-persistence-contention-package/native-1/result.json)
passes all ten selected children in 54.209 seconds harness / 17.808 seconds Go.
An unchanged conflict retains byte-identical SQL and the original deadline;
actual post-abort changes/recovery/expiry deny the special classification;
newer observations survive an older failure CAS. Dropping an actual successful
COMMIT acknowledgement still causes fencing. The changed database-incarnation
comparison is component evidence, not an actual restart experiment.

All 4,336 original dependencies, 2,253 native source hashes and exact source sets
remain unchanged, with joined cleanup and scratch removal. Full fleet/custody
regression and original installed owner startup remain separate checks.

The [six-path historical inventory integration](../test/results/owner-audit-inventory-native-integration.json)
adds the complete-LIST mismatch correction and the explicit native inspection
fixture. Its [final native run](../test/results/owner-audit-inventory-native-package/native-policy-real-2/result.json)
passes all five children and their parent in 39.738 seconds harness / 1.365
seconds Go. Bucket-scoped coarse List initially allows versions but denies
multipart listing, retaining five validated entries. An exact principal/bucket/
prefix multipart-list policy permits the same reader's next independently
bounded three-LIST operation. Other prefixes/buckets, part/body reads and
mutations remain denied. Independent reads confirm all seven actual version/
marker entries, their bytes, unfinished upload and part remain unchanged.

The [original List-only failure](../test/results/owner-audit-inventory-native-package/native-real-1/result.json)
and [test tracing constructor failure](../test/results/owner-audit-inventory-native-package/native-policy-real-1/result.json)
remain preserved. A new [real TLS constructor regression](../test/results/owner-audit-inventory-native-package/native-policy-component-2/result.json)
passes after moving tracing to the owned server; production transport checks
are unchanged. Earlier 11 top-level / 47 named inventory race cases retain their
exact production dependency provenance. The final 2,309 dependencies and 2,249
native source hashes remain stable; owned cleanup and scratch removal complete.
This qualifies bounded inspection, not full pagination, physical backing,
writer quiescence, retirement or public access. No runtime service is enabled.

## Regional native enrollment succeeds; backend construction still fails

The [fifth direct observation run](../test/results/direct-observation-native-5/result.json)
returns exit 1 after 128.686 seconds harness / 32.362 seconds Go. Original owner
enrollment succeeds in 2.930 seconds and original regional enrollment succeeds in
14.808 seconds after the fixture certificate-time correction. The next regional
backend constructor returns invalid in 137 microseconds; no observation case
runs. A later restarted regional process is separate failure evidence, and the
original remote helper Join requirement remains unsatisfied.

All 2,299 original runner source hashes, exact harness file set and archived
results are independently verified unchanged. Owned service cleanup and both
scratch removals complete. The actual compiled helper identity is retained in
the result. The next investigation is the original regional backend constructor;
no current route, installed runtime or real issuer latency is qualified.

## Regional native run remains blocked before observation requests

The [fourth direct observation run](../test/results/direct-observation-native-4/result.json)
fails in 153.707 seconds harness / 26.496 seconds Go. The original owner enrolls
in 2.931 seconds; the original regional enrollment returns denied after 8.916
seconds. No direct observation case runs. A later restarted process is separate
failure evidence and cannot stand in for the original. The positive original
helper Join check fails; local shutdown and container cleanup do not establish it.

All 2,298 runner source files, the exact harness source set and recorded hashes
remain unchanged. Owned service cleanup and both scratch removals complete.
The actual helper digest is recorded in the result. Setup/issuer authority is
still synthetic, and no installed runtime or real issuer latency is qualified.

The [actual-helper regression](../test/results/regional-fixture-issuer-time-integration.json)
now reproduces a fixture certificate-time mismatch for both client and server:
signing-time NotBefore is later than the original permit start, so the unchanged
verifier rejects a still-live permit. The two fixture issuers now use the original
CheckedAt, matching the owner fixture. With deliberately aged synthetic permits,
the original code fails both expected cases and the correction passes two
top-level / seven named race cases, helper build, integration compile and vet.
All 2,280 dependencies remain unchanged and scratch cleanup completes. This is
component evidence; native5 must determine whether it resolves the actual run.
No production verifier, proof, provider or reconciliation deadline is changed.

## Owner startup diagnostics and actual SQL contention reproduction

The [seven-path diagnostic change](../test/results/owner-sql-prerequisite-integration.json)
retains current SQL acceptance and reports fixed sanitized failure reasons from
the same deciding statement. Compilation, the original-code negative, four
top-level / 18 named focused race cases and vet pass. The first native invocation
omitted OpenBao and failed before either selected case; that setup failure is
preserved rather than counted as product evidence.

The [corrected native run](../test/results/owner-sql-prerequisite-package/prerequisite-2/result.json)
passes both cases in 43.011 seconds harness / 3.003 seconds Go. An independently
persisted observation expires at its original deadline and the constructor
reports source-current unavailable. The actual installer bridge holds a shared
lock during its callback; the scoped observer reaches its unchanged one-second
lock timeout, then its existing failure fence suspends trust after the callback
releases the lock. The constructor reports recovery unavailable with no role
claims or creations. The bridge remains open, proving the lock is per operation.

All 2,956 original dependencies and 2,246 native source hashes remain unchanged;
owned service cleanup and scratch removal complete. This demonstrates a concrete
contention failure mode, but cannot reconstruct the first installed run's failed
predicate. A narrow unchanged-observation contention fix is next; no recovery,
suspension, deadline, grant or runtime enablement change is included here.

## Historical owner audit inventory passes component checks

The [three-path inventory implementation](../test/results/owner-audit-inventory-integration.json)
reports actual versions, markers, unfinished uploads and current-key consistency
for one original owner configuration. It retains partial validated findings on
later failure and supports expired historical sources without treating them as
current authority. It performs no deletion or quota release.

The [component run](../test/results/owner-audit-inventory-package/result.json)
passes compilation, ten top-level / 42 named race cases, vet and Go architecture.
Four negatives reproduce findings loss against the prior unrun draft; they are
not evidence of an earlier production vulnerability. All 2,299 dependencies and
source mirrors remain unchanged; owned scratch is removed after joined exit.
Actual scoped SeaweedFS inventory, pagination, physical backing and retirement
remain pending.

The [ADR153 native helper selection](../test/results/regional-native-selection-integration.json)
is also integrated. The exact six build-ignore helper files compile and pass vet
with unchanged dependencies; the resulting helper was not executed by that
component check. The original three-party Kubernetes observation rerun is next.

## Regional enrollment operation passes the reproduced deadline regression

The [ADR153 implementation](../test/results/regional-lifecycle-integration.json)
adds an explicit per-enrollment/signing native operation while preserving general
attesters and the existing SQL/audit/provider effects. Fifteen tested paths are
integrated; no production selector, schema or role grant changes.

The [component qualification](../test/results/regional-lifecycle-package/evidence/RESULT.json)
first reproduces the old path's failure after valid admission and stored outcome:
two complete 54-observer/12-probe checks consume most of the original five seconds,
and the third fails before acceptance at 4.989 seconds. The corrected real HTTPS
reader performs 22/6, 12/0, 12/0 and 22/6 requests and completes in 2.542 seconds,
retaining 2.459 seconds. SQL, audit and recovery are synthetic in this comparison;
it does not qualify native Kubernetes/SQL/provider availability.

Whole-tree race compilation, 23 top-level / 179 named native-reader component
races, 57 top-level / 210 named application/domain races, affected vet and all
canonical gates pass. All 4,401 dependencies and source mirrors remain unchanged;
owned scratch is removed. Original proof dates, five-second operations,
thirty-second Reconcile, client rates, irreversible spend and joined Close remain
unchanged. The explicit original H/A/R fixture selection and real-service rerun
are next; its test issuer is a separately stated qualification limit.


## Original owner startup exposes a SQL provider-construction blocker

The [first actual owner continuation](../test/results/runtime-provider-owner-native-1/result.json)
fails in 470.467 seconds harness / 425.675 seconds Go. Original protected
activation, setup-free command replay and worker startup succeed. Three advancing
worker observations retain 3.556, 3.804 and 4.454 seconds after independently
verified encrypted versioned audit. The owner root constructor succeeds in
1.617 seconds with original request deadlines still live.

Construction of the owner's four-purpose SQL provider then returns unavailable
in 18.162 ms, before owner roles, launch or process identity. This is not a
measured timeout; the precise rejected current-SQL predicate still needs diagnosis.
No owner identity or observation-route success is claimed. Both source inventories
are unchanged, owned cleanup is complete and scratch is removed. The earlier
worker-only pass and this distinct owner failure remain separate evidence.

Next: diagnose the exact SQL construction prerequisite, and qualify ADR153's
explicit regional enrollment operation against the reproduced nested-read cost.
Product deadlines, connection limits and permissions remain unchanged.


## Current retention and full Kubernetes permissions regression pass

The [corrected native run](../test/results/retention-permission-native-1/result.json)
passes the unchanged full permissions harness in 111.396 seconds, including
actual retention guard enforcement, ordered policy changes and durable SQL/S3
reconciliation. Both observation and admission phases exit zero, every required
selected case passes, sources remain unchanged and owned cleanup is complete.
It retains the three successful storage/fleet phases from the prior matrix;
the earlier skipped context-fixture phase remains recorded as failed.

Migration 57 now has component, actual PostgreSQL/S3 and Kubernetes reconciliation
coverage. This is not full current custody or installed public-runtime qualification.
Next is the original protected owner process alongside the already qualified worker;
its receipt-gated regional observation backend remains separate unfinished work.


## Retention and bootstrap storage matrix: three passes, Kubernetes fixture selection corrected

The [native matrix](../test/results/retention-bootstrap-native-1/result.json)
passes actual SQL57 parser/planner/populated-index checks (101 named cases,
23.208 seconds harness), current retention history/effects/restrictive catch-up
(11 named cases, 12.350 seconds), and the full fleet suite (130 named cases,
55.360 seconds). This includes all eight bootstrap initial/replay/claim/signing
version-history cases after the explicit UUID fixture casts. Sources remained
unchanged and every owned service was removed.

At 4,096 synthetic rows per history, rebuilding the two partial invalid-receipt
indexes took 158.688 ms and 350.928 ms; smaller 1/256-row cases also passed.
These measurements are fixture results, not production migration latency bounds.

The fourth phase failed qualification: the context harness did not supply
ASSERVAT_PERMISSION_FIXTURE, so the selected Kubernetes retention test skipped.
Zero passing cases were correctly rejected; its source/cleanup evidence remains
preserved. The unchanged permissions harness supplies the required namespace,
structural CRDs, PostgreSQL and SeaweedFS. Its retention rerun is next; the prior
three passes do not need repetition for this wrapper correction.


## Original owner continuation passes component checks; native storage matrix next

The [owner continuation](../test/results/runtime-provider-owner-integration.json)
adds a separately selected real owner startup after the qualified running worker.
Nine selector checks, integration/command compilation, 26 top-level owner race
cases (73 named cases), affected vet and Go architecture checks pass. The final
cleanup-only correction also compiles and passes vet; all 2,938 dependencies
remained unchanged during qualification. Owner cleanup now follows the worker's
source-loss assertions so it cannot substitute a different failure trigger.

The new owner selector has a predeclared twelve-minute fixture/fourteen-minute
Go ceiling; the existing worker-only bounds and every product deadline remain
unchanged. Actual owner Pod/process identity, paired certificate audit and current
registry qualification remain unrun. No receipt-gated observation backend, public
investigation route or Helm runtime is enabled. The next sequential native matrix
covers migration 57 receipt predicates/indexes, historical retention effects,
the corrected fleet seeds and the actual Kubernetes retention reconciler.


## Bootstrap native issuance passes; two synthetic enrollment seeds need typed parameters

The [actual fleet report](../test/results/bootstrap-receipt-native-1/actual-report-interpretation.json)
records a failed first run (69.496 seconds harness / 34.076 seconds Go), with
2,227 unchanged sources and complete owned teardown. All six actual versioned
issuance/replay/claim history cases pass. Two synthetic enrollment fixtures fail
before signing because SQL infers the same parameter as both text and UUID.
The [two-line fixture correction](../test/results/bootstrap-receipt-fixture-uuid-casts/integration.json)
uses explicit UUID-to-text casts; product authority and deadlines are unchanged.
Its real rerun remains pending. The original wrapper also used the wrong report
prefix for fleet mode; its failed output is preserved alongside the actual
fleet logs and separate interpretation, rather than relabeled as a pass.


## Retention history and bootstrap receipts pass component regression gates

The [retention correction](../test/results/retention-receipt-versions-integration.json)
adds migration 57 with two fixed input-only invoker predicates and partial indexes.
Current readiness rejects any affected earlier or latest invalid checkpoint or
lifecycle receipt. Structural historical replay and restrictive catch-up remain
available. PUBLIC EXECUTE is explicit for these two table-free predicates; no
security-definer or role-specific write grant is added. The existing completion
history scan remains, so this is not constant-time readiness.

The [retention component run](../test/results/retention-receipt-versions-package/retention-component-2/result.json)
passes compilation, 213 top-level / 998 named race cases, vet, pinned generation
and SQL/spec/architecture/design gates. All 3,114 dependencies remain unchanged
and scratch is removed. Four original-code counterexamples are retained. The
first compile failure exposed a nullable generated Boolean; the corrected caller
explicitly rejects invalid/null results. Only the expected generated query file
changes, alongside nineteen authored paths and the guarded schema-head advance.
Actual PostgreSQL parser, planner, history and populated index-build checks remain
next; no production migration-time claim follows from these component results.

The [bootstrap correction](../test/results/bootstrap-receipt-versions-integration.json)
validates full issuance receipts at activation and retained minimized provenance
at claim/signing/activation. Historical provider-result accounting stays possible.
Its [component run](../test/results/bootstrap-receipt-versions-package/result.json)
passes seven-package compilation, 249 top-level / 1,204 named affected race cases,
vet and SQL/spec/architecture/design gates; two old-code assertions fail as intended.
All 4,393 dependencies remain unchanged, with clean scratch removal. This adds no
SQL query, schema, grant or authority interval. Actual versioned issuance/claim and
signing integrations remain required. Public investigation remains disabled.


## Direct helper inputs now arrive before startup; regional enrollment remains blocked

The [third owned multi-cluster run](../test/results/direct-observation-native-3/result.json)
returns 1 after 140.671 seconds harness / 22.522 seconds Go. All 2,238 source
hashes remain unchanged and owned Docker teardown completes. Required immutable
inputs arrive in less than one millisecond after process startup; the original
owner enrolls in approximately 2.93 seconds. The regional helper instead fails
its first enrollment after approximately 4.96 seconds. No direct observation
operation is issued, and the host cannot confirm the regional positive joined
marker; Docker teardown does not substitute for that marker.

Source tracing identifies four full regional attestations inside one original
five-second enrollment interval. Each stable attestation requires 54 observer
and 12 probe requests. At retained 20 QPS / burst 20, the observer refill floor
for 216 reads is 9.8 seconds. This is a source-derived request-count lower bound,
not measured API traffic. Enrollment/signing composition is under correction;
no deadline, client-rate limit or authorization requirement has been widened.


## Protected provider worker passes the original installed startup path

The [owned native run](../test/results/runtime-sustainability-native-1/result.json)
returns 0 after 527.344 seconds. All 2,238 source hashes remain unchanged and
owned teardown reports no failures. The actual compiled worker launches through
protected generated inputs and records three advancing SQL owner observations,
with an independently checked encrypted object version. Source loss preserves
history; removing its scheduling Lease leads to the original process exit.
The pass also includes passive replay and administrator-removal negatives.

This is short startup/source/audit qualification. It does not establish sustained
provider renewal, capacity/cleanup availability, full installation load or public
investigation. The [two-file direct-observation fixture correction](../test/results/direct-observation-projection-order-integration.json)
also passes integration race compilation, 33 named setup/identity assertions,
vet and Go architecture with all 2,252 dependencies unchanged. Required inputs
now precede container startup, retaining the same Pending Pod identity and
original two-minute setup deadline. Its multi-cluster native rerun is next.


## Worker provider coordination passes component gates; native startup is next

The [59-path runtime composition](../test/results/runtime-sustainability-integration.json)
keeps five finite FIFO purposes and one expensive operation active per worker.
The concrete SQL source observer supplies scheduling notices after acknowledged
observations; those notices grant no authority and cannot extend a selected
proof. Owner audit selects its immutable candidate after waiting and consumes
that same ticket once. Only this worker's retained observer changes to the
reviewed 40 QPS / burst 20; five other clients stay at 20/20. The per-process
budget is 140 QPS / burst 120, not an installation-wide measurement.

The [component evidence chain](../test/results/runtime-sustainability-package/runtime-sustainability-4/qualification-chain.json)
retains the intended early-selection counterexample, passed fleet/capacity,
Kubernetes contention, KMS and full bootstrap races, and the two intermediate
failures. A test-only clock correction preserves the original backoff; removing
a duplicate nil check preserves its predicate. The final run passes affected vet,
Go architecture and canonical spec/architecture/design gates. Root verifies all
59 bases/payloads, 4,197 dependencies and recorded logs before integration. Two
isolated comment-only edits accurately describe private constructor selection;
non-comment source lines are unchanged.

The private command now selects the complete protected provider layout. Helm and
public investigation remain disabled. The next owned native run exercises one
original launch, actual in-Pod provider/source/audit work and independent SQL/
encrypted-version witnesses. Capacity and cleanup projections remain pending in
that fixture; sustained active-capacity/cleanup availability is not yet qualified.


## Permission and publication receipt corrections pass combined component gates

The [41-path combined change](../test/results/permission-publication-audit-integration.json)
validates complete retained receipts at permission assignment/reset/initial,
automation-policy, capture publication, catalog and current download/key fences.
Deny assignments survive missing or foreign-root audit joins. Existing bounded
queries return the required receipt fields together, without per-assignment
lookups; historical progress and completed-effect accounting stay distinct.

The [combined component run](../test/results/permission-publication-audit-package/result.json)
passes seven-package compilation, 280 top-level / 1,185 named affected race cases,
vet, pinned SQL generation and spec/architecture/design/Go-architecture gates.
Four original permission/policy checks fail as intended, alongside the separately
retained twenty original publication assertions. Only the two expected generated
query files change. All 4,336 dependencies stay unchanged and scratch is removed.
The [real-service qualification](../test/results/permission-publication-native-1/result.json)
passes permission/policy scenarios (40.568 seconds harness) and the twelve
publication/download history cases (19.835 seconds harness). Both retain 2,184
unchanged source hashes and complete owned cleanup. Retained empty/null versions
deny current effects under the original admitted deadlines; exact restoration
permits the original operation and historical rows remain unchanged. These use
synthetic protected authority roots. Full shared regressions and retention history
with indexed readiness remain a separate continuation.


## Multi-cluster startup diagnostics identify delayed input projection

The [five-path diagnostic fixture](../test/results/direct-observation-diagnostic-integration.json)
passes standalone helper/integration compilation, fourteen named label/parity
checks, both vet selections and Go architecture. Root verifies all 2,210
component dependencies and exact payload/base hashes before integration. The
helper reports only fixed setup labels and bounded durations; no credential or
arbitrary error content is rendered.

The [second native run](../test/results/direct-observation-native-2/result.json)
fails after 190.483 seconds harness / 85.376 seconds Go, with all 2,196 sources
unchanged and owned Docker teardown complete. The original owner Pod is running
without restarts, but its optional immutable input projection has not arrived at
the fixture's sixty-second readiness deadline. HWORK and regional input reads
subsequently complete after approximately 72 and 78 seconds. Later enrollment
failures occur during cleanup and do not establish a separate enrollment defect.
No H/A/R operation is issued. Fixture setup sequencing remains under review;
operation, authority and client-rate limits are unchanged.

The separately staged runtime-coordination candidate passes fleet/capacity and
Kubernetes contention tests, then fails a healthy-provider hint test invoked
inside its original one-second anti-spin interval. That failure and all unrun
later gates are retained in its component report; a test-only clock correction
is staged. It is not integrated or qualified as installed runtime.


## Capture/publication receipt checks pass preliminary component tests

A separate source-staged correction validates complete retained capture and
verification receipts at current publication/catalog/download/key consumers,
while preserving structural historical progress. The existing catalog join
returns its two records together; no new query, grant, provider call or authority
interval is added. Permission-transaction fence changes will be composed before
integration, with source ownership kept explicit.

The [second preliminary run](../test/results/publication-audit-versions-preliminary/preliminary-2/result.json)
passes six-package compilation, 264 top-level / 1,074 named affected race cases
and vet. Old code fails twenty intended receipt assertions. SQL generation changes
only the expected publication query output; all 3,072 dependencies remain unchanged
and scratch is removed. The first attempt's compile errors are preserved separately.
This batch is not yet live; combined canonical gates and real-service qualification
remain required. Historical receipts are not rewritten or assigned invented versions.

## Direct multi-cluster fixture compiles; first native run stops at setup

The [thirteen-path test fixture](../test/results/direct-observation-native-fixture-integration.json)
compiles its actual standalone helper and integration package, passes DTO parity,
both vet selections, Go architecture and offline harness checks. All 2,198
component dependencies stay unchanged and build scratch is removed. Root checks
all payload/base/freeze hashes before integration. This adds no runtime selector.

The [first native run](../test/results/direct-observation-native-1/result.json)
fails during helper readiness, before the first H/A/R purpose is issued. Harness
elapsed time is 175.387 seconds, with 75.096 seconds reported by Go; all 2,196
native source hashes stay unchanged. Owned Docker teardown completes, but the
fixture cannot positively establish joined regional-helper shutdown. These are
separate outcomes. The original failure logs do not identify the waiting role or
setup phase; a narrow diagnostic follow-up is being staged without changing
client limits, operation bounds or retry behavior. No native transfer or installed
availability is qualified by this run.

## Current routing and download audit versions pass real-service tests

The [second native run](../test/results/current-audit-versions-native-2/result.json)
passes the targeted worker/native/window historical-receipt matrix (30.144 seconds
harness, 11.000 seconds reported by Go) and fleet/provider suite (55.305 seconds
harness, 47.495 seconds reported by Go). Both retain 2,168 unchanged source hashes
and complete owned cleanup. Actual empty/null retained receipts deny current
worker configuration, identity, signing, activation, locators, native reads and
connector registry use. Historical accounting and cancellation remain possible.
The fixtures still supply synthetic protected roots; public runtime stays disabled.

The [first native attempt](../test/results/current-audit-versions-native-1/result.json)
passes response-window cases but fails the longer history matrix after its ordinary
fixture's only five-second permission observation expires. The fixture correction
uses the existing joined background source owner and attributes child failures to
the child test. It changes no product authority interval, role or login deadline.
The original failure, exact source changes and subsequent passing result remain
in the integration package. Approximately 398 GiB is free after teardown.


The [43-path correction](../test/results/current-audit-versions-integration.json)
requires immutable original versions at current worker configuration, dispatch,
enrollment/certificate, connector activation/registry and native batch/window
consumption. Existing historical decoders still permit accounting for already
performed I/O and cancellation. Locator validation projects its already-joined
worker in the same query; certificate reads add one bounded enrollment lookup.
No source deadline, role grant, schema head or public runtime selector changes.

The [completed component run](../test/results/current-audit-versions-package/result.json)
passes compilation, 310 top-level / 1,347 named race cases, affected vet and
SQL/spec/architecture/design gates. Twenty old-predicate empty/null cases fail
as intended. Pinned sqlc changes only the expected locator query file. All 42
payload/base checks and 3,052 dependencies stay unchanged, and scratch is removed.
Root independently verifies those hashes after the power outage before integration.

The [first attempt](../test/results/current-audit-versions-package/interrupted-priority1-1/reboot-interruption.json)
lost power during compilation and remains unqualified. The replacement actually
finished before the second outage; its durable terminal result is retained.
Both JSONB and bytea fixture readbacks now compare the intended receipt fields
and retain the actual stored representation for unchanged-history checks. The
subsequent native result above qualifies that correction. Permission/retention
and other effect-audit families remain a separate continuation.

## Connector profile cleanup SQL correction passes focused qualification

The [focused original-schema run](../test/results/connector-profile-cleanup-alias-package/before/result.json)
reaches the actual cleanup UPDATE trigger under the original private cleanup
login and fails with SQLSTATE 42703: its outer audit variable `a` has no
`process_id` field. The runner predicted an ambiguous `a.id` error (42702), so
both its nonzero exit and the [actual-error interpretation](../test/results/connector-profile-cleanup-alias-package/before/interpretation.json)
are retained. All 2,158 sources remained unchanged and cleanup completed.

The [four-path correction](../test/results/connector-profile-cleanup-alias-integration.json)
adds migration 56, advances the embedded runtime head, and adds the focused
negative regression. Reversing only the nested alias change reconstructs SQL51's
original function byte-for-byte. No stored dates, permissions, reference checks
or accounting change. The [corrected checks](../test/results/connector-profile-cleanup-alias-checks/result.json)
pass deterministic SQL generation, focused embedded-schema races, canonical
spec/architecture/design/Go-architecture gates and the real connector identity/
fast-retirement matrix (62.439 seconds harness, 36.816 seconds reported by Go).
All 2,160 native source hashes remain unchanged, cleanup completes and owned
build scratch is removed. The original live profile now receives its intended
reference denial and remains byte-for-byte unchanged. Full positive connector
retirement remains a separate unrun real-time gate.

## Full custody passes after releasing completed fixture bursts

The [fourth native run](../test/results/session-capacity-native-4/result.json)
passes `make custody-integration`: 11 top-level / 336 named cases, 678.925 seconds
including harness work (653.396 seconds reported by Go). All 2,158 source hashes
remain unchanged and cleanup completes. Context takes 618.46 seconds and the
subsequent custody group 9.02 seconds within the separately bounded aggregate
budget. Before the owner race, total client connections fall from 41 to 35 and
idle permission connections from eight to two. The original 48-connection server,
sixteen-connection pools, eight-way race and operation deadlines remain unchanged.

Native content/resume/interruption, owner claims and Stop retirement now pass
together with SQL55 and the joined fixture pool release. This resolves the
reproduced full-suite exhaustion; earlier failing reports remain retained. The
suite still uses explicit synthetic protected roots and does not establish an
installed public investigation workflow. Approximately 398 GiB remains free.

## Configuration-worker contention remains a measured blocker

The [fourth component candidate](../test/results/configuration-runtime-admission-4-package/result.json)
compiles seven packages and passes six selectors, both controlled-before failure
assertions, and fleet/capacity races (119 top-level / 496 named cases). Kubernetes
races pass 29 top-level / 76 named cases but fail the persisted-source contention
case: wrap finishes in 2.858 seconds with 4.248 seconds originally available;
unwrap exhausts its already-selected 3.142-second source interval before provider
HTTP or SQL work. A fresh five-second pair passes. The shared native request graph
therefore still cannot establish installed availability under its original bounds.
KMS/bootstrap races, vet and Go architecture did not run after that failure.

All 53 payload/base checks and 2,196 dependencies remained unchanged; owned scratch
was removed. The candidate remains unintegrated. Source-only follow-up is examining
bounded admission before authority selection; it must not renew an admitted proof,
extend a deadline or treat a successful retry as sustained availability. The full
custody rerun with the independent pool correction passes as recorded above.

## Full custody reproduces retained connection bursts; fleet and initial pass

The [third native run](../test/results/session-capacity-native-3/result.json)
passes fleet (60.216 seconds, 116 named cases) and initial installation (47.3
seconds, 62 named cases), including both owner PKI profiles' twelve historical
empty/null-version denials and initial schema 55. Every phase retains 2,158
unchanged source hashes and completes cleanup. These are component fixtures
with synthetic protected roots, not an installed investigation workflow.

Full custody fails and reaches its 600-second aggregate alarm after the context
matrix completes in 589.63 seconds; the next custody test had run for only seven
seconds. PostgreSQL confirms connection exhaustion during native content, owner
claims and Stop retirement. Before the owner race, 41 client connections include
eight idle permission connections retained from the earlier publication burst;
the passing selected sequences had 38 and 39. Native exchange, control and
window cases pass with migration 55, but the whole suite remains failed.

The [three-path fixture correction](../test/results/publication-burst-pool-integration.json)
lets the outer fixture release its idle permission burst at the existing
publication/download boundary after child work has joined. It keeps the
48-connection server, sixteen-connection pools and eight-way race unchanged.
Only the full-suite process budget advances from 600 to 900 seconds; individual
authority/provider/retention bounds and other suite budgets remain unchanged.
Integration-package compilation and spec/architecture/design/Go-architecture
checks pass, with owned scratch removed. The corrected full native qualification
subsequently passes in the fourth-run checkpoint above.

## Native-key SQL alias correction follows real transfer failure

The [second session-capacity native run](../test/results/session-capacity-native-2/result.json)
passes the expanded publication/preparation/request-owner sequence (47.771 seconds),
then fails the transfer matrix (89.27 seconds). Native control races, admission
races and response-window accounting pass, but four transfer cases encounter
SQLSTATE 42702 in migration 54's native-key trigger: its PL/pgSQL session variable
and nested table alias both use `s`. Each phase retains 2,157 unchanged source
hashes and complete cleanup. Capture-intent and fleet phases did not run.

The [additive migration 55 correction](../test/results/native-key-alias-integration.json)
changes only that table alias and its generation/scope
references; migration 54, stored sessions, ACLs, accounting and all original
authority/deadline checks remain unchanged. The shared runtime schema head is
55. SQL generation, focused initial-schema/session race tests and canonical
spec/architecture/design/Go-architecture gates pass. Actual full-custody,
fleet and initial-service qualification follows in the newer checkpoint above;
that run reproduces the separate connection-exhaustion cause.

## Typed observation listener and regional metadata component

The [five-path addition](../test/results/observation-v2-listener-integration.json)
supplies the fixed v2 listener and concrete four-purpose metadata reader. The
listener retains separate finite-proof/standby slots and joined cancellation;
workload discovery brackets its namespace-name LIST with exact original UID
reads. Compile, focused listener/lifetime races (11 top-level / 40 named),
metadata races (five / 32), affected vet and Go architecture pass without skips.
All 2,179 dependencies and five payloads stayed unchanged, and owned scratch was
removed. No runtime selector or actual multi-cluster workflow is qualified.

## Session-capacity reads no longer require private helper privileges

The [real initial/custody run](../test/results/audit-create-native-1/result.json)
passes initial installation (53.2 seconds, 62 named cases), then fails full custody
(491.759 seconds Go / 509.64 seconds total). Both phases retain 2,150 unchanged
source hashes and complete cleanup; fleet did not run. SQL diagnostics identify
capture-intent fixture admission missing an existing production function grant,
plus native/content window queries executing SQL54 helpers whose private ACLs
exclude runtime roles. A separate request-owner race hits the 48-connection lab's
reserved-slot boundary; its cause is under investigation, without raising limits.

The [ten-path session projection correction](../test/results/session-capacity-reads-integration.json)
uses ordinary SELECT and the existing strict snapshot/digest decoder. Exact
session/account/allocation/root/deadline identities remain required; only original
policy dates/limits replace renewed parent values. Current counters, residual
retention and overdue state remain unchanged. No helper grants or SECURITY
DEFINER expansion is added. Compilation, focused races, vet, SQL generation and
spec/architecture/design gates pass; the new managed-session read-only-role
regression now passes the [real managed-capacity suite](../test/results/session-capacity-native-1/result.json)
(82.25 seconds, 95 named cases). Its runtime read role has no private-helper
execution privilege, and renewal retains the original session facts. The
publication/request-owner diagnostic pair also passes (34.116 seconds), without
reproducing the earlier full-suite exhaustion. Both phases retain 2,152 unchanged
source hashes and complete cleanup. About 402 GiB remains free after the runs.
The one-line capture fixture grant now matches production. The request-owner fixture records bounded
role/state/pool counts before obtaining race authority; this diagnostic itself
changes no connection limit or cleanup behavior.

## Required audit versions reach owner runtime composition

The [eighteen-path correction](../test/results/owner-audit-versions-integration.json)
selects required-version audit stores for the remaining owner/configuration and
cleanup runtime constructors. Current owner configuration, enrollment and
certificate receipts reject missing/null versions while preserving original
historical bytes and generic evidence-store behavior. Controlled old predicates
reproduce eight intended failures. Corrected owner races pass 12 top-level / 140
named cases, bootstrap races 20 / 91 and strict-storage races 2 / 18, without
skips; compilation and affected vet pass. All 2,990 dependencies stayed unchanged
and owned scratch was removed. Two temporary-mirror documentation failures
(missing progress, then its linked evidence files) remain recorded; the complete
live spec, architecture, design and Go-architecture gates subsequently pass.
Real historical SQL/PKI denial cases are added; full initial/custody/fleet service
qualification is next. Kubernetes loader qualification and installed runtime
availability remain separate unfinished work.

## Direct regional-observation holder component integrated

The [twenty-path component](../test/results/observation-direct-holder-integration.json)
removes the intermediate owner hop while retaining current native/SQL/TLS checks,
original deadlines, bounded discovery and one-use pending claims. A failed
candidate no longer cancels another already-running authenticated positive;
it still cannot report absence or start another candidate itself. The controlled
prior variant reproduces that failure. Four unchanged package race results from
v2 retain 100 top-level / 339 named passes; v3 Kubernetes races pass 16 top-level /
109 named cases, all without skips. Compile, affected vet and Go architecture
pass. V2's Kubernetes timeout remains recorded: its fake API waited for a server
cancellation notification without consuming the request body. The corrected
fixture joins the actual client before explicitly releasing its independently
owned handler; product deadlines and behavior are unchanged. All 2,162 v3
dependencies, payloads and reused evidence matched before integration, and scratch
was removed. Complete native multi-cluster availability and runtime selection
remain pending; request-count estimates are not measured performance.

## Initial audit history requires the original immutable version

The [five-path history correction](../test/results/initial-audit-history-version-integration.json)
closes a separate ADR-151 gap: new writes already required versions, but the
shared initial-receipt predicate still accepted old empty/null values at SQL
acknowledgement, activation, historical observation and runtime-bridge setup.
Those values now deny without changing persisted bytes. The controlled prior
predicate reproduces two direct and four historical acceptance failures;
corrected races pass 10 top-level / 66 named cases with no skips. Whole-repository
compilation and affected vet pass; all 3,025 dependencies stay unchanged and
scratch is removed. Two real-service regressions assert invalid receipt rejection
before SQL persistence and subsequent acknowledgement of the exact original
version. They are added but not yet native-qualified.

## Audit creation retains successful versions across existing writers

The [twenty-path extension](../test/results/audit-create-pinning-integration.json)
now applies exact acknowledged-version readback to the remaining reconciling
audit creators and download-window creation. Definite HTTP 412 retains existing
semantic reconciliation; unknown PUTs do not trigger GET, and Find remains
read-only. The original owner writer reproduces receipt substitution, and the
original window writer rejects a valid original after latest changes. Corrected
object/framing races pass 60 top-level / 185 named cases; audit-application races
pass 34 top-level / 75 named cases, with no skips. Whole-repository compilation
and affected vet pass. All 3,023 dependencies and twenty payloads stay unchanged;
owned scratch is removed. Native service qualification for this wider change
remains next; the previous five-path native results are not reused as its pass.

## Original configuration-worker caller provenance integrated

The [four-path caller producer](../test/results/owner-worker-caller-integration.json)
returns only public provenance derived from the original positive account,
Deployment, full template/image, owner selection and configuration launch.
Two genuine native brackets and two exact reads of each original journal/child
reject replacements and changed/expired final state; no transient Pod/ReplicaSet
identity or runtime authority is invented. Component compilation, seven caller
race tests (18 named entries) and three affected regressions (12 named entries)
pass. Both intended failing-before variants reproduce final-read defects. The
first vet run catches a test's deliberate mutex copy; the corrected reflection
fixture then passes its focused race, vet and Go architecture (53 packages,
302 edges). All 2,969 dependencies and retained prior results were checked before
integration. No installed runtime selector is enabled; actual owner provisioning
and complete native observation remain pending.

## Audit receipt pinning passes initial and retirement services

The [third retained native run](../test/results/audit-pinning-native-3/result.json)
passes the full initial-installation suite (47.061 seconds) against PostgreSQL,
S3 and OpenBao. Both selected operation-audit retirement cases also pass,
including finite accounts, retained history and uncertain writers. The combined
retirement command fails before download-stop setup: its legacy fixture role
lacks EXECUTE on migration 54's `capacity_managed_admission_until`. The PostgreSQL
log identifies that denial; it is not a stop-writer or receipt-verification result.

The [targeted fourth run](../test/results/audit-pinning-native-4/result.json)
passes download-stop retirement after the fixture receives the exact existing
production capture/storage function grant. It exits zero in 75.081 seconds with
2,128 unchanged source hashes and no cleanup failures. Each preceding native
phase also retains unchanged hashes and successful cleanup. Production grants,
deadlines and authority checks were unchanged. These results qualify the five-path
receipt correction against the selected real services; they do not qualify an
installed public download workflow or complete version retirement for every
other audit family.

Earlier [first](../test/results/audit-pinning-native-1/result.json) and
[second](../test/results/audit-pinning-native-2/result.json) initial-installation
failures remain retained. Their fixture corrections mirror the production
observer's column-level view-lock grant and separate the hub's exact credential
manifest from the installer's larger hub-plus-reconciler inventory. The fixture
continues to authenticate every installed role and rejects reconciler credentials
and the full installer inventory at the hub verifier; runtime permissions and
credential acceptance were not broadened.

## Known audit receipts select their exact immutable version

The [five-path readback correction](../test/results/audit-version-pinning-integration.json)
now pins successful initial audit writes, positive operation/download-stop writes
and retained deletion-certificate verification to the acknowledged version and
ETag. It verifies complete byte count and ciphertext digest before decoding.
The controlled prior writer reproduces both intended initial-version substitution
failures. Corrected object/framing races pass 57 top-level / 177 named entries;
installer races pass four top-level / 30 named entries, with no skips. Whole-repo
compilation and affected vet pass, all 3,018 source dependencies stay unchanged,
and owned build scratch is removed. HTTP 412 reconciliation, uncertain PUT spend,
writer completion and original deadlines retain their separate existing semantics.
This follow-up is not part of the preceding native bootstrap result; its subsequent
actual-service initial/retirement verification is recorded above.

## Required initial audit versions pass the original native bootstrap

The [fresh versioned-audit native run](../test/results/initial-versioned-audit-native-1/result.json)
completed with exit zero in 515.704 seconds, four named passing cases, all 2,142
source hashes unchanged and no cleanup failures. It executes the actual fresh
bootstrap v4 → preparation v2 → installer v2 chain against Kubernetes,
PostgreSQL, OpenBao and versioned object storage, requires a nonempty/non-null
initial audit receipt and reads that exact version. It also retains the original
four-command passive replay, nineteen-resource handover, scoped provider/SQL
worker-input production and administrator-removal rejection. The product binary
is `a349f23cdaa0dabd853a725739ee84f1916b80e450790a03b59cb6e70a9eb68c`, image
`sha256:519874283011c74c9b38f597e1683a8cfb4c30320d61e99bff956d8d36933c4a`.
Both runtime Deployments remain at zero replicas. Temporary node volume and build
scratch were removed; this does not qualify persistent power-loss behavior.

The preceding [combined live-source checks](../test/results/initial-owner-integration-1/result.json)
passed whole-repository compilation, 9 top-level / 28 named race interactions
with no skips, Go architecture, specification, architecture and design gates.
All 3,018 retained source hashes were unchanged. These results establish the
initial-version constructor/format change and input production. Full physical
version accounting/retirement, independently approved restart/restore, runtime
refresh/owner startup and public investigation remain pending. A separately staged
readback correction pins known successful PUT/retained receipts instead of
consulting the mutable latest-key pointer; it is not part of this native result.

## Initial audit versions and original owner selection integrated

The [33-path initial audit change](../test/results/initial-audit-version-integration.json)
now enforces [ADR-151](decisions/151-initial-audit-version-requirement.md): both
accepted active installer formats require a nonempty immutable audit version.
Fresh bootstrap v4 binds preparation services v2 and installer v2 before effects.
Original historical input bytes remain unchanged; missing/null versions deny
without a weaker constructor, repeated write or adoption of the latest object.
The TLS regression reproduces all four missing/null failures with the old
constructor; corrected tests pass 4 top-level / 30 named race entries, compilation,
vet, Go architecture and canonical specification. The earlier broad initial
suite passed 152 top-level / 703 named entries with one native-only skip; only
the constructor, its regression and native fixture changed afterward. Its
symlinked-embed mirror failure is retained; the corrected mirror uses real files.
Actual fresh-bootstrap version enforcement and full version retirement are still
pending native qualification.

The [21-path original owner selection](../test/results/owner-bootstrap-selection-integration.json)
allocates permission-root and logical peer identities once in the retained
resource journal and a fixed immutable public child. Generated owner inputs
require its original receipt and current native proof. Lost replies remain
lookup-only, selection creates no permission stream or peer authority, and no
runtime selector is enabled. Component races passed 27 top-level / 95 named
entries, plus compilation, vet and Go architecture. The corrected canonical
schema checks passed 121 schemas / 10,560 assertions, architecture 1,219 positive /
120 negative cases and 63 design screens. Original relative-reference and missing
mirror-link failures remain recorded. Real SQL4, owner startup and aggregate
shared-client availability remain unqualified.

All 54 payloads had their original bases and hashes checked before integration;
3,001 initial-audit dependencies, 2,951 owner-selection dependencies and 1,223
actual linked files matched. The pre-reboot unfinished runs have no retained
terminal verdict and are not counted as passing. Post-reboot qualification used
owned temporary build scratch and removed it after joining the processes.
Combined live-source checks and the sequential actual-service run follow this
checkpoint; component evidence does not enable a public debugging workflow.

## Pending observation receiver preserves one original operation

The [ten-path receiver integration](../test/results/observation-pending-receiver-integration.json)
passes compilation, vet, architecture and 81 top-level / 295 named race entries
with no skips and 2,082 unchanged dependencies. Actual HTTP/2 tests cover bounded
locator GET, one exact claim POST, all four framed ordinals and Receipt/EOF joins;
native and SQL authority remain synthetic. Pending reservations are retained
before output, unknown claims stay spent, and cancellation joins owned work.
This component does not select an installed route. A direct configuration-worker
to exact regional-stream holder path is under implementation to remove a redundant
owner hop while preserving the original caller and deadlines.

The [two-path live-channel deadline fix](../test/results/observation-channel-bounds-integration.json)
now immediately carries each shorter observed cutoff into the next candidate/SQL
read, metadata result and current-key lock wait. The original implementation
fails four intended regressions. The corrected checkpoint passes 44 top-level /
184 named race entries with zero skips, compilation, vet and Go architecture;
all 2,081 dependencies remain unchanged and build scratch is removed. An initial
compile failure from a local-name collision is retained separately. This closes
a component deadline gap; the pending locator/receiver and installed v2 route
remain separate work.

## Fresh provider pair passes the real bootstrap-to-input path

The [third native run](../test/results/provider-pair-native-3/result.json) returns
zero after owned cleanup: 411.662 seconds for the Go integration package,
602.932 seconds for setup/build/test/cleanup, four named PASS entries, all 2,116
source hashes unchanged and no cleanup failures. The actual product binary is
`af90f05efc810a51293a539c4b5590fbf8f0537fb37eba6f278fb0b113863c43`;
its exact built image runs the original protected activation. Owned build
scratch and the ephemeral node volume are removed.

The original four-command bootstrap and setup-free replay lead to the nineteen
inert resource receipts and retained guard handover. Actual upstream inspection,
source-scoped audit IAM, immutable version reads, cross-prefix/delete/versioning
denials, three original SQL roles and finite worker2 input publication all pass.
Role provisioning takes 16.806 seconds; the separate input driver takes 7.689
seconds across its bounded phases. All six original 20 QPS/burst20 clients remain
shared through the path. These total phase timings do not extend an individual
proof deadline. Both runtime Deployments remain at zero replicas.

This qualifies the named fresh bootstrap-to-input component. Worker launch and
provider refresh under sustained contention, owner input/startup, required
version enforcement for initial/recovery audit, full physical-copy retirement
and the installed investigation remain pending. Earlier setup failures remain
recorded below; no chart runtime enablement follows from this test.

The [isolated fixture diagnostic](../test/results/kind-startup-diagnostic-3/result.json)
starts the same pinned Kubernetes image in 31.155 seconds and passes `/readyz`,
using a dedicated bounded 3 GiB tmpfs volume for this disposable node's `/var`.
All 2,105 source hashes are unchanged and owned cluster/seed/volume cleanup
passes. The preceding ordinary-filesystem diagnostic reproduces containerd
threads blocked in `reserve_bytes.cold` for the entire 180-second startup limit;
host Btrfs metadata allocation is 98.2% used. An initial tmpfs attempt also failed
because Docker discarded its pre-start population; explicitly copying the exact
image's `/var` into the running seed fixes that fixture defect. All failures are
retained. The provider-pair fixture now uses the qualified ephemeral setup with
normal startup and product deadlines. This is not Kubernetes persistence or
product installation qualification; the subsequent native result is above.

The [three-path owner operation refinement](../test/results/owner-projection-identity-integration.json)
now rejects copied outer handles at all five native boundaries before touching
the original operation. The controlled original-boundary variant fails all five
intended assertions; corrected race tests pass five top-level/thirteen named
entries, including the composed projection/launch positive. Compilation and vet
also pass, all 2,593 dependency hashes remain unchanged and owned build scratch
is removed. This is component verification, not an installed runtime result.

The [second fresh provider-pair run](../test/results/provider-pair-native-2/result.json)
also stops before product tests: PostgreSQL becomes ready in 15.266 seconds,
but the owned Kind control plane never starts its API server during bootstrap.
Containerd records the four control-plane container creation requests without
completion before cleanup. The 183.223-second run preserves all 2,116 unchanged
source hashes, exact product image/binary identity and successful fixture and
build-scratch cleanup. This is a test-environment startup failure, not a product
qualification. The root cause and an independently healthy owned fixture are
were investigated before the passing third run above.

## Original launch phases and joined shutdown components

The [55-path continuation](../test/results/provider-launch-integration.json)
integrates the finite worker launch, owner role/projection/launch phases and
joined provider shutdown. The worker checkpoint passes 47 top-level/121 named
corrected race entries; its three controlled-before cases reproduce deadline
extension, uncertain receipt selection and detached shutdown. A separate copied
worker-wrapper regression fails before the fix and passes with exact wrapper
identity enforced. The owner checkpoint passes 27 top-level/48 named Kubernetes
component entries and five named PostgreSQL zero-handle checks. Its actual
PostgreSQL role flow and installed process remain unqualified. The analogous
owner wrapper identity refinement is qualified separately above.

The [combined check](../test/results/provider-launch-combined/result.json)
returns zero: native integration package compilation 14.960 seconds, selected
joined-shutdown/copy races 22.428 seconds and Go architecture/specification/design
gates 10.778 seconds, with unchanged sources and removed owned build scratch.
These tests do not run the native lab. Before its second run, review corrected
two unexecuted fixture defects: the audit Secret uses the declared configuration
credential filename, and the input constructor receives the actual completed
nineteen-resource snapshot retained before handover. Current phase2 authority
still comes from the operation's independent native reads.

The first fresh provider-pair native run stopped before cluster creation or Go
tests: owned PostgreSQL was still initializing after the fixture's short startup
poll. [Its failure record](../test/results/provider-pair-native-1/result.json)
preserves the actual binary identity, all 2,074 unchanged sources, successful
owned cleanup and removed build scratch. The new qualification mode now gives
fixture initialization a measured, bounded 90-second wait before any product
operation. No product proof, installation or SQL transaction deadline changes.
The original setup failure remains unqualified evidence; the second run is
recorded above.

## Fresh provider pair and actual framed observation components integrated

The [164-path integration](../test/results/provider-pair-framing-integration.json)
joins the provider-installed foundations, the qualified schema contracts and
[ADR-149](decisions/149-fresh-provider-installed-pair.md), the actual HTTP/2 v2
framing component, and the fresh original-bootstrap qualification fixture.
All 2,448 worker and 1,944 framed dependencies matched before integration.
The console-qualified owner selection schema supersedes the earlier permissive
copy; twelve other shared schemas match byte for byte.

The framed component passes 47 top-level/172 named race entries, compile, vet
and architecture checks. A forced non-UTC input first reproduced a timestamp
encoding failure; v2 writers now emit UTC while preserving the original instant
and deadline. Real mutual TLS/HTTP2 and joined closure are exercised, with
synthetic native/source/SQL authority. Locator lifetime and the installed route
remain separate unfinished composition.

The worker phase tests and controlled-before regression pass. A final reviewed
SQL correction narrows the context immediately when the final native observation
shortens the deadline; its affected packages compile and PostgreSQL vet passes.
That minimal follow-up runs no native test. The combined fresh native run is
next: original bootstrap and resource claims, actual named provider inspection,
scoped versioned audit storage, original SQL role production and finite worker
input acknowledgement. Worker launch, owner startup, initial/restore version
enforcement, complete physical-version retirement and the public investigation
workflow remain unqualified. No runtime enablement follows from this integration.

## Typed observation coordinator retains the original proof through completion

The [seven-path v2 coordinator](../test/results/observation-operation-coordinator-integration.json)
passes compilation, 35 top-level/154 named race entries, vet and Go architecture
checks. The four phases took 11.069, 15.861, 1.891 and 1.940 seconds respectively;
all 1,937 dependencies and the tested payloads remained unchanged. Its owned
native handle supplies one initial observation and one final observation. Final
facts are retained for current SQL/key checks through receipt completion, with
each shorter cutoff applied immediately to subsequent I/O. Cancellation and
closure join admitted work.

The first run failed because the new v2 verifier equated configuration-source
protection with the separate workload guard. Removing that invalid comparison
preserves independent checks of both controls; the regression explicitly uses
distinct digests. That failed run remains archived. Component tests use actual
TLS keys/exporters and closed codecs with synthetic native, SQL and terminal
ports. Actual HTTP/2 framing, holder/locator lifetime, installed selection and
the complete multi-cluster path are the next work; this is not a deployed route.

## Real SQL observation pairs reject changed authority

The [SQL49 operation regression](../test/results/observation-operation-sql-integration.json)
passes its owned PostgreSQL/S3 run: 14.596 seconds for the selected Go package,
73.332 seconds including harness setup/build/cleanup, all 1,956 source hashes
unchanged and no cleanup failures. Eight cases cover both original source pairs,
source changes after either SQL read, source revocation, recovery blocking,
database-incarnation changes, a shorter SQL cutoff and cancellation during an
observed database lock wait. The same scoped pool accepts a separate fresh
request after cancellation. The first pair remains incomplete; no final result
survives a failed second pair. Existing EXECUTE-only credentials gain no row-read
or source/recovery-write privilege.

The first run failed because the fixture activated only the client certificate;
SQL correctly requires both client and server certificates before a connector
process serves. The corrected fixture activates both and checks ordinary current
registration before the new operation. That initial failure is preserved.
Native source values, TLS correlation and initial authority are synthetic here;
this qualifies actual SQL consumption and fences, not the full installed route.
The framed conversation, installer and complete investigation remain active work.

The maintainer also explicitly accepted required versioned audit storage, without
an extra gateway service, including tracking and deleting every physical version.
The [evidence contract](../specs/evidence.md#req-evd-002--commit-protocol-and-partial-artifacts)
and [provider research](research/audit-storage-qualification.md) now record that
decision. Version-pinned reads, independently controlled retirement and complete
copy accounting remain required; acceptance does not enable an unqualified
runtime profile or resolve the earlier restart-read failure.

## Regional source and producer preserve one original operation

The [seven-path source/producer component](../test/results/observation-operation-source-integration.json)
retains one native operation across four numbered replies, current process keys,
the actual TLS exporter and both exact SQL registration results. Returning from
one frame does not cancel the owned stream; failed, changed or repeated phases
close it without renewing deadlines. Existing v1 formats and readers remain
unchanged. A real boundary test caught rounding of a large backing revision;
the new v2 codec now uses the existing integer-preserving closed codec.

The corrected checkpoint passes the focused integer regression, four-package
compilation/vet, 15 top-level/90 named race entries and Go architecture checks,
with all 1,929 dependencies unchanged. The initial test compile error and the
subsequent integer-encoding failure remain archived. Tests use real process keys
and TLS exporters with synthetic native/SQL values and a typed test exchange;
they do not yet exercise the actual v2 framed conversation. That channel,
coordinator, shared locator lifetime and complete installed routing remain active
implementation work. No new runtime profile is enabled.

## Actual native observation primitive passes consecutive requests

The [native primitive run](../test/results/owner-operation-native-integration.json)
returned 0 after complete owned cleanup. The selected Go package passed in
11.995 seconds (10.93 seconds for the test), with eight named PASS entries and
all 1,964 source hashes unchanged. Full harness setup/build/cleanup took
477.811 seconds; that duration is separate from measured request latency.

The original production-limited clients completed the first request in about
0.41 seconds and five immediately consecutive requests in about 1.40 seconds
each. Every request used 28 observer and six probe calls, including two expected
independent admission denials, within its original five-second interval. No
client/rate/bucket replacement or delay separates these operations. An actual
administrator change to the same Pod's annotations between the two native
boundaries correctly rejects final facts and permanently closes that operation.

This qualifies the native primitive on its owned reference fixture. It supplies
no process/TLS/SQL authority, normal background reconciler, full observation
conversation or installed investigation result. Those consumers and the fresh
installer remain the next work. The previous expensive nested receiver still
has its separately recorded expected-denial result; it has not been silently
replaced by this narrower success.

## Explicit observation consumers pass component checks

The [ten-path consumer checkpoint](../test/results/observation-operation-consumer-integration.json)
adds native-operation values, closed application ports and a separate SQL49
reader for actual numbered source values. The original SQL query, roles and
legacy source brackets remain unchanged. The second source pair must continue
the same original operation and reach final ordinal four; a first-pair registry
result cannot release metadata. Actual TLS/key checks and terminal delivery are
still separate required consumers.

Six-package compilation and vet pass; selected races pass 33 top-level/245 named
entries. Two architecture mirror failures are preserved: omitted embedded SQL,
then an overly broad directory exclusion. A corrected exact-path mirror passes
53-package/298-edge architecture checks with all 1,921 dependencies unchanged;
the unchanged compilation/race/vet evidence is reused explicitly. These are
component tests, including a synthetic fixed-query SQL seam, not native SQL or
an installed observation conversation.

The [one-file native primitive regression](../test/results/owner-operation-native-integration.json)
also compiles and passes vet; its subsequent native run passes as recorded above. It exercises
six consecutive operations through the same API clients and an actual Pod
mutation between native boundaries. Full v2 wire/channel lifetime, current
SQL/TLS composition, installer availability and complete investigation
qualification remain active work. Runtime selection stays disabled.

## Integrated repository checks pass; installed availability remains open

The [combined repository gate](../test/results/operation-and-shutdown-gates.json)
returned 0: full Go vet/race checks completed in 926.433 seconds, followed by
specification, architecture, Go dependency and interface-design checks in
10.410 seconds. All 2,354 tracked source hashes remained unchanged throughout.
This includes the owner/regional observation primitives, conservative legacy
shutdown and corrected scoped-audit cleanup policy. The fresh worker/owner v2
installer graph and observation consumers remain staged and are excluded.

[Complete-path availability](validation.md#complete-path-availability) is now an
explicit S-01/S-02 qualification requirement. Counted installed call graphs
exposed nested reads whose minimum API admission time already exceeds their
original five-second interval. The active redesign gives bounded operations
explicit ownership of their initial/final native checks and actual current
source reads. Staged lower request counts are design evidence until qualified
with the real shared clients, normal background activity and original deadlines.
No installed investigation success, public enablement or slice completion is
claimed by the repository gate. Continue through that composition and the native
installation/investigation qualification.

## Regional observation and legacy shutdown components pass

The [regional observation primitive](../test/results/regional-observation-operation-integration.json)
now performs two independent native checks and four actual protected source-value
reads. Its counted synthetic API uses 50 observer and 12 probe calls. All original
request, token, root and backing deadlines remain binding; changed or unavailable
inputs close the operation. A first fixture failed before admission because its
timestamp violated the existing microsecond contract. After correcting that
fixture, two failing-before regressions exposed omitted backing validity checks
in the new component. Both checks are restored. Compilation, 14 top-level/120
named race entries, vet and Go architecture pass with 1,805 unchanged dependencies.
This is actual TLS around a synthetic API, not qualified native routing.

The separate [legacy shutdown correction](../test/results/owner-deployment-join-integration.json)
waits for runtime readiness work, route registration/delivery and admitted SQL
wrapper calls before closing shared pools. Shutdown admits no new wrapper work;
an unissued release remains occupied until its original lease expires. The
original deployment defects reproduce, as does controlled removal of the new
router wait. Compilation, 33 top-level/110 named race entries and vet pass with
2,091 unchanged dependencies. No native SQL/API test or fresh runtime profile is
claimed by this component. Full routing and installation remain next; the combined repository gate
subsequently passed as recorded above.

## Native observation operation primitive passes component checks

The [four-path observation component](../test/results/owner-observation-operation-integration.json)
owns the original native observations and performs one independent final native
check before returning them. Cancellation joins admitted reads; final mutation,
unknown results and expired original deadlines close the operation. The focused
race selection passes 12 top-level tests/148 named entries, with compile, vet
and Go architecture checks passing and all 1,802 dependency hashes unchanged.
Actual TLS surrounds a synthetic Kubernetes API: counted calls are 14 observer
plus three probe calls per boundary for one Pod, or 17 plus three for two Pods.
These are component counts, not installed latency results. Full hub/regional
composition, fresh source reads and the original five-second native workflow
remain pending. No runtime route is selected by this component.

## Narrow cleanup policy resolves the multipart permission failure

The [corrected scoped-storage run](../test/results/scoped-audit-retirement.log)
passes all ten named entries, including complete version/marker retirement and
multipart inventory/abort. Retirement now has no base Write permission; an
independently administered policy allows only exact-prefix deletion and abort.
It cannot upload a part, create an upload or ordinary object, read/delete a
foreign object, or change bucket policies/versioning. Runtime writer restrictions
remain in force. Actual test time is 5.28 seconds; the
[environment report](../test/results/scoped-audit-retirement-environment.json)
records 1,934 unchanged sources and complete cleanup. Compile and vet passed
before the [two-path fixture correction](../test/results/scoped-audit-retirement-policy-integration.json).

The pinned provider treats abort as a legacy PutObject policy match, so the old
explicit write denial also denied cleanup. The narrower recipe and primary
source evidence are recorded in [storage qualification](research/audit-storage-qualification.md).
This resolves the permission failure below; it does not qualify installed
provisioning, SQL backing, writer quiescence or restart/restore. No runtime
profile is enabled.

### Preserved failed multipart run

The [multipart follow-up](../test/results/scoped-audit-multipart-test.log)
retains all earlier runtime audit/version/permission passes but fails independent
`AbortMultipartUpload` with a real backend 403. Listing the exact incomplete
upload succeeds and retirement is correctly denied adding a part. That complete
test fails, so its subsequent version-retirement phase
does not run. The [report](../test/results/scoped-audit-multipart-environment.json)
records 1,931 unchanged sources and complete lab cleanup. The first successful
version/marker run is preserved separately below. The correction above retains
the failed assertion and does not give cleanup administrator access.

## Scoped immutable-audit permissions and independent retirement pass

The [owned scoped-storage run](../test/results/scoped-audit-storage-first/scoped-audit-storage.log) passes
the actual SDK, adapter-facing TLS and encrypted owner-configuration writer
with separate configuration, owner and retirement credentials. Eight concurrent
configuration writes converge on one version. The original committed version
remains readable after a runtime write replaces the latest pointer; malformed
latest content cannot be reconciled. Both runtime identities are denied deletion
and bucket-policy/versioning changes. Cross-service and anonymous reads fail.
Independent retirement inventories four bounded pages, deletes five versions
including an unacknowledged null copy plus one deletion marker, and verifies
complete absence. The [environment report](../test/results/scoped-audit-storage-first/scoped-audit-storage-environment.json)
records the actual 2.15-second test, 1,931 unchanged sources and clean teardown.

`make audit-storage-integration` reproduces this exact owned fixture. Ordinary
custody runs retain their existing credentials and selection; the explicit mode
cannot combine with another selection or inherit an environment opt-in.
Compilation and vet passed before integration. Storage administration and
wrapping keys are synthetic, and the TLS fixture retains its private plaintext
backend hop. SQL backing, uncertain-copy accounting, multipart cleanup,
restart/restore and the complete installed worker/owner path remain unqualified
by this run. No public or Helm runtime is enabled. Continue the complete fresh
profile and the operation-owned native routing proof together.

## Native routing deadline failure reproduced; versioned audit adapter qualified

The [owned native receiver test](../test/results/regional-observation-native-cost-test.log)
reproduces the availability defect with actual Kubernetes, SQL and mutual TLS.
Its first complete pair proof takes 3.715 seconds and 94 observer/24 probe API
requests. Repeating that proof returns unavailable after another 1.199 seconds:
4.914 seconds total, 118 observer/30 probe requests, with only 81 milliseconds
of the original query remaining. The named test passes because it expects this
failure; **routing itself does not succeed**. Expected admission-denial probes
account for the HTTP failure counters. SQL pool acquisitions are not statement
or lock counts. The [terminal report](../test/results/regional-observation-native-cost-environment.json)
records 1,946 unchanged source hashes and complete cleanup. Initial roots,
source/registration facts and wrapping keys remain explicit fixture authority.
The next change must address hub and regional proof amplification together,
retain the original deadline/rate bounds and prove the complete exchange.

The [explicit versioned audit adapter](../test/results/versioned-audit-store-integration.json)
rejects empty/null version IDs in write receipts, audit reconciliation and pinned
reads. Its affected object-store race suite passes 61 top-level tests/225 named
entries and vet. The [actual S3/SDK/encrypted-audit test](../test/results/versioned-audit-native-test.log)
passes eight concurrent writers resolving to one receipt, preserved original
bytes after latest-key replacement, rejected malformed reconciliation and
unversioned/suspended writes, and deletion of all four versions including
unacknowledged null copies. The test itself takes 0.32 seconds; its harness
records 1,927 unchanged sources and no cleanup failures. Credentials and wrapping
authority remain synthetic; backend IAM, accounting/recovery and installation
are not qualified by this test.

The working implementation choice is immutable versions intrinsic to the fresh
worker2/owner2 pair, with version-specific GET permissions and no automatic
fallback. The optional maintainer preference question was unanswered; this is
an implementation assumption, **not user-confirmed approval**. The source graph
still requires its complete installation qualification before enablement.

The [installed reader copy correction](../test/results/configuration-worker-reader-copy-integration.json)
also reproduces caller mutation before the fix, then passes its three reader
race tests/14 named entries and vet. It changes no profile or authority scope.

## Further input ownership fixes pass; routing availability needs correction

The [three-path projection correction and regression](../test/results/projection-input-ownership-integration.json)
prevents callers changing retained nested scope and prevents material generation
mutating its input. All three original regressions fail before the fix; the
corrected selection passes 28 top-level tests/264 named PASS entries and vet.
The [seven-file follow-up](../test/results/legacy-input-ownership-integration.json)
fixes the same defect in bootstrap construction, bootstrap state creation,
public observation, bridge administration and cleanup projection construction.
All five original defects reproduce; 47 top-level tests/253 named race entries
and vet pass with 2,078 unchanged dependencies. These changes preserve existing
layouts, deadlines and authority checks.

The [regional forwarding component](../test/results/regional-observation-forwarder-integration.json)
passes 152 named race entries using real TLS/HTTP2 with synthetic authority
ports. Its concrete native composition is **not available within its deadline**:
expanding the measured port calls requires at least 304 requests on the shared
20-QPS/burst-20 guard/workload client. Even without server latency, this requires
at least 14.2 seconds, exceeding the original five-second bound. This is a
source-derived lower bound, not a native timing measurement. A native
counterexample and operation-scoped proof composition are next; no listener or
installed runtime selection, rate increase or deadline extension is enabled.

[Storage probes three and four](research/audit-storage-qualification.md)
preserve concurrent-create and exact-version-deletion results plus a restart
readiness failure. The later run passes its version checks; it does not erase
the earlier 500 response or qualify production storage/accounting/recovery.

## Worker shutdown joins are corrected; storage permissions are under qualification

The [five-path shutdown correction](../test/results/configuration-worker-join-integration.json)
reproduces both previous defects before the fix: cancelled configuration observers
could outlive Run, and externally initiated Close could release provider resources
before its active leader call finished. The corrected full application/fleet and
bootstrap race suites pass 147 top-level tests/675 named PASS entries, followed by
vet. All 1,920 dependencies remained unchanged. No provider, request or Lease
expiry was extended, and this changes no installation layout.

[Storage permission research](research/audit-storage-qualification.md) now records
a measured gap in the pinned SeaweedFS create-only policy condition. Ordinary
conditional operations and prefix/deletion denials work, but the policy also
rejects correctly conditional writes. A separate diagnostic confirms that
version-addressed records survive replacement attempts and that writer deletion
and versioning suspension are denied. These are candidate semantics, not a
qualified installed audit store. The maintainer's choice of versioned storage
versus an enforcement gateway is pending; no unsafe runtime fallback is enabled.


## Provider setup and complete candidate reads pass actual-service retries

The [fresh provider run](../test/results/owner-provider-setup-native-retry-result.json)
passes all seven child scenarios and their parent, including sixteen read-only
setup checks, denial of inspection-token encryption, changed-purpose rejection,
generated pool-scoped certificate roles and maintained Transit/PKI effects.
Go execution took 11.561 seconds; all 1,933 source hashes stayed unchanged and
cleanup completed without failures. This supersedes the pending retry below,
while preserving its first failed run. Privileged provider setup and accepted
installation/recovery/signing facts remain synthetic; installed startup and
elapsed credential rollover remain unqualified.

The [candidate SQL/S3 fixture](../test/results/regional-observation-candidates-native-result.json)
also passes, in 3.853 seconds of Go execution with 1,917 unchanged source hashes
and clean teardown. It retains all seventeen same-Pod process candidates,
denies eighteen at the configured bound, preserves legacy overflow denial,
excludes retired entries and rejects original source expiry/configuration
changes. Initial source/recovery/native proof inputs remain synthetic.
[Specification and architecture gates](../test/results/provider-correction-candidates-contracts.json)
pass in 7.189 seconds. Work continues on the complete fresh installation profile
and regional forwarding; no public or Helm runtime is enabled.


## Provider compatibility corrections and complete observation candidates

The first [setup native run](../test/results/owner-provider-setup-native.log)
failed at the authentication-mount read. All 1,918 source hashes stayed unchanged
and the owned lab cleaned up. Isolated pinned OpenBao diagnostics show that
`sys/auth/<mount>` requires more than the named read ACL; the equivalent
`sys/mounts/auth/<mount>` works with the intended read-only credential. The
[archived diagnostics](../test/results/owner-provider-setup-diagnostics/archive.json)
also establish the exact returned role fields. Generated PKI roles now explicitly
forbid caller-supplied not-before and constrain not-after to the existing
21-minute provider ceiling (the runtime certificate periods remain unchanged).
Actual scoped signing accepts 20m30s and rejects 22m and supplied not-before.
Global authentication mount TTLs are not changed.

The [seven-path correction](../test/results/owner-provider-setup-correction-integration.json)
passes compilation, provider-configuration and selected owner-provider races,
and vet. Its full-input binding preserves exact integer generations above 2^53;
the targeted regression first failed and then passed. Actual public provider
read shapes are retained as test inputs. The complete Kubernetes/provider retry
remains pending; diagnostics do not qualify installed operation.

The [complete candidate component](../test/results/regional-observation-candidates-integration.json)
passes SQL generation, seven-package compilation/vet, Go architecture and
185 named race entries. Explicitly opted observation pools use the separate
bounded complete SQL candidate reader and one complete Ready endpoint scan;
omitted configuration and context-start retain their original fixed-16 reader.
Both meaningful before regressions are preserved. The real SQL fixture and
multi-owner forwarding are not yet qualified. No public or Helm runtime is enabled.


## Provider setup reader and regional receiver pass component checks

The [provider setup component](../test/results/owner-provider-setup-component-integration.json)
passes affected compilation, all provider-configuration races, selected owner
provider races and vet. Its read-only client verifies sixteen named setup
objects through pinned TLS, preserves one original at-most-five-second interval,
and returns an opaque check bound to the complete original public input, pool
and roots. Denials include changed policy, unsafe Transit settings, expanded
certificate identity/usage, redirects, response limits, expiry and joined closure.
Real OpenBao response-shape and generated PKI-role qualification is the next run;
synthetic HTTPS component tests do not establish that compatibility. No installed
profile or public serving is enabled.

The [regional receiver](../test/results/regional-observation-routing-receiver-integration.json)
passes 90 named race entries, compilation, vet and Go architecture. The separate
[configuration-worker component](../test/results/configuration-provider-component-integration.json)
passes 44 top-level tests/266 PASS entries, compilation and vet. Those packages
provide the closed receiver, pure two-purpose provider recipe and fixed worker
shape; actual installed selection and end-to-end availability remain pending.


## Leased provider effects pass real Kubernetes/OpenBao checks

The [extended owned-provider run](../test/results/owner-provider-leased-effects-native-check.log)
passes all seven child scenarios and their parent in 11.468 seconds of Go
execution, with 1,889 unchanged source hashes and no cleanup failures. The new
child exercises the maintained Transit binding roundtrip, both actual verified
PKI certificate responses and joined credential retirement through the new
leased clients. Independent provider lookups reject all four retired tokens.
Existing audience/policy, original-Pod deletion, reviewer rotation and recreated
account tests continue to pass.

Provider setup is privileged fixture work; installation/current-source/recovery
and signing-permit facts remain explicitly synthetic. This does not qualify the
installed supervisor, elapsed token rollover or production provider setup. The
[joint specification/architecture checks](../test/results/routing-effects-integrated-contracts.json)
also pass in 7.676 seconds. Work continues on the genuine pre-launch configuration
input producer, the coherent fresh worker/owner v2 profile and regional routing.

## Full Go gate passes; routing and leased effects are integrated

The [full Go retry](../test/results/projection-owner-lifetime-full-go-result.json)
passes the schema prerequisites, vet and complete repository race suite in
875.144 seconds. Kubernetes completes in 856.445 seconds; all 2,013 source hashes
remain unchanged. Native tests requiring owned fixtures skip in this gate. The
earlier failed full run and focused fixture failures remain recorded below.

The [routing contract integration](../test/results/regional-observation-routing-contract-integration.json)
passes compilation, 154 named race entries, vet and Go architecture with 1,894
unchanged dependencies. It preserves exact uint64 sequence values, original
request bytes and all existing proof ordinals. This provides typed locator/claim
values, not an installed receiving or forwarding route.

The [leased provider effects](../test/results/owner-provider-effects-integration.json)
pass compilation, 28 selected top-level race tests and vet with 1,984 unchanged
dependencies. The fixed four-purpose clients reuse existing Transit and issuer
codecs, reject foreign paths before credential borrowing, and do not authenticate
or replay signing from the effect path. Their current-proof inputs remain
synthetic in these tests. The [native extension](../test/results/owner-provider-effects-native-component-integration.json)
compiles and passes vet; its subsequent real-provider result is recorded above. Fresh
installation input production and the shared worker/owner v2 composition remain
in progress. Public serving and the Helm runtime remain disabled.

## Projection timing and provider lifetime corrections pass component tests

The [eleven-path projection integration](../test/results/public-projection-enforcement-integration.json)
removes repeated operation-local enforcement traversals while retaining the
original deadline, default 20-QPS limiter and five explicit current-authority
boundaries. The measured regression fails before the correction and passes
afterward in 3,006 milliseconds of its original 3,550-millisecond interval.
Nine top-level tests/27 PASS entries and vet pass, including changed permissions,
unknown writes, expiry, cancellation and permanent failure. The original namespace
fixture UID correction is included. All 2,600 dependencies stayed unchanged.
Two subsequent static mirror attempts failed because their copies omitted link
targets; their actual failures are archived. The subsequent
[live specification and architecture checks](../test/results/projection-owner-lifetime-contracts.json)
pass in 7.152 seconds. The full Go gate subsequently passes as recorded above;
native installed publication is still unqualified.

The [six-path provider lifetime integration](../test/results/owner-provider-lifetime-integration.json)
passes compilation, 25 selected top-level race tests and vet with 1,976 unchanged
dependencies. It serializes each of four fixed credential owners, bounds failure
backoff and current/draining credentials, preserves admitted effect deadlines
through response closure, and joins control calls and outstanding borrows on
shutdown. Native provider tests were explicitly skipped in this component run;
the separate real-provider qualification below remains narrower than deployed
supervisor qualification. No runtime selector or public listener is enabled.

## Regional receiving listener passes bounded socket checks

The [five-path listener integration](../test/results/regional-observation-listener-integration.json)
passes compilation, 24 named race entries and vet. Seven new regional listener
tests and seventeen existing observation entries pass in 9.455 seconds of Go
execution; all 1,884 dependencies remain unchanged. Actual loopback TLS/HTTP2
checks cover standby beyond five seconds, separate proof capacity, original
accept/parent deadlines, required peer certificates, terminal EOF and joined
shutdown. Source authority is synthetic. Runtime selection, cross-owner
forwarding and installed two-cluster qualification remain pending.

## Standard provider authentication passes real Kubernetes/OpenBao checks

The [owned provider qualification](../test/results/owner-provider-auth-native-check.log)
exits 0 with all six child scenarios and their parent passing in 11.568 seconds
of Go execution. All 1,872 source hashes remain unchanged; cleanup reports no
failures. The actual provider accepts the four generated login/renewal profiles,
permits each first Transit/PKI effect, and denies other purposes and token
creation. Wrong audiences and additional policies are rejected. After observed
original-Pod deletion, old-token renewal fails while a new Pod-bound token on
the same service account can authenticate. Reviewer rotation succeeds; a
recreated service account cannot replace the configured original UID.

These are real TokenReview/provider observations with privileged fixture setup.
They do not qualify installed owner authority, elapsed 600-second token expiry,
kubelet rotation or the pending four-purpose credential supervisor. No runtime
selector or Helm workload is enabled. The provider qualification uses a closed,
single-cluster harness selection whose compile/vet and selector checks are
[recorded separately](../test/results/owner-provider-native-component-integration.json).

The separate projection timing diagnostic confirms that nested proof traversals
exhaust the original verified interval: 86 HTTP requests spend 46 milliseconds
in transport but complete after the remaining 3,551 milliseconds under the
unchanged 20-QPS limiter. The immutable Secret exists, but its receipt is not
acknowledged. The correction above retains original deadlines and explicit checks
around writes while removing redundant operation-local proof traversal. The full
Go gate remains open until the integrated retry completes.

## Provider control and regional holder pass; full Go gate remains open

The [regional holder integration](../test/results/regional-observation-holder-integration.json)
adds the bounded receiving handler, one-use local stream ownership, current
same-channel coordinator and scoped SQL49 reader. Compilation, 111 selected race
entries, vet and Go architecture pass; all 1,866 dependencies stayed unchanged.
Actual loopback HTTP/2 and mutual TLS still use synthetic source/registry facts.
The installed listener, exact-owner forwarding and two-cluster availability have
not been qualified.

The [private provider control integration](../test/results/owner-provider-control-integration.json)
passes compilation, 65 selected race entries and vet with 1,956 unchanged
dependencies. It retains the original credential/body deadlines, disallows
transparent effect replay, and authenticates HTTPS against the configured roots.
A controlled reversal of the new TLS-dialer restriction reproduced disclosure
to the test endpoint; this is not a claim about a previously deployed defect.
Actual Kubernetes/OpenBao authentication and the four-purpose runtime supervisor
remain separate work. No provider selector is enabled.

The [configuration generator correction](../test/results/capacity-configuration-probe-integration.json)
now preserves the original installed capacity probe and rejects an unsupported
start-admission branch instead of silently changing the generated guard. Both
regressions reproduced before the correction; five tests/25 PASS entries and vet
pass afterward, including unchanged legacy omission. All 2,579 dependencies
remain unchanged. The first build was interrupted by filesystem allocation
failure before tests started; its record is retained beside the successful retry.

The [full Go gate](../test/results/capacity-owner-provider-full-go-result.json)
exited 2 after 848 seconds with unchanged sources. Five public-role tests failed
in a shared fixture that reused the bootstrap namespace UID for runtime. A
staged test-only correction reproduces that failure before the change and lets
the complete role-claim loop pass afterward. It also exposes a separate failure
in projection publication; that failure is under investigation. The focused
group additionally reached its three-minute runner limit, so neither that group
nor the full gate is reported as passing. Production freshness and request-rate
limits remain unchanged. Public serving and the Helm runtime remain disabled.

## Capacity owner reads and updated resource layout pass native checks

The [full native capacity SQL matrix](../test/results/capacity-local-owner-native-check.log)
passes 95 entries in 75.544 seconds of Go execution. The new generated role70
reads exact current owner candidates and activated leaves, denies unrelated
owner writes, rejects a replaced source, and retains its original 400-millisecond
deadline while waiting on a locked owner row. Role71 remains denied owner reads.
The existing encrypted context publication and original download session still
pass. All 1,838 source hashes remain unchanged and cleanup reports no failures.
Kubernetes source/owner proof and the initial CA in this SQL fixture are
explicitly synthetic; this does not qualify installed owner routing.

The [updated Kubernetes resource round-trip](../test/results/capacity-owner-resource-roundtrip-native-check.log)
passes both layouts and all nineteen generated resources per layout, including
the installed capacity observer/probe RBAC. The children take 9.80 and 10.74
seconds; total Go execution is 21.585 seconds. All 1,854 source hashes remain
unchanged and cleanup reports no failures. Both Deployments remain at zero;
this verifies API admission/defaulting/readback, not active worker startup.

The [integrated static gates](../test/results/capacity-owner-provider-integrated-contracts.log)
pass SQL generation, Go architecture, 114 schemas/10,396 specification assertions
and 1,218 positive/120 negative design cases. The full repository Go race gate
is next. Provider login/lease lifecycle, the regional stream holder and actual
projection-to-worker composition remain in progress; public serving stays disabled.

## Installed capacity inputs and provider recipes pass component checks

The [33-path capacity integration](../test/results/capacity-local-owner-integration.json)
adds receipt-bound original owner inputs, the protected capacity projection,
current installed owner client, exact role70 reads and fresh worker RBAC. Full
contracts/bootstrap races pass 490 entries; corrected Kubernetes races pass 222
and SQL-role races pass 12. Five-package compilation and vet pass. The first
Kubernetes run exposed two fixture defects: an unchanged negative digest and a
nil receipt dereference in the fake API. Their exact test-only corrections and
the failed run remain archived. All 2,687 dependencies stayed unchanged. The new
actual role70 registry/denial/lock cases are compiled but have not run yet.

The [eight-path provider/composed-projection integration](../test/results/owner-provider-recipe-composed-integration.json)
passes compilation, six provider recipe tests, the composed interrupted-installation
race and vet, with all 1,926 dependencies unchanged. The production projection
and launch code preserves lookup-only handling after unknown replies and passive
replay after confirmed launch. This test supplies synthetic enforcement, SQL and
provider inputs; it does not run an owner Pod or authenticate to OpenBao.

[ADR-147](decisions/147-standard-owner-provider-authentication.md) selects standard
bounded Kubernetes authentication with four fixed purposes. Its public profile
remains standalone until the actual credential lifecycle and installed selection
are implemented together. Next are integrated contract checks, the complete
native capacity SQL matrix, fresh resource round-trip and the full Go gate.
Provider lifecycle and regional holder/routing continue separately. No installed
developer workflow or public runtime is declared ready.

## Concrete regional stream passes component checks

The [seven-path stream component](../test/results/regional-observation-stream-integration.json)
passes compilation, 62 named race cases, vet and Go architecture (1.659,
8.519, 0.407 and 1.509 seconds). All 1,684 dependencies, payloads, original
path states and source-file inventory remain unchanged. Tests use actual
loopback TLS 1.3/HTTP/2 with explicit synthetic native source/registry facts.
They cover selected peer rejection, setup/Hello cancellation, joined proof/body
work, retained slots, failed-phase non-replay and missing/extra terminal EOF.

The regional client now owns its actual stream and proof channel through final
closure. Holder/listener/routing and installed two-cluster availability remain
pending; no public listener is enabled. Frozen source-time documentation and
results remain archived; the separate documentation status correction reports
the component evidence without treating it as native deployment qualification.

## Fresh installed-owner bootstrap guard handover passes

The [full fresh bootstrap run](../test/results/installed-owner-bootstrap-bridge-native-check.log)
passes all four selected entries. The actual four-command Restricted bootstrap
and original compiled activation complete, setup-free replay passes, and the
fresh installed-owner layout completes its runtime-resource/guard bridge in
88.16 seconds. Administrator removal is detected without recreation. Total
Go execution is 388.313 seconds, with all 1,821 source hashes unchanged and
no cleanup failures. The original compiled image digest and detailed assertions
remain in the [test log](../test/results/installed-owner-bootstrap-bridge-native.log).

This run selects the new layout before the first original journal claim; it
does not adopt or rewrite a completed legacy installation. It retains the
actual unknown-create/CAS, passive history, current protection, recovery and
controller cleanup checks. Its separately supplied provider roots remain fixture
inputs. It does not start the owner service, produce ongoing provider credentials
or qualify an installed developer workflow.

Next are the concrete regional HTTP/2 stream, capacity worker's installed owner
client and standard bounded provider authentication. Their isolated source
packages are being reviewed and tested; public runtime stays disabled.

## Fresh resource layouts and early coverage pass native checks

The [real API round-trip](../test/results/owner-fresh-layout-roundtrip-native-check.log)
passes both legacy and installed-owner layouts: nineteen actual generated
resources each, zero replicas, API defaulting and exact readback. The two children
take 9.82 and 11.41 seconds; total Go execution is 22.280 seconds. All 1,821
source hashes remain unchanged and cleanup reports no failures. This qualifies
the fresh resource layout, not installed owner execution or provider production.

The [full PostgreSQL capacity matrix](../test/results/capacity-processing-coverage-native-check.log)
passes 87 entries in 73.917 seconds of Go execution. The three added cases reach
the actual purpose15 and purpose40 coverage gates: uncovered retention is
rejected, all listed budget/audit/lineage charges stay unchanged, and an original
400-millisecond caller expires while waiting for permission serialization.
The original supported request still completes encrypted publication and its
download session. All 1,805 source hashes remain unchanged and cleanup reports
no failures. Synthetic human/source/bootstrap inputs remain explicit.

The [integrated static gates](../test/results/owner-input-processing-contracts.log)
pass SQL generation (47 files), Go dependency checks (53 packages/297 edges),
10,374 specification assertions and 1,218 positive/120 negative design cases.
This resolves the isolated mirror's missing-evidence link failure without
changing a gate. The full fresh bootstrap-to-runtime guard bridge is next;
provider lifecycle, regional streaming and the installed public workflow remain
unfinished.

## Original installation inputs and early retention coverage integrated

The [eight-path original-input change](../test/results/owner-original-input-integration.json)
rejects changed original endpoints, roots, guard pins and workload templates
before new owner projection or launch effects. The new constructor regression
fails before the correction; six-package compilation, targeted races and vet
pass, with all 1,906 dependency hashes unchanged. Two compiled native fixtures
now distinguish the fresh installed-owner layout from the legacy layout; neither
new native branch has run yet.

The [twenty-path coverage change](../test/results/processing-coverage-admission-integration.json)
adds a current retention-coverage check before preview and admission. Actual
SQL admission repeats it before charging resources; known insufficient coverage
has a shared browser/MCP explanation that preserves uncertainty about earlier
same-key submissions. Full capture/presentation/bootstrap races, focused SQL
predicate/role tests, integration compilation, vet and both architecture checks
pass. The staged specification gate fails because its isolated mirror omits
linked historical test evidence; the integrated specification gate remains next.
All 3,260 dependencies stayed unchanged. The new real SQL coverage/no-charge
cases are compiled but unrun. The production public constructor still needs its
existing purpose15 reader; no fixture supplies installed authority.

Next are integrated contract gates, the actual API round-trip of both original
layouts, the new SQL coverage cases and the full fresh installation bridge.
Provider credential lifecycle and regional stream/routing composition continue
separately. Public runtime remains disabled.

## Eight native owner-role cases pass

The [actual owner-role SQL matrix](../test/results/owner-identity-roles-native-matrix-check.log)
passes all eight selected children (3.63 seconds for the test; Go 4.684 seconds).
It uses real PostgreSQL, S3 and OpenBao and independently audited initial
activation for each fixture scope. Four-purpose role creation, SCRAM login,
exact direct/ambient privileges, connection ceilings, runtime-administrator
denial, unknown claims, lost completion and original root/recovery checks after
blocking locks pass. All 1,795 source hashes remain unchanged and cleanup reports
no failures. The private Kubernetes root, accepted owner source and admission
facts in this SQL fixture remain synthetic; this is not installed owner startup.

Next are complete original-input binding, native qualification of the fresh
nineteen-resource layout, bounded provider-material production and regional
stream/routing composition. The early retention-coverage check is separately
staged. Public runtime remains disabled until the complete workflow qualifies.

## Owner root fixture passes; shared digest respects the application boundary

The [corrected owner-root fixture](../test/results/owner-identity-root-fixtures-integration.json)
passes six-package compilation, actual private-root races and vet (18.535,
36.669 and 2.301 seconds). All 1,906 dependencies and four test-only payloads
remain unchanged. Current enforcement, ordered claims/completions, lost committed
CAS and wrong-version/kind rejection are exercised with explicitly synthetic
API and accepted-source facts. The integrated eight-case native SQL hook has
compiled but has not yet run. Provider-material production, full original-input
validation and installed layout/launch qualification remain pending.

The [first combined static gate](../test/results/regional-observation-owner-fixes-contracts.log)
passes SQL generation and rejects the new domain hashing imports. The
[seven-path correction](../test/results/regional-observation-digest-layer-integration.json)
moves the unchanged deterministic digest to the existing C-04 application
package. The architecture gate is unchanged. A first correction fails compilation
because of an import-alias shadow; the corrected version passes architecture,
wire parity/channel races and vet (2.634, 8.856 and 3.551 seconds), with all 1,833
dependencies unchanged. The [combined contract gates](../test/results/regional-observation-owner-root-contracts.log)
now pass: 47 SQL-generated files, 53 Go packages/297 import edges, 112 schemas,
10,366 specification assertions and the architecture catalog. The native SQL
role matrix remains next; this does not enable public serving.

## Native capacity guard passes; regional conversation foundations integrated

The [corrected real Kubernetes capacity-probe case](../test/results/owner-capacity-probe-native-rv-corrected-check.log)
passes in 8.00 seconds (Go 9.059 seconds), with 1,786 unchanged source hashes and
no cleanup failures. It verifies the exact dry-run capacity branch, persistent
and differently scoped denials, and the independent capacity guard with both
policies installed. Its permissive fixture CRDs do not qualify the production
CRD schema or an installed worker. The earlier failed case remains recorded.

The [regional conversation foundation](../test/results/regional-observation-foundations-integration.json)
adds fresh process-owned proof replies, exact installed workload checks, closed
framing/order, bounded channel state and unchanged request-digest bytes.
Six-package compilation and vet pass; focused races execute five packages with
252 passing entries. All 1,808 dependency hashes and 25 payload/base identities
remain unchanged. Native attestation still checks both original source reads;
the private key snapshot removes redundant local registry recursion without
supplying activation authority. Concrete streaming, holder routing and installed
two-cluster availability remain pending.

The [four installation corrections](../test/results/owner-installed-probe-template-fixes-integration.json)
retain the required third processing-source probe and explicit existing bounded
eviction tolerations in the fresh original template. Their named regressions
fail before and pass after the corrections; broader existing initial-runtime,
installed-owner and identity tests pass. The full producer-6 run still fails in
its new private-root fixture, which returns an unversioned Secret unlike the
real API. That failed package is preserved; its remaining four paths are not
integrated. A fixture-only response correction, complete original-input checks,
native scoped-role checks and the fresh installed-layout test remain next.
No public runtime, complete investigation workflow or implementation slice is
declared ready.

## SQL54 native matrix passes; installed guard qualification continues

The [next actual PostgreSQL matrix](../test/results/capacity-production-native-lineage-fixed-check.log)
passes: 84 passing entries, 73.657 seconds of Go execution, 1,770 unchanged source
hashes and no cleanup failures. It covers the separate purpose roles, three
root/workload phases, lost-reply recovery, managed capture intent/publication,
original download-session allocation, retained spend, expiry and atomic renewal.
Capture admission plus encrypted intent acknowledgement takes 197 ms with 4,786 ms
of the original interval remaining. All actual publication-lineage predicates
pass. The [fixture correction](../test/results/capacity-lineage-fixture-integration.json)
selects 20-second retention and a one-second deletion budget before policy
acceptance, within its existing 60-second backing; no SQL threshold or authority
interval was expanded. Longer product retention needs sufficient prepaid backing
and an early preview/admission check, still being implemented. This component
pass does not establish continuous replenishment or installed multi-cluster work.

The [original capacity-probe component](../test/results/owner-capacity-probe-integration.json)
retains the exact original worker account/UID throughout the guard and activation
contracts. Affected compilation, focused races and vet pass; SQL generation,
Go/specification/architecture gates pass with 10,354 specification assertions.
The [owned two-case Kubernetes run](../test/results/owner-capacity-probe-and-endpoints-native-check.log)
returns exit 1. The existing owner endpoint case passes in 87.46 seconds, including
the explicit three-port profile, pre-Ready identity and actual provider/TLS paths.
The new capacity-probe case fails at its fixture administrator's stale policy
resourceVersion after a status update. All 1,785 hashes remain unchanged and
cleanup is complete. The [fixture correction](../test/results/owner-capacity-native-fixture-integration.json)
requires the unchanged original policy UID/spec/generation and uses its current
resourceVersion; compile and vet pass, native rerun pending. A separately found
third-probe constructor omission and original-template tolerations are still
staged. No public runtime or installed developer workflow is enabled.

## Capacity admission advances; publication remains blocked

The [four-path SQL54 timestamp correction](../test/results/capacity-policy-time-correction-integration.json)
preserves the original cutoff while producing the exact UTC JSON representation
used by the typed Go boundary. The native diagnostic previously established that
only timestamp spelling differed: non-time fields and the represented instant
were equal. SQL52's immutable whole-policy equality remains unchanged.

The [actual PostgreSQL rerun](../test/results/capacity-production-native-policy-time-fixed-check.log)
passes the formatter's valid/invalid cases and now reaches managed capture
admission: exact policy equality is true, and the admission/audit pair takes
241 ms with 4,738 ms of the original request interval remaining. The run still
returns exit 1: catalog publication encounters `unqualified processing lineage`.
It records 76 passing entries, 12.339 seconds of Go execution, 1,764 unchanged
source hashes and no cleanup failures. This is not a passed complete capacity
matrix; the next task is to correct that lineage mismatch without extending
retention, authority or backing.

The [owner producer component](../test/results/owner-identity-producer-integration.json)
is also integrated: separate four-role verification, original projection child
attempts and launch reconciliation. Its affected compilation, focused races and
vet pass; the subsequent contract gates pass with 10,345 specification assertions.
Native production/installation qualification remains open. Additional shared
probe and original-input checks are staged separately and grant no runtime
readiness. No installed developer workflow or implementation slice is complete.

## Original owner startup and local observation components integrated

The [sixty-nine-path integration](../test/results/installed-owner-observation-integration.json)
joins the original installed owner layout, four-purpose role verification,
independent credential/configuration child receipts, current native startup
reader and observation-only runtime. The local client authenticates the actual
owner before reading or transmitting the worker token. The fresh worker has
the bounded local metadata reads needed for that check. Legacy layouts and
full-loader behavior remain distinct; optional mounted files grant no authority.

The combined immutable check passes affected compilation (15.368 seconds),
focused races (24.086 seconds) and vet (2.047 seconds), with all 1,557 dependencies
and 69 payload/base identities unchanged. SQL generation, Go architecture,
specification and architecture checks also pass: 112 schemas and 10,341
specification assertions. The owner role producer/projection/launch component
has a separate passing source check, but is not integrated here. Native installed
startup, backend promotion and multi-cluster observation remain unqualified.

The [SQL54 sentinel correction](../test/results/capacity-root-sentinel-integration.json)
now passes all 35 actual SQL validator cases and the three root phases
(162 ms, with 4,781 ms of the original authority interval remaining). The
[owned run](../test/results/capacity-production-native-sentinel-fixed-check.log)
still returns exit 1: the next readiness fixture omitted its Pod UID, rejecting
before SQL and allowing earlier expected-denial assertions to pass for the
wrong reason. All 1,705 source hashes are unchanged and cleanup is complete.
The [two-path fixture correction](../test/results/capacity-storage-target-integration.json)
uses the complete target and explicitly refuses structural-invalid errors as
fence evidence. Its regression fails before and passes under race afterward;
the actual matrix must be rerun. No complete capacity or installed workflow
pass follows from these component results.

## Cleanup supervision integrated; native capacity reaches root reservation

The [forty-path cleanup integration](../test/results/capture-cleanup-runtime-integration.json)
adds separate cleanup SQL/storage/key facets and receipt-gated configuration,
capacity and cleanup supervision. A subsystem stops and joins its siblings on
failure. Historical cleanup retains its original policy and uncertain spend;
optional mounted files alone confer no authority. The immutable component check
passes SQLc generation, affected compilation, focused races and vet. This
constructor is not yet selected by the installed command.

The [six-path fixture correction](../test/results/capacity-native-inputs-integration.json)
adds positive synthetic safety/burst allowances and fixes the fixture's request
count to its existing prepaid bound. Shared native input preflight passes; no
production ceiling was raised. The combined SQL, Go architecture, specification
and architecture gates pass with 10,289 specification assertions.

The [next owned PostgreSQL run](../test/results/capacity-production-native-inputs-fixed-check.log)
returns exit 1 (Go 3.283 seconds). Actual function identity, paired-root lost-reply
recovery and purpose-separated role checks pass. Root reservation then fails:
`capacity_root_configuration_valid` calls `connector_digest` with an empty
digest. All 1,704 source hashes are unchanged and cleanup is complete. This is
not a passed capacity matrix. Correct that production SQL path, then rerun the
actual matrix. Owner installation/credential provenance and observation routing
remain staged components; the installed developer workflow is still unfinished.

## SQL54 reaches actual role production; capacity scenario setup still fails

The migration's PL/pgSQL CASE expression was parenthesized without changing its
semantics. The next native run exposed a missing fixture-only row-lock privilege;
that fixture now matches the existing production fleet-observer role. Both
failed runs and their complete cleanup/source reports remain under
`test/results/capacity-production-native-parse-fixed*` and
`test/results/capacity-production-native-observer-fixed*`.

The latter run also exposed a production role-verifier defect: PostgreSQL's
`timestamptz` display spelling differs from the compiled function signature.
The [three-path correction](../test/results/runtime-role-function-identity-integration.json)
compares exact resolved function OIDs and retains the existing grant allowlist,
layout digest and connection limits. Its regression fails before the correction;
corrected focused races, integration compilation and PostgreSQL adapter vet pass.

The [next actual run](../test/results/capacity-production-native-function-fixed-check.log)
returns exit 1 (Go 2.782 seconds). Actual alias/OID qualification passes and all
fixed SQL roles are produced in 2,078 ms. Setup then rejects a synthetic capacity
budget before the capacity scenario matrix starts. All 1,674 source hashes are
unchanged and owned cleanup is complete. This is not a capacity matrix pass or
an installed workflow. Correct and preflight the fixture inputs, then continue
real role-separated capacity qualification and protected service provisioning.

## SQL54 integrated; first actual migration fails before capacity tests

The [161-path integration](../test/results/capacity-production-integration.json)
combines the immutable capacity component, installed-worker/role inventory and
new SQL fixture with its one-line compile correction. Reviewed parent changes
advance the schema to 54 and add exactly five first-installation inventory
relations. SQLc independently reproduces all 47 generated files; Go architecture,
specification and architecture gates pass (10,258 specification assertions).
These are source checks, not an accepted runtime migration.

The [first owned PostgreSQL run](../test/results/capacity-production-native-check.log)
returns exit 1 during migration, before any selected test passes. PostgreSQL
reports a syntax error at the end of a PL/pgSQL block ending in the root-marker
trigger definition. All 1,673 source hashes are unchanged and owned cleanup is
complete. Correct the actual migration syntax and rerun the full capacity matrix;
no SQL54 native pass, operating envelope or installed activation is claimed.

## Owner bootstrap profile passes actual provider and registration tests

The [combined owned run](../test/results/owner-bootstrap-provider-native-fixed-check.log)
returns exit 0 (Go 24.877 seconds): both the legacy and opted owner certificate
profiles pass actual OpenBao signing, SQL registration/activation and encrypted
object audit. All 1,554 source hashes remain unchanged and cleanup is complete.
The opted case uses actual TLS 1.3/HTTP2 for common-name verification and rejects
an absent independent candidate, common-name use of exact-owner verification,
legacy acceptance of an opted leaf and an unapproved third provider SAN.

The [first run](../test/results/owner-bootstrap-provider-native-check.log)
failed before signing because the new fixture constructed an invalid ACL string;
its exit 1, unchanged hashes and complete cleanup are retained. The correction
changes that fixture string only. Provider/Pod/recovery inputs remain synthetic
installation authority; this is not installed routing or multi-owner balancing.
The combined source compiles and static Go/specification/architecture gates pass
(10,219 specification assertions). Continue original private owner provisioning,
receipt-gated startup and regional observation composition.

## Cluster-local transport and optional owner TLS profile integrated

The [42-path integration](../test/results/cluster-local-profile-integration.json)
retains checked local observation components, strict actual TLS-name/HTTP-authority
matching and the optional fresh-install owner bootstrap certificate profile.
Local-hop compile/race/vet checks passed. Actual HTTP/2 regressions fail before
both name-binding corrections and pass afterward; the owner-profile component
compile, focused races and vet also pass. Immutable payload, base and dependency
hashes matched at integration. No authority deadline or retry budget changed.

These tests use synthetic authority and issuer fixtures. Actual opted OpenBao
signing, remote observation exchange, service routing and installed multi-cluster
operation remain pending. The optional profile does not enable a listener or
public workflow. Continue private owner provisioning and the installed runtime
composition; repository gates for this combined source follow separately.

## Original bootstrap and runtime guard handover pass together

The [full native rerun](../test/results/initial-runtime-object-defaults-bridge-check.log)
returns exit 0 (Go 384.982 seconds), with all 1,548 source hashes unchanged and
complete owned cleanup. Original preparation/activation/retirement and setup-free
replay pass. The runtime bridge creates all nineteen fixed inert resources,
recovers lost CREATE and both guard-CAS replies by exact lookup, and retains
read-only original history during recovery. Actual zero-replica controller/GC,
missing-owner denial and administrator-removal denial also pass. Earlier failing
root/defaulting runs remain recorded below.

This qualifies the original bootstrap-to-guard handover in the owned reference
fixture. It does not run the owner/public services or supply their complete
provider projections. Continue configuration/public/capacity provisioning,
regional observation and actual installed browser/MCP capture-to-download
composition. The first full developer workflow and complete product remain
unfinished; no completion percentage or ETA follows from this component pass.

## Generated runtime resources pass actual API round trip

The [five-path correction](../test/results/initial-runtime-object-defaults-integration.json)
sets `Always` explicitly on both fixed Deployment templates and permits only
their original controller revision `1`, retaining exact UID/generation/spec
checks. The focused regression fails before the correction; corrected races,
affected compilation and vet pass with all 1,533 dependency hashes unchanged.
Existing claims are not migrated or adopted.

The [owned Kubernetes run](../test/results/initial-runtime-object-roundtrip-check.log)
returns exit 0 (Go 10.464 seconds), with all 1,548 source hashes unchanged and
complete cleanup. All nineteen generated objects pass CREATE, independent GET
and final readback. Both Deployments remain at zero replicas; actual first
controller revisions pass while changed generation, revision, template or
annotations deny. No Pod starts. The fixture's source plan and receipts are
synthetic: this proves resource defaulting and comparison, not activation or
installed runtime. Continue the full bootstrap/guard-bridge native composition,
then configuration/capacity/public startup.

## Original root pin fixed; native Deployment round trip remains failing

The [five-path correction](../test/results/initial-runtime-root-pin-integration.json)
retains the actual acknowledged preparation-root UID independently of the
optional original create-input field. The composed failing-before test reproduces
the earlier identity error; corrected resource/bridge races, affected compilation
and vet pass with all 1,702 dependencies unchanged. Replacement and explicit-pin
checks remain mandatory. Static gates pass with 10,208 specification assertions.

The [native rerun](../test/results/initial-runtime-root-pin-native-check.log)
returns exit 1 (Go 332.287 seconds), with all 1,546 hashes unchanged and complete
cleanup. Original bootstrap and passive replay pass, the corrected constructor
and earlier resources proceed, and resource index 10 (the inert owner Deployment)
fails the exact object check. API defaulting and the Deployment controller's
initial revision annotation are being qualified; no arbitrary metadata/spec
change is accepted to make the comparison pass.

The context harness now has a closed `--runtime-object-roundtrip` mode: one owned
cluster, the exact package-local test, a distinct opt-in and required named PASS.
It cannot be combined with another qualification or arbitrary test selection.
All 16 pure new/existing selection regressions pass in
[the harness record](../test/results/runtime-object-harness-selection.json).
Actual round-trip qualification and the complete native bridge remain pending.

## Native runtime bridge stops at original identity check

The opt-in [bootstrap-chain run](../test/results/initial-runtime-bridge-native-check.log)
returns exit 1 (Go 299.342 seconds), with all 1,545 source hashes unchanged and
complete cleanup. The actual four installation commands, original activation,
manager retirement and setup-free replay pass. The new runtime bridge child
fails while constructing its protected inert-resource producer, before its
resource journal or runtime objects are created: the original identity check
returns `ErrChanged`. This is not a passed runtime handover. The exact input,
original activation digest and preparer representation are being compared;
no deadline or identity check has been relaxed.

The 32-path resource/guard package is integrated. Its affected compile/vet and
static contracts pass (52 Go packages, 281 permitted edges, 102 schemas and
10,207 specification assertions). Those checks do not supersede the real API
failure. Continue with the reproduced identity mismatch and native guard
transition before installed configuration/capacity/public startup.

## Combined native downloads and retention expiry pass

The [corrected seven-case run](../test/results/native-retention-observer-combined-check.log)
returns exit 0 (Go 119.311 seconds), all 1,513 source hashes unchanged and cleanup
complete. Ordinary content, range resume, interrupted original/new sessions,
original control negatives, exactly-one-winner admission and native exchange all
pass together. Ranges reconstruct 352 original bytes without budget refill. The
new expiry case confirms that repeated retained-policy reads do not update the
source and that its actual original expiry denies subsequent reads.

The fixture previously wrote retention observations during permission reads,
including through a captured authority closure. Native cases now use the actual
read-only accepted-source reader and a separate joined source owner, started
before publication. The [counterfactual run](../test/results/native-retention-observer-before-check.log)
with the old consumer fails the combined current-read/proof/deadline check with
a nil port error (Go 1.529 seconds); it does not reach the later row-equality
assertion. Its 1,513 hashes and cleanup also verify. Earlier failures remain above
their original evidence; this identifies and removes artificial fixture writes
without claiming that every earlier failure had one exclusive cause.

Only four test paths changed. Product deadlines, authority, locks, pools, budgets
and retry rules are unchanged. Synthetic identity, issuer, Pod and bootstrap
facts remain explicit. This is one combined reference run, not installed-runtime,
large-artifact throughput or sustained availability qualification. Runtime
provisioning and real regional startup remain the next composition work.

## Installer bridge constructor failure reproduced and fixed

The new post-activation administrator facet incorrectly used the runtime Ledger
constructor, which rejects administrator credentials. The
[actual failing-before run](../test/results/initial-runtime-bridge-sql-before-check.log)
reproduces that exact failure before its effect callback (Go 0.497 seconds).
The purpose-specific correction keeps the runtime restriction and independently
checks its own current applied schema, original database incarnation and required
administrator role before locking recovery and the original activation.

The [corrected matrix](../test/results/initial-runtime-bridge-sql-after-check.log)
passes all eleven actual SQL/provider cases (Go 2.432 seconds), including changed
schema/incarnation, runtime credentials, recovery after a lock wait and expired
effects. Both runs retain all 1,512 source hashes and complete cleanup. Only the
four SQL/application/test paths are integrated; Kubernetes source/witness facts
remain synthetic in these cases. The native guard transition, full resource
provisioning and installed public workflow are still pending.

## Untraced six-case download run still fails

The [combined untraced run](../test/results/native-active-enrollment-untraced-final-check.log)
returns exit 1 (Go 109.193 seconds), with all 1,509 source hashes unchanged and
cleanup complete. Ordinary content passes. Resume reaches its third range before
the HTTP/2 stream fails; interruption, both control cases and exchange fail during
preparation. The earlier four-case diagnostic pass therefore does not establish
a reliable combined workflow. No cause has been isolated and no deadline, pool,
retry or authority limit has been broadened. Investigation now follows the exact
native admission and preparation lifetimes rather than repeating the same suite.

## Four remaining native cases pass with bounded diagnostics

The [diagnostic native run](../test/results/native-phase-diagnostic-remaining-check.log)
returns exit 0 (Go 71.809 seconds), all 1,510 source hashes unchanged and cleanup
complete. Interrupted original/new sessions, original control negatives, fresh
exactly-one-winner admission and native exchange all pass. The
[start observation](../test/results/native-phase-diagnostic-remaining-host.json)
records low CPU contention. This does not establish the exclusive cause of the
earlier failures or qualify sustained operation under contention.

The bounded timings recorded no error in instrumented ports. One fixed attachment
label fell back to `other`; its timing remains present without a distinct name.
The [removal record](../test/results/native-phase-diagnostic-removal.json)
verifies restoration of the exact three original files and removal of the owned
diagnostic file. Archived source/results remain available. A combined untraced
six-case run follows; no deadline, authority, pool or retry behavior changed.

## Full Go baseline passes; bounded native diagnostics integrated

The [full Go gate](../test/results/native-active-enrollment-go-result.json)
returns exit 0 after 797.042 seconds: embedded contracts, all-package vet and
all-package race tests pass. All 1,641 checked source hashes remain unchanged.
The [static gates](../test/results/native-active-enrollment-contracts.log) also
pass: 10,182 specification assertions, Go dependency rules, architecture and
63 screen contracts. These do not override the native failures below.

The [four-path temporary diagnostic package](../test/results/native-phase-diagnostic-package/HANDOFF.md.txt)
is integrated with all original/payload and 1,507 dependency hashes verified.
It times existing fixture calls and retains bounded fixed-label results without
extra reads, query hooks, deadline changes or renewed authority. Its two recorder
race tests and integration-package vet pass. The next native run must distinguish
setup permission expiry from the actual HTTP/transfer failure; diagnostics alone
are not a product fix.

## Active enrollment removes redundant setup; combined native result remains mixed

The [three-path change](../test/results/native-active-enrollment-integration.json)
omits unused enrollment-route setup only when independent current Job/Pod and SQL
observations preserve the exact already-active worker, key and peer. Original
request bounds, renewal boundaries, native TLS/admission and subsequent authority
checks remain binding. The staged regression failed before the change; 110 named
race-test entries and affected vet pass afterward, with unchanged dependencies.

The [combined native run](../test/results/native-active-enrollment-qualified-check.log)
returns exit 1 (Go 155.395 seconds), with all 1,509 source hashes unchanged and
cleanup complete. Ordinary content and range resume pass; resume reconstructs
352 original bytes without budget refill. Interruption fails before receiving its
first response or deliberately disconnecting. Both control cases fail during
preparation, before their concurrency assertions; the exchange case fails earlier
at publication permission setup. The [host observation](../test/results/native-active-enrollment-qualified-host.json)
records unrelated compilation and sharply increased CPU contention during the run.
That does not establish the exclusive cause. These failures remain unresolved;
there is no combined-suite, sustained-availability or installed-workflow pass.

## Native installer launch matrix passes

The [corrected Kubernetes run](../test/results/configuration-launch-kubernetes-distinct-check.log)
returns exit 0 (Go 137.201 seconds), with all 1,524 source hashes unchanged and
cleanup complete. All five cases pass: exact launch/replay, lost claim reply with
no launch, lost committed Deployment reply with lookup-only recovery, changed
probe enforcement, and missing original projection. Actual admission, guarded
Secret CAS, immutable inputs and scheduling-gated controller/foreground cleanup
are exercised. Successful launch operations take 4.67–4.70 seconds within their
original five-second bounds; these timings are not a scale or availability claim.

Combined with the six passing actual SQL cases below, this qualifies the named
launch boundaries. SQL/provider facts in the API fixture and Kubernetes source
facts in the SQL fixture remain synthetic and separate. No test executes the
runtime image, establishes the initial-to-runtime guard handoff, or completes the
installed browser/MCP investigation. Earlier setup and namespace failures remain
recorded rather than replaced by the passing result.

## Installer SQL launch checks pass; native Kubernetes fixture corrected

The [actual SQL matrix](../test/results/configuration-launched-sql-check.log)
returns exit 0 (Go 3.812 seconds): six cases cover positive launched replay,
missing roles, ambient privileges, changed sources, original lock expiry and
recovery after a lock wait. All 1,508 source hashes are unchanged and cleanup is
complete. Protected Kubernetes launch facts remain synthetic in this SQL matrix.

The [first Kubernetes attempt](../test/results/configuration-launch-kubernetes-check.log)
fails during Kind bootstrap, before Go tests. Exported owned-node logs show
control-plane container creation taking roughly 49–52 seconds, with API/etcd
startup reaching the bootstrap deadline. All 1,524 source hashes are unchanged
and cleanup is complete; this is no application test verdict.

The [same-image retry](../test/results/configuration-launch-kubernetes-retry-check.log)
reaches the actual Kubernetes API: positive launch, exact readback/replay,
scheduling-gated Pod creation and protected foreground cleanup pass (29.71 seconds).
Its four negative cases fail before their bodies because a fixture truncated
`custodyID` to its fixed prefix and reused the same terminating namespace. The
run returns exit 1 (Go 29.812 seconds), all 1,524 hashes unchanged and clean teardown.
The [one-path correction](../test/results/configuration-launch-kubernetes-namespace-fix.json)
keeps the complete generated UUID, giving each case its own valid 53-character
namespace. Full native negative qualification remains pending; no product limit
or authority changed. The image stays nonexecuting, and SQL/provider facts in
this API matrix remain synthetic.

## Fresh concurrency and ordinary download pass; resume delay persists

The [isolated real-service run](../test/results/native-fresh-content-isolated-check.log)
returns exit 1 (Go 38.457 seconds), with all 1,506 source hashes unchanged and
cleanup complete. Ordinary authenticated content passes (21.86 seconds), and
the separately prepared concurrent Observe/response case passes (8.25 seconds):
one winner, exact original identity and budgets, unchanged losing-side spend.

Resume fails during preparation continuation (7.94 seconds), before its range
assertions. The [host observation](../test/results/native-fresh-content-isolated-host.json)
records that the earlier unrelated heavy job had finished; CPU pressure was low.
The worker reaches connector admission with about 2.07 seconds of the original
interval left, then becomes uncertain. This narrows investigation to preparation
and admission latency; it does not yet identify one exclusive cause. No deadline,
polling interval, authority or budget was extended. Sustained availability and
the installed developer flow remain unqualified.

## Native combined run remains mixed; installer launch integrated

The [untraced combined download run](../test/results/native-admission-consolidated-final-check.log)
returns exit 1 (Go 93.977 seconds), with all 1,504 source hashes unchanged and
cleanup complete. Interrupted original/new sessions, the original control case
and the exact native exchange pass. Ordinary content and range resume fail during
preparation continuation. The host had concurrent unrelated work and elevated CPU
pressure; that observation does not isolate the cause or qualify performance.
The separate fresh-admission case reaches preparation but fails a duplicated
old-case completion assertion before its actual concurrency check.

The [one-path fixture correction](../test/results/native-fresh-race-separation-package/HANDOFF.md.txt)
keeps that completion assertion in its original control case and leaves the fresh
case's authority, exactly-one-winner and ten accounting assertions intact.
Compile/vet passed before integration, with all 1,525 dependencies unchanged.
Its actual native concurrency behavior remains pending.

The [eleven-path installer launch component](../test/results/configuration-launch-package/HANDOFF.md.txt)
is also integrated. A retained one-use claim permits the exact stopped-to-running
Deployment CAS; lost replies allow readback only. Original SQL role provenance
remains immutable, with a separate current read-only verification path after
launch. The [integration record](../test/results/configuration-launch-integration.json)
verifies all payload/base hashes and records the five unrelated parent fixture
changes since the stage's dependency snapshot. The stage's focused loopback TLS
races and vet pass; actual Kubernetes/SQL and installed handoff remain pending.
The [integrated launch race/vet check](../test/results/configuration-launch-integrated-go.log)
returns exit 0 (Kubernetes package 74.947 seconds); other selected packages have
no matching tests and are compiled/vetted only. Integrated Go architecture,
specification, architecture and design gates pass (10,165 specification assertions,
1,206 architecture checks, 63 screen contracts). These static and loopback checks
do not establish native installed behavior.

## Independent control-race fixture integrated; temporary callbacks removed

The [six-path fixture correction](../test/results/native-control-fixture-package/HANDOFF.md.txt)
is integrated after all 1,525 dependency and original/payload hashes matched in
the [integration record](../test/results/native-control-fixture-integration.json).
The original control case now requires both admissions to remain denied after
an incomplete response. A separate `native-control-admission-race` case obtains
its own original allocation, session, worker and preparation before testing one
winner across independent SQL pools. Ten accounting/generation counters check
loser behavior and retained spend; no rows or budgets are reset. Existing
completion, current-authority and expiry assertions remain.

Compile and integration vet pass; native behavior still requires the combined
run. Temporary callback wrappers and timing state are removed, preserving direct
original calls and the content fixture's finite two-minute aggregate bound. The
earlier query tracer is also absent. The integrated
[Go/specification/architecture checks](../test/results/native-admission-consolidated-contract-check.log)
pass (10,155 specification assertions and 1,206 architecture checks with 120
negative cases); those checks do not qualify native behavior.

## Interrupted transfer passes; control fixture reused an uncertain response

The [follow-up native run](../test/results/native-admission-consolidated-controls-check.log)
returns exit 1 (Go 53.762 seconds), with all 1,504 source hashes unchanged and
cleanup complete. The interrupted original session and separately admitted new
session both pass. The control case now also executes and passes the exact
already-closed, wrong-fence/sequence and held-row completion checks, preserving
owner state and charges under the original deadlines.

Its later simultaneous status/content assertion fails because neither admission
succeeds. That test first closes a response without an acknowledged successful
window, then incorrectly expects this same uncertain session to admit new work.
The production control reader correctly retains uncertainty in that situation.
The fixture must assert continued denial there and exercise exactly-one-winner
admission using a separately prepared fresh session. No production uncertainty
rule, charge or deadline will be weakened to satisfy the old assertion.

## Consolidated native exchange passes with query tracing disabled

The [selected real-service exchange](../test/results/native-admission-consolidated-exchange-check.log)
returns exit 0 (Go 13.526 seconds), with all 1,505 source hashes unchanged and
cleanup complete. Preparation, committed metadata observation and exact native
content transfer pass through actual SQL, encrypted object storage and TLS. Human,
Pod and installation facts remain synthetic; this is not an installed workflow or
throughput benchmark. The two same-call check consolidations leave all original
authority intervals and frame/effect checks intact.

The rejected query-tracer fixture has been removed from live sources; its exact
package and failed native composition remain archived above. It is not a supported
diagnostic interface. The next selected run covers the remaining control-race
and interrupted/new-session cases; no broader SQL optimization is justified yet.

## SQL tracing diagnostic rejected before the workflow

The [first instrumented run](../test/results/native-admission-sql-diagnostic-check.log)
returns exit 1 before any selected native case executes: `postgres.New` correctly
rejects a pool configured with a query tracer. The temporary diagnostic therefore
cannot measure this path through the supported constructor. All 1,505 source
hashes remain unchanged and cleanup is complete. Its synthetic trace tests did
not qualify this composition. The production tracer prohibition remains intact;
the next functional run leaves the diagnostic disabled. An unrelated HAPTIC race
run was also present on the host, recorded in the
[host observation](../test/results/native-admission-sql-diagnostic-host.json);
no performance or SQL contention conclusion follows from this run.

## Native admission checks consolidated; SQL timing diagnosis prepared

The [seven-path correction](../test/results/native-admission-checks-package/HANDOFF.md.txt)
removes two immediately repeated permission traversals in synchronous native
construction and attachment. A private one-use value carries the just-completed
check through local validation; original context, clock, exact operation and
known shortening are checked again. Public constructors, effect boundaries and
frame checks retain their full current checks. The meaningful original-budget
regression fails before the correction; the affected full native race suite and
vet pass afterward. All 1,505 dependency and payload/base hashes match in the
[integration record](../test/results/native-admission-checks-integration.json).
This does not yet establish real-service availability.

The preceding [callback diagnostic](../test/results/native-admission-callback-diagnostic-check.log)
returns exit 1 (Go 75.977 seconds): ordinary content and the original interrupted
session pass; the new session, control-race and standalone exchange cases fail.
All 1,501 source hashes remain unchanged and cleanup reports no failures. These
failures exhaust the original native lease while the outer fixture and worker
remain current; full current callbacks take roughly 100–280 ms in this run.
The new SQL completion-negative assertions are still not reached. Increasing
the ordinary-content aggregate fixture context separately allows that case to
pass; no product authority interval was changed.

A [two-file opt-in SQL timing observer](../test/results/native-sql-timing-integration.json)
now records at most 32 slowest query/acquire durations using fixed labels, totals
and outcome booleans. Unknown names become `other`; no SQL text, arguments,
credentials, error bodies or evidence is retained. Compile, focused race tests
and vet pass with 1,374 Go/module dependencies unchanged. This temporary fixture
observer adds no database calls or deadlines. Query durations include row
consumption, and acquisition can include connection setup; these measurements
alone cannot identify server execution or lock-wait time. The next selected
real-service case will measure the remaining path before further optimization.

## Inert deployment credential provisioning corrected

The [four-path correction](../test/results/configuration-inert-package-v1/HANDOFF.md.txt)
removes a startup dependency cycle: the workload builder creates zero replicas,
but the credential source previously required one. The exact zero-replica
deployment may now supply the provisioning observation. Rollout capacity is still
evaluated against the future one-replica state, and spec/resource-version changes
invalidate an in-flight claim. Provisioning neither creates a Pod nor authorizes
launch. Successful-launch disposition/replay and the installed command handoff
remain required.

All original/payload hashes and 1,372 dependencies were verified in the
[integration record](../test/results/configuration-inert-integration.json).
The staged regression fails before the correction; affected compile/races/vet pass
after it. The [integrated focused race and contract gate](../test/results/configuration-inert-integrated-check.log)
returns exit 0, including zero-to-one and zero-to-one-to-zero invalidation,
unchanged original claims and the existing current-enforcement cases. These use
synthetic Kubernetes enforcement and SQL receipts; native installed provisioning
is still unqualified.

## Native completion run exposes separate admission and fixture limits

The [five-case real-service run](../test/results/native-terminal-handoff-qualified-check.log)
returns exit 1 (Go 164.627 seconds); all 1,499 source hashes remain unchanged and
cleanup has no failures. Authenticated two-range reconstruction passes, including
four positively joined worker conversations through the new exact SQL close.
The interrupted session's original cancellation phase also passes. The whole
selected suite does not pass.

Ordinary content reaches its outer twenty-second lab cancellation while preparing
and auditing HTTP delivery. That aggregate context includes setup, enrollment,
forty current metadata reads and HTTP checks; the passing range case uses a
separate two-minute aggregate bound. Product authority/worker/session intervals
remain distinct. The interrupted flow's new session and the standalone exchange
instead fail at hub admission with their original short lease nearly exhausted,
before the new final completion callback. The control-race case fails during
preparation before its new SQL-negative assertions execute. Exact callback timing
is still needed; none of these failures establishes successful qualification of
the unexecuted assertions or permits a longer product authority interval.

## Exact native completion handoff integrated

The [18-file handoff](../test/results/native-terminal-handoff-package/HANDOFF.md.txt)
is integrated after verification of all payload/base hashes and 1,497 dependencies
in the [integration record](../test/results/native-terminal-handoff-integration.json).
Successful final Done now requires an acknowledged exact SQL owner closure under
the original lease. Ordinary cleanup, an already closed row, expiry and unknown
COMMIT results cannot certify success. The existing wire format and worker backoff
are unchanged; final-marker loss remains uncertain and local slots stay held until
their I/O joins. No authority interval, allocation or refund was enlarged.

The staged two-hop TLS regression fails before the change and passes afterward,
including ordinary relay checks denying after closure. Its initial broader race
run exposed a fixture HTTP handler outliving its test; joining admitted handlers
fixed that separate defect. Corrected affected races, compile/vet and static checks
pass in the archived package. The [integrated affected gate](../test/results/native-terminal-handoff-integrated-check.log)
also returns exit 0: native/evidence/PostgreSQL/bootstrap/integration race tests,
their vet checks, Go architecture and specification/architecture/design checks.
The real SQL/native positive, held-lock, already-closed and interrupted-transfer
cases remain to run.

## Integrated configuration composition gates pass

The [complete integrated gate](../test/results/configuration-role-composition-integrated-gates.log)
returns exit 0: Go vet and all package race tests, Go architecture, specification,
architecture and design checks pass. The Kubernetes package completes in 771.171
seconds within the fifteen-minute aggregate package bound. This supersedes the
earlier ten-minute aggregate timeout; original operation and test-specific
deadlines remain unchanged. The seven-file configuration composition follow-up and
bound-worker continuation are included. The design checks report 10,139 specification
assertions and 1,206 architecture checks with 120 negative cases. These are component
and contract gates, not an installed workflow or production qualification.

## Configuration credentials pass real service qualification

The [14-case native matrix](../test/results/configuration-runtime-roles-native-check.log)
passes (Go 12.274 seconds), with all 1,488 source hashes unchanged and no cleanup
failures. Actual PostgreSQL role creation/readback and scoped login, encrypted
S3/OpenBao audit and current acknowledgement pass, including lost claims,
expired observations, source rollback/mutation and source/recovery changes after
blocking locks. The three-role observation/audit/read path completes under its
original five-second bound. Kubernetes source/Secret and initial witness inputs
are synthetic in this fixture; installed provisioning remains unqualified.

The [seven-file follow-up](../test/results/configuration-composition-package-v1/HANDOFF.md.txt)
is now integrated with exact [payload/base verification](../test/results/configuration-composition-integration.json).
It registers the private configuration installer command and generates its
closed inputs and separate immutable credential projection from existing
installation records. The workload builder remains inert and Restricted.
The installed hub-worker constructor switch and actual protected handoff remain
pending. Extraction changed a test helper and excluded an unfinished public
command; integrated compilation/races still require a new run.

The corrected [specification/architecture/design checks](../test/results/configuration-role-corrected-design-check.log)
pass: 10,133 specification assertions, 1,206 architecture checks with 120 negative
cases, and the existing 63-screen/nine-journey contract mapping. The initial
contract run rejected four fragment-only schema self references; the
[correction](../test/results/configuration-schema-reference-correction.json)
uses canonical registered IDs without changing schema constraints. The earlier
Go import check passes for 52 packages/280 edges. The full Go gate's aggregate
timeout remains recorded below and its rerun is pending.

## Configuration credential component integrated; native qualification next

The [42-file package](../test/results/configuration-role-package-v1/HANDOFF.md.txt)
is integrated with all payload and existing-base hashes verified in the
[integration record](../test/results/configuration-role-integration.json).
ADR-140 supplies the three fixed configuration SQL roles, protected claim and
projection components, and current audit acknowledgement. Generated installation
and the installed command switch remain separate pending work; the chart and
public services remain disabled.

The [first integrated gate](../test/results/configuration-role-integrated-gates.log)
returns exit 2. Go vet and every other package's race tests pass. The Kubernetes
package reaches its aggregate ten-minute timeout while the current projection
test has run for six seconds. Its expanded suite has 200 top-level tests,
including actual-rate proof and expiry paths; this is not a passing whole-suite
verdict. The finite package timeout is now fifteen minutes. All original
operation, source, claim and test-specific deadlines are unchanged. Full Go
qualification and the subsequent contract gates still require actual runs.

## Interrupted native reconstruction passes; terminal-ordering fix remains

The [supervised-source native run](../test/results/native-interrupted-supervised-original-scheduling-check.log)
returns exit 0 (Go 42.560 seconds), with all 1,461 source hashes unchanged and no
cleanup failures. Its original interrupted session and explicit new session both
pass: cancellation preserves uncertain spend and denies reuse; only an independently
admitted new session reconstructs the native artifact through authenticated ranges.
The fixture uses real SQL, object storage, encryption and TLS, with synthetic human,
Pod and installation inputs. This does not qualify an installed user workflow or
large-file throughput.

The [bounded preparation/metadata trace](../test/results/native-preparation-and-cold-trace-check.log)
identified an independent fixture problem: refreshing permission/configuration
values did not renew their controllers' original 30-second permission and retention
leases or the synthetic fleet observation. The second phase therefore entered with
only about 1.65 seconds of original authority remaining. The owned fixture observer
now renews those exact leases while it remains alive. Its fleet update preserves
the original source, activation, incarnation, suspension and recovery fields and
cannot revive an expired root. A synthetic login has one fixed end and returns fresh
five-second identity observations; the first attempted two-minute identity was
invalid and its [failed run](../test/results/native-interrupted-renewed-source-owners-check.log)
is preserved. No product request deadline or authority was extended.

An attempted immediate reconnect after a locally Joined worker conversation exposed
a separate runtime ordering defect in the [native test](../test/results/native-interrupted-supervised-sources-check.log):
the worker can observe completion before the hub removes the original SQL locator.
The [exact reversion](../test/results/native-joined-scheduling-reversion.json)
restores the previous scheduling behavior. Its one-second delay is scheduling slack,
not proof of remote cleanup; a deliberate terminal-ordering correction and delayed
cleanup regression remain required. The passing run above does not settle that race.

Temporary timing and connection instrumentation is now removed, with exact
[archived sources and removal hashes](../test/results/native-diagnostic-removal/removal.json).
An uninstrumented run and integrated Go checks remain pending. The
[capability baseline](implementation-status.md) replaces inconsistent percentage
estimates with explicit implemented, integrated and installed-workflow evidence.

## Native interruption ownership and bounded-worker continuation correction

The [connection diagnostic](../test/results/native-interrupted-connection-counts-check.log)
returns exit 1 with 1,459 unchanged source hashes and clean teardown. The actual
fixture server allows 48 connections. After a positively canceled content exchange,
41 connections remain across 37 roles; after the explicit new session is prepared,
42 remain before constructing its worker. The former recursive continuation kept
the first phase's listeners, routing and purpose-specific SQL pools alive while
allocating the second phase. The diagnostic reads bounded connection counts only;
it changes no limits, evidence or authority.

The [phase ownership correction](../test/results/native-interrupted-phase-ownership/)
now runs the interrupted session and explicit new session as sequential owned
subtests. First-phase defers and cleanups finish before second-phase resource
allocation. Only the shared HTTP/audit fixture and original two-minute fixture
deadline span both. Original SQL spend, denial and uncertain-work assertions remain;
cleanup does not release their charges. Integration compilation passes (exit 0,
[compile log](../test/results/native-phase-compile.log)); native qualification is next.

The [bound-worker package](../test/results/native-bound-worker-package/HANDOFF.md)
is integrated after verifying both payload/base hashes and 1,210 dependency hashes
([record](../test/results/native-bound-worker-integration.json)). A currently bound
worker receives fresh exact live Job/Pod checks, independent SQL attachment checks
and current authority after blocking reads, without replaying completed launch
operations. Unbound launch recovery and all original deadlines remain unchanged.
The meaningful regression failed before this correction. Its first after-test had
an incorrect cleanup-deadline assertion, preserved with the failure; the corrected
race selection passes 22 top-level tests/76 named entries, and affected vet passes.
These synthetic port tests do not establish native timing or availability. The
combined [frozen real-service run](../test/results/native-interrupted-phase-owned-check.log)
returns exit 1 (Go 30.509 seconds), with all 1,460 source hashes unchanged and no
cleanup failures. Its original interrupted-session subtest passes, including
canceled content, retained uncertain spend, denied reuse and explicitly admitted
new session. Joined first-phase cleanup reduces open SQL connections from 42 to
33; the second worker and its preparation now succeed without connection
exhaustion. The second phase's subsequent cold metadata observation expires
before its regional result joins. That separate availability failure prevents a
complete interrupted-download verdict. The next diagnostic must isolate the cold
metadata operation within its unchanged original five-second interval; no retry
of uncertain work or authority extension follows from this test.

The integrated [specification/architecture gate](../test/results/native-phase-owned-design-check.log)
returns exit 0: 10,040 specification assertions, 1,206 architecture checks and 120
rejected invalid cases. Full integrated Go qualification after the bound-worker
change remains pending; its focused race/vet results above retain their exact scope.

## Native range download passes after preserving its original audit profile

The [HTTP-only diagnostic run](../test/results/native-http-port-trace-check.log)
returns exit 1 with 1,460 unchanged source hashes and clean teardown. Its first
HTTP preflight audit reservation fails with nearly five seconds still remaining.
The [PostgreSQL log](../test/results/native-http-port-trace-postgres.log) identifies
`outstanding audit history profile mismatch`: the fixture had replaced the
normal lane's store and backup identities after processing initialization had
already committed records under the original profile. The database correctly
retained that obligation.

The [fixture correction](../test/results/native-audit-profile-fixture/change.diff)
reuses the exact acknowledged original policy through a bounded fixture-admin
read. It changes only the explicitly provisioned revision, capacity/reserves and
new-admission validity. Existing records, child dates, storage/backup identities,
history qualification and spend remain intact. No runtime role or authority
check was broadened; this read is not an installation policy producer.

The [next real SQL/S3/TLS run](../test/results/native-range-retained-audit-profile-check.log)
returns exit 0 (Go 31.489 seconds), with all 1,460 source hashes unchanged and no
cleanup failures. Two authenticated HTTP/2 byte ranges reconstruct the original
352-byte native artifact after the earlier identity observation expires. Four
worker conversations positively join. The test verifies one original preparation,
two content key bindings, nine individual unwrap slots, all four preflight audit
pairs, unchanged session/artifact identity and no new response/window/key spend
for conditional mismatch or depleted backing. The fixture's human, Pod and
installation authority inputs remain synthetic. This is neither installed runtime
qualification nor large-artifact throughput evidence.

Temporary preparation and HTTP decorators are now removed, with exact archive
and [restoration hashes](../test/results/native-audit-profile-fixture/trace-removal.json)
preserved. The [uninstrumented range/interruption follow-up](../test/results/native-range-interrupted-clean-check.log)
returns exit 1 (Go 33.022 seconds), with all 1,458 sources unchanged and clean
teardown. Range preparation again becomes uncertain before content. The
interruption case reaches a real canceled content conversation, then fails with
custody unavailable; its [database log](../test/results/native-range-interrupted-clean-postgres.log)
records exhausted ordinary connection slots. Exact failure labels are added for
the next diagnostic. Preparation availability and fixture connection ownership
are separate unresolved issues; neither this run nor the earlier positive range
result qualifies interrupted reconstruction or the installed workflow.

The [post-correction specification/architecture checks](../test/results/native-profile-fix-design-check.log)
return exit 0: 10,033 specification assertions, 1,206 architecture checks and 120
rejected invalid architecture cases. Production Go is unchanged by these fixture
corrections; the earlier full Go gate remains the code evidence. Next investigate
already-bound worker dispatch replay within the original preparation interval,
and measure quiescent versus active fixture pool ownership before changing pool
capacity. Neither failure permits a deadline extension or uncertain-work replay.

## Regional owner ledger passes real SQL/object-store qualification

The [selected ADR-139 owner-ledger run](../test/results/regional139-owner-ledger-check.log)
returns exit 0 (Go 3.840 seconds, five PASS entries), with all 1,459 tested source
hashes unchanged and no cleanup failures. It verifies separately credentialed
SQL/S3 discovery, missing/audit/activation/purpose/retirement rejection, bounded
result overflow, a read role without effect permissions, and expiry of the original
observation while waiting behind a real row lock. The fixture's CA, native proof
and initial accepted recovery remain synthetic. Native regional first/continuation
routing and the installed developer workflow are still separate pending checks.

## Native phase trace reaches the first HTTP range; transfer remains failing

The [bounded fixture-only trace](../test/results/native-preparation-trace-package/HANDOFF.md)
passed its focused compile/race check before integration. Its decorators forward
the original contexts, calls, results and errors; they record only fixed phase
names, timing/deadlines and closed error categories. They change no product
authority or deadline. The original fixture and trace are preserved for removal
after diagnosis.

The [selected real SQL/S3/TLS run](../test/results/native-preparation-port-trace-check.log)
returns exit 1 in 18.790 seconds, with 1,459 unchanged source hashes and no cleanup
failures. Preparation and metadata observation both positively join. The first
HTTP byte-range request then returns 503 before native content delivery. This
reaches the revised audit-pool setup without its earlier configuration conflict,
but does not qualify the actual HTTP audit/transfer path.

The [retained phase timings](../test/results/native-preparation-port-trace-phases.json)
show original preparation reaching its final metadata permit with about 495 ms
remaining. No deadline was extended. The diagnostic retains its first 512 events
and a separate first-error slot; 791 later events were omitted, and none of its
wrapped ports reported an error. A separate HTTP-only trace of audit, session and
response admission is next. The earlier intermittent preparation failures remain
unresolved; a passing preparation in this run is not a demonstrated availability
fix. Range/resume and interrupted transfer qualification are still pending.

## Incremental framed reader integrated; Go and design checks pass

The [seven-file reader package](../test/results/framed-cursor-package/HANDOFF.md)
is integrated after verifying all payload/base hashes and 356 dependency hashes;
the [integration record](../test/results/framed-cursor-integration.json) preserves
those exact inputs. The reader now yields at most one MiB per call, retains one
authenticated index page and decoded frame, and performs no next-frame prefetch.
Cancellation joins actual outstanding I/O before releasing owned buffers. Full
reads verify all three whole-file hashes before delivering the final chunk;
partial reads retain their narrower integrity claim. A separate range-work value
counts complete intersecting frames and pages without granting authority.

The original push reader failed the boundary regression by reading the next frame
before the application rejected delivery. The corrected isolated package passes
51 top-level framed/artifact race cases and affected vet, including the existing
highly compressible logical file over two GiB. That case verifies pagination and
tail decoding, not multi-GiB network transfer or production memory/throughput.
The existing push API now uses the same incremental decoder. Persistent format,
key-opening count, SQL and application authorization are unchanged.

The [integrated gate run](../test/results/framed-cursor-integrated-gates.log)
passes full Go vet/races and the dependency check (52 packages/280 internal
edges), then returns exit 2 at the documentation check: the archived copy of an
architecture document retained links relative to its original location. Its exact
bytes are now archived as `.md.txt`, like the inert `.go.txt` code evidence.
The [subsequent specification/architecture/design gates](../test/results/framed-cursor-integrated-design-gates.log)
return exit 0 (10,020 specification assertions). No Go change was needed for that
archive correction. Generic large-object publication,
window-owned key/reader lifetime, finite window history retirement and installed
PCAP/core downloads remain separate unfinished work. No larger context limit or
public collection route is enabled. The real-service native preparation failure
below remains unresolved; fixture-only phase tracing is the next diagnosis.

## Browser restart passes; native idle-response delivery corrected

The [combined built-browser gate](../test/results/console-restart-integrated-browser-refresh.log)
returns exit 0: the existing console journey passes 19 checks and 15 accessibility
scans, and the new native-restart journey passes four boundaries and two scans.
These use the actual compiled React console, Go HTTPS/session/CSRF and operation
transports with synthetic current identity, case and file services. The restart
case exercises an interrupted browser attachment, lost Stop/preparation replies,
reuse of the original request keys and a new transfer only after explicit user
action. It is not encrypted SQL/object-store transfer qualification.

The [first combined run](../test/results/console-restart-integrated-browser.log)
passed restart but failed the existing journey because Chromium discarded the
navigation response body from its debugging protocol. The test still checks the
first real response and rendered evidence; complete canonical wire assertions now
run on an explicit same-page Refresh evidence details operation. No response is
mocked or assertion removed. The corrected combined Go run took 19.401 seconds.

The [native listener correction](../test/results/native-idle-integration.json)
is integrated after exact base/payload and dependency checks. An actual
listener/client regression first reproduced loss of the authenticated no-command
response: Go HTTP/2 could report idle before its buffered final frames were
flushed. The server now uses Go's graceful keep-alive shutdown rather than closing
the raw socket in an idle callback. The one-request guard, original deadlines and
joined capacity accounting remain. Focused native/mTLS race tests and vet passed
in the isolated package; the next real-service range/interruption runs must verify
the integrated SQL/S3/TLS path. The full combined repository gates below predate
this listener correction and the browser fixture changes.

The [first integrated native range run after the listener fix](../test/results/native-retry-range-after-idle-fix-check.log)
returns exit 1 with 1,453 unchanged sources and clean teardown. It now receives
positive no-command responses correctly, but its active preparation becomes
uncertain. A [test-only phase diagnostic](../test/results/native-retry-preparation-phases-check.log)
then positively joins preparation and metadata observation, before failing in
HTTP preflight audit fixture setup. That diagnostic was removed byte-identically;
its exact instrumented source is retained as a `.go.txt` artifact. Neither run
qualifies range delivery, and the preparation timing failure remains recorded.

Source review found the new HTTP fixture trying to create revision one of a
normal audit pool already created by the processing fixture. The correction uses
the actual revisioned configuration API, retains the existing spend and funds
four HTTP preflight pairs in addition to earlier processing work. The multi-request
fixture timeout is now finite two minutes; every product authority, worker,
operation and socket deadline is unchanged. The [next run](../test/results/native-retry-range-after-audit-fixture-fix-check.log)
returns exit 1 earlier at dispatch because an observation expires; it also records
1,453 unchanged sources and clean teardown. The native fixture now refreshes its
explicitly synthetic protected source observations before dispatch, using the same
observer subsequently maintained by the native loop. This does not renew a human
request or operation. Qualification of these fixture corrections remains next.

The [next current-observation run](../test/results/native-retry-range-current-fixture-check.log)
still encounters an expired earlier observation during the separate initial worker
reservation (exit 1; 1,453 unchanged sources; clean teardown). Fixture observation
ownership now begins before that reservation and remains single and joined through
all native phases, including the interrupted case's later fresh session. Each
independent admission obtains its own observation; an in-flight authority is never
renewed. This also removes nested duplicate fixture observers.

The [supervised-fixture run](../test/results/native-retry-range-supervised-fixture-check.log)
passes those setup boundaries but still returns exit 1 during the original metadata
preparation continuation (Go 11.497 seconds; 1,453 unchanged sources; no cleanup
failures). There is no successful range-transfer result yet. Preparation's bounded
critical path remains the next diagnosis; no deadline, permission check or spent
budget was weakened. The audit-fixture revision correction has not yet been reached
successfully in this final run, and actual interruption qualification remains unrun.

After these fixture changes, the [local follow-up design gates](../test/results/native-browser-followup-design-gates.log)
pass with exit 0: spec (10,016 assertions), architecture, Go dependency ownership
and UI/interface design. The [integrated affected race suites](../test/results/native-browser-followup-race.log)
also pass (native transport 15.079 seconds; mTLS adapters 9.568 seconds). They do
not supersede the failing real-service range run. The next implementation task is
to diagnose and reduce unnecessary work on the original bounded preparation path,
then qualify range and interrupted transfers with unchanged security deadlines.
Parallel public installation, protected capacity and generic framed-reader work
remains isolated and does not enable the public service.

## Native retry and regional serving pass combined gates; real-service qualification next

The [combined integrated gates](../test/results/combined139-retry-integrated-gates.log)
return exit 0 for Go vet/full races, Go architecture (52 packages/280 internal
edges), SQL generation (46 matching bindings), specification (91 schemas/10,002
assertions), architecture, Helm and design checks. Console contract validation,
TypeScript and all 133 tests also pass. These checks cover the integrated ADR139
and retry V2 sources; external SQL/S3/TLS and built-browser qualifications are
separate and still pending.

The [retry V2 package](../test/results/native-retry-v2-HANDOFF.md) is integrated
after all 17 payload/base hashes and 1,427 current dependencies matched. Closed
local response state now needs an independently acknowledged successful window
before another first-context attempt is eligible. The console offers an explicit
new download after a native browser request, including when its status remains
Ready; it confirms the old Stop and preserves both request keys through unknown
replies. Earlier uncertain spend remains charged. Native ranges and a genuinely
interrupted transfer have distinct compiled qualification cases.

The stage records a failing uncertainty regression and a failing stale-Ready UI
regression before their fixes. Corrected focused Go races/vet, fixture compilation,
38 affected UI tests and TypeScript checks pass. Those Go checks precede the
separately integrated ADR139 composition; its exact dependency transition is
retained. Combined repository gates now pass above; actual SQL/S3/TLS selectors
and built-browser qualification remain pending. This does not enable public runtime or qualify
large-artifact transfers.

The first real-service range run and its labeled rerun fail before preparation:
[initial](../test/results/native-retry-range-first-check.log),
[labeled](../test/results/native-retry-range-diagnostic-check.log). Both record
exit 1, zero selected passes, 1,451 unchanged sources and no cleanup failures.
A [temporary diagnostic run](../test/results/native-retry-source-stage-diagnostic-check.log)
isolates the copy-record lookup; its production-file logging was then removed
byte-identically. The dedicated new fixture lacked the existing context
source/locator SELECT grants that older control fixtures supplied. The
[test-only role correction](../test/results/native-retry-source-role-correction.patch)
adds those two existing reads, with no effect privilege or caller authority.

The [next run](../test/results/native-retry-range-after-role-fix-check.log) confirms
initial session, pending metadata and source reads now succeed. It fails during
preparation because the worker receives a generic transport failure after the
connector has returned the positively checked no-command disposition. It records
exit 1, zero selected passes, 1,451 unchanged sources and clean teardown (Go
8.453s). Exact native listener/client reproduction is next; this run does not
qualify range bytes or justify treating generic network errors as retryable.

## Packaged Helm bootstrap passes; native content and public workflow remain in progress

The [packaged Helm diagnostic run](../test/results/helm137-native-hook-diagnostic-check.log)
returns exit 0 with four passing entries. The actual chart/product on empty
PostgreSQL and real TLS OpenBao/S3 passes original manager/schema/activation/audit
and retirement, positive managed-copy closure, setup-free replay, retained
failed-hook CLI resume and uninstall preservation. Its
[environment report](../test/results/helm137-native-hook-diagnostic-environment.json)
records anonymous exact-image denial, authenticated manifest GETs from both
owned nodes, the exact image absent before both pulls, 1,458 unchanged sources
and no cleanup failures. The registry, private network and fixture TLS/auth files
are positively absent after cleanup. The Go suite took 347.577 seconds.

This run uses the same product binary SHA256
`9e0481cf4f5435c6cb677201959ad7b1e83cae40df62ad28c3219ab871f1fbd0`
as the preceding failed hook run; only test diagnostics changed. It establishes
a passing packaged composition, not a fix for that earlier unexplained startup
failure or long-running availability. That failure remains recorded below.
Public runtime, installed capacity/source/role production, restore and the full
capture-to-download workflow remain unfinished. No whole slice is complete.

The [ADR139 package](../test/results/regional139-HANDOFF.md) is now integrated
after all 14 payloads, seven existing bases and 1,461 dependencies matched.
It composes the two fixed private purposes on the accepted native port and fixes
an owner shutdown that returned after six seconds with a child still running.
The original regression failed; corrected focused bootstrap races (9.716s),
listener races (13.585s), integration-source compilation, affected vet and four
selector checks pass in the stage. Integrated gates and actual SQL owner
enumeration plus regional first/continuation exchanges remain required. No new
public route is enabled. The shared raw pre-TLS ceiling does not promise fairness
against unclassified connection pressure; admitted purpose slots remain separate.

The post-Helm `make spec-check architecture-check helm-check` run returns exit 0
in [the contract log](../test/results/helm137-qualified-contracts.log). It precedes
the ADR139 integration and its new documentation; combined verification follows.

The [combined repository gates](../test/results/combined136-138-integrated-gates.log)
now return exit 0: full Go vet/races, 52 packages/279 import edges, 46 matching
sqlc bindings, 91 schemas/9,976 assertions, architecture, Helm render/package and
design checks. These precede the focused HTTP/2 correction below; external
fixture suites are separate and remain pending.

The [ADR136 package](../test/results/native136-HANDOFF.md) is integrated after
46 payload/base hashes and 1,373 dependencies were checked. Fifteen dependency
changes match the independently integrated ADR137 package exactly; no unreviewed
source replacement was accepted. SQL53 changes only the fixed content-preflight
audit classifiers, retains the 91-table inventory and matches the binary schema
head. Combined sqlc regeneration produces the supplied attachment binding and
preserves ADR135's owner query. The package's affected races/vet and fixture
compilation pass; its three new real-service selectors remain unrun.

The [ADR137 package](../test/results/helm137-HANDOFF.md) is integrated after
58 payload/base hashes and 21 dependencies matched. It adds the optional fixed
four-command Helm hook, immutable public input revisions, terminal-only resume
and explicit private-registry propagation through the existing managed copy.
Focused Go, Helm/schema/package and offline checks passed in isolation. The new
`--helm-bootstrap` fixture now has the passing packaged run above; the earlier
setup/hook failures remain below. The chart continues to reject public runtime
enablement.

The [first packaged Helm run](../test/results/helm137-native-first-check.log)
fails before Kubernetes setup: the registry fixture incorrectly equated Docker's
image ID with the exported configuration digest. The daemon uses containerd's
image store and reports an index digest instead. No product command or native
case ran. All 1,457 source files compare unchanged after exit; the harness did
not yet set its in-run comparison field on setup failure. Owned registry/network
and private credential/TLS files were positively removed.
The [fixture correction](../test/results/helm137-registry-identity-correction.patch)
now verifies the exact image's bounded hash-checked descriptor chain to its
exported platform/configuration, preserving separate binary, image, configuration
and uploaded-manifest identities. An actual tiny Docker build/export passes
[that check](../test/results/helm137-docker-containerd-identity-after.json), and
four offline selector/identity/cleanup tests pass. No product input or image was
substituted. Setup failures now also record the source comparison before their
terminal report; this never counts an unexecuted test as passed. Packaged native
requalification remains pending.

The [second attempt](../test/results/helm137-native-after-image-identity-check.log)
passes the descriptor identity check, then fails before Kubernetes because the
Docker archive contains gzip-compressed layers. The original fixture compared
their compressed hashes directly with uncompressed rootfs diffIDs. Its terminal
report records exit 1, zero selected passes, 1,457 unchanged sources and complete
owned cleanup. The [layer correction](../test/results/helm137-registry-layer-correction.patch)
preserves exact exported bytes, checks bounded decompression against the original
rootfs identities and uploads the matching OCI media type. Five offline tests
pass, including invalid digest, corrupt gzip and decompression-bound rejection.
No product image or authority change is involved; the next packaged run remains
required.

The [third packaged run](../test/results/helm137-native-after-export-fixes-check.log)
passes archive setup and reaches the actual Helm-installed bootstrap Pod, which
fails during the four-command chain. It returns exit 1 with zero selected
passes, all 1,458 tested source hashes unchanged, no cleanup failures and
positive removal of the owned registry/network/private TLS/auth files. The
generic Helm error does not identify the failed command; the fixture now reads
bounded logs/status for the exact original hook before cleanup. That diagnostic
addition is not a product fix or a passing installation qualification. The next
run must identify the underlying failure before changing product behavior.

The [native download fixture correction](../test/results/native136-fixture-HANDOFF.md)
now maps the exact HTTP-shaped synthetic cookie to its existing synthetic session
and waits for handler return before asserting final SQL/audit outcomes. The cookie
regression failed against the original fixture, then focused races/vet passed.
These two test-only files and four dependencies were hash-checked on integration.
Receiving the Content-Length bytes alone is not reported as joined server-side
completion. The actual SQL/S3/native/HTTP selector remains unrun.

ADR138's five public routing/composition files are integrated after matching
their hashes and reviewing three final ADR136 changes against the earlier
22-file HTTP snapshot. Its routing races previously passed; configured-provider
and installed qualification remain pending. A parallel review identified a
native HTTP/2 transition defect: the preflight socket deadline remained armed
while the first content phase obtained fresh authority. The
[focused correction](../test/results/native136-h2-HANDOFF.md) is now integrated
after five payload/base and six dependency hashes matched. The actual TLS/HTTP2
regression fails before with a stream reset at the old deadline; focused
browser/evidence races and vet pass afterward. Positive preflight now advances
only the socket idle bound before fresh setup; all byte authority and original
response bounds remain unchanged. A second actual HTTP/2 test covers a pause
between independently leased chunks. This is local transport evidence, not an
installed worker/provider result. The
[integrated correction races](../test/results/combined136-138-corrections-races.log)
now pass for affected Kubernetes, evidence, browser and bootstrap tests; affected
vet also returns 0. External qualification remains next.

The [connector proof-reuse correction](../test/results/regional135-reuse-HANDOFF.md)
is integrated after five payload/base and 1,289 dependency hashes were checked;
three dependency changes match the recorded HTTP/2 correction. One completed
native process proof may be reused only inside its original interval, with
current credential/source/workload/input/guard checks, cancellation and
generation invalidation. Client QPS and authority deadlines are unchanged.
Focused races and fixture-source compilation pass; the corrected actual local
start timing remains unrun. New per-phase counts will distinguish original
proof work from Prepare/Ready/Consume overhead. Full installed HTTP/2 source and
frame amplification remain separate follow-up work.

## Regional context transport: repository checks passed, native setup corrected

The [ADR135 package](../test/results/regional135-HANDOFF.md) is integrated after
all 45 original/payload hashes and 1,305 current dependency hashes matched. It
adds a connector-originated signed HTTP/2 exchange, request-owned current
identity checks, joined cancellation and concrete connector API process/start
adapters. The owner enumeration query changes no SQL migration or schema head.
The two existing-file edits retain omitted-capability behavior and add only the
exact optional capacity/main-CREATE and status-UPDATE admission branch.

The [integrated gates](../test/results/regional135-integrated-gates.log) return
0 for full Go vet/races, Go architecture (52 packages/278 internal edges), SQL
generation (45 matching bindings), specification (89 schemas/9,937 assertions)
and architecture contracts. This resolves the earlier sparse-overlay vet
limitation at the new package's actual path. The
[first Kubernetes run](../test/results/regional135-native-reader-first.log)
failed in fixture setup: the Deployment controller updated status while guards
were installed, making the original scale request's resourceVersion stale. Its
[terminal report](../test/results/regional135-native-reader-first-check.log)
records exit 1, no passing selected case, 1,385 unchanged source hashes and
complete cleanup; the Go case took 1.040 seconds. No API-process or local-start
assertion had been reached. The fixture now retries only definite conflicts after
rereading and checking the original UID and complete spec; it never adopts a
replacement or retries an uncertain update. Native requalification is pending.
The [second run](../test/results/regional135-native-reader-after-scale-fix.log)
passes that setup and reaches current process observation, which fails after
2.800203409 seconds. Its
[terminal report](../test/results/regional135-native-reader-after-scale-fix-check.log)
records exit 1, 1,385 unchanged hashes and complete cleanup; Go took 8.237 seconds.
Review found that `ReadAPIProcess` recorded its observation start before the
nested guard started a new five-second interval, then copied that later cutoff
unchanged. The outer observation could therefore exceed its own maximum even
when the guard succeeded. The caller now bounds the entire guard by its original
start plus five seconds. [Affected races](../test/results/regional135-process-deadline-races.log)
pass (exit 0, 1.085 seconds); real-service requalification remains pending.
The measured API operation counts and elapsed phases are retained separately
from this timestamp defect; repeated checking under the existing rate limiter
still needs measurement through the complete local-start sequence.
The [third native run](../test/results/regional135-native-reader-after-deadline-fix.log)
now accepts the actual defaulted process and passes both named Secret/foreign
denial and changed-input rejection. Its local-start subcase fails after one
CapacityReservation CREATE: the repeated post-create check returns at
4.995665377 seconds, with only 4.333884 milliseconds left in the original
five-second interval. Ready/start assertions are not reached. The
[terminal report](../test/results/regional135-native-reader-after-deadline-fix-check.log)
records exit 1, two passing subcases, 1,385 unchanged source hashes and complete
cleanup; Go took 15.122 seconds. The enclosing test remains failed. The native
timings now establish a separate repeated-check cost problem under the existing
20-QPS client ceiling. A bounded reuse/coalescing correction is being designed;
no authority deadline or rate limit has been increased.
Protected signing/profile/input provisioning, regional command startup and the
combined installed investigation remain unfinished; public collection stays
disabled. Review also identified the existing native listener's fixed path and
ten-second socket as a missing serving composition: the pending same-port change
must retain that native limit while separately bounding context standby, with
independent capacity and joined cancellation.

## Public endpoint composition: staged routing qualification

The [ADR138 source checkpoint](../test/results/public-context138-HANDOFF.md)
composes the existing public transports around one healthy audited backend.
Five focused routing regressions pass with the race detector, including actual
loopback TLS preserving native response deadlines, flush and exact bytes;
encoded/absolute/cross-host paths and API-to-console fallback are rejected.
The complete constructor also compiles against ADR136's frozen 22-file HTTP
snapshot after exact base/payload verification, with the five routing races
passing in the combined overlay. Configured-provider and installed-service
qualification remain pending. No live product Go source or public enablement changed.
Regional transport, native download and Helm installation packages continue in
isolated agent stages; their component results do not establish installed flows.

## Corrected installation and continuation: combined repository checks passed

The [combined rerun](../test/results/bootstrap133-continuation134-corrected-gates-rerun.log)
returns 0 for `make go-check go-architecture-check spec-check architecture-check`:
full Go vet/race suites, 51 packages/269 internal import edges, 85 schemas/9,918
assertions and the design catalog pass. Native suites below qualify the actual
installation and regional acquisition separately; ordinary Go tests do not run
those external fixtures. The first combined attempt failed because a copied
compatibility-test source in `test/results` was discovered as an unintended Go
package. Its bytes were preserved as
`bootstrap133-stage-legacy_compatibility_test.go.txt` before the passing rerun;
no product behavior or gate was relaxed.

The [schema52 database-recovery run](../test/results/database-recovery52-after-native-corrections.log)
now passes actual initial, PostgreSQL restart and logical restore phases. Its
[terminal report](../test/results/database-recovery52-after-native-corrections-check.log)
records exit 0, three passing phases, 1,348 unchanged source hashes and complete
cleanup. This proves the current incarnation fence, not operator-approved
restore activation or preservation of every feature's state across restore.
The [full schema52 custody run](../test/results/custody52-after-native-corrections.log)
also passes. Its [terminal report](../test/results/custody52-after-native-corrections-check.log)
records exit 0, 318 passing entries, 1,348 unchanged source hashes and complete
owned cleanup; the Go suite took 540.852 seconds. This supersedes the earlier
schema50 full result for the current integrated source. The separately timed
connector-retirement qualification remains unrun; its ordinary-suite skip is
not a passing release result. Installed regional transport (ADR135),
authenticated native content/runtime composition (ADR136) and the supported
Helm bootstrap workflow (ADR137) remain staged work, not enabled product routes.

## Managed setup-copy cleanup: corrected native v3 chain passed

The [ADR133 package](../test/results/bootstrap133-HANDOFF.md) is integrated
after all 30 original/payload hashes and eleven dependencies matched. New
installations select bootstrap v3; retained v1/v2 guards keep their existing
wire bytes and v2/v3 retries use their original version. After independently
verified activation and manager retirement, a finite original claim controls
guarded deletion of the two exact managed credential copies and immutable
sanitization of the seed. Unknown guard creation never permits another CREATE.
The guard objects remain protected by trusted installer/RBAC authority;
Kubernetes admission policies cannot protect their own mutation.

Staged affected races/vet, complete legacy guard-byte comparison and contract
checks pass. The [integrated contract gates](../test/results/bootstrap133-integrated-contracts.log)
also return 0. The [first actual four-command v3 run](../test/results/bootstrap133-native-first.log)
fails in the retirement phase with `setup differs from the saved installation`.
Its [terminal report](../test/results/bootstrap133-native-first-check.log)
records exit 1, zero passing entries, 1,345 unchanged source hashes and complete
owned cleanup. The Go case took 236.895 seconds. The
[metadata correction](../test/results/bootstrap133-metadata-HANDOFF.md) is now
integrated: cleanup previously rejected the installation/request annotations
that the actual producer places on both copies. It now verifies both exact
values against the retained claim and keeps the closed metadata checks.
Producer-shaped regressions reproduce four failures before the correction;
affected races and vet pass afterward. The
[corrected native chain](../test/results/bootstrap133-native-after-metadata.log)
now passes: all four compiled commands, positive managed-copy deletion,
immutable seed sanitization, fresh setup-free replay and administrator guard
removal detected without recreation. Its
[terminal report](../test/results/bootstrap133-native-after-metadata-check.log)
records exit 0, three passing entries, 1,348 unchanged source hashes and complete
cleanup; the Go suite took 291.326 seconds. The original activation Pod was
`c0d3d988-20e0-4d6e-aa3a-b2453ec35dbb`, running
`docker.io/library/asservat-context-worker@sha256:5c44ab2c0f5fff1392376652389b2bc48dd03145f0af0827c517dd667e7eec86`.
The fixture supplies upstream services and explicit administrator credentials;
the product creates its manager, schema, witness, activation and retirement.
No Helm/runtime enablement or broader backup/heap erasure is implied. Partial
pre-seed and expired/uncertain cleanup recovery remain explicit gaps.

## Explicit collection continuation: corrected native acquisition passed

The [ADR134 package](../test/results/continuation134-HANDOFF.md) is integrated
after all 32 payload/base hashes and eight current SQL52 dependencies matched.
Browser and MCP share optional `continue_acquisition: true` on the original
preview/key request. The console exposes a deliberate action for retained,
pending captures. Ordinary replay, polling and reload remain passive.

The runner now allows only the positively acknowledged first SQL preparation
to create wrapping keys. The package preserves failing-before evidence for
concurrent/lost-reply preparation and an expired original preparation interval.
Staged affected races/vet, OpenAPI and all 49 browser/MCP contracts pass; the
console's 125 unit tests and production build pass. The
[integrated repository gates](../test/results/continuation134-integrated-gates.log)
return 0: full Go vet/race suites, 51 packages/269 import edges, 44 matching SQL
bindings, 84 schemas/9,876 assertions and the architecture catalog. These gates
precede the subsequent ADR133 integration. The
[built-browser journey](../test/results/continuation134-browser.log) also returns
0: nineteen journeys, fifteen accessibility scans and no external requests or
CSP/runtime errors. It uses actual Go TLS/session/operation transports and the
built React console with synthetic identity/capture/case services.

The [first actual regional continuation run](../test/results/continuation134-native-first.log)
fails before its unavailable-start injection: the initial request returns
`context admission unavailable` and records zero start calls. Its
[terminal report](../test/results/continuation134-native-first-check.log) records
exit 1, no selected pass, 1,345 unchanged source hashes and complete cleanup.
The Go case took 5.038 seconds including setup; that duration is not evidence
that the request's authority interval expired. Diagnosis is in progress.
The context harness now retains bounded owned-PostgreSQL failure logs before
cleanup. The [diagnostic rerun](../test/results/continuation134-native-diagnostic.log)
locates the failure inside reviewed SQL admission: 28.849261 ms, no accepted
capture or audit reservation; the complete request took 415.800818 ms. Its
[terminal report](../test/results/continuation134-native-diagnostic-check.log)
records exit 1, zero passing entries, 1,345 unchanged source hashes and complete
cleanup. The bounded PostgreSQL log was retained successfully and shows no
unexpected driver error for that admission. Audit deadline precision and the
fixture lifecycle budget caused the failure. The
[five-path correction](../test/results/continuation134-admission-fix-HANDOFF.md)
is integrated after exact base/payload checks: truncate only the live audit
cutoff downward to SQL precision, and fund the fixture's unchanged 30-second
write interval with 120-second audit retention. Both defects have failing-before
regressions; affected races, integration compilation and vet pass. No caller,
capture, cleanup or proof interval is extended.

The [corrected native continuation](../test/results/continuation134-native-after-admission-fix.log)
now passes actual C09 preview/request, SQL52 admission and encrypted intent
acknowledgement, passive replay and explicit fresh-current continuation. Its
initial injected unavailable start occurs after admission; the subsequent call
uses one original execution and local CAS. The fixture verifies, publishes and
reads 362 exact native bytes after deleting the actual target and executor Pods;
Nodes, exec, Secret reads and token minting remain denied to the collector.
Its [terminal report](../test/results/continuation134-native-after-admission-fix-check.log)
records exit 0, two passing entries, 1,348 unchanged source hashes and complete
cleanup; the Go suite took 10.912 seconds. Reviewed admission took 59.860327 ms
and original encrypted intent publication 119.208141 ms in this local fixture.
Human, retention, capability and initial bootstrap authority remain explicit
fixture inputs; this does not qualify installed regional or public transports.
No installed transport or public runtime is enabled by these component results.

## SQL52 capture-intent lifecycle: native qualification passed after two corrections

The [frozen 39-path package](../test/results/capture52-HANDOFF.md) is integrated
after every current-base and payload hash matched. Parent regeneration matches
all seven changed/generated payloads; the whole SQL check covers 44 bindings.
Schema head is now 52 with 91 permanent installation tables. The
[integrated gates](../test/results/capture52-integrated-contracts.log) pass:
51 packages/269 internal edges, SQL generation, 84 schemas/9,860 assertions
and the architecture catalog. Staged affected races, helper compilation, vet
and actual Go embedded digest pass with the exact integrated51 plus52 bundle;
the handoff retains commands, terminal outcomes and earlier failures.

This adds atomic capture/audit capacity reservation, one irreversible writer
claim per phase, finite reconciliation reads and separate positive completion
for cleanup. Review reproduced a completed-acknowledgement retry failure after
the original audit write cutoff. The included correction uses a separate exact
read-only retained acknowledgement before any active journal or object I/O;
failed/malformed reads never fall through into effects. Original acquisition
and write deadlines are unchanged. The [first actual SQL/S3 run](../test/results/capture52-native-first.log)
fails all seven cases while refreshing retention in the new fixture, before
their audit assertions. Its [terminal report](../test/results/capture52-native-first-check.log)
records exit 1, no selected pass, 1,333 unchanged source hashes and complete
cleanup. The fixture evaluates freshly observed policy/proof against a timestamp
taken before the blocking read. The fixture correction preserves every original
authority deadline and evaluates the newly observed facts at the current time.
The [second native run](../test/results/capture52-native-after-time.log) reaches
admission: legacy/wrong-key rejection and the held-pool deadline case pass,
while five cases fail with `context admission inputs changed`. Its
[terminal report](../test/results/capture52-native-after-time-check.log) records
exit 1, two passing entries, 1,333 unchanged source hashes and complete cleanup.
The actual PostgreSQL log identifies a missing column-level lock privilege for
the new admission role. The [reviewed correction](../test/results/capture52-storage-lock-HANDOFF.md)
adds the existing narrow `UPDATE(source_uid)` lock profile, while preserving
denial of allocation, generation, digest, freshness, insertion and deletion
writes. It also maps dependency failures to unavailable service; a missing
binding still reports changed input. This column privilege is not a claim that
PostgreSQL offers a separate lock-only privilege.

The [corrected native run](../test/results/capture52-native-after-storage-lock.log)
passes all selected cases, including the real role regressions, concurrent
writer claims, original reconciliation cutoffs, passive acknowledgement reuse
and healthy retirement with zero/two-second fixture backup horizons. Its
[terminal report](../test/results/capture52-native-after-storage-lock-check.log)
records exit 0, eleven passing entries, 1,333 unchanged source hashes and complete
cleanup. The Go suite took 112.324 seconds. Admission plus both encrypted audit
acknowledgements took 157.845935 ms under the original live caller interval in
this local fixture; regional collection was outside that measurement. Backup
footprints, source policy and human roots remain explicit fixture inputs.
Public runtime remains disabled. Initial/restore qualification of the new head, source
provisioning, unknown-writer recovery and control-metadata retirement remain open.

## Context capability: native Kubernetes qualification passed

The new [owned API case](../test/integration/context_capability_native_test.go)
uses the concrete capability reader and admission guard with separate
read-only and probe accounts. It verifies actual guard denial, unchanged
dry-run resource versions, fixed cluster/image/recovery-epoch selection,
immediate missing-protection rejection and binding/source replacement denial.
The [native result](../test/results/context-capability-native-first.log)
passes; its [terminal report](../test/results/context-capability-native-first-check.log)
records exit 0, one selected passing entry, 1,315 unchanged source hashes and
complete owned-service cleanup. The Go package took 7.267 seconds. Initial
image qualification and accepted recovery are explicit fixture facts; this
does not qualify installer provisioning or a running regional collector.

The opt-in `make connector-retirement-integration` harness is also integrated.
Its [eleven synthetic harness cases](../test/results/connector-retirement-harness-integrated.log)
pass, including rejection of missing/too-short exact test evidence and removal
of the opt-in from ordinary runs. The real-time native gate remains unrun.

## SQL51 connector retirement: integrated fast native qualification passed

The [thirty-path connector package](../test/results/connector51-HANDOFF.md)
is integrated with schema head 51, the 88-table installation inventory and
regenerated SQL. Parent integration preserved the existing `processing-result/v1`
MAC domain: the frozen candidate omitted it, and the
[before regression](../test/results/connector51-processing-mac-before.log)
reproduced three existing privacy-workflow failures. The corrected
[six-package race run](../test/results/connector51-integrated-race.log) returns
0, including those workflows and the actual embedded 51-migration digest
`8c01f3a8ec8632900871388b2c03ac01692dc7a4e40057d8a087a66fc4358396`.
External fixture cases skip in that ordinary Go run. The
[integrated contract checks](../test/results/connector51-integrated-contracts.log)
return 0: 42 generated SQL files match, 51 packages/268 internal edges pass,
84 canonical schemas/9,845 assertions pass, and the architecture catalog passes.

Each accepted connector cohort now reserves its own bounded retirement
operation before ordinary admissions can spend that capacity. Restriction
commits independently of encrypted audit; unknown outcomes retain original
identity, dates and spend. SQL51 adds no public collection or disclosure route.
The [actual SQL/S3 fast run](../test/results/connector51-fast-first.log) passes
prepaid retirement, original connector/backing behavior and both existing
processing restriction/native-output cases. Its
[terminal report](../test/results/connector51-fast-first-check.log) records
exit 0, nine passing entries, 1,314 unchanged source hashes and complete owned
cleanup; the Go package took 39.147 seconds. Current protected source/issuer
facts remain explicit fixture inputs. Real-time ticket cleanup and schema51
installation/recovery qualification remain pending. The separate maximum-duration admission
boundary and final profile/source/root teardown are also unqualified; schema50
results below do not establish those outcomes.

## Corrected full custody baseline passed

The [full schema50 custody rerun](../test/results/custody50-final-after-worker-facets.log)
now passes, including the worker cases that previously failed for missing
processing-state reads. Its [terminal report](../test/results/custody50-final-after-worker-facets-check.log)
records exit 0, 303 passing entries, 1,296 unchanged source hashes and complete
owned-service cleanup; the Go suite took 395.413 seconds. It covers actual
SQL/S3/TLS custody, current permissions, constrained key use, worker admission,
native transfer, cancellation/history accounting and automation acceptance.
Fixture identity/installation authority remains explicit, so this is component
regression evidence, not an installed browser/MCP workflow. The separate
[database recovery baseline](../test/results/database-recovery50-after-bootstrap.log)
also passes actual initial, PostgreSQL process restart and logical restore
phases. Its [terminal report](../test/results/database-recovery50-after-bootstrap-check.log)
records exit 0, three passing entries, the same 1,296 unchanged hashes and
complete cleanup. It verifies the incarnation fence; it does not implement
operator-authorized restore activation. Staged SQL51/52 and bootstrap-v3 work is
not part of either result.

## All four private installation commands: native command-chain qualification passed

The [nine-path scratch/runner package](../test/results/bootstrap-chain-HANDOFF.md)
is integrated after verifying every original and payload hash. Kubernetes'
native memory-backed scratch mount now contains an exact process-owned `0700`
projection child; the existing private-file and exclusive-lock checks remain.
No privileged initialization or change to the v2 admission guard is involved.
The [affected integrated race tests](../test/results/bootstrap-chain-integrated-race.log),
three selector regressions and [specification/architecture checks](../test/results/bootstrap-chain-integrated-contracts.log)
pass. The preserved before regression rejects the former direct shared-volume
composition at the unchanged private-directory gate.

The [actual empty-database command-chain run](../test/results/bootstrap-chain-native-first.log)
passes all four compiled commands in a Restricted Pod with native tmpfs,
fsGroup and sequential subPath mounts. Product code creates its own original
manager/credentials/projections, initializes the exact compiled schema50 bundle,
activates through the original Pod, completes eight-step handover and positively
retires the manager's privileges, sessions and login. Independent checks verify
the encrypted immutable activation audit. After the fixture removes its
operator-owned setup inputs and revokes its supplied issuer token, a fresh Pod
runs all four commands successfully with original identities/progress unchanged.
The [terminal report](../test/results/bootstrap-chain-native-first-check.log)
records exit 0, two passing entries, 1,296 unchanged source hashes and complete
owned-lab cleanup; the Go package took 249.300 seconds. The original activation
Pod UID and exact compiled image digest are retained in the test log.

The fixture supplies the initial administrator and upstream SQL/S3/OpenBao
services; it supplies no synthetic manager receipt, completed schema, activation
flag or recovery transition. This qualifies healthy first-installation command
composition, not restart/restore recovery or the full investigation product.
The v2 guard still retains managed SQL/provider source copies and the broad seed.
Positive copy cleanup under a fresh explicit v3 capability, official Helm runner
packaging, installed public workflows and broader regression remain work in
progress. Public and chart runtime remain disabled.

## Bootstrap commands integrated; broad custody exposed missing fence reads

The [integrated repository checks](../test/results/bootstrap-command-integrated-gates.log)
pass vet, every Go race suite, the 51-package/268-edge dependency check and
41 matching generated SQL files. The same invocation then fails specification
validation because the new provider-name definition used fragment-only schema
references, which this repository's offline registry does not accept. Replacing
those five references with the existing canonical schema ID preserves validation;
the [corrected contract run](../test/results/bootstrap-command-contracts-after.log)
passes 84 schemas, 9,832 assertions and the architecture catalog. This correction
does not change runtime code or repeat the already-passing Go suites.

The [28-path bootstrap package](../test/results/bootstrap-command-HANDOFF.md)
is integrated after verifying every original/payload hash and ten source
dependencies. It adds the four private command phases, bounded observation
credential replacement and v2 passive-history routing before broad setup reads.
The staged race/vet/schema results are retained in the handoff. The first
[real Kubernetes passive-replay run](../test/results/bootstrap-passive-native-first.log)
fails while constructing the original preparation projection, with unchanged
sources and complete lab cleanup. The guard-only fixture reused duplicate
provider role/policy names that the eventual provider profile correctly rejects.
Bootstrap's earlier validation had only checked string length, so this is also
a product early-validation gap. The [new before regression](../test/results/bootstrap-provider-names-before.log)
reproduces acceptance of duplicate, reserved and malformed provider names before
effects. Static input and final profile now share the strict name validator;
fixtures use distinct names and the canonical schema carries the same name
limits. The [corrected affected race run](../test/results/bootstrap-provider-names-after.log)
passes; the [native rerun](../test/results/bootstrap-passive-native-after.log)
also passes original seed/guard/projection, a lost committed history CREATE,
exact restart recovery without another CREATE, metadata-only replay and native
locator/history mutation denial. Its
[terminal report](../test/results/bootstrap-passive-native-after-check.log)
records exit 0, three passing entries, 1,293 unchanged source hashes and complete
cleanup. This API test explicitly supplies a synthetic SQL manager receipt and
does not qualify SQL activation or manager retirement. Restricted tmpfs
runner preparation, complete command-chain qualification and managed credential
copy deletion remain separate work. Helm/public runtime stays disabled.

The [full schema50 custody run](../test/results/custody50-full.log) failed in
seventeen worker enrollment/active-owner cases while recording 285 passing test
entries. Its [terminal report](../test/results/custody50-full-check.log) confirms
1,279 unchanged source hashes and complete owned-lab cleanup. Actual PostgreSQL
errors identify missing `processing_root` reads: the existing enrollment,
activation and active-owner test roles lacked SQL50's three read-only processing
tables used by their current download fence. The fixture grants now include
only those reads; added native assertions retain denied state mutation and no
current-processing access for historical audit/passive locator roles. The
affected [native rerun](../test/results/processing50-worker-facets-after.log)
now passes all selected worker cases and both processing cases. Its
[terminal report](../test/results/processing50-worker-facets-after-check.log)
records exit 0, 36 passing entries, 1,292 unchanged source hashes and complete
cleanup. This includes the actual encrypted SQL/S3/key-service and two-hop TLS
native exchange with explicitly synthetic peer/Pod/issuer authority. No runtime
authority check was bypassed. The broader suite still needs a final rerun.

## Schema50 initialization through original activation: native qualification passed

The [fresh empty-database run](../test/results/initial-schema-handover50.log)
uses the actual protected schema loader, all embedded migrations through 50,
the original compiled activation Pod, encrypted activation audit and the eight
handover cleanup steps. It rejects the mismatched original database incarnation
before active preparation, then verifies passive reopening with setup
credentials unavailable. The [terminal report](../test/results/initial-schema-handover50-check.log)
records exit 0, thirteen passing entries, 1,279 unchanged source hashes and
complete owned-lab cleanup. The actual activation image digest and Pod UID are
recorded in the test log; no replacement workload supplied the success.

Bootstrap identities, original SQL manager and provider inputs remain explicit
fixture inputs. The loader executes in the test process; activation executes in
the actual Pod. This healthy initial-installation result does not qualify a
physical database restart/restore, the staged bootstrap command chain, automatic
Helm provisioning or the complete investigation workflow. Broader custody and
recovery regressions remain next alongside staged installer/retirement work.

## Context capability and request connection: integrated, runtime disabled

The [fourteen-file checkpoint](../test/results/context-capability-HANDOFF.md)
is integrated after every original and payload hash was verified. The
[capability contract](architecture/context-capability.md) supplies the same
protected immutable collector/projection tuple to preview and execution, exact
accepted-intent lookup and a request-owned connection to the existing regional
runner. Acknowledged intent reuse performs no new object write. Historical
accepted replay remains passive; pending legacy intents cannot start through
this connection. The SQL schema stays at 50.

The [full integrated gates](../test/results/processing50-capability-final-gates.log)
return 0: repository vet and every Go race suite, all embedded contracts,
51-package/268-edge architecture checks, 41 matching generated SQL files,
81 canonical schemas and specification/architecture checks. These ordinary Go
tests do not execute the external fixtures. This source package does not enable
a public collection constructor.
The durable intent writer lifecycle, explicit fresh same-key acquisition
continuation, regional start transport, installed role composition and native
qualification remain required. Subagents are completing staged installer and
connector retirement work while their bounded cached checks run separately.

## Current processing and native placement: SQL50 integrated

The [combined source package](../test/results/processing50-combined-HANDOFF.md)
is integrated after all 81 original/payload hashes were checked. It preserves
SQL49's private connector actors, lifecycle duties and backing-acceptance audit
classification. The current schema is 50 with 87 permanent inventory tables;
local SQL generation returned 0. The original isolated regressions and review
remain in the [source handoff](../test/results/processing50-original-HANDOFF.md).

[ADR-127](decisions/127-current-processing-and-download-placement.md) adds
explicitly initialized durable processing restrictions, verified context lineage,
prepaid independently audited release and exact client/installed-route policy.
Ordinary case metadata and native download effects consume the current decision;
new publication and capacity renewal cannot erase restrictions or extend original
history dates. Unknown state and unsupported ancestry deny.

The [integrated affected race suites](../test/results/processing50-integrated-race.log)
pass for thirteen packages; the [corrected contract checks](../test/results/processing50-contracts-after.log)
pass 80 schemas and the architecture catalog. The initial contract run rejected
relative schema references; using the schema's existing canonical ID fixed the
references without relaxing validation. Kubernetes adapter races, integration
compilation and affected vet also pass.

The [first actual SQL/S3 run](../test/results/processing50-native-first.log)
passes connector renewal/exhausted-source handling and processing restriction,
immutable-date renewal and prepaid release. The transfer case fails; its helper
initially hid the exact failure location. The [focused diagnostic](../test/results/processing50-native-transfer-diagnostic.log)
reaches publication and prepared-download audit, then rejects an unchanged
round-tripped audit intent. Comparing Go timestamp representation treated
process-local monotonic clock data as persisted identity. The
[failing-before unit regression](../test/results/download-audit-equality-before.log)
and [passing affected race suites](../test/results/download-audit-equality-after.log)
cover the correction: exact time instants and every other field stay binding.
The correction changes no authority, deadline, accounting or wire format.
The [combined rerun after the time fix](../test/results/processing50-native-equality-after.log)
also identified a fixture connection leak: connector child tests retained their
SQL pools until the entire parent suite ended, exhausting the unchanged
48-connection lab. Child-owned closure fixes that leak without changing server
capacity, roles or product behavior. The [corrected selected run](../test/results/processing50-native-pools-after.log)
now passes connector renewal plus both processing cases. Its
[terminal report](../test/results/processing50-native-pools-after-check.log)
records exit 0, five passing entries, 1,270 unchanged source hashes and complete
cleanup. Restricting an acknowledged prepaid batch blocks its stale proof and
new reservations; release permits the exact original batch without refund,
replacement or extra output. This is real SQL/S3 qualification, not a complete
HTTP/browser download or production installation.

The fresh schema-to-handover test now passes as recorded above; broader
qualification remains required.
Production source/backing provisioning,
business-history retirement, operator UI and public role composition are still
unfinished; this component does not enable Helm or public evidence access.

## Connector renewal and bootstrap guard: native corrections qualified

The [complete selected connector run](../test/results/connector49-fast-qualified.log)
now passes actual SQL/S3 process admission, distinct client/server activation,
backing continuation, original-date preservation and both exhausted-source
close/promotion cases. The [terminal report](../test/results/connector49-fast-qualified-check.log)
records exit 0, 1,236 unchanged source hashes and complete cleanup. Protected
source/Pod/issuer/backing inputs remain explicitly synthetic. Installed issuer
composition, prepaid historical retirement and the real minimum-time lifecycle
test remain unfinished.

The [corrected native bootstrap guard](../test/results/bootstrap-guard-native-after.log)
passes eleven named entries against Kubernetes, including rejection of the
original invalid expression, exact private creation/update, namespace and RBAC
protection, unrelated-name behavior, independent dry-run observation and token
audience/lifetime/anchor restrictions. The [terminal report](../test/results/bootstrap-guard-native-after-check.log)
records exit 0, 1,237 unchanged source hashes and complete cleanup of both owned
clusters. This fixture exercises the actual guard and observer credentials; it
does not provision the private seed, SQL/provider credentials or full installer.

The [role-name correction](../test/results/connector-role-fixture-HANDOFF.md)
preserves the complete deterministic UUID. The [variable correction](../test/results/bootstrap-variables-HANDOFF.md)
removes three unused policy declarations while retaining the original rule
expressions and subresource restrictions. Both have retained failing-before
regressions. The latter's first integration compilation overlapped the two-file
fixture integration and failed; the stable-tree compile and vet passed. All
earlier actual-service failures remain recorded below.

Specification and architecture checks pass in the
[contract log](../test/results/connector-overlap-bootstrap-contracts.log).
The [combined final gates](../test/results/connector-bootstrap-final-gates.log)
return 0: repository vet and every Go race suite, embedded contracts, 51-package
ownership/dependency checks, 40 matching generated SQL files, 79 canonical
schemas and the specification/architecture checks. These ordinary Go tests do
not rerun the external fixtures described separately above. The next native
composition is the original schema-to-handover case with the added final SQL
incarnation binding. SQL50 has a reviewed combined source candidate, but is not
integrated; its actual processing tests and fresh schema inventory remain
required. Public installation, capture and download composition remain disabled.

The [first-context integration map](reviews/first-context-integration.md) now
identifies concrete remaining connections: protected capability discovery,
exact intent auditing and still-live collection start, download allocation/runtime
adapters, authenticated content GET and public role composition. A subsequent
source review confirms that the old capture-intent object writer lacks a durable
pre-I/O claim for uncertain writes. Acknowledged-receipt reuse alone cannot fix
that lifecycle; its minimal durable correction is being designed before public
enablement. These are implementation findings, not completed user workflows.

## Original schema binding passes; connector and bootstrap follow-ups remain

The corrected [schema-consumption SQL run](../test/results/schema-consumption-after.log)
passes fourteen named entries, including changed database/postmaster rejection,
original unaudited activation and exact scoped-role cleanup. Its
[terminal report](../test/results/schema-consumption-after-check.log) records
exit 0, 1,235 unchanged source hashes and complete cleanup. This uses fixture
protected roots and does not qualify production restart/restore.

The [connector overlap rerun](../test/results/connector49-overlap-after.log)
reaches real SQL/S3 client/server activation and backing continuation, resolving
the earlier issuance failure. Two later exhausted-source subcases fail because
their fixture truncates away the unique suffix of its role identifiers. The
[terminal report](../test/results/connector49-overlap-after-check.log) records
exit 1, unchanged sources and complete cleanup; the full connector selection
remains unqualified pending the test-only naming correction.

The [first native bootstrap guard run](../test/results/bootstrap-guard-native-first.log)
confirms actual API rejection of the original variable-dependent match condition.
It then rejects the corrected policy's unused `namespace` variable as an invalid
CEL identifier. The [terminal report](../test/results/bootstrap-guard-native-first-check.log)
records exit 1, unchanged sources and complete cleanup. Removal of the now-unused
declarations is being prepared; no native enforcement success is claimed yet.

## Connector observation overlap: regression reproduced and correction integrated

The [historical permit correction](../test/results/connector-overlap-HANDOFF.md)
reproduces the generic issuance failure in the actual persisted-result decoder,
both coordinator purposes and the X.509 verifier. Current observations obtained
sequentially can legitimately start after the immutable request start. Historical
validation now checks the original intervals' intersection; actual signing and
delivery retain current authority and the original expiry limits.

All nine original/payload hashes were verified before integration. The retained
[failing-before tests](../test/results/connector-overlap-before.log) exit 1; the
[five staged package race suites](../test/results/connector-overlap-after-race.log),
vet and integration compilation pass. The actual SQL/S3 connector rerun remains
required before attributing the previous native failure solely to this defect.
The one-path schema fixture cleanup correction is also integrated: it retires
the exact roles through their original manager before dropping them. Neither
correction enables public runtime or completes connector lifecycle qualification.

## Generated SQL manager and positive retirement: native qualification passed

The [owned PostgreSQL/OpenBao/S3 manager run](../test/results/initial-bootstrap-manager-first.log)
passes its parent and three named subcases in 9.029 seconds. It creates the actual
finite original manager, initializes a separate empty database, provisions the
existing purpose/history roles and verifies encrypted activation. It also proves
that changing login flags alone leaves an existing session alive, then exercises
exact history-grant transfer and positive session/login closure. The [terminal report](../test/results/initial-bootstrap-manager-first-check.log)
records exit 0, 1,230 unchanged source hashes and complete cleanup. Kubernetes
seed, witness and history-read authority remain synthetic in this SQL fixture.

The separate [schema-consumption SQL run](../test/results/schema-consumption-first.log)
rejects both wrong database and earlier postmaster pins without activation rows,
but exits 1 because its new scoped-role fixture cleanup fails. Its [terminal report](../test/results/schema-consumption-first-check.log)
records unchanged sources and successful outer lab cleanup. PostgreSQL's retained
diagnostics identify remaining manager-origin grant dependencies; the fixture
must use the existing exact role-retirement facet before dropping those roles.
No successful full schema-consumption run is claimed yet.

An independent source review also found that the new bootstrap admission match
condition uses policy variables where Kubernetes permits only earlier request
context. A request-only correction and actual API regression are being staged;
the full Kubernetes bootstrap producer remains unqualified and disabled.

## Connector SQL49 native fast qualification: first failure retained

The [first real SQL/S3 connector run](../test/results/connector49-fast-first.log)
fails at initial client issuance with the generic fleet error text
"current signing trust unavailable", before
the intended paired activation/renewal matrix. The [terminal report](../test/results/connector49-fast-first-check.log)
records exit 1, 1,230 unchanged source hashes and complete cleanup. No native
connector activation or renewal success is claimed; the exact underlying
issuance boundary is not yet identified. Diagnosis preserves source, role,
recovery and deadline checks.

Integrated [SQL49 contract/SQL generation gates](../test/results/connector49-integrated-contracts.log),
[seven affected package race suites](../test/results/connector49-integrated-race.log)
and [Kubernetes connector races, integration compilation and vet](../test/results/connector49-integrated-targeted.log)
pass. The later [combined bootstrap/schema contract gate](../test/results/bootstrap-schema-integrated-contracts.log)
also passes. None substitutes for the failed external-service case.

## Original schema consumption and generated bootstrap inputs: integrated

The verified [16-path schema correction](../test/results/schema-consumption-HANDOFF.md)
now checks completed schema provenance on direct active preparation and carries
its database-incarnation binding through the protected activation projection
into each SQL effect. Completed passive reopening still precedes setup credential
loads. Retained failing-before decoder/producer tests reproduce the missing
binding; staged corrected races, vet, compilation and schema checks pass.

The disjoint [20-path bootstrap checkpoint](../test/results/initial-bootstrap-HANDOFF.md)
adds guarded seed/projection generation and finite original SQL-manager
creation/retirement. All base, payload and dependency hashes were verified before
integration. Its staged focused races/vet and canonical schema checks pass.
Real SQL tests for both changes and combined native schema-to-handover remain
unrun on this source. The manager test requires the fleet harness's OpenBao
fixture. Command/file composition, full bootstrap-to-Pod qualification, official
Helm runtime packaging and final deletion of managed credential copies remain
unfinished; no public runtime is enabled.

## Connector process identity and renewal: SQL49 component integrated

The verified [62-path source package](../test/results/connector49-HANDOFF.md)
is integrated, with generated queries rebuilt locally. The shared schema head is
49 and first-installation inventory contains 83 permanent tables. New connector
processes retain a stable logical account while using separate client/server
keys, exact activated-certificate lookup and independently audited backing
renewal. Six private SQL duties isolate this work from human investigation audit.
An admitted backing candidate prepays its exact terminal close/promotion so
ordinary transition-budget exhaustion cannot strand it.

Staged affected races/vet and local SQLc generation pass; integrated checks and
the selected real SQL/S3 fixture remain pending at this checkpoint. Protected
source/Pod/provider/backing facts in that fixture are explicitly synthetic. This
does not qualify installed enrollment, complete finite retirement or the actual
minimum-time renewal/cleanup case. Prepaid historical retirement tickets and
the initial-schema incarnation correction remain separate active work.

## Initial schema integrated gates: passing

The [full Go gate](../test/results/initial-schema-full-go.log) passes embedded
contracts, repository vet, every Go race suite and dependency ownership
(51 packages, 264 internal edges). The [detailed vulnerability scan](../test/results/initial-schema-vulnerabilities-verbose.log)
reports no affected code or imported packages. Its sole module-level advisory,
GO-2026-5932, concerns the unimported OpenPGP package; the passing architecture
gate explicitly rejects importing that package. The [specification and architecture gates](../test/results/initial-schema-qualified-contracts.log)
also pass. These results cover the healthy schema/handover checkpoint below,
before the pending original-incarnation consumption correction.

## Empty database through original installation handover: native composition passed

The [composed real-service run](../test/results/initial-schema-handover-first.log)
passes twelve named entries in 193.961 seconds. The harness starts with no schema
or application grants; the actual protected schema loader runs the embedded
migrations, replays its original completed binding and removes its distinct DDL
projection before preparation. The original activation Pod then completes SQL
activation, independent encrypted audit verification, all eight cleanup steps
and passive reopening without setup credentials. The [terminal report](../test/results/initial-schema-handover-first-check.log)
records exit 0, 1,157 unchanged source hashes and complete cleanup.

This is a healthy-path qualification with fixture-supplied bootstrap identities,
manager and provider inputs. The schema loader runs in the test process; the
activation command runs in its original compiled Pod. A separate review found
that direct active preparation still needs the completed schema's original
database-incarnation binding carried into its final SQL effects. That correction,
automatic bootstrap provisioning and complete installed public workflows remain
pending; this run does not qualify restart/restore or enable the chart.

## Initial schema metadata correction: native PostgreSQL qualification passed

The [corrected selected PostgreSQL run](../test/results/initial-schema-metadata-after.log)
passes the parent and ten named subcases: original-prefix recovery and lost
completion, exact manager privileges, hostile metadata/history, changed database
incarnation, expired authority, held-lock rejection and read-only completion after
child-role creation. The [terminal report](../test/results/initial-schema-metadata-after-check.log)
records exit 0, 1,157 unchanged source hashes and complete cleanup. The validator
now requires PostgreSQL18's exact primary-key plus four NOT NULL constraints;
extra checks, missing nullability and a different primary-key column reject.
The earlier failed runs remain below. This qualifies the SQL component with a
synthetic protected root; native Kubernetes schema-to-activation composition,
automatic bootstrap provisioning and the public workflow remain pending.

## Initial schema metadata: actual PostgreSQL constraint mismatch confirmed

The [bounded diagnostic rerun](../test/results/initial-schema-metadata-before.log)
confirms one retained original claim, version zero and exactly one primary-key
plus four NOT NULL constraints in PostgreSQL's metadata catalog. The validator
incorrectly expected only one constraint row. The [terminal report](../test/results/initial-schema-metadata-before-check.log)
records the expected failure, 1,157 unchanged source hashes and complete cleanup.
Dependent checks now stop when schema initialization fails, preventing invalid
baseline state from appearing to qualify later negative cases. The exact
constraint-set correction and hostile constraint tests are being prepared;
native migration and installation success remain unclaimed.

## Initial schema native SQL: first failure retained

The [first selected real PostgreSQL run](../test/results/initial-schema-first.log)
fails before retaining the expected first migration prefix. Later dependent
cases consequently lack a completed schema; their negative results are not
independent qualification. The [terminal report](../test/results/initial-schema-first-check.log)
records exit 1, 1,157 unchanged source hashes and complete lab cleanup. The
metadata constraint verifier is the next diagnosis; no schema initialization
success is claimed. The [integrated specification and architecture gates](../test/results/initial-schema-integrated-contracts.log)
pass, but do not establish native migration behavior. The composed installation
run remains pending until this prerequisite passes.

## Separate initial schema loader: integrated, native qualification pending

The verified 23-path [ADR-130 package](../test/results/initial-schema-HANDOFF.md)
and seven-path [schema-to-handover fixture](../test/results/schema-handover-HANDOFF.md)
are integrated. The private schema role applies only the binary's embedded
migrations under its original protected database-incarnation claim; preparation
and activation receive no DDL credentials. An interrupted post-schema setup has
a separate read-only completion check, and completed installation retains the
existing passive history path. All root observations preserve their original
deadlines, including an already-started Goose operation.

Staged affected race/vet, schema and dependency checks pass; the new composed
fixture compiles and its fifteen synthetic harness checks pass. Real SQL and the
empty-database schema-to-activation run remain unrun at this checkpoint. These
tests must distinguish fixture-supplied bootstrap/provider inputs from actual
schema/preparation behavior. Source inventories now include embedded migration
Go files. The official chart and public investigation workflow remain disabled;
automatic bootstrap provisioning and general restart/restore are unfinished.

## Combined handover corrections: healthy native installation passed

The [combined real-service run](../test/results/initial-handover-conflicts-qualified.log)
passes twelve named entries, including original image/Pod activation, independent
SQL/encrypted-audit verification, eight cleanup acknowledgements and passive
reopening after setup credentials are unavailable. The [terminal report](../test/results/initial-handover-conflicts-qualified-check.log)
records exit 0, 1,146 unchanged source hashes and complete lab cleanup. This source
includes both bounded confirmed-conflict handling and the Pod-before-SQL
observation correction. Synthetic status-only native API tests qualify the exact
HTTP409 bodies; this healthy actual-loader run does not inject a conflict into
the original activation effects. The separate synthetic TLS suite covers that
retry state machine. Integrated [specification, architecture and Go dependency checks](../test/results/handover-conflicts-integrated-contracts.log)
pass. The [full integrated Go gate](../test/results/handover-conflicts-full-go.log)
also exits 0: embedded/schema checks, repository vet, every Go race suite and
dependency ownership pass on this combined checkpoint. Fixture-supplied bootstrap
inputs, general exceptional/restart/restore recovery, production provisioning and
public workflows remain separate requirements.

## Bounded installation conflict recovery: integrated, combined qualification pending

The ten-path [confirmed-conflict package](../test/results/handover-conflicts-HANDOFF.md)
is integrated after verifying every base and payload hash. Original staging and
Pod launch may make one second conditional UPDATE only after the real HTTP409
response is durably acknowledged and a separate retry claim succeeds. Original
identity, credential limits and the five-second interval remain unchanged.
Unknown replies and already recorded retries permit observation only. The
retained old-method regression fails as expected; staged affected race/vet,
integration compilation and eighteen canonical schema cases pass. Native Status
shape was measured separately; actual injected-conflict execution is not yet
qualified. The combined source also includes the observation-order correction
below; repository gates and the original-command native handover are next.

## Successful activation observation race: correction integrated

The two-path [observation-order correction](../test/results/handover-observation-HANDOFF.md)
is integrated with verified base/payload hashes. The supervisor now observes the
original Pod before reading independent SQL history, preventing a successful
terminal Pod from being paired with a pre-commit SQL snapshot. The returned
history deadline is explicitly capped by the original Pod and caller bounds.
The extracted original order and missing output cap each have retained failing
regressions; the staged complete bootstrap race suite and vet pass. No Pod result
substitutes for independent SQL activation. The parent will qualify the combined
runtime with the pending bounded-conflict correction; the earlier native pass
below remains evidence for its exact earlier source.

## Original activation handover and healthy cleanup: native composition passed

The [owned real-service handover run](../test/results/initial-handover-history-qualified.log)
passes all twelve named entries (119.161 seconds including Go overhead). It
executes the actual `initial-prepare` loader and the original `initial-install`
Pod, checks the exact compiled image and zero exit/restarts, verifies original
SQL activation and the immutable encrypted S3 audit, completes all eight ordered
retirement steps and reopens history after setup credentials are unavailable.
The [terminal report](../test/results/initial-handover-history-qualified-check.log)
records exit 0, 1,143 unchanged source hashes and complete lab cleanup.

Separate synthetic admission cases in that run establish exact native HTTP409
Status bodies for status-only Pod and admission-policy revision changes, plus
retirement marker/spec/UID/deletion protections. The wrong-node case identifies
Kubernetes NodeRestriction as the earlier denial. These synthetic statuses never
replace the actual activation Pod's observed outcome.

This is a qualified healthy installation component with fixture-supplied
bootstrap identities, provider roots/configuration and S3 credentials. It does
not supply general unknown-request recovery, restart/restore activation, complete
production provisioning or an enabled Helm/public investigation workflow.
Bounded confirmed-conflict recovery, connector lifecycle and processing
restrictions remain active continuation work. Full integrated Go gates are
now [passing](../test/results/handover-history-full-go.log), including repository
vet, all Go race tests, embedded/schema consistency checks and Go dependency
ownership. The [specification and architecture gates](../test/results/handover-history-final-contracts.log)
also pass. A subsequent source review identified a separate SQL-before-Pod
observation race; its deterministic regression and correction are being staged
without rewriting this passing native checkpoint's scope.

## Original history manager: selected real PostgreSQL qualification passed

The [corrected selected PostgreSQL suite](../test/results/initial-history-qualified.log)
passes all twelve named entries, including original history-role creation/replay,
passive SELECT-only access and the membership/privilege/identity mutations.
The final hostile case now establishes a real manager-attributed grant to a
separate NOLOGIN fixture member, verifies its catalog attribution and tests
product rejection before removing that exact grant. The [fixture-only correction](../test/results/history-grant-fixture-HANDOFF.md)
does not alter product permissions. The [terminal report](../test/results/initial-history-qualified-check.log)
records exit 0, 1,143 unchanged source hashes and complete cleanup. This qualifies
the bounded history-role component; actual original-Pod activation, cleanup and
passive installer replay still require the composed handover run.

## Original history manager correction: integrated, native fixture refinement pending

The thirteen-path [history-manager correction](../test/results/history-manager-HANDOFF.md)
is integrated with verified original/payload hashes. New explicit handover plans
pin the original SQL manager name/OID before declaration; passive verification
accepts only its exact incoming bootstrap-superuser administrative grant. The
loader preflights that identity without changing the completed passive path.
The parent fixture now provisions and pins the actual synthetic manager before
creating guards/root and adds separate native Pod/VAP conflict-wire checks.
Integrated compilation, affected vet and [contract/dependency gates](../test/results/handover-history-integrated-contracts.log)
pass.

The [first corrected real PostgreSQL run](../test/results/initial-history-after.log)
passes original creation/replay and passive access, along with ten named
subcases covering platform membership behavior, changed options, missing/extra
memberships, extra writes, replaced manager identity and passive access after
manager privilege retirement. The suite exits 1 because one adversarial
fixture's manager self-grant is rejected before reaching the product verifier;
its mutation must be corrected. The [terminal report](../test/results/initial-history-after-check.log)
records 1,143 unchanged hashes and complete cleanup. Full selected-suite and
actual activation/handover success remain unclaimed.

## Installation history role: isolated native failure reproduced

The six-path [diagnostic package](../test/results/history-diagnostic-HANDOFF.md)
is integrated with verified original/payload hashes and retained focused race/vet
results. It separates history-role creation from final binding and exposes only
a fixed phase, validated SQLSTATE and cancellation flag. The [selected real
PostgreSQL run](../test/results/initial-history-before.log) fails at
`history-role-privileges`, with no SQLSTATE and no deadline expiry (0.311 seconds
including Go overhead). The REVOKE statement itself did not return an error;
the exact remaining catalog state still needs confirmation before changing the
contract. The [terminal report](../test/results/initial-history-before-check.log)
records 1,143 unchanged source hashes and complete lab cleanup. No installation
activation success follows from this diagnostic.

The [separate catalog probe](../test/results/initial-history-membership-before.log)
now confirms exactly one original-manager membership before and after REVOKE,
with the bootstrap grantor and ADMIN-only options unchanged. It rolls back its
synthetic role, then reproduces the unchanged product verifier failure. The
[terminal report](../test/results/initial-history-membership-before-check.log)
records one passing diagnostic subcase, the expected product failure, 1,143
unchanged hashes and complete cleanup. This matches PostgreSQL's documented
non-superuser creator behavior. The correction will pin that original manager
name/OID in new handover plans and accept only its exact incoming management
grant; it must retain the passive login's restricted rights and reject all other
memberships. Implementation and after-fix qualification remain pending.

## Original installation handover: integrated, native qualification pending

The 42-path [ADR-129 package](../test/results/handover-implementation-HANDOFF.md)
and five-path [native fixture](../test/results/handover-fixture-HANDOFF.md)
are integrated after verifying every original and payload hash. The supervisor
now composes original Pod handover, historical activation observation and eight
ordered cleanup steps. A separate SELECT-only history login supports passive
replay after temporary credentials are retired. Legacy profiles retain their
original encodings and guards; the chart remains disabled.

Staged affected race tests, vet and canonical schema checks pass. The combined
parent fixture compiles and passes vet against all 36 exact frozen Go dependency
paths. The new `make initial-handover-integration` owns a fresh database and exact
test selection. Its separate synthetic API-status admission checks are not
actual activation evidence; the other fixture path must execute the original
compiled image and verify its SQL and encrypted object audit. Integrated [specification, architecture and Go dependency gates](../test/results/handover-integrated-contracts.log)
pass. The [first real-service handover run](../test/results/initial-handover-first.log)
exits 1 (6.932 seconds including Go overhead): the separate synthetic admission
fixture incorrectly set a node before removing its scheduling gate, and the
actual constructor then failed at SQL-material preflight before Run. Its
[terminal report](../test/results/initial-handover-first-check.log) records 1,140
unchanged source hashes and complete lab cleanup. The admission fixture is being
corrected without changing the actual activation Pod. The loader failure traces
to using a root-bound credential read merely to compare a fourth password before
Declare. The three-path [preflight correction](../test/results/handover-preflight-HANDOFF.md)
is integrated with matching original/payload hashes and passing focused race/vet
regressions. It compares the fourth password without returning credentials or
manufacturing a preparation record; bound issuance still requires its original
record. The admission fixture now clears its synthetic gate before assignment
and retains only a successful CREATE identity for cleanup. Integration-source
compilation and spec-check pass. The explicit first-installation harness now
creates only its one used cluster; ordinary context selections still create two.
The [corrected run](../test/results/initial-handover-preflight-corrected.log)
passes six admission subcases and advances through constructor preflight into
Run, then fails at `sql-and-providers/history-role-provision` (72.951 seconds
including Go overhead). The wrong-node case is denied earlier by Kubernetes
NodeRestriction; its assertion now identifies that exact rejection instead of
claiming the request reached Asservat's policy. The [terminal report](../test/results/initial-handover-preflight-corrected-check.log)
records 1,140 unchanged source hashes and complete cleanup. History-role SQL
provisioning is the next diagnosis. No activation or complete installation
success is claimed.

## Initial provider provisioning: actual loader and retirement qualification passed

The five-file [retirement response correction](../test/results/provider-retirement-encoding-HANDOFF.md)
is integrated after verifying every original and payload hash. The retained
failing unit regression now passes with the affected race tests and vet. Only
the existing exact invalid-accessor message and its pinned single-error wrapper
are accepted; malformed raw bodies, other errors/statuses and a still-authenticated
original token remain rejected. No deadline, issue retry or permission changed.

The [small real-provider test](../test/results/initial-provider-retirement-corrected.log)
passes all four named entries, including both purpose-specific issue, verification,
revocation and replay paths (1.177 seconds including Go test overhead). The actual
trace confirms the exact wrapped accessor rejection and independent original-token
HTTP 403. Its [terminal report](../test/results/initial-provider-retirement-corrected-check.log)
records 1,123 unchanged source hashes and complete cleanup.

The [full actual-loader fixture](../test/results/initial-provider-loader-qualified.log)
also passes all 19 named entries (100.390 seconds including Go test overhead),
using owned Kubernetes, PostgreSQL and OpenBao services. It exercises fixed-file
loader/Run preparation, replay of the original immutable seven-file projection,
separate live Transit encrypt/decrypt rights, original provider revocation/replay,
and the existing native retirement-denial checks. Its
[terminal report](../test/results/initial-provider-loader-qualified-check.log)
records the same 1,123 unchanged hashes and complete cleanup. Bootstrap identities,
provider configuration and supplied S3 credentials remain fixture inputs. The
original activation Pod stays gated: this qualifies preparation and provider
retirement components, not actual activation or composed installation cleanup.

The integrated [Go vet/race and dependency gates](../test/results/provider-retirement-integrated-code.log)
pass (50 packages, 263 internal edges), as do the
[specification and architecture checks](../test/results/provider-retirement-integrated-contracts.log)
(75 schemas, 49 MCP contracts, 173 examples and 176 requirement/scenario pairs).
These contract counts do not describe enabled runtime interfaces. The continuing installer work covers
the exact original Pod handover, actual activation outcome, passive historical
reconciliation and joined credential/material retirement. Connector renewal and
processing restrictions remain staged parallel work. No public workflow or Helm
runtime is enabled by this checkpoint.

## Initial provider provisioning: role-cap and retirement diagnostic history

The [minimal real-provider regression](../test/results/provider-issuer-fixture-HANDOFF.md)
is integrated and included in the normal fleet suite. Its
[before-fix run](../test/results/initial-provider-issuer-before.log) confirms the
pinned OpenBao role-only child lookup reports a zero `explicit_max_ttl` despite
nonrenewability and finite actual expiry; both product issuance cases reject it.
The [terminal report](../test/results/initial-provider-issuer-before-check.log)
records 1,121 unchanged source hashes and complete cleanup.

The four-file [child-role compatibility fix](../test/results/provider-role-cap-HANDOFF.md)
is integrated with verified hashes, a retained failing unit regression, passing
affected races and vet. The issuer still requires a positive explicit cap.
Child admission retains exact current role/ACL, purpose/parent/metadata,
nonrenewability and original issue/expiry checks. No deadline, QPS, issue retry
or permission was changed. The
[after-fix provider run](../test/results/initial-provider-issuer-after.log)
now completes issuance and verification for both purposes, then fails their
revocation-confirmation step (0.146 seconds including Go overhead). Its
[terminal report](../test/results/initial-provider-issuer-after-check.log)
records 1,122 unchanged hashes and complete cleanup. The next diagnostic checks
only bounded static response facts; complete provider retirement and the full
loader rerun remain unqualified.

The [retirement wire diagnostic](../test/results/initial-provider-retirement-diagnostic.log)
now confirms that the actual provider accepts each accessor revocation with HTTP
204. The subsequent accessor lookup returns HTTP 400 with a single error, but
that error does not match the adapter's exact `invalid accessor` string. The
original-token authentication rejection check is therefore not reached. This
locates a provider error-response compatibility issue, not a measured timeout or
revocation refusal. Its [terminal report](../test/results/initial-provider-retirement-diagnostic-check.log)
records one passing shape subcase, two failed retirement cases, 1,122 unchanged
source hashes and complete cleanup. The correction must retain an explicit
qualified invalid-accessor response plus actual rejection of the original token;
arbitrary HTTP 400 is not retirement evidence.

## Initial provider provisioning: integration and diagnostic history

The 25-file [ADR-128 checkpoint](../test/results/initial-provider-stage-HANDOFF.md)
is integrated after exact original and payload hash verification. The actual
private preparation loader now composes original SQL/probe credentials, two
one-use scoped OpenBao issue claims and the fixed seven-file immutable activation
projection. Managed S3 credentials remain explicitly supplied; their local use
deadline is not provider expiry or revocation. The original Pod remains gated.

Staged focused race/vet/schema checks pass. The schema test initially omitted a
canonical dependency while constructing its test fragment; that failure and the
corrected standalone result are retained. No canonical requirement was weakened.
Integrated [specification and architecture checks](../test/results/initial-provider-integrated-contracts.log)
pass (75 schemas, 49 MCP tools and 176 requirement/scenario pairs). The full
integrated [Go vet/race and dependency checks](../test/results/initial-provider-integrated-code.log)
also pass (50 packages, 263 import edges). The first actual
[Kubernetes/PostgreSQL/OpenBao loader run](../test/results/initial-provider-loader-native.log)
fails in constructor preflight with the generic protected-input error, before
credential issuance (31.964 seconds; two setup subcases pass). The
[terminal report](../test/results/initial-provider-loader-native-check.log) records
1,116 unchanged source hashes and complete cleanup. The pinned OpenBao ACL
response then reproduced a strict-decoder incompatibility in a failing unit
regression. The seven-file [correction](../test/results/provider-loader-correction-HANDOFF.md)
accepts documented typed metadata while retaining exact ACL matching, false
template-expansion flags, bounded bodies and rejection of policy expiry. It also
adds fixed phase diagnostics without displaying secret-bearing causes.
Integrated [affected race tests](../test/results/provider-loader-correction-integrated-race.log)
and [contract/dependency gates](../test/results/provider-loader-correction-integrated-contracts.log)
pass. The [corrected native run](../test/results/initial-provider-loader-corrected-native.log)
now passes loader construction but fails in `Run` with the generic permission
configuration error (62.581 seconds; two setup subcases pass). Its
[terminal report](../test/results/initial-provider-loader-corrected-native-check.log)
records 1,118 unchanged hashes and complete cleanup. The fix resolves the
constructor compatibility issue; finer execution-phase diagnostics are required
before the remaining setup failure can be located. The three-file
[execution diagnostics](../test/results/provider-run-diagnostic-HANDOFF.md)
are now integrated with verified original/payload hashes and a passing
[focused race check](../test/results/provider-run-diagnostic-integrated-race.log).
The next [native run](../test/results/initial-provider-run-diagnostic-native.log)
locates the failure at `sql-and-providers/provider-wrap`, after loader,
public-input and SQL preparation succeed (63.642 seconds including Go overhead;
two setup subcases pass). Its
[terminal report](../test/results/initial-provider-run-diagnostic-native-check.log)
records 1,118 unchanged source hashes and complete cleanup. The five-file
[provider timing diagnostics](../test/results/provider-phase-diagnostic-HANDOFF.md)
are subsequently integrated with verified hashes and passing staged race/vet
checks. The [timed native run](../test/results/initial-provider-phase-diagnostic-native.log)
locates the failure inside `provider-issue`: 2,427 ms elapsed, 28,953 ms remaining
on the parent and 2,572 ms on the original operation. This disproves the timeout
hypothesis; the 62.630-second test duration includes cleanup. Its
[terminal report](../test/results/initial-provider-phase-diagnostic-native-check.log)
records 1,120 unchanged source hashes and complete cleanup. Provider response
validation is the next investigation; no process, authority or retry bounds were
changed. No complete provider or installer success is claimed.
Guarded handover, activation observation, composed credential retirement and
unknown-issuance recovery remain required; this checkpoint enables no public
collection or disclosure.

## Combined schema48 qualification passed

The [final full custody run](../test/results/verifier-installer-connector-custody-final.log)
passes all 298 named entries (359.716 seconds including Go test overhead).
Its [terminal report](../test/results/verifier-installer-connector-custody-final-check.log)
records 1,105 unchanged source hashes and complete cleanup. The two overdue
fixtures described below now use qualified current admission while preserving
their original denial assertions; the [targeted rerun](../test/results/operation-overdue-verifier-profile-native-check.log)
also passes both cases. No production guard was relaxed.

The current [first-installation suite](../test/results/verifier-connector-initial-installation-check.log)
passes 16 entries, and [database recovery](../test/results/verifier-connector-recovery-check.log)
passes all three initial, process-restarted and logically restored phases.
Each records the same 1,105 unchanged source hashes and complete cleanup.
The final [specification and architecture gates](../test/results/schema48-final-contracts.log)
also pass (73 schemas, 49 MCP tools and 176 requirement/scenario pairs).
These results qualify the implemented component boundaries, including retained
historical audit spend and scoped SQL provisioning. They do not establish an
installed investigation workflow, production restore orchestration or connector
renewal. Provider provisioning through the actual installer loader, guarded
handover, connector renewal and durable processing restrictions remain active work.

## Initial connector key ownership: integrated

The first [combined full custody run](../test/results/verifier-installer-connector-full-custody.log)
exits 1 with 295 passing entries and two failing overdue-cleanup fixtures. Both
fixtures attempted new admission using a historical unqualified profile, which
SQL48's constructor correctly rejects. The test setup now keeps required v3
backing while leaving overdue cleanup unselected; it retains the original denial
assertion. Actual historical nil/v1/v2 rows remain covered by the separate
migration fixture. Production guards and constructors are unchanged. The failed
run records 1,105 unchanged hashes and complete cleanup. The targeted and full
requalification results are recorded above; the failed result is retained.

The five-file [connector checkpoint](../test/results/connector-initial-stage-HANDOFF.md)
is integrated after original and payload hash checks. It owns one process-local
key/CSR, retains original bootstrap timing and checks independently activated
registration. It also fixes a reproduced TLS callback failure: native preflight
must provide supported signature schemes to a real process-owned callback.
Actual connection verification remains mandatory. Staged race/vet and loopback
TLS/current-revocation tests pass, as do integrated [affected race tests](../test/results/connector-initial-integrated-race.log),
[vet](../test/results/connector-initial-integrated-vet.log) and [Go/specification/architecture checks](../test/results/connector-verifier-installer-contracts.log)
(50 packages, 261 import edges).
Synthetic bootstrap/issuer/registry tests do not qualify production enrollment,
server issuance, renewal or an installed connector. Those remain in progress.

## Original SQL provisioning and prepaid audit verification: integrated

The eighteen-file [original SQL provisioning package](../test/results/initial-sql-provisioning-stage-HANDOFF.md)
and eighteen-file [SQL48/ADR-125 correction](../test/results/operation-verifier-stage-HANDOFF.md)
are integrated after checking every original and payload hash. SQL has been
regenerated. No new permanent table was added, and the strict installation
inventory ordering regression remains covered.

The installer composes current original public/private inputs, a one-use immutable
credential Secret and scoped temporary SQL roles. It retains the original binding
and deadlines across replay; provider credentials, guarded handover and automatic
retirement remain open. The audit correction requires a durable prepaid claim
before certificate verification and retains historical unknown spend. New healthy
admission requires explicit version-three history-budget acceptance, including
zero-backup-horizon configurations. Migration alone grants no such acceptance.

Staged race/vet/schema checks and fixture compilation passed as recorded in the
handoffs. The combined [Go vet/race, dependency and SQL generation checks](../test/results/verifier-installer-combined-code.log)
and [specification, architecture, design and download checks](../test/results/verifier-installer-combined-contracts.log)
now pass. The [actual migration-history fixture](../test/results/operation-verifier-migration-native.log)
passes (15.70 seconds for the selected case); the [native Kubernetes/SQL provisioning fixture](../test/results/initial-sql-provisioning-native.log)
passes all 20 named entries (74.595 seconds including Go test overhead). Both
terminal reports record 1,102 unchanged source hashes and complete cleanup.
Original Secret/role replay, wrong-password refusal and irreversible role retirement
are exercised with the Pod still gated. Fixture bootstrap/material/provider inputs
remain explicit; this is not the installed command or provider handover. Full
custody and current installation/recovery checks remain next. Public runtime stays off.

## Private native listener and schema47: combined qualification passed

The twenty-four-file [ADR-122 listener package](../test/results/native-owner-listener-stage-HANDOFF.md)
is integrated with original and payload hashes verified. It composes optional
private HTTP/2 serving, a distinct audited native port, protected API/topology
inputs and separately credentialed native metadata reads. Historical omitted
fields preserve their original encoding. Staged races, actual listener tests,
schema checks and integration compilation pass. The combined
[Go vet/race, architecture and SQL checks](../test/results/native-owner-stop-combined-code.log)
and [specification/architecture checks](../test/results/native-owner-stop-combined-contracts.log)
also pass (50 packages, 260 import edges, 38 generated SQL files).
The [changed real SQL/S3/listener fixture](../test/results/native-owner-listener-qualified.log)
passes the separately credentialed read facet's mutation denials, exact 352-byte
native file/checksum, SQL completion and three distinct Joined conversations.
Its [terminal report](../test/results/native-owner-listener-qualified-check.log)
records 1,090 unchanged source hashes and complete cleanup. Human/Pod/issuer and
initial backing authority remain explicit fixture inputs. Connector identity/renewal,
protected projection provisioning and public workflow composition remain open.

The new SQL47 tables exposed an inventory-order regression in first activation.
The [real before-fix suite](../test/results/stop-retirement-initial-inventory-before.log)
fails the positive preparation/provisioning cases; its
[terminal report](../test/results/stop-retirement-initial-inventory-before-check.log)
records 1,081 unchanged hashes and complete cleanup. The fixed list retains exact
catalog equality and adds a fast strict-order/duplicate regression. The
[after-fix first-installation suite](../test/results/stop-retirement-initial-inventory-after.log)
now passes all 16 cases, including actual scoped SQL role provisioning/retirement.
The [database recovery suite](../test/results/native-owner-stop-recovery.log)
also passes initial, process-restarted and logically restored phases. Both
terminal reports record 1,090 unchanged hashes and complete cleanup. These are
component qualification, not the complete installed workflow or a production
restore coordinator. Full aggregate custody will run with the separately reviewed
ordinary-audit verifier correction when it is integrated.

## Prepaid Stop retirement: selected provider qualification passed

The twenty-three-file [SQL47/ADR-124 package](../test/results/download-stop-lifecycle-stage-HANDOFF.md)
is integrated after original and payload hash verification. It adds positive
writer completion, finite object/SQL cleanup, independent prepaid certificate
verification and backed cooling history for new explicitly qualified Stop
obligations. Unknown writers stay charged; parent download reservations are
unchanged. Pending reconciliation continues independent eligible records after
a provider failure without renewing its original pass. Staged race/vet and SQL
generation checks are recorded in the handoff; combined gates and actual
PostgreSQL/S3 execution are pending. The schema head is now 47. Combined
[Go vet/race, architecture and SQL generation](../test/results/download-stop-lifecycle-combined-code.log)
pass (50 packages, 260 import edges, 38 generated SQL files), as do the
[specification and architecture contracts](../test/results/download-stop-lifecycle-combined-contracts.log).
The [selected real PostgreSQL/S3 run](../test/results/stop-retirement-native-combined.log)
now passes both strict joined native exchange (10.10 seconds) and the new Stop
retirement/backup-history/unknown-writer case (64.08 seconds). Its
[terminal report](../test/results/stop-retirement-native-combined-check.log) records
two selected passes, 1,081 unchanged source hashes and complete cleanup. This
qualifies the implemented Stop lifecycle and final upstream cancellation fix
under the fixture's explicit synthetic authority/backing boundaries. Full custody,
first-installation/recovery and the subsequent ADR-122 listener remain separate.

The full custody harness now has an explicit 600-second Go/660-second process
budget: the previous full run took about 280 seconds, and the new original-clock
retirement cases add about 65–80 seconds. Selected, fleet, initial-installation
and database-recovery runs retain their 300-second Go limit. Individual authority,
provider and retention deadlines are unchanged. This is an aggregate test budget,
not a runtime permission or a passing result.

The private installer diagnostic run remains a qualification failure. It records
one TokenRequest returning HTTP 422 and no TokenReview, with the original anchor
and irreversible issuance claim retained. The continuity policy currently omits
the exact intended token subresource operation; a bounded correction and negative
cases are in progress. Its [terminal report](../test/results/initial-private-probe-diagnostic-native-check.log)
records 1,066 unchanged source hashes and complete cleanup. No failed issuance
claim is reset or retried. The [three-file correction](../test/results/initial-private-probe-token-admission-HANDOFF.md)
is now integrated with verified hashes. It preserves historical policy bytes
and adds ten native negative cases; its staged races and fixture compilation
pass. The [after-fix native run](../test/results/initial-private-probe-token-native.log)
passes 31 cases, including original-token replay and all ten new scope negatives.
Its [terminal report](../test/results/initial-private-probe-token-native-check.log)
records 1,081 unchanged hashes and complete cleanup. The combined Go gate above
predates this separate Kubernetes policy correction; protected SQL/provider
provisioning and actual installer handover remain required.

## Joined native download and private installation probe

The nine-file [terminal closure correction](../test/results/native-content-closure-HANDOFF.md)
is integrated after original/payload hash verification. Its deterministic real
two-hop HTTP/2 regression fails before the fix and passes afterward. Only an exact
zero-byte final relay marker can use the original checked, monotonically shortened
lease after the hub's own successful retirement. No data, command or new-work
authority is added. Cancellation, expiry, malformed markers and failed writes
retain their negative checks. The [strict real SQL/S3 rerun](../test/results/native-exchange-sql-joined.log)
now verifies the exact 352 native bytes/checksum, SQL completion, original key
spend and three distinct positively Joined worker conversations. Its
[terminal report](../test/results/native-exchange-sql-joined-check.log) records
all 1,060 source hashes unchanged and complete cleanup. This resolves the logged
worker uncertainty below for the tested bounded context path; large artifacts
and installed public downloads remain unqualified.

A subsequent [two-file upstream cancellation correction](../test/results/native-upstream-cancel-HANDOFF.md)
is integrated. The queued relay now retains actual upstream/process cancellation
after buffering a final marker and joins its cancellation callback on close.
Its deterministic real-HTTP/2 case fails before and the full native race suite
passes after. Normal terminal EOF remains distinct from explicit stream closure.
The strict SQL/S3 run above predates this final correction; combined provider
requalification is still required for the latest source.

The nineteen-file [private installation probe checkpoint](../test/results/initial-private-probe-stage-HANDOFF.md)
is integrated with verified hashes and C-21 ownership for pure provider-input
validation. Original private Secret identity, one acknowledged issuance claim,
authenticated token response and unchanged expiry survive replay; an unknown
issuance cannot become another TokenRequest. Historical plans preserve their
compiled protection-policy bytes. Staged races and schema checks pass. Actual
[integrated vet](../test/results/native-private-integrated-vet.log) and
[specification/architecture checks](../test/results/native-private-contracts.log)
pass, replacing the overlay-only vet limitation. The [real Kubernetes run](../test/results/initial-private-probe-native.log)
passes the public-input producer and its protection cases, but private probe
preparation fails with configuration unavailable before the replay assertions.
The overall result is exit 1; the [terminal report](../test/results/initial-private-probe-native-check.log)
records 1,066 unchanged source hashes and complete cleanup. Private probe runtime
qualification is open and targeted diagnosis is in progress. SQL/provider provisioning, credential retirement,
guarded handover and activation remain separate work, and Helm runtime stays off.

Cleanup review separately found repeatable independent certificate verification
after an unavailable acknowledgement in the existing operation-audit lifecycle.
The isolated [failing-before regression](../test/results/operation-verifier-budget-before.log)
demonstrates eight provider calls with zero durable verifier claims. The
[open correction design](../test/results/operation-verifier-budget-open-design.md)
reserves migration48 separately from the Stop lifecycle's migration47. It requires
prepaid independent verification and explicit history-budget compatibility;
neither correction nor runtime qualification is claimed yet.

## Browser/MCP download controls: integrated, combined qualification pending

The forty-six-file SQL46/ADR-119 package is integrated with verified base/payload
hashes; combined SQL has been regenerated at schema head 46 with 76 permanent
tables. Its
[handoff](../test/results/public-context-download-stage-HANDOFF.md) records the
actual staged Go race/vet, browser/MCP, UI and schema checks. Ordinary context
prepare/status/cancel now share the canonical browser/MCP operations. Browser
preparation attaches bounded server-side refresh ownership; status stays read-only.
Every new public download reserves an independent Stop obligation before acquisition,
so exhausted normal operation-audit capacity cannot prevent its original actor
from stopping it. Restriction precedes provider I/O; separate recovery checks
gate the bounded encrypted audit effects. Full Stop retirement and protected
backing issuance remain required. No listener or Helm runtime has been enabled.
The combined [Go vet/race, Go architecture and SQL generation checks](../test/results/public-download-combined-code.log)
pass, including all 49 packages and 37 generated SQL files. Combined
[specification, architecture, design, download and console checks/build](../test/results/public-download-combined-contracts-console.log)
also pass. The console build retains a bundle-size warning; no limit was raised
to hide it. The [selected real PostgreSQL/S3 Stop fixture](../test/results/public-download-stop-selected.log)
passes original-actor cancellation without evidence scopes, exhausted normal
audit capacity, stable replay, separate SQL roles and a recovery-incarnation
mismatch that allows restriction while preventing new audit spend. Its
[terminal report](../test/results/public-download-stop-selected-check.log) records
all 1,058 source hashes unchanged and complete cleanup. Accepted backing and
human identity remain explicit fixture inputs; provider/backup retirement and
installed public composition remain unqualified. The [combined custody suite](../test/results/public-download-combined-custody.log)
also passes all 296 named entries. Its [terminal report](../test/results/public-download-combined-custody-check.log)
records the same 1,058 unchanged source hashes and complete cleanup. This includes
the existing native-exchange test whose final worker uncertainty was only logged;
the explicit qualification limit below still applies.

## Typed installation inputs and deployed native startup: selected cases passed

The thirteen-file ADR-123 package is integrated after all base/payload hash checks.
Its [handoff](../test/results/initial-final-inputs-stage-HANDOFF.md) records staged
race/vet and schema checks. The private preparer creates the nine fixed public
startup/guard resources while retaining original UIDs, one-use effects and a
gated Pod. Private credentials, handover and activation are still separate work.
The parent native-worker fixture now exercises v2 alongside the existing v1
executable: an immutable credential projection, actual TLS and Pod-token checks,
distinct valid nonces, bounded idle backoff and positive retirement. Its operation
admission is explicitly an empty synthetic registry; it does not test evidence
transfer. Integrated [focused races and fixture compilation](../test/results/native-startup-installer-focused.log)
pass. The [first combined native run](../test/results/native-startup-installer-first.log)
passes the legacy worker (18.36 seconds) and the installer public-input case
(57.63 seconds, sixteen subtests). The v2 worker fails after exactly one accepted
native idle exchange; the whole run exits 1. Its terminal report records all
1,038 source hashes unchanged and complete cleanup. The installer result is
positive selected evidence; it does not qualify v2 startup or the combined suite.
The worker's client-start-relative idle deadline is being corrected against
the independently bounded server observation and original client setup budget.
The [focused regression fails before](../test/results/worker-native-idle-before.log)
and [passes after](../test/results/worker-native-idle-final.log), including rejection
after the original setup budget. Full bootstrap races and current specification,
architecture and design checks also pass. The [v2 native rerun](../test/results/native-worker-pod-second.log)
passes the actual compiled Restricted Pod, immutable secret projection, two
separate current mTLS/Pod-token idle exchanges and confirmed foreground retirement.
Its [terminal report](../test/results/native-worker-pod-second-check.log) records
all 1,039 source hashes unchanged and complete cleanup. This qualifies deployed
startup/idle supervision; it does not exercise native evidence bytes, timed
certificate renewal or production credential provisioning. Those remain required.

## Native exchange and worker startup: integrated, combined qualification pending

The 53-file SQL45/ADR-116 payload and 24-file parent ADR-121 startup payload are
integrated after original/payload hash checks. That checkpoint introduced schema
45 with 73 permanent tables; the SQL46 checkpoint above is the current head.
Generated queries were regenerated against the combined tree.
The [exchange handoff](../test/results/native-exchange-stage-HANDOFF.md) records
actual staged tests and the remaining fixture boundaries. The native v2 worker
composes its process-owned credentials with the separate HTTP/2 transfer loop,
scoped fixed storage projection and remote unwrap service. Temporary storage
credentials must cover the original worker lifetime. The 64 MiB v2 minimum is
a provisional configured floor, not measured RSS.

[Staged startup vet/race tests](../test/results/worker-startup-native-supervision-v2-final.log)
pass against the frozen v2 API. The exchange regressions found an undersized
command limit and two-hop cancellation loss. The guarded four-file follow-up
now routes production ConnectorAdmission through the same joined receive owner
and gives the SQL45 window alias a distinct name from its PL/pgSQL record. Its
production-constructor test failed before at one second and passes after the
fix; [the handoff](../test/results/native-admission-fix-stage-HANDOFF.md) records
that evidence. Combined [full Go vet/race, architecture and SQL generation](../test/results/native-startup-combined-code-first.log)
pass (49 packages, 252 import edges, 36 generated SQL files), as do
[specification, architecture, design and download checks](../test/results/native-startup-combined-contracts-first.log).
The first selected SQL/S3 invocation used the wrong enclosing test name and
was correctly rejected as an empty selection. The
[correctly selected run](../test/results/native-exchange-sql-second.log) fails
during regional preparation. A subsequent
[diagnostic run](../test/results/native-exchange-sql-diagnostic.log) shows that
both relay admissions succeed, all three unwrap slots are consumed and the
worker reaches Joined before preparation returns unavailable. Both executed
runs preserve all 1,034 source hashes and complete owned-service cleanup;
neither qualifies the transfer. A real HTTP/2 regression reproduces a terminal
ordering race: the server began another blocking current check after flushing
the positive final marker, which the worker could already receive and close.
The [three-file correction](../test/results/native-terminal-frame-HANDOFF.md)
moves the required blocking check before Done and preserves original deadlines,
known cancellation and the data path's post-write checks. One hundred focused
repetitions and all native/mTLS/evidence race tests pass. The
[corrected real-service run](../test/results/native-exchange-sql-terminal-fix.log)
now completes preparation and metadata observation with Joined worker results,
then fails the content transfer with zero output bytes. Its final operation has
about one second of original authority remaining at connector admission. The
run exits 1 with all 1,039 hashes unchanged and complete cleanup. This verifies
progress through the earlier failure, not successful download qualification;
the same identity batch had covered both metadata lookup and subsequent content
admission. The [five-file phase correction](../test/results/native-response-phase-HANDOFF.md)
closes the joined metadata batch, acquires fresh current authority from the same
live reader, and intersects retention/original response bounds before admission.
The before regression fails; affected evidence/native/browser races pass with
revocation, changed-client, cancellation and shortened-retention negatives.
The native fixture now uses the actual browser live-reader component over its
explicit synthetic session store. The [phase-corrected real-service run](../test/results/native-exchange-sql-phase-fix.log)
exits 0, delivers the exact 352-byte context file, verifies its checksum and records
DownloadCompleted. Its [terminal report](../test/results/native-exchange-sql-phase-fix-check.log)
records all 1,040 source hashes unchanged and complete cleanup. However, the
content worker reports an uncertain final acknowledgement, which this version of
the fixture only logs. The passing test therefore does not prove a clean joined
exchange. A deterministic two-hop HTTP/2 regression reproduces the hub retiring
its operation before the connector forwards the final marker. The fix and a
strict assertion for all three worker results are in progress; full native
exchange qualification remains open.
The current
regional decoder remains bounded to 4 KiB pod-status, and each native conversation
retains its original five-second proof/lease. Neither generic response accounting
nor these component checks establish a large-file or installed public download.
Protected listener, credential/backing producers, v2 Pod qualification, public
composition and full installed workflow remain required. Helm stays disabled.

Startup review also found a separate protocol mismatch: the actual v2 worker
generated UUID nonces, while the native encoder requires canonical base64url
encoding of 32 random bytes. The added wire-contract regression
[fails before correction](../test/results/worker-native-nonce-before.log), and
the corrected generator plus all focused worker-native startup/supervision
[race tests pass](../test/results/worker-native-nonce-after.log). This does not
explain the SQL fixture failure, whose separate worker already used valid nonces.

## Gated installation preparation: integrated and native qualification passed

The seventeen-file ADR-120 package is integrated after verifying every original
and payload hash. [The handoff](../test/results/initial-activation-preparation-stage-HANDOFF.md)
records focused staged race/vet/schema results. The private preparation command
now supports an explicit immutable continuation that creates only the exact inert
scheduling-gated Pod. Each actual POST consumes one of sixteen original request
records; a known UID prohibits replacement, and only the original joined response
can close its request. Shutdown joins the full preparation call. A separate
credential binder persists one original fifteen-minute interval against the exact
private material and full startup identity, without issuing SQL/provider rights.
Integrated [affected race/vet checks](../test/results/initial-activation-preparation-integrated.log)
and [specification/architecture gates](../test/results/initial-activation-preparation-contracts.log)
pass. The [selected native Kubernetes run](../test/results/initial-activation-preparation-native.log)
passes 35 named entries, including actual 201 request drain, delayed original
POST, retained uncertainty, original UID and late 409 after the fixture guard
transition. Its [terminal report](../test/results/initial-activation-preparation-native-check.log)
records 975 unchanged source hashes, no post-exit changes and complete cleanup.
The fixture supplies the final guard transition explicitly; this does not qualify
the unfinished production handover.
Typed final input production, one-use provider effects, ungating, activation and
positive retirement remain required. Public services and Helm runtime stay disabled.

## Retained installation state: integrated and selected native qualification

The sixteen-file ADR-118 package is integrated after verifying every original
and payload hash. [The handoff](../test/results/initial-preparation-state-stage-HANDOFF.md)
records its focused staged tests and remaining scope. The protected immutable
private-material reader and exact original-interval codec do not issue roles or
choose a new credential interval. A separate SELECT-only historical reader binds
the exact original installation, startup plan, claim and audit receipt. Missing
state does not prove no effect; historical activation does not clear recovery.
Integrated Go vet/race, architecture and all 35 SQL generation checks pass in
[the combined code log](../test/results/refresh-installation-combined-code-gates.log).
The first contract check rejected fragment-only schema references; canonical
self-document references now pass specification, architecture, design and download
checks in [the corrected contract log](../test/results/refresh-installation-combined-contract-gates-after.log).
The [fresh-installation suite](../test/results/refresh-installation-pristine.log)
passes sixteen named entries, including the exact 70-table inventory and the
new SELECT-only history reader, real blocked-read expiry, denied current operator
and unchanged later recovery fence. Its
[terminal report](../test/results/refresh-installation-pristine-check.log)
records 968 unchanged source hashes and complete cleanup. Current Kubernetes
read authority is synthetic in that SQL suite. The combined
[native Kubernetes selection](../test/results/refresh-installation-native.log)
passes 36 named entries in 98.826 seconds, including the actual Restricted
installer, historical read after its exit, missing-guard/unbound/wrong-SQL-role
rejections, protected preparation and all retirement/cleanup checks. The
[native terminal report](../test/results/refresh-installation-native-check.log)
records 968 unchanged source hashes, no post-exit changes and complete cleanup.
That fixture still supplies the trusted bootstrap and provider inputs; it is not
an automatically provisioned Helm installation. The [database recovery qualification](../test/results/refresh-installation-recovery-check.log)
also passes all three actual initial/restart/logical-restore phases with the same
source and cleanup guarantees; independent activation remains fixture-supplied.
Production material persistence, the gated Pod, provider/SQL provisioning and original guard
handover remain separate work; no installer or Helm runtime completion is claimed.

## Download-owned browser refresh: selected native qualification

The reviewed SQL43 package is integrated after all 25 base/payload hash checks;
22 source files were copied and SQL was regenerated against the combined schema.
Migration 43 now precedes 44; the schema head remains 44 and the exact initial
installation inventory includes 70 tables. The [handoff](../test/results/browser-refresh-owner-stage-HANDOFF.md)
records focused staged race/vet checks and the limits of its compile-only native hooks.
The [owner contract](architecture/browser-refresh-owner.md) binds explicit browser
POST consent to the original session, current accepted download, finite demand,
one-use provider refresh and positive joined cleanup. Logout removes authority
without refunding unjoined work. Public operation attachment, native browser
transfer, process-loss reconciliation and metadata retirement remain unfinished.
Integrated [code gates](../test/results/browser-refresh-owner-integrated-code.log)
passed full Go vet/race, Go architecture and all 35 generated SQL files.
[Contract gates](../test/results/browser-refresh-owner-integrated-contracts.log)
passed specification, architecture, design and download checks. The
[first SQL/S3 run](../test/results/browser-refresh-owner-native-first.log) failed
because the native fixture used the legacy authority field while calling the
current-identity preparation method. The fixture now supplies CurrentAuthority;
production method checks were unchanged. The
[second run](../test/results/browser-refresh-owner-native-second.log) reached
prepared evidence and owner admission, then exposed a production observation
interval defect: the outer observation start and a later nested five-second end
made an interval longer than its maximum. The
[focused before regression](../test/results/browser-refresh-owner-interval-before.log)
reproduces the one-microsecond extension. The view now preserves the outer end,
and maintenance also retains the original settings/session deadline. Focused
[race tests after correction](../test/results/browser-refresh-owner-interval-after.log)
pass. Both failed native runs recorded unchanged source and complete cleanup.
The third and fourth SQL runs reached current response demand but failed while
binding its one-use claim. A diagnostic run identified PostgreSQL SQLSTATE 42702:
the trigger's local record and an EXISTS alias both used `c`. The migration now
uses an unambiguous alias; temporary diagnostics were removed. The
[fifth run](../test/results/browser-refresh-owner-native-fifth.log) passed that
claim and reached pending-pause lookup, where PostgreSQL rejected the generic
session query's unnecessary UPDATE privilege requirement. Pause now uses a
dedicated SELECT under the existing exclusive browser-root lock, preserving a
coherent session/claim observation without granting session writes. Its native
regression requires SQLSTATE 42501 for attempted session UPDATE and DELETE.
All five failed selected runs and the diagnostic run recorded unchanged source
and complete owned-lab cleanup; none is a passing qualification. The corrected
[sixth selected run](../test/results/browser-refresh-owner-native-sixth.log)
passed the complete owner case in 2.09 seconds: actual publication/preparation,
response-bound pending/settled lookup, one-use claims, delayed-COMMIT closure,
logout capacity and exact privilege denial. Its
[terminal report](../test/results/browser-refresh-owner-native-sixth-check.log)
records 958 unchanged source hashes, no post-exit changes and complete cleanup.
The [full combined custody suite](../test/results/refresh-installation-full-custody.log)
then passed 294 named entries in 271.827 seconds. Its
[terminal report](../test/results/refresh-installation-full-custody-check.log)
records 968 unchanged source hashes, no post-exit changes and complete cleanup.
Process authority in the owner case remains explicitly synthetic; these results
do not establish a public native transfer. Fresh-installation, recovery and native
Kubernetes installation results are recorded above.

The actual Keycloak/PostgreSQL/OpenBao
[provider run](../test/results/browser-refresh-owner-provider-first.log) passed
13 named entries, including explicit-POST-owned rotation without tab polling.
Its [terminal report](../test/results/browser-refresh-owner-provider-first-check.log)
records 913 unchanged source hashes, no post-exit changes and complete cleanup.
That provider helper deliberately supplies synthetic accepted download/process
demand; the separate real SQL owner test now passes as recorded above. No runtime
route or Helm service is enabled by this integration.

## Resumable installer preparation: native qualification passed

The reviewed twelve-file ADR-117 checkpoint is integrated after complete base
and payload hash checks. The private `initial-prepare` command resumes nine fixed
declarative resources under independently checked continuity protection, with a
producer-owned public root and original per-effect deadlines. Roles/bindings can
retire only in place, leaving their keys occupied against delayed CREATEs.
Credentials, provider calls, executable Pods, witnesses and activation remain
outside this retry set. The [staged handoff](../test/results/initial-preparer-stage-HANDOFF.md)
records actual focused checks and explicit remaining work. Integrated focused
race/compile checks pass in [the focused log](../test/results/initial-preparer-focused.log),
and specification/architecture checks pass in
[the contract log](../test/results/initial-preparer-contract-gates.log).
The [first native run](../test/results/initial-preparer-native-first.log) failed:
target-namespace deletion was not denied by the continuity policy. Test cleanup
also encountered admission rejection while deleting retired cluster RBAC objects.
The other selected deletion, retired-authority and delayed-CREATE checks passed;
the enclosing test failed and is not qualified. Its
[terminal report](../test/results/initial-preparer-native-first-check.log)
records 942 unchanged source hashes, no post-exit changes and removal of both
owned clusters/services. That lab cleanup result does not erase the test's own
cleanup failures. The namespace rule and cleanup convergence are being corrected;
native qualification of the integrated source has not yet completed. The reviewed
two-file correction removes the invalid empty-request-namespace assumption for
core Namespace keys while keeping exact resource/name matching. The
[second native run](../test/results/initial-preparer-native-second.log) passes all
14 functional subtests, including target and bootstrap namespace deletion denial.
It still exits 1 because fixture cleanup does not recognize the returned policy
rejection. The [second terminal report](../test/results/initial-preparer-native-second-check.log)
records 942 unchanged source hashes, no post-exit changes and complete owned-lab
cleanup. Those facts do not make the failed test qualified; the teardown
classification has been corrected in the fixture: it recognizes only structured
403/422 denial from the exact owned policy/binding, keeps the original cleanup
deadline and retries the same UID. Focused race tests pass in
[the cleanup regression log](../test/results/initial-preparer-cleanup-status-integrated.log);
the [combined native rerun](../test/results/refresh-installation-native.log) now
passes the enclosing preparation test and all fourteen functional subtests,
with unchanged source and complete cleanup. Credential-state persistence,
finite activation-Pod recovery and guarded handover continue separately; this
does not enable Helm runtime services or complete an installation.

## Browser refresh contention and one-click logout

The standalone Busy/CSRF package is integrated independently of pending SQL43.
A committed same-session rotation during CSRF decryption now returns bounded
metadata-free Busy; immutable-session changes and revocation still deny.
The console preserves its existing page during temporary refresh contention,
keeps the original attempt/session deadlines, and resumes normal refresh
scheduling after a bounded unsuccessful attempt.

The follow-up logout regression reproduced a second race: rotation during the
logout POST's CSRF check. Canonical HTTP 409 now promises that revocation has not
started. The console retries only that response within the original shared
CSRF/logout budget. Once revocation starts, uncertain errors cannot become
retryable Busy; lost replies and generic failures still require explicit retry.
The [Go before log](../test/results/browser-logout-busy-before-go.log) records
the incorrect post-effect 409 (and an initial test assumption corrected to retain
the existing generic 503 Retry-After header); the
[console before log](../test/results/browser-logout-busy-before-console.log)
reproduces both the failed one-click logout and lost shared retry budget.
Focused after checks pass, as do full
[Go vet/race and architecture gates](../test/results/browser-busy-final-code-gates.log)
and [console contract/TypeScript/tests](../test/results/browser-busy-final-console-gates.log)
with 115 tests in eight files. Public authentication documentation and generated
TypeScript now describe the exact pre-revocation retry boundary.

The actual Keycloak/PostgreSQL/OpenBao
[identity run](../test/results/browser-busy-native.log) passed 12 named entries
in 9.639 seconds. A real decrypted CSRF read held across an actual committed
provider rotation returns Busy, and a fresh lookup recovers without another
rotation. Eight concurrent refresh callers accept only success or canonical
Busy. Its [terminal report](../test/results/browser-busy-native-check.log)
records 890 unchanged source hashes, no post-exit changes and complete cleanup.
Protected identity/settings inputs remain fixture-owned; this does not qualify
SQL43 download-owned refresh or a production installation.

The first built-console attempt failed before launching a browser because the
pinned Playwright browser executable was missing. After installing that exact
headless Chromium build, the [second run](../test/results/browser-busy-console-browser-after.log)
passed 18 journeys and 14 accessibility scans in 16.864 seconds, with no external
requests, CSP errors or JavaScript errors. Both CSRF-GET and logout-POST Busy
cases reach sign-out with one click and exactly one revocation. The
[archived report](../test/results/browser-busy-console-browser-report.json)
and [package hashes](../test/results/browser-busy-console-package-hashes.json)
identify this result. This uses the real compiled React/Go HTTPS transport with
synthetic session/capture/case services, not public-runtime authority. Runtime
Helm services remain disabled. Specification, architecture and design checks passed in the
[contract gate log](../test/results/browser-busy-final-contract-gates-after.log).
The optional full OpenAPI gate initially lacked its development validator;
after installing the previously recorded 0.9.0 version, its
[separate run](../test/results/browser-busy-openapi-after.log) passed. Next
continue SQL43 ownership, the native evidence exchange and protected installation
composition.

## Overdue original audit cleanup: selected native qualification

Migration 44 and [ADR-115](decisions/115-overdue-operation-audit-erasure.md) are
integrated after verifying the frozen 19-file manifest and every base/payload
hash. Shared SQL was regenerated. The independent cleanup change does not depend
on pending migration 43: the temporary schema head is 44 with the same 68-table
inventory. There is no installed runtime database; all owned native fixtures are
fresh and removed after qualification. The later combined source must apply 43
before 44 on a fresh fixture and add its tables to the pristine inventory.

New explicitly eligible records can irreversibly fence certificate creation and
purge positively closed originals after the proof window is missed. Independent
current absence acknowledgement still gates identifying SQL retirement and
capacity release. Original dates, finite cleanup generations, uncertain charges
and backup-history floors remain binding. Old records, unknown writers, claimed
certificates and restart/restore are explicitly excluded pending reconciliation.
Integrated [code gates](../test/results/overdue-audit-code-gates.log) returned 0
for Go vet/race, architecture and SQL generation (34 generated files).
[Contract gates](../test/results/overdue-audit-contract-gates.log) returned 0
for specification, architecture, design and downloads. The
[first native attempt](../test/results/overdue-audit-native-first-check.log)
failed during migration, before any selected test ran: a `CASE` expression in a
PL/pgSQL `IF` condition needed parentheses. The one-expression correction is
integrated. The failed attempt's
environment report records complete cleanup; it did not record a source-freeze
verdict. The harness now creates a fresh empty test log and records source hashes
and provider diagnostics on setup failures too.

The [second native run](../test/results/overdue-audit-native-second.log) passed
both existing healthy/cooling cases and both new overdue-original cases in
114.510 seconds. Its [terminal report](../test/results/overdue-audit-native-second-check.log)
records 933 unchanged source hashes, no post-exit changes and complete cleanup.
The cases use actual SQL locks, object deletion and independent absence checks;
their backup-history qualification inputs remain synthetic. The
[full custody regression](../test/results/overdue-audit-full.log) also passed:
293 named passing entries in 267.478 seconds. Its
[terminal report](../test/results/overdue-audit-full-check.log) records the same
933 unchanged source hashes, no post-exit changes and complete cleanup.
The [pristine-installation suite](../test/results/overdue-audit-initial.log)
passed 12 named entries in 2.473 seconds, including the 68-table inventory and
temporary purpose-role provisioning/retirement. Its
[terminal report](../test/results/overdue-audit-initial-check.log) records the
same source and cleanup guarantees. The
[database recovery run](../test/results/overdue-audit-recovery-check.log) passed
all three actual PostgreSQL initial/restart/logical-restore phases, again with
933 unchanged hashes and complete cleanup. That test establishes incarnation
fencing with synthetic independent activation; it does not implement production
recovery or historical cleanup reconciliation. No runtime endpoint is enabled.

After the SQL correction, `make sql-check spec-check architecture-check
design-check download-check` returned 0 in the
[final gate log](../test/results/overdue-audit-final-gates.log), including all 34
generated SQL files. Go sources were unchanged from the earlier full Go
vet/race gates; the subsequent real-service suites exercised the corrected
migration. Download-owned refresh, the native relay and the preparation
supervisor remain separately staged work.

## Native response accounting: selected real-service qualification

The [first selected run](../test/results/native-response-first.log) passed five
affected legacy download/control cases but failed the new response/window case:
the separate audit role lacked PostgreSQL's UPDATE privilege for a response-row
lock. Its preserved provider log identified `LockDownloadResponse` precisely.
The correction grants only UPDATE on the immutable ID column; no lease or
counter mutation was added. The [second run](../test/results/native-response-second.log)
passed the new case in 2.06 seconds; its
[terminal check](../test/results/native-response-second-check.log) records 925
unchanged source hashes, no post-exit changes and complete cleanup. Byte counts
above the real bounded context size are synthetic accounting inputs, not actual
large-artifact decoding or network throughput.

Integrated [code gates](../test/results/native-response-refresh-code-gates.log)
returned 0: full Go vet/race, 48 packages/247 allowed import edges and 33 matching
generated SQL files. [Contract gates](../test/results/native-response-refresh-contract-gates.log)
also returned 0 for specification, architecture, design and download contracts.
The subsequent native-test-only strengthening requires exact privilege-denial
SQLSTATEs and rejects changing the lock-only immutable ID. The combined full
[custody run](../test/results/native-response-refresh-full.log) passed with those
assertions: 291 named passing entries in 213.643 seconds. Its
[terminal check](../test/results/native-response-refresh-full-check.log) records
925 unchanged source hashes, no post-exit changes and complete cleanup. The
[recovery run](../test/results/native-response-refresh-recovery-check.log) also
passed all three actual PostgreSQL initial/restart/logical-restore phases with
the same unchanged-source and cleanup guarantees. These recovery tests retain
their synthetic independent activation boundary. The schema42
[first-installation suite](../test/results/native-response-refresh-initial.log)
passed 12 named entries in 2.490 seconds, including the exact 68-table inventory,
current activation/audit checks and scoped role provisioning/retirement. Its
[terminal check](../test/results/native-response-refresh-initial-check.log) also
confirms 925 unchanged hashes and complete cleanup. Protected fixture inputs
still do not qualify the complete production installer; no public endpoint is
enabled.

Next implementation work is staged separately: durable download-owned browser
refresh under migration43 and the actual approved-context
worker-to-connector-to-hub native exchange under migration45. The latter uses a
separate finite HTTP/2 stream and exact regional key authority; it does not turn
certificate enrollment into a byte channel. Neither is claimed as integrated or
externally qualified here. Migration44's later integration is recorded above.

## Credential scheduling verified against an actual SQL wait

The nine-file credential scheduling change is now integrated. Login and refresh
use verified token and group freshness deadlines independently of short identity
observations. The scheduling predicate preserves the original session and
one-use claim deadlines but allows work whose scheduled time has already arrived.
It does not grant background ownership or extend authentication.

The [native before run](../test/results/refresh-scheduling-native-before.log)
reproduced rejection of a still-valid replacement after `pg_blocking_pids`
confirmed an actual session-row lock wait. Only that new scheduling case failed;
the [terminal check](../test/results/refresh-scheduling-native-before-check.log)
records unchanged sources and clean teardown. After applying the reviewed SQL
adapter correction, the full owned Keycloak/PostgreSQL/OpenBao fixture passed
11 named entries in 9.908 seconds. Its
[after log](../test/results/refresh-scheduling-native-after.log) and
[terminal check](../test/results/refresh-scheduling-native-after-check.log) record
880 unchanged source hashes, no post-exit changes and complete cleanup. The new
lock test uses synthetic opaque credentials; the surrounding suite exercises
actual provider login, refresh, current group replacement and logout. This does
not qualify an unattended download or the staged durable refresh owner.

## Integrated audit retirement and native response accounting

Migration 00041 and the explicitly selected healthy presentation wrapper are now
integrated. The wrapper's missing-constructor regression failed before the fix;
the affected presentation/browser/MCP race tests then passed in
[the focused log](../test/results/healthy-audit-presentation-after.log).
The [code gates](../test/results/operation-lifecycle-code-gates.log) passed
Go vet/race, 48 packages/246 import edges and 32 matching generated SQL files;
[contract gates](../test/results/operation-lifecycle-contract-gates.log) also
passed. These gates preceded the two SQL expression corrections below.

The first real PostgreSQL/S3 run failed because JSON field extraction and array
subtraction needed explicit parentheses in two migration expressions. The
[failed run](../test/results/operation-lifecycle-native-first-check.log) and
provider logs remain preserved. After correcting both expressions, the
[second run](../test/results/operation-lifecycle-native-second-check.log) returned
0: both selected healthy/cooling lifecycle cases passed, with 900 unchanged
source hashes, no post-exit changes and complete fixture cleanup. This verifies
on-time object retirement, conservative uncertain spend and backed cooling with
synthetic qualification inputs; it does not qualify actual backup retention,
late-before-certificate cleanup, recovery reconciliation or public runtime.

Migration 00042 and the 23-file response/window package are now integrated after
checking every base and payload hash. The shared schema head, 68-table pristine
inventory, SQL generation, existing runtime read role and native fixture hook
have been updated. Native response qualification remains pending. Staged tests
covered a synthetic 64 MiB plus 17-byte response and 1 TiB accounting arithmetic;
neither is a deployed large-file transfer. The combined custody harness timeout
is now 300 seconds because the prior 139-second suite plus the new 61-second
audit lifecycle tests exceed its former 180-second aggregate limit. Product
authority deadlines are unchanged.

## Active continuation: download-owned refresh and audit retirement

[ADR-114](decisions/114-download-owned-browser-refresh.md) now requires browser
downloads to survive console-tab closure without relying on page refresh timers.
The accepted direction reuses server-held online credentials and one-use SQL
refresh claims, with explicit Download POST admission, fixed session/transfer
limits and current preparation/response demand. Review found that existing hub
configuration does not provide a suitable purpose-backed process ceiling;
the accepted design uses durable owners backed by existing bounded sessions and
exact accepted-download consumers before runtime composition. Local map limits
will not be advertised as a global
capacity bound. Verified group-age scheduling is an independent implementation
fix in progress.

`make spec-check architecture-check design-check download-check` returned 0 for
the design changes in the [gate log](../test/results/download-refresh-design-check.log).
This is contract validation, not server refresh or large-file qualification.
Parallel staged work continues on download-owned refresh and overdue audit
retirement. Healthy public-operation audit retirement is integrated as recorded
above, including backed residual SQL history, and still needs separate recovery
and late-before-certificate handling;
successful on-time cleanup must not be reported as complete privacy lifecycle
support or permission to enable public runtime.

## Current continuation: identity during long native responses

The [live-reader identity factory](architecture/native-reader-identity.md) now
supplies fresh, separately owned authentication observations for one original
download request. Existing metadata handles remain nonrenewable. Browser reads
never refresh credentials; a separately authorized POST may refresh the same
session, and a concurrent committed refresh produces a bounded busy result
without returning the old identity. Revocation, changed actor/client and expired
credentials stop the reader. No native byte relay or public runtime is enabled.

The integrated [code gates](../test/results/native-reader-code-gates.log)
returned 0 for `make go-check go-architecture-check sql-check`, including race
tests, 48 packages/243 import edges and 31 matching sqlc files. The
[contract gates](../test/results/native-reader-contract-gates.log) also returned
0 for `make spec-check architecture-check design-check download-check`.

The [real Keycloak/PostgreSQL/OpenBao fixture](../test/results/native-reader-identity.log)
returned 0 with 10 named passing entries in 9.525 seconds. It exercises
continuation beyond the original short observation, explicit POST refresh with
the same session, and logout rejection. Its
[terminal check](../test/results/native-reader-identity-check.log) and
[environment report](../test/results/native-reader-identity-environment.json)
record 840 unchanged source hashes, no post-exit changes and complete cleanup.
These results qualify the identity composition, not native payload delivery or
an installable investigation flow. The server-side refresh owner needed for
downloads that outlive the console tab remains a reviewed proposal; large-file
accounting/transport and finite audit retirement are active parallel work.

## Current continuation: browser identity through worker lifecycle

The [request-owned lifecycle](architecture/worker-current-lifecycle.md) now connects
actual browser/MCP `CurrentIdentity` to worker dispatch, credential enrollment,
local routing and shared owner locators. One original observation survives all
blocking work and may only shorten; later effect contexts receive the shorter
deadline. Human credentials stay in the hub, and existing private channels remain
certificate-only. No SQL migration or public runtime was enabled.

The missing typed API and shorter-effect-context regressions failed before the
change; their [API baseline](../test/results/worker-current-lifecycle-stage-api-before.log)
and [deadline baseline](../test/results/worker-current-lifecycle-stage-shorter-before.log)
are retained. The [staged race run](../test/results/worker-current-lifecycle-stage-focused-race-final.log)
passed for the evidence and TLS adapters. After integration,
`make go-check go-architecture-check sql-check` returned 0 in the
[code gate log](../test/results/worker-current-lifecycle-code-gates.log):
vet/race, 48 packages/243 import edges and 31 matching sqlc files.
`make spec-check architecture-check design-check download-check` also returned 0
in the [contract log](../test/results/worker-current-lifecycle-contract-gates.log).

The [owned SQL/S3/TLS fixture](../test/results/worker-current-lifecycle-native.log)
passed all 15 selected worker cases in 32.355 seconds, including enrollment under
an actual `NewBrowserRequest`, an exclusive SQL lock crossing its original expiry,
and a separate fresh request attaching to the same admitted worker. Its
[terminal check](../test/results/worker-current-lifecycle-native-check.log) and
[environment report](../test/results/worker-current-lifecycle-native-environment.json)
record exit 0, 882 unchanged source hashes, no post-exit hash changes and complete
cleanup. Current authorization, SQL roles, encrypted audit and TLS are real;
session storage, Job/Pod proofs and the certificate issuer remain explicit fixture
inputs. This is not real SSO, in-Pod native transfer or a complete download flow.

Active parallel work covers finite operation-audit retirement, including retained
backup/WAL accounting, and the large-file download path. Review found that the
current single-batch HTTP sink, 1,024-batch session cap and offset-zero completion
rule cannot provide the specified multi-GiB workflow. The next design preserves
short current-authority checks while separating the original response lifetime
and cumulative bounded transfer accounting. The metadata `CurrentIdentity` handle
will not become renewable. [ADR-113](decisions/113-large-native-response-accounting.md)
now records the accepted response/window/lease design: 64 MiB prepaid accounting
windows, current leases of at most five seconds and checked writes of at most
1 MiB. Its specification/architecture/design/download checks returned 0 in the
[design gate log](../test/results/large-native-response-design-check.log).
The new runtime path remains open work, not a qualified large-file fix.
Protected runtime/install composition, all remaining collection mechanisms and
the complete S-01/S-02 and later slice exits remain unfinished.

## Active continuation: audited deletion and public operation audit

[ADR-111](decisions/111-positive-context-writer-deletion.md) and
[the deletion contract](architecture/context-deletion.md) add positive joined
completion for the bounded API context writer, immutable purge results and
independent encrypted audit before evidence-storage release. Migration 00039
preserves historical executions without fabricating completion, rejects generic
finalization for the new protocol and retains unknown write obligations. The
first staged unit/race and contract checks passed. The first focused real SQL/S3
run failed with `retention decision mismatch` when the new deletion fixture tried
to shorten the effective cutoff; the existing retention guard rejected that
setup. Its [log](../test/results/context-deletion-first.log) and
[environment report](../test/results/context-deletion-first-environment.json)
record exit 1, 848 unchanged source hashes and complete cleanup. The correction
and subsequent passing runs are recorded below; runtime retention checks were
not relaxed. No public runtime, general writer drain, metadata retirement or
complete S-02 exit is enabled by this component.

The failing cleanup fixture now uses the existing transactional retention facet
to create the immutable decision and advance its guarded overlay. No production
retention check changed.

[ADR-110](decisions/110-bounded-public-operation-audit.md) and
[operation auditing](architecture/operation-audit.md) are integrated as migration
00040, preserving 00039's tables, guards and grants. The combined pristine
inventory contains 63 tables. Six typed operations now have a shared optional
audit boundary, one trusted request ID, separately backed ordinary/resolution
capacity, immutable encrypted intent/outcome and exact-key lookup after unknown
write replies. Current identity and the original metadata deadline still bound
delivery. Protected key/backend provisioning, authenticated ingress rejection
coverage, interrupted-audit reconciliation and safe retirement remain pending;
bootstrap does not enable this boundary yet.

[Context download coordination](architecture/context-download-control.md) now
adds preparation/status use cases and SQL reads without another migration.
An accepted request key resolves the original allocation and limits before any
new plan is selected. Status reads do not start a worker or decrypt another copy;
later metadata reads require fresh authority over the original verified
preparation. Ordinary initial startup supports bounded automatic same-key POST
continuation. Missing regional native runtime permits no reservation, and lost
verified metadata is unavailable rather than fabricated. Public cancellation,
audit mediation, native attachment and runtime mounting remain pending.

The cross-review additionally corrected five concrete boundaries. Known denials
keep private audit classification while outward errors remain nondisclosing;
new audit reservations preserve backing expiry after account-lock waits;
download continuation cannot cross its original session deadline; terminal status
remains readable under current rights without a worker/cache; and native HTTP
delivery joins its cancellation callback before releasing the connection.
Completed may omit the entire native metadata group in the shared browser/MCP
contract. The console clears old native details and bounds terminal status by
current managed access; it never prepares from a status timer. A Completed result
does not prove that a client saved the local file.

Failing-before regressions are preserved for
[audit classification](../test/results/operation-audit-classification-before.log),
[terminal status](../test/results/download-terminal-status-before.log),
[late continuation](../test/results/download-terminal-continuation-before.log),
[terminal cleanup timers](../test/results/download-terminal-timer-before.log)
and [the HTTP deadline callback](../test/results/download-sink-join-before.log).
The combined [code gates](../test/results/context-audit-download-final-code-gates.log)
returned 0 with vet/race, 48 packages/243 import edges and 31 matching sqlc files.
The [interface gates](../test/results/context-audit-download-final-interface-gates.log)
returned 0 with 104 Web tests, TypeScript/native-ESM validators, console build,
specification/architecture/design checks and 29 positive/137 negative download
contract cases. The existing main-bundle size advisory remains. These gates skip
external fixtures; the real SQL/S3 results follow below. Existing
schema-38 results below establish the preceding baseline, not these new source
changes. Broader provider and actual-browser qualification remain pending.

The first combined focused SQL/S3 run passed all three operation-audit cases and
the API execution/deletion case, then failed the new terminal-download fixture
after its thirty-second wait: the fixture's permission-observer lease had also
expired. The [first log](../test/results/context-audit-download-focused-before.log)
and [report](../test/results/context-audit-download-focused-before-environment.json)
record exit 1, 871 unchanged hashes and complete cleanup. Renewing that observer
lease exposed the independently expiring thirty-second synthetic fleet source;
the [second log](../test/results/context-audit-download-focused-second.log) and
[report](../test/results/context-audit-download-focused-second-environment.json)
again record exit 1, unchanged sources and complete cleanup. The test now requests
an original fifteen-second transfer session and waits beyond it, within unchanged
source lifetimes. The temporary observer renewal was removed. This retains real
session expiry, old-preparation rejection and read-only terminal-status checks
without extending source authority or changing production limits. The corrected
[focused run](../test/results/context-audit-download-focused-final.log) returned 0:
all five selected cases passed in 20.996 seconds. Its
[report](../test/results/context-audit-download-focused-final-environment.json)
records 871 unchanged source hashes and complete cleanup, checked after terminal
exit. This qualifies the selected SQL/S3 compositions with explicit synthetic
identity, source, placement and installation inputs. The subsequent
[full custody suite](../test/results/context-audit-download-full-custody.log)
returned 0 with 287 named test entries in 139.453 seconds. Its
[environment report](../test/results/context-audit-download-full-custody-environment.json)
records 871 unchanged hashes and complete cleanup, independently rechecked after
terminal exit. The [full Kubernetes/provider suite](../test/results/context-audit-download-full-context.log)
then returned 0 with 110 named test entries in 241.483 seconds. Its
[report](../test/results/context-audit-download-full-context-environment.json)
records the same 871 unchanged hashes and complete cleanup. Six real OpenBao/S3
audit intent/outcome pairs used exactly 12 wraps, 12 unwraps, 12 PUTs and 12 GETs;
pair latency was 13.506 ms p50 and 233.415 ms maximum in this small synthetic
fixture. This is provider integration evidence, not production burst or latency
qualification. The [database restart/restore run](../test/results/context-audit-download-recovery-environment.json)
returned 0 in all three phases, and the [first-installation run](../test/results/context-audit-download-installation-environment.json)
returned 0 with 12 named entries. Both retained 871 unchanged hashes and complete
cleanup. Their explicit fixture activation/provisioning boundaries remain;
passing them does not implement production restart/restore or Helm provisioning.
The [actual-browser check](../test/results/context-audit-download-browser.json)
also returned 0: 16 journeys, 14 accessibility scans, no external requests and no
CSP/runtime errors. All 916 source/build hashes stayed unchanged and matched the
post-exit files. This uses the built React console and actual Go TLS/static/
session/operation routes with synthetic current identity/capture/case services;
the native download backend remains deliberately unavailable in that fixture.

The subsequent [regional preparation-result owner](architecture/context-download-result.md)
is integrated in five hash-checked files. It retains one acknowledged verified
metadata result before the unchanged first-response authority gate, with exact
worker/process/session identity, at most two calls, one native attempt and joined
shutdown. A fresh authorized read can recover those facts without another native
read, unwrap or batch. Unknown acknowledgements remain unavailable and spent.
The expiry regression failed with the old retention ordering and passes with the
new ordering; the [integrated evidence-package race run](../test/results/context-download-result-integrated-race.log)
returned 0 in 1.154 seconds. These tests use synthetic worker/current-authority
ports; preceding native reports do not qualify this new owner or a native-work
transport.

Authenticated browser/MCP rejection auditing is also integrated in ten
hash-checked files. Invalid schema/missing-read requests use ordinary audit
backing; valid resolution keeps its reserved audit lane. A request-owned atomic
disposition prevents duplicate auditing and late SDK callbacks from dispatching;
strict constructors bind one audited service and preserve the original HTTP
deadline/cancellation for both supported MCP revisions. SDK parameter errors are
sanitized before release. The live identity check now precedes SQL timestamp
flooring, fixing an independently reproduced false denial. Both defects have
[failing-before evidence](../test/results/operation-ingress-before.log).
Unauthenticated/oversized/overload counters remain bounded and process-local;
reserved audit backing does not establish whole-HTTP-ingress availability.

The combined [code gates](../test/results/context-ingress-result-code-gates.log)
returned 0 with vet/all-package race checks, 48 packages/243 allowed edges and
31 unchanged generated SQL files. [Contract/design gates](../test/results/context-ingress-result-contract-gates.log)
returned 0, including 1170 architecture checks and the unchanged download wire
contract. The targeted [SQL/S3 rerun](../test/results/context-ingress-result-native.log)
returned 0 with all four selected operation-audit/download-control cases in
19.344 seconds; its [report](../test/results/context-ingress-result-native-environment.json)
records 879 unchanged hashes and clean teardown. It exercises the existing real
storage composition, not the new owner's synthetic current-worker proof as a
production runtime. The [combined browser run](../test/results/context-ingress-result-browser.json)
returned 0 with 16 journeys, 14 accessibility scans, no external requests/CSP/
runtime errors and 924 unchanged source/build hashes, checked again after exit.
The prior full native/recovery/installation results remain source-specific
baseline evidence; they were not rerun as a full matrix for these follow-ups.

Two isolated implementation tracks remain active: typed request-owned browser
identity through worker dispatch/enrollment, and finite retirement for positively
completed operation-audit writes. An independent review is checking the latter's
quota, role, privacy and recovery boundaries. Staged work is not integrated or
qualified until its separate results are recorded. Public runtime remains
disabled, and no task or S-01/S-02 exit is marked complete.

## Qualified checkpoint: case navigation and bounded metadata capacity

The combined candidate now includes [ADR-108](decisions/108-backed-context-control-capacity.md)
workload-backed control metadata capacity and [ADR-109](decisions/109-published-context-case-navigation.md)
ordinary published-case navigation, with migrations 00037/00038 and an exact
58-table installation inventory. Current accepted permission, original audience,
effective retention and recovery checks precede case disclosure. Browser and MCP
share the same `get_case` projection; artifact versions are not native-file hashes.
Protected capacity configuration producers, finite metadata retirement and the
public operation audit boundary remain unfinished.

The lazy evidence/download console is integrated. Its component checks passed
98 tests plus native ESM validation and a production build. An idle-expiry
regression failed before the local rerender timer and now passes: expired
evidence loses its Download affordance without polling or changing dates.
The native download
affordance supports all canonical artifact kinds, retains uncertain preparation
keys and uses direct authenticated same-origin attachments; no backend transfer
is fabricated when the service is unavailable. The [actual-browser run](../test/results/context-case-browser.json)
passed 16 journeys and 14 accessibility scans with 881 unchanged source/build
hashes, no external requests and no CSP/runtime errors. Desktop and 320px evidence
screens were visually inspected. Its real Go TLS/session/CSRF/case routes use
synthetic case/capture authority and deliberately have no native-download backend;
they qualify UI behavior, not a public transfer. The
[first browser failure](../test/results/context-case-browser-before.log) retained
unchanged sources; consuming the response body immediately fixed a navigation
race in the test harness without removing wire/UI assertions.

The [targeted native API run](../test/results/context-api-runner-native-environment.json)
passed acquisition, encrypted custody, independent publication and exact 362-byte
native retrieval, with 802 unchanged source hashes and no cleanup failures. It
also deleted the actual target and executor before historical publication/read.
This uses real Kubernetes Pod-bound credentials, SQL, S3 and the product runner
in the fixture process; fixture human/bootstrap/key authority does not constitute
a deployed regional executable. Qualification exposed an admission defect in
normal foreground deletion, now corrected by allowing only the exact controller
to remove an existing foreground finalizer without changing Pod content.

The schema-37 [Go/SQL gates](../test/results/context-evidence-capacity-code-gates.log)
and [specification/design/Helm gates](../test/results/context-evidence-capacity-document-gates.log)
passed. Its subsequent [full custody run](../test/results/context-evidence-capacity-custody-before-environment.json)
failed with 811 unchanged sources and no cleanup failures. The failures exposed
fixture timestamp precision, a cyclic migration-copy transaction and retained
concurrency pools that starved later tests. Those fixture corrections are now
applied without changing production denials or database connection limits;
schema-38 combined Go/SQL and document gates passed (48 packages, 238 import
edges, 28 generated SQL files). Its [first full custody run](../test/results/context-case-custody-timeout-environment.json)
passed 259 entries, including new case navigation and all context admission
cases, before the aggregate two-minute timeout interrupted the later policy
suite. It retained 829 unchanged hashes and no cleanup failures. The context
parent alone took 86.15 seconds; earlier parents account for the exhausted
budget. The harness now records a finite three-minute Go process allowance plus
one minute of outer cleanup allowance; individual authority, lock and provider
deadlines are unchanged. The next [timing-failure run](../test/results/context-case-custody-contention-environment.json)
retained 831 unchanged hashes and clean cleanup, but several original five-second
operations expired while a separate staged build was active. PostgreSQL connection
saturation was absent; observed WAL sync delays and host write activity suggest
I/O contention, not yet a proven sole cause. The source-identical
[full rerun with staged builds held](../test/results/context-case-custody-final-environment.json)
passed 283 named parent/subtest entries in 122.637 seconds, with 831 unchanged
hashes and no cleanup failures. This includes the new case/current-audience
projection, all metadata-capacity cases and the existing download SQL/TLS/S3
components. The earlier loaded failure remains evidence of a qualification
availability limit, not a waived success or measured production SLO. The
[full Kubernetes/context run](../test/results/context-case-native-full-environment.json)
then passed 109 named parent/subtest entries in 242.822 seconds, with 831 unchanged
source hashes and no cleanup failures. It includes the real API executor,
worker/owner identity, protected configuration and native context paths; each
fixture's synthetic initial authority boundaries still apply.
[Database recovery](../test/results/context-case-recovery-environment.json) passed
its three initial/restarted/restored phases and
[initial installation](../test/results/context-case-installation-environment.json)
passed 12 named checks against schema 38. Both retained 831 unchanged source hashes
and had no cleanup failures. These are component qualifications; protected full
installation provisioning and the public investigation workflow remain pending.

Independent encrypted operation intent/outcome auditing and positive producer
completion/deletion checkpoints are in separate staged work. No public listener,
runtime-enabled Helm installation, complete S-01/S-02 exit or broader packet,
syscall, core/profile acquisition workflow is claimed by these additions.

## Earlier checkpoint: context UI, MCP and API execution contracts

Parallel work now composes the same five bounded context operations for browser
and MCP, a React diagnostic/review/submission/progress flow, durable progress
under [ADR-105](decisions/105-durable-context-progress.md), and explicit regional
Kubernetes API execution under [ADR-104](decisions/104-regional-api-context-execution.md).
The single shipped diagnostic is a 4096-byte whole-pod status snapshot. Broader
capture profiles, recorders and investigation workflows remain requirements;
unsupported input is rejected rather than silently simplified.

The combined candidate now includes [ADR-106](decisions/106-regional-api-context-start.md)
regional execution preparation/start/result components and
[ADR-107](decisions/107-atomic-context-request-resolution.md) accepted-or-closed
request recovery, with migrations 00035/00036 and an exact 54-table installation
inventory. An acknowledged closure permits explicit editing; unknown replies
retain the original preview/key and accepted work cannot be cancelled by closure.
Closing an own passive review remains possible after target access is lost;
returning accepted metadata still requires current target read rights.

The combined [Go/SQL gates](../test/results/context-execution-resolution-code-gates.log)
passed: vet/race suites, 46 packages/225 architecture edges and 26 matching sqlc
files. [Specification/design/Helm gates](../test/results/context-execution-resolution-document-gates.log)
passed, including 49 MCP/browser pairs and configuration-only chart validation.
The console passed 66 tests, native ESM validation and its production build.
The [actual browser run](../test/results/context-execution-resolution-browser.json)
passed 11 journeys and nine accessibility scans with 858 unchanged source/build
hashes, terminal 0 and no external requests or CSP/runtime errors. Its actual Go
TLS/session/operation routes still use explicitly synthetic identity/capture
services; it is not real acquisition or deployment qualification.

A further response regression reproduced final identity checks returning a
shorter deadline that presentation and transport ignored. The corrected browser
and both MCP revisions clamp the actual socket to that deadline as well as the
original metadata bound. Before/after evidence is in
[the failing regression](../test/results/context-resolution-identity-shortening-before.log)
and [passing transport race suites](../test/results/context-resolution-transport-final.log).
The request-owned identity handle also now retains the earliest deadline across
sequential and concurrently completing observations. Its
[before regression](../test/results/context-identity-monotonic-before.log) failed;
the [identity and transport race rerun](../test/results/context-identity-monotonic-after.log)
passed after the fix.

The first combined native custody run failed seven request-resolution fixtures:
their authenticated test identity had capture scope but lacked the required read
scope. The production denial was correct; the fixture now supplies both scopes,
and an explicit negative case verifies that capture-only resolution cannot create
a closure fence. The [failed combined report](../test/results/context-execution-resolution-custody-before-environment.json)
retains test exit 1, 801 unchanged hashes and no cleanup failures; its new API
execution/publication case passed. The [focused SQL/S3 resolution rerun](../test/results/context-resolution-focused-environment.json)
passed 15 named tests, also with 801 unchanged hashes and no cleanup failures.
This targeted pass does not replace the pending full combined qualification.
Other external results below predate migrations 00035/00036 unless explicitly
identified otherwise.

API-only planning and verification now support an unscheduled Pod without Node
or exec permission. Node acquisition retains its historical scope encoding.
The console shows the actual selected Pod and keeps uncertain submissions tied
to their original key. Acceptance is a receipt; independently authorized durable
progress determines the current phase. A five-minute review handle outlives the
short observation used to generate an assessment, and submission reacquires
current facts without silently changing the reviewed scope.

Review found a response-freshness gap: a final identity lookup could finish after
the shorter permission observation expired. Successful service replies now
carry the earliest original metadata deadline privately through presentation
and the final transport write. The [focused regression log](../test/results/context-response-deadline-final.log)
records passing presentation/browser/application race tests, including a blocked
final identity check that must suppress the accepted receipt. This does not
claim real execution or publication.

The [final Go/architecture/SQL gates](../test/results/context-public-code-gates-final.log)
returned 0 (46 packages, 215 internal edges, 25 matching generated SQL files).
The [specification/architecture/design gates](../test/results/context-public-document-gates-final.log)
returned 0, including 1130 positive architecture checks and 120 rejected cases.
The first gate caught a stale embedded policy preset schema; its exact canonical
change was reviewed and regenerated. The failed gate remains recorded separately.

Actual browser qualification exposed an AJV CommonJS helper import defect that
Vitest's transformed module path had hidden. A native ESM regression reproduced
it, then passed after the build adapter correction without changing validator
rules. Browser testing also corrected explicit form labels and an incorrect test
expectation for the existing CSRF-denial status. `npm run check` now passes 49
component tests plus native positive/negative validator cases; production build
passes. The [browser terminal log](../test/results/context-public-browser-after.log)
and [environment](../test/results/context-public-browser-environment.json) record
10 passed journeys, eight accessibility scans, no external/CSP/runtime errors,
885 unchanged source/build hashes and the exact installed Chrome test binary.
The session/capture ports in that browser fixture remain explicitly synthetic.

The source-frozen [custody suite](../test/results/context-public-custody-environment.json)
passed 255 named tests; [database recovery](../test/results/context-public-recovery-environment.json)
passed all three initial/restarted/restored phases; [initial installation](../test/results/context-public-installation-environment.json)
passed 12 tests. Each reported terminal 0, 773 unchanged source hashes and no
cleanup failures. These qualify components with the fixtures' documented
synthetic authority boundaries. The full current Kubernetes/context suite
failed in `TestOwnerEndpointsWithRealKubernetes`: the current workload-protection
check became unavailable immediately after a controller replaced a Pod. Its
[preserved report](../test/results/context-public-native-before-environment.json)
records unchanged sources, test exit 1 and no cleanup failures. The new
unscheduled API-only test passed, including denial of Node/exec access and exact
362-byte encrypted/verified native retrieval. That component result does not
make the failed suite successful. A focused native reproduction then established
the resource-version race: an update between GET and dry-run returns HTTP 409
before admission is checked. The bounded exact-conflict retry retains the
original five-second deadline and rejects unrelated denials. Unit regressions
failed before and passed after the fix. The
[targeted native rerun](../test/results/owner-probe-race-after-environment.json)
passed `TestOwnerEndpointsWithRealKubernetes`, including deterministic version
advancement, with 773 unchanged sources and no cleanup failures. This targeted
result does not replace the pending combined full-suite qualification. The
initial diagnostic logged binary Kubernetes status bytes; the failed raw log is
preserved, diagnostics now escape bytes, and the harness records source/cleanup
evidence even on invalid UTF-8 without treating that run as successful.

A subsequent visual/contract review corrected the browser retention notice to
submission-based dates, matching ADR-103: waiting consumes the lifetime and an
accepted retry does not reset it. It also found a remaining structured parity
bug: the shared assessment still emits the generic first-acquisition anchor.
The typed schema/presentation/rule-digest correction is now applied: exact
pod-status previews require `submissionPreparation`, v2 rules invalidate old
unsubmitted reviews, and accepted same-key replay preserves original dates.
Durable accepted-or-closed recovery is now implemented at the component level;
its new native concurrency fixtures pass the focused SQL/S3 run above. Concurrent preflight
failures are still never proof that another invocation did not commit.

The protected bootstrap still leaves collection disabled. Production execution
provenance, capability/storage producers, publication/download composition,
installation and control-metadata fairness/retirement remain open. No complete
S-01/S-02 exit or public listener is enabled by these component additions.

## Qualified checkpoint: shared context preview and request

Parallel implementation now connects [named workload resolution](architecture/workload-target-resolution.md),
the [shared context coordinator](architecture/context-investigation.md),
[impact/data-handling assessment](architecture/context-assessment.md) and durable
SQL previews under [ADR-103](decisions/103-durable-context-previews.md).
The exact diagnostic remains `builtin-pod-status-v1`; this does not implement
the broader incident-context preset or enable a public collection route.

Migration 00033 adds immutable passive previews, the existing ten-per-human
limit across clients and 1000-per-installation limit, with expiry-only cleanup.
Accepted idempotency lookup runs before preview access and checks current stored
target rights/recovery after locks. It can return the original operation after
the preview expires or the Pod disappears. Fresh requests preserve reviewed pod,
owner/node, scope, audience, placement and rule pins while reacquiring all authority.
Review corrected a retention defect before qualification: evidence dates begin
at submission preparation, so a two-minute review does not consume a requested
one-minute evidence lifetime. The selected owner chain, not matching labels alone,
determines permission and storage scope.

The same assessment projection serves browser/MCP composition. It explains
unknown workload overhead, configured native output limits, transient raw API
exposure and retained manifest provenance. Review corrected an overly narrow
transient-only claim for addresses/paths: issuer URL provenance is retained in
the protected manifest. Relative access, deletion due and administrator maximum
ages remain distinct; no preview promises an absolute future evidence expiry.

Focused coordinator, resolver, storage-reader and assessment race tests passed.
[Combined Go/architecture/SQL gates](../test/results/context-preview-code-gates.log)
returned 0: vet/all race tests, 46 packages/205 internal edges and 24 matching SQLc
files. [Specification/architecture/design gates](../test/results/context-preview-document-gates.log)
also returned 0, including 1123 positive architecture checks and 120 rejected cases.
The read-only storage adapter preserves source freshness and exact revisions
without reserving capacity or accepting configuration.

Native qualification completed with the results below. The first full custody run failed after
the new concurrency fixture retained its preview pools into later download tests,
exhausting PostgreSQL connections. [The failed test log](../test/results/context-preview-custody-before.log),
[provider log](../test/results/context-preview-custody-before-postgres.log) and
[environment](../test/results/context-preview-custody-before-environment.json)
are retained: 744 unchanged source hashes, no cleanup failures, and an actual
nonzero terminal result. Helper/subtest pool cleanup is now bounded correctly;
database limits were not increased. A storage denial assertion also now uses a
real column and requires SQLSTATE 42501. The [complete custody rerun](../test/results/context-preview-custody-final.log)
returned 0 with 248 passing parent/subtest entries. Its
[environment report](../test/results/context-preview-custody-final-environment.json)
records 744 unchanged hashes and no cleanup failures; those hashes and actual
terminal completion were checked again after cleanup. The
[recovery regression](../test/results/context-preview-recovery.log) returned 0
across initial, restarted and restored database phases. Its
[environment report](../test/results/context-preview-recovery-environment.json)
records 744 unchanged hashes and no cleanup failures. The
[first-installation suite](../test/results/context-preview-installation.log)
also returned 0 with 12 passing entries; its
[environment report](../test/results/context-preview-installation-environment.json)
has the same verified hash count and clean removal. These are component fixtures,
not qualified production restore or installer provisioning. The
[full Kubernetes regression](../test/results/context-preview-native.log) returned 0
with 106 passing entries in 232.891 seconds, including workload selection in both
owned clusters. Its [report](../test/results/context-preview-native-environment.json)
records 744 unchanged hashes and no cleanup failures, verified after the actual
harness terminated. The source freeze is released for the next implementation batch.

Remaining: protected production capability/configuration producers, authorized
discovery and capture progress, encrypted free-text reason creation, public
browser/MCP/UI mapping, full execution/publication/native download and protected
installation. Historical capture retirement/fairness (U13) remains a production
blocker; passive preview cleanup does not solve it. No task or slice is complete.

## Console, MCP and shared identity checkpoint

The maintainer authorized parallel subagents where they improve throughput.
Separate ownership produced the [console session boundary](architecture/console-runtime.md),
[MCP HTTP boundary](architecture/mcp-runtime.md) and
[shared current-identity handoff](architecture/current-request-identity.md).
All three are implemented components; no public investigation listener, complete
capture workflow or Helm runtime has been enabled.

The production React/TypeScript workspace now has a locked build, canonical
OpenAPI types and standalone response validators, explicit session/outage/logout
states and an abortable identity scope. The first npm resolution rejected
TypeScript 7 against the generator's TypeScript 5 peer requirement; the product
uses 5.9.3 without a peer override. Full and runtime npm audit reports contain
zero known vulnerabilities. A [failing UI regression](../test/results/console-unit-before.log)
showed that returning to a tab after uncertain logout lost its failed-sign-out
state. Retaining logout intent fixes that race; subsequent component checks
passed all 19 tests. Automatic mutation retry and browser credential/evidence
persistence were not introduced.

The Go asset handler snapshots bounded packaged files, serves only the current
root page and exact hashed assets, and never substitutes HTML for API/auth/native
download paths. The [static race tests](../test/results/console-delivery-final-unit.log)
passed, including the actual built bundle. The
[first browser run](../test/results/console-browser-before.log) failed: its expiry
setup shortened the old session before login created a new one. The retained
[failure report](../test/results/console-browser-before-report.json) also exposed
React Aria's fixed pressable CSS being blocked by CSP. The test now shortens the
actual new session, and the handler permits only that reviewed CSS hash without
unsafe-inline/eval. An independent source/hash regression guards that exception.

The [final browser run](../test/results/console-browser-final.log) returned 0 in
3.022 seconds: eight journeys, four accessibility scans, zero external requests,
runtime/CSP errors or reported accessibility violations. Its
[environment report](../test/results/console-browser-final-environment.json)
records 653 unchanged scoped Go/web/bundle hashes. The fixture uses actual
loopback HTTPS, Go static/session handlers and built React with an explicitly
synthetic current-identity service. It is not real-provider, installation or
full investigation qualification. [Screenshots and report](../test/results/console-browser/report.json)
include the [sign-in page](../test/results/console-browser/sign-in.png) and
[320px layout](../test/results/console-browser/sign-in-mobile.png).

MCP uses official Go SDK v1.8.0 with current bearer resolution, resource metadata,
finite request/output/concurrency bounds and no invented tools. Actual official
clients negotiate both required revisions in
[the passing race suite](../test/results/mcp-boundary-final.log). Separate
before-fix tests reproduced inconsistent legacy routing hints and method-case
aliases; their rejection is now covered. Targeted vet, module verification and
the [targeted vulnerability scan](../test/results/mcp-boundary-vulnerability.log)
passed. Current identity and empty SDK discovery do not implement evidence tools
or qualify real-provider MCP OAuth.

The new C-02 request-owned identity source supports browser cookies and bearer
tokens without exporting OIDC credentials or adding a second policy evaluator.
Current checks retain original cancellation/deadlines and reject changed
principal/policy/groups/scopes. Existing C-03 capture/read/download evaluators
consume it. [Affected race tests](../test/results/current-request-identity-race.log)
passed. The [real-provider suite](../test/results/current-request-provider.log)
subsequently returned 0: eight passing parent/subtest entries in 4.465 seconds,
including current request resolution before and after actual HTTPS logout with
no refresh/credential rotation or recreated session. The
[environment report](../test/results/current-request-provider-environment.json)
records 679 unchanged hashes and empty cleanup failures, verified after actual
harness termination. This uses real Keycloak/PostgreSQL/OpenBao with fixture
administrator provisioning; it does not enable the production workflow.

[Combined Go/architecture/SQL gates](../test/results/console-mcp-code-gates.log)
returned 0 with vet/race tests, 45 packages/192 internal edges and 22 matching
sqlc files. [Console gates](../test/results/console-product-gates.log) returned 0
with generated-contract checks, strict TypeScript, all 19 behavior tests and the
static build. [Specification/architecture/design gates](../test/results/console-mcp-document-gates.log)
also passed; final documentation links are rechecked after recording these results.

The remaining path to S-02 is a shared capture preview/request/progress service,
authorized discovery/case projections, production execution/publication and
native-download composition, plus protected installation. Review also confirmed
the lifetime 1024-row capture ceiling and the API-only status collector's node
dependency; [U13/U14](reviews/user-task-review.md) track them. The implemented
`builtin-pod-status-v1` diagnostic must not be presented as the broader planned
`incident-context/v1` preset. Full scope and all later collectors remain required.

## Installer continuation (still incomplete)

The maintainer explicitly resumed after the fulfilled ADR-098 pause and requested completion of the remaining implementation without further component handoffs. Current work connects the initial-activation coordinator to protected process inputs, scoped credentials and an executable. Verification and remaining installer/recovery gaps will be recorded here; the earlier pause is historical.

[ADR-099](decisions/099-protected-initial-installer.md) and its [execution contract](architecture/initial-installer.md) now describe the private executable, closed provider/pin projection, finite Restricted Pod, native namespace guard and exact live Pod/account proof. The startup file determines the immutable plan digest. Separate preparation/audit/activation roles and the existing encrypted object audit preserve ADR-098; no schema migration, public route or chart runtime switch was added.

The [first native run](../test/results/initial-installer-native-first.log), [environment report](../test/results/initial-installer-native-first-environment.json) and [terminal harness](../test/results/initial-installer-native-first-check.log) returned 1. All 692 recorded source hashes matched after actual termination and cleanup was empty. The actual image reached activation with exit 0 and rejected missing protection/unbound writer tokens with exit 1, but all three cases failed their subsequent immediate token-retirement assertion. Kubernetes's positive authentication cache invalidates that assertion. The installer now independently reads live account objects; retirement waits for measured authentication denial. The same run exposed an older concurrent-test assumption: independently timed source snapshots can legitimately lose to a newer stored observation. The race now shares one observation and a separate regression requires older observations to remain rejected; production SQL semantics are unchanged. These partial outcomes are not a passing suite.

The [affected race tests](../test/results/initial-installer-unit-race.log) returned 0, including deleted/replaced accounts despite accepted authentication, wrong/unbound Pod identity, privileged principals and Pod specification mutation. [Specification/architecture/design gates](../test/results/initial-installer-document-first.log) returned 0 with 65 schemas and 12 application roles.

The [corrected native run](../test/results/initial-installer-native-second.log), [environment report](../test/results/initial-installer-native-second-environment.json) and [terminal harness](../test/results/initial-installer-native-second-check.log) returned 0: 15 passing parent/subtest entries in 39.098 seconds, all 693 captured source hashes verified after termination and no cleanup failures. The actual Restricted installer Pod `58f2f6f3-25bf-4ecb-b615-048abd15f4fa` completed with exit 0, using image `sha256:09f753af6cae994416e606ed1116c46b1a9f6c5e52a900890a2de1218ba8d7a8` built from binary SHA-256 `2cca176b5c6c960a7c60153c9b6611842cf12bd0dcfeeb55ece9196290f43f45`. Missing-guard and unbound-token Pods exited 1 without consuming a witness or inserting an attempt. Native namespace protection rejected RBAC-permitted workload creation, pinned-Pod updates and writer-token minting; fixture-only attack rights were removed before launch. Probe-token retirement was confirmed after the actual authentication cache ceased accepting it, not assumed from Secret deletion. All three Pods were removed normally and the harness removed its owned clusters/image.

[Full code gates](../test/results/initial-installer-code-gates.log), `make go-check go-architecture-check sql-check`, returned 0 with vet/race tests, 43 packages/189 internal edges and 22 matching sqlc files. The [full context regression](../test/results/initial-installer-full-context.log), [environment/source report](../test/results/initial-installer-full-context-environment.json) and [terminal harness](../test/results/initial-installer-full-context-check.log) subsequently returned 0: 102 passing entries in 184.060 seconds, all 693 captured source hashes matched after termination and cleanup was empty. The actual hub-worker Pod `302ad0ed-ce0f-4ff7-89c4-72faaaa49532` used image `sha256:2dcce337c1fac4c16097b02ee443c7263d622b1c8a3df16074f6af6785bdf208`, built from the same `2cca176b5c6c960a7c60153c9b6611842cf12bd0dcfeeb55ece9196290f43f45` binary. This snapshot predates the ADR-100 dependency/credential changes below and is not their qualification. Production provider/pin provisioning, credential retirement, local-key bootstrap and restart/restore remain required; the passing fixture still provisions synthetic external credentials and is not the product installer lifecycle.

## Continuing: temporary SQL credential lifecycle (ADR-100)

[ADR-100](decisions/100-temporary-initial-sql-credentials.md) and its [contract](architecture/initial-sql-credentials.md) add three random expiring purpose logins, client-derived SCRAM verifiers, exact direct/ambient privilege validation, replay without renewal, and idempotent retirement of both new-login and existing-session effect authority. A closed 4096-byte private state codec binds persisted passwords to the complete startup plan. There is no SQL migration or public API change. The trusted maintenance principal and Secret/provider orchestration remain separate from the activation Pod.

The [first provider suite](../test/results/initial-role-provider-first.log), [source/cleanup report](../test/results/initial-role-provider-first-environment.json) and [harness](../test/results/initial-role-provider-first-check.log) returned 0 with 12 passing entries, all 696 captured hashes verified and empty cleanup. Subsequent review identified a missing ambient privilege check. The [before-fix regression](../test/results/initial-role-ambient-before.log), [report](../test/results/initial-role-ambient-before-environment.json) and [harness](../test/results/initial-role-ambient-before-check.log) returned 1 because a PUBLIC table grant was accepted. After implementing indirect privilege checks, the [corrected provider regression](../test/results/initial-role-ambient-after.log), [report](../test/results/initial-role-ambient-after-environment.json) and [harness](../test/results/initial-role-ambient-after-check.log) returned 0: 12 entries in 2.364 seconds, all 696 hashes verified and no cleanup failures. Table/column grants via PUBLIC, public schema creation and a callable SECURITY DEFINER function are all rejected. Fault injection uses only the owned test database.

The [private-state race tests](../test/results/initial-role-state-unit.log) returned 0. They cover exact round trip, expired-state retirement decoding, wrong installation/plan, duplicate/unknown/case-aliased/trailing JSON, malformed credentials, bounded input and redacted formatting. The [dependency scan](../test/results/initial-role-vulnerability.log) found no vulnerabilities in imported packages or called symbols; the earlier module-only unused-package advisory remains documented.

The [first native selection](../test/results/initial-role-native-selection.log), [report](../test/results/initial-role-native-selection-environment.json) and [harness](../test/results/initial-role-native-check.log) returned 1 because the native opt-in environment variable was omitted: the selected test skipped. All 698 hashes matched and cleanup was empty. This provides no product-test qualification. The [corrected native invocation](../test/results/initial-role-native-corrected-check.log), [suite](../test/results/initial-role-native-final.log) and [source/cleanup report](../test/results/initial-role-native-final-environment.json) returned 0: 16 passing entries in 39.019 seconds, all 698 hashes verified and no cleanup failures. It persisted and reread exact immutable Secret state before the product manager provisioned random expiring roles. The actual activation Pod used those credentials and all three native cases retired them through the product adapter. Image `sha256:227f6b9bb2f309720a1ad4741919830e67e47b8bf756c9bd48d883a4686d529e` was built from binary SHA-256 `0bf7d639822a9fa78171a99b5c096a863c766234561072e5c304a3261cb03e7a`. Maintenance principals, provider setup and Kubernetes writes still belong to the fixture, not a product supervisor.

[Code gates](../test/results/initial-role-code-gates.log), `make go-check go-architecture-check sql-check`, returned 0: vet/race, 43 packages/190 internal edges and 22 matching sqlc files. The first [document gate](../test/results/initial-role-document-gates.log) rejected relative schema references; the schema now follows the repository's absolute-reference convention. The [recheck](../test/results/initial-role-document-recheck.log) returned 0: 66 schemas, 541 rejected examples/8780 assertions, architecture 1103 positive/120 negative checks and the existing 63-screen design checks. These are design gates, not participant testing or full platform qualification.

Continuing into production protected credential persistence and provider lifecycle. The installation supervisor, local-key pre-activation path, restart/restore, complete public investigation workflow and later collection mechanisms remain unfinished; no slice exit or full product completion is claimed.

The protected Kubernetes state adapter now owns current administrator/guard/startup checks, one create-only Secret request, exact-content lookup after an uncertain reply and UID-bound reads suitable for later retirement. The [race tests](../test/results/initial-state-unit.log) returned 0 for nine modes, including wrong administrators, an already-launched Pod, missing/lost guards, expired final observations, forbidden writes and an uncertain response without POST replay. The [native suite](../test/results/initial-state-native-final.log), [source report](../test/results/initial-state-native-final-environment.json) and [terminal harness](../test/results/initial-state-native-check.log) returned 0: 16 passing entries in 51.853 seconds, all 700 hashes verified and no cleanup failures. The product adapter persisted and reread the Secret before role provisioning, rejected changed contents/wrong UIDs, allowed exact retained-state retirement after Pod termination and denied creation after launch. Image `sha256:f36ee36c2a445713c52f295e72374b4bea0879513c2ac92dbf182c27c96e2674` was built from binary SHA-256 `6e127a1441a691f309cfc816e50836b99b0c88ea7d4aa78d34a97f26cc6d60e9`. The fixture still establishes the clean namespace, guards, startup inputs, maintenance principal and external providers; persistent supervisor orchestration remains unfinished.

The [credential substitution regression](../test/results/initial-role-binding-before.log), [report](../test/results/initial-role-binding-before-environment.json) and [harness](../test/results/initial-role-binding-before-check.log) reproduced a real loader gap: otherwise functional fixture SQL roles for an unrelated scope were accepted and the invalid Pod reported success. Exit 1; all 700 hashes matched and cleanup was empty. The executable now derives the exact installation/purpose username before any connection and requires actual SCRAM-SHA-256 authentication. The [affected race tests](../test/results/initial-role-binding-unit.log) returned 0 across PostgreSQL, Kubernetes and bootstrap packages.

The [corrected native suite](../test/results/initial-role-binding-after.log), [source report](../test/results/initial-role-binding-after-environment.json) and [harness](../test/results/initial-role-binding-after-check.log) returned 0: 17 passing entries in 60.117 seconds, all 700 hashes verified and empty cleanup failures. The wrong-role Pod now fails before witness consumption/SQL attempt creation; the valid Pod still activates and protected state persistence/retirement remains qualified. The [full code gate](../test/results/initial-state-code-gates.log) then returned 2 due to an existing mTLS fixture failure; it is not a passing gate. A 200-run [targeted repetition](../test/results/initial-state-forwarder-repeat.log) happened to pass, so it was not treated as a fix. The [deterministic regression](../test/results/initial-state-fixture-before.log) instead reproduced the cause: the fixture regenerated immutable enrollment `ClaimedAt` on every observation, allowing a second boundary between the authenticator's two reads to simulate a replacement. The fixture now keeps its first enrollment while observations and certificate renewal remain current. The [whole mTLS race suite](../test/results/initial-state-fixture-after.log) returned 0; production checks were not weakened. The [full code recheck](../test/results/initial-state-code-recheck.log), `make go-check go-architecture-check sql-check`, subsequently returned 0 with vet/race, 43 packages/190 internal edges and 22 matching sqlc files, including stable enrollment through certificate renewal. The earlier native report therefore differs from current source only in this test fixture; its runtime binary remains the qualified one. The [document/design gates](../test/results/initial-state-document-gates.log) returned 0 with 66 schemas, 541 rejected examples/8790 assertions, 1104 positive/120 negative architecture checks and 63 design screens. These results still do not supply the clean-namespace/provider/launch supervisor or full installation/user workflow.

## Continuing: installation namespace staging (ADR-101)

[ADR-101](decisions/101-installation-namespace-staging.md) and its [contract](architecture/initial-namespace-staging.md) add an inert pre-namespace policy plan and a current reader bound to actual namespace/guard identities. Setup permits only configured administrators; the single non-administrative exception is an explicit dry-run UPDATE of the named final startup inputs. A distinct preparation marker remains denied, so staging and final protection can be probed independently. This adds no runtime activation, SQL migration, public API, dependency or Helm switch.

[Unit/race checks](../test/results/initial-namespace-unit.log) returned 0. The [native test](../test/results/initial-namespace-native-final.log), [source/cleanup report](../test/results/initial-namespace-native-final-environment.json) and [terminal harness](../test/results/initial-namespace-native-check.log) returned 0: one test in 7.933 seconds, all 704 hashes verified after actual termination and no cleanup failures. The policy/binding were installed before a fresh owned namespace; the future writer account was created only after an independent native proof. Actual RBAC-permitted Secret/Pod/token/persisted-input operations were denied; harmless final-input dry runs were initially allowed and then independently denied by a separate final policy. Removing the staging binding invalidated the current reader. The namespace was removed normally after owned guard retirement. No provider credentials or activation were installed; this is not a complete clean-history or multi-API-server qualification.

[Code gates](../test/results/initial-namespace-code-gates.log), `make go-check go-architecture-check`, returned 0 with vet/race and 43 packages/190 internal edges. [Specification/architecture/design gates](../test/results/initial-namespace-document-gates.log) returned 0. Production create-only namespace/bootstrap journal, provider provisioning, guarded handover, local-key bootstrap, restart/restore and complete user workflows remain pending. Continue into those producers without treating the guard observation as historical integrity or a completed installation.

### Namespace creation and exact resumption

The staging continuation now includes the product `InitialNamespaceCreator`.
It makes ordered create-only policy/binding/namespace requests under current
administrator identity, returns acknowledged partial pins and refuses automatic
repair/adoption. Read-only resumption checks exact retained native identities and
the original preparation request. No provider credentials or activation are
created by this adapter; the durable supervisor journal remains in progress.

The [failing response regression](../test/results/initial-namespace-creation-before.log)
returned 1: omitted namespace reply labels/annotations inherited fields from the
outgoing request. Decoding into an empty response fixes both cases. The
[affected race tests](../test/results/initial-namespace-creation-after.log) returned
0, covering lost replies without POST replay, partial acknowledged identities,
administrator loss, collisions, changed/replaced/missing guards and namespace
replacement. Integration cases in that command skip without the external fixture.

The [actual Kubernetes test](../test/results/initial-namespace-creation-native-final.log),
[source/cleanup report](../test/results/initial-namespace-creation-native-final-environment.json)
and [terminal harness](../test/results/initial-namespace-creation-native-check.log)
returned 0: one test in 8.193 seconds, all 706 source hashes verified after
termination, unchanged sources and no cleanup failures. It uses the product
creator, waits for read-only native resumption, rejects an existing namespace,
wrong namespace identity and another preparation request, then preserves the
independent staging/final guard checks. Removal of the binding denies both
current protection and resumption. Complete resource inventory, durable
preparation state and the provider/handover supervisor remain required.

The subsequent [code gates](../test/results/initial-namespace-creation-code-gates.log)
and [document/design gates](../test/results/initial-namespace-creation-document-gates.log)
returned 0 before the journal continuation below.

## Continuing: durable preparation creates (ADR-102)

[ADR-102](decisions/102-initial-preparation-journal.md) and the
[journal contract](architecture/initial-preparation.md) add the private public-data
ConfigMap record, ordered bounded intent/receipt transitions and exact guarded
resumption. Only an acknowledged first conditional update reports a fresh
attempt; unknown replies, conflicting updates, expired final checks and replay
cannot renew it. No SQL migration, dependency, public endpoint or runtime Helm
switch changed. Initial root persistence and the actual setup effect supervisor
remain unfinished.

The [journal race tests](../test/results/initial-preparation-unit.log) returned 0
in 17.496 seconds. They exercise concurrency, persisted-but-lost update replies,
expiry/guard loss after a write, administrator loss, journal replacement, malformed
history, pending-intent exclusion, immutable receipts and replay without a new
attempt. The [native run](../test/results/initial-preparation-native-final.log),
[source/cleanup report](../test/results/initial-preparation-native-final-environment.json)
and [terminal harness](../test/results/initial-preparation-native-check.log)
returned 0: one actual Kubernetes test in 10.381 seconds, all 709 captured source
hashes verified after termination, unchanged sources and no cleanup failures.
The product creator persists the root ConfigMap, two concurrent journal callers
retain exactly one fresh intent before the fixture creates the future writer,
then the exact native account receipt survives client reconstruction without a
second attempt. Plan substitution, journal recreation and removed staging
protection deny. The account mutation and harmless probe provisioning are still
fixture-owned; the journal itself is not an implemented resource supervisor.

[Full code gates](../test/results/initial-preparation-code-gates.log),
`make go-check go-architecture-check`, returned 0 with vet/race, 43 packages and
190 internal edges. [Specification/architecture/design gates](../test/results/initial-preparation-document-gates.log)
returned 0: 67 schemas, 550 rejected examples/8842 assertions, 1106 positive and
120 negative architecture checks, and the existing 63 design screens. Continue
with exact setup resource creation/reconciliation, root retention, complete
inventory, protected handover and provider/retirement orchestration; no complete
installation or investigation workflow is enabled by these component results.

### Predefined setup resource creation

The continuation now adds the actual `InitialPreparationResources` producer for
the writer account, two namespace Roles/RoleBindings and the predefined
ClusterRole/ClusterRoleBinding. It binds the validated public workload-plan
digest, reserves an intent before POST, verifies the empty-decoded typed reply
and exact operation markers, then records the actual receipt. Retries use only
lookup; an absent, replaced or mutated target never causes a second create.
Pods, Secrets, arbitrary bodies and extra RBAC rules are unavailable through this
producer. Probe bootstrap, root retention and the remaining supervisor remain
separate work.

The [derived-name regression](../test/results/initial-preparation-names-before.log)
returned 1: a valid account name could produce an invalid overlong Role name.
The shared workload builder now rejects that plan before any side effect.
[Affected race checks](../test/results/initial-preparation-resources-after.log)
returned 0 in 29.790 seconds, including lost resource replies, missing/replaced
accounts, changed/omitted automount settings and no recreation on retry.

The [native resource run](../test/results/initial-preparation-resources-native-final.log),
[source/cleanup report](../test/results/initial-preparation-resources-native-final-environment.json)
and [terminal harness](../test/results/initial-preparation-resources-native-check.log)
returned 0: one Kubernetes test in 36.195 seconds, all 710 captured source hashes
verified after terminal completion, unchanged sources and no cleanup failures.
The product created all seven exact setup resources and repeated `Ensure`
preserved their UIDs. The journal also retained its independent concurrent
intent/receipt test, changed-plan/removed-guard denials and separate final-input
proof. Owned cluster RBAC and namespace resources were removed normally. This
test creates no workload or provider credentials and supplies no activation.
[Document/design gates](../test/results/initial-preparation-resources-document-gates.log)
returned 0 with 67 schemas, 550 rejected examples/8852 assertions, 1106 positive
and 120 negative architecture checks, and the existing 63 screens. The
[full code gates](../test/results/initial-preparation-resources-code-gates.log),
`make go-check go-architecture-check`, subsequently returned 0 with vet/race,
43 packages and 190 internal import edges. These passing component results do
not enable a public collection route or complete the installation supervisor.

## Paused at maintainer request: ADR-098 checkpoint (2026-10-11)

Implementation is paused at the verified first-installation activation component described below. No subsequent installer implementation was started; the follow-up consisted of reading the existing contracts. The stop check found no active repository build/test processes and no Asservat-named Docker containers. Existing verification logs and their cleanup reports remain the evidence for the completed component; no integration suite was rerun merely to pause.

No runtime or public contract changes accompany this pause. Production installer plan/credential/pin provisioning, the pre-activation local-key audit path, and separate restart/restore coordination remain unfinished. The full product and S-01/S-02 exits are not complete. After explicit resumption, continue with protected installer provisioning from this checkpoint; do not treat the first-installation coordinator as restore authority or enable the chart/public workflow prematurely.

## Resumed: first-installation activation (ADR-098)

The maintainer resumed the full implementation goal after the ADR-097 pause. [ADR-098](decisions/098-first-installation-activation.md) and the [component contract](architecture/initial-installation.md) now add the C-04 initial coordinator, separate C-08 audit ports, C-21 SQL/S3 adapters and migration 00032. Exact table-inventory locks reject operational history before preparation and final activation. The original claim is consumed outside SQL, audited through verified envelope encryption and separately acknowledged before atomic activation. Completed retries cannot clear subsequent recovery/suspension. Production installer provisioning and all restart/restore coordination remain unfinished; no chart runtime or public investigation endpoint is enabled.

Current measured evidence:

- [Deterministic failing clock regression](../test/results/owner-fixture-clock-before.log) reproduced the old mTLS fixture problem: setup and client clocks straddled a renewal boundary. The fixture now follows the caller's clock with X.509 second precision. [Whole mTLS race suite](../test/results/owner-fixture-clock-after.log) returned 0; production credential validation was unchanged.
- [First-installation provider tests](../test/results/initial-installation-first.log), [source/cleanup report](../test/results/initial-installation-first-environment.json), [terminal harness](../test/results/initial-installation-native-check.log): `make initial-installation-integration` returned 0, ten parent/subtest entries, all 683 captured source hashes verified after termination and empty cleanup failures. The case took 0.97 seconds; this is not capacity qualification. It composes real PostgreSQL/S3/OpenBao with explicit synthetic Kubernetes witness/source observations.
- The provider cases cover one retained attempt under four concurrent preparations; missing witness/audit; interrupted audit and exact resumption; existing operational rows before or after preparation; SQL loss after witness consumption; unknown tables/row security; source/incarnation substitution; original expiry through a lock wait; and actual SQLSTATE `42501` cross-role denials. A completed retry preserves a subsequently restored recovery block. The new migration does not activate existing roots.
- [Code gates](../test/results/initial-installation-code-gates.log): `make go-check go-architecture-check sql-check` returned 0 with vet/race, 43 packages/189 internal edges and 22 generated SQL files. Subsequent changes add native composition and audit-negative tests; their qualification is tracked separately below.
- [Audit and credential tests](../test/results/initial-installation-audit-clock-tests.log) returned 0. The purpose-separated encrypted audit rejects changed witness scope, plan/source/claim/database, wrong format and corrupt bytes, and denies failed encryption.
- [First native fixture attempt](../test/results/initial-installation-context-check.log), [environment](../test/results/initial-installation-context-first-environment.json) failed before product tests: Kind's first control plane could not bootstrap its administrator before the deadline. Exit 1; all 685 captured hashes still matched, owned fixtures removed, no cleanup failures. No product qualification follows. The harness now retains failed nodes only until its existing finally cleanup and exports owned-node diagnostics on setup failure.
- The old temporary validation environment had disappeared. Installing the previous requirements in a fresh environment [failed the negative schema checks](../test/results/initial-installation-document-gates.log) because jsonschema's optional URI/date-time checkers were absent. The requirements now select its maintained `format-nongpl` extra, and [an explicit preflight regression](../test/results/spec-missing-format-regression.log) rejects incomplete environments. [Specification/architecture/design recheck](../test/results/initial-installation-document-recheck.log) returned 0 after installing the declared dependencies. This follows the [library's documented format dependencies](https://python-jsonschema.readthedocs.io/en/stable/validate/#validating-formats); no product runtime dependency changed.

The [native protected-input composition](../test/results/initial-installation-native-context.log), [environment report](../test/results/initial-installation-native-context-environment.json) and [terminal harness](../test/results/initial-installation-context-diagnostic-check.log) now pass: exit 0, 15 passing parent/subtest entries, all 685 captured hashes verified after termination and no cleanup failures. The real protected witness/fleet-source case took 6.71 seconds and the separate witness suite 6.85 seconds. It uses actual Kubernetes API identities, UID pins and native admission with real SQL/S3/OpenBao; the SQL coordinator enables the initial root without a fixture administrator activation UPDATE. After the fixture independently sets a later recovery block and removes source protection, the coordinator cannot clear it. Tokens, plan digest, roles and provider setup remain fixture-provisioned, not a protected installer Pod. Both owned clusters and the synthetic worker image were removed. The preceding Kind startup failure remains failed historical evidence; no host setting or other cluster was changed.

[Final code gates](../test/results/initial-installation-final-code-gates.log) returned 0 after the native-composition and audit-negative tests were added. [Final specification/architecture/design gates](../test/results/initial-installation-final-document-gates.log) also returned 0.

The full schema-32 [custody suite](../test/results/initial-installation-full-custody.log), [report](../test/results/initial-installation-full-custody-environment.json), [terminal harness](../test/results/initial-installation-full-custody-check.log) returned 0 with 240 passing entries in 106.456 seconds. The full [fleet suite](../test/results/initial-installation-full-fleet.log), [report](../test/results/initial-installation-full-fleet-environment.json), [terminal harness](../test/results/initial-installation-full-fleet-check.log) returned 0 with 99 passing entries in 35.189 seconds. All 685 source hashes matched each report after termination and both cleanup lists are empty.

The full [native context suite](../test/results/initial-installation-full-context.log), [report](../test/results/initial-installation-full-context-environment.json), [terminal harness](../test/results/initial-installation-full-context-check.log) also returned 0: 102 passing entries in 185.500 seconds, all 685 hashes matched and cleanup is empty. The actual Restricted worker case passed in 17.61 seconds including normal deletion. Observed Pod `17cb9b4e-b2e4-4af0-81bf-7c25bcc7d07f` used image `sha256:2f77e8dc37a876625aeb59bae7d6234663fe32869507fd0ab78be8e6871d7aaf`, built from binary SHA-256 `c57c6aeefd76d29d7a62c299aaa2a17a6dbb10d18aab5bc45fd1b2c923b079ba`. Both owned clusters and the test image were removed. Native first-installation composition runs separately under its explicit fresh-database selection; the full context suite retains synthetic recovery in its older worker/owner fixtures. No production timed token renewal, deployment capacity or end-user slice completion follows.

The [database recovery run](../test/results/initial-installation-recovery.log), [report](../test/results/initial-installation-recovery-environment.json), [terminal harness](../test/results/initial-installation-recovery-check.log) returned 0 for all three actual phases against schema 32, with 685 matching source hashes and clean removal. The PostgreSQL start changed from `2026-10-11T11:33:58.286602Z` to `11:34:02.513348Z` on restart while OID stayed 16384; logical restore kept that process time and changed the database OID to 18111. Both denied saved activation. The test's subsequent recovery acceptance remains explicitly synthetic, not the new first-installation method.

No old fixture result is presented as a run of changed source. Next finish protected installer plan/credential/pin provisioning, including a pre-activation local-key audit capability without a recovery dependency cycle, and the separate qualified restart/restore protocol. Then continue the end-user context/download flow and remaining product slices.

## Paused checkpoint: one-use installation witness (ADR-097)

The maintainer requested a neutral stopping point. [ADR-097](decisions/097-one-use-installation-witness.md) and the [component contract](architecture/installation-witness.md) record the completed bounded change: C-04 read/consume ports, private domain/wire values and a C-21 Kubernetes adapter for a protected one-use ConfigMap. Consumption uses current exact writer identity/RBAC, independent admission proof, UID/resourceVersion comparison, native immutability and independent readback. Exact retries retain the original claim; conflicts, expiry, missing protection and replaced objects deny use. No SQL activation writer, public endpoint, dependency or Helm runtime feature was added.

Actual verification:

- [Affected race tests](../test/results/installation-witness-unit.log): `go test -race ./internal/domain/fleet ./internal/adapters/kubernetes -run 'TestInitialWitness|TestFleetAdministration'` returned 0. Closed-wire tests include duplicate/unknown/case-alias members, zero digests/OID, excessive intervals, submicrosecond/noncanonical timestamps and equal source/plan digests.
- [Native Kubernetes suite](../test/results/installation-witness-native.log), [environment report](../test/results/installation-witness-native-environment.json), [terminal harness](../test/results/installation-witness-first-check.log): the targeted `TestInstallationWitnessWithRealKubernetes` run returned 0, with all four parent/subtest entries passing. The case took 9.26 seconds. All 674 captured source hashes matched after actual harness termination, `sourceUnchangedDuringTest` is true and cleanup failures are empty. Both owned Kind clusters were removed. These times are not throughput measurements.
- The native case verifies consumption/repeat, four competing claims with one retained winner, immutable reset denial, writer CREATE/DELETE denial, missing/recreated UID rejection, expired-attempt denial and missing-admission refusal without consumption. It uses real Kubernetes API tokens and synthetic database/source/plan facts. It does not qualify a Pod-bound protected installer, SQL pristine-state checks or activation audit.
- [First broader Go check](../test/results/installation-witness-go-gates.log) returned 2 from Make: the existing `TestOwnerForwarderCancellationBeforeTransmission/client-after-lookup` failed during credential fixture enrollment with `signed control work rejected`. The witness/Kubernetes package passed. No mTLS source was changed. [Ten targeted race-enabled repeats](../test/results/installation-witness-existing-mtls-recheck.log) returned 0; the intermittent fixture failure remains an open qualification issue rather than a claimed fix.
- [Full Go recheck](../test/results/installation-witness-go-recheck.log): `make go-check go-architecture-check` returned 0, including vet/race tests and the 43-package/189-edge architecture check. A passing repeat does not erase the preceding intermittent failure.
- [Documentation gates](../test/results/installation-witness-document-gates.log): `make spec-check architecture-check design-check` returned 0, including 64 schemas, 176 requirements/scenarios and 63 design screens. Native source hashes were reverified after these documentation edits; all 674 still match. These design checks do not qualify deployment or cryptography.

The full native context, custody and fleet suites were not rerun for this component. Earlier broad qualification below retains its original source scope. The witness remains unwired, so it cannot enable collection or relax the existing recovery fence.

Next task after explicit resumption: finish the independent initial/restore activation coordinator, including atomic eligible-SQL checks, encrypted durable activation audit, protected installer identity/pins, recovery checkpoints, old-primary fencing and qualified automatic lossless-restart activation. Resolve the intermittent mTLS fixture failure before relying on repeated broad-suite reliability. No complete TASK, S-01/S-02 exit or whole-product completion is claimed.

## Current database incarnation fence (ADR-096)

[ADR-096](decisions/096-database-incarnation-fence.md) closes a reproduced recovery hole: an old SQL `recovery_blocked=false` flag, followed by fresh configuration observation, was enough to serve current authority. Migration 00031 adds separately accepted PostgreSQL process/database identifiers and a derived effective-trust view. Every product trust read/lock and connector peer join now uses that view, including final capture/download effect checks. Ordinary observers cannot renew activation. The migration also sets stored suspension/recovery flags to blocked for already-running legacy readers. Reactivation must first fence older binaries and credentials. Existing roots receive no automatic activation; public APIs, CRDs, artifact formats and dependency choices are unchanged.

The runtime change is C-21 SQL enforcement with existing C-04/C-14 consumers under REQ-DB-005. Scoped roles gain view SELECT and only the installation-column UPDATE privilege required for their existing row locks. Activation fields remain private. Generated effective rows have a distinct Go type; raw stored trust rows cannot accidentally satisfy the authority helper signatures.

Actual verification:

- [Failing regression](../test/results/recovery-incarnation-before-custody.log), [report](../test/results/recovery-incarnation-before-custody-environment.json): real PostgreSQL reproduced old enabled flags plus source refresh reactivating authority. Exit 1, 665 unchanged source hashes, owned fixtures removed.
- [First integration attempt](../test/results/recovery-incarnation-first-custody.log), [report](../test/results/recovery-incarnation-first-custody-environment.json): the observer lacked the new view's row-lock permission. Exit 1, 666 unchanged hashes, clean removal. The correction grants UPDATE only on its installation column, never the activation fields.
- [Exact-denial test correction](../test/results/recovery-incarnation-permission-custody.log), [report](../test/results/recovery-incarnation-permission-custody-environment.json): PostgreSQL structurally rejects writes to a computed view column with SQLSTATE `0A000` before checking ACLs. The fixture had incorrectly required `42501` for that operation. Other activation writes still require actual `42501` permission denial. Exit 1, 667 unchanged hashes, clean removal.
- [Corrected observer tests](../test/results/recovery-incarnation-observer.log), [report](../test/results/recovery-incarnation-observer-environment.json): ordinary observation, stale activation, equal-time/expired-lock behavior and exact SQL role denials pass. Exit 0 with 667 verified source hashes and clean removal.
- [Final local gates](../test/results/recovery-incarnation-legacy-final-gates.log): `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0. Vet/race tests pass; 43 Go packages/189 internal edges and 22 generated SQL files match. These gates alone do not qualify database restore.
- [Full custody suite](../test/results/recovery-incarnation-final-custody.log), [report](../test/results/recovery-incarnation-final-custody-environment.json), [terminal harness](../test/results/recovery-incarnation-final-custody-check.log): exit 0, 240 passing test entries, 667 verified unchanged source hashes, no cleanup failures. Includes denial of a previously obtained recovery proof after database activation changes, current peer denial, and existing admission/download/accounting behavior.
- [Full fleet suite](../test/results/recovery-incarnation-final-fleet.log), [report](../test/results/recovery-incarnation-final-fleet-environment.json), [terminal harness](../test/results/recovery-incarnation-final-fleet-check.log): exit 0, 99 passing entries, 667 verified source hashes and clean fixture removal. Uses real scoped PostgreSQL/S3/OpenBao provider compositions.
- [Final database recovery phases](../test/results/recovery-incarnation-database-final.log), [report](../test/results/recovery-incarnation-database-final-environment.json), [terminal harness](../test/results/recovery-incarnation-database-final-check.log): `make database-recovery-integration` returned 0 for legacy-root migration, actual restart and actual logical restore. All 667 hashes matched and all owned fixtures were removed. The original server start was `2026-10-11T00:29:07.505461Z`, changing to `00:29:12.472916Z` on restart while database OID remained 16384; restoring into a new database retained that process time but changed OID to 18091. Both rejected saved activation even after source refresh and clearing suspension. Activation itself is explicitly fixture-only.

- [Full native Kubernetes suite](../test/results/recovery-incarnation-before-legacy-block-context.log), [report](../test/results/recovery-incarnation-before-legacy-block-context-environment.json), [terminal harness](../test/results/recovery-incarnation-before-legacy-block-context-check.log): exit 0, 98 passing entries, 667 source hashes verified after terminal cleanup, no cleanup failures. The suite took 186.926 seconds; the actual Restricted worker case passed in 17.61 seconds including normal foreground deletion. Its observed Pod `67e77b46-fb1a-4154-a503-fecd95a2badc` used the exact loaded image `sha256:2488107ceb13ac1bb4cdd1a260ea5dfbfb3f6771fe3a8995f78ad5601b24fd42`, built from binary SHA-256 `11d896b63de865f0c18f7089d56567dc0e8b393a93af3897e4c434d7e7a1e92b`. No timed native token renewal or production capacity claim follows.
- [Final legacy-reader hardening](../test/results/recovery-incarnation-legacy-final.log), [report](../test/results/recovery-incarnation-legacy-final-environment.json), [terminal harness](../test/results/recovery-incarnation-legacy-final-check.log): the final migration additionally blocks stored flags under its table lock, protecting old queries as well as the new view. `make database-recovery-integration` returned 0 again for the enabled legacy root, actual restart and actual logical restore. All 667 source hashes match the final source; cleanup is empty. Restart changed server start `2026-10-11T00:34:57.563366Z` to `00:35:05.824545Z` while OID stayed 16384; logical restore retained that process time and changed OID to 18091.

Qualification scope after the last review: only `migrations/00031_database_activation.sql` and its dedicated `test/integration/database_recovery_test.go` changed after the full custody/fleet/native runs. Every other recorded source hash, including all production Go/query bindings, provider/harness code and native worker sources, still matches those reports. The final database-recovery run qualifies that exact upgrade-path change; final vet/race, SQL-generation and design gates also pass. The broad suites are not represented as reruns of the final migration bytes. Their fresh databases had no existing trust rows to backfill.


Remaining work: independent protected first-installation and restore activation, a protected installation witness that survives SQL loss, retained revocation/deletion/accounting reconciliation, old-primary fencing and qualified automatic lossless-restart activation. Never turn the fixture's administrator UPDATE into a production startup hook. This fence does not detect arbitrary same-process superuser rewrites or complete VM/process rollback and does not qualify replication, physical-backup restoration, production rolling upgrades, or the end-user investigation flow. The full goal, TASK exits and S-01/S-02 remain open.


## Current native hub worker and lifecycle (ADR-094/095)

[ADR-094](decisions/094-native-hub-worker-projections.md) adds a zero-replica Restricted hub-worker Deployment/account/RBAC builder and kubelet-managed API-token projections. The process account has only the union of the already process-accessible Kubernetes client permissions; SQL and key credentials remain separate. ConfigMap/Secret projections select fixed files, startup/source ConfigMaps cannot alias, service-link environment injection is disabled, and image/configuration/role scope remains explicit. Generation does not launch the worker or activate recovery. The local native test builds and loads the actual executable by digest, with hashes taken before compilation.

Native execution exposed lifecycle defects beyond template validation. [ADR-095](decisions/095-hub-workload-garbage-collection.md) permits the exact garbage collector's workload metadata maintenance only with unchanged spec/labels/annotations, and permits final removal of an already-deleting terminal Pod only by its assigned node. Runtime accounts gain no workload-write or credential privilege. Existing policy UID/generation/spec checks remain; installer pins must match the refined policy. The native tests exercise actual foreground deletion and reject changed specs, authority metadata, configuration and Secret updates.

Recorded unsuccessful runs are retained:

- [Initial launch](../test/results/native-worker-first-context-storage.log), [harness](../test/results/native-worker-first-check.log), [report](../test/results/native-worker-first-context-storage-environment.json): the newly created Deployment's resourceVersion raced its controller. Launch now retries only the same UID and unchanged spec. The harness returned 1 with 665 unchanged source hashes and clean fixture removal.
- [Initial Pod startup](../test/results/native-worker-second-context-storage.log), [harness](../test/results/native-worker-second-check.log), [report](../test/results/native-worker-second-context-storage-environment.json): provider connection timeout. The separate [gateway probe](../test/results/native-worker-gateway-probe.log) confirmed host-to-gateway connectivity but timeout from an owned container. No workstation firewall change was made. The fixture now runs TLS bridges in an owned private container with no published ports; its backend hops remain private plaintext. The report returned 1 with 665 unchanged hashes and clean removal.
- [Native operation before teardown fixes](../test/results/native-worker-third-context-storage.log), [harness](../test/results/native-worker-third-check.log), [report](../test/results/native-worker-third-context-storage-environment.json): actual worker observation, encrypted audit, source-removal denial and Lease-loss shutdown succeeded, but foreground deletion failed. The entire case therefore failed. All 666 hashes matched, with clean harness removal.
- [Exact garbage-collector regression](../test/results/native-worker-gc-before-context-storage.log), [harness](../test/results/native-worker-gc-before-check.log), [report](../test/results/native-worker-gc-before-context-storage-environment.json): native RBAC-permitted metadata update received the exact namespace-policy denial and foreground finalizers remained. The harness returned 1 with 665 unchanged hashes and clean removal.
- [Assigned-node regression](../test/results/native-worker-node-before-context-storage.log), [kubelet journal](../test/results/native-worker-node-before-context-storage-kubelet.log), [harness](../test/results/native-worker-node-before-check.log), [report](../test/results/native-worker-node-before-context-storage-environment.json): metadata maintenance succeeded after its correction, while the actual kubelet could not remove its terminated Pod. The fixture also had an overly generic error predicate for negative admission checks; it now verifies exact native policy/binding causes, as the existing guard tests do. This run failed, with 665 verified hashes and clean removal.
- The [first broad gate](../test/results/native-worker-before-tool-isolation-gates.log) passed vet/race but rejected the standalone fixture bridge as an ordinary product package. The bridge is now an explicitly built, build-ignored fixture tool. The architecture rule is unchanged; no product package can import the tool.

The [targeted race tests](../test/results/native-worker-final-units.log) passed. The [corrected local gates](../test/results/native-worker-gates.log) returned 0: `make go-check go-architecture-check sql-check spec-check architecture-check design-check`, covering full vet/race, 43 packages/189 internal edges, 22 matching SQL-generation files, 63 schemas/526 rejected invalid examples and 63 mockup screens. The shared PostgreSQL TLS fixture was restored byte-for-byte to the previous qualified source; no SQL implementation changed.

The final [full native harness](../test/results/native-worker-final-context-check.log) returned 0 after terminal cleanup. Its [suite log](../test/results/native-worker-final-context-storage.log) passed in 185.505 seconds: the outside-Pod worker case took 15.66 seconds, the in-Pod case 17.61 seconds including normal foreground deletion, and the existing owner case 82.70 seconds. The [environment report](../test/results/native-worker-final-context-storage-environment.json) records an unfiltered run, 98 passing top-level/subtests, 665 unchanged source hashes and empty cleanup failures. Every source hash matched after terminal exit. The actual observed Pod image equals the loaded manifest reference recorded with the compiled binary SHA-256; the report retains all three identities. No owned fixture remains. Timings describe entire test cases, not production capacity or stop-latency guarantees.

The native case verifies all three garbage-collector metadata shapes, denials for changed spec/labels/annotations and credential/configuration writes, denial of kubelet-initiated running-Pod deletion, and actual subsequent terminal Pod removal and foreground finalization. The test does not force-delete Pods, remove finalizers as administrator or disable admission. Missing fleet roots remain recovery-blocked, and exactly one explicit fixture-only administrator transition enables subsequent audited observations. Removing source protection fences reads; Lease loss ends the original worker process without recreating the Lease.

Production installer orchestration, independent initial/recovery/restore activation, owner in-Pod routing, scheduled token renewal, provider IAM/TLS topology, whole-hub health and public investigation/download workflows remain open. The S3 fixture uses synthetic credentials; bucket/client scoping is not production backend-IAM qualification. The test image includes its build-ignored synthetic bridge tool and is not a release image. No complete TASK or S-01/S-02 exit follows. Next implement protected installation/activation without fixture authority and compose native owner routing. All source failures above remain failed historical runs.

## Previous private-namespace scheduling (ADR-093)

[ADR-093](decisions/093-bounded-hub-scheduling-permission.md) closes the mismatch between the configuration worker's named Lease RBAC and the private namespace admission policy. The private owner deployment now requires `schedulingLeases`, at most four exact same-namespace account/Lease pairs, with `[]` granting none. Native admission permits only UPDATE on those named coordination Lease main resources; creation/deletion and every other actor/resource remain guarded. Runtime retains original UID/CAS/record checks and named get/update RBAC. This grants scheduling only, never configuration acceptance, recovery, credentials or evidence authority. No new dependency, SQL migration, public API or developer approval is introduced.

The [native pre-fix regression](../test/results/scheduling-lease-before.log) failed at the actual scoped account's persistent Lease update with the namespace policy's exact denial. Its [harness](../test/results/scheduling-lease-before-check.log) returned 1; the [report](../test/results/scheduling-lease-before-environment.json) records the selected test pattern, 661 unchanged source hashes and empty cleanup failures. Every source hash matched before edits. This proves the composition defect; it is not a broad-suite qualification. The context harness now offers a recorded `--run` pattern and rejects zero passing selected tests; its ordinary Make target still runs the complete suite.

The [affected race tests](../test/results/scheduling-lease-units.log) returned 0. The [full local gates](../test/results/scheduling-lease-gates.log) also returned 0: `make go-check go-architecture-check sql-check spec-check architecture-check design-check`, including full vet/race, 43 packages/189 internal edges, 22 matching sqlc files, 63 schemas/526 rejected invalid examples, and the existing 63-screen design validation. Closed input, finite/unique scope, invalid names and caller-memory isolation are covered. The combined native test now installs both source policies and the private namespace policy, confirms actual RBAC scope, and uses temporary broader fixture-only attack rights to distinguish admission rejection from RBAC rejection; those rights must be removed before runtime starts.

The corrected [full native harness](../test/results/scheduling-lease-context-check.log) returned 0 after terminal cleanup. Its [suite](../test/results/scheduling-lease-final-context-storage.log) passed in 169.481 seconds, including the worker case in 15.86 seconds and the existing owner startup/source-protection cases. The [environment report](../test/results/scheduling-lease-final-context-storage-environment.json) records the unfiltered run, 661 unchanged source hashes and empty cleanup failures. Every hash matched current files after the actual terminal result. Both source and namespace admission coexist, actual runtime RBAC remains scoped, temporary attack permissions are removed, missing source protection fences SQL, and deleting the original Lease cancels and joins runtime without recreating it. These durations describe entire cases/suites, not production capacity. No owned context fixture remained after cleanup. Installer-generated projections/workloads, independent initial/recovery/restore activation and in-Pod/public flows remain incomplete. No complete TASK or S-01/S-02 exit follows from these components.

## Previous protected configuration reconciliation (ADR-091/092)

[ADR-091](decisions/091-protected-configuration-reconciliation.md) and [the worker contract](architecture/configuration-reconciliation.md) add protected fleet-source observation, independent bounded fleet/owner loops, three scoped SQL roles and the fixed private `hub-worker` deployment projection. The pinned client-go scheduling Lease cancels and joins work after loss, cannot create/adopt a replacement, and grants no source or recovery authority. First observation remains recovery-blocked. The same provider input reader now supplies owner and worker composition. Installer provisioning, restore detection, native Pod placement and public investigation flows remain unfinished.

The SQL precision regression failed against the prior implementation: an equal PostgreSQL timestamp extended fleet authority. Its [failed log](../test/results/config-reconcile-clock-before.log) and [source/cleanup report](../test/results/config-reconcile-clock-before-environment.json) retain that evidence. The adapter now normalizes timestamps to database microseconds and rejects equal-time extension, revision changes or unfencing. The final real-SQL qualification below passed the regression, including a replay after a fence.

The initial [native context harness](../test/results/config-reconcile-context-check.log) returned 2 from Make (component test exit 1). The [suite](../test/results/config-reconcile-first-context-storage.log) passed the new mounted configuration-worker case in 14.34 seconds: real admission, Lease, SQL/S3/OpenBao, blocked first observation, one explicit fixture recovery acceptance, automatic audited refresh, source loss and joined Lease-loss shutdown. No background fixture timer refreshed that worker's source. The full suite failed in the owner case because the namespace denial masked the independently expected source-policy denial. The [report](../test/results/config-reconcile-first-context-storage-environment.json) records 660 unchanged source hashes and no cleanup failures; every hash matched current files before further edits. That run is not a passing integration qualification.

[ADR-092](decisions/092-independent-source-admission-probes.md) fixes that composition through exact installer-selected same-namespace account/ConfigMap dry-run UPDATE exceptions in the namespace policy. Real writes and other requests remain denied even without the source guard. The required private `configurationProbes` array is finite, unique and copied into the protection plan/digest; the independent source denial remains mandatory. No public permission control or extra approval was added. The native case additionally tests both guards together, deliberate source-guard removal and negative scope/persistence controls.

The [local gates](../test/results/source-probe-gates.log) returned 0: `make go-check go-architecture-check sql-check spec-check architecture-check design-check`, including full vet/race, 43 packages/189 internal edges, 22 matching sqlc files, 63 schemas/519 rejected invalid examples and existing design validation. Earlier [corrected reconciliation gates](../test/results/config-reconcile-corrected-gates.log) also passed; their preceding failed lease test used a read-only fixture for a PUT and was corrected with its own protocol fixture. The [dependency scan](../test/results/config-reconcile-vulnerability-check.log) found zero affected code/imported packages and one module-only advisory. Client-go reuse adds an inherited go-difflib runtime dependency and a goleak test checksum without upgrading existing versions, as recorded in ADR-091.

The corrected [native harness](../test/results/source-probe-context-check.log) returned 0 after terminal cleanup. The [suite](../test/results/source-probe-final-context-storage.log) passed in 166.153 seconds; the configuration worker took 14.46 seconds and the combined owner case took 82.51 seconds. Both admission policies remained independently observable, and the new source-guard-removal controls denied every persistent/foreign request while leaving resourceVersion unchanged. The owner loader/token-loss/recovery/shutdown cases also passed. The [environment report](../test/results/source-probe-final-context-storage-environment.json) records 660 unchanged source hashes, exit 0 and empty cleanup failures. Every hash matched current files after actual harness termination, and no owned context container remained before the separate custody suite started. These suite durations are not production capacity measurements.

The separate [custody harness](../test/results/source-probe-custody-check.log) returned 0 after cleanup. Its [suite](../test/results/source-probe-final-custody.log) passed in 107.816 seconds, including `equal-or-rounded-observation-cannot-extend-or-unfence` and existing contention/recovery/role cases. Its [report](../test/results/source-probe-final-custody-environment.json) records 661 unchanged source hashes, exit 0 and empty cleanup failures. Every hash matched current files after terminal completion; the earlier native context hashes also still matched the same final code. Next qualify the reconciliation scheduling account against the private workload namespace policy, then complete installer projections and independent installation/restore activation before native in-Pod and public workflow composition. The present worker fixture has source protection but not the owner namespace guard; never grant its runtime identity installation-administrator status to make the Lease work. No full TASK, S-01/S-02 or installation exit is complete.

## Previous protected owner deployment (ADR-090)

[ADR-090](decisions/090-protected-owner-deployment.md) and [the deployment contract](architecture/owner-deployment.md) add the fixed private startup projection, explicit provider trust, five distinct SQL role pools, native Kubernetes proof/protection, scoped S3/OpenBao audit and purpose-specific certificate issuance. `asservat hub-api` now starts this owner subsystem through the existing runtime/router. The loader reads current accepted configuration/recovery but has no acceptance or recovery-write credential. Public browser/MCP/federation/evidence routes and automatic installation provisioning remain unavailable. Three private schemas were added; no SQL migration or dependency changed.

The [pre-fix regression](../test/results/owner-loader-before.log) returned 1: opening a FIFO token file blocked before type validation. The shared mounted-file reader now confines relative projection symlinks, opens nonblocking and reads only bounded regular files without group/world write permissions. Owner and worker startup use it. Current provider token and storage reads never fall back after projection loss; SQL password rotation applies to new connections while retaining the selected username. Existing SQL connections retain their original finite lifetime and database privileges. Temporary-buffer clearing is best effort, not a Go/SDK zeroization guarantee.

`make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [the gate log](../test/results/owner-loader-gates.log): full vet/race suite, 43 packages/189 internal edges, 22 matching sqlc files, 62 schemas/506 rejected invalid examples and 63 design screens. Unit tests cover mounted-file confinement/rotation/FIFO rejection, explicit SQL TLS/no fallback, ambient credential rejection, password/role continuity, current Kubernetes/OpenBao tokens, missing storage credentials and malformed closed credential input. The [documentation continuation](../test/results/owner-loader-document-gates.log) also returned 0 after adding ADR-090 and its cross-references. These checks are not native installation evidence.

The [native context harness](../test/results/owner-loader-context-check.log) returned 0 after test completion and cleanup. Its [suite log](../test/results/owner-loader-final-context-storage.log) passed in 157.105 seconds; the owner case passed in 82.15 seconds. The [environment/source report](../test/results/owner-loader-final-context-storage-environment.json) records 651 unchanged source hashes, test exit 0 and empty cleanup failures. Every recorded hash matched current files after actual harness termination. No owned fixture containers remained before starting the separate custody suite.

The new native case constructs the actual loader from fixed files using distinct real SQL grants, Kubernetes Pod/token/admission proof, TLS S3 encrypted audit and scoped OpenBao wrapping/signing. It establishes identity before Pod Ready, loses readiness when the original Pod token file disappears, recovers after restoration, and cancels/joins runtime work after invalid current bundle input. The listener is reserved on an owned ephemeral port; the fixture does not take over a workstation service. Initial recovery, source freshness and mount provisioning are explicitly fixture-owned. The loader still runs outside the protected pause Pod; this does not qualify native in-Pod routing, public transfers or production credential delivery.

The separate [custody harness](../test/results/owner-loader-custody-check.log) also returned 0 after cleanup. Its [suite](../test/results/owner-loader-final-custody.log) passed in 107.824 seconds. The [report](../test/results/owner-loader-final-custody-environment.json) records 652 unchanged source hashes, test exit 0 and empty cleanup failures; all hashes matched current files after terminal completion. The earlier native context hashes still matched the same final code. No owned fixture containers remained. These times describe full suites, not per-operation latency or production capacity.

Next complete installation-generated projections and protected source/recovery reconciliation, then native in-Pod routing, connector proof mediation, actual evidence transfer and public investigation workflows. Full S-01/S-02 and later slices remain unfinished; the implementation goal stays active.

## Earlier multi-cluster worker routing (ADR-089)

[ADR-089](decisions/089-multicluster-worker-routing.md) and [the routing contract](architecture/worker-routing.md) remove the owner runtime's single-profile assumption. A shared installation/root-bound SQL read facet resolves exact stored cluster profiles; effect stores keep their original profile constraints. An atomic bounded catalog supplies only public control documents selected by current profile digest and cluster. The actual forwarder checks that trust before token transmission and after current-state revalidation; roots from another catalog cluster cannot verify the result. Shared receiving uses each original registration's own store, without a global mutation store. No SQL migration, dependency, public wire or permission model changed.

The [initial regression](../test/results/worker-multicluster-before.log) failed to compile because the catalog constructor did not exist. The first combined fixture compilation then found a missing `strings` test import; [that failed run](../test/results/worker-multicluster-components.log) is retained. After correction, [affected race/component tests](../test/results/worker-multicluster-components-final.log) returned 0. Real-crypto/TLS tests cover two clusters through one forwarder, separate CA trust, cross-cluster issuer rejection, absent/changed/removed profile material, caller-owned pool/input isolation and failed replacement preservation. Authority ports and address remapping in these TLS fixtures remain synthetic.

The shared SQL identity helper now explicitly intersects the caller and parent session deadlines and rereads worker/session state after blocking configuration checks. Existing dispatch already caps worker run time by the parent deadline; this change does not claim that the old dispatcher extended parent lifetime. The new independently enforced caller cutoff and post-wait cancellation are material changes.

`make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [the gate log](../test/results/worker-multicluster-gates.log): full vet/race suite, 42 packages/188 internal edges, 22 matching sqlc files, 59 schemas/476 invalid examples/8424 assertions, 24 components/14 interfaces/49 entities and 63 design screens. The [real custody harness](../test/results/worker-multicluster-custody-check.log) then returned 0 after cleanup. [The archived SQL/S3 suite](../test/results/worker-multicluster-final-custody.log) passed in 107.654 seconds, including the two-cluster read-facet case (1.39 seconds) and exact request-owner receiver case (2.74 seconds). It verifies separate simultaneously admitted profiles through one reader, unchanged per-profile denial, root/installation/worker mismatch, a shorter caller cutoff, role mutation rejection, isolated profile fencing and parent cancellation during an observed PostgreSQL configuration-lock wait. Initial accepted configuration/dispatch inputs remain explicitly synthetic. [The environment report](../test/results/worker-multicluster-final-custody-environment.json) records test exit 0, unchanged sources and no cleanup failures; all 639 recorded hashes matched current files after actual harness termination and no labeled containers remained. The [native context harness](../test/results/worker-multicluster-context-check.log) subsequently returned 0 after cleanup. [Its archived suite](../test/results/worker-multicluster-final-context-storage.log) passed in 131.168 seconds, including the native owner case in 67.20 seconds. [The report](../test/results/worker-multicluster-final-context-storage-environment.json) records test exit 0, unchanged source and no cleanup failures; all 638 recorded hashes matched current files after termination and no labeled fixture containers remained. This preserves actual two-cluster context storage and Kubernetes/OpenBao/SQL owner proof, activation, readiness and revocation behavior. It does not run the new cross-cluster forwarder inside a Pod: that path still has the separately described synthetic-authority TLS and SQL qualification boundaries.

Next: protected installation/connector synchronization of the same immutable control documents, deployment/credential loading and the hub entry point, continuously reconciled recovery/configuration, then actual in-Pod routing/native transfers and the public UI/MCP/download flow. No full TASK or S-01/S-02 exit is complete; the full implementation goal remains active.

The maintainer requested completion of the remaining implementation without stopping at component handoffs on 2026-10-10. Continue through the existing S-00–S-09 sequence, including the developer UI/MCP/native-download workflow and subsequent collection features. Do not mark an unsupported mechanism or unrun qualification as complete. This log supplements, rather than replaces, the requirements and implementation plan.

## Earlier owner readiness and runtime composition

[ADR-088](decisions/088-owner-startup-readiness.md) and [the startup contract](architecture/owner-startup.md) implement pre-Ready owner identity checks plus a concrete credential/listener/forwarding lifetime. C-04 adds `OwnerReadinessIdentity` and `OwnerStartupReadiness`; C-21 returns owned public CSR/certificate snapshots and verifies current roots. The check binds both purposes to the exact pool/process, active registry and native Pod/token/CSR/protection proof without requiring an already Ready endpoint. It repeats current checks, retains the original five-second/parent/proof deadlines, compares accepted configuration across purposes and rejects keys that close or change while the other purpose is checked. It never signs or creates authority.

`bootstrap.OwnerRuntime` validates the protected pool/source and current configuration, suppresses only its own process's core dumps, generates a fresh random process epoch and independent keys, then joins enrollment/renewal, actual private TLS receiving, live forwarding and serial expiring readiness. It clears failed/stale readiness, gates new forwarded work, closes keys/sockets on cancellation/failure and joins started tasks within six seconds. The runtime is private composition, not the missing deployment loader or hub command. No schema, SQL migration, dependency, public API or user approval changes.

The [before-implementation regression](../test/results/owner-startup-before.log) returned 1 because the native test's readiness check did not exist. The initial [compile run](../test/results/owner-startup-compile.log) returned 1 for a misnamed process-protection helper; it was corrected to the existing process-local implementation. [Affected race tests](../test/results/owner-startup-unit.log), [expanded snapshot/proof tests](../test/results/owner-startup-final-unit.log) and [final lifecycle tests](../test/results/owner-startup-lifecycle.log) returned 0. The synthetic runtime fixture uses real generated CSR/certificates and mutual TLS with explicit synthetic configuration/registry/proof ports. It becomes locally ready while real HTTP admission still returns 403 because current peer/route protection is unavailable. Tests cover readiness loss/recovery without extra signing, exact source mismatch, copied public bytes, closed/changed keys, proof/configuration changes, short/expired parents, new epochs, stale/rolled-back hints, shutdown during enrollment, listener failure and owned listener/key cleanup.

`make go-check go-architecture-check spec-check architecture-check design-check` returned 0 in [the gate log](../test/results/owner-startup-gates.log): full vet/race suite, 42 packages/188 allowed edges, 59 schemas/476 invalid examples/8398 assertions, 24 components/14 interfaces/49 entities and 63 design screens. The [native harness](../test/results/owner-startup-context-check.log) subsequently returned 0 after test completion and cleanup. [Its archived suite](../test/results/owner-startup-final-context-storage.log) passed in 128.963 seconds, including the owner case in 66.75 seconds. The [environment/source report](../test/results/owner-startup-final-context-storage-environment.json) records 635 unchanged source hashes, test exit 0 and empty cleanup failures. Every hash matched current files after actual terminal completion; no labeled test containers remained. These are whole-suite/case durations, not readiness latency or throughput measurements.

Actual Kubernetes Pod/token/CSR and admission proof plus OpenBao/SQL activation established readiness before Kubernetes Ready while existing peer admission still denied it. Readiness remained valid while current and rejected removed roots and a deleted Pod. This native run exercises the readiness checker; the runtime lifecycle fixture remains synthetic, and neither runs the new composition inside a Pod. Provider credentials, initial recovery and accepted installation facts remain fixture inputs. The serial readiness loop's fleet-wide API/SQL load and long-duration stability remain unqualified. No SQL adapter or migration changed, so the separate custody suite was not repeated in this continuation.

Next implement the protected deployment/credential loader and hub entry point with continuously reconciled recovery/configuration and actual installer acceptance, then qualify in-Pod native routing. Initial RecoveryBlocked is not cleared by readiness, and fixture recovery/token/issuer inputs cannot become production authority. Connector-local proof mediation, actual evidence transfer, the public UI/MCP/download flow and the remaining collection features remain unfinished. No complete TASK or S-01/S-02 exit is claimed; the full goal stays active.

## Earlier live owner delivery (ADR-087)

[ADR-087](decisions/087-live-owner-delivery.md) and [the sender contract](architecture/owner-forwarding.md) implement the missing live last hop. The private owner-relay/v2 response is one bounded length-prefixed certificate frame followed by an open silent HTTP body. The original receiver retains its exact operation; the forwarder now supplies `WorkerEnrollmentExchange` directly to the existing worker handler. Both slots remain charged through delivery/cleanup. EOF, extra bytes, errors and caller/owner/root cancellation end delivery; Close cancels the socket and joins the monitor. The received deadline is intersected with independent local checks and the current worker interval. No SQL migration, dependency, public API or user approval changes.

The [before-implementation regression](../test/results/owner-live-before.log) returned 1 because the forwarder did not implement the live exchange. [Initial live tests](../test/results/owner-live-unit.log), [affected component tests](../test/results/owner-live-components.log), [actual worker-response tests](../test/results/owner-live-worker-response.log) and [final stream/cancellation cases](../test/results/owner-live-stream-tests.log) returned 0 under the race detector. Synthetic real-TLS tests cover owner/caller/root cancellation, Close, network loss, the unchanged final deadline and held concurrency. They reject fixed-length, oversized, foreign-format and expired frames; EOF and extra bytes cancel any already-returned delivery. Strict codec tests reject truncated, duplicate/unknown/missing/aliased fields and consume exactly one frame. The real worker handler's blocked TLS response is deterministically interrupted by remote owner cancellation; normal delivery succeeds and both sides release exactly once. Test authority remains explicit synthetic ports with owned address remapping.

`make go-check go-architecture-check spec-check architecture-check design-check` returned 0 in [the gate log](../test/results/owner-live-gates.log): full vet/race suite; 42 packages/188 internal edges; 59 schemas, 476 rejected invalid examples and 8376 assertions; 24 components/14 interfaces/49 entities and 63 design screens. The [native harness](../test/results/owner-live-context-check.log) subsequently returned 0 after test completion and cleanup. [Its archived suite](../test/results/owner-live-final-context-storage.log) passed in 124.990 seconds; the owner case passed in 60.57 seconds. The [source/environment report](../test/results/owner-live-final-context-storage-environment.json) records 631 unchanged source hashes, test exit 0 and no cleanup failures. All hashes matched current files after actual harness termination, and no labeled test containers remained. These are whole-suite/case durations, not per-operation latency.

The native owner fixture retains actual Kubernetes protected configuration, purpose-separated OpenBao certificates, SQL activation and current Ready/root/deletion checks, using the updated v2 receiver request. Its inner enrollment operation deliberately remains unavailable; it does not qualify this sender inside a Pod or the native cross-replica live path. The two-hop live response and blocked worker TLS behavior are covered by the separately described synthetic-authority tests. No SQL adapter or migration changed, so this continuation did not repeat the separate custody suite.

A silent partition cannot provide instantaneous remote revocation; the independently retained final identity deadline bounds it to at most five seconds after the last local identity check. Already sent bytes cannot be retracted. Certificates remain separate from current activated identity and evidence authority. Protected process startup, native routing, connector-local proof mediation, evidence transfer and the public investigation workflow remain pending. No complete TASK or S-01/S-02 exit is claimed; the full implementation goal remains active.

## Earlier outbound owner certificate transfer (ADR-086)

[ADR-086](decisions/086-outbound-owner-enrollment.md) and [the sender contract](architecture/owner-forwarding.md) add `mtls.OwnerForwarder`: exact current locator/worker/route lookup, purpose-separated current local client identity, actual destination authentication before Pod-token/CSR transmission, one-use HTTP with no redirect/POST replay, and independent worker-certificate/result revalidation. Added private ports are `OwnerClientIdentity` and read-only `WorkerOwnerLookup`; the existing store embeds the latter. No SQL migration, public API, wire change or dependency is added.

The sender returns a verified public certificate and deliberately does not implement the existing live `WorkerEnrollmentDelivery` interface. A completed HTTP reply cannot stand in for the remote human request's still-live cancellation context. Receiver ownership remains live through its network flush, and sender ownership through receiving/revalidation. Protected startup, complete native routing, original control ownership through final downstream delivery, connector proof mediation and evidence transfer remain mandatory. Do not use a fabricated background delivery to conceal that gap.

The [before-implementation build](../test/results/owner-forward-before.log) returned 1 with missing local-client methods. The first sender-test build failed on unused test imports; [the corrected sender/receiver race tests](../test/results/owner-forward-unit-after.log), [composed unit tests](../test/results/owner-forward-composed-unit.log) and [final cancellation/race tests](../test/results/owner-forward-final-unit.log) returned 0. They use the actual sender, receiver and TLS/certificate implementations with explicit synthetic registry/route/worker/signing ports. An unexported unit-only dial remapping reaches an owned loopback listener; production constructors expose no such override.

These tests assert zero HTTP requests for revoked local/remote identity, removed roots, foreign process, stale locator and cancellation before transmission; rejection after locator/worker/identity changes during the reply; exact CSR/worker/root/expiry verification; one POST after a lost reply; redirect/malformed/oversized-header rejection; address fallback before HTTP; bounded concurrency; and interruption of a stalled response on sender closure. The worker and sender now share their certificate validator. Current local-client orchestration runs the same rejection matrix as actual-peer and local-server checks without fabricating TLS.

`make go-check go-architecture-check spec-check architecture-check design-check` returned 0 in [the gate log](../test/results/owner-forward-gates.log): full vet/race suite; 42 packages/188 allowed internal edges; 59 schemas, 470 rejected invalid examples and 8354 assertions; 24 components/14 interfaces/49 entities; and 63 design screens. These are component/design checks, not a deployed workflow.

The [native harness](../test/results/owner-forward-context-check.log) returned 0 after test completion and cleanup. [Its suite](../test/results/owner-forward-final-context-storage.log) passed in 124.524 seconds; the owner case passed in 60.75 seconds. The [environment/source report](../test/results/owner-forward-final-context-storage-environment.json) records 628 unchanged source hashes, test exit 0 and empty cleanup failures. Every hash matched current source after actual termination. These are whole test durations, not per-operation latency.

The native owner fixture adds current local-client checks with actual Kubernetes/OpenBao/SQL/S3 state before readiness, while Ready, after root removal and after Pod deletion, retaining the existing receiver and worker-credential cases. It does not place this sender inside the protected Pod or establish native routing to that process. The protocol sender/receiver combination remains a separately qualified synthetic-authority test. No owned containers remain. No SQL adapter or migration changed in this continuation; the preceding SQL receiver qualification remains historical evidence, not a new SQL-suite run.

Next complete protected startup, native routing and live original control ownership through final worker delivery, then connector proof mediation, native evidence transfer and the public investigation flow. Full S-01/S-02 and later slices remain unfinished; the implementation goal stays active.

## Earlier private owner enrollment receiver (ADR-085)

[ADR-085](decisions/085-private-owner-enrollment-receiver.md) and [the receiver contract](architecture/owner-relay.md) add a real bounded mutual-TLS HTTP receiver, distinct current local serving checks, exact existing owner-registration lookup, response-time peer revalidation and owned socket shutdown. The private owner-relay/v1 request carries the existing worker request and a non-authorizing locator; the public worker response is unchanged. No SQL migration or user approval is added. Outbound forwarding, protected in-Pod startup, connector proof mediation and native transfer remain unfinished.

The [initial missing-method regression](../test/results/owner-relay-before.log) returned 1 before implementation. The first [transport race run](../test/results/owner-relay-unit.log) rejected valid requests because an outer start was compared against a slightly later underlying observation end; the receiver now intersects both original deadlines. A shutdown test initially required a connection error and was corrected to also permit an empty 503 racing immediate socket closure; it still rejects successful output. [Composed component tests](../test/results/owner-relay-composed-unit.log) then returned 0. These use synthetic peer/operation ports; integration cases skip without native fixtures.

A subsequent [response regression](../test/results/owner-relay-chain-before.log) returned 1 when a zero-length certificate chain was serialized as null. The receiver now emits the contract's empty array. [Response tests](../test/results/owner-relay-response-unit.log) returned 0 under race detection, including deterministic blocked TLS writing over net.Pipe: cancelling the exact delivery owner interrupts the write and releases it once. Additional application tests check replacement during shared-store lookup, serialization-stable locator equality, and all current boundaries for both local and remote identities.

`make go-check go-architecture-check spec-check architecture-check design-check` returned 0 in [the final component/design gates](../test/results/owner-relay-final-gates.log): full vet/race suite, 42 packages/187 allowed internal edges, 59 schemas/470 rejected invalid examples/8329 assertions, 24 components/14 interfaces/49 entities and 63 design screens. The schema reference checker now handles standard JSON Pointer array indices, allowing the relay schema to reuse the existing request variant without duplicating it. Those contract/UI checks do not prove a deployed runtime.

The [native harness](../test/results/owner-relay-context-check.log) returned 0 after test completion and cleanup. [Its suite](../test/results/owner-relay-final-context-storage.log) passed in 125.381 seconds, including the native owner case in 57.65 seconds. The [report](../test/results/owner-relay-final-context-storage-environment.json) records 626 unchanged source hashes, test exit 0 and empty cleanup failures; each hash matched current source after actual termination. Actual Kubernetes/OpenBao/S3/SQL owner credentials and current protection/Ready checks reach the new listener, whose inner operation deliberately returns unavailable. Root removal and Pod deletion deny admission.

The separate [SQL/S3 harness](../test/results/owner-relay-custody-check.log) also returned 0 after cleanup. [Its suite](../test/results/owner-relay-final-custody.log) passed in 105.756 seconds; `download-worker-request-owners` passed in 2.78 seconds through the new registration lookup and stale-owner rejection. The [report](../test/results/owner-relay-final-custody-environment.json) records unchanged sources, test exit 0 and empty cleanup failures, with every source hash verified after termination. These times describe complete test cases, not per-request latency. No owned test containers remain.

Do not infer a fully composed native forwarding workflow, protected installation, production load capacity or release readiness from these component integrations. Next implement outbound discovery/current verification before credential transmission, protected in-Pod startup and connector proof mediation, then native evidence transfer and the public UI/MCP flow. Complete S-01/S-02 and all later slices remain unfinished; the full implementation goal stays active.

## Current process-owned owner credentials and renewal

[ADR-084](decisions/084-process-owned-owner-credentials.md) and the [credential lifecycle contract](architecture/owner-credentials.md) add separate P-256 server/client key custody, independently checked audited enrollment/registry results, copied actual-TLS callbacks, original-expiry signer snapshots and bounded paired renewal. No SQL migration or public wire contract changes. Protected bootstrap/listener composition and exact-request forwarding remain pending.

The [credential before-implementation build](../test/results/owner-credentials-before.log) returned 1 with missing credential types and an unused import caused by those missing types. The [supervisor before-implementation build](../test/results/owner-runtime-before.log) likewise returned 1 with missing runtime types. The [credential race tests](../test/results/owner-credentials-unit.log), [combined credential/supervisor race tests](../test/results/owner-credentials-runtime-unit.log), and [composition build/race tests](../test/results/owner-credentials-composition-build.log) returned 0. Native cases skip without fixture variables. Actual mutual TLS is exercised in unit tests with synthetic enrollment/registry; eight-hour supervisor tests advance a synthetic clock and do not qualify eight hours of provider operation.

`make go-check go-architecture-check` returned 0 in [the code gate log](../test/results/owner-credentials-code-gates.log): vet, full Go/race suite and 41 packages/182 allowed internal import edges. The native Kubernetes/OpenBao/S3/PostgreSQL test was extended to enroll separately owned keys, reject a replacement key before provider signing, exercise actual TLS callbacks and retain current peer checks. `make spec-check architecture-check design-check` returned 0 in [the initial document gate log](../test/results/owner-credentials-design-gates.log); these are design checks only.

The [first native harness](../test/results/owner-credentials-context-check.log) returned 2. Its [suite](../test/results/owner-credentials-first-context-storage.log) passed the new owner case in 53.56 seconds, but later failed the existing connector bootstrap fixture: immediate KV configuration after mounting returned HTTP 400 instead of 204. The whole suite therefore failed (115.149 seconds), despite the owner case passing. [The report](../test/results/owner-credentials-first-context-storage-environment.json) records 618 unchanged hashes, test exit 1 and empty cleanup failures, verified after actual termination.

Two separate pinned-image diagnostics, [ordinary](../test/results/owner-credentials-kv-diagnostic.log) and [CPU-throttled](../test/results/owner-credentials-kv-throttled-diagnostic.log), each created 100 fresh KV mounts without reproducing the response. Both scripts returned 1 because reproduction was not achieved, and both removed their owned container/network. The original response body was not retained, so its exact cause remains unconfirmed. OpenBao's [KV upgrade guard](https://github.com/openbao/openbao/blob/main/internal/builtin/logical/kv/upgrade.go) demonstrates a temporary invalid-request response during backend initialization. The fixture now polls only the read-only configuration route, with finite attempts/deadline and retry restricted to that exact documented startup error, before its single configuration write. Other errors fail; no credential/configuration writes are replayed. [The new readiness before-implementation build](../test/results/owner-credentials-kv-readiness-before.log) failed with missing helper definitions; [the implemented focused race tests](../test/results/owner-credentials-kv-readiness-unit.log) passed. This fixture improvement is not proof that the original 400 was the upgrade response. Broader rerun results follow when complete.

Remaining work includes protected runtime installation/recovery/issuer bootstrap, process execution inside the intended Pod, socket/session lifetime, private request forwarding, native transfer, local CA and public UI/MCP/download workflows. The earlier startup configuration-availability uncertainty remains recorded below. Full S-01/S-02 and later slices remain incomplete; the implementation goal stays active.

The [readiness rerun harness](../test/results/owner-credentials-readiness-context-check.log) returned 0. [Its complete suite](../test/results/owner-credentials-readiness-context-storage.log) passed in 115.938 seconds, including the owner case in 54.29 seconds and the previously failing connector KV setup. [Its report](../test/results/owner-credentials-readiness-context-storage-environment.json) records 619 unchanged source hashes, test exit 0 and empty cleanup failures; all hashes matched after actual termination. These are complete-test durations, not per-operation latency. This success does not retroactively identify the original 400 response.

Subsequent review found cancellation between the initial check and credential-lock acquisition. [The deterministic regression](../test/results/owner-credentials-cancel-before.log) failed both the cached-identity and fresh-enrollment paths. The adapter now rechecks cancellation after the lock before either path. Final checks below must cover that source change; the earlier native report predates it.

Final qualification covers that cancellation fix and the KV readiness fixture change. `make go-check go-architecture-check` returned 0 in [the final code log](../test/results/owner-credentials-final-code-gates.log), including vet, the complete Go/race suite and 41 packages/182 allowed import edges. `make context-integration` returned 0 in [the final harness log](../test/results/owner-credentials-final-context-check.log). [The full native suite](../test/results/owner-credentials-final-context-storage.log) passed in 116.810 seconds; the owner case passed in 53.35 seconds and the connector case in 0.73 seconds. These are whole-test timings. [The final report](../test/results/owner-credentials-final-context-storage-environment.json) records 619 unchanged source hashes, test exit 0 and empty cleanup failures, all verified against current files after terminal cleanup. No containers with the owned fixture label remained. Final document/architecture/design validation is recorded in [the final design log](../test/results/owner-credentials-final-design-gates.log).

Next compose protected hub startup, projected owner-token access and listener/connection lifetime, then exact-request private forwarding and native transfer. Long-duration real-provider renewal and aggregate issuance load remain unqualified. The successful component tests do not implement the complete debugging platform, qualify protected installation history, or enable public collection/disclosure.

## Current native owner activation and peer authentication

[ADR-083](decisions/083-current-owner-authentication.md) and [the current peer contract](architecture/owner-authentication.md) add C-04 authentication over actual TLS, active registration, current roots, exact Ready routing and pool-bound native workload protection. Original deadlines survive every read, and both registration/protection are checked around routing. The TLS adapter owns bounded copied/reparsed public certificate state and revalidates current roots/time on reuse. SQL remains migration 30; no public route or forwarding is enabled.

Verification history and final qualification:

- The [before-implementation check](../test/results/owner-authentication-before.log) returned 1 because the required authentication types/service did not exist. The [first implementation unit run](../test/results/owner-authentication-first-unit.log), [composition compile/unit run](../test/results/owner-authentication-composition-build.log) and [focused race suite](../test/results/owner-authentication-unit.log) returned 0. Integration cases skip without owned fixture variables; these are not native integration results.
- `make go-check go-architecture-check` returned 0 in [the code gate log](../test/results/owner-authentication-code-gates.log): vet, Go/race suite, 41 packages and 182 permitted import edges. This includes exact workload-pool rejection before native API I/O and the new peer/TLS boundary tests.
- The first full `make context-integration` returned 2 in [the harness log](../test/results/owner-authentication-first-context-check.log). [The suite](../test/results/owner-authentication-first-context-storage.log) returned 1 because the new fixture expected HTTP 204 from Transit key creation, whose actual response was HTTP 200. [Its report](../test/results/owner-authentication-first-context-storage-environment.json) records 611 unchanged source hashes and empty cleanup failures; all hashes matched after actual process termination. The corrected fixture expects the actual successful response. No native composition success is claimed from the failed run.
- The corrected HTTP fixture reached native pre-Ready enrollment but exposed a product timing defect: structural checks evaluated the nested configuration at the proof start, before that native read had completed. [The second suite](../test/results/owner-authentication-corrected-context-storage.log) failed, and [its report](../test/results/owner-authentication-corrected-context-storage-environment.json) records 611 unchanged source hashes and empty cleanup failures. The [focused regression](../test/results/owner-authentication-proof-order-before.log) independently failed on the same ordering. Structural checks now require an overlap of the original intervals; current SQL checks and the original deadline remain unchanged. The synthetic provider fixture now uses the native start-before-configuration ordering too. [The affected race tests](../test/results/owner-authentication-proof-order-unit.log) returned 0; external tests skip without fixtures.
- The next [full context run](../test/results/owner-authentication-proof-order-context-storage.log) passed the corrected SQL/provider lifecycle but failed earlier during the initial native Pod proof. [Its report](../test/results/owner-authentication-proof-order-context-storage-environment.json) records 612 unchanged hashes, exit 1 and empty cleanup failures, checked after terminal cleanup. No earlier proof or SQL invariant was relaxed. The native adapter now identifies the failed phase with fixed sanitized error text while preserving the underlying error category; it never includes API responses, tokens or workload data. [The affected native-adapter race test](../test/results/owner-authentication-proof-diagnostics-unit.log) passed. These failed runs did not establish native composition qualification.

The test process owns CSR/private keys and the loopback TLS listener; the controller-created pause Pod does not run a hub executable. Initial installation recovery/issuer bootstrap and its fresh observation are explicit fixture inputs. Protected runtime installation, owner credential transport/supervision, locator-bound forwarding, native transfer, local CA and the public workflow remain pending. No S-01/S-02 or TASK completion is implied.

Further native composition diagnostics:

- [The phase-diagnostic run](../test/results/owner-authentication-diagnostic-context-storage.log) reached a custody failure after initial proof; [its report](../test/results/owner-authentication-diagnostic-context-storage-environment.json) records 612 unchanged hashes, exit 1 and empty cleanup failures. [The following run](../test/results/owner-authentication-sql-diagnostic-context-storage.log) identified intermittent initial accepted-configuration unavailability before the new SQL path; [its report](../test/results/owner-authentication-sql-diagnostic-context-storage-environment.json) likewise records 612 unchanged hashes and complete cleanup.
- Inspection found an independent durable-comparison defect: raw equality on the recovery observation included Go's process-local monotonic clock representation. [A JSON round-trip regression](../test/results/owner-authentication-clock-before.log) failed with an otherwise valid, identical signing attempt. Comparison now uses exact identity/revision and time instants. [The corrected focused race test](../test/results/owner-authentication-clock-unit.log) passed.
- [The policy-composition run](../test/results/owner-authentication-policy-composition-before-context-storage.log) completed sixteen exact source-policy dry-run denials while namespace protection was active. It then failed because the diagnostic fixture installed a SQL tracer that the production constructor explicitly forbids. The tracer was removed; the constructor restriction remains. [Its report](../test/results/owner-authentication-policy-composition-before-context-storage-environment.json) records 612 unchanged hashes, exit 1 and empty cleanup failures. No policy exception or weaker admission was introduced on this evidence.
- [The corrected affected unit/race run](../test/results/owner-authentication-corrected-unit.log) returned 0. The final native run below includes both timing fixes and the original no-tracer SQL wiring.

The final `make context-integration` returned 0 in [the harness log](../test/results/owner-authentication-clock-context-check.log). [The complete Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/owner-authentication-final-context-storage.log) passed in 103.903 seconds, including the native owner case in 40.15 seconds; these are whole-test durations, not per-operation latency. [Its report](../test/results/owner-authentication-final-context-storage-environment.json) records 612 unchanged source hashes, exit 0 and empty cleanup failures; all hashes matched after actual process termination. The case proved native pre-Ready proof through signing/audit/activation, suspension/resume with exact certificate reuse, readiness gating, current-root removal, per-purpose retirement and deleted-Pod denial on retained TLS snapshots. Sixteen source-policy probes passed with workload protection active. Earlier initial-configuration unavailability was observed and is retained above; this successful run does not qualify long-duration startup availability or replace the remaining protected runtime/bootstrap work.

The final `make go-check go-architecture-check sql-check` returned 0 in [the code gate log](../test/results/owner-authentication-final-code-gates.log): vet, the full Go/race suite, 41 packages/182 allowed import edges and 22 matching generated SQL files. `make custody-integration` also returned 0 in [its harness log](../test/results/owner-authentication-custody-check.log). [The full custody suite](../test/results/owner-authentication-final-custody.log) passed in 106.258 seconds. [Its report](../test/results/owner-authentication-final-custody-environment.json) records 613 unchanged source hashes, exit 0 and empty cleanup failures; all hashes matched after terminal cleanup. `make spec-check architecture-check design-check` returned 0 in [the final design log](../test/results/owner-authentication-final-design-gates.log). These remain component/design qualifications; full S-01/S-02 and subsequent platform slices are unfinished. Next implement process-owned runtime credentials and renewal, protected bootstrap and exact-request private forwarding, retaining the recorded startup-availability uncertainty.

## Current durable owner enrollment and activation

[ADR-082](decisions/082-durable-owner-enrollment.md) and the [registration contract](architecture/owner-registration.md) add migration 30, immutable process/purpose/key enrollment, encrypted enrollment/certificate audit, committed signing spend, separate activation/current registry and bounded retirement/history cleanup. Pending/uncertain/retired registrations remain counted until all possible leaves and owner locators expire. Stored provider results can finish audit after the signing deadline using fresh proof and current roots, without another signing call or renewed permit. No public route is enabled.

Verification so far:

- The focused current-root/resumed-certificate test returned 0 in [the unit log](../test/results/owner-registration-current-trust-unit.log). `make go-check go-architecture-check sql-check` returned 0 in [the code gate log](../test/results/owner-registration-code-gates.log): vet, Go/race suite, 41 packages/181 import edges and 22 sqlc-generated files.
- An initial harness invocation rejected the unsupported `--test-pattern` argument before starting fixtures (exit 2); the documented `--run` option was then used.
- The [first actual provider run](../test/results/owner-registration-first-fleet.log) reached stored-certificate retry but failed a synthetic recovery refresh: two `clock_timestamp()` calls exceeded the exact thirty-second SQL interval by one microsecond. The fixture now derives both ends from one statement timestamp; no product freshness limit changed. [That report](../test/results/owner-registration-first-fleet-environment.json) records unchanged sources, exit 1 and empty cleanup failures.
- The [corrected targeted real SQL/S3/OpenBao suite](../test/results/owner-registration-corrected-fleet.log) returned 0 in 12.939 seconds (whole test suite, not per-operation latency). It proves interrupted audit after signing, exact retry without a new provider call after the original deadline, immutable keys, separate purposes/roles, concurrent spend, finite uncertain retry, post-lock expiry, retirement without refund, source/recovery fences, 32 retained registrations per Pod and expired restored-state cleanup. [The corrected report](../test/results/owner-registration-corrected-fleet-environment.json) records 605 unchanged hashes and empty cleanup failures; all hashes matched at archival after actual process termination. Later audit-conflict assertions and log clarification require the final broader run below.
- The initial `make spec-check architecture-check design-check` returned 0 in [the design log](../test/results/owner-registration-design-gates.log). Design gates do not establish runtime authority.

The full `make context-integration` returned 0 in [the harness log](../test/results/owner-registration-context-check.log). [The complete Kubernetes/OpenBao/S3/SQL regression](../test/results/owner-registration-final-context-storage.log) passed in 76.367 seconds, including the added conflicting-audit assertions. [Its environment report](../test/results/owner-registration-final-context-storage-environment.json) records 604 unchanged hashes, exit 0 and empty cleanup failures; every hash matched after actual process termination. `make custody-integration` also returned 0 in [its harness log](../test/results/owner-registration-custody-check.log); [the full custody regression](../test/results/owner-registration-final-custody.log) passed in 106.431 seconds. [Its environment report](../test/results/owner-registration-final-custody-environment.json) records 605 unchanged hashes, exit 0 and empty cleanup failures, verified after actual process termination. A final review then strengthened the owner-role test to require SQLSTATE `42501`, distinguishing permission denial from immutable-row guards. Only `test/integration/owner_registration_test.go` changed after these two broad runs; no runtime/migration/fixture source changed. The [final affected real-provider/race test](../test/results/owner-registration-final-fleet.log) returned 0 in 13.060 seconds with the strict privilege assertions. [Its final report](../test/results/owner-registration-final-fleet-environment.json) records 605 unchanged current source hashes and empty cleanup failures; all hashes matched after actual termination. Comparing the broad-run reports confirms that the strengthened owner test is their only subsequent source difference. The final `make spec-check architecture-check design-check` also returned 0 in [the final design log](../test/results/owner-registration-final-design-gates.log). Their Pod proof or initial recovery/issuer bootstrap boundaries remain explicit. Complete protected installation, native Pod-proof-to-activation composition, owner credential transport, long-duration renewal/restore qualification, private forwarding/native transfer, local CA and public UI/MCP/download workflows remain pending. No S-01/S-02 or whole TASK is checked off.

## Current pre-Ready hub owner enrollment proof

[ADR-081](decisions/081-hub-owner-enrollment-proof.md) and the [enrollment proof contract](architecture/owner-enrollment-proof.md) implement the C-04 proof ports and C-21 Kubernetes adapter. A dedicated online Pod-token audience, identity-free signed CSR, exact account/Pod/ReplicaSet/Deployment chain, accepted configuration and concrete native workload guard must agree. The original five-second interval is clipped to configuration/protection/token deadlines; status-only startup transitions are allowed without renewing the proof. Tokens/specs remain temporary adapter inputs and only digests/provenance leave it. The shared TokenReview decoder preserves acquisition-worker audience/name checks. SQL remains migration 29; no public enrollment endpoint or evidence authority is enabled.

Verification completed with actual terminal exits:

- The [initial package/race build](../test/results/owner-enrollment-first-build.log), [focused owner/worker token regression](../test/results/owner-enrollment-unit.log) and [integration compile check](../test/results/owner-enrollment-integration-build.log) returned 0. The latter skips real integration without fixture variables and is not native qualification.
- `make go-check go-architecture-check` returned 0 in [the code gate log](../test/results/owner-enrollment-code-gates.log): vet, all Go/race tests and 41 packages/181 permitted import edges.
- `make context-integration` returned 0 in [the harness log](../test/results/owner-enrollment-first-context-check.log). [The complete Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/owner-enrollment-final-context-storage.log) passed in 66.926 seconds; the combined owner discovery/configuration/protection/enrollment case passed in 14.03 seconds. These are whole-test durations, not operation-latency claims.
- [The environment report](../test/results/owner-enrollment-final-context-storage-environment.json) records 593 unchanged source hashes, test exit 0 and empty cleanup failures. All hashes matched current files after the actual harness process terminated; no owned test containers/networks remained.
- `make spec-check architecture-check design-check` returned 0 in [the final design gate log](../test/results/owner-enrollment-final-design-gates.log). These validate contracts/mappings, not durable enrollment or production startup.

The native test composes the actual protected ConfigMap observer, encrypted SQL/S3 configuration acceptance and private workload guard. A new real Deployment revision has an unsatisfied readiness gate and a scheduled Pod; its actual bounded Pod token/CSR obtains a valid proof while the Ready endpoint reader rejects it. Satisfying the gate makes that same Pod routable. Client/server purposes work separately; wrong-audience, unbound, foreign Pod/issuer, invalid CSR and deleted-Pod inputs fail. Existing worker token, startup and provider tests pass through the shared decoder. The initial recovery/issuer roots, process epoch and proof request remain fixture inputs; no certificate is activated by this proof.

Next complete trusted clean-installation/workload history and durable owner key/process enrollment, encrypted enrollment audit, pre-I/O signing spend, certificate audit/activation and bounded renewal/retirement. Then compose private forwarding/native transfer. A Pod token does not prove process uniqueness, and current admission does not repair historical compromise. Full S-01/S-02 and all later slices remain incomplete; the goal stays active.

## Current private hub workload protection

[ADR-080](decisions/080-private-hub-workload-protection.md) and the [workload protection contract](architecture/owner-workload-protection.md) add a private namespace admission profile and independent current-enforcement proof. The proof requires an RBAC-permitted unchanged dry-run denied by the exact pinned policy/binding, preserves the original five-second deadline and checks namespace identity before and after. Secret reads and clean installation remain separate prerequisites; this does not implement historical integrity, token/CSR attestation, enrollment or activation. SQL remains migration 29 and public interfaces are unchanged.

The [focused unit/race check](../test/results/owner-workload-first-unit.log) passed. The [full Go/race/import gates](../test/results/owner-workload-code-gates.log) returned 0 with 41 packages/181 allowed import edges. The [initial document/architecture/design gates](../test/results/owner-workload-design-gates.log) returned 0. Tests without fixture variables skip external integration; these results do not replace the native gate.

The [first owned Kubernetes harness](../test/results/owner-workload-first-context-check.log) returned 2 because [the suite](../test/results/owner-workload-first-context-storage.log) failed the real protected Pod replacement check after the attack-denial checks. [Its report](../test/results/owner-workload-first-context-storage-environment.json) records test exit 1, 588 unchanged source hashes and empty cleanup failures; all hashes matched after the process terminated. The [diagnostic rerun](../test/results/owner-workload-diagnostic-context-storage.log) also failed replacement, recording no new Pod or post-policy controller events. [Its report](../test/results/owner-workload-diagnostic-context-storage-environment.json) likewise records unchanged sources and complete cleanup. No native success is claimed from either run.

The corrected expression normalizes optional API-group/subresource fields rather than broadening any principal's operations. Native assertions now require an intentional static denial, excluding CEL evaluation errors, and test permitted ReplicaSet-controller Pod creation before the actual replacement. The [corrected unit/race build](../test/results/owner-workload-normalized-unit.log) passed. Final code/runtime qualification passed:

- `make go-check go-architecture-check` returned 0 in [the final code gate log](../test/results/owner-workload-final-code-gates.log), including vet, all Go/race tests and 41 packages/181 allowed import edges.
- `make context-integration` returned 0 in [the final harness log](../test/results/owner-workload-normalized-context-check.log). [The complete Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/owner-workload-final-context-storage.log) passed in 54.994 seconds; the owner discovery/configuration/workload protection test passed in 6.73 seconds. These durations cover whole tests, not individual lookups.
- [The final environment report](../test/results/owner-workload-final-context-storage-environment.json) records 588 unchanged source hashes, test exit 0 and empty cleanup failures. All hashes matched current files after the actual harness process terminated; no owned test containers/networks remained.
- `make spec-check architecture-check design-check` returned 0 in [the final design gate log](../test/results/owner-workload-final-design-gates.log). These remain documentation/contract checks, not owner enrollment or public-workflow qualification.

The real native test proves exact intentional denials for forged Pods with hub/default accounts, forged ReplicaSets, Deployment/account mutation, legacy-token Secret creation, TokenRequest, ephemeral containers and exec CONNECT. It also proves separate observer RBAC, an allowed administrator dry-run, permitted reference-controller creation, actual Restricted Pod replacement to Ready, immediate guard rejection after binding removal and an admitted unchanged dry-run negative control. Neither dry-run persisted changes. The earlier generic denial-prefix assertion would have accepted CEL errors; the tightened assertion is retained.

Next complete protected clean-installation/workload history, Pod/token/CSR proof independent of readiness, durable enrollment, pre-I/O signing spend, encrypted issuance audit and current certificate activation, followed by private forwarding/native transfer. Untested controller variants and the full S-01/S-02/public workflow remain incomplete; no whole-task exit is marked.

## Current hub owner certificate issuance

[ADR-079](decisions/079-owner-certificate-issuance.md) and the [owner issuance contract](architecture/owner-issuance.md) add fixed-purpose OpenBao signing, strict identity-free CSR verification, exact owner client/server leaf checking against both pinned and current roots, and renewable UTC periods for long-lived hubs. Twenty-minute windows allow one-minute advance renewal; retries keep the original expiry. SQL remains migration 29. This provider boundary does not implement enrollment proof, durable signing spend, certificate audit/activation, local CA or forwarding.

The [first real provider attempt](../test/results/owner-issuance-first-fleet.log) rejected server signing. A diagnostic retry was not qualified: [its report](../test/results/owner-issuance-diagnostic-fleet-environment.json) records source mutation before the harness terminated. A premature overlapping attempt failed Docker address-pool allocation before tests ([log](../test/results/owner-issuance-provider-errors-check.log)); no provider success is claimed from it. All owned fixtures were subsequently removed. The final frozen [failing regression](../test/results/owner-issuance-alt-names-before-fleet.log) exposed OpenBao's exact error: `alt_names` requires a string, not an array. [Its report](../test/results/owner-issuance-alt-names-before-fleet-environment.json) records unchanged tested source and complete cleanup.

After fixing that wire field, the [targeted provider harness](../test/results/owner-issuance-corrected-provider-check.log) returned 0 and [the test](../test/results/owner-issuance-corrected-fleet.log) passed in 1.130 seconds overall. It signed real client/server CSRs, completed mutual TLS, verified exact identities/usages/deadlines and provider-role/revocation denial. [The report](../test/results/owner-issuance-corrected-fleet-environment.json) records 584 unchanged sources and empty cleanup failures; hashes matched at terminal cleanup. Enrollment/configuration/recovery/spend are synthetic fixture inputs. The later [unit/race regression](../test/results/owner-issuance-final-unit.log) additionally checks the exact DNS wire type, no automatic retry on 429, no unaudited POST, stable periods and stale/foreign certificate rejection. Final regressions passed:

- `make go-check go-architecture-check` returned 0 in [the code gate log](../test/results/owner-issuance-code-gates.log): vet, all Go/race tests and 41 packages/181 permitted import edges.
- `make fleet-integration` returned 0 in [the harness log](../test/results/owner-issuance-fleet-check.log); [the full suite](../test/results/owner-issuance-final-fleet.log) passed in 23.387 seconds. [The report](../test/results/owner-issuance-final-fleet-environment.json) records 585 unchanged sources and empty cleanup failures, with hashes matched after terminal cleanup.
- `make context-integration` returned 0 in [the harness log](../test/results/owner-issuance-context-check.log); [the full Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/owner-issuance-final-context-storage.log) passed in 63.660 seconds, including actual owner issuance and the existing guarded configuration/worker path. [The report](../test/results/owner-issuance-final-context-storage-environment.json) records 584 unchanged sources and empty cleanup failures; final hashes matched.
- `make spec-check architecture-check design-check` returned 0 in [the design gate log](../test/results/owner-issuance-doc-gates.log). These remain document/contract checks, not activation evidence.

Enrollment must independently prove Pod/account/workload membership before readiness. Reusing the Ready-endpoint routing reader here would create a certificate/readiness startup cycle. This separation and the requirement to protect workload/account creation are explicit in the architecture; no readiness check was weakened.

Continue with protected owner Pod/process and workload/issuer proof, durable enrollment, finite pre-I/O signing spend, encrypted issue audit and current certificate activation. Then compose private forwarding and native transfer without exposing this adapter directly to user/worker input. Full S-01/S-02 and the broader platform remain incomplete.

## Current durable owner configuration acceptance

[ADR-078](decisions/078-owner-configuration-acceptance.md) and the extended [owner configuration contract](architecture/owner-configuration.md) add migration 29, immutable source/revision history, negative-observation watermarks, exact encrypted audit and separate SQL roles. Current readers retain the original deadline and require matching active recovery/issuer state. Known rollback/mutation commits a fence before returning conflict; old failure cleanup and historical audit cannot revive or replace newer trust. Already acknowledged observations reuse their receipt without further key operations. No public interface or whole-task/slice completion is implied.

The initial focused real SQL/S3 fixture passed in 1.886 seconds, recorded in [its harness log](../test/results/owner-acceptance-targeted-check.log), [test log](../test/results/owner-acceptance-targeted-custody.log) and [report](../test/results/owner-acceptance-targeted-custody-environment.json). All 577 recorded source hashes matched at terminal cleanup and cleanup failures were empty. This established missing/unaudited denial, restart/replay, eight simultaneous observations, negative watermarks, mutation/rollback fences, source/role immutability, suspension/recovery/issuer changes and expiry after a proven SQL lock wait. The subsequent test revision additionally exercises the 1024-revision application and database bound.

Final verification passed:

- `make go-check go-architecture-check sql-check` returned 0 in [the code gate log](../test/results/owner-acceptance-code-gates.log): vet, all Go/race tests, 41 packages/181 permitted import edges and 21 matching generated SQL files. Integration tests without fixture variables remain skips in this command.
- `make custody-integration` returned 0 in [the harness log](../test/results/owner-acceptance-custody-check.log). The [full SQL/S3 suite](../test/results/owner-acceptance-final-custody.log) passed in 106.568 seconds, including the expanded owner test in 0.90 seconds. [Its report](../test/results/owner-acceptance-final-custody-environment.json) records 577 unchanged sources and empty cleanup failures; hashes matched current files after completion.
- `make context-integration` returned 0 in [the harness log](../test/results/owner-acceptance-context-check.log). The [full Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/owner-acceptance-final-context-storage.log) passed in 61.069 seconds; the owner discovery/protected-source/SQL/audit/route test passed in 5.05 seconds. These durations cover complete tests, not single calls. [Its report](../test/results/owner-acceptance-final-context-storage-environment.json) records 576 unchanged sources, matching final hashes and empty cleanup failures.
- `make spec-check architecture-check design-check` returned 0 in [the design gate log](../test/results/owner-acceptance-doc-gates.log). These verify documents/contracts and mappings, not production activation.

The real Kubernetes route fixture now connects the protected source to these SQL/S3 acceptance components. Recovery activation and audit wrapping roots remain explicitly synthetic fixture inputs; production issuer/bootstrap and certificate activation are unfinished. Next are those prerequisites, authenticated private forwarding, connector-local proof mediation and supervised native transfer, followed by complete UI/MCP/Helm and remaining slices.

## Current protected owner configuration continuation

[ADR-077](decisions/077-protected-owner-configuration.md) and [protected owner configuration](architecture/owner-configuration.md) add the private owner-pool JSON contract, public CA validation, admission-qualified source and C-04 route composition. The shared ConfigMap proof engine retains the existing worker policy/denial/pins. Observation source, actual owner endpoint and current configuration must agree, with the earliest original five-second/root deadline. No SQL/public wire change or credential/evidence authority is introduced.

The [first focused build](../test/results/owner-config-first-build.log) and [expanded component regression](../test/results/owner-config-second-build.log) passed. A [failing cached-observation regression](../test/results/owner-config-cached-before.log) caught rejection of a still-fresh original observation; composition now accepts it without extending expiry. The corrected [full Go/race/import gates](../test/results/owner-config-final-code-gates.log) returned 0. The [owned service harness](../test/results/owner-config-context-check.log) returned 0 and [its suite](../test/results/owner-config-final-context-storage.log) passed in 57.629 seconds. The owner discovery/configuration composition passed in 5.54 seconds; this is the whole multi-operation test, not one route lookup. It verified actual admission and read/probe roles, unchanged ConfigMap resource versions after dry-run, suspension/resume and missing-protection rejection. The existing restricted worker credential path also passed with the shared guard. [The final report](../test/results/owner-config-final-context-storage-environment.json) records 564 unchanged source files and no cleanup failures; recorded hashes matched current files after terminal cleanup. Process identity and CA issuance remain synthetic inputs.

`make spec-check architecture-check design-check` [returned 0](../test/results/owner-config-docs.log): 58 schemas, all 176 requirement/scenario pairs and the architecture/UI/interface mappings. Those design checks do not qualify an issuer or network relay.

Next: durable owner-configuration/recovery acceptance, protected issuer enrollment and audited certificate activation, private forwarding, connector-local proof mediation and native evidence delivery. This source reader does not complete certificate bootstrap or any whole task/slice. Local login and bundled installation also remain pending.

## Current hub owner discovery continuation

[ADR-076](decisions/076-hub-owner-discovery.md) and [hub owner discovery](architecture/hub-owner-discovery.md) add exact hub installation/cluster/issuer/Pod/process bindings, the C-04 endpoint reader, a bounded Kubernetes Service/EndpointSlice/Pod/account/ReplicaSet/Deployment adapter and standard-library TLS 1.3 verification. No SQL or public wire change is introduced. Routing observations preserve the original five-second deadline; TLS independently checks the expected process and current certificate lifetime. Neither source construction nor a signed leaf supplies protected bootstrap, issuer activation or evidence authority.

The [focused race regression](../test/results/owner-discovery-unit.log) passed both Kubernetes and mutual TLS tests. The [full Go gate log](../test/results/owner-discovery-go-gates.log) shows successful schema/vet/race tests followed by an import-gate rejection of `net/netip`. The corrected [import gate](../test/results/owner-discovery-import-gate.log) passes with that pure standard-library address parser explicitly allowed; sockets, DNS and HTTP remain forbidden in domain code.

The [first owned Kubernetes suite](../test/results/owner-discovery-first-context-storage.log) failed discovery because real controller target references omit the optional API version. [Its report](../test/results/owner-discovery-first-context-storage-environment.json) records 555 unchanged sources and no cleanup failures. A [focused regression](../test/results/owner-discovery-missing-version-before.log) reproduced that failure before fixing the adapter to accept absent or `v1` and still independently GET the exact core/v1 Pod. Explicit foreign versions remain rejected.

The corrected [full Go/race/import gates](../test/results/owner-discovery-final-go-gates.log) returned 0. The [second owned-service harness](../test/results/owner-discovery-final-context-check.log) returned 0; [its full suite](../test/results/owner-discovery-final-context-storage.log) passed in 54.741 seconds. Actual owner discovery passed in 1.15 seconds, including read-only RBAC, controller output, invalid scope, readiness override and deletion. [The final environment report](../test/results/owner-discovery-final-context-storage-environment.json) records 555 unchanged source files and no cleanup failures; all recorded hashes matched current files after terminal cleanup. Synthetic TLS issuance and process expectations remain explicit; this does not prove production issuer activation or a running hub relay.

`make spec-check architecture-check design-check` also [returned 0](../test/results/owner-discovery-final-docs.log). These are design/contract gates, not runtime forwarding qualification. No SQL contracts changed in this continuation; the earlier SQL-owner qualification remains separately recorded below.

Next: protected owner-pool/issuer configuration, certificate issuance/activation, private forwarding before credential transmission, connector proof mediation and supervised native delivery. Local login and bundled-service installation also remain incomplete. No S-01/S-02 or whole TASK exit is claimed.

## Current shared worker owner continuation

[ADR-075](decisions/075-worker-owner-locator.md) and [shared owner locators](architecture/worker-owner-locator.md) add migration 28, a purpose-specific PostgreSQL store, separate claim/lookup fixture roles, local-registration publication and exact-owner enrollment receiving. SQL stores opaque request/process IDs and original deadlines/fences; it stores no credentials, Pod tokens, evidence or endpoint URLs. Current human/recovery/configuration/session/worker checks precede a claim and are repeated after locks. Active ownership cannot be renewed or silently replaced; stale release cannot delete a replacement. Registration failure closes local ownership, and unknown SQL outcomes remain bounded by original expiry.

The [first scoped SQL harness](../test/results/worker-owners-first-custody-check.log) returned 0; [its suite](../test/results/worker-owners-first-custody.log) passed in 4.071 seconds with 548 unchanged source files and [complete cleanup](../test/results/worker-owners-first-custody-environment.json). It exercised two owner pools/registries, an independent lookup role, eight competing claims, immutable deadline replay, direct transition/role attacks, current actor/session binding, actual row-lock expiry and cancellation. The subsequent exact-owner receiving check and same-certificate replay passed in the expanded full regression below.

[Focused race tests](../test/results/worker-owners-third-build.log) pass. [The code gates](../test/results/worker-owners-code-gates.log) returned 0: vet/race, 41 packages/178 allowed internal imports and all 20 generated SQL files. The full `make custody-integration` returned 0 in [the harness](../test/results/worker-owners-full-custody-check.log); [the suite](../test/results/worker-owners-full-custody.log) passed in 105.315 seconds. [Its environment report](../test/results/worker-owners-full-custody-environment.json) records 548 unchanged source files, 231 passed test names and no cleanup failures; the current-source comparison also found no changes. The first spec/architecture/design checks returned 0 in [the documentation gate](../test/results/worker-owners-first-docs.log). The sequential `make context-integration` returned 0 in [the harness](../test/results/worker-owners-context-check.log); [the suite](../test/results/worker-owners-context-storage.log) passed in 50.460 seconds, including the compiled restricted-Pod credential runtime and verified termination. [Its environment report](../test/results/worker-owners-context-storage-environment.json) records 547 unchanged source files, no current-source differences and no cleanup failures. No fixture process identity or synthetic Pod/CA proof qualifies authenticated hub discovery or network forwarding.

Next complete protected process discovery and private forwarding, connector-local proof/reference mediation, public owner registration and native evidence delivery. S-01/S-02 and all complete TASK exits remain unfinished.

## Current worker request routing continuation

[ADR-074](decisions/074-worker-request-routing.md) and [worker request routing](architecture/worker-request-routing.md) add bounded process-local registration of current authenticated owners against the admitted SQL worker registry. Each worker retains separate token readers and exact actor/client/artifact scope. Registration I/O, active owners and closing in-flight work share a finite limit; old-handle cleanup cannot remove a replacement. A mandatory-close private delivery keeps the original cancellation/deadline effective through certificate response write/flush, including blocked writes. Public JSON, SQL schema, dependencies and developer approvals are unchanged.

The recovered prior focused build passed; no previous test process remained active. The expanded [focused race tests](../test/results/worker-routes-final-focused.log) pass for distinct concurrent workers, current installation/scope, stale registration after I/O, cancellation/shutdown, held capacity and response lifetime. [The complete code gates](../test/results/worker-routes-code-gates.log) returned 0: Go vet/race, 41 packages/178 permitted internal import edges and all 19 generated SQL files. The full `make custody-integration` returned 0 in [the harness](../test/results/worker-routes-full-custody-check.log); [the suite](../test/results/worker-routes-full-custody.log) passed in 102.701 seconds, including the routed enrollment/current SQL binding and held-delivery/same-certificate replay case. [The environment report](../test/results/worker-routes-full-custody-environment.json) records 540 unchanged source files, 230 passed test names and no cleanup failures. The current-source comparison also found no changes. The sequential `make context-integration` also returned 0 in [the harness](../test/results/worker-routes-context-check.log). [The complete suite](../test/results/worker-routes-context-storage.log) passed in 51.111 seconds, including the actual compiled restricted-Pod credential startup/OpenBao issuance and confirmed retirement. [Its environment report](../test/results/worker-routes-context-storage-environment.json) records 539 unchanged source files and no cleanup failures; the current-source comparison found no changes. The SQL case retains synthetic Pod/CA inputs, while the Kubernetes case retains synthetic dispatch/issuance authority. Neither is a fully composed public download.

Distributed owner rendezvous, authenticated browser/MCP registration, outbound connector mediation, protected listener/issuer bootstrap and actual native transfer remain required. This does not complete a TASK or S-01/S-02 exit.

## Current worker startup continuation

[ADR-073](decisions/073-worker-startup.md) and [worker startup](architecture/worker-startup.md) add the first `asservat download-worker` executable and composition root. The credential phase validates closed immutable public configuration, exact original identity/timing/digest arguments and actual downward-API Pod UID, suppresses its own Linux core dumping before key creation, and supervises enrollment/renewal without a blocking status observer. The executable does not link Kubernetes/SQL clients. Credential readiness explicitly reports that native transfer is unavailable; no empty transfer or public success is introduced.

The changed startup template also exposed a historical cleanup defect. Cleanup now validates stored original Job/Pod identities and spec digests, while fresh launch/binding still require the current template. Additional/replacement or uncertain Pods retain their capacity charge for a separate orphan path. Termination persistence, exact-UID foreground deletion and verified absence remain unchanged. No SQL migration, developer approval or dependency was added.

Focused race tests passed in [the sixth build](../test/results/worker-startup-sixth-build.log). They cover complete original renewal periods, bounded initial failure, cancellation, an unconsumed notification channel, strict configuration/argument parsing, process-local core-limit readback and cleanup of an original older template. The [compiled CLI check](../test/results/worker-startup-cli.log) passes without Kubernetes/SQL dependencies and rejects unknown/incomplete startup without echoing inputs. [The first complete gates](../test/results/worker-startup-first-gates.log) returned 0 before final documentation updates: Go vet/race/import, SQL generation, specification, architecture and design checks.

The first real-service run failed before Job creation because its two-minute synthetic dispatch exceeded the existing one-minute protected fixture profile. [The failure](../test/results/worker-startup-first-context-storage.log) and [environment](../test/results/worker-startup-first-context-storage-environment.json) are retained; tested sources were unchanged and cleanup completed. The fixture now retains the original one-minute deadline. Production limits were not relaxed. The second run created the restricted worker but did not observe its credential-ready diagnostic; [its log](../test/results/worker-startup-second-context-storage.log) and [cleaned environment](../test/results/worker-startup-second-context-storage-environment.json) are retained. The third run added bounded enrollment-stage and Pod-state diagnostics: the process remained running, logs were readable/empty, and no enrollment request reached the host bridge listener ([log](../test/results/worker-startup-third-context-storage.log), [cleaned environment](../test/results/worker-startup-third-context-storage-environment.json)). The next fixture uses an owned non-root container to relay encrypted TCP to a private Unix listener, retaining the exact TLS trust checks and leaving host firewall/settings untouched. Combined Kubernetes/OpenBao and full SQL regression remained pending at that checkpoint. An independent runtime/schema mismatch for an empty endpoint fragment was reproduced in [the failing test](../test/results/worker-startup-endpoint-before.log) and corrected with [passing race tests](../test/results/worker-startup-endpoint-after.log).

The corrected `make context-integration` returned 0 in [the fourth harness run](../test/results/worker-startup-fourth-context-check.log). [The complete suite](../test/results/worker-startup-fourth-context-storage.log) passed in 49.266 seconds. The actual compiled command ran in its digest-pinned restricted Pod, loaded the mounted public trust and projected token, generated its own key/CSR, enrolled through the real TLS handler and OpenBao issuer, and emitted the fixed credential-phase diagnostic only after installing the returned credential. Independent token/Pod proof, sign-role denial/revocation, SIGTERM shutdown and confirmed Job/Pod retirement passed. The [environment report](../test/results/worker-startup-fourth-context-storage-environment.json) records 535 unchanged source files and complete cleanup; a subsequent current-source comparison found no changes. The separate owned TLS relay/image cleaned up through the Go fixture's checked cleanup hooks. This proves the initial credential runtime in a Pod; dispatch registry and issuance audit remain synthetic in this case, and native transfer is absent.

The full `make custody-integration` returned 0 in [the harness](../test/results/worker-startup-full-custody-check.log); [the suite](../test/results/worker-startup-full-custody.log) passed in 102.444 seconds. [Its environment report](../test/results/worker-startup-full-custody-environment.json) records actual selected/passed tests, unchanged sources and empty cleanup failures. The current-source comparison for both final service reports found no changed Go/SQL/fixture files. `make go-check go-architecture-check sql-check` returned 0 in [the final code gates](../test/results/worker-startup-final-go-gates.log): vet/race, 41 packages/178 allowed imports and all 19 generated SQL files. The current executable was rebuilt and its negative CLI/import checks passed. `make spec-check architecture-check design-check` returned 0 in [the final documentation gates](../test/results/worker-startup-final-docs.log): 57 schemas, 443 rejected invalid examples, all 176 requirement/scenario mappings and the existing 63-screen/browser/MCP contracts. These design checks do not qualify public routing or native transfer.

Next: protected issuer/endpoint initialization, active browser/MCP/connector request-owner routing and actual native work/byte relay. Continue connection/orphan cleanup, local CA/login, bundled services and remaining collection/UI/MCP requirements. Neither a TASK nor an end-to-end slice is complete.

## Previous worker credential channel continuation

[ADR-072](decisions/072-worker-credential-channel.md) and [the channel contract](architecture/worker-credential-channel.md) implement the acquisition process key and private credential transport under REQ-DEP-003, REQ-DLD-003 and REQ-CAP-003. The client generates one in-memory P-256 key/identity-free CSR and renews within the original worker periods. Separate pinned server and issuer roots, exact response correlation/key/Pod/role/expiry checks, a fixed rotating projected-token reader, one active request and no redirect or automatic POST replay bound this bootstrap path. Closing the owner cancels enrollment and disables retained signer snapshots; it does not promise heap erasure or close separately owned established transports.

The private handler accepts only the worker CSR/token exchange. `WorkerEnrollmentOperation` binds current human authority to one active request and exact admitted worker for at most thirty seconds, preserving parent cancellation and keeping user credentials outside the worker wire. Its request-owned proof reader avoids token substitution between concurrent calls. Installation identity is separately checked from the permission-root ID. The existing independent SQL signing/audit/activation roles and original deadlines remain unchanged; no migration, developer permission or extra approval was added. C-20 now consumes C-14's narrow enrollment port. The closed JSON schema is private; public browser/MCP operations and UX remain unchanged.

A regression demonstrated that keeping the bootstrap TLS connection alive allowed renewal to send a Pod token after the server certificate expired. The [pre-fix test](../test/results/worker-channel-server-expiry-before.log) failed with that behavior; [the corrected race test](../test/results/worker-channel-server-expiry-after.log) passes with a fresh server handshake for every actual enrollment. A current-period credential performs no network request, so this does not create per-frame or per-key traffic. Failed renewal keeps the original credential only through its original expiry.

Verification uses build TMPDIR `/home/phil/.cache/asservat-build/tmp` and Make PYTHON `/tmp/asservat-openapi-validation/bin/python`:

- `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [the first complete gate run](../test/results/worker-channel-first-gates.log). After expanding the actual provider fixture, `make go-check go-architecture-check sql-check` returned 0 again in [the second gate run](../test/results/worker-channel-second-gates.log). Vet/race tests pass, 39 packages/177 allowed imports and 19 generated SQL files match. Initial design checks cover 56 schemas, 429 rejected examples, 176 requirements/scenarios and the existing 63-screen/49-entity/browser/MCP mappings.
- Local real-TLS tests cover actual mTLS use of the process-owned key, renewal with token reread, finite old-certificate overlap, wrong key/Pod/role/installation/usages/expiry, wrong nonce/response identity, untrusted endpoint/issuer, malformed/oversized/duplicate JSON, redirects/lost replies without replay, cancelled/parallel requests, failed-renewal expiry and closed signer snapshots. The projected-token test follows actual filesystem symlink replacement and checks fresh buffers, invalid size/syntax and cancellation. These tests use a test CA and synthetic token authentication, not production authority.
- The first targeted fixture invocation used an incorrect test selector and ran no tests despite Go exit 0: [log](../test/results/worker-channel-first-custody.log). It is not qualification. The fixture runner now rejects empty selection and root-only success when a subtest was requested, and records the actual passed test names. The [correctly selected run](../test/results/worker-channel-second-custody-check.log) passed; [its environment](../test/results/worker-channel-second-custody-environment.json) records the exact new subtest and complete cleanup.
- The full `make custody-integration` returned 0 in [the harness log](../test/results/worker-channel-full-custody-check.log); [the suite](../test/results/worker-channel-full-custody.log) passed in 101.903 seconds. The added case composes the real TLS client/handler/process key and bound control operation with the existing current authorizer, separate SQL enrollment/audit/activation roles and encrypted S3 audit. Foreign worker selection and cancelled parent authority deny. [The environment report](../test/results/worker-channel-full-custody-environment.json) records 524 unchanged source files, 230 passed test names and complete cleanup. Its Pod proof and CA remain fixtures; a valid TLS certificate alone does not stand in for activated SQL identity.

- `make context-integration` returned 0 in [the context harness](../test/results/worker-channel-first-context-check.log); [the complete suite](../test/results/worker-channel-first-context-storage.log) passed in 49.485 seconds. The actual worker case now uses the production credential client/handler and its process-owned key with real Kubernetes Pod TokenReview and fixed-role OpenBao CSR signing, followed by a real mTLS handshake, certificate-bound worker proof and Job retirement. Its dispatch registry, signing permit/audit and active requester remain fixtures, and the key-owning client runs in the test runner rather than the fixture Job. [The environment report](../test/results/worker-channel-first-context-storage-environment.json) records 523 unchanged source files, exit 0 and complete cleanup of both owned clusters and service fixtures.

Both final service reports were compared with the current Go/SQL/fixture sources after completion; no tested source changed. Final documentation gates are recorded in [the documentation log](../test/results/worker-channel-final-docs.log).

Next: protected endpoint/issuer and exact worker startup pins, active browser/MCP/connector routing, the acquisition executable and renewal/connection supervisor. Then complete native-file delivery, local CA/login, bundled-service installation and the remaining collectors and S-00–S-09 requirements. No complete TASK, slice or public investigation workflow is claimed.

## Previous acquisition credential checkpoint

[ADR-071](decisions/071-download-worker-enrollment.md), [the enrollment contract](architecture/worker-enrollment.md) and migration 27 implement acquisition credential enrollment/renewal components. Initial enrollment now verifies the admitted worker and Pod-bound token without requiring a pre-existing certificate. An identity-free signed CSR binds one immutable process key. Current download authority and protected worker configuration remain mandatory. Separately audited enrollment precedes nonrefundable signing; verified public certificates require independent encrypted audit and activation before the SQL identity reader accepts them.

Twenty-minute renewal periods derive from the original worker start, with a one-minute overlap and two finite signing attempts per period. They cannot extend the worker/evidence deadline, reset counters or change its key. Domain tests cover the full eight-hour schedule, short workers, rounding down to certificate seconds, epoch boundaries and original-proof expiry. Repeated enrollment recovers the recorded certificate/audits without new signing or encryption; failed/uncertain signing stays spent. No private key, bearer token or provider credential enters these SQL/audit records.

The coordinator keeps signing, audit and activation on separate credentials. The external issuer reuses the maintained OpenBao client and standard Go X.509 verifier with a fixed sign-only role and no retries. The TLS verifier's shared certificate-validation function supports checking the actual issuer response without fabricating a completed TLS handshake. A fixture CA is explicitly test-only; the accepted local static-key CA alternative is not implemented by this change.

Verification used `TMPDIR=/home/phil/.cache/asservat-build/tmp` and Make `PYTHON=/tmp/asservat-openapi-validation/bin/python`:

- The first focused real PostgreSQL/S3 flow passed in [worker-enrollment-first-custody.log](../test/results/worker-enrollment-first-custody.log): unregistered-certificate denial followed by enrollment/audit/activation and normal dispatch/retirement. This preceded the expanded tests and final deadline propagation; it is retained as early evidence.
- `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [worker-enrollment-first-gates.log](../test/results/worker-enrollment-first-gates.log): vet/race, 38 packages/171 allowed imports, 19 matching sqlc files, 55 schemas/165 examples/412 rejected cases and unchanged public UI/API mappings. The focused race run is in [worker-enrollment-fourth-build.log](../test/results/worker-enrollment-fourth-build.log).
- The full `make custody-integration` returned 0 in [worker-enrollment-second-custody-check.log](../test/results/worker-enrollment-second-custody-check.log); [the suite](../test/results/worker-enrollment-second-custody.log) passed in 100.529 seconds. New cases exercise audit-before-signing/activation, signed-result recovery after missing audit without another provider call, exact replay, key replacement denial, eight-way single-use signing, two uncertain-attempt exhaustion, separate SQL role privileges, acknowledgement reuse and expiry behind the worker lock without a spend. Existing dispatch, key access, downloads, retention, policy and custody cases pass. [The environment report](../test/results/worker-enrollment-second-custody-environment.json) records 516 unchanged source files, exit 0 and complete cleanup. Worker token/registry authority and the CA are synthetic; certificates and chain verification, SQL transactions and encrypted S3 audit are real.
- `make context-integration` returned 0 in [worker-enrollment-first-context-check.log](../test/results/worker-enrollment-first-context-check.log); [the suite](../test/results/worker-enrollment-first-context-storage.log) passed in 47.979 seconds. The real worker test (16.01 seconds) uses actual Kubernetes Pod-bound token proof before a certificate exists, OpenBao sign-only CSR issuance, a real TLS handshake with that certificate, then certificate-bound worker proof and Job retirement. Foreign key/issuer epoch and signer credential/role failures deny. Existing context/storage/provider tests pass. [The environment report](../test/results/worker-enrollment-first-context-storage-environment.json) records 515 unchanged source files, exit 0 and complete cleanup of both owned clusters/services. The private key is generated in the test, and signing permits/audit, dispatch registry and issuer provisioning remain fixtures. It is not the production worker executable or a fully composed public download.

Next: protected issuer/bootstrap configuration and the bounded authenticated worker/control transport, acquisition executable with process-owned key handling, and continuous supervision. Compose these with the public browser/MCP/native-file flow and implement the local-CA alternative, local login, bundled storage/database and installation/recovery gates. General collectors, full orphan cleanup and the remaining S-00–S-09 product work remain unfinished; no whole TASK or slice is complete.

## Previous protected worker configuration checkpoint

[ADR-070](decisions/070-protected-worker-configuration.md) and [the worker configuration contract](architecture/worker-configuration.md) add the protected administrator source, migration 26 current/revision projections and encrypted configuration audit. The real source qualifies an exact pinned native admission policy with a separate non-administrator dry-run probe, validates the closed ConfigMap twice and preserves its original five-second deadline. Dispatch and worker identity require the current audited profile; a new unaudited revision supersedes old authority immediately. Profile rollout never rewrites a worker identity or resets uncertain charges, and historical cleanup remains available after expiry/suspension. This closes the constructor-profile authority gap without enabling a public endpoint.

The missing-projection defect was first reproduced in [worker-config-before-custody.log](../test/results/worker-config-before-custody.log): an unaccepted constructor profile could reserve a worker. The regression now rejects that call. The first real Kubernetes run failed when a fixture assumed its administrator belonged to `system:masters`; the native guard correctly refused that user's later update. [The failed run](../test/results/worker-config-first-context-storage.log) is preserved. The fixture now pins its actual authenticated administrator username as trusted bootstrap input; the guard remains unchanged.

Verification used `TMPDIR=/home/phil/.cache/asservat-build/tmp` and Make `PYTHON=/tmp/asservat-openapi-validation/bin/python`:

- `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [worker-config-first-gates.log](../test/results/worker-config-first-gates.log). Vet/race tests, 38 packages/171 allowed imports, 18 matching sqlc files, 55 schemas/165 examples/412 rejected cases and the existing interface/UI mappings pass. The new synthetic parser tests reject omitted/aliased/duplicate/unknown fields, foreign scopes, unpinned images and invalid limits; they do not supply admission authority.
- `make context-integration` returned 0 in [worker-config-second-context-check.log](../test/results/worker-config-second-context-check.log). [The real Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/worker-config-final-context-storage.log) passed in 48.497 seconds. The worker test (16.53 seconds) exercises distinct source/probe identities, actual native admission, mutation/deletion denial, protection removal and SQL fencing, explicit new protection/revision acceptance and the restricted Job/TokenReview/retirement path. [Its environment report](../test/results/worker-config-final-context-storage-environment.json) records 498 unchanged source files, exit 0 and no cleanup failures. Recovery trust, audit wrapping material, bootstrap pins, executable and certificate issuer remain explicit fixtures; this is not a deployed download service.
- `make custody-integration` returned 0 in [worker-config-final-custody-check.log](../test/results/worker-config-final-custody-check.log). [The full SQL/S3 suite](../test/results/worker-config-final-custody.log) passed in 88.347 seconds. New cases cover missing/changed/suspended/fenced profiles, same-revision substitution, rollback, unaudited supersession, exact audit reuse, five SQL role boundaries, older failed-observation fencing, original identity expiry, cleanup after expiry and observation expiry behind a held lock. Existing download, custody, enrollment, permission and policy tests pass. [Its environment report](../test/results/worker-config-final-custody-environment.json) records 499 unchanged source files, exit 0 and complete cleanup. Kubernetes inputs/Job effects in this SQL suite remain synthetic and are independently exercised by the real API suite above.

Configuration history has a finite 1024-revision ceiling; safe history retirement is pending. Current observation is a component method, not a supervised runtime: the real Job fixture explicitly refreshes it before effects. Installer/bootstrap pin provisioning, acquisition certificate enrollment/issuance, the finite authenticated worker/control executable and its supervisor remain next. Public UI/MCP/native-download composition, full orphan cleanup, local login and bundled-service installation remain unfinished. No complete TASK or S-01/S-02 exit is claimed.

## Previous worker dispatch checkpoint

[ADR-069](decisions/069-download-worker-dispatch.md) adds [audited worker dispatch](architecture/download-worker-dispatch.md), migration 25 and the restricted Kubernetes Job driver. Original intent, audit, single-use launch, Job/Pod binding and termination/retirement are durable; a lost create response does not create another Job, and cleanup persists termination before deletion. The dispatched proof source now reads SQL identity and immutable current worker configuration before TokenReview. The product acquisition command and issuer remain unfinished.

Focused race tests passed in [dispatch-fifth-build.log](../test/results/dispatch-fifth-build.log). The first owned SQL/S3 run passed the new coordinator/ledger cases in [dispatch-first-custody.log](../test/results/dispatch-first-custody.log), with unchanged sources and complete cleanup recorded in [its environment](../test/results/dispatch-first-custody-environment.json). That targeted run preceded the fixes below. SQL job effects and authority inputs remain synthetic; the actual Kubernetes test is separate.

The next continuation verified that the interrupted Kubernetes run had terminated with failure and cleaned its fixtures; it did not restart an unknown live test. [First run](../test/results/dispatch-first-context-storage.log) and [diagnostic rerun](../test/results/dispatch-second-context-storage.log) reproduce Pod admission rejecting `Never` against the cluster's default preempting PriorityClass. The driver now pins a dedicated zero-priority, non-preempting class and requires exact named read-only access. A separate [failing parser regression](../test/results/dispatch-list-before.log) exposed rejection of standard PodList items without redundant TypeMeta; the typed-list path now permits omitted kind/version while rejecting foreign explicit types and preserving full spec checks.

[Failing SQL regressions](../test/results/dispatch-retry-before-custody.log) also reproduced unnecessary encrypted audit work on retries and unusable sub-second worker reservations. The dispatcher now reuses exact acknowledged receipts, and admission rejects a sub-second interval without charging a worker. [Focused race tests](../test/results/dispatch-sixth-build.log) pass. These fixes are not yet a runnable download service.

Current verification uses `TMPDIR=/home/phil/.cache/asservat-build/tmp` and Make `PYTHON=/tmp/asservat-openapi-validation/bin/python`:

- `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [repository gates](../test/results/dispatch-final-gates.log): vet/race, 38 packages/171 allowed edges, 17 matching sqlc files, 54 schemas/165 examples/391 rejected cases, 176 requirements/scenarios and the existing 63-screen/49-entity/browser/MCP mappings.
- `make context-integration` returned 0 in [the third harness run](../test/results/dispatch-third-context-check.log). The [final suite](../test/results/dispatch-final-context-storage.log) passed in 46.652 seconds, including actual Job creation, exact image/config/Pod identity, non-preempting PriorityClass admission and source-change denial, projected-token proof, known termination and foreground deletion. It also reran the existing Kubernetes/OpenBao/S3/PostgreSQL context and local-key lifecycle tests. The [environment report](../test/results/dispatch-final-context-storage-environment.json) confirms 482 unchanged source files and complete cleanup of both owned clusters and service fixtures. The acquisition executable, human dispatch authority, identity-registry response and peer-certificate issuance in the new Job test are explicit fixtures, not the production runtime.
- The full `make custody-integration` returned 0 in [the harness log](../test/results/dispatch-final-custody-check.log). The [suite](../test/results/dispatch-final-custody.log) passes all new dispatch cases: unaudited denial, fresh audit and acknowledged-receipt reuse, mismatched-receipt identity, eight-way single-use launch, no sub-second reservation/charge, exact Pod binding, pending/cancelled capacity retention, expiry after a held child lock, cancellation, lost-create lookup and persisted-termination recovery after a lost delete reply. Existing native-file/TLS/S3, permission, policy, enrollment and custody regressions also pass. [Its environment report](../test/results/dispatch-final-custody-environment.json) confirms unchanged tested sources and complete fixture cleanup. Kubernetes Job effects in this SQL suite are simulated; the separate real Job suite above establishes the adapter behavior. Neither fixture provides protected profile enrollment or production certificate issuance.

Next: protected profile acceptance/rollout, peer issuance and actual authenticated acquisition/control runtime. Full pending/orphan cleanup, public collection/UI/MCP/native-download and small-profile installation remain unfinished. No complete S-01/S-02 or other TASK exit is claimed.

## Previous worker identity checkpoint

[ADR-068](decisions/068-download-worker-attestation.md) adds [Kubernetes worker proofs](architecture/download-worker-attestation.md) to the local download key binding. The source checks actual TokenReview, dedicated audience, account/Pod identity and current namespace/Job/Pod specifications against protected dispatch inputs. The C-14 coordinator and migration 24 SQL consumer preserve original five-second proof deadlines, exact certificates, legacy denial and irreversible key slots. This does not issue peers, produce trusted dispatch or add a runtime endpoint.

Focused race tests pass in [worker-proof-targeted.log](../test/results/worker-proof-targeted.log). The earlier coordinator fixture used its own session ID in the wrong-session test; [worker-proof-third-build.log](../test/results/worker-proof-third-build.log) records that test failure and the fixture now substitutes a distinct ID. `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [worker-proof-first-gates.log](../test/results/worker-proof-first-gates.log): vet/race, 38 packages/169 allowed imports, 16 matching sqlc files and unchanged public schema/UI mappings.

The first real Kubernetes/TLS/context suite passed with unchanged sources and complete cleanup in [worker-proof-first-context-storage.log](../test/results/worker-proof-first-context-storage.log). It verifies actual TokenReview, dedicated audiences, exact Pod/account identity, spec mutation/deletion and reviewer RBAC. Its dispatcher pins and certificate issuer remain fixtures. The first full SQL suite failed because the narrowly scoped fixture coordinator role lacked INSERT on the newly added proof column; [worker-proof-first-custody.log](../test/results/worker-proof-first-custody.log) preserves the failure. Only that column's insertion permission was added; proof UPDATE remains forbidden. Final real-service reruns now pass:

- `make custody-integration` returned 0 in [worker-proof-second-custody-check.log](../test/results/worker-proof-second-custody-check.log). The [full SQL suite](../test/results/worker-proof-final-custody.log) passed in 72.632 seconds, including missing/stale/foreign proofs, replay preserving original proof/deadline, forbidden proof updates, legacy NULL denial, expiry behind parent and child locks without spending, failed renewal of expired proofs, and native download through real SQL/TLS/S3. Its worker proofs, human/configuration authority and certificates are explicit test inputs. The [environment record](../test/results/worker-proof-final-custody-environment.json) confirms 469 unchanged source files, exit 0 and complete cleanup.
- `make context-integration` returned 0 in [worker-proof-final-context-check.log](../test/results/worker-proof-final-context-check.log). The [final Kubernetes/OpenBao/S3/PostgreSQL suite](../test/results/worker-proof-final-context-storage.log) passed in 32.156 seconds. This includes actual dedicated-audience Pod-bound TokenReview, restricted reviewer RBAC, live account/Job/Pod/spec checks and mTLS identity, plus existing context/native-file and protected key-lifecycle regressions. The [environment record](../test/results/worker-proof-final-context-storage-environment.json) confirms 468 unchanged source files, exit 0 and removal of both owned clusters and all service fixtures. It does not compose real dispatch/issuer enrollment with a public user download.

Build commands used `TMPDIR=/home/phil/.cache/asservat-build/tmp` and Make `PYTHON=/tmp/asservat-openapi-validation/bin/python`. The final documentation/catalog gate results are in [worker-proof-final-docs.log](../test/results/worker-proof-final-docs.log). No runtime/chart collection was enabled.

Remaining: protected dispatch and Job creation, certificate enrollment/issuance and authenticated token delivery; then current authorities for other key purposes and runnable small-profile bootstrap. Full collection/UI/MCP/native-download workflows remain unfinished.

## Previous protected local key lifecycle checkpoint

[ADR-067](decisions/067-protected-local-key-lifecycle.md) adds [protected local key lifecycle](architecture/local-key-lifecycle.md): pinned ConfigMap/immutable Secret reads, five-second coalesced observations, mandatory pre/post-crypto guards and migration 23 public version history. Additive rotation preserves retained keys and rejects accepted rollback/material substitution/reuse. Safe retirement and deployment/source enrollment/PKI remain unfinished.

The missing guard was reproduced by [a failing regression](../test/results/key-lifecycle-before.log): an otherwise authorized service accepted an operation with no current configuration. Targeted race tests now pass in [component checks](../test/results/key-lifecycle-third-build.log), including protected source bounds, original deadline checks and coalesced refreshes. The real-service tests below now pass; no production throughput or installation claim follows from them.

Verification used `TMPDIR=/home/phil/.cache/asservat-build/tmp` and Make `PYTHON=/tmp/asservat-openapi-validation/bin/python`:

- `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0: [repository gate log](../test/results/key-lifecycle-final-gates.log). Vet/race tests, 38 packages/168 allowed edges, 16 matching sqlc files, 54 schemas/165 examples/391 rejected cases and all architecture/UI mappings pass. The earlier [first gate log](../test/results/key-lifecycle-first-gates.log) returned 2 because the specification checker requires a registered absolute schema reference instead of a bare local fragment; the schema now uses its canonical registered ID. No runtime validation was weakened.
- `make context-integration` returned 0: [harness log](../test/results/key-lifecycle-context-check.log), [suite log](../test/results/key-lifecycle-final-context-storage.log), 30.115 seconds. The new 5.92-second lifecycle case used actual Kubernetes named read-only RBAC/immutable Secrets, SQL version acceptance and real mTLS wrap/unwrap. Rotation preserved old reads and fenced old instances; rollback, suspension, changed/removed/reused material, active-version rollback, expiry during a held SQL lock, blocked recovery, Secret deletion/replacement and runtime mutation privileges were checked. Its operation approval resolver remains test-only; this is not end-to-end user authorization. The [environment report](../test/results/key-lifecycle-final-context-storage-environment.json) confirms 461 current source hashes, unchanged execution and complete cleanup of both owned clusters and service fixtures.
- `make custody-integration` returned 0: [harness log](../test/results/key-lifecycle-custody-check.log), [suite log](../test/results/key-lifecycle-final-custody.log), 68.075 seconds. Existing SQL authority, context publication, local/external native-download, retention, peer and policy tests pass under migration 23. The [environment report](../test/results/key-lifecycle-final-custody-environment.json) confirms unchanged sources and complete fixture cleanup. This suite's existing key-service cases use synthetic configuration guards; the actual protected Kubernetes lifecycle is the separate context case above.

Configuration observations are reused only for their original five seconds, with coalesced refresh and SQL checks before/after crypto. This avoids repeated Kubernetes Secret reads per key operation without adding an indefinite cache; provider/API aggregate burst performance is still unqualified. Additive rotation is implemented, but historical-key removal is refused until a retirement operation checks retained-data and recovery obligations.

Next: protected acquisition/key-service peer issuance and runtime bootstrap, followed by the remaining purpose-specific authorities and small-profile installation. Source enrollment/admission, encrypted key-administration audit, automatic process replacement, safe retirement and backup/restore/lost-key handling remain pending. No runtime/chart collection was enabled; the complete UI/MCP/native-download investigation platform remains unfinished.

## Previous download key authority checkpoint

[ADR-066](decisions/066-download-key-authority.md) and [download key authority](architecture/download-key-authority.md) now bind local unwrap to a concrete audited/prepaid SQL download batch, configured artifact key and exact acquisition certificate. Migration 00022 separates coordinator insertion from key-service consumption; three irreversible slots cover data/index/manifest keys. Current parent generation, audit, permission, retained privacy, published artifact/version and recovery are checked after locks. The acquisition reader uses a batch-bound mTLS opener and the existing S3/native decoder. No extra approval, root key in acquisition, provider fallback, public endpoint or chart runtime was added.

The initial reader is the existing complete 4096-byte pod-status slice. The shared canonical key-binding helper preserves all three historical framed/v1 AAD byte strings in a golden regression. Large-file readers must retain a bounded authorized decoder across output batches; this continuation does not introduce per-frame key-service calls or claim to implement arbitrary raw/share downloads.

Verification for this continuation, using build TMPDIR `/home/phil/.cache/asservat-build/tmp` and Make PYTHON `/tmp/asservat-openapi-validation/bin/python`:

- Owned targeted SQL/S3/TLS tests returned 0 in [download-key-targeted-check.log](../test/results/download-key-targeted-check.log), 9.046 seconds: wrong peer/artifact, absent audit, cancellation, permission/recovery changes, expiry after a blocking lock, binding replay and eight-way slot contention. A 352-byte encrypted context was recovered from real S3 through the actual TLS handler and SQL resolver, with native checksum equality and three unwrap slots each for preparation/content. [Log](../test/results/download-key-targeted-custody.log) and [environment](../test/results/download-key-targeted-custody-environment.json) record unchanged tested source and complete cleanup. Collection/identity/configuration inputs and peer issuance remain fixtures; the key authorizer itself is the real SQL implementation.
- Initial Go/vet/race/import/sqlc gates returned 0. Full custody subsequently exposed two fixture mistakes: the new test attempted retention mutation without its mandatory lifecycle decision, and an existing expired-source test evaluated `clock_timestamp()` twice, making a nominal five-second interval one microsecond too long. The [failed suite](../test/results/download-key-first-full-custody.log) and [environment](../test/results/download-key-first-full-custody-environment.json) are retained. The tests now use the actual retention-tightening transaction and one exact timestamp respectively; no product guard was loosened. Both corrected cases returned 0 in [targeted check](../test/results/download-key-fixture-fixes-check.log), with [unchanged source/complete cleanup](../test/results/download-key-fixture-fixes-custody-environment.json).
- `make go-check go-architecture-check sql-check spec-check architecture-check design-check` returned 0 in [final repository gates](../test/results/download-key-final-gates.log): vet/race checks, 38 packages/167 allowed edges, 15 matching sqlc files, 53 schemas/165 examples/380 rejected cases and existing architecture/UI mappings.
- `make custody-integration` returned 0 in [final full check](../test/results/download-key-final-custody-check.log), 68.826 seconds: [suite log](../test/results/download-key-final-custody.log). Retention shortening and failed crypto retaining its paid slot now pass alongside the complete existing custody/permission/peer/policy suite. The [environment report](../test/results/download-key-final-custody-environment.json) confirms unchanged tested sources and complete cleanup. The final `make context-integration` also returned 0 in [context check](../test/results/download-key-final-context-check.log), 24.990 seconds: real Kubernetes/OpenBao/S3/PostgreSQL context and native-file regression under migration 22. Its [log](../test/results/download-key-final-context-storage.log) and [environment](../test/results/download-key-final-context-storage-environment.json) confirm unchanged tested sources and complete cleanup of both owned clusters. This suite exercises the existing external-provider context path; the local SQL/TLS/S3 reader was qualified in the full custody run above.

Next: protected acquisition-peer issuance/control mediation and key-source/issuer/Secret lifecycle, then remaining purpose-specific key authorities and runnable local-provider composition. The current local service still lacks installation/bootstrap; the public browser/MCP investigation and other collection mechanisms remain unfinished. Earlier checkpoints follow.

## Previous private key-service checkpoint

[ADR-065](decisions/065-local-key-service-boundary.md) adds the [private local key boundary](architecture/local-key-service.md): I-14/A-KEY, TLS 1.3 peer verification, separate remote wrapping/unwrapping/signing facets, a bounded HTTP handler and C-03 current-operation coordination. Client identity/role is only a negative guard; a mandatory resolver must bind the exact request and peer to current accepted authority for at most five seconds. The coordinator checks deadlines after blocking resolution and crypto, and the transport bounds delivery. Production authority resolvers, protected key/issuer lifecycle and runnable service/bootstrap are still missing. No chart runtime, new dependency, SQL migration or public collection was enabled.

Actual TLS fixture tests compose the new clients, server and real local crypto with **test-only** exact authority mappings. They pass role/purpose separation, revocation and certificate expiry on reused connections, signing with a pinned public key, bounded concurrency, request/response substitution and no redirect/replay. An irrelevant explicit `sealed` object was accepted by both a wrap handler and unwrap response reader before the shape fix: [failing regression](../test/results/key-service-irrelevant-before.log), [passing targeted suite](../test/results/key-service-tls-final-targeted.log). The fixture does not establish current SQL authority or Secret/certificate lifecycle behavior.

The maintainer asked whether concurrent cores would send their payloads through OpenBao. The existing storage implementation already uses envelope encryption: three bounded keysets are wrapped before acquiring each artifact, and all payload encryption/upload is local. Added `TestArtifactKeyCallsIndependentOfPayloadSize` verifies three wraps and three unwraps for empty, 4096-byte and 16,777,295-byte synthetic artifacts, with no further calls during full/range reads. The largest serialized keyset was 131 bytes; the enforced bound is 4096 bytes. [REQ-EVD-001](../specs/evidence.md), [artifact format](architecture/artifact-format.md) and REQ-CAP-003 now explicitly distinguish this fixed storage-key work from aggregate authentication/audit/attempt load. Provider burst capacity remains unqualified.

Verification for this continuation (build TMPDIR `/home/phil/.cache/asservat-build/tmp`, Make PYTHON `/tmp/asservat-openapi-validation/bin/python`):

- Targeted `go test -race` across authorization, TLS integration and framed-codec tests returned 0 in [key-service-tls-final-targeted.log](../test/results/key-service-tls-final-targeted.log).
- `make go-check go-architecture-check spec-check architecture-check design-check` returned 0 in [key-service-final-gates.log](../test/results/key-service-final-gates.log): vet/race checks, 38 packages/164 allowed import edges, 53 schemas/165 examples/380 rejected invalid cases, 11 application roles/14 interfaces and existing UI/API mappings. First-run vet rejected four unkeyed literals; these were corrected. The second run exposed a schema regex accepting trailing newline in base64; the schema now rejects it, as the strict runtime decoder already did. Both failed logs are retained as `key-service-first-gates.log` and `key-service-second-gates.log`.
- `make context-integration` returned 0 in [key-service-final-context-check.log](../test/results/key-service-final-context-check.log). The actual S3/OpenBao/PostgreSQL/two-cluster Kubernetes suite, including the standalone real-TLS key-service fixtures, passed in 24.189 seconds: [component log](../test/results/key-service-final-context-storage.log). The [environment report](../test/results/key-service-final-context-storage-environment.json) confirms unchanged tested Go sources and no cleanup failures; both owned clusters were removed. Local key-service authority remains synthetic and its TLS fixtures are separate from the real S3/context path. These results do not qualify production authority, key-service restart/restore or aggregated provider load.

Next: implement current operation authority and protected Secret/issuer/bootstrap/recovery lifecycle for A-KEY, retaining stale-process fencing and exact existing operation deadlines, then continue local identity and bundled-service work alongside S-01/S-02 public workflow composition. Key-service TLS components are not a completed small-deployment profile.

## Previous local-key foundation checkpoint

The maintainer accepted implementation of the [small-deployment recommendations](research/small-deployments.md). [ADR-064](decisions/064-local-key-material.md) and the [local key foundation](architecture/local-keys.md) add bounded, purpose/installation/version-bound wrapping and pinned Ed25519 signing backends using existing cryptographic dependencies. The private Secret payload has a closed schema and strict runtime loader. Browser credential encryption now consumes the existing provider ports; artifact framing, native files and credential envelopes remain unchanged. These components hold root/private keys and are intended only for an isolated key-service process; no production role is wired to them yet.

Unit/race tests pass for malformed material, rotation, binding/version/purpose substitution, tampering, cancellation/concurrency and real-codec native files/ranges. Tests reload serialized material; they do not simulate process disaster recovery. A typed-nil signing option also reproduced a panic in the existing OpenBao signer (`local-keys-signing-before.log`); the shared validation fix passes (`local-keys-after.log`). The provider-port conversion then exposed nil/uninitialized OpenBao instances panicking (`local-keys-unconfigured-before.log`); both facets now reject invalid configuration before accessing their client. No runtime/chart switch, new dependency or SQL migration was introduced.

Verification for this continuation (all build commands used `TMPDIR=/home/phil/.cache/asservat-build/tmp` and Make checks used `PYTHON=/tmp/asservat-openapi-validation/bin/python`):

- `make go-check go-architecture-check spec-check architecture-check design-check` returned 0 after both fixes: [final gate log](../test/results/local-keys-final-gates.log). Vet/race tests pass; 37 packages/157 allowed import edges, 52 schemas/165 examples/359 rejected cases and all architecture/UI mappings validate.
- `go test ./internal/adapters/kms -run '^$' -fuzz '^FuzzLocalKeySecret$' -fuzztime=15s -parallel=2` returned 0: [fuzz log](../test/results/local-keys-fuzz.log), 141,369 executions. This bounded fuzz run covered the unchanged local Secret loader, not the subsequent OpenBao nil-instance guards.
- `make identity-integration` returned 0 after the final guards: actual Keycloak/PostgreSQL/OpenBao browser/signing regression passed in 4.294 seconds. The [provider log](../test/results/local-keys-final-identity-provider.log) and [environment report](../test/results/local-keys-final-identity-provider-environment.json) record unchanged sources and complete cleanup. The earlier successful pre-guard run is retained separately as `local-keys-first-identity-provider*`.
- `make context-integration` returned 0: actual S3/Kubernetes/OpenBao/PostgreSQL components passed in 23.749 seconds. The new local-key/S3 test recovered the encrypted manifest and an exact 8,389,341-byte native file/hash plus a cross-frame range; existing context/PKI paths also passed. See [context log](../test/results/local-keys-final-context-storage.log) and [environment report](../test/results/local-keys-final-context-storage-environment.json): unchanged sources, both owned clusters removed and empty cleanup failures. Local root-key operations are in-process test fixtures and S3 uses the harness TLS bridge; this does not qualify local key-service authentication, production S3 TLS/IAM or Helm restart/backup behavior.

Next small-profile work: authenticated purpose-scoped remote key facets, current operation authority, protected Secret/bootstrap/recovery lifecycle, PKI/local enrollment delivery, then local accounts/OAuth and bundled PostgreSQL/pgBackRest/SeaweedFS packaging with operational qualification. [REQ-DEP-001–005](../specs/deployment-profiles.md) remain incomplete. The official Helm chart remains configuration-only; S-01/S-02 public authorization/custody composition and the developer workflow remain unfinished.

## Small-deployment research checkpoint

The initial small-deployment research established [ADR-063](decisions/063-small-deployment-alternatives.md), REQ-DEP-001–005 and candidate qualifications. That documentation-only checkpoint introduced no runtime/provider implementation; the local key continuation above is subsequent work.

Documentation verification: `make spec-check architecture-check design-check PYTHON=/tmp/asservat-openapi-validation/bin/python` returned 0; [gate log](../test/results/small-deployment-design-check.log) records 176 requirements/scenarios, 51 schemas, 165 examples, all requirement owners and existing UI/API mappings passing. These are static design checks, not deployment or local-provider tests. No runtime suite was rerun for this documentation-only change.

## Previous implementation continuation

The submission continuation implements [ADR-062](decisions/062-policy-submission-signatures.md) and [private policy provenance](architecture/policy-submissions.md). Authenticated human submissions bind persisted policy identity/spec, independently compiled scope, installation/recovery epoch, original nonce and finite deadlines in a canonical purpose-specific JWS. Existing JWX supplies framing; a dedicated nonexportable OpenBao Ed25519 key supplies signing through `crypto.Signer`, with explicit version/public-key pins and sign-only credentials. A pinned Kubernetes ConfigMap supplies strictly validated current public trust. `SignedPolicyAcceptor` carries the original verification deadline into SQL; a new acceptance must still match after blocking locks. Verification refresh does not change idempotency, extend authority or grant collection. No new dependency or migration was added.

The subsequent browser handoff review reproduced two defects: the returned identity could outlive its browser session, and the login callback returned an identity without checking expiry after session creation (`browser-handoff-before.log`). Current SQL creation/reads now return a transient observation carrying the original protected-settings deadline; CSRF-only reads do not. Callback/final resolution intersect token/policy, session and settings deadlines and recheck cancellation and exact session identity. The new unit/race regressions pass (`browser-handoff-after.log`). This does not add a stored lease or change the administrator's session lifetime.

Verification so far for this continuation:

- `TMPDIR=/home/phil/.cache/asservat-build/tmp make go-check go-architecture-check sql-check spec-check architecture-check design-check openapi-check PYTHON=/tmp/asservat-openapi-validation/bin/python` returned 0 (`submission-handoff-final-gates.log`): vet/race tests, 37 packages/157 permitted import edges, 14 matching sqlc files, 51 schemas/165 examples/344 invalid cases, and both API contracts.
- Before the browser handoff fix, actual Keycloak/OpenBao submission signing passed with a real current browser identity, sign-only ACL, explicit version rotation, retirement and current-key revocation (`submission-final-identity-provider.log`). Actual SQL/S3 passed in 59.662 seconds, including signed acceptance/replay and submission/trust expiry during lock waits (`submission-final-custody.log`). Actual Kubernetes observation/admission passed, with the admission/retention phase taking 52.153 seconds (`submission-final-permission-admission.log`), including named public-key reader access, key removal and same-name source replacement. The corresponding three named environment reports confirm unchanged tested sources and empty cleanup failures.
- Failed provider fixture runs are retained as `submission-first/second/third-identity-provider*`: the pinned OpenBao version returns HTTP 200, rather than the fixture's original 204 expectation, for key creation, rotation and configuration. The first SQL failure is retained as `submission-first-custody*`: the fixture needed a matching proof after changing the nonce and microsecond-compatible synthetic trust timestamps. Neither fix relaxed product validation. The browser handoff regressions separately failed before their product fixes.
- The combined provider/SQL/Kubernetes run including browser handoff returned 0 (`submission-handoff-final-integration-check.log`). Actual Keycloak/OpenBao passed in 4.565 seconds and SQL/S3 in 59.751 seconds; the named `submission-handoff-final-*-environment.json` reports confirm unchanged tested sources and empty cleanup failures. The Kubernetes observation and admission/retention phases passed in 15.538 and 50.464 seconds respectively.

A follow-up regression reproduced unreachable sessions consuming quota after a failed callback, including cancellation and unknown creation outcomes (`browser-callback-cleanup-before.log`). The service now makes one bounded independent attempt to revoke only its newly generated ID, preserving the original error and finite expiry if cleanup is unavailable. Successful callbacks remain active. The same complete Go/import/SQL/spec/architecture/design/OpenAPI gates returned 0 after this fix (`submission-complete-gates.log`), including the new regressions. The affected real Keycloak/PostgreSQL/OpenBao suite also returned 0 (`submission-complete-provider-check.log`, `submission-complete-identity-provider.log`), with unchanged sources and no cleanup failures in its named environment report. Cancellation/unknown-commit injection is a unit regression; ordinary provider/SQL operation is the real-service qualification. The earlier completed custody/Kubernetes evidence remains separately scoped; those unchanged adapter paths were not rerun for the callback-only cleanup.

Remaining work includes complete policy compilation and Kubernetes/GitOps admission provenance, protected source/key/bootstrap/restore supervision, atomic grant/quota execution, and public React/MCP/capture/native-download composition. The signature profile currently supports human policy submissions only; test source/compiler/bootstrap inputs remain synthetic where no producer exists. S-01/S-02/TASK-07 remain unchecked. Continue toward the end-to-end context investigation rather than treating these component results as a completed platform. Earlier checkpoints follow.

The policy-source continuation adds a bounded Kubernetes DebugPolicy reader and the current-source observer feeding the existing SQL journal. It pins cluster/namespace/resource identities, validates the complete authored spec with 15 offline schema resources, supports fractional resource thresholds, ignores CRD status as authority and preserves separate authored/collection-intent digests. Pause/control edits remain separate from collection changes. The existing SQL intent version still advances on missed generations and change-and-revert; deleting objects create permanent UID tombstones. This does not resolve execution dependencies, authenticate submissions or issue a permit.

`make go-check go-architecture-check sql-check spec-check architecture-check design-check openapi-check` with the TMPDIR/PYTHON below returned 0 (`policy-source-gates.log`). `make permission-integration` returned 0 (`policy-source-permission-check.log`); the admission/retention phase completed in 49.996 seconds after the separate observation phase. `policy-source-permission-kubernetes-environment.json` reports unchanged sources and no cleanup failures. Its input hashes now also cover the canonical policy bundle and JSON/YAML examples. The new real Kubernetes → separately credentialed SQL test passes named read-only RBAC, pause/resume, collection changes, skipped generations, deletion tombstones and same-name replacement. Its permissive DebugPolicy CRD is an explicitly test-only fixture; the product chart has not gained an unqualified policy CRD or enabled collection.

Protected browser settings now connect a pinned, strictly decoded Kubernetes ConfigMap to a separately credentialed PostgreSQL projection under [ADR-061](decisions/061-current-browser-configuration.md). Migration 00021 retires unqualified roots and adds finite source leases and never-reused session epochs. Runtime issuer/client/origin binding, rollback/replacement rejection, irrevocable shortening of existing session lifetimes and local/provider logout during settings outages are implemented. The settings reader cannot alter its Kubernetes input; its SQL role cannot read/write credential ciphertext or create a login/session. Production source/bootstrap protection, restoration qualification and public execution remain separate unfinished work.

Verification of the browser settings continuation:

- `TMPDIR=/home/phil/.cache/asservat-build/tmp make go-check go-architecture-check sql-check spec-check architecture-check design-check openapi-check PYTHON=/tmp/asservat-openapi-validation/bin/python` returned 0 (`browser-settings-final-gates.log`): race/vet tests, 37 packages/153 import edges, 14 matching sqlc files, 50 schemas/164 examples/344 invalid cases, 49 domain entities and the business/authentication API contracts.
- `make identity-integration custody-integration permission-integration` with the same TMPDIR/PYTHON returned 0 (`browser-settings-final-integration-check.log`). The final real Keycloak/PostgreSQL/OpenBao suite passed in 4.251 seconds, full custody SQL/S3 suite in 59.089 seconds, and permission/admission/retention suite in 47.773 seconds after the separate observation phase. `browser-settings-final-identity-provider-environment.json`, `browser-settings-final-custody-environment.json` and `browser-settings-final-permission-kubernetes-environment.json` all report unchanged tested sources and no cleanup failures.
- Added regressions cover unqualified boolean roots, legacy challenge revocation, runtime binding mismatch, private role limits, shorter-then-longer maximum lifetime, source rollback/replacement and same-revision mutation, stale failure versus newer success, settings expiry during a SQL lock, outage sign-out, pause and epoch reuse. The real Kubernetes test composes named RBAC reads, the observer and SQL; changing suspension blocks callbacks and a same-name replacement fences the previous projection.

Next: complete authenticated submission/signature/compiler and protected runtime composition, including policy discovery/watch supervision, then independent approval/admission and the developer's actual React/MCP/capture/native-download flow. The overall S-01/S-02/TASK-07 scope is still unfinished; these checks do not enable a production collector. Earlier checkpoints follow.

The browser-session continuation now composes real Keycloak code/PKCE/nonce login, current identity resolution, encrypted PostgreSQL credentials through OpenBao/Tink, authenticated HTTP session/CSRF endpoints, coordinated refresh, local logout and verified provider back-channel logout. Migration 00020 adds one-use login records, fixed session deadlines, non-reusable refresh claims and replay-safe logout receipts. A separate cleanup role and bounded application loop remove expired credentials without creating or renewing sessions. [ADR-060](decisions/060-bounded-browser-sessions.md), [architecture](architecture/browser-sessions.md), [authentication protocol](interfaces/browser-auth-openapi.yaml) and the domain catalog describe these contracts.

Verification for this continuation:

- `TMPDIR=/home/phil/.cache/asservat-build/tmp make go-check go-architecture-check sql-check spec-check architecture-check design-check openapi-check PYTHON=/tmp/asservat-openapi-validation/bin/python` returned 0 (`browser-final-gates.log`): vet/race tests, 37 packages/153 permitted import edges, 13 matching sqlc files, 49 schemas/163 examples/344 invalid cases, 49 mapped domain entities and both business/authentication OpenAPI contracts.
- `make identity-integration` with the same TMPDIR/PYTHON returned 0 (`browser-final-integration-check.log`); the actual combined suite took 3.890 seconds (`browser-final-provider.log`). Tests include eight concurrent refresh callers with one rotation, one-use callback races, wrong-browser binding, removed group membership, encrypted-state corruption, local and real Keycloak logout during a claimed refresh, expiry after a held SQL lock, epoch changes, capacity limits and separate cleanup credentials with 256/44-row progress. `browser-final-environment.json` confirms unchanged tested sources, verified loopback-only provider binding and empty cleanup failures.
- `make custody-integration` returned 0 (`browser-final-custody-check.log`); the complete prior SQL/S3 integration suite took 59.485 seconds (`browser-final-custody.log`). `browser-final-custody-environment.json` confirms unchanged tested sources and empty cleanup failures after migration 00020.

The new negative token tests first reproduced logout `nbf` and token-purpose confusion (`browser-token-negative-before.log`), then passed after explicit checks. Current OIDC logout expiration is also mandatory. The first real callback delivery attempt timed out from the bridged provider (`browser-backchannel-first-provider.log`); the fixture now uses capability-dropped Keycloak on an explicitly verified loopback listener. An intermediate listener assertion rejected Java's IPv4-mapped spelling (`browser-loopback-first-environment.json`); normalization retains the exact loopback/port check. These failed runs are preserved separately. No workstation firewall, unrelated service or cluster was changed.

The complete platform is still unfinished. This continuation qualifies the browser/identity/session components with synthetic protected configuration; it does not qualify production bootstrap or create collection/disclosure authority. Next: protected session/root and policy-source/signature/compiler composition, step-up and independent-review/grant/quota transactions, then the actual React/MCP/native-download capture workflow and remaining S-03–S-09 mechanisms. Public runtime/collectors remain disabled and TASK-07/S-01/S-02 remain unchecked. Earlier records below describe the preceding checkpoints.

The maintainer accepted [ADR-059](decisions/059-unattended-policy-authority.md): team policies continue after creator departure under bounded independent authorization; human access uses standard OIDC sessions. The [normative contract](../specs/policy-automation.md), resolved scopes/grants, UI/MCP summaries and [configuration/eligibility components](architecture/policy-automation.md) now implement the foundation. Ordinary permission writers cannot administer automation envelopes. The persistence continuation below adds initial durable policy acceptance and current SQL automation projections. Protected signed-submission/source/compiler production, atomic grant/quota admission, browser sessions and public activation remain unfinished; no directory/offline credential code is enabled.

Migration 00019 now persists independently audited automation envelopes, finite policy-source observations, immutable scope acceptance, consumed nonces and encrypted acceptance receipts. Separate SQL source/accept/audit/read credentials enforce the component boundaries. The accepted-policy/current-delegation readers now back the private automation evaluator. Current team editors are separate from the immutable original creator; pause/resume and harmless control edits preserve authority, expiry and budgets. Collection-intent changes, deletion, generation gaps, changed sponsorship, stale observations and recovery-epoch changes prevent eligibility. No token, personal group-membership snapshot or directory credential is stored.

The initial regressions reproduced a dropped automation envelope and incorrect coupling between current delegation digest and a historical audience-assignment digest (`policy-persistence-before.log`). They now pass. The first real SQL run also exposed timestamp-location inequality on an otherwise identical observation; explicit UTC normalization fixes it. A dedicated missed-generation test reproduced A → B → A revival (`policy-generation-gap-before.log`), now prevented by the monotonic intent version. An intermediate SQL run caught PostgreSQL parameter-type ambiguity in that condition; the query now casts the generation explicitly. Failed runs are preserved separately, not reported as passes.

Verification for this continuation:

- `TMPDIR=/home/phil/.cache/asservat-build/tmp make go-check go-architecture-check sql-check spec-check architecture-check design-check PYTHON=/tmp/asservat-openapi-validation/bin/python` returned 0 (`policy-persistence-final-gates.log`): vet/race tests, 37 packages/148 permitted import edges, 12 matching sqlc files, 49 schemas/163 examples/344 rejected invalid cases, architecture and design checks.
- `make custody-integration` with the same TMPDIR/PYTHON returned 0; the full real PostgreSQL/S3 suite took 59.217 seconds (`policy-persistence-final-custody.log`). All 17 policy cases pass: encrypted audit gating/immutability, concurrent nonce replay, creator departure, historical assignment continuity, independent envelope audit, pause/resume, missed generations, later team editors, deletion/expiry/recovery, tampering, denied authors, revocation, expiry during lock wait and role separation. `policy-persistence-final-custody-environment.json` confirms unchanged tested sources and empty cleanup failures.
- `make permission-integration` with the same environment returned 0 (`policy-persistence-permission-check.log`). The real Kubernetes → protected reader/journal → SQL → encrypted audit → current automation projection runs within the guarded reconciliation test, while the original ordinary-delegate continuity tests remain intact. The admission/local-start/retention suite took 47.393 seconds. `policy-persistence-permission-environment.json` confirms unchanged tested sources and empty cleanup failures.

These are component integrations with synthetic authenticated policy/compiler/KMS inputs. They do not qualify a production signed submission, browser session, cumulative policy spend, privileged collector or public workflow. The next task is protected policy-source/signature/compiler and standard human-session composition, followed by exact grant/independent-review and atomic execution fences. Source freshness and accepted limits must never be substituted for those remaining permits. TASK-07 and S-01/S-02 remain unchecked. See [team automation architecture](architecture/policy-automation.md) for the changed contracts and remaining limits.

The bounded automation-binding reader regression failed before implementation (`automation-binding-before.log`) and now passes. `make go-check go-architecture-check spec-check architecture-check design-check helm-check` returned 0 in `team-automation-final-gates.log`; the synthetic browser run returned 0 with 662 checks and no reported accessibility violations or external requests (`team-automation-ui.log`). Shared contracts now cover 49 schemas, 163 examples and 344 invalid cases. The policy review [preview](../design/ui/previews/team-policy-review.png) shows team authority, original creator separation, expiry and cumulative limits. These are component/prototype checks, not a production session or recurring-execution test.

Real Kubernetes automation admission passed in all four runs, including administrator creation, schema rejection and ordinary delegate create/update/delete denial. The first full fixture failed its separate retention steady-availability check 133 ms after the original five-second observation deadline (`team-automation-first-permission-admission.log`); expiry correctly blocked use. Added bounded failure-only watch/LIST timing diagnostics. Two subsequent complete fixture runs passed (30.826 and 30.953 seconds for admission; `team-automation-diagnostic-*` and `team-automation-repeat-*`), with unchanged tested sources and empty cleanup failures. Those reruns alone did not establish a fix.

The follow-up regression reproduced a concrete scheduling defect: a 120 ms guard-call timing shift made the fixed ticker skip a complete refresh cycle, yielding a 1.88-second observation interval (`retention-renewal-jitter-before.log`). Scheduling now follows the actual observation time and rejects clock rollback. Original freshness, rate and watch-history requirements are unchanged. The configuration race suite and full Go/import gates pass (`retention-renewal-jitter-after.log`, `team-automation-renewal-gates.log`). The strengthened real Kubernetes fixture, including 30 seconds of continuous unrelated writes and retention lease renewal, passed with exit 0 in 49.388 seconds (`team-automation-final-permission-admission.log`); tested sources remained unchanged and cleanup was complete. This fixes the reproduced skipped-cycle defect, not every possible Kubernetes bookmark-delay condition. Production watch-latency and failure qualification remain required.

The updated Helm CRD passes actual installation, upgrade, rollback and uninstall in hub/cluster/combined modes (`team-automation-helm-integration.log`, `team-automation-helm-environment.json`; Helm 4.3.0, Kubernetes 1.37.0, unchanged sources and clean teardown). The chart remains a configuration foundation. At that checkpoint policy-acceptance/current-delegation adapters were next; migration 00019 above now adds those private facets. Protected input production, atomic runtime checks, standard human sessions and the public developer workflow remain; do not mark TASK-07 or an end-to-end slice complete from these results.

Final `make spec-check architecture-check design-check` passed (`team-automation-contract-final.log`). `make openapi-check live-check download-check investigation-check` also returned 0 (`team-automation-interface-gates.log`): locally bundled OpenAPI validation, 45 live checks and the paired native-download/investigation DTO scenarios. These interface checks do not perform production token refresh, recurring capture or native transfer. The owned preview server was stopped after browser verification.

The Keycloak provider fixture also passes nested/ancestor stable-ID membership, deduplication, slash-containing names and removal (`identity-hierarchy.log`, 2.904 seconds; source-stable, clean teardown). The context recovery continuation passed all repository gates in `context-recovery-gates.log`.

Capture admission, context verification and catalog publication now share the [current recovery transaction fence](architecture/download-recovery.md#capture-and-publication-continuation). The new real-service regression first reproduced three missing checks, then passed after fixing them (`context-recovery-before-custody.log` / `context-recovery-after-custody.log`, both source-stable and fully cleaned). Downloads use that same installation identity. Public workflow, protected activation and regional transfer composition remain pending.

The maintainer selected Helm as the official installation method and Keycloak as the first supported/tested browser/MCP identity provider. The initial chart passes offline schema/render/package checks and the owned Kubernetes installation/upgrade/rollback/uninstall fixture (`helm-integration.log`, Helm 4.3.0, Kubernetes 1.37.0; unchanged source and complete cleanup). The fixture includes a changed schema/chart version, rejection of an invalid upgrade without changing the release revision, preserved CRDs/custom-resource UIDs and an unchanged workload namespace. The first runs exposed a generated empty `required` array that Kubernetes omits; normalization fixed same-schema ownership conflicts without changing validation. The documented first install establishes one explicit CRD field manager so subsequent changed schemas require no forced ownership. It installs configuration foundations only; runtime deployment templates will follow usable role composition. See [installation scope](installation/helm.md).

[Download recovery fencing](architecture/download-recovery.md) now passes actual SQL/S3/native HTTPS regression (55.855 seconds; unchanged source and complete cleanup). Blocking recovery, changing issuer epoch/configuration or expiring trust prevents further output from prepaid sessions without refunding uncertain spend. Protected activation and regional acceptance remain pending.

The [current context-download authorizer](architecture/download-authority.md) now combines ordinary rights, original audience, verified catalog and retained policy obligations, then rechecks identity/denies after I/O. Unit/race tests pass. The real SQL/S3/native-HTTPS suite passed with this composition (`download-authority-integration.log`, 52.904 seconds; unchanged source and complete cleanup), and the repository gates passed in `download-authority-gates.log`. Regional/recovery inputs remain synthetic until their production producers are implemented.

The [final retention effect checks](architecture/retention-effects.md) now carry complete accepted source versions into collection/publication/download transactions. The strengthened real SQL/S3 regression passed (51.789 seconds) in `retention-effect-second-integration.log`, with unchanged source and complete cleanup. Go/race/import/SQL/spec/architecture/design gates also passed in `retention-effect-gates.log`. The first run caught a fixture timestamp preceding its newly read policy observation; that fixture has been corrected without changing the freshness rule. No public authority or slice completion is implied.

A later sustained run exposed a remaining single-waiter timing gap (`retention-topology-initial-*`): the first pending LIST could approach expiry before a bookmark arrived. The follower now keeps at most five original observations, confirms the freshest covered watermark, and separately preserves the floor from accepted/known-changing lists. Unit/race tests pass in `retention-observation-window-unit.log`. The final real Kubernetes run passed (33.215 seconds), including 15 seconds of availability under unrelated API writes, topology immutability and same-name replacement rejection. `retention-observation-window-permission-kubernetes-environment.json` records unchanged source and empty cleanup failures. SQL/S3 regression also passed (46.883 seconds), archived as `retention-observation-window-custody.log` and its environment report. Go/race/import/sqlc/spec/architecture/design gates pass in `retention-topology-gates.log`.

Migration 18 implements finite complete-source observations and derived readiness, including the same-resource LIST/watch watermark, completed catch-up and both audit streams. The sustained Kubernetes regression reproduced intermittent availability and now passes after separating known policy changes from unconfirmed version progress. Seven seconds of unchanged policies under unrelated API writes remained available without extending any original observation deadline. The real admission suite returned 0 in `retention-ready-steady-after.log` (21.485 seconds); its named environment report records unchanged source and empty cleanup failures. The preceding failed regression is retained under `retention-ready-steady-before-*`. Go/race/import/sqlc/spec/architecture/design gates pass in `retention-ready-gates.log`. Final SQL/S3 regression passed with exit 0 (46.747 seconds) in `retention-ready-integration-check.log`, with unchanged source and complete cleanup; production topology/selector and operation authority composition remain the next work. See [ADR-056](decisions/056-retention-watch-watermark.md).

Migration 17 now applies ordered retained policy obligations in bounded atomic SQL pages. The real eight-worker test passes: three contexts across three checkpoints yielded nine visits, three shortening decisions and three completed jobs; later relaxation did not revive evidence. Bookmarks persist their resume cursor without scheduling another scan. See [catch-up scope](architecture/retention-catchup.md), `retention-catchup-unit.log` and `retention-catchup-integration-check.log` (exit 0; 45.860 seconds; unchanged source and complete cleanup). Newly encountered historical selectors remain unavailable. The subsequent migration-18 continuation adds the source-read barrier described above; accepted topology and public authority composition remain required.

The retention follower now composes the real guarded Kubernetes watch, protected initial-review ConfigMap, SQL checkpoints and encrypted S3 audit. Its real-provider test passed with unchanged tested sources and complete cleanup (`retention-reconciler-kubernetes-check.log`, admission Go run 13.510 seconds). Restart consumes the durable cursor after two policy edits without another initial review. That earlier run did not cover Ready promotion or retained-evidence catch-up; the subsequent continuations above add those component facets.

A reproduced cleanup-budget defect is fixed: a larger required budget is subtracted from the already-bound hard deadline, even if the new maximum is longer. Migration 16 supports a completely closed retained read interval without changing original registration. Unit/race and full SQL/S3 tests pass (`retention-budget-before.log`, `retention-budget-after.log`, `retention-budget-integration-check.log`; integration exit 0, 45.662 seconds).

The corrected retained-origin integration suite passed with exit 0 in `test/results/retention-origins-integration-check.log`; its environment report recorded unchanged source and no cleanup failures. The two preceding failures are retained under `retention-origins-failure-*`. PostgreSQL logs identified idle fixture pools exhausting the 48-connection server ceiling. Completed publication phases now release those connections; the eight-request races and server limit remain unchanged.

The next continuation adds [durable retention checkpoints](architecture/retention-checkpoints.md), protected initial-value review and separately encrypted acceptance audit under migration 15. Unit/race checks pass. The full SQL/S3 fixture passed with exit 0 (45.256 seconds), recorded in `test/results/retention-source-integration-check.log` and `test/results/custody.log`. Catch-up and Ready-source production were unimplemented at that checkpoint; migrations 17/18 above add those facets. No TASK or slice exit is completed by these components.

| Component | Implemented and checked | Still required before public use |
| --- | --- | --- |
| Identity and permission configuration | Strict access tokens, protected identity settings, native permission admission, bootstrap audit ordering, continuous explicit-binding reconciliation and full capture audience; real Kubernetes/SQL/S3 tests pass | Keycloak token/PKCE/refresh fixture now passes; operator realm acceptance, inherited-source acceptance and complete public session/client composition remain |
| Context planning and admission | Exact pod/owner/node identity, conservative retention intersection, canonical context scope, atomic custody/admission and encrypted intent audit; real two-cluster and SQL/S3 tests pass | Protected retention/capability readers, public submission coordinator and dispatch composition |
| Signed work and local start | Strict Ed25519 JWS, immutable prepaid start CRD, forward-only CAS, role guard, lost-response and real Kubernetes race tests pass | Current reference resolution, signed start ticket, node process exclusion and partition qualification |
| Peer identity | TLS client profile, protected signing trust, one-use claims, encrypted claim/certificate audit, bounded PKI attempts and atomic activation; combined OpenBao/TLS/SQL/S3 tests pass | Protected administration and credential-channel components now pass Kubernetes/OpenBao tests; renewal/revocation writers, node attestation, trust/recovery production and listeners remain |
| Evidence storage and downloads | Framed encryption, SQL custody, full context verification, audit-gated catalog publication and bounded native-download sessions; real SQL/S3/HTTPS component tests pass | Production current result/privacy gates, protected transfer-budget configuration, regional relay/public ingress, writer barrier and complete retention/deletion composition |

Active continuation: one-use enrollment and trusted execution, followed by verified catalog publication, download/cutoff/deletion and the actual UI/MCP developer workflow for S-01/S-02. Then complete remaining S-03–S-09 features, packaging and the qualified runtime matrix. No collector or public acquisition/disclosure path is enabled by these components. External participant/managed-provider qualifications remain unverified until actually performed.

## Existing verified baseline

Artifact/context codec, SQL custody, manifest verification, strict token identity, ordinary eligibility and Kubernetes permission observations are implemented components. Their individual records are under `docs/research/`; none by itself completes a slice. The latest permission input verification is `test/results/permission-verification.json`.

Use `/home/phil/.cache/asservat-build/tmp` for Go builds on this workstation. Own and clean up disposable test environments. Keep the public acquisition path unavailable until its authority, audit, custody, capacity and privacy requirements have passed together. Do not use test-only authorities in runtime composition.

Bootstrap issuance now passes real PostgreSQL/S3/OpenBao tests: separate reservation, credential-record, audit and activation roles; exact immutable receipts; current reauthorization after I/O; stable retry IDs/deadlines; and composed issuance-to-certificate TLS admission/revocation. See [the contract](architecture/bootstrap-issuance.md) and `test/results/bootstrap-issuance-integration-check.log`. Protected SQL trust observation/recovery and public ingress remain active work. No slice or TASK exit is implied.

Protected fleet observation also passes real SQL races/role tests in `test/results/fleet-observation-integration-check.log`. Missing roots and restart remain recovery-blocked; current settings never clear restoration, replace issuer epoch or extend source freshness. [Observation contract](architecture/fleet-observation.md).

Retention observation/matching and structural/native API admission are implemented with passing unit/race and real Kubernetes/RBAC/CEL tests; [contract and actual qualification status](architecture/retention-observation.md). Current source/metadata qualification, signed propagation and existing-evidence shortening remain separate prerequisites.

The [context executor and encrypted producer](architecture/context-execution.md) now pass race/concurrency and real Kubernetes/OpenBao/S3/SQL tests. Keys precede acquisition; current scope is rechecked after I/O; unknown/failed starts remain spent. The internal receiver binds collector process epoch. Current production reference resolution and outcome/catalog publication remain incomplete. Active continuation is reference-provider identity qualification and composition toward the developer workflow.

Keycloak 26.8.0 reference-provider qualification passed with actual TLS access tokens, PKCE, refresh/group updates, stable ID rename behavior and protected attributes. [ADR-053](decisions/053-keycloak-access-profile.md) adds an explicit provider profile; no IdP dependency or public route is enabled. `make identity-integration` returned 0 with unchanged source and empty cleanup failures. Public sessions, step-up and operator realm qualification remain pending.

Context publication now has a separate semantic-verification record, immutable encrypted audit and atomic catalog association under migration 00012. The first real SQL/S3 concurrency/role/failure suite passed; see [the contract](architecture/context-publication.md). A SELECT-only retained-audience reader now exists. Generic custody remains insufficient for visibility, and the mandatory external result/privacy gate and public native-download/session composition are still pending.

The regional [native context reader](architecture/context-native-read.md) passed exact-byte recovery after the acquisition window, plus cancellation/audience/retention-cutoff checks in both real workload clusters. `make context-integration` returned 0 with unchanged source and no cleanup failures. This remains an internal acquisition-role reader; session/budget/audit/HTTP and UI/MCP disclosure composition is active work.

Native-download preparation/resume contracts now omit unknown metadata, expose an opaque strong ETag and use standard If-Match/If-Range behavior under ADR-054. Design/range unit checks and the synthetic 662-check browser gate pass. Migration 00013 implements session reservation, batch spend, current SQL/catalog fencing and separate encrypted audit facets; its real-service fault tests passed in the subsequent continuation below. See [download sessions](architecture/download-sessions.md). Continue into composed regional transfer and the public workflow; no S-02/TASK exit is implied.

The corrected download ledger and composed context worker now pass real PostgreSQL/S3/HTTPS tests: immutable encrypted audit before output, native partial/full recovery, a checksum-verified synthetic local JSON file, per-principal/installation stream limits, conservative retry spend, cancellation/revocation and late-generation isolation. `test/results/download-composed-integration-check.log` returned 0 with unchanged source and no cleanup failures. Public authority/locality/restore composition, session presentation, relay and UI/MCP remain pending.

Download Go/race/import/sqlc/DTO/OpenAPI/spec/architecture/design gates pass in `test/results/download-composed-gates.log` (37 packages, 131 permitted import edges, eight generated SQL files). The HTTP sink shares pure artifact values with the acquisition service, preserving the existing transport dependency direction. Current work has moved to retention-source guard qualification, followed by current privacy and runtime authority composition.

Current retention-source guard qualification now passes real Kubernetes tests with pinned policy/binding identity, native enforcement, separate read/probe roles, dry-run nonpersistence and negative controls. `test/results/retention-guard-kubernetes-check.log` returned 0 with source unchanged and no cleanup failures. Source value acceptance, selector protection, complete topology and retained-evidence shortening remain in progress.

Existing-evidence [retention shortening](architecture/retention-lifecycle.md) now passes real SQL/S3 tests, including signed encrypted journal retries/key rotation, current transfer/finalization fences and overdue cleanup without refunds. Migration 00014 preserves immutable provenance and current Go/race/sqlc/spec/architecture/design gates pass. Current protected policy-source acceptance/topology and runtime composition remain the next work; these synthetic policy inputs confer no production authority.

The two-cluster lifecycle regression also passed. The next continuation adds original/later-applied policy reference tracking, complete accepted hub/local source composition and an ordered Kubernetes retention watch journal. Unit/race checks pass; source acceptance SQL/checkpoint/audit/catch-up production and selector-guard composition remain required. Current real Kubernetes and updated SQL regression results are pending their runs.

The retention watch/accepted-reader/origin-tracking Go/race/import/sqlc/spec/architecture/design gates pass. Real Kubernetes lower-then-raise, LIST/watch ordering and read-only roles pass in `test/results/retention-watch-kubernetes-check.log` with unchanged sources and no cleanup failures. Continue with durable C-01 source acceptance, audited checkpoint/catch-up state and protected selector/topology producers; the current journal acknowledgement in that fixture is synthetic.
