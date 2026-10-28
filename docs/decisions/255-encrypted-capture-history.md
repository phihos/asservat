# ADR-255 — Encrypted parameterized capture history

Date: 2026-10-27. Status: implementation in progress; qualification below.
Requirements: REQ-HIS-001–004, REQ-PRV-008; S-04 increment 5, S-06 increment 12.
Migration 00101 follows approved-recording funding (00100) and approved-plan acceptance (00099).

## Requirement and observed gap

The maintainer requires every specified feature in the first release, including
repeatable capture settings and bounded private history. Those outcomes and their
privacy/retention rules are maintainer requirements. The mechanisms below are
engineering choices under the complexity gate, not additional maintainer demands.

ADR-236 reconstructs pod-status settings from an accepted scope, always returns
the pod-status recipe, and cannot restore recorder filters or windows. Recorder
history must use an immutable encrypted parameter snapshot; incidental execution
scope JSON does not become a new history parameter store.

## Decision

Reuse the existing four-object framed codec, three wrap-only key preparations,
version-pinned ciphertext receipts, custody allocations, and verified inventory
purge. A separate typed HistoryExpectation binds the accepted capture, original
execution digest, keyed selector/settings identity and independent storage dates.
It is control data, never a ContextExpectation, public artifact or fake execution.
No parameter plaintext, native hash, reason, grant or recipient list enters SQL.

The hub already receives authored parameters. It uses its existing protected
control-key seal/open facets under history-specific AAD and media type; evidence
keys remain unavailable to the hub. Ciphertext crosses the existing authenticated
outbound connector connection in a separate bounded frame family. Common frames
retain their existing bounds. No hub-to-regional-store reachability is assumed.
The connector receives a metadata-prefix-only object capability; evidence write
credentials remain write-only and no key is delivered to the collector or node.

Summary visibility and settings readability are separate from durable execution,
audience, accounting and audit records. History quotas cannot roll back capture
admission. Settings become available only after four acknowledged, version-pinned
receipts bind the exact sealed input and its manifest commit. This is advisory
settings availability, never an evidence verification or publication verdict.
Before returning any plaintext or preparing a repeat, the reader verifies all
four objects, the authenticated manifest/commit and the keyed settings identity.
There are **zero eager verification GETs** on the write path. Unknown or incomplete
writes remain unavailable and charged; corrupt reads return unavailable without
reconstructing parameters from plaintext execution scope. Typed current signed
operation authority and independently established writer completion precede
physical cleanup; neither expiry, local Close nor a lookup refunds storage.

The existing immutable account-key projection supplies keyed selector/settings
identities, under distinct MAC domains. Ordinary audit-input key rotation does
not regroup history. A parameter snapshot preserves requested values, original
effective values, authored composition/edits, expanded recipe and dependency pins.
Repeat uses fresh eligibility, privacy, retention, budgets and any new approval;
old grants, sharing, reason and selected runtime members confer no authority.
Opaque repeat lineage has its own finite deadline and never grants source access.

## Complexity gate

| # | Benefit/cost | Answer |
|---|---|---|
| 1 | Observed harm | Every recorder repeat is currently unavailable; no production frequency claim. |
| 2 | Maintainer acceptance | History outcomes/privacy are required; this mechanism is an engineering choice. |
| 3 | Typical deployment | Yes: reuse of a manual filter/window is an ordinary investigation workflow. |
| 4 | Precedent | Reuses this repository's independently qualified immutable framed custody. |
| 5 | Added privileges | One prefix-only metadata storage capability per region; no evidence read/delete, new ingress, wrapping root or artifact unwrap. |
| 6 | Degraded states | SettingsUnavailable and HistoryUnavailable; reuse reserved/stored/deleting/deleted custody states. |
| 7 | Configuration | Required administrator-lowerable history ceilings; no self-tuning machinery knobs. |
| 8 | External dependency | Existing connector, S3 backend and KMS only; no new storage engine or component. |
| 9 | Aggregate cost | Three wraps and four PUTs per snapshot, zero eager verification GETs; four version-pinned GETs and three unwraps per settings read/repeat. Each preview still uses the existing current identity, workload, capability, permission, retention and capacity checks. Added SQL transactions reserve history quota/custody, claim a selected regional writer and settle its receipts; reads authorize before and after remote/KMS work. One supervised, joined cleanup loop per hub checks a small SQL candidate page every three seconds (0.33 idle SQL reads/s/replica, zero idle API/KMS/S3); it processes at most 16 records serially, drains successful full pages and paces failures. Retirement inventories object versions/uploads and deletes them before typed completion/refund. Work scales with captures, never packets/Pods. Combined installed workflow latency remains to be measured. |
| 10 | Upgrade/rollback | Additive schema; old pod-status history remains compatible. Stopping new history writes cannot abandon retained cleanup or charges. |
| 11 | Smaller alternative | Plaintext parameters, uncharged objects and durable audit retention violate the accepted contract. A single-object ledger would add a second lifecycle instead of reusing four receipts. |

Registration has no purpose-specific role bounds. At a 128 KiB parameter limit it
reserves **1,671,168 bytes (1.59375 MiB)** and four object slots: about 159 MiB
for 100 snapshots, 1.56 GiB for 1,000 and 155.6 GiB at the installation ceiling
of 100,000. These are conservative reservations, not physical measurements or
capacity promises; insufficient history capacity leaves collection functioning.
Do not change shared registration digests/retirement rules solely to shrink this
bounded over-reservation before a measured capacity problem exists.

## Qualification

Synthetic real-Tink component run `history-parameters-component-1.log` passed
round trips, exact ciphertext/manifest/expectation substitutions and bounded
bundle decoding. For 482 / 33,214 / 123,326 parameter bytes it measured 3,708 /
36,652 / 126,763 physical ciphertext bytes, and 4,961 / 48,885 / 169,037 encoded
bundle bytes. Each round trip used exactly three wraps and three unwraps; no
payload entered the key service. Key wrapping was an explicit test-only adapter,
so these are codec costs, not native provider or installed workflow measurements.

The history-specific role limits (192 KiB data, 4 KiB index, 128 KiB encrypted
manifest, 32 KiB commit) derive an exact **486,077-byte** JSON/base64 bundle bound:
13 JSON punctuation bytes plus `4 * sum(ceil(roleMaximum / 3))`. Both endpoints
enforce the total and each encoded role before allocating decoded ciphertext,
including exact four-object cardinality. The existing common 32 KiB frames are
unchanged. Only signed history operations use the separately derived finite
authority, bundle and escaped receipt envelope bounds.

The prior schema-100 history checkpoint’s focused real PostgreSQL/S3 run
`history-parameters-native-10` passed encrypted
write/read, own-selector eviction without premature refund, ordinary evidence
deletion-path refusal and actual history-prefix inventory before charge release.
It measured **4,214 physical ciphertext bytes** against **1,671,168 reserved
bytes** for its synthetic parameter record. The selected subtest took 7.67 s;
the Go fixture took 9.142 s, with unchanged relevant sources and no
cleanup failures. This is component evidence, not installed recorder performance.
Runs 9–10 additionally cover positive persisted lineage, source-expiry extension
and unknown-source refusal, nanosecond request-deadline normalization, required
encrypted snapshots with no scope fallback, and settled projection/counter
pruning. Runs 1–5 exposed fixture role/eligibility/time issues and a production
registration normalization mismatch; run 6 passed the initial custody slice.
Run 7 found a source-read fixture permission omission. Run 8 reproduced a real
ordering bug: per-selector eviction hid the chosen source before the new
snapshot's source check. Source authority now precedes eviction in the same
locked transaction, and its original expiry bounds the final check. All earlier
actual failure reports remain retained alongside runs 9–10.

## Composition and independent lifetimes

`public_context_compose.go` composes the existing protected account-key MAC and
control sealer/opener with the typed SQL history facet and regional dispatcher.
The dispatcher uses the existing outbound `contextstart.Router`, selecting the
actual executor epoch before SQL issues a writer claim. The regional adapter uses
its separately projected `history-storage.json` capability on the existing store
and bucket, restricted to `history/v1/<root>/<cluster>/`; it cannot access evidence
or another root/cluster prefix. No hub S3 address or evidence credential is added.
The provider recipe proposes the exact prefix policy; existing external provider
provisioning remains administrator-owned.

Metadata policy uses the existing explicit case-metadata defaults/maxima and
general privacy restrictions, independently of evidence lifetime. New history
never uses scope JSON as parameter storage. Source-derived repeats retain their
original content cutoff and policy origins; rereading or repeating cannot renew
that deadline. Lowered quotas hide oldest history only from the originating
allocation, with physical obligations retained until verified cleanup. Original
summary deadlines and unknown writer spend are never rewritten to meet a lower
limit. Expired, fully settled projections and unused zero counters are pruned in
bounded pages; durable execution/audit records remain independent.

A deterministic scheduling audit also found that always retrying the first 16
due records would starve another region behind a persistently unavailable one.
This is a reproduced algorithmic case, not a measured production outage. The
existing indexed capture-ID keyset and one process-local cursor now advance past
failed candidates, including partial passes stopped by the original budget, and
reset at the end. The hint grants no authority; every candidate still needs its
own current SQL authority and exact completion. No retry map, durable phase,
extra request, configuration or overlapping pass is added. Deterministic
two-region and partial-pass regressions verify both progress and retained spend.

The first 100,000-row real-SQL probe found two complete scans behind the bounded
16-row output: 64.47 ms for an idle hint and 62.82 ms with one due row. These are
synthetic minimal TEMP columns and warm local storage, not production CPU or row
width measurements. An indexed UNION of four separately bounded 16-ID branches
selects at most 64 IDs before deduplication and the unchanged 16-row keyset/order.
The fourth probe passed old/new equivalence for 81 IDs across six pages. Its
original predicate took 67.54 ms, the UNION without active indexes 10.65 ms, and
the custom plan with two partial active-state indexes 0.049 ms. The third probe
also exposed a real cached generic-plan regression: about 0.54 s after the fifth
execution despite a fast custom EXPLAIN. Only this read-only hint now uses pgx
CacheDescribe through a scoped DBTX wrapper around the generated query; pool
policy and all effect transactions remain unchanged. Ten repeated actual adapter
calls past that transition took 0.605–0.958 ms; EXPLAIN was 0.033 ms and the named
generic-plan counter did not advance. This sends about 3 KiB query text per
three-second idle request instead of retaining the demonstrated half-second scan.

Each new partial index occupied 90,112 bytes after 1,000-row churn; the existing
summary index occupied 6,144,000 bytes. For 1,000 minimal TEMP rows, history insert
time changed from 9.17 to 10.81 ms, available transitions from 10.90 to 11.86 ms,
and hiding from 9.20 to 11.04 ms. The unrelated custody insert measurement varied
from 4.57 to 108.29 ms; it is retained, not attributed to history indexes.
These local warm TEMP/no-WAL probes are neither production latency nor installed
aggregate cost. All four reports, including failures, are retained; run 4 had
actual exit 0, identical source hashes and no cleanup failures. No cadence,
authority check, durable state, privilege or configuration changes for this fix.

## Large browser settings

The shared MCP result contract remains 24 KiB (and the MCP socket writer 64 KiB).
Only authenticated browser `get_capture_settings` receives a private server-owned
160 KiB prepared-response budget and fixed client read cap. It uses the same
current authorization, existing public audit lane and original source deadlines.
Canonical JSON is written directly, so HTML-sensitive/multibyte strings cannot
grow through a second HTML-escaping serialization. Snapshot admission already
bounds the initial escaped JSON to 128 KiB before canonicalizing it. The audit
contains only existing HMAC/count/references; its encrypted record cap stays
64 KiB, and general digest/output limits remain unchanged.

One settings invocation performs four history GETs/three unwraps, plus its
existing two public audit records (two PUTs, two exact GETs, two wraps and two
unwraps): **2 PUTs, 6 GETs, 2 wraps, 5 unwraps**, excluding current authority SQL/API
work and later audit retirement. Each later audit deletion certificate adds one
PUT/GET/wrap/unwrap. A proposed 17-call fragment protocol would instead require
34 audit PUTs, 102 total GETs, 34 wraps, 85 unwraps and 17 sets of current checks,
plus 17 later certificates. The fixed browser budget avoids that protocol,
additional reads and failure states without persistent plaintext or a new lane.

## Restore boundary

The existing recovery reader/transaction guard fences a restored database
incarnation; it does not inventory an entire object store. History reads require
both the typed available header and generic `stored_unpublished` custody state,
four current receipts, original dates and current recovery/permission/retention.
Missing, pruned or expired headers cannot authorize a read/repeat or a scope-JSON
fallback. Generic deleted attempts keep their independent no-second-refund
tombstones. A restored old header still references its original attempt/dates;
an orphan object's fixed `history/v1/` key identifies its storage purpose.

Implemented inventories cover per-attempt object/version/upload cleanup and
separate purpose-specific audit diagnostics. Global reconciliation of every
recognized prefix after backup/restore remains an existing platform gap; this
change does not claim to supply it or complete backup-horizon qualification.
No extra permanent purpose/mapping field or personal routing marker is retained
solely for a hypothetical future inventory mechanism.

Current unit/race regressions cover fresh workload Pod selection, exact explicit
Pod refusal, original filter/window/composition restoration, edited retention,
collector/compiler drift refusal, policy current-Pod selection, final authority
and expiry shortening during reads, and cursor audience/target/deadline binding.
Full installed browser/MCP capture→settings→repeat qualification remains pending.

## Schema-101 composition checkpoint

The history migration is 00101 after ADR-257's 00100 funding correction; the
compiled SQL adapter requires schema 101. Isolated composition `11806a29` retains
history checkpoint `c36d6452` and committed approved-recording `f3a1fb60`, including
original-owner cancellation checks. No history crypto, quota, retention,
capability, regional unwrap restriction or fallback contract changes.

Local pre-push, affected race and console checks passed. Focused real
PostgreSQL/S3 `history101-parameters-native-1` passed the existing
`history-parameters-custody` case (actual exit 0, 7.36 s selected / 8.874 s Go).
All 3,200 captured source hashes matched and cleanup was empty, with owned
containers independently absent. Physical ciphertext was 4,208 bytes against the
unchanged 1,671,168-byte reservation. Authority/process inputs remain synthetic;
installed console/history remains unqualified. The later PR100 target
composition and executable browser fixture wiring are recorded separately in
the progress record; prior native results above retain their original source
provenance.

## Original submission budget and installed read failure

Installed run 40596917652 on `3673c264` reached one accepted approved capture
and its authenticated native PCAPNG download, then failed at the first
`get_capture_settings` with `ParametersUnavailable`, before React editing or a
repeat. Go took 625.780s and the approved subtest 152.28s. All 3,249 source hashes
matched, source stayed unchanged and cleanup was empty; environment report
SHA-256 `7c1509ce004a716d6dfe3b85d52a9da111af9d76213d5ff57bc943812bd2d1f9`.
The first 2,660-byte PCAPNG has SHA-256
`8734a0032c1bbc89118a851703f86111a3e5cc70a6a7f27185df49ab30341b2d`.
The whole approved/history case failed; no final approved-recording report was
written. That failure alone does not distinguish an absent/incomplete snapshot
from a retained read, relay or codec failure.

A deterministic application regression reproduces a concrete ordering defect:
admission and acknowledged intent succeed, then Start consumes the original
five-second invocation and returns an uncertain deadline error. Deferred history
runs afterward with zero budget, records nothing and cannot be retried by passive
replay. The local RED preserves the accepted capture and one start; it is not
proof that this was the hosted failure's precise phase.

The same synchronous advisory history attempt now runs after acknowledged intent
and current identity, before blocking Start. An early failure retains the one
existing best-effort attempt; replay remains passive. All work retains the
original invocation, identity, source and accepted deadlines. Provider counts
remain three wraps/four PUTs per successful snapshot, with zero eager GETs; this
moves their latency earlier on the dispatch critical path. A current identity
check follows that blocking work before Start (one additional existing-port
recheck per dispatch attempt reaching this boundary, including explicit
continuation). No timer, background task, retry, durable phase,
credential or storage path is added. A quick history error still permits Start
when time remains. Slow history can consume the original budget and prevent
Start; admission remains accepted, and no deadline is extended. Installed timing
must establish the combined cost before this workflow is qualified.

Closed write/read stage and original-invocation context-state words use one
private constructor callback through the existing bounded event logger. They
never include provider errors, identities, parameters, credentials or object/key
locators; the public ParametersUnavailable response is unchanged. The fixture
also logs one exact capture's closed header/custody states and numeric receipt
count before history and on failure, using its existing administrator connection.
This is diagnostic fixture authority only. Subsequent failure invokes existing
process diagnostics so a write outage and read/relay/codec failure are separable.
No settings operation grants evidence read, download or cleanup authority, and
no hub connection to regional S3 is introduced. Fresh installed qualification
remains required.

Local focused sequencing/diagnostic tests pass (0.019s); full capture/bootstrap/
presentation race suites pass in 11.019s / 52.790s / 74.493s, and the local browser
proxy helper race passes in 1.072s. Canonical pre-push passes with the existing
spec virtualenv and pinned sqlc, including 227 console tests. The initial
sequencing RED and a subsequent diagnostic-test duplicate-field compile failure
are retained separately. No external fixture or collector ran for this fix.

## Retained receiver and private exchange cost

The next frozen installed run, 40601041862 on `c267cde7`, again failed at the
first settings read. Its new diagnostics establish required history with
`header=write_claimed`, visible=true, custody=reserved, no writer completion and
zero acknowledged copies, followed by `write/execute/deadline` and
`read/storage/live`. Those SQL facts do not establish absence of physical
objects. Execute includes receiver rechecking, signing and the frame/object
exchange; that run did not distinguish the failing inner phase. Go was 618.860s,
selected subtest 159.45s; source stayed unchanged and cleanup was empty across
3,251 recorded sources. Report SHA-256
`63886dbb9427659877c0bbe41a11e140412defc117346e1ff5a734ae04929593`.
The complete installed history workflow remains unqualified.

A local composition now invokes the actual RegionalHistoryDispatch through the
existing actual process-owned mTLS/H2 fixture, handler/router/source frames,
real history JWS and regional history protocol. Current source/SQL authority and
object effects remain synthetic; no external service or collector runs. Fast
write/read calibration took about 6ms with three source reads. A controlled
200ms regional source latency under one original 500ms parent reproduced a
failure after 500ms, before any object effect. Preparation and the duplicate
Execute Receiver call each took about 202ms; local signing was 0.2ms, leaving
insufficient time for the work frame's own mandatory source read. This is a
reproduced composed cost defect, not a measurement of native S3 or proof that
it alone caused the installed failure.

Execute now consumes the checked receiver already retained by Prepare, within
that receiver's original ValidUntil and unchanged minimum NotAfter. Its exact
channel/executor cannot change. RunHistory still checks the live attachment,
original owner context and standby membership; the actual first work frame still
pulls/validates the current regional source and peer before any effect. Current
signing trust and final-peer checks remain. This removes one redundant source
round trip and its existing checks: three source reads become two, not zero.
The same controlled-delay write succeeds in 406ms normally (434ms under parent
race) inside the unchanged 500ms parent. Positive reads preserve all four exact
ciphertexts/receipts; changed source, closed attachment, canceled caller and
expired original bound all refuse with zero object effects.

Finite elapsed/remaining buckets for attach, initial receiver, sign and exchange
use the existing bounded logger and step timings. Existing stream diagnostics
also report the first closed exchange stage/reason after failure, without another
read, payload, provider error or authority. No timeout, renewal, retry, detached
context, KMS/object capability, durable state or background task is added.
Fresh exact-source installed timing is still required to establish the original
native inner failure and qualify the complete browser/repeat workflow.

Final local affected races pass: mTLS 38.143s, context-start 10.800s, bootstrap
56.057s and capture application 11.082s. Canonical pre-push passes, including
227 console tests. Independent read-only review found no blocker in retained
proof/current-frame separation, joined ownership, finite diagnostics or the
actual-adapter TLS test. No external qualification is implied by these gates.

### Native40607161911: write/read advances, repeat preview remains unqualified

Exact `b944fd93` passed the initial approved native capture and wrote history:
`available`, visible, writer completed, four acknowledged ciphertext copies. The
built browser then successfully read settings, edited the packet filter to
`tcp dst port 8080` and after-window to `3s`, but its preview returned `error`.
The assertion at installed-history-browser.mjs:44 discarded the public error code;
retained output cannot identify its closed failure stage. The whole run failed
(Go 607.616s, approved-recording subcase 157.51s); it is not a completed repeat,
browser approval or second native capture. No new installed run is established.

The fixture now reports only finite preview status/code words and invokes its
existing closed SQL/process diagnostics if the browser workflow fails. No settings,
identities, provider text or credentials enter that added assertion. This adds
no production read, watch, endpoint, authority or retry. One later guarded installed
run is necessary to determine the actual code/stage if it cannot reproduce locally.

A real HTTPS/HTTP2 browser POST -> session/CSRF -> audited presentation -> C09
regression reuses the existing response-reserve fixtures. Exact `2s` -> `3s` and
filter edits pass with SQL-precision dates; expired source and unavailable settings
refuse with zero admissions. It uses synthetic session/facts/history/compiler
ports. Recipe/filter/profile fields come from the first real C09 canonical preview,
but the history header is constructed: this does not exercise accepted snapshot
creation, encryption, real SQL or a collector and cannot establish the Native cause.

That composition found a separate test-induced precision defect. CaptureSettings
and HistoryLineage accept future time.Time instants without a microsecond condition;
CompileRecorder requires persisted preview deadlines on microsecond boundaries.
A source expiry with an additional 777ns made the edited route return NotAvailable
at compile while the SQL-precision case passed (RED exit 1). Repeat now floors the
lineage cutoff to UTC microseconds before planning, preserving the earlier original
bound. Both paths, edited settings and original-expiry refusal pass (focused race
3.715s, exit 0). Current SQL summary/effective expiry and original-anchor duration
retention are expected microsecond-aligned; this is not attribution to the installed
failure. The fix is one time normalization per repeat, zero I/O, extra reads, state,
configuration or deadline extension; no broader time framework is introduced.

Local affected races passed: capture 11.202s, MCP 58.956s, browser 20.108s;
final required-approval route case 3.715s, local pinned tunnel 1.071s. Canonical
pre-push exited 0 (227 console tests); no external fixture or collector was run.
The local route adds five audited browser operations per case (two precision
cases), zero admissions, and approximately 1.1s unraced synthetic test runtime;
its mocked compiler does not qualify native libpcap/Gadget behavior.

### Native40613137981: discovery response visibility

Exact `ad131f4b` failed earlier: after Find diagnostics, the driver's default
five-second row locator saw zero rows (Go 616.048s / subcase 161.29s). Encrypted
history still reported available/visible/writer complete/four acknowledged copies.
Neither diagnostics nor history-list response was retained, and the edited preview
was not reached; its actual cause remains unknown. The earlier sub-microsecond
port defect remains distinct and is not an explanation of either installed failure.

The actual React discover controller awaits list_diagnostics and then
list_capture_history. The fixture now arms both response waiters before the click,
checks HTTP status plus each body's finite envelope status/code, then starts the unchanged DOM
row assertion. Network/operation bounds, locator timeout, authorization, quotas
and retry count are unchanged. Failed/missing/invalid responses fail with a closed
operation label; early failure still closes the browser and safely settles the
other waiter. Existing settings/preview checks reuse that same bounded diagnostic.
This is a small reversible driver sequencing correction, not a new authority or
wait framework, and cannot qualify the installed history workflow by itself.

Syntax and canonical pre-push passed (227 console unit tests); existing built
React/HTTPS browser checks passed 23 journeys/20 accessibility scans, plus four
native-restart boundaries/two scans (Go 21.785s). These existing synthetic checks
do not run the installed continuation or establish its missing response outcomes.
No new test framework, timeout, product change or external fixture was added.

### Native40617618424: history target exchange refusal

Exact `d7cdb5d3` failed after the corrected discovery wait: list_diagnostics
returned HTTP 200/ok; list_capture_history returned HTTP 200/error/NotAvailable
(Go 589.644s, subcase 153.55s). Encrypted history remained available with four
acknowledged copies. Neither the DOM wait, lineage precision nor edited preview
explains this failure. The hub logged `restarts/read/other`: history's regional
workload resolution failed before ListCaptureHistory's SQL read/eligibility.
An adjacent canceled route namespace read is not proof of causal ordering;
stream interruption or later browser cleanup can cancel that read. The underlying
installed I/O cause is still unknown.

The existing closed stream classifier now recognizes the supported Go net/http
conversion into the already-used x/net/http2.StreamError. It retains only fixed
INTERNAL/deadline/CANCEL/PROTOCOL/REFUSED/other classes, never stream IDs, Cause
text or payload. INTERNAL means deadline only when Cause is exactly
os.ErrDeadlineExceeded; an unqualified INTERNAL establishes neither timeout nor
peer origin. Classification invokes no Error/Is/Unwrap methods, but may invoke
net.Error.Timeout and a directly implemented structured As bridge. These are
trusted in-process Go error interfaces, as in ordinary Go error handling; network
input cannot inject Go method implementations. This is not an arbitrary-method-
free guarantee. A regression executes the direct bridge exactly once and retains
panic Error/Is/Unwrap methods, including a refused conversion that stays `other`.
This changes diagnostics only: no transport, query, deadline, authority,
retry, current check or public response changes.

The actual mTLS/HTTP2 fixture now also tests diagnostics ResolveWorkload followed
by history ObserveWorkloadRestarts for a zero-Pod workload. Holding the second
fresh route check across the first query's 500ms cutoff passes, preserving the
second original deadline and retained source identity. Callback inspection found
no demonstrated stale-callback defect: stream-affecting frame/setup callbacks
join before reuse; the remaining cancel-only callbacks own invocation-local
contexts. This positive synthetic path does not reproduce the installed failure.

A deliberate real HTTP2 write cutoff during that second current route check
produces a closed target refusal while the caller still has time. It reports
`restarts/read/http2-deadline` (race pass 1.136s); the legacy classifier reports
only `restarts/read/other`. The moved existing idle-write-deadline test exercises
the actual stdlib As conversion and neutral INTERNAL result; fixed-code tests
retain private-error noninspection. This is a test-induced diagnostic witness,
not attribution of the installed interruption or completed browser qualification.

Complexity gate: (1) one observed closed history-list failure whose I/O cause is
unavailable; (2) no accepted timing risk reopened; (3) shared transport diagnostics
benefit, no typical-path product behavior change; (4) Go's supported StreamError
conversion, no protocol/error parser; (5) zero privileges/credentials/exposure;
(6) six diagnostic classes, zero product/fallback states; (7) zero configuration;
(8) existing Go HTTP2/x/net dependency; (9) zero added API/SQL/network requests,
watches or goroutines, one type conversion only on errors, CPU unmeasured;
(10) no wire change, diagnostic-only rollback; (11) retaining `other` cannot
distinguish the demonstrated transport cutoff. No collector/external fixture or
hosted rerun is part of this local checkpoint; actual installed cause and complete
history/repeat qualification remain pending.

Legacy-classifier diagnostic RED exited 1; the corrected actual-cutoff witness
passed. Full affected races passed: context-start 10.893s and mTLS 38.527s.
Canonical pre-push exited 0, including 227 console tests. These local gates
establish neither the installed interruption's cause nor a successful repeat.
