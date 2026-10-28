# Remaining native response qualification

Date: 2026-10-28. Status: installed attempts failed before traffic. Request preflight and SQL measurement regression checks pass; installed paced transfer and combined costs remain pending.

## Missing helper setup branch and early preflight (2026-10-28)

Native 40605062812 on `e9e3c64e` failed before invoking the traffic helper:
`exact owned traffic target unavailable`, with a 731ns refusal and no valid
receipt. The environment has no nativeTrafficHelper descriptor. Actual Go was
586.959s; approved recording was 137.49s. All 3,230 source hashes independently
match the frozen source, unchanged with cleanup `[]`. Environment SHA-256:
`3a07e6f84b9789364328aed128248029c48672f3dc4e3fc5390ed9fbc2fc85e5`;
measurement report SHA-256:
`dbf9d8899a697dcbd9f14810d35a894742ca5435d76b417aeb2cf5706be2ed7c`.
This establishes a setup omission, not failure or success of the direct route.

Helper copying was nested inside Helm's private-registry branch, while the
actual native-paced provider-pair setup uses no Helm registry. A pure setup-path
regression reproduced that conditional mismatch (exit 1, 0.019s). Installation
now runs in the common owned-regional-node setup, enumerates its exact Kind
nodes and retains the same ownership/SHA checks. Descriptor validation precedes
serialization and Go launch. The actual Go bootstrap entry independently refuses
a missing descriptor before touching provider/API inputs. No API-proxy fallback,
collector guard relaxation, timeout/quota change or new product privilege is added.
The fast topology has one regional node; the Helm topology can have two. Copy
cost follows the enumerated owned set rather than assuming the Helm topology.

All 17 pure selection/setup tests pass in 0.032s, including ownership/hash
mismatch and missing descriptor. Affected parent races pass in 1.197s, including
a child invocation of the actual bootstrap entry with unusable provider inputs
that must fail at the earlier helper guard. The new exact selection
`^TestNativePacingTrafficWithRealKubernetes$` uses the existing context runner
with one synthetic Kind, its existing PG/S3/OpenBao/TLS bridge fixtures and one
Restricted traffic Pod. It exercises this same common installer, serialized
descriptor, actual hash check and Docker command to the exact Pod UID/IP/node.
No bootstrap, Keycloak, collector or BPF participates.

The one authorized owned probe on frozen `092cbe4f` passed: test 7.94s, Go
9.011s and terminal runner exit 0. All 3,231 source hashes independently match,
source stayed unchanged and cleanup is `[]`. The serialized descriptor and
node-side binary both use SHA-256
`1a93443af11b51b656cc8d5231a2f694984daf8334636a29a3c5217fa2dabee6`.
The live Pod UID, IP, original node UID and boot ID were checked without target
replacement. The actual Docker command delivered sixteen batches / 65,536
records / 4,194,304 bytes with valid final acknowledgement in 7.556100912s
including launch/join; child time was 7.52062203s. Common setup's one ownership,
copy and hash pass took 0.120864s and copied 11,293,151 bytes. This is measured
fixture setup/traffic cost, not product acquisition or whole installed-job cost.

Artifacts are under `~/.cache/asservat-build/native-pacing-kind-probe-1-artifacts/`:
environment SHA-256
`b719880e91cee33f8d23107f56348caa4dcc7631d4b1b745e90bded4827cba46`;
exact probe report SHA-256
`831a56f4492df2d59e7fb907783f58c60db6bbfd094d51914201d52e83ed9ec3`.
Independent read-back confirms the named Kind node, four provider containers,
both owned networks, worker image tag/digest and Kind cluster are absent;
`owned-resource-absence.json` retains those actual checks. Generated reports were
archived before restoring only this run's tracked outputs. This qualifies the
synthetic owned-node/Pod route and common setup path. No capture, collector,
near-full artifact, native download/renewal or combined product cost was tested.
A fresh installed run remains necessary.

## Serialized traffic route failure and direct fixture client (2026-10-28)

Native 40600135398 on `4d2e1033` exited 1 after setup SQL snapshots succeeded.
Actual Go was 603.040s; approved recording was 146.39s. The traffic phase ended
at 8.500202059s with seven acknowledged batches, 28,672 complete records and
1,863,232 received bytes: seven full 262,144-byte batches plus 28,224 bytes of
an incomplete eighth. Its acknowledgement refusal remains a failed experiment.
No near-full artifact, paced native body or renewal was qualified. The retained
measurement report SHA-256 is
`e02d16de7f7dfd5ae9544c05144921e3dab24a896a13d0c29937c7eec045c8be`;
environment SHA-256 is
`b96062832090d54cb25673b513981447e8d930d4eb93d9820ebdcf25c14a1da8`.
All 3,230 source hashes independently match `4d2e1033`, source stayed unchanged
and the environment report records cleanup `[]`. Exact artifacts remain under
`~/.cache/asservat-build/codex-bf86-resume/native-paced-40600135398-artifacts/native-continuation-native-paced-1/`.

The fixture serialized sixteen API Pod-proxy responses, each containing 4,096
individually flushed 64-byte writes. That installed route could not deliver the
fixed workload within its phase. The report did not retain individual batch
latencies, so this does not establish a particular Kubernetes buffering defect.
The correction uses the existing statically built provider-proxy fixture binary
as one finite traffic client on the selected Pod's exact owned Kind node. It
connects directly to that live, UID-checked Pod IP on port 8080; there is no
Pod port-forward, loopback route, DNS, environment proxy, redirect, replacement
workload, filler or retry. Ordinary approved-recording traffic remains unchanged.

The existing CGO-disabled build produces a static Linux executable, avoiding a
runner-versus-Kind libc dependency. The measured local artifact is 11,293,151
bytes. Setup copies the same binary to the enumerated already owned regional nodes
and verifies its SHA-256 and each Kind ownership label before collection. The
fixture descriptor/environment retains that digest and exact node allowlist.
At Running, one live Pod GET verifies the selected UID and provides its node/IP.
One Docker exec runs the client; a closed 2 KiB numeric receipt is required,
including last status/body bytes/acknowledgement and a fixed failure code. Missing
or invalid receipts are explicit, never zero-cost success. Parent wall time and
client time are separate. The absolute earlier caller/8.5s cutoff includes
process launch; stdin EOF cancels the child and the parent waits for process exit.
A failed join or deadline fails the experiment. No new image, Pod, service,
listener, product credential, privilege or background service is added. Setup
adds one binary copy (about 10.8 MiB), one ownership inspection and one
hash read per enumerated owned node; traffic replaces sixteen API-proxy exchanges with one Pod GET and
sixteen direct HTTP requests in one process. Actual installed setup/runtime cost
remains unmeasured.

A local RED modeled a 1.1s per-request proxy delay and reproduced seven complete
batches at the fixed deadline (exit 1, 8.504s). This deliberately injected delay
is not a measurement of Kubernetes internals. The final GREEN keeps that route
failed and sends the identical fixed workload directly to the actual fixture
traffic handler: delayed route seven batches / 1,835,008 bytes / 8.500915135s;
direct route sixteen batches / 65,536 records / 4,194,304 bytes / 7.537577943s.
The explicit-file fixture race suite exited 0 in 17.709s, retaining no-retry and
finite-handler checks. The former duplicate integration traffic loop was removed
so these checks exercise the binary's actual client. Parent receipt/foreign-node/
loopback/EOF-cancellation-and-join and measured-size checks passed with races in
1.127s. No collector or external Kubernetes fixture ran locally. The owned-node
network route and actual retained capture size still require installed proof;
all sixteen batches alone cannot qualify packet count or near-full PCAPNG size.

Canonical local `make pre-push` exited 0 (218 console checks; specification
13,280 assertions; architecture 1,326 positive checks). The final receipt suite
also refuses partial/missing acknowledgements, extra JSON, unknown fields and
more than 2 KiB of helper output. Static binary inspection and these local tests
do not establish the installed node route.

Review follow-up: the child receipt now decodes into a dedicated eight-field
value before validated fields are copied to the report. Child JSON cannot set
parent-owned ReceiptValid or ClientElapsed, including before a later decode
failure. The injected-field regressions reproduced both acceptance and tainted
error artifacts (RED exit 1, Go 0.035s; affected parent race GREEN exit 0,
1.134s). Final canonical pre-push including vet and all 218 console checks
exited 0. Valid partial receipts still preserve
their acknowledged counts, received bytes and closed failure. This is one fixed
receipt value per phase, with zero additional API/process calls, timers or
privileges. The actual traffic client and its measured synthetic proof are
unchanged; no external or installed run accompanied this correction.

## Incomplete SQL measurement and owned PostgreSQL proof (2026-10-28)

Paced Native 40595384061 on `76bae03c` exited 1 after an uncertain submission
resolved to the same accepted capture, before traffic or pacing. The setup
snapshot comparison failed at the transition to observed Running. Actual Go
was 596.503s (installer 394.97s; approved-recording 137.89s). Environment report
SHA-256: `9a02e42ff2fd8fd79664ada933a9cab15b98bca876c9a505d51c7db36db30032`;
3,223 source hashes matched the frozen source, unchanged with cleanup `[]`.
The report writer returned before saving its numeric edges. Consequently the
specific failed comparison is unknown; inherited statistics saturation is a
hypothesis, not an established cause. No paced transfer or aggregate cost passed.

The test-only writer now persists incomplete numeric Before/After edges with a
closed failure reason before returning its error. Missing/reset/evicted coverage
still refuses qualification; it produces no invented zero SQL delta. A focused
regression failed before the correction because its report file was absent
(0.014s), then passed with races (1.063s). No query text, parameters, credentials
or product telemetry are added. After completed bootstrap, the owned installed
fixture resets its private statistics once before the first measurement edge.
That adds one fixture-administrator SQL call; no measurement phase is reset or
retried after loss of coverage.

The existing custody runner has a narrowly selected `--native-statistics` mode
for `^TestNativePacingSQLWithRealPostgres$`, using its existing PG/S3 containers
without collectors. The immutable PostgreSQL image
`postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c`
reports 18.6-1.pgdg12+2. Its default 5,000-entry capacity and the test's 20s
context are unchanged. PostgreSQL 18 normalizes utility statements; SET literal
values are unsuitable for producing distinct entries. See the
[PostgreSQL 18 statistics contract](https://www.postgresql.org/docs/18/pgstatstatements.html)
and its [query jumble implementation](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/nodes/queryjumblefuncs.c).
Distinct role identifiers remain significant: `CreateRoleStmt.role` is a string
without a jumble-ignore annotation, and the
[node generator](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/nodes/gen_node_support.pl)
emits string jumbling for that field. The real numeric preflight independently
checks this behavior before stressing the library.

Three separately frozen owned runs are retained under
`~/.cache/asservat-build/native-pacing-statistics-baseline-{1,2,3}-artifacts/`:

| Run/source | Actual result | Environment SHA-256 |
|---|---|---|
| 1 / `dabd1945` | Exit 1, test 0.05s / Go 0.109s: SHOW text could not scan into an integer; no stress proof. | `5e283e32cb90684c92e7db2f003b5960ab1f12b494a84b2830730925efac302d` |
| 2 / `4973b863` | Exit 1, test 0.07s / Go 0.137s: 5,001 SET utilities left deallocations 0→0; saturation assumption refused. | `70325ddf80c2d9fe1d6aa7e846dd19e65faf3283a75811d7fac699900d313c09` |
| 3 / `0b83e8a5` | Exit 0, test 0.30s / Go 1.360s: rollback-only distinct NOLOGIN role DDL qualified the mechanism. | `d4ff988aa046c16ce075d2ad3847b7cda7de448e16befd2c7e25101d0e0d2b41` |

Each report has 3,187 independently matched source hashes, unchanged source and
cleanup `[]`; exact owned PG/S3 containers are independently absent. In run 3,
the two-identifier preflight increased both entry and distinct-ID counts from
1,852 to 1,854. Two bounded batches of 5,001 CREATE ROLE commands ran in rolled
back transactions; no bootstrap roles survived. Deallocations rose first to 8,
then 28, and the measured interval refused eviction. One reset strictly before
the first positive baseline reduced deallocations to 0. The existing positive
case still required exactly two narrow-role calls, one normalized statement,
correct row counts, administrator exclusion and cross-database isolation. An
explicit later reset also refused comparison. This is induced mechanism proof,
not an installed runtime result or recovery of the earlier missing edges.

Final local canonical `make pre-push` exited 0, including 218 console checks;
focused report/SQL/provider race checks exited 0 in 1.064s. Specification
validation passed 13,277 assertions and the architecture gate passed 1,326
positive checks. These are local checks, not another installed result.

The bounded-response change targets fresh installations with matched component
versions. Mixed peers can refuse longer operations; it claims no installed
rolling upgrade. Regional connector and download-worker upgrades remain the
existing [ADR-227 backlog](../decisions/227-upgrade-and-rollback.md), without
adding drain machinery to this fix. A fresh installed pacing run with retained
measurement edges remains required before qualifying its payload and costs.

## First installed pacing attempt and request preflight (2026-10-27)

Run 40591118979 on `fa69b019` failed before approval or traffic generation:
`preview_capture` returned `InvalidComposition`. Actual Go exited 1 in
480.868s; the approved-recording subtest took 9.84s. The first transient storage
refusal delivered its typed response with Finish below 100ms; the later refusal
was a deterministic request error. All 3,223 source hashes independently match,
sources stayed unchanged and cleanup reported no failures. Environment report
SHA-256: `2ee0c3233a477878e0087496c9378905a3465e30583631906ef461db187ff5ca`.
The pacing report is incomplete, with no traffic, capture, native body or owner
renewal. It qualifies none of those paths or their aggregate costs.

The fixture requested `actionMaxBytes`, a general schema field that immutable
`builtin/network-connections/v1` does not expose. Its authored output ceiling
already exceeds the recorder's existing 8 MiB native cap. Removing that
unsupported override preserves the same effective cap, aggregate 16 MiB bound,
ten-second recording, twenty-second action deadline and independent approval.
No profile, compiler validation, quota, production code or authority changes.

The preflight now runs the actual builtin planner and derives its accepted
recording, rather than checking only input-schema validity. Target/retention
facts and the existing recorded filter compiler are synthetic; actual libpcap
filter behavior and installed collection remain separately qualified. Before
the fixture correction the new test exited 1 in 0.060s with the exact unexposed
field path. Afterward the focused race checks exit 0 in 1.334s and require the
10,000ms recording, 8 MiB native cap and approval. Original approved-recording
arguments remain unchanged. Canonical pre-push and focused race checks passed; independent source review found no concrete blocker. A fresh installed pacing result is still required.


ADR-258 separately qualifies paced 8,126,572-byte synthetic transport, actual
4 KiB SQL/S3/TLS/key-slot delivery, and the actual Kubernetes response-proof
producer. These results do not establish their installed composition.

## Tested helpers

The real loopback TLS/HTTP2 test streams 8,323,072 synthetic bytes with exact
whole/range/resume SHA-256, using a 32 KiB client buffer. With consumption held,
the server writes only 65,536 bytes ahead. Whole delivery takes 6.551 s and the
server writer itself stays blocked for 6.727 s. This proves final-client
backpressure rather than just delayed processing of an already-buffered body.
The complete test takes 13.47 s. These are synthetic bytes, not a collected
PCAPNG or installed-runtime result.

[`native_pacing_client_test.go`](../../test/integration/native_pacing_client_test.go)
clones the installed transport and preserves its TLS/routing; HTTP/1, incorrect
status/range/length/ETag/hash, truncation, excess bytes and an unbounded caller
are refused. Original-deadline cancellation closes and joins a blocked read.
[`native_pacing_traffic_test.go`](../../test/integration/native_pacing_traffic_test.go)
provides the bounded owned-node client boundary and measured-size gate; the
actual traffic loop lives in the existing provider-proxy fixture binary. The real loopback
traffic-protocol test acknowledges 16 batches, 65,536 writes and 4,194,304 application bytes
in 7.530 s. It does not infer packets or native artifact size from write counts.

The existing fixture signals workload now serves `/traffic?records=N` through
its existing port. The fixture-only
[handler](../../test/fixtures/provider-proxy/main.go) caps each request at
65,536 64-byte flushed writes and eight seconds, preserving an earlier caller
cutoff. Completion trailers report actual writes/bytes and whether the stream
finished; unknown/partial batches are not retried. Existing `/log` behavior is
unchanged. No production endpoint, credential, listener or debug setting is added.

Run the helpers with:

```sh
go test -race -count=1 ./test/integration -run '^TestNativePacing'
go test -race -count=1 test/fixtures/provider-proxy/main.go test/fixtures/provider-proxy/traffic_test.go test/fixtures/provider-proxy/counters_test.go
```

The standalone fixture command is intentional: provider bridge code retains its
existing ignored-file boundary. An initial architecture gate rejected extracting
it into a normal product package; that extraction was removed without changing
the rule. The actual handler also passes a full 4 MiB / 65,536-write HTTP test.

## Reuse the installed public journey

After PR-100 passes, start from its `continuation-approved-recording` focus and
the history continuation after its integration. Reuse
`installed_approved_recording_native_test.go`: real independent Keycloak
approval, expired-preview submission, exact selected workload, official collector
installation, publication and public native-download preparation. The collector
helper requires `/etc/asservat-disposable-host`. Run only on the owned disposable
qualification host; never install a collector/BPF program on this workstation.
No hosted dispatch is authorized by this plan.

The existing PR-100 helper's small `/log` requests and nonempty-PCAPNG check
remain its original qualification. For this separate near-full experiment,
review the builtin recorder's existing 8 MiB cap, `packetAfter=10s`, `actionTimeout=20s` and finite
composition limits before approval. No duration changes after acceptance are
allowed. Keep the product's current 8 MiB native cap.
After the exact accepted capture reports Running, run sixteen batches of 4,096 flushed 64-byte writes
at 500 ms start intervals. Maximum application payload is 4 MiB; traffic phase
ends after 8.5 s or the earlier original context, with no retry. Record real
capture/traffic timestamp overlap. Public Running records execution start before gadget attachment; it is not an attach-ready signal. Record the execution observation and traffic interval, then verify actual retained packets and timestamps. An undersized result fails without retry. TCP segmentation, ACKs and PCAPNG overhead are
not predictable from application writes; measure them.

The caller must invoke `nativePacingRequireNearFullRecording`: only measured
native sizes 8,323,072..8,388,608 bytes qualify. A tiny artifact or a byte above the
current cap fails. Record standard PCAPNG interface/drop statistics through the existing native tools (`capinfos -M -I` and tshark), not a hand-written packet parser. The current format combines all filtered/unsupported/output-full/lost drops in its ISB; it does not expose a separate OutputFull/LostSamples breakdown to this fixture. Report that measurement gap explicitly rather than inventing per-cause counts. Cap saturation or dropped packets must be
explicit; reaching the size does not mean all generated traffic was retained.
No hidden capture retry, larger native limit or replacement workload is allowed.
If this bounded source does not fill the window, keep the failed measurement and
adjust a later reviewed fixture budget; do not relabel it as a full-window pass.

## Make pacing reach the production writer

Clone the existing final-client HTTP transport. Use its supported
`http.HTTP2Config` receive windows of 64 KiB per connection and stream, then read
32 KiB every 25 ms (nominal 1.25 MiB/s, roughly 6.4 s for 8 MiB). These are test
client settings, not a product timeout or configuration. Verify HTTP/2 was
negotiated. Small flow-control windows prevent a slow reader from being hidden
behind megabytes of client buffering. Record actual delivery time, native bytes,
original operation deadline and observed SQL response/window lease sequences;
require the same cursor/window to cross the first five-second observation.

Require exact SHA-256, authenticated metadata, native filename and successful
PCAPNG parsing. Reuse the same prepared artifact for an unpaced control, a paced
whole transfer, a valid range/resume and stale If-Range behavior. These four sessions exhaust the existing cumulative session reservation. Revocation, cancellation and concurrency remain separate qualification gaps; do not raise or refund the budget for them. Permission-change timing follows the accepted bounded recheck contract, so this experiment adds no immediate-revocation guarantee. Never
renew a closed identity batch or add per-piece key opening. Preparation and
each response window retain their separate three one-use unwrap slots.

## Phase budget for the disposable runner

The qualified PR100 baseline is Native run 40586980099; its source tree matches
canonical main `eed8594020645fe6d10f8c6565e69a6235c7507d`.
The whole job took 964s, the Go package 620.173s and the approved-recording subtest
155.60s. It passed actual independent approval, a real preview-expiry wait and
native PCAPNG validation of a 2,360-byte recording; it did not run pacing, a
near-full recording or history. All 3,201 source hashes matched the frozen
source and cleanup failures were empty. The environment report SHA-256 is
`d86eef8c74434bdb9240530927c3dd0edbbe6d1defb333ce432ff245843063da`.

Reuse that installation and approval flow. In `continuation-native-paced` the
reviewed ten-second recording replaces the ordinary two-second recording; it
is not another approval flow or an additive history run. Allow 20s for the
recording/traffic phase (reviewed ten-second window, action timeout 20s, finite
traffic 8.5s), 60s for preparation work, 60s for control/paced/range/stale-If-Range
bodies and the matched idle baseline, and 60s for joined cleanup and measurement
snapshots. This 200s allowance is a planning estimate, not measured added runtime
or a per-phase product deadline. Four sessions retain their own preparation
bounds: each existing 60s polling cutoff can have one already-started 45s call,
so the allowance is not a worst-case guarantee. No uncertain POST is replayed.

The immutable 20-minute job cap leaves 236s above the observed 964s baseline;
adding the proposed 200s gives 1,164s and only 36s margin. The immutable 18-minute Go
cap leaves 459.827s above 620.173s; the same projection gives 820.173s and 259.827s
margin. Setup variance and aggregate measurement cost are unqualified, so the
narrow job margin must be reported, not treated as proof that the run will fit.
The first guarded paced run must retain both caps and produce a terminal test
result and clean cleanup; timeout/cancellation is not a pass. No phase, request,
operation, evidence or session deadline is increased to fit this experiment.

The nominal near-full paced body remains about 6.4s at 1.25MiB/s. Neither that
arithmetic nor the successful small baseline establishes an installed slow-link
throughput, aggregate-cost result or actual two-version/drained-rollout proof.

## Count the complete workflow

Take phase snapshots before preparation, before each body, and after joined
cleanup. Include an equal-duration idle baseline with the same installed
reconcilers; report background-inclusive deltas separately from attributable
request counts rather than subtracting them and calling the result exact.

- Kubernetes: fixture-only Metadata audit events for the relevant installed
  service accounts, filtered to TokenReview and finite object GET categories.
  Never record request/response bodies, bearer tokens or Secret contents. The
  direct producer baseline is two TokenReviews/eight GETs per receiving hop;
  response rechecks within the original operation must add zero proof API calls.
  Protected dispatch/profile reads remain a separate measured category.
- S3 and provider KMS: extend the existing fixture-only provider TLS proxy with
  bounded method/operation counters and response-header latency snapshots, as
  defined below. Count no object names, query values, bodies, wrapped keys or
  credentials. Keep its current forwarding behavior. S3 audit/artifact effects
  remain ambiguous within a method category; report that limitation. These Bao
  operation totals describe provider control work; installed artifact unwraps
  use the separate local A-KEY service.
- Local artifact keys: pin the existing SQL native owner/window and its single
  native-key row. `used_roles=7` records three irreversible role authorizations
  (data, index, manifest), consumed before backend crypto. Combined with a
  successful authenticated native transfer/hash, this supports the inference
  that its three required opens succeeded and renewal added no authorized opens.
  Report `ConsumedKeySlots=3`, not a direct successful-decrypt or HTTP-attempt
  count. Rejected requests and crypto followed by a failed post-check remain
  unmeasured. Keep preparation and publisher verification separate.
- SQL: use the owned PostgreSQL server's standard `pg_stat_statements` extension
  in fixture configuration only, if available in the pinned image. Read numeric
  call/time/row counters by the generated installation roles, without query text
  or parameters. Snapshot numeric per-role aggregates; label background
  activity. Calls count statement executions, not wire round trips;
  `total_exec_time` excludes planning time by default, and top-level execution
  includes stored-function work. These values are not exact end-to-end SQL
  overhead. Use actual service-role login credentials; do not mistake fixture
  `SET ROLE` statements for application calls. Do not add a product pgx tracer
  or parse SQL protocol traffic. The pinned image's extension can initialize and
  return numeric snapshots; installed phase attribution remains unqualified.
- Record end-to-end preparation/body/cleanup latency, provider operation counts,
  bytes, SQL calls/time, peak fixture/container memory and CPU. Counters add no
  production API, credentials, background service or runtime permission. Measure
  their fixture overhead with the unpaced control.

## Provider snapshot interface

The existing provider bridge serves `GET /__asservat_fixture/counters` on either
its S3 TLS origin (8443) or KMS TLS origin (8444). Both listeners expose the same
process counters. Reuse the fixture's existing pinned TLS roots/client; no token
is needed for these numeric fixture snapshots. SQL port 8445 is unchanged. This
is an owned test-fixture route, never a product endpoint. Reads are `no-store`,
do not forward to a provider and do not count themselves. Other methods return
405. There is no reset or label input.

The JSON object always has fifteen fixed keys:
`s3_get`, `s3_head`, `s3_put`, `s3_post`, `s3_delete`, `s3_other`, `kms_encrypt`,
`kms_decrypt`, `kms_sign`, `kms_verify`, `kms_login`, `kms_lookup`, `kms_renew`,
`kms_revoke`, `kms_other`. Each value contains only integer totals:
`dispatches`, `active_roundtrips`, `transport_errors`, `status_2xx`, `status_3xx`,
`status_4xx`, `status_5xx`, `status_other`, `roundtrip_to_headers_nanoseconds`.
Unknown methods/operations use the fixed `other` category. Paths, object names,
query/header values, bodies and credentials never enter the counter state or
snapshot. Requests and responses, including the exact body objects and their
streaming/upgrade interfaces, pass through unchanged. Counter code does not
retry, buffer, read or close bodies.

Dispatches count calls into the backend HTTP RoundTripper, not wire attempts;
internal transport retries are not individually visible. Concurrent durations
overlap, so their sum is not end-to-end wall time or CPU time. Time ends at response
headers or transport error, excluding body lifetime/bytes and final downstream
flush. `active_roundtrips=0` therefore does not prove body/worker quiescence.
Use the journey's actual joined lifecycle and phase/idle snapshots. Deltas are
background-inclusive; S3 methods cannot distinguish audit from artifact effects.
Label that ambiguity rather than adding path or payload tracing. Measurement
cost is two short mutex updates per dispatch and a fixed fifteen-entry snapshot;
there is no additional backend request, goroutine or production dependency.

## Decision gate

One owned installed run, with frozen source hashes and joined cleanup, must
demonstrate the large exact payload, actual backpressure and current SQL owner
renewal together. Keep its original twenty-second response ceiling; do not tune
it while the run is active. Report aggregate costs per preparation, per window,
per delivered MiB and for concurrent responses. API/key work should scale with
admitted windows, not chunks, workload replicas or idle viewers. If measured
costs or the approximately 0.4 MiB/s ceiling floor are impractical, reassess the
whole design before proposing a different finite bound. A successful 1.25 MiB/s
case does not promise arbitrary slow-client support or complete S-02.


## Local composed fixture wiring checkpoint (2026-10-27)

The unpublished `continuation-native-paced` focus now wires the existing real
installation, independent fresh-form approval and real preview-expiry flow into
one reviewed finite 10s recording, exact-target bounded traffic and four cumulative
download sessions. The original approved-recording request stays 2s. Replay and
other-client checks in the paced focus run after publication so they cannot
consume the finite traffic opportunity. Running is execution observation only;
absence of observed running, undersized output or missing real packet overlap
fails without a capture retry or replacement.

The four sessions are unpaced whole, paced whole, two disjoint ranges in one
session (joined full hash), and stale If-Range falling back to a whole response.
The range session charges 4MiB preparation plus two fixed 8.375MiB framed-read
bounds: 20.75MiB within the existing 24MiB read budget; output totals one native
file within 16MiB. No ignored cipher/index overhead or limit increase is used.
The recording phase remains open through actual publication and case lookup; first-to-last snapshot deltas also include gaps between phases. Public completed state plus one pinned SQL read must positively confirm the
paced response's final acknowledgement and closed owner/window; byte EOF alone
cannot pass. The 64KiB HTTP/2 receive windows / 32KiB client reads at 25ms preserve
backpressure. One initial and one after-five-seconds SQL sample require a newer
lease sequence on the same operation/window/deadline and exactly three consumed
local-key authorization slots. Preparation has its separate three slots.

The setup phase starts before public processing/login/preview/review and ends at the first observed execution start. Installation/bootstrap work precedes this phase and is not attributed to the investigation. Later phase snapshots include generated-role statement counts/time/rows, fixed
provider request/status/header-time counters and an idle interval matched to the full paced phase (HTTP setup, body and completion checks), with exact measured edges rather than subtracting assumed equal totals.
The fixture-only API-server audit logs RequestReceived Metadata for ServiceAccount
GET and TokenReview CREATE under blocking-strict writes. Four existing-admin
readyz markers establish bounded retained coverage and are excluded from counts.
Logs are bounded to four 32MiB files per cluster; raw exports stay in the private
fixture directory and are deleted after numeric aggregation. Missing coverage,
truncation, duplicate audit IDs, phase overlap or statistics reset fails the
measurement. No runtime permission, credential, watch or product audit path was
added. All deltas include background services and separate snapshot edge times;
they are not an atomic causal trace or CPU cost.

The existing collector-native tooling setup has a three-minute step bound, one
170s apt operation plus 5s termination grace, no acquisition retries, bounded
network/lock waits and visible failures; no native test starts after setup
failure. Working preinstalled tools skip apt. The 20-minute job and 18-minute Go
limits remain. No hosted paced run, near-full collected result, installed owner
renewal, aggregate cost or mixed-version qualification has passed yet.


The statistics library is preloaded at fixture startup, but its SQL extension is
created only after the actual initial installation/schema/role workflow finishes.
Creating it earlier would violate the pristine-schema contract. The extension
lives in `fixture_native_statistics`, with all schema/table/function PUBLIC
privileges revoked in one transaction, and only the fixture administrator reads
its qualified views. No product guard is changed. The revised explicit-file
real PostgreSQL helper passed in an owned network-none, read-only PG18 container:
test exit0, source unchanged, ordinary-login schema/table/function access denied,
correct two target-database statements with administrator/other-database work
excluded, cleanup exit0 and container confirmed absent. Runner elapsed1.614s;
report SHA-256 `d5c09d7acb27efaa07df785c12657ffffb8d091d5c8a4e4ee242d27d821b2451`.
The first harness attempt failed before executing the test because Docker cp
refused a read-only container root; that failed report is retained. The passing
attempt used a private read-only bind of the test binary and synthetic fixture.
Neither result qualifies installed bootstrap, aggregate runtime cost or capture.

Final local checkpoint checks passed: targeted integration helper race tests
(22.656s; external fixture tests skipped there and qualified separately above),
14 Python topology/configuration/privacy/coverage tests, workflow YAML and Bash
syntax, spec-check, architecture-check, Go architecture and diff checks. A
separate read-only review confirmed that this focused installed path does not
rerun initial schema inventory after adding the private fixture schema. A future
initial-schema replay would reject it; this experiment does not qualify that
combination. The branch remains unpublished and has not run a collector locally.

## Fixture candidate after Native40609943030

Exact `7f721c08` failed before PCAPNG/download/owner proof: the genuine owned-node
helper acknowledged 15 batches / 61,440 records, read 4,026,176 bytes including a
94,016-byte final partial response, and hit the original 8.5s phase cutoff.
Parent wall time was 8.504619291s; client wall time 8.466837358s. Go failed in
582.174s / selected subcase 141.20s. Frozen report SHA-256 is
`23cfc611fec3d56bca9d3e007100bbaea5584344538e130591bf556eb1ea7825`;
all 3,231 sources matched, unchanged=true and cleanup=[] (root verified).
No native artifact or download/owner qualification is established by this run.

The helper schedules each batch at started+i*500ms: sixteen batches have a
7.5s nominal scheduled span and only 1s final tail, further reduced by process
startup or catch-up after slow batches. This interval is fixture engineering,
not a maintainer minimum observation duration. The candidate uses 250ms: a 3.75s
span and 4.75s nominal tail. It preserves sixteen acknowledged batches, 4,096
64-byte Write+Flush records per batch, 4 MiB total, one in-flight connection,
no retries, original 8.5s phase, 10s action, 20s response and 8 MiB native limit.
Near-full measurement and actual paced DOWNLOAD >5s assertions stay binding.
Nominal offered batch cadence doubles during a shorter period; total writes and
bytes do not grow. Actual packets, native size and combined CPU cost need the
installed run; application write counts do not substitute for them.

Before code, complexity gate:
1. One actual installed fixture deadline failure; final response was partial.
2. No accepted requirement mandates the fixture's 500ms or 7.5s schedule.
3. Qualification fixture only, zero production behavior changes.
4. Reuses its existing absolute batch schedule, direct HTTP client and handler.
5. Zero new privileges, credentials, listeners or services.
6. Zero new failure/fallback states; existing partial/deadline results remain.
7. Zero runtime knobs; one fixed interval adjustment.
8. Existing Go/net/http, owned-node route and runner scheduling remain dependencies.
9. Same 65,536 flushed writes / 4 MiB; nominal cadence 2x, active span 1/2;
   two fixed numeric child wall-time fields, still <=2048B receipt. No CPU claim.
10. Fixture-only rollback is one constant; parent receipt fields stay protected.
11. Shorten intentional waiting before changing traffic volume or any limit.

A representative local variable-work model will run the actual helper/direct
handler: small varying first-batch delays and four 300ms waits during the last
batch's writes. It tests available tail under the unchanged deadline, not the
cause or performance of the installed node/collector. Receipt WaitElapsed and
WorkElapsed will separate measured client wall waiting from HTTP/ACK work; they
include scheduler/network time and are not CPU measurements. No packet API calls,
collector execution, external fixture or additional qualification budget is added.

The failed installed setup also measured 132.674s / 79,127 SQL calls (about596.4/s)
and 5,198.45ms summed PostgreSQL execution. This includes background and approved
setup work, not isolated download, CPU or steady-state cost. Preserve that cost
edge for combined qualification; it does not identify the traffic deadline cause.

Local model RED at 500ms: actual exit1, 8.503s package, 15 acknowledged batches,
200 final response with 196,608 partial bytes. GREEN at 250ms under race: all
sixteen acknowledged batches / 65,536 records / 4,194,304 bytes in 4.989702030s;
measured schedule wait 2.603112970s and HTTP/ACK work 2.386545239s. The receipt
JSON is 194 bytes before its newline, below unchanged 2048B. Full ignored-helper
race suite passed in 18.920s. The actual full-volume Write+Flush handler took
576.996951ms wall, and the direct sixteen-batch client 3.786846030s wall. Those
are synthetic loopback measurements, not native collector or CPU performance.

Parent decoding still rejects extra JSON, unknown fields and injected parent
receipt/client timing fields. New wait/work durations must be nonnegative,
nonoverlapping within child elapsed; child elapsed is capped at the unchanged
8.5s phase plus existing 250ms process-join allowance. A success still needs the
original phase live and positive measured wait/work, exact bytes/writes and last
ACK. Valid partial failure diagnostics remain retained. Parent elapsed remains
measured by the parent, never accepted from child JSON. Focused receipt/cancel/
target/size races passed in 1.208s.

Final pure selection passed all 15 named top-level pacing tests in 14.952s,
explicitly excluding real PostgreSQL/Kubernetes cases and removing external
fixture descriptor variables. Canonical pre-push exited 0 (218 console tests).
The cgo-free helper built with the runner's `-trimpath -buildvcs=false` flags on
Go1.27.2 linux/amd64; local binary SHA-256
`b61b5cc588bd993eea874c5520b9ea85628a9a4a570e6805c63affaa6e077e7e`.
No Kind probe or hosted rerun occurred. Root must review/freeze and coordinate
one owned-route probe after the shared external slot is free; installed native
capture/download qualification remains pending.

### Owned traffic-route probe on the candidate

The single authorized probe on frozen `5fdcad4f` passed with exact selection
`^TestNativePacingTrafficWithRealKubernetes$`: test 5.22s, Go 6.279s, actual runner
exit 0 in 69.714s including setup/teardown. All 3,231 source hashes independently
matched, sourceUnchangedDuringTest=true and cleanupFailures=[]. Exact owned Kind
node, Pod UID/IP, original node UID/boot and serialized helper SHA were checked.
The node used the expected `b61b5cc5...e077e7e` cgo-free helper, not a replacement.

The actual owned-node command acknowledged sixteen batches / 65,536 records /
4,194,304 bytes in 3.811040756s parent wall and 3.772793883s child wall. The child
measured 3.440206167s schedule wait and 0.332554706s HTTP/ACK work (not CPU).
Common ownership/copy/hash setup took 0.138701815s and copied 11,293,387 bytes
onto the one owned node. No collector, BPF, Gadget, native artifact or download
participated; this proves the finite traffic route only. Installed near-full
recording, owner and >5s paced native download still need their guarded run.

The cache archive `native-traffic-tail-owned-kind-1/results` preserves all generated
results before restoration. Environment SHA-256
`99489e5ce1fc884af85407b104b0fc45ecbce663c4c4c07b56f187c10f2f09b0`;
probe SHA-256 `ce770b779668c222252e78aa2738c8d4b083c2410ca5240982afc833b3d85632`.
After terminal archival, independent checks found no run-labelled containers,
networks, volumes or images, no owned Kind node/cluster, and neither exact owned
network remained. Generated repository results were restored only after archival.
