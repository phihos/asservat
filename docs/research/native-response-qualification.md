# Remaining native response qualification

Date: 2026-10-27. Status: tested qualification helpers; installed paced transfer and combined costs unrun.

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
provides the finite traffic runner and measured-size gate. The real loopback
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
review `actionMaxBytes=8 MiB`, `packetAfter=10s`, `actionTimeout=20s` and finite
composition limits before approval. No duration changes after acceptance are
allowed. Keep the product's current 8 MiB native cap.
After the exact accepted source reports Running, run sixteen batches of 4,096 flushed 64-byte writes
at 500 ms start intervals. Maximum application payload is 4 MiB; traffic phase
ends after 8.5 s or the earlier original context, with no retry. Record real
capture/traffic timestamp overlap. TCP segmentation, ACKs and PCAPNG overhead are
not predictable from application writes; measure them.

The caller must invoke `nativePacingRequireNearFullRecording`: only measured
native sizes 8,323,072..8,388,608 bytes qualify. A tiny artifact or a byte above the
current cap fails. Record the existing collector's OutputFull/loss counters and
standard PCAPNG interface/drop statistics (using existing verification/tshark,
not a hand-written packet parser). Cap saturation or dropped packets must be
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
whole transfer, a valid range/resume and stale If-Range behavior. Add bounded
revocation and original-request cancellation cases, retaining original deadlines
and conservative spend; require no successful post-cutoff write/ACK. Never
renew a closed identity batch or add per-piece key opening. Preparation and
each response window retain their separate three one-use unwrap slots.

## Phase budget for the disposable runner

Once the current installation/approval/history setup qualifies, reuse it rather
than installing another graph. Reserve twenty seconds for one additional capture:
its reviewed window is ten seconds, action timeout twenty seconds, and bounded
traffic phase 8.5 seconds. Preparation keeps its existing fixed deadlines, with a fixture wait
budget of 60 seconds for its acknowledged continuation; no uncertain POST replay.
Allow 60 seconds total for an unpaced control, paced whole, two resume ranges and
stale If-Range, each under its original request/session/operation bounds. The
expected near-full paced body is about 6.4 seconds at 1.25 MiB/s, not a new
server deadline. Reserve another 60 seconds for joined cleanup and phase
snapshots. Total extra phase allowance is three minutes twenty seconds after the
installation/approval journey, with root selecting the complete runner budget.
No installed run has consumed this budget yet.

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
