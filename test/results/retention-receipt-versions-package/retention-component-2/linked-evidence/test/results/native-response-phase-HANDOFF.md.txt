# Native response metadata/content phase boundary

Five paths frozen in manifest.json/work; live sources unchanged. No new wire, migration, current-identity extension or worker reconnect behavior.

The real SQL45 fixture now completes preparation and metadata observation, but content attaches with about one second remaining in the original metadata identity interval. DownloadResponseTransfer reused that same batch. It now joins/closes the successful Describe batch and obtains a fresh reader batch plus ordinary current authorization before admitting the response. Immutable verified metadata stays fixed; current retention dates and original session/request/connection bounds are intersected. Changed principal/client, authority denial or cancellation causes no response reservation. Describe is never repeated to manufacture success. The initial source observation must still finish within its original interval.

The integration fixture replaces its deliberately one-use ReaderIdentity fake with the actual NewBrowserLiveReader over the already explicitly synthetic session store; no personal credential is forwarded or manufactured. Initial synthetic reference is used only to seed that fixture store. The body mismatch diagnostic also includes the actual transfer error so future failures are not hidden by the zero-byte symptom.

Qualification:
- before.log: test-only overlay against live coordinator fails all five new phase tests (exit 1). Success case reports download authority/session expired; changed rights wrongly admits response before failure. These simulate four seconds of completed metadata work followed by two seconds of content work.
- after-race.log: GOMAXPROCS=2 TMPDIR=/home/phil/.cache/asservat-build/tmp go test -p 2 -race -count=1 -overlay <stage>/overlay.json ./internal/application/evidence ./internal/transport/native ./internal/transport/browser; terminal exit 0, package times 1.549s/1.865s/2.980s.
- compile.log: same overlay, go test -p 2 -run '^$' ./test/integration; compiled, no external tests executed.
- vet.log: same overlay, go vet -p 2 on those four packages; terminal exit 0.
- Preserved *-incomplete-test-source.log records the first regression fixture missing its mandatory delivery-ack facet; corrected with an explicit compile-time CurrentNativeResponseSource assertion before the actual before/after runs. No production correction depended on that initial test mistake.

Next: parent hash-review/apply, run exact TestContextAdmissionWithRealServices/download-worker-native-exchange under frozen source and retain terminal cleanup. Current code tests do not prove the SQL45 native content flow passes. All original per-conversation <=5s limits remain; this is not generic large-artifact throughput qualification. Continue ADR122 private listener and installed native read composition afterward.
