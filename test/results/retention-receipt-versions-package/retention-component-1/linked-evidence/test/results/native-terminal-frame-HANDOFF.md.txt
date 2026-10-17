# Native final marker ordering correction

Scope: three paths, exact base/new hashes in manifest.json; no live source writes, SQL/frames/authority lifetimes unchanged. handler.go, new terminal_test.go and native-exchange architecture note only.

The actual SQL/S3 fixture reached worker Joined and consumed all three unwrap slots, then returned native exchange unavailable. This patch fixes a deterministically reproduced transport race consistent with that trace: Send flushed positive Done then started another blocking current-authority check, which normal peer shutdown could cancel. Done now uses begin's current blocking check before writing and original deadline/known cancellation checks around the actual write/flush. All other frames retain post-I/O current checks. Application final metadata authorization, audited preparation commit and conservative uncertainty remain unchanged. A successful marker is transport completion, never a claim of global joined quiescence or local filesystem persistence.

Evidence:
- before.log: real TLS1.3/h2 new regression failed (exit 1): normal peer close invalidated already flushed final marker.
- after-repeat.log: same test passed 100 repetitions (exit 0).
- after-race.log: GOMAXPROCS=2 TMPDIR=/home/phil/.cache/asservat-build/tmp go test -p 2 -race -count=1 -overlay <stage>/overlay.json ./internal/transport/native ./internal/adapters/mtls ./internal/application/evidence; terminal exit 0 (1.859s, 8.514s, 1.539s). New negatives cover known denial, partial Done write, failed flush, and retained data post-write check; existing two-hop cancellation/lost final acknowledgement tests included.
- vet.log: go vet -p 2 with same overlay and three packages; terminal exit 0.

The synthetic current checker supplies only the deliberately blocked observation in the regression; real h2/client/server/flush/closure are exercised. This is not proof the actual SQL/S3 failure is fully resolved. Next: parent hash-review/apply and rerun exact TestContextAdmissionWithRealServices/download-worker-native-exchange using source freeze/terminal cleanup; preserve original failures and diagnostic log. Then continue ADR122 receiver/installed read-only composition. No public native endpoint is enabled by this patch.
