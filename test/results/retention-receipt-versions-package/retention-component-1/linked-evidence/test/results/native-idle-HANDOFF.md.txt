# Native idle response correction

Two-path additive package against integrated ADR139. Payloads and base snapshots are immutable. No live edits or external fixtures were run. All own build handles are terminal.

## Reproduction and root cause

The production `native.Serve` listener plus exact `Handler`, valid synthetic `NativeIdle` and actual `mtls.NativeClient` lost the successful no-command reply after exactly one admission. Before session 7342 failed with `native exchange unavailable` (0.119s). Unlike the prior adapter-only httptest case, this test includes the actual socket lifetime wrapper and server callbacks. The new test's issuer, worker and SQL/proof authority are explicitly synthetic; it is transport qualification, not installed authority.

The pinned Go 1.27.2 local source confirms the ordering: `src/net/http/internal/http2/server.go` `startFrameWrite` writes frames into its buffer, `wroteFrame` can call `closeStream`, and `closeStream` calls `ConnStateIdle` before the later frame scheduler flush. The raw socket close from our idle callback can therefore discard the buffered 204/END_STREAM. Sources inspected at `/home/phil/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.2.linux-amd64/src/net/http/internal/http2/server.go` lines 1175–1179, 1200–1256, 1572–1600, 1317–1355; public configuration at `src/net/http/server.go` lines 3790–3806. The comment's idle-after-flush premise was incorrect.

## Correction

Replace that callback with standard `http.Server.SetKeepAlivesEnabled(false)`. The pinned HTTP/2 implementation starts graceful GOAWAY when its stream closes, allowing pending response frames to flush. The existing atomic first-request guard still refuses any additional conversation on that socket. Original accepted-time 10s native / 30s context-start limits, 2s shared prelude, certificate shortening, cancellation and joined purpose/socket reservations remain unchanged. No Handler disposition validation, client retry classification, acquisition or credential authority is changed. Reservations remain occupied during graceful socket shutdown until the socket/handler actually join.

## Checks

`checks.json` and logs contain commands, actual terminal handles and results. Corrected exact regression passed (82532, 1.149s). Focused race checks passed (68227: native 13.669s, mtls 1.125s), including actual shared h2 standby and independent purpose capacity, prelude expiry, original socket deadline refusal, joined closing slots, client exact positive versus generic/malformed/expired no-command responses. Affected existing-package vet passed (60634). The regression verifies three independently opened sockets through one reserved slot, exact original reference/nonce/Until, no stream and exactly one admission per call. The before test was only gofmt formatted before subsequent checks.

## Integration and next check

Verify `manifest.json` bases/payloads and relevant `dependencies.json` entries, then apply only the two listed paths. `changes.patch` is reviewable. Existing frozen ADR139 package remains unchanged. Parent owns integrated checks and the rerun of `TestContextAdmissionWithRealServices/download-worker-native-content-resume`; that actual SQL/native path remains unrun for this correction. Do not count this local synthetic-authority loopback result as the native fixture passing. Resume ADR141 isolated capacity work after the parent's diagnostic priority and source/build hold allow it.
