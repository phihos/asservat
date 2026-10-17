# Built-browser native restart qualification

Two new test files; no product, schema, public contract, generated asset, or existing journey changes. The existing evidence browser journey is preserved.

- `test/integration/console_native_restart_test.go` supplies a finite synthetic C14/session/file service behind the actual Go HTTPS session, current-request, CSRF, investigation and canonical presentation composition.
- `web/tests/native-restart-journey.mjs` drives the actual built React console with Chromium. It uses native anchors and the browser download API, not route interception, a JavaScript Blob, or mocked fetch.

`manifest.json` contains exact new-file hashes and null bases. `base-hashes.json` and `dependencies.json` are objects. All 1,489 dependencies matched the live tree at freeze. The passing run independently recorded 1,492 unchanged live/staged source and built-asset hashes. `built-assets.json` identifies the four isolated production assets; assets are evidence only and are not an integration payload.

## Qualified behavior

The initial actual native attachment sends a short body under the full Content-Length and closes. Chromium reports a failed download; the backend and visible page remain Ready, without an operation error. After the original explicit link click, the page exposes **Start a new download** and this exact copy:

> Starts the browser download from the beginning and stops the previous request. Both attempts count toward your download limit.

The fixture records the first Stop, validates the canonical result, sends only one byte of its JSON body under the exact full Content-Length, flushes, and closes the actual connection. No new preparation follows the lost result. A second explicit restart replays the original Stop key. Only its exact positive minimal receipt permits the one new preparation key. That newly accepted response is lost through the same partial-body boundary. **Retry same download request** reuses the new key, without another session or Stop. Server counters prove no content request occurs through either uncertainty/reconciliation phase. The second explicit anchor click alone requests the new path, and Chromium receives the complete expected synthetic body.

The browser may internally retry the broken original attachment. Every original-path request remains counted against the fixture's fixed total ceiling of four; the test permits at most three original GETs plus the one final new-path GET. Page network events are not used to count attachments. Actual download events/failure, exact anchor hrefs, explicit clicks, visible requested status and server counters establish the relevant boundaries. This does not claim retries are free, refunded or remotely Joined.

Two axe scans pass with no selected WCAG violations. CSP, external-page-request and web-storage assertions pass.

## Actual checks

| Handle | Command / scope | Exit |
| --- | --- | --- |
| 64533 | New integration selector source compile, browser gate absent | 0 |
| 76358 | Isolated production `npm run build` (generated checks, TypeScript, Vite) | 0 |
| 31153 | Actual browser/race: first test assumed one GET; Chromium made a same-path retry | 1 |
| 83426 | Actual browser/race: server retries did not all appear in page request events | 1 |
| 90157 | Actual browser/race: attachment emitted no page request event | 1 |
| 98742 | Actual browser/race: pre-header abort did not reliably expose lost new-prepare reply; page became Ready | 1 |
| 91010 | Final actual browser/race, partial-response loss and authoritative server counters | **0** |

All five browser run environment reports state source unchanged. The parent diagnostic-label edit was already present before 83426's snapshot. The final browser test took 2.92 seconds; its Go/race package completed in 3.981 seconds. All owned test/browser/server processes joined. No additional broad Go gate or standalone full vet was run; the final `go test -race` retained its default vet behavior.

The four failed runs and their exact source/report snapshots are preserved as evidence, with Go source archived as `.go.txt`. The fourth run did not capture enough server counters to attribute the unexpected successful reply conclusively; it establishes the fixture's earlier abort boundary was nondeterministic. The final failure-report path now includes bounded server counters.

Final engine: Google Chrome for Testing 153.0.8010.12, SHA256 `ded93a9c9a53a1ae040f08124badcca95c938e9d5015ff340c3b5538c41bf39e`. The tested executable path and complete command are in `evidence/browser-fifth-environment.json`.

Final staged invocation:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/planning/console-native-restart-20261012/tmp \
ASSERVAT_CONSOLE_BROWSER_TEST=1 \
ASSERVAT_CONSOLE_RESTART_ROOT=/home/phil/.cache/asservat-build/planning/console-native-restart-20261012/work \
ASSERVAT_CHROMIUM=/home/phil/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell \
go test -race -overlay=/home/phil/.cache/asservat-build/planning/console-native-restart-20261012/overlay.json \
-count=1 -run '^TestConsoleNativeRestartWithBuiltPackage$' -v ./test/integration
```

After integration, build `web/dist` normally and omit the overlay and `ASSERVAT_CONSOLE_RESTART_ROOT`. That optional variable is a test-only isolated asset/report root, not a product setting. The fixture requires an owned loopback HTTPS listener, uses a 90-second original test context, bounds Node output, and joins/kills its owned process group on cancellation.

## Scope and next step

This qualifies actual packaged React/browser/Go transport behavior with synthetic browser identity, C14 state and file bytes. It does not qualify SQL, encrypted audit, an IdP, regional workers, installed production authority, physical file persistence, or encrypted native range/interruption recovery. Those remain distinct parent-owned native selectors. Parent can integrate the two files and preserve the existing journey unchanged. There are no live changes or active build handles from this package.
