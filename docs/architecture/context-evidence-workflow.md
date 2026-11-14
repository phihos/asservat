# Capture → evidence details → native download

Wiring map under REQ-UI-001/003, REQ-DLD-001–004, REQ-MCP-005 and S-02. Scope
starts with approved pod-status metadata; every later artifact mechanism brings
its native download. UI code contains no kind or debugger allowlist.

## Developer flow

After publication, capture progress carries a separately authorized `case_id`;
the console links only that ID to `/cases/<uuid>`. `get_case` returns current
authorized metadata and artifacts; no access returns a nondisclosing
unavailable screen. Each authorized artifact has Download.
`download_artifact(action=prepare)` uses an idempotency key; Preparing shows no native
size, checksum or filename. Ready metadata supplies native format, length,
full SHA-256, coverage, current retention and an authenticated same-origin
content path. The browser saves the bytes directly from that path, without
JavaScript buffering or MCP. Local-tool use is the developer's choice.

Downloads state that local copies are outside automatic deletion. Missing raw
grant, expiry and unavailable services are shown, never replaced with a fake
download. Raw and shared artifact authority are prerequisites for those
branches; a generic renderer does not turn a context-only backend into raw
support.

## Components

| Step | Source | Design |
| --- | --- | --- |
| Capture progress | `internal/application/capture/context_progress.go` | C-09 `ContextCaseNavigator` asks C-16 for ordinary case access and returns no link on failure ([context progress](context-progress.md)). |
| Case metadata | `get_case`, `list_artifacts` in `specs/contracts/mcp-tools.json` | C-16 reads the published-only case locator with one authorization per operation ([context cases](context-cases.md)). |
| Download authority | `internal/application/authorization/download.go` | `ContextDownloadAuthority` checks eligibility, retained audience, client and stored retention once per operation. Raw/share paths deny until implemented. |
| Session and reservation | `internal/application/evidence/download.go`, `internal/adapters/postgres/download.go` | [Download control](context-download-control.md): idempotency key, workload counter, session row and audit row in one transaction. |
| Native metadata and bytes | `internal/application/evidence/context_download.go` | Regional reader Deployment (A-READ) over the connector connection; the hub holds no unwrap key ([native exchange](native-exchange.md)). |
| HTTP attachment | `internal/transport/browser/download_delivery.go`, `download_range.go` | Authenticated GET, authorization before headers, range selection, no compression, run to original bounds ([ADR-312](../decisions/312-started-downloads-run-to-original-bounds.md)). |
| Cancellation and status | `CancelDownload`, `LookupDownload` | [Shared operations](public-context-download.md) and Stop; status changes are pushed by SSE / MCP bounded wait. |

## Canonical meanings

- The `get_case` / `list_artifacts` descriptor `digest` is the immutable
  artifact version (for pod-status, the ciphertext-copy receipt digest), not
  the native file SHA-256. Only download metadata supplies the native SHA-256.
- Download status distinguishes Preparing from pending query results; the UI
  never invents a download ID or metadata.
- A browser attachment save is not checksum verification. The UI shows the
  full SHA for local verification and reports server-sent bytes, not local
  persistence.
- A hard reload does not mint another preparation key for an unacknowledged
  preparation.

## Console

The `/cases/<uuid>` shell lazily loads `web/src/evidence`, which uses the
canonical `get_case` and download prepare/get/cancel contracts through the
same-origin CSRF transport. **View evidence** appears only for a returned case
ID. A tab may run several downloads in parallel (for example a core and its
companions); server concurrency slots and the reader's busy status bound load.
The original artifact/session/key receipt is retained for the same user, and protected metadata clears on scope
loss or sign-out. No local or session storage is used.

Only verified Ready metadata creates the same-origin attachment link; there is
no Blob, base64, storage URL or local-tool launch. A full restart is labeled
separately from range resume. Completion is described as a recorded transfer,
not local persistence.

Status arrives over the page's SSE stream; the console sends no status polls.
An idle row removes its Download button at the returned `expires_at` using a
local timer that performs no network request and renews nothing.
