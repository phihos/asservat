# Capture → evidence details → native download: wiring map

Source inspection dated 2026-10-11. This is a staged next slice under
REQ-UI-001/003, REQ-DLD-001–004, REQ-MCP-005 and S-02; no public runtime
activation or completed native flow is implied. Scope is ordinary approved
pod-status metadata first. Every later enabled artifact mechanism must bring
its native download; UI code must not contain a kind/debugger allowlist.

## Developer flow

After actual publication, capture progress may include a separately authorized
`case_id`. The console links only that ID to `/cases/<uuid>`. No case/artifact
ID is guessed from the capture or exposed from internal candidate fields.
`get_case` returns current authorized metadata and artifacts; absent access or
uncomposed service returns a nondisclosing unavailable screen. Each authorized
artifact has Download. The existing `prepare_artifact_download` operation uses
an original idempotency key; Preparing shows no invented native size, checksum
or filename. Ready metadata supplies actual native format, length, full SHA-256,
coverage, current retention and an authenticated same-origin application path.
The browser saves native bytes directly using that path, without buffering them
in JavaScript or sending them through MCP. It never claims local disk success
from an HTTP/status result. Compatible local tools are the user's choice.

Downloads state plainly that local copies are outside automatic deletion.
Missing raw grant, expiry, service unavailability and disabled native runtime
must be visible, never replaced with a fake successful download. Current
covering grants should be reused by the real coordinator. Raw and shared
artifact authority remains a prerequisite for those backend branches; a generic
UI renderer must not turn a context-only backend into support for raw artifacts.

## Existing components and concrete missing connections

| Step | Existing source | Required composition / remaining work |
| --- | --- | --- |
| Published capture progress | `internal/application/capture/context_progress.go`, `internal/adapters/postgres/context_progress.go` | The concrete C-09 `ContextCaseNavigator` now independently invokes C-16 ordinary case access, preserves original deadlines and returns no link on failure; protected runtime composition remains pending. Succeeded alone is historical publication, not current evidence readability. |
| Case/detail metadata | Canonical `get_case` and `list_artifacts` in `specs/contracts/mcp-tools.json`; browser equivalents already defined | ADR-109 now supplies the C-16 coordinator, immutable published-only SQL locator and shared browser/MCP mapping. The bounded exact-case lookup checks current identity, complete denies, original retained audience, effective retention and recovery before schema-valid descriptors/handling notice. Pre-disclosure operation auditing and protected mounting remain pending. Shared view needs its own explicit-share facet; no ordinary-only fallback. Do not use upload/custody rows as published evidence. |
| Verified context catalog | `internal/adapters/postgres/context_publication.go: ContextPublications.ContextDownloadEvidence`, interface `internal/application/authorization/download.go: ContextDownloadCatalog` | Existing SELECT projection validates published/verified/audited context, original scope, ciphertext version and retained origins. It is an internal observation, not public authorization. Public artifact-ID resolution must acquire trusted target/scope internally without disclosing an existence oracle before rights. Native filename/checksum are deliberately absent. |
| Ordinary current download authority | `internal/application/authorization/download.go: ContextDownloadAuthority.CheckDownloadCurrent` | Reuse request-owned current identity; checks ordinary target eligibility, original audience, retained policy proofs, client and final rights. It supports approved context only. Raw/share/grant paths are not implemented and must deny rather than relabel artifacts. Current `DownloadEnvironmentReader` has only fixture implementations: protected regional/client/processing restrictions and recovery composition are missing. |
| Transfer reservations | `internal/application/evidence/download.go`; `internal/adapters/postgres/download.go`; `internal/application/capacity/download.go` | The [context download coordinator](context-download-control.md) and [shared browser/MCP operations](public-context-download.md) now bind current actor/client, exact artifact version, finite deadlines and trusted allocations. Protected per-workload allocation/backing production and upload-priority scheduling remain missing; the internal SQL reservation is not public authority. |
| Native metadata preparation | `internal/application/evidence/context_download.go: ContextDownloadWorker.Prepare`; `internal/adapters/objectstore/context_native.go` | Run in regional acquisition role, never public hub. Preparation is charged, independently audited decryption; actual SHA/filename/coverage must not be synthesized from SQL. The [regional result owner](context-download-result.md) now retains an acknowledged result for fresh authorized metadata reads without another decrypt. The [native exchange](native-exchange.md), v2 [worker startup](worker-startup.md) and optional [owner listener](native-owner-listener.md) now implement bounded transport components. Their selected real-service tests retain synthetic installation authority; complete protected worker/connector provisioning and the installed response channel remain pending. |
| Purpose-separated Job lifecycle | `internal/application/evidence/download_dispatch.go`, `internal/adapters/postgres/download_workers.go`, `internal/adapters/kubernetes/download_jobs.go` | Dispatcher, exact lost-create reconciliation, termination/retirement and admitted profile bindings exist. Selection of current protected profile/environment and actual public preparation/session orchestration remain missing. |
| Worker identity/routing | `internal/bootstrap/download_worker.go`, `internal/application/evidence/worker_runtime.go` and peer/owner routing packages; `docs/architecture/worker-routing.md` | `RunDownloadWorker` preserves credential-only v1 and explicitly composes credentials plus native exchange in v2. Actual Restricted-Pod startup/idle and separate SQL/S3/TLS byte-transfer tests pass. Connector process-owned client/server issuance, renewal, protected projections and the complete installed worker path remain pending; the hub receives no unwrap key. |
| Audited verified native bytes | `internal/application/evidence/context_download.go: ContextDownloadWorker.Transfer`, `internal/application/evidence/context_native.go`, `internal/adapters/objectstore/context_native.go` | Existing worker verifies complete ≤4096-byte pod-status content, encrypts audit and withholds the final batch until integrity passes. The request-owned native attachment now mediates current human authority through process-local callbacks and fresh identity observations, including separate metadata/content phases. Actual byte tests retain explicit synthetic human/Pod/bootstrap inputs; protected public composition remains pending. Other mechanism workers need qualified streaming/range/read-work implementations before enabling them. |
| HTTP attachment | `internal/transport/browser/download_delivery.go`, `download_range.go` | `HTTPDownloadDestination` is a final sink, not an authenticating route. Need exact HTTPS browser/OAuth GET ingress, current client/download authority, effect/relay admission, range selection before accounting, no buffer/compression, cancellation and after-header abort. Never register ContextNativeReader or the sink directly. |
| Cancellation/status | `Downloads.CancelDownload`, `LookupDownload` and intent/outcome accounting | [Shared get/cancel operations](public-context-download.md) now enforce current identity, minimized status and separately prepaid Stop audit. [Positive Stop retirement](download-stop-lifecycle.md) passes selected real SQL/storage tests while retaining uncertain charges. The installed active-stream cancellation journey remains required; a SQL state change alone does not prove that a socket stopped. Unknown requests keep their original keys and charges. |
| Public UI/MCP | Existing canonical prepare/get/cancel and content endpoint contracts | New UI uses these unchanged real wire schemas with explicit unavailable states. MCP must not advertise tools until their real application service exists; no file bytes, storage URLs or credentials in tool results. Authenticated content paths are navigation, not bearer access. |

## Minimum parent implementation order

1. ADR-109 now implements ordinary context `ContextCaseNavigation`, the current
   exact-case metadata service and browser/MCP mapping. Complete combined native
   qualification, operation auditing and protected runtime composition before
   enabling this path. Native download production composition remains separate.
2. Connect the existing public prepare/get/cancel coordinators to installed
   exact-artifact resolution, protected allocation/environment/backing producers
   and separately credentialed ledgers. Return unavailable before effects if
   native dispatch/relay is absent.
3. Complete protected connector client/server identity and renewal, acquisition
   projections and native preparation/content composition under request-owned
   authority; then mount the authenticated content route. Reuse the existing
   purpose-scoped key bindings, writer accounting, native listener and current
   catalog/retention/recovery gates. Do not mount an unwrap root in the hub.
4. Qualify one actual context capture → publication → details → native file
   through browser and OAuth, comparing exact bytes/SHA. Exercise expired and
   revoked access, lost prepare replies, bounded range/retry spend, cancel while
   active and stale metadata. Broader/raw/share artifact paths remain denied
   until their corresponding service/worker/grant qualification exists.

## Canonical observations to resolve in later backend design

- `get_case` / `list_artifacts` descriptor `digest` is the immutable verified
  artifact version. For pod-status it is the existing serialized verified
  ciphertext-copy receipt digest, not native file SHA. Only separately verified
  download metadata supplies the native SHA-256. No digest algorithm changes
  are introduced by documenting this distinction.
- Download status can represent Preparing and pending query envelopes. UI must
  distinguish them and never invent a download ID or metadata. Prefer immediate
  bounded Preparing/session receipt so unknown-outcome recovery remains clear.
- A browser attachment save is not a client-side checksum verification engine.
  Display the exact full SHA for local verification and report server-emitted
  bytes without claiming file persistence or successful local inspection.
- Hard reload recovery of an unacknowledged preparation key is not solved by
  in-memory console state. Do not silently mint another key on a retry.

## Separable console implementation

The console's exact `/cases/<uuid>` shell contains a lazy evidence module.
`web/src/evidence` consumes existing canonical `get_case` and download
prepare/get/cancel contracts through the same-origin CSRF metadata transport;
these generated clients do not register or enable backend tools. The existing
capture view offers **View evidence** only for a currently returned case ID.
Missing backend composition produces an unavailable view without fabricated
artifact rows, progress, native metadata or download links.

The initial view coordinates one active download request per tab. It retains
only the original artifact/session/key receipt for the same user across session
checks; protected case and native metadata clear on scope loss. Unknown
preparation and cancellation remain explicit same-key retries. A terminal
session cannot revive, and starting another download is deliberate. Signed-out
or changed-user state clears receipts; no local/session storage is introduced.

Only verified ready metadata creates an exact same-origin native attachment
link. The browser handles file bytes directly; there is no JavaScript Blob,
base64, native-reader call, public storage URL or local-tool launch. An
interrupted full restart is labeled separately from authenticated-client
range resume. Server completion is described as recorded transfer, never proof
of local file persistence. Local-copy handling/deletion remains the developer's
responsibility. Raw approval and unsupported native mechanism branches need
real services before they can succeed.

Synthetic controller/component tests and canonical validators exercise these
states. They are not proof of SQL authority, worker execution, native byte
integrity, a deployed service or usability with participants. The new lazy
bundle and case navigation now pass the actual Go/browser journey with synthetic
C-16 authority: 16 journeys, 14 accessibility scans and 881 unchanged source/build
hashes in [the report](../../test/results/context-case-browser.json). Native
download is deliberately unavailable in that fixture; no successful file transfer
is fabricated. Combining real catalog authority with production operation audit
and backend delivery remains open.

Ready native metadata stays stable while the developer reads it; the console
checks expiry without repeatedly preparing or polling an untouched ready file.
Explicit start and nonterminal transfer states use bounded status polling.
Status delivery still needs the separately authorized worker metadata channel
identified above; the hub must not re-decrypt evidence on every status read.

An idle artifact row removes its Download button at the already returned
`expires_at` and explains expiry. This bounded local timer neither renews
retention/authority nor performs network polling; it stops when the case view
or current session scope is discarded. Server-side current access checks still
apply to every explicit action.
