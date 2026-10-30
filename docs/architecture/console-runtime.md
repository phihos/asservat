# Production console session boundary

C-20 owns `web/`, `internal/console` and the browser transport. This implements
the session boundary and initial pod-status authoring/progress part of REQ-UI-001/003/005/007 and TASK-07/08 under
[ADR-046](../decisions/README.md). It does not complete S-02 or enable
the public investigation service. The interactive design prototype remains a
separate artifact.

## Build and delivery

`web/package-lock.json` pins the React/TypeScript/Vite build, React Aria controls
and test tooling. `make console-install` installs that lock with dependency
lifecycle scripts disabled. `make console-check` checks canonical contract
generation, TypeScript and behavior tests; `make console-build` produces
`web/dist`. Node and npm are build/test dependencies only.

`console.New(origin, files)` snapshots a bounded image-owned filesystem at
startup. The constructor accepts an exact HTTPS origin and a complete local
Vite bundle. It rejects extra files, symlinks, source maps, remote entry-point
references and malformed packages. The handler serves the currently implemented
`/`, `/captures/new`, `/policies`, `/shares` and exact UUID `/captures/<id>` and `/cases/<id>` shells and exact hashed assets. It never substitutes HTML for an unknown
API, authentication, download or console route. Bootstrap must compose those
handlers explicitly and qualify any separate TLS termination boundary.

The shell and errors are private/no-store; hashed assets use immutable caching.
Responses forbid framing and referrers, restrict connections and executable
resources to the same origin, and require no unsafe-eval or unsafe-inline. The
reviewed fixed React Aria pressable CSS is allowed by its exact SHA-256 CSP hash;
other runtime-injected styles are not implicitly allowed. Dependency changes
must retain browser qualification. This is a presentation constraint, not proof
that the release package or its dependencies are trustworthy.

Vite's [production build](https://vite.dev/guide/build) produces packaged static
assets for the Go handler. Production never runs the Vite development server.

## Session behavior

`BrowserSession` coordinates in-memory UI state, not application authorization.
The initial/returning tab reads `/auth/csrf`, then sends an empty-body POST to
`/auth/refresh` with the returned CSRF token. The browser supplies Origin and
the HttpOnly cookie; JavaScript never receives provider tokens. Automatic
redirect following is disabled for these fetches. Responses have a ten-second
deadline, a 32 KiB decoded-body ceiling and schema validation before display.

Investigation operation responses retain their existing bounds. The passive
`preview_recording_save` result has a dedicated 128 KiB decoded-body ceiling for
16 complete source assessments; `get_capture_settings` retains its existing
160 KiB browser view. The server validates these named result bounds, preserves
original identity/deadline checks and buffers writes before disclosure. Inventory
and other metadata requests keep their existing budgets.

Session, CSRF and the five implemented investigation operation types/validators
are generated from the existing canonical OpenAPI files. The build-only adapter
resolves external schema identifiers and fragments against the closed local
contract registry. AJV compiles standalone validators at build time; explicit
ESM helper imports let Vite bundle their small runtime helpers. Unrecognized
CommonJS helpers fail generation. The pinned helpers' CommonJS default export
is normalized across native ESM, the test runner and Vite; `console-check` runs
positive and negative validator checks in native Node ESM as well as component
tests. This retains the actual schema constraints and avoids a test-transform
interop success hiding a broken production validator. The browser does not compile schemas, fetch
remote schemas or evaluate generated code dynamically. Generation drift fails
the console gate; no library or schema service is added at runtime.

Concurrent session checks share one in-flight operation. The controller checks
current identity at least once per minute while active and independently clears
the view at the fixed server expiry. A refreshed response cannot extend an
already observed deadline for the same active principal. Failed checks remove
protected content and provide retry and local sign-out. Background/page-cache
transitions hide the protected view before a new current check. Initial
`pageshow` does not duplicate the initial refresh.

Every successful identity refresh replaces an abortable data scope; consumers
must cancel scoped requests, clear protected caches and discard late results.
This supplements current server authorization and does not turn a minute-old
browser observation into a disclosure lease. There is no localStorage,
IndexedDB, service worker, global evidence cache or provider credential in the
console. Future authoring can retain harmless drafts for the same current user
while clearing protected results; no resource title or audience is inferred
from an identity-only session response.

The investigation controller retains the user-entered target/retention draft,
an eligible reviewed preview's UUID/original expiry, and a bounded in-memory
request receipt for the same user when the session scope changes. The receipt contains only preview/capture UUIDs, the original
idempotency key, last observed status revision, and acknowledged closed disposition. Catalog, review and progress
projections are removed immediately. New-user login or sign-out clears the
controller. After a same-user refresh, users can explicitly continue the same
reviewed request without another preview, with current server checks; no old
target/assessment metadata is redisplayed. Original preview expiry still binds.
Hard reload cannot recover an unacknowledged receipt; the UI says
to keep the tab open. A known capture uses its authenticated UUID progress route
and can be reloaded without submitting another capture.

Sign-out clears the view before network work. CSRF retrieval/local logout still
work during settings outages. An unknown logout outcome says the server session
may remain active and offers retry; it never claims success or silently reopens
the workspace when the tab returns. Generation checks reject late pre-logout,
pre-expiry and replaced-request results even if a transport ignores abort.

## Initial investigation workflow

The production React view accepts an explicit registered cluster UUID,
namespace, workload kind and name. This transitional form does not claim to
provide authorized inventory search. It calls the actual shared
`list_diagnostics`, `preview_capture`, `request_capture`, `resolve_capture_request` and `get_capture` routes;
no catalog, target, history or progress fixture is packaged into the application.
The narrow supported preset is `pod-status/v1`, not `incident-context/v1` or a
CaptureProfile. Other returned diagnostics cannot silently become pod status.

Users can retain the administrator default or request a finite shorter access
duration. Review shows the independently selected pod and workload identity,
one-pod selection, configured 4 KiB output limit, unmeasured resource impact,
potentially retained and transient user data, relative access/deletion ages and
local-copy limits. After the assessment's five-second deadline, its age is
informational: the same reviewed preview remains submittable through its
original at-most-five-minute expiry. Submission reacquires current conditions
on the server without changing reviewed scope. No five-second reading/click
deadline or automatic replacement preview is introduced. Actual preview expiry
requires an explicit new review; refresh may select a different pod.
Disabled collection, blockers and the unsupported approval workflow cannot be
overridden by the UI.

Submission saves its original preview/key receipt in memory before I/O. All
uncertain failures retain it, including errors denying the latest attempt
without proving an earlier attempt absent. Explicit retry sends the same
preview and key in both body and required header; it never re-previews or
generates a replacement key. Bounded canonical errors supply remediation;
untrusted HTTP/provider error bodies are never shown. Acceptance triggers a
status read; it is not reported as new Pending work or successful evidence.

An uncertain request also offers **Resolve before editing**. This explicit call
uses the original preview/key and can only return the accepted operation or
acknowledge durable closure of the unaccepted reviewed request. Acceptance opens
progress; it never offers another collection. Closure removes protected review
metadata and offers **Edit request**, which restores only the user-entered draft.
Editing does not fetch a new preview, mint a key or submit automatically. Ordinary
errors and a lost closure reply retain the original receipt and both retry paths.
Accepted receipts win over late replies; scope replacement discards stale responses.
A same-user session refresh retains acknowledged closure, while logout or identity
change clears it. The server's resolution path remains available under current
`evidence:read` and original actor/client ownership when collection is disabled.
Returning accepted metadata also requires current original-target read rights;
closing an own unaccepted draft does not. No capture capability or running pod
is needed for closure.

Progress renders authorized durable phase/revision, distinguishes Pending from
Finalizing, rejects decreasing revisions within the tab and clears old status
after an unavailable read. Refresh uses the server's bounded retry delay and
stops at a terminal phase. This view has no cancellation, case viewer or native
download action because those public workflows remain unimplemented; it cannot
advertise unavailable actions or fabricate their links. Native downloads for
every artifact remain a required subsequent product workflow.

## Qualification boundary

`make console-browser-check` starts an owned loopback HTTPS Go server, serves the
actual built assets and composes real browser/session/canonical investigation
transports with explicitly synthetic session and typed capture/progress services.
Playwright drives login/CSRF/refresh/logout, unavailability, revocation, fixed
expiry, bounded review/retention, stale review, uncertain same-key replay,
Pending/Finalizing progress, accepted resolution, uncertain closure replay, explicit editing after acknowledged closure and exact route reload. Axe checks desktop and narrow
layouts. It verifies absence of external requests, runtime/CSP violations and
HTML fallback on API paths. The test requires an installed test browser; set
`ASSERVAT_CHROMIUM` for an existing compatible executable. It downloads no
browser and starts no external identity provider.

Results and actual failures are recorded in
[implementation progress](../implementation-progress.md). This qualification
does not replace the real Keycloak/SQL/KMS suite, participant testing, manual
accessibility checks, protected deployment, or the complete investigation
workflow. These fixtures do not qualify SQL admission, Kubernetes collection,
evidence publication or protected installation. Missing backend composition
remains an explicit unavailable operation in the UI.
