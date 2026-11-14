# Production console

C-20 owns `web/`, `internal/console` and the browser transport. This
implements the session boundary and pod-status authoring/progress part of
REQ-UI-001/003/005/007 and TASK-07/08 under
[ADR-046](../decisions/README.md) and ADR-330. The interactive design prototype
remains a separate artifact. Sessions are described in
[browser sessions](browser-sessions.md).

## Build and delivery

`web/package-lock.json` pins the React/TypeScript/Vite build, React Aria
controls and test tooling. `make console-install` installs that lock with
dependency lifecycle scripts disabled. `make console-check` checks contract
generation, TypeScript and behavior tests; `make console-build` produces
`web/dist`. Node and npm are build/test dependencies only; production never
runs the Vite development server ([Vite production build](https://vite.dev/guide/build)).

`console.New(origin, files)` snapshots the image-owned bundle at startup. It
accepts an exact HTTPS origin and a complete local Vite bundle and rejects
extra files, symlinks, source maps, remote entry-point references and
malformed packages. The handler serves `/`, `/captures/new`, `/policies`,
`/shares`, `/captures/<uuid>`, `/cases/<uuid>` and hashed assets. It never
substitutes HTML for an unknown API, authentication, download or console
route.

The shell and errors are `private, no-store`; hashed assets are immutable.
Responses forbid framing and referrers, restrict connections and executable
resources to the same origin and allow no `unsafe-eval` or `unsafe-inline`.
The fixed React Aria pressable CSS is allowed by its SHA-256 CSP hash.

Operation request/response types and validators are generated at build time
from the canonical OpenAPI files. AJV compiles standalone validators; the
browser compiles no schemas, fetches no remote schemas and evaluates no
generated code at runtime. Generation drift fails `console-check`. Responses
are schema-validated before display. The browser sets no client-side
response byte ceiling; server pagination and SSE bound response size.

## Session state in the browser

The tab reads `/auth/csrf`, then POSTs `/auth/refresh` with the CSRF token;
the browser supplies `Origin` and the HttpOnly cookie, and JavaScript never
sees provider tokens. Redirect following is disabled for these calls.

Session changes (logout, revocation, expiry) and operation progress arrive on
the page's Server-Sent Events stream (ADR-330 D1); the console does not poll.
The view is cleared at the fixed session expiry, on a session-ended event and
on sign-out before any network work. A changed identity replaces the
abortable data scope: in-flight requests are cancelled, protected caches
cleared and late results discarded. There is no localStorage, IndexedDB,
service worker, evidence cache or provider credential in the console. The
server authorizes every operation once (ADR-311); the browser's view of the
session is presentation state, not authority.

## Investigation workflow

The form takes a registered cluster, namespace, workload kind and name and
calls the shared `list_diagnostics`, `preview_capture`, `request_capture` and
`get_capture` operations. The supported preset is `pod-status/v1`; other
diagnostics cannot silently become pod status.

Users keep the administrator default retention or request a shorter finite
duration. The preview (ADR-330 D9) is a dry run that returns the resolved
plan and its digest. Review shows the selected Pod and workload, one-pod
selection, the output bound (the 2 MiB Kubernetes API response cap), unmeasured resource impact, possibly
retained user data, access/deletion ages and local-copy limits. Disabled
collection, blockers and unsupported approval cannot be overridden in the UI.

On submit the console generates one idempotency key and sends it with the
plan digest (ADR-330 D7). It keeps the key, digest and user draft in memory
until the server acknowledges the request. Any uncertain failure keeps them;
retry sends the same key and digest and returns the stored outcome. If the
plan changed, the server reports what changed and the user reviews again.
Editing the request discards the key and starts a new preview. Errors show
canonical remediation; untrusted HTTP or provider error bodies are never
shown. A known capture is reachable by its UUID route and survives reload.

Progress renders the durable phase and revision from the SSE stream,
distinguishes Pending from Finalizing, ignores decreasing revisions and
clears status when the stream reports the capture unavailable. The view offers
no cancellation, case viewer or native download until those workflows exist;
it does not advertise unavailable actions. Native download for every artifact
remains a required workflow.

Grouped recording saves use the same `request_capture` request timeout as MCP
([ADR-268](../decisions/268-grouped-save-dispatch-window.md)); a new group
selects its start time once within the request
([ADR-269](../decisions/269-original-grouped-save-request-bounds.md)).

## Verification

`make console-browser-check` serves the built assets from a loopback HTTPS Go
server with real browser/session/investigation transports over synthetic
services. Playwright covers login, CSRF, refresh, logout, revocation, expiry,
review, same-key retry, progress and route reload; Axe checks desktop and
narrow layouts. The check fails on external requests, CSP violations and HTML
fallback on API paths. Set `ASSERVAT_CHROMIUM` to use an installed browser.
Results are recorded in [implementation progress](../implementation-progress.md).
