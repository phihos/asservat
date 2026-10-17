# ADR-114: Browser refresh owned by an active download

- Status: accepted design; implementation and native qualification in progress
- Date: 2026-10-11
- Requirements: REQ-AUT-001, REQ-DLD-003, REQ-DLD-004
- Owners: C-02 Identity, C-14 Evidence delivery

## Problem

A native attachment can continue after the console tab closes or is suspended.
Page timers therefore cannot maintain its browser session. ADR-113's live reader
correctly obtains fresh observations without refreshing credentials, but this
alone cannot keep a long download usable across access-token/group expiry.
The existing refresh schedule also considers token expiry and a one-minute
interval without explicitly scheduling ahead of a shorter accepted group age.

## Decision

The authenticated, same-origin, CSRF-protected Download/prepare POST explicitly
admits a bounded server-owned refresh continuation for the original browser
session and accepted download. This is part of the existing Download action;
there is no additional consent dialog. GET, HEAD, status and range retry cannot
create, revive or extend that continuation. The attachment GET stays read-only
with respect to credentials. Native bytes do not pass through a JavaScript Blob.

C-02 retains one local owner/timer per original browser session and a bounded
set of accepted download consumers. Bind actor and client, original session
identity, exact download identity and fixed deadlines. A consumer cannot extend
another consumer, the session, a grant or evidence retention. An explicit
supervisor owns the accepted asynchronous work; a finished POST or console tab
does not own its lifetime. Cancellation and shutdown join all retained work.

Refreshing requires current minimized C-14 demand: a fixed thirty-second
attachment grace anchored to the first explicit POST consumer admission, or an
exact active response generation/owner and its original short delivery lease.
The grace is narrowed by original session, download and retained-access ends;
it permits refresh scheduling, not preparation liveness or evidence delivery.
Polling, replay, status, GET and other consumers cannot renew it. This is an
implementation timeout requiring qualification, not a measured startup guarantee.
Cancelled/terminal downloads and logout deny even during the grace. A stale
Preparing/Streaming label or distant response expiry is insufficient. A due,
already admitted refresh claim may have
a bounded pause while the byte lease expires; no bytes are sent without a new
current lease. Closing the last consumer stops new refresh calls. Work already
admitted to the provider remains bounded by its original claim/session/task
deadline and must be joined. Logout, revocation, settings and recovery checks
still win over a concurrent token replacement.

Reuse the existing server-encrypted tokens, provider adapter and durable one-use
SQL refresh claims. Do not add offline tokens, a provider directory account, a
general job scheduler or per-chunk OAuth calls. Busy claims permit bounded
zero-output waiting. Unknown provider/commit results never permit replay of the
old refresh credential. Replacement tokens must preserve original session and
principal identity; current complete groups replace old groups.

A competing ordinary browser refresh POST must not create an unrelated rotation
claim while a current live owner has bounded download demand. It receives a
temporary busy result and the existing owner performs the due rotation. Browser
handling retains the session and page; busy is not logout or a login redirect.
Waiting/retry remains finite, and a newly stricter current schedule must wake the
existing loop or have an explicitly bounded delay. Once ownership is fenced and
no owned unjoined claim remains, an ordinary explicit POST may refresh again
without releasing owner capacity or recreating download continuation. A stored
owner row or uncertain old claim alone cannot authorize this fallback.

The same verified-claims/current-policy resolution supplies token and group
freshness deadlines for scheduling. Those facts confer no evidence authority
and must not be confused with the at-most-five-second identity observation.
Schedule before the earliest credential/group/session deadline, with a bounded
lead and the accepted provider operating envelope. Current observations may
shorten the next due time; outage or unexpected denial cannot renew old claims.
Unsupported provider latency/group-age combinations must be explicit instead of
silently extending freshness or retrying refresh in a tight loop.

The implementation uses durable session-bound owners and exact accepted-download
consumers alongside the existing SQL refresh claims. Under the browser-root lock,
the union of live session IDs and retained owner IDs consumes the existing
MaxSessions allowance. At most sixteen consumers belong to one session, and
each accepted download has one immutable consumer backed by its existing
allocation. Owners survive session deletion while owned work remains; logout
removes authority immediately without prematurely releasing capacity. Tokens
retain their existing encrypted storage rather than gaining a second copy.

Replacement ownership requires positive joined closure of the previous work.
Lease expiry fences new effects but cannot prove an old blocked provider call
has finished. Process-loss cleanup therefore needs an independently established
termination witness or node/process fence; a Kubernetes 404, expired locator or
forced deletion is insufficient. This recovery path remains implementation work.

After owner-process loss, a GET or startup scan cannot recreate refresh demand.
The transfer may continue only while its existing credentials/authority permit;
an interrupted transfer needs an explicit authenticated Download/resume POST
under the original transfer/grant budget. Automatic owner failover requires a
separately bounded durable admission/ownership design. This is not a promise of
uninterrupted transfer through hub failure.

## Research and design boundary

Checked on 2026-10-11, [RFC 10017 §6.1.2.2](https://www.rfc-editor.org/rfc/rfc10017.html#section-6.1.2.2)
describes server-side token custody and refresh in a backend-for-frontend;
[§6.1.3.3](https://www.rfc-editor.org/rfc/rfc10017.html#section-6.1.3.3) covers CSRF
defenses. [RFC 9700 §4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14)
addresses refresh-token protection, binding and replay. These support the
existing token-custody model; the task ownership, capacities and delivery leases
above are Asservat design decisions, not requirements from those RFCs.

[Keycloak's session timeouts](https://www.keycloak.org/docs/latest/server_admin/index.html#_timeouts)
and [offline access](https://www.keycloak.org/docs/latest/server_admin/index.html#_offline-access)
have different lifetime/logout behavior. This feature uses ordinary online
sessions and remains bounded by the qualified provider configuration.

## Qualification

Reproduce the shorter-group-age scheduling defect. Test deduplication, fixed
deadlines, busy/unknown claims, consumer closure during provider work, capacity
exhaustion, stale demand and process-owner loss. Qualify actual Keycloak, SQL and
encrypted credentials across several refresh periods without page refresh calls,
including group removal, logout, settings shortening and claim races.

Then qualify a browser-native large-file transfer with the initiating page
closed/frozen, with actual response accounting and byte relay. Include prepare
on one hub and content on another, exact provider-call counts, cancellation and
resume. Passing identity-only tests cannot establish the complete download UX.
