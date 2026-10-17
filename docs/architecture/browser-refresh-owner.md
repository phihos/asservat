# Browser refresh owned by an accepted download

Owners: C-02 Identity and C-14 Evidence delivery. Implements the normal ownership
path of [ADR-114](../decisions/114-download-owned-browser-refresh.md), alongside
[the connection-owned reader](native-reader-identity.md). This component does not
mount a public route or complete production process-loss recovery.

## Explicit admission and scheduling

`BrowserRefreshOwners.Admit` belongs to the authenticated, exact-origin,
CSRF-protected prepare/download POST. It resolves the original real browser
session without refreshing, checks current identity, and supplies a private
hashed session locator to the concrete PostgreSQL journal. The journal rechecks
current accepted download rights, recovery, effective retention, settings and the
exact serving process through `OwnerAuthenticator`. Human input cannot choose the
process binding or mint a refresh owner. GET, status, startup and worker code do
not call admission. Tokens remain in the existing encrypted browser session;
refresh-owner rows contain no credentials, groups, URLs or native metadata.

A process retains one loop per admitted session, with at most 128 local owners
(including unresolved admission/closing placeholders) and sixteen concurrent POST
admission calls. These are local ceilings, not the global backing. SQL43 counts
the union of live browser-session IDs and retained owner-only IDs under the
existing browser-root lock and `MaxSessions`. A repeated login/logout sequence
cannot erase an owner whose provider work has not joined. Per-subject session
admission likewise includes retained owner actor keys.

One retained consumer row belongs to each already accepted, charged download.
At most sixteen active bindings may belong to an owner. Detached rows preserve
the original first-admission/grace/hard deadlines and remain backed by that
download's existing allocation/session accounting. New owners, polling and replay
cannot reset the first thirty-second attachment grace. Its deadline is narrowed
by the original browser/download/access bounds. It permits scheduling only,
without proving preparation activity or granting bytes. Afterwards scheduling
requires the exact current SQL42 response owner/generation and short lease.
Terminal/cancelled downloads, logout, expiry and unavailable current protection
stop new provider work even during grace.

The loop observes demand and protected policy at most once per second. One
credential verification supplies the original token/group expiry window. Later
policy reads can only shorten it; they do not decrypt a token, replay old groups
or supply evidence authority. Each due attempt performs a full current identity
resolution before the existing one-use SQL refresh claim. Its original at-most-
ten-second deadline is bounded by session, owner, download and retained access.
Failed or unknown provider outcomes do not replay a refresh credential. A new
schedule requiring another attempt within one second stops the owner; this is a
finite unsupported-cadence guard, not a qualified provider-latency envelope.

A competing ordinary explicit refresh POST receives typed Busy only for current
owned demand or an unjoined owned claim. It shortens the persisted due time so the
existing loop wakes within its one-second cadence. Browser Busy handling preserves
the page/session and shares one finite attempt budget across CSRF and POST. It
never treats a possibly completed logout/refresh as safe to replay.

## Waiting during an owned refresh

`BrowserRefreshReader` combines the existing original-connection reader with a
private read-only pause lookup. Generic Busy is insufficient. The lookup binds the
same browser actor/client and exact accepted download/response owner/generation
to the immutable claim version and original claim deadline. It never extends a
response lease or authorizes bytes. Closing the original reader joins active
lookups; retained handles cannot detach cancellation through another context.

Pending permits bounded no-output waiting. Settled is a wakeup only when the
provider call positively joined and a newer credential version committed to the
same session. Its version remains the original claim version. The C14 consumer
retains that first claim/deadline and permits exactly one fresh identity attempt;
repeated Busy, mismatch, denial or expiry stops the response. The new identity
and SQL lease must pass before more bytes. C14's optional consumer is a separate
composition, not implemented by a fake credential or worker identity proxy.

## Transactions and closure

Effect ordering is recovery, browser root/session/owner, permission, then download
state. Current identity, serving-process and retention observations happen before
locks; original intervals are checked again after blocking work. SQL42 never
acquires browser locks while holding its download transaction, avoiding a reverse
lock order. Purpose credentials separate owner admission, normal owner maintenance
and read-only pause observations. Pause session reads use SELECT under the exclusive
browser-root lock. Other session reads/writes take a shared or exclusive lock on
that same root, so this short observation sees a coherent claim and session. The pause role receives no session UPDATE privilege, and its result grants
only bounded no-output waiting. Ordinary browser SQL receives only a minimized
busy function, not evidence-catalog reads.

Logout deletes identity immediately. Its owner record survives until actual local
observations/provider calls join and the historical exact claim/owner closure is
acknowledged. Lease expiry fences effects but cannot refund global or local owner
capacity. Joined owners detach consumers; they can be deleted once the original
browser session is absent. Existing bounded browser cleanup can remove these
positively joined rows. A still-live session retains the monotonic generation.

An uncertain admission starts no provider work. Once the synchronous SQL callback
has returned, exact-proposal abandonment takes the same browser-root lock. Any
already-sent INSERT/COMMIT must settle first, and the returned callback can send no
later statement. Only that server-generated, unclaimed proposal can be closed;
a different/replayed or claimed owner is untouched. Unknown cleanup retains the
same bounded local placeholder and durable charge. A later explicit POST must
resolve that placeholder before generating another proposal. The lock is the
admission fence; timeout or an unlocked absent lookup is not a closure proof.

## Qualification and remaining work

Focused staged Go race tests cover current-policy shortening without another POST,
no extra token verification during schedule observation, exact POST consent,
blocked-provider shutdown joining, logout, unknown closure accounting, immutable
reader cancellation and pending/settled response bindings. They are component
results, not native download qualification.

The actual Keycloak/SQL/OpenBao provider suite passes thirteen named entries,
including rotation without tab polling. The separate selected SQL/S3 case passes
publication/preparation/response-backed owner admission, pending/settled pause,
one-use claims, logout capacity and delayed COMMIT cleanup observed through
`pg_blocking_pids`. Real-service testing exposed and corrected an extended
observation interval, a trigger alias collision and an unnecessary session lock
privilege. The provider helper uses synthetic accepted demand/process observations;
the SQL helper uses synthetic accepted process observations. Neither claims a
deployed end-to-end transfer. Exact logs, source freezes, cleanup and remaining
combined regressions are in [implementation progress](../implementation-progress.md).

Required remaining composition includes the explicit public POST owner attachment,
private routing and C14 pause consumer, provider operating-envelope qualification,
and a browser-native large transfer with its initiating tab closed or frozen.
Production bootstrap must supply current serving-process authority and scoped
SQL credentials. No runtime/chart activation is enabled by this component.

Process-loss reconciliation also remains required: independently observed exact
protected Pod/process termination, retained witness before terminal-object removal,
and a separately qualified infrastructure fence for an already missing/partitioned
Pod. Enrollment retirement, expiry and Kubernetes 404 alone cannot prove provider
work joined. Until that path exists, an orphan stays charged and fenced; permanent
stranding is not a completed recovery feature. Download metadata retirement must
also retire detached consumer history, and qualified orphan cleanup must bound
retained identifying owner data. Count bounds here do not claim those outstanding
privacy lifetimes have been implemented.
