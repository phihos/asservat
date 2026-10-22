# Identity during a native response

Under [ADR-113](../decisions/113-large-native-response-accounting.md), the C-02
live-reader factory belongs to one authenticated native-content HTTP
request. It supplies fresh, separately owned short observations while the
original connection, actor/client, browser session and transfer limits remain
binding. It does not change `CurrentIdentity`, provide evidence permission,
refresh credentials or implement a native byte relay. Production composition
and large-file transfer qualification remain pending.

`NewBrowserLiveReader` and `NewBearerLiveReader` take the original request
context, installation-configured authentication services, private original
credential, expected principal and server-resolved hard deadline. Ingress must
already enforce its HTTPS/origin/resource/client rules. The hard deadline comes
from the original download, grant and surrounding request; it is not a public
duration override. Constructor authentication must pass before a reader is
returned. A failed constructor cancels and joins its work.

The concrete `LiveReader` implements C-02's `ReaderIdentity`:

```go
type ReaderIdentity interface {
    BeginBatch(context.Context) (IdentityBatch, error)
    Close()
}
type IdentityBatch interface {
    CurrentIdentity
    Close()
}
```

There is at most one owned batch, including initial authentication and cancelled
observations that have not yet returned. `ErrReaderBusy` differs from the
provider's `ErrSessionBusy`; neither causes an automatic retry. `BeginBatch`
uses the existing request constructor with a fresh interval of at most five
seconds. Batch cancellation remains linked to its caller and original HTTP
owner even if a later consumer supplies `context.Background()`.

Each batch keeps the existing exact principal/policy/group/scope checks and
original nonrenewable interval. Successful shorter observations monotonically
shorten the batch's tracked interval too; their expiry requires a fresh batch
and is not mistaken for a new terminal identity denial. A new batch reads
current groups and policy anew. The C-03 consumer must authorize the same immutable download with those
current claims; the reader itself does not decide resource entitlement.
Replacing groups between batches is not permission to merge old and new groups
or ignore a deny. Old or closed batches cannot resolve identity again.

Under [ADR-220](../decisions/220-response-owned-download-permissions.md), C-03 may
retain only the response's ordinary-entitlement decision for 30 seconds from its
original reconstruction start. A new batch still authenticates current identity;
changed claim sets trigger fresh eligibility before catalog access. The expired
old identity is never reused as authentication. Current SQL permission fences
remain, so known revisions/suspension may deny before the cadence cutoff. The
response discards its private observation on Close or a failed check.

`Close` cancels and joins active observations before releasing the batch slot.
The content coordinator retains a batch through its current SQL lease and final
bounded writes, then closes it before acquiring the next observation. Multiple
sequential <=1 MiB writes may use that lease while every write checks its
original deadline/cancellation/range. The reader knows no artifact sizes or
accounting windows. On reader close, the private credential closure is released
after joined work; this is not a claim of physical erasure from the Go heap.

Browser resolution always passes `allowRefresh=false`. An independent ordinary
CSRF-protected POST may rotate the encrypted credentials of the same session;
the next batch then verifies its new token and groups. GET never refreshes,
creates a session or adopts a new cookie. A trustworthy observation of a shorter
session expiry permanently shortens the reader even if that batch later fails;
a later longer value cannot undo it. SQL row revocation, current settings and
token/group expiry remain checked by the existing browser resolver.

If the final persisted read finds a strictly newer credential version for that
same session, the resolver returns `ErrSessionBusy` instead of the old token's
identity. The session ID, actor/client, provider session, creation and original
authentication times, current settings revision and unextended expiry must agree;
both observations retain their original deadlines. This also handles an old-token
denial racing a committed refresh. Other identity contradictions, revocation,
expired observations or replacement rows still deny. Neither branch refreshes
credentials during the GET.

Replacing a browser cookie does not itself tell an already-open GET that its
original row was revoked. That GET stays tied to its original session and ends
on its revocation, expiry, connection cancellation or other authority loss. No
instantaneous cross-process logout notification is claimed; current short leases
and already-emitted socket buffers retain their documented limits.

For bearer clients, every batch revalidates the same original presented token.
Fresh policy reads do not change its expiry or issued-at group freshness. A new
token requires a new authenticated HTTP request and ordinary authorized range
resume, retaining original download/grant bounds and retransmission accounting.
No token strings, cookies, `ReaderIdentity` or `CurrentIdentity` are forwarded
to acquisition workers. Their private transport receives independently checked
admitted batch/lease identities, never an identity-shaped substitute credential.

Known provider busy may be handled by the content coordinator as a finite,
zero-output wait before another batch admission. This factory deliberately
returns the original typed error and performs no refresh, retry, timer-driven
authentication or authority fallback. A proven source denial/expired credential,
principal substitution or identity contradiction within a still-live batch marks
the original reader terminal and cancels it immediately. This does not wait from
inside the counted observation; consumer cleanup calls Close to join. A later
permissive source cannot revive that GET. Expiry of the short observation alone
is distinct: it requires a new batch and full fresh authentication. Metadata
request handlers continue to use their existing one-operation `CurrentIdentity` and cannot become renewable
by importing this factory.

Focused tests exercise continuation beyond five seconds, unchanged old-handle
expiry, current group replacement, principal/client substitution, retained
shortening from failed work, typed busy without provider refresh/retry,
token/group-age expiry, owner cancellation with Background, and blocked-reader
joining before slot release. The integrated Go/race, architecture, SQL and
contract gates passed, as recorded in [implementation progress](../implementation-progress.md).
The [real Keycloak/PostgreSQL/OpenBao run](../../test/results/native-reader-identity.log)
also passed continuation beyond the first observation, separate explicit POST
refresh and logout rejection. Its
[terminal check](../../test/results/native-reader-identity-check.log) records
exit 0, unchanged sources and complete cleanup. Synthetic unit sources are not
production identity authority. Complete response/accounting/HTTP relay
qualification remains separate; no public-runtime or large-file claim follows
from this factory alone.

A complete browser download must not depend on keeping the console tab open or
on its JavaScript refresh timer. A bounded server-side refresh owner, explicitly
started by an authenticated CSRF-protected POST and retaining existing one-use
refresh claims and fixed session expiry, needs a separate accepted design and
qualification under [ADR-114](../decisions/114-download-owned-browser-refresh.md).
It is not implemented by this factory. Until that composition is
qualified, this component does not establish tab-independent long-download UX.
