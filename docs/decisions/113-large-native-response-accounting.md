# ADR-113: Whole native responses with bounded accounting windows

- Status: accepted design; implementation and external qualification in progress
- Date: 2026-10-11
- Requirements: REQ-DLD-001–004, REQ-CAP-004, REQ-PRV-004; S-02
- Owners: C-02 identity, C-14 evidence, C-20 transport, C-21 adapters

## Problem

The initial pod-status transfer fits one 4 KiB response. Its HTTP sink rejects a
second delivery, and the legacy session counts every at-most-1 MiB batch against
a 1,024-request ceiling. That cannot deliver a complete 1 GiB file plus its
preparation, much less the specified multi-GiB cores or 1 TiB native format.
Likewise, completing only an offset-zero batch cannot establish that a longer
response was delivered contiguously. The reviewed code demonstrates these limits;
the production transfer service has not been enabled.

Reusing the initial five-second metadata identity for an entire download would
also stop normal long transfers. Extending that observation instead would reuse
stale identity and policy facts. Creating two independently encrypted audit
objects and fully resolving identity for every MiB scales control work with every
small socket write. Those are separate problems requiring separate bounds.

## Decision

Keep the native representation, 1 TiB format ceiling, original raw grants,
artifact/version, actor/client, transfer deadline and cumulative output/read-work
limits. Introduce three distinct units without changing the legacy context path:

| Unit | Bound and responsibility |
| --- | --- |
| Native response | One authenticated HTTP GET and original live owner, one exact full-file or single-range selection, one Content-Length and ETag. Its hard end is the earliest original session, grant, worker, evidence and reader limit. |
| Accounting window | At most 64 MiB of contiguous selected output, with bounded read/decode work and separately reserved SQL/audit capacity. Full conservative spend and a durable encrypted intent precede its work; an immutable outcome follows. It grants no authority by itself. |
| Delivery lease and chunks | Fresh current identity and SQL authority for at most five seconds. Sequential writes are at most 1 MiB each and check the same original unexpired lease, cancellation, exact range and prepaid remaining capacity before every write. No output occurs while obtaining the next lease. |

The initial window size is a versioned implementation choice, not a measured
optimum or a new user control. A smaller final window covers the remaining
selection. An uncertain window stays fully spent: at most 64 MiB of additional
output budget is unavailable after such an interruption, rather than losing up
to 1 GiB for a typical multi-GiB core. Retrying never increases an existing raw
grant or silently creates a replacement session. Later changes to window size
require explicit accounting/version compatibility and measured qualification.

An unexpired current observation may cover multiple chunks. This explicitly
refines the earlier per-batch authority/spend/audit wording: every chunk crosses
the current permit boundary, while admission and durable audit cover the bounded
prepaid window. A new five-second lease requires fresh current authorization,
including identity, permissions, retained audience, raw/share grant when needed,
retention, locality, recovery and exact SQL writer generation. A window is never
a cached authorization decision. Known cancellation, denial or failed authority/
SQL/audit work stops output. Cross-process revocation remains bounded by the
original short lease plus already-emitted socket buffers; there is no claim of
instantaneous partition-proof revocation.

## Identity belongs to the original HTTP reader

A private hub-owned live reader creates fresh existing `CurrentIdentity` handles
for successive leases. It keeps the original HTTP context, principal/client and
credential source, with one active observation at a time and joined cancellation.
An old handle never renews. New batches use current groups and settings; within a
batch the existing exact-claims checks still apply. A caller-supplied background
context cannot detach work from the original connection or extend its hard end.

Browser batches reread the original server session without refreshing tokens.
The separate CSRF-protected refresh POST may replace its provider credentials and
groups while preserving the same opaque cookie and fixed session expiry. A known
refresh-in-progress may produce a finite pause before a new lease, with no output;
it cannot revive an admitted expired lease. Session expiry may only shorten.
Logout or row revocation denies subsequent checks. Changing a browser cookie
alone is not proof that the server revoked an already-open request's old session.

An OAuth response retains the original presented token. Revalidation cannot
advance token expiry or group-at-issue freshness. When either expires, bytes stop;
a client may refresh through its normal OAuth flow and resume using a new
authenticated GET with the same actor/client, original download and strong
If-Match. GET never performs token refresh. After headers, failure aborts the
native stream rather than appending a login page or JSON error.

The native attachment does not inherit the React page's replaceable metadata
request scope or collect a multi-GiB file into a JavaScript Blob. Its connection
has its own finite lifetime, and server-side logout/cancellation still applies.
Workers receive no human cookie, bearer token or serialized `CurrentIdentity`.
The acquisition Job-to-connector-to-hub I-13 route and regional key custody remain
mandatory; certificate enrollment channels remain separate.

## Accounting, completion and finite storage

Separate response/window records preserve original range and writer generation.
Do not raise or reinterpret the legacy 1,024-batch limit. Protected allocation
must reserve finite response/window records, paired audit objects/bytes and
supported residual-history backing before enabling the new path. Existing
allocations gain no large-response authority through migration defaults.

For a fixed window size W, reserve at least `ceil(authorizedOutput / W) + R`
window slots, where R is the finite admitted response count. This covers full
windows and one tail or empty completion per response; every unknown attempt
also spends a slot. Invalid requests confer no resource credit. At 64 MiB, an
uninterrupted 1 TiB transfer needs 16,384 windows and 32,768 paired audit objects.
These counts are arithmetic, not throughput, provider-capacity or storage
qualification. Audit object bounds, SQL footprint, failed operations, cleanup
and backup/WAL retention must also be covered. Finite safe retirement is a
runtime prerequisite; the separate public-operation audit lifecycle does not
automatically qualify download-window records.

Only the still-live original response may consume its acknowledged prepaid
window. A lost owner or uncertain write leaves the full reservation spent; no
replacement resumes from an unverified in-memory cursor. A subsequent eligible
GET reserves new work within the original session/grant. Old generations cannot
renew after a replacement and late outcomes provide historical accounting only.

Each next window starts at the exact contiguous acknowledged response cursor.
The preceding outcome must be independently acknowledged before more output.
Duplicate, overlapping, missing or reordered outcomes cannot complete a response.
Full-file verification must succeed before the final bounded chunk is released.
Only exact total delivery plus acknowledged outcomes may report Completed; a
partial-range response remains resumable. Neither result proves local disk save.

One HTTP response sets headers for the entire selected range. Per-lease write
deadlines and cancellation callbacks must finish before a later lease uses the
socket. A timed-out/uncertain write ends the response; it is never revived by
resetting its deadline. Plaintext queues and memory remain bounded independently
of the logical 64 MiB reservation. The hub has no unwrap keys.

## Qualification and current boundary

The implementation must prove bounded arithmetic through 1 TiB, quota contention,
exact response completion, current authorization after blocking locks, unknown
write/commit handling, purpose-separated SQL/audit roles and cancellation races.
Actual browser-session refresh/logout qualification is separate from synthetic
identity tests. A real transfer must stream more than 1 GiB with exact checksum,
authenticated range resume, expiry/revocation, slow-reader cancellation, corrupt
final-frame rejection, bounded memory and measured provider/control work.

Arithmetic, an HTTP loopback test or the earlier 2 GiB mechanism experiment does
not prove the installed workflow. Protected producers, regional framed-reader
attachment, authenticated I-13 transport, audit/backup retirement and public
runtime installation remain necessary. The [implementation record](../implementation-progress.md)
tracks actual results; this decision alone enables no endpoint.
