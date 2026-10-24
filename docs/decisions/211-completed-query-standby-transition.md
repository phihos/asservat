# ADR-211 — Return a completed target query to its original standby interval

Date: 2026-10-20. Status: implemented; component checks pass; installed qualification pending.
Requirements: REQ-FED-001/003, S-02; TASK-03 / TASK-11.

## Context

[ADR-135](135-live-regional-api-context-start.md) separates the original thirty-second
passive context-start residence from an operation's authority.
[ADR-179](179-outbound-only-first-installed-profile.md) permits up to four
independent target queries on that standby before work begins. Every query
performs current source, peer and target checks under its own original bounds.

The native installed journey on `4db57af3` completed previews but failed the
following capture target queries. It did not admit a capture. A separate actual
HTTP/2 regression reproduced one mechanism: a successfully completed query
left its short socket deadline behind, and that deadline terminated the next
query while both its independent caller and the original standby remained live.
This reproduction does not attribute every native failure to that mechanism.

Both hub socket directions matter. A matched answer acknowledges the outbound
query, but the HTTP/2 server's old write deadline can still terminate the stream
while idle. Merely restoring the read deadline leaves that timer active.

The router also allowed a capture attachment to pull a source reply while a
query was reading the same exchange. A second query could reserve that busy
standby as well. A completed-query transition needs exclusive phase ownership.

## Decision

1. Reserve the standby for one query under the router lock. Other queries and
   attachments cannot select it while that reservation is held. The existing
   query count is spent at reservation and never refunded. Once dispatched,
   the reservation remains until the query and its callbacks have joined.
   Cancellation before dispatch can release the reservation because no query
   I/O occurred.
2. Only the hub's semantically completed pre-work query may return to passive
   waiting. Completion requires the expected answer kind, sequence and method,
   a fully decoded result or recognized closed failure, and the still-live
   original query. This includes the minimum of its caller, explicit receiver
   and exact Send/Receive peer cutoffs, checked by wall clock even before
   expiry callbacks run. All query frame I/O and deadline callbacks must
   finish first, with no other logical frame or source exchange in progress.
3. Restore both hub socket deadlines to the exact original standby deadline.
   Never derive a new thirty-second interval or clear a deadline. The stream
   and standby must still be live, with no attempted or accepted work lease.
   Failure, cancellation, expiry or a failed deadline hook closes the stream
   permanently. A terminal query failure withdraws its standby before its
   result becomes available to another caller.
4. A successful answer retains its original target cutoff and the earliest
   contributing caller, explicit receiver and Send/Receive peer cutoff.
   Returning to passive waiting does not renew either proof, authorize work,
   or replay the query. A subsequent query performs its own complete checks;
   capture still reselects no replacement Pod.
5. Do not restore deadlines in generic `Send`, `Receive` or source-write
   cleanup. Do not restore the regional answer's write deadline: the region
   has no acknowledgement that its answer was consumed. Its next bounded
   write installs its own deadline. Setup already returns to the original
   standby interval after its authenticated empty response.
6. [ADR-163](163-original-work-transport-observation-lease.md)'s work lease is
   unchanged. Any attempted work prevents this transition, including an
   unsuccessful attempt. Original work deadlines, final current checks,
   conservative spend and joined resource accounting remain binding.

7. Addendum after installed native 95: a burst of previews spent the only
   standby's four queries and later queries failed at `router` for the rest
   of its thirty-second residency. A query that finds no selectable standby
   now withdraws idle, unattached standbys of its cluster whose budget is
   spent, then keeps waiting within its original deadline for the region's
   fresh registration. Without a waiting query a spent standby remains
   available for work. The spent count is never refunded.

Busy-to-idle notification may wake waiting query selectors, but their existing
original deadline and reserved time for execution remain unchanged. Frame,
source, query, byte, connection and capture ceilings are unchanged.

## Verification

The actual HTTP/2 regression failed before implementation: the second query
still had over three seconds of its own interval remaining when the first
query's retained socket deadline terminated it.

Passing actual HTTP/2 checks cover successive independent queries across the
first caller's expiry, an idle gap, and subsequent independently leased work.
Component checks cover closed denial responses, earliest returned proof
cutoffs, original query and standby expiry, cancellation, malformed or
mismatched answers, attempted work, deadline-hook failure, closure races,
peer revocation, and exclusive query/attachment ownership through joined
completion. The complete context-start and mTLS packages passed the race
detector in 2.783 and 34.382 seconds respectively; independent source review
found no remaining blockers.

Current test results and the next frozen installed run belong in
[implementation progress](../implementation-progress.md). This decision alone
does not qualify capture, publication, native download or deletion.
