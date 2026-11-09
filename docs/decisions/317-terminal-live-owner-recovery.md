# ADR-317: Terminal recovery after live-owner loss

Status: implemented; component and real-PostgreSQL qualification passed.
Installed owner-failover qualification is pending.

## Context

ADR-310 binds the private source selection, filters and replay of a live view to
its original hub-owner process. Native run 42689236964 replaced that process
successfully, but every subsequent read was forwarded to the dead owner and
returned `LiveUnavailable`: no gap or terminal state appeared. Persisting or
transferring the private session to the replacement would contradict the
minimized SQL/privacy design and add a substantial recovery protocol.

REQ-LIV-003 already permits either an explicit reconnect gap or ending the view
on view restart/hub failover. Ending is sufficient; session adoption is not a
product requirement.

## Decision

When a remote original owner cannot complete a non-transient forwarding
operation, the receiving owner ends the view instead of adopting it:

1. Resolve the current identity and original owner route as before. Recovery
   requires the dedicated `ErrOwnerLost` sentinel, emitted only for route,
   dial/TLS or premature-stream failures. Every error frame from a reachable
   owner—including ordinary `ErrUnavailable`, source-read transient errors,
   access denial, conflicts, capacity failures and caller cancellation—keeps
   its existing behavior and cannot close the durable control.
2. Read only the minimized durable control. Validate the original cursor using
   its MAC over watch/fence/selection/revision/position/budget and the complete
   principal, including client ID. A same-human different client cannot close
   the view.
3. Compare the original revision and fence, then change only the control state
   to `Closed`. Revision, accepted/idle/hard expiry and cumulative spend stay
   unchanged. Repeated recovery is idempotent and releases active slot counts.
4. Return an empty terminal batch at that same revision with a `reconnect` gap,
   existing cumulative spend and no continuation. No source read, source/filter
   persistence, replay transfer, replacement subscription or new cursor occurs.

Migration 00147 adds the two closed SQL functions and their EXECUTE grants on
the existing hub role. It adds no table privilege, stored actor text, source
identity, filter, cursor or event payload. The cursor MAC now includes the
already in-memory principal; its public `live1` shape is unchanged.

## Complexity check

1. Observed failure: one actual native run, every read during owner failover
   failed without a terminal outcome; this blocks ordinary owner replacement.
2. The accepted spec explicitly allows ending the view; no accepted risk is
   reopened.
3. This covers the typical owner-restart path, not only a synthetic edge case.
4. Ending a process-local transient view is simpler than the novel alternative
   of durable encrypted session adoption; no broker or shared session store is
   added.
5. Zero new credentials, listeners, collector privileges or external access;
   two narrow SQL functions reuse the hub credential.
6. Zero new public states: existing `Closed` and `reconnect` are reused.
7. Zero new configuration or background machinery.
8. Dependencies remain PostgreSQL and the existing authenticated owner route.
9. Normal reads add no SQL request. Recovery adds one control read and one
   conditional close only after a failed remote operation, bounded by the
   original request deadline. Memory/network payloads remain existing minima.
10. Upgrade is one additive migration; Down drops only the two functions.
    `Closed` was already a supported control state and disablement needs no
    data rewrite.
11. Returning permanent unavailability was the smaller code change but did not
    meet the required terminal/gap semantics. This is the smallest compliant
    fix; adopting private state is intentionally rejected.

## Verification

- Application regressions cover original-client terminal recovery, stable
  replay, cross-client refusal before close, unchanged revision/deadlines/spend
  and zero source reads/session adoption.
- Real PostgreSQL qualification covers exact control reads, wrong principal and
  fence refusal, idempotent close and original accounting bounds under the
  compiled hub role. Migration generation and affected package/vet gates pass.
- Installed native qualification must still prove Pod replacement, terminal MCP
  behavior, unchanged SQL accounting and cleanup before this path is called
  installed-qualified.
