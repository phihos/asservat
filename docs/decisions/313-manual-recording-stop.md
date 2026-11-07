# ADR-313: Stop for every finite manual recording

Status: accepted; implements the existing REQ-LIF-005 / SC-LIF-005 requirement
that cancellation stops a manual session. Installed qualification pending.

## Context

`cancel_capture` accepted only source snapshots, profiles, logs and the finite
syscall-argument recording (ADR-281). A running manual packet metadata, raw
packet, HTTP header or syscall metadata recording returned `NotAvailable`, so
installed manual sessions could not be stopped (observed in the
`continuation-ongoing-live-manual` CI suite). The spec already requires
"Completion/cancellation stops that session".

## Decision

Reuse the ADR-281 argument Stop for every accepted expectation with a
`Recording` and no `Snapshot`, `Profile` or `Logs`:

- Hub request: same `snapshot_cancel_*` request columns, expected revision,
  idempotency key and current progress rights; a started execution dispatches
  `RecordingStop` with the exact original writer Pod UID/epoch, attempt,
  expectation digest and WriteUntil.
- Regional holder: the stop queues the existing node `cancelPacketCapture`
  for the exact original work item. The packet and syscall engines already
  register in the node's running set. `Cancelled` requires the original node
  result to arrive and its handling (and any local writer) to return; a queue
  acknowledgement, missing holder or uncertain start never establishes it.
- SQL outcome: `RecordAPIRecordingCancellation` with the original writer's
  `RecordingCancellation` proof; migration 00146 widens only the
  `guard_snapshot_cancel` request rule from the argument recording to any
  `Recording` expectation. Joined-proof and immutability checks are unchanged.

Partial data: the node reports an early stop as a failure with an empty
placeholder, never as a shorter recording, and the regional holder cancels an
unread store wait. A cancelled recording therefore produces no artifact. An
already admitted Store keeps stored-wins behavior and finalizes under its own
authority and WriteUntil. Spend is not refunded.

## Consequences

0 new services, credentials, watches, background loops or configuration.
Live views of the session close on the Stop request (existing
`cancelRequested` check). Down restores the schema-145 request rule for new
requests only.
