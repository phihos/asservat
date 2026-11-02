# ADR-279 — Manual finite raw packet recordings (S-04 increment 14, slice 1)

Date: 2026-11-02. Status: accepted (agent decision); implementation in slices.
Requirements: REQ-NET-004 (`rawPackets`, `protocolSnaplen`), REQ-AUT-006
(observation sessions; manual raw authority is required), REQ-ASM-003,
ADR-249 (individual approval, result-access children), ADR-261 (finite
metered observation admission).

## Context

`rawPackets` keeps payload prefixes, so it needs explicit payload approval,
the raw class and metered observation (REQ-AUT-006). ADR-261 built the meter,
typed permit and node binding for one finite policy packet action; manual raw
authority stayed unimplemented. A raw artifact is only usable when someone may
download it: ADR-249's ad hoc grants already carry result-access children for
that, while policy grants confer no download rights.

## Decision

1. Manual first. A manual composition with one `rawPackets` packet action that
   is finite (`onTrigger`, `before: 0s`, `after` at most 15 s) needs individual
   approval with data class `raw` and observation limits. Ongoing raw, rings,
   Saves and policy raw output follow in later slices.
2. Per-transport caps: one default `snaplen` and at most one cap each for
   tcp, udp and icmp, 1 to the engine maximum (1500 with the pinned gadget);
   larger values are refused with a remedy, never narrowed silently. Caps are
   byte budgets, not redaction.
3. The recording is a distinct native type `rawPcapng` of class `raw`;
   expectation validation ties the raw profile, raw type and raw class
   together. New fields are omitted when empty, so existing digests are
   unchanged.
4. Observation is charged per ADR-261 before the filter and caps, from a
   pool on the approved ad hoc grant: reserved once per session, never
   refilled by replay or restart; exhaustion stops the capture with
   `ObservationBudgetExhausted`.
5. Download of the raw artifact consumes the grant's result-access child;
   sharing raw output stays refused until the S-06 raw-share approval exists.

6. A `rawPackets` action needs a `packetFilter`: the observation binding pins
   a compiled program, and a filter narrows the payload a review covers.
   Filters still read only the header snaplen (`CheckPrefixProgram`); a
   predicate on later payload bytes is refused as unsupported.
7. The node keeps each retained frame's prefix up to its transport cap
   (`snaplen` otherwise); the engine still hands over at least the header
   snaplen so a short cap still classifies its transport. The publisher
   rechecks the stored `rawPcapng` against the accepted caps
   (`packets.CheckRaw`) in the same verification read: each frame is held to
   its transport's cap as soon as its IP header names the protocol, and a
   frame too short to name it to the smallest cap. Caps are therefore at
   least 54 bytes (Ethernet plus the fixed IPv6 header), so every frame the
   node keeps names its transport.

## Complexity gate

Benefit: raw packets are a specified first-release capability. Cost: one
native type, a grant-scoped observed-byte pool reusing the ADR-261 session
table, per-transport truncation on the node; no new service, credential or
background task. Disabling: raw needs approval and a profile that asks for it.

## Implementation (slice 4)

Publication and the download plumbing carry `raw` only for `rawPcapng`
(`ContextExpectation.ServedClass`). The catalog record now states the class
and action. `ContextDownloadAuthority` keeps ordinary `DownloadApproved`
eligibility with metadata semantics and, for raw, refuses every share and
never keeps a response-owned entitlement; its last check is C-03's
`GrantService.CurrentResultAccess`. On the first download after verified
commit this materializes, idempotently, the child for exactly the artifact
version and the requesting human's approved client (`Materialize`), then
checks the child's use with a current, unrevoked, unexpired parent; its end
bounds the authority. Every raw batch then reserves one use under its own ID
before any byte is read (`ReserveRawResult`, which finds the child by
parent/artifact/client and calls `Use`): one operation per preparation batch,
and each response window's bytes under the window ID (the 4 KiB content
batch charges its bytes the same way). A missing port or a refused
reservation fails the batch closed. The download environment admits `raw` as
a client class, and installer clients list it; the grant still names the
clients. The child ID never leaves C-03.
