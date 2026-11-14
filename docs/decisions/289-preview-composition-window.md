# ADR-289 — Bounded outer capture-preview composition

> Superseded in whole or in part by [ADR-330](330-event-driven-system-design.md) (event-driven system design, 2026-11-14). Where this record prescribes polling, expiring freshness windows, per-request Jobs, private PKI or enrollment layers, object-store audit, spent-on-uncertain accounting or installer-era guards, ADR-330 applies.

Date: 2026-11-03. Status: implementation selected under the maintainer's
standing authorization to simplify costly timing choices; installed
qualification pending. Requirements: REQ-HIS-002, REQ-INV-003.

## Observed problem

Native `continuation-approved-recording` run 41564008984 at `d84e0cf8`
completed its capture and saved history, then failed three repeat previews
with HTTP 503. A repeat preview first reads encrypted settings, then resolves
the current workload and checks recorder availability. These sequential
regional operations shared the ordinary five-second outer request window.
In one preview the history exchange alone took 1.917 s and the target query
1.23 s; the recorder call began with less than half a second remaining and
expired. Another preview expired during target resolution. Separate
`get_capture_settings` requests sampled below 500 ms do not measure these
composed repeat previews.

## Decision

`preview_capture` gets a prospective fifteen-second outer request window,
selected once at browser/MCP ingress through `OperationRequestWindow`.
This accommodates the existing at-most-five-second settings stage, the
existing at-most-five-second preview stage, and finite ingress/audit/reply
work. Fifteen seconds is a bounded engineering allowance, not a measured
latency target or guarantee that every deployment can finish.

Every contained identity, recovery, target, eligibility, retention and
transport observation keeps its original expiry. The Settings and
PreviewComposition stage caps remain five seconds. A current-request handle
still rejects initial identity expiry, later shortening, changed identity,
revocation and owner cancellation. No observation is renewed to consume the
larger window. Preview review lifetime and subsequent capture deadlines are
unchanged. Ordinary non-preview operations retain their existing windows.

The history-read observation is consumed when Settings returns authorized
immutable parameters. It is not reused as collection permission: the next stage
runs current collection eligibility and binds the original parameter-source
expiry through RepeatedFrom.ExpiresAt. No field gains a later authority expiry.

The operation-level selection also covers direct previews so browser and MCP
choose one predictable bound before inspecting sensitive settings. It adds
no schema field, client knob, retry, background task or new regional RPC.
The existing longer-operation timing selection now gives previews their own
`preview_capture` (and `preview_capture/service-failed`) doubling-report
sequence instead of the shared `normal` lane sequence. Sampling remains bounded
and carries no additional private values or I/O.

## Complexity gate

1. Observed: three failed preview attempts in one installed run; previous
   timing runs also failed repeat previews. User-visible repeat is unusable.
2. No accepted risk is reopened; original authority freshness remains fixed.
3. Repeat is an ordinary first-release workflow.
4. Reuses the project's existing bounded multi-stage request mechanism used
   by capture submission and evidence reads; no novel mechanism.
5. Zero privileges, credentials or network exposure added.
6. Zero new failure or fallback states.
7. Zero configuration options.
8. No new external dependency; existing regional services remain required.
9. Same API/object/key work and concurrency limits; each preview slot can be
   occupied at most 15 rather than 5 seconds. No new watches or retained memory.
10. Migration 00126 gives PostgreSQL audit admission the same prospective
    fifteen-second preview envelope. It adds no table or column and never
    rewrites an existing intent. Its tested SQL Down restores five-second
    preview admission; Up restores fifteen seconds with prior intent replay
    and charges preserved. Running an older binary against new history is
    not qualified by this SQL roundtrip.
11. This one operation bound is smaller than adding combined workload/recorder
    RPC variants or splitting public preview into new resumable phases.

## Verification

A deterministic composed regression uses the actual audit and current-request
identity boundaries with synthetic regional stages taking 3+2+1 seconds.
The old outer window refuses it; the new one permits it. Initial identity
expiry, changed identity, cancellation and an expired individual observation
remain refused. This proves the composition boundary, not native latency.
The real PostgreSQL/S3 regression first failed at audit Begin against schema
125: the existing SQL trigger still allowed only five seconds. With migration
00126, fifteen-second preview Begin/Finish and unchanged five-second ordinary
requests pass; direct SQL insertions beyond either bound are rejected. Eight
audit lock-expiry/history/accounting/overdue cases pass (132.083 seconds), as
does an actual 126 Down/Up roundtrip (2.236 seconds). All reports record unchanged
source and no cleanup failures. The previous failed native run also has unchanged
source hashes and no cleanup failures. Installed qualification remains pending.
