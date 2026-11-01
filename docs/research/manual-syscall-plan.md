# Finite manual syscall metadata recording (slice B3, part 1)

Date: 2026-11-01. Requirements: REQ-CPR-003 (manual compositions are a
DebugCapture authoring form), specs/syscalls.md, specs/action-lifecycle.md
(manual requests are finite). Code map: main 764e7cfb.

A manual capture is one artifact, so a manual packet + syscall composition
becomes a group (part 2). Part 1 makes a single finite syscall metadata
recording possible, mirroring the manual packet Recording (ADR-248) and
reusing the ongoing syscall engine (ADR-273).

## Decisions

- `artifact.Recording` gains `Syscalls *RecordingSyscalls` (`omitempty`, so
  packet digests are unchanged). Kind `syscallTrace` / Profile `metadata`;
  no filter program; duration 1–60 s (the compiler's `maxSyscallAfter`).
- NativeType follows the Recording kind (`pcapng` ↔ `packetCapture`,
  `syscallRecords` ↔ `syscallTrace`), in the hub expectation, the connector
  result check and migration 00115 (processing trigger Recording branch).
- New node work kind `WorkSyscallCapture`: an older node only checks
  `Kind`, so an added field on `PacketCapture` would run tcpdump instead.
  Unknown kinds are refused by old nodes, which fails safe.
- The node runs the existing `syscallEngine` for the duration with a local
  events-per-second limiter (no source permit exists for a finite run) and
  encodes JSON Lines with `syscalls.AppendEvent`.
- A quiet interval (no retained call) reports failure for now, like an empty
  source window: a result needs bytes (`PacketResult.Valid`) and an empty
  native upload is unqualified. Revisit with native evidence if quiet Pods
  matter.
- Availability: `targets.RecorderRequest` gains `Syscall`; the region selects
  the syscall mechanism. An older region answering for packets still fails
  safe at start (its `Recording.Valid` refuses the kind).

## Qualification

`collector-packet` gains a finite syscall capture beside the source check;
an installed `manual-syscall` focus previews and requests
`syscall-activity/v1` with `actionExecutionMode=onTrigger, before 0s` and
downloads the JSON Lines.

## Part 2 (after this)

Manual packet + syscall compositions as a group of child captures sharing one
review (the ADR-266 group, with a manual group kind).
