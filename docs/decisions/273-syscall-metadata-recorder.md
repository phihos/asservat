# ADR-273 — Syscall metadata recorder on the ongoing source path

Date: 2026-11-01. Status: accepted (agent decision under the maintainer's
"implement the spec end to end" goal); unit tests pass, native qualification
pending.
Requirements: specs/syscalls.md (REQ-SYS-001/002, metadata mode),
specs/action-lifecycle.md (syscallTrace defaults to ongoing), S-04.

## Context

The node collector reported `syscallTrace AdapterUnavailable
[RecorderNotImplemented]`. ADR-244 fixed the native format (`syscallRecords`,
`asservat-syscall-events/v1`, JSON Lines) and its manifest validator; no
producer existed. Research and pinned blobs are in
docs/research/syscall-recorder-plan.md.

## Decision

1. **Engine.** Inspektor Gadget `traceloop` v0.57.0 eBPF program only, from
   pinned digest-checked blobs. Its wasm layer is not shipped, so the
   program's `syscalls` argument-definition map stays empty and the program
   never calls `bpf_probe_read_user`. Asservat's operator refuses to start
   when that map is not empty. One non-overwritable perf array per pod mount
   namespace is installed in `map_of_perf_buffers`; namespaces are rescanned
   every second so restarted containers stay traced.
2. **Metadata only.** Userspace decodes number, tgid, boot timestamps and the
   exit return value; `comm` and argument registers are never read. ENTER and
   EXIT pair by (monotonic timestamp, tgid) with at most `maxTrackedThreads`
   waiting halves, evicted first-in first-out in constant time. The ring
   keeps a fixed 32-byte record per call, stamped at its completion (exit),
   so a call that blocked longer than the ring age is not stale when it
   returns; `duration_ns` gives its entry.
3. **Reuse of the packet source.** A syscall source is a `PacketSource` with
   `Syscalls` set. Its selection digest (`SyscallFilterDigest`, domain
   separated, never zero, owned by `application/delivery` beside the other
   source digests) occupies `Binding.ProgramDigest`, so the signed
   binding, SQL admission, ring, meter, renewal, snapshot, connector and
   publication paths are shared; a packet permit can never start a syscall
   engine or the reverse. The selection carries names, `result: errors`,
   `maxEvents` and `maxTrackedThreads`, all digest-bound; the node resolves
   names for its ABI and refuses unknown names. `result: errors` still charges
   every observed call (specs/syscalls.md) and retains only failures;
   `maxEvents` caps each saved window (ring residency stays bounded by ring
   bytes, 48 bytes per event). Up to 16 numbers use the kernel
   filter; larger selections are filtered in userspace before any charge.
4. **Accounting.** Each event spends 256 credit units
   (`SyscallEventCredit`), so the existing byte rate and credit bound events;
   the policy rate is additionally capped at `maxEventsPerSecond` × 256.
   Over-rate events, lost perf samples, pairing gaps and stale timestamps are
   ring gaps that the saved window's coverage reports (InputUnknown), not a
   source stop or a source-level InputUnknown (which the hub ends and
   replaces) — the spec's "stop or bounded-drop visibly". Spent credit, leaf
   expiry and a closed ring still stop the source. A failed window carries
   the syscall native type so the connector records the failure.
5. **Scope of this increment.** Ongoing DebugPolicy sources with automatic
   incident snapshots and Save, published and downloadable as JSON Lines.
   `SourceSnapshotContext.ActionKind` (omitted for packets, so existing packet
   plan digests are unchanged) selects the expected native type, the policy
   action and the retention evidence type. The download policy accepts
   `syscallTrace` (three evidence types). Migration 00113 widens the
   publication lineage predicate and the hub's collect query to
   `syscallRecords`; the artifact manifest schema gains its syscall variant.
6. **Availability.** The hub requests the syscall recorder explicitly
   (`OngoingRecorderRequest.Syscall`) and checks the node's syscall mechanism,
   not the packet one.

## Limitations (recorded, not hidden)

- Traceloop has no thread id: `thread_ref` repeats the process reference.
- Nonreturning calls (`exit`, `exit_group`, `rt_sigreturn`) are encoded with
  outcome `unknown`; the event schema has no nonreturning outcome.
- An empty window (no calls at all) reports absence, because the upload path
  requires bytes.
- Records keep pairing order, not call-time order.
- Unknown syscall names are refused by the node, not at policy compile time.
- Calls still in flight at a window's end are not in that window. A new
  container's namespace is traced up to one second after it appears; that
  late attach is reported as an input gap (InputUnknown), not quiet input.
- Perf buffers (64 pages per CPU per container namespace) are outside the
  ring reservation.
- x86_64 only (other architectures report the recorder unavailable); arguments mode, raw syscall queries, live watch, finite
  onTrigger and manual syscall recordings follow in later increments.

## Complexity gate

1. Problem: a first-release spec feature with no producer (not hypothetical).
2. Not previously accepted as a gap.
3. Typical deployments: yes (same nodes as packet capture).
4. Precedent: Inspektor Gadget traceloop; reused rather than a new program.
5. Privileges: none beyond the collector's existing eBPF capabilities.
6. Degraded states added: none new (ring gap/InputUnknown already exist).
7. No new configuration.
8. External component: the pinned traceloop program (same engine family).
9. Cost: bounded by the existing source meter and ring limits.
10. Disable: policies without a syscall action never arm it.
11. Smaller alternative: none that produces evidence.
