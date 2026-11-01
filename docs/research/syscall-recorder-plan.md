# Syscall metadata recorder: implementation plan (2026-11-01)

S-04 requires qualified syscall metadata sources. The node collector reports
`syscallTrace AdapterUnavailable [RecorderNotImplemented]`
(`internal/domain/collector/capability.go`, `implemented = {MechanismPacket}`).

## Engine: Inspektor Gadget traceloop v0.57.0, without its wasm layer

Pinned blobs (linux/amd64, fetched from ghcr.io 2026-11-01):

- index    `e06e1c5f1397780162a91241771bd5833831dd6d7ec075e3bda6985404f97626`
- manifest `7779c72c24ec9f1023ec837cc3caf7492396b2e5be29d71e06331d44c08bace6`
- config   `491c5f695113c3d2c5f5a4ea2897f631cffe8789c0434ac0df40f03189e54b74` (1249 B)
- eBPF     `49f885dd5bd0c6399efb1ead3971fa264558b5c3b81c2686486ab90f21841a73` (67896 B)
- wasm     `248c1aac2da98270ec3f72e7499cb0096f079278a59e4d4627ccd2858944508f` — NOT shipped

The OCI handler skips layers without an image operator
(`oci-handler/oci.go:480`), and Asservat does not link the wasm operator.
Without wasm, the `syscalls` definition map stays empty, so the eBPF program
never calls `bpf_probe_read_user`: only syscall number, pid, mntns, cpu,
timestamps and the return value are emitted. Asservat's own operator must
refuse to run unless `syscalls` is empty (acquisition-time enforcement of the
spec's no-user-memory rule), create a non-overwritable perf array per target
mntns in `map_of_perf_buffers`, fill `syscall_filters`/`syscall_enable_filters`
and read with `cilium/ebpf/perf` (exact `LostSamples`). Drop `comm` and raw
argument registers; keep metadata only.

## Format

ADR-244: `syscallRecords`, `asservat-syscall-events/v1`, JSON Lines
(`application/x-ndjson`, `.jsonl`), validated by
`internal/adapters/objectstore/manifest/native.go` (`syscallCheck`).

## Steps

1. ADR + spec/contract updates (deferrals below).
2. `internal/adapters/gadget/traceloop.go` pins, `traceloop_gadget.go`
   (gadget && linux) `TraceSyscalls`, fetch script + collector image blobs.
3. `internal/adapters/syscalls/`: enter/exit pairing, boot-time clock, errno
   names, rate bucket, fixed 48-byte record, JSON Lines window encoder.
4. Ring: `packets.Ring.AddRecord` reuse (segments/eviction/coverage).
5. Domain: `PacketSource.Syscalls` filter, `PacketResult.NativeType`,
   `implemented[MechanismSyscall]`.
6. Node: `node_syscall_source.go` mirroring the packet source; 256 B credit
   per event on the existing meter; loss -> ring gap.
7. Planning/hub: accept `syscallTrace` metadata mode; evidence type and
   artifact kind from the action; downloads and publisher stream check.
8. Connector: pass `NativeType` through `DeliverPacket`.

Tests: unit (pairing, ring, encoder vs schema, capability, compiler matrix);
native `collector-syscall` suite and the installed ongoing focus.

## Deferred (complexity gate)

Arguments mode / sensitive grants / syscall_query / live watch (need
user-memory reads and reviewed budgets); thread identity (gadget has no tid);
calls spanning windows; ia32 compat, mntns switches, arm64.
