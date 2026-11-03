# Traceloop argument-budget prototype

An isolated ADR-281 engine experiment, under the maintainer's 2026-11-03
permission for a narrowly scoped, digest-pinned upstream traceloop patch.
Nothing in the product imports this directory. The existing metadata engine,
its empty definition map and its pinned published gadget remain unchanged.
Argument mode remains unavailable pending the full implementation and native
qualification. This experiment adds no approved syscall definition table.

## Source and build identity

`pins.json` records Inspektor Gadget v0.57.0's immutable commit, upstream C SHA-256,
patch/header SHA-256, patched C and measured compiled-object SHA-256, target flags and the Linux/amd64
`gadget-builder` OCI manifest digest. `prepare.py` refuses any source mismatch,
applies the patch without fuzzy matching and rechecks the result. It never
executes the program. Its optional compile uses only an unprivileged build
container: no network, host namespace, devices, capabilities or BPF mount.
The generated object is not yet a packaged/runtime-pinned Gadget OCI artifact.

```sh
python3 experiments/syscall-argument-budget/test.py --tmpdir "$HOME/.cache/asservat-build"
python3 experiments/syscall-argument-budget/prepare.py "$HOME/.cache/asservat-build/arguments-build-1" --compile
python3 experiments/syscall-argument-budget/prepare.py "$HOME/.cache/asservat-build/arguments-build-2" --compile
cmp "$HOME/.cache/asservat-build/arguments-build-1/program.bpf.o" "$HOME/.cache/asservat-build/arguments-build-2/program.bpf.o"
```

The first command runs host C tests and compiles an ISA probe without loading it.
The other commands download and verify the upstream source and compile the full
patched object using the pinned builder. Use new output directories. A local
already-downloaded C file may be supplied through `--upstream`; the same digest
check applies. Generated sources, objects and build reports belong outside Git.
No script performs attachment, `BPF_PROG_LOAD`, registry publication or CI dispatch.

## Accounting mechanism

One non-per-CPU `ARRAY` value contains 64-bit remaining events, remaining bytes,
a sticky stopped flag, the original boot-clock deadline and the approved maximum
probe charge: 40 bytes before map overhead. All allowed mount namespaces of one
whole-pod session use this same cell. Container discovery/addition never creates
another allowance. The future loader must initialize the cell once, freeze its
userspace writes and the definition map before exposing namespaces to this
program, and never replace/reset its maps to resume a session.

At each admitted entry or exit, before user-memory helpers, reserve one event and
the entire probe's conservative maximum byte charge. A bounded (eight-attempt)
64-bit CMPXCHG loop refuses if insufficient. Event reservation is not refunded
when byte reservation fails. Expiry, insufficient budget, a probe above its
approved charge, or repeated contention stops the session irreversibly. This may
stop before all budget is usable; it never borrows/refills capacity. Missing or
zero-initialized state denies. Probes already admitted on another CPU can finish
their reserved reads; the flag is not instantaneous cross-CPU revocation.

The upstream entry path can fall through a successful string/scalar helper into
a second 128-byte read; the exit scalar path can similarly fall through. This
prototype preserves upstream helper behavior and reserves **256 bytes per eligible
argument**, in addition to the fixed 256-byte probe charge. The maximum is
`256 + 6 * 256 = 1,792` bytes per probe. The first read is at most 128 bytes and
the second at most 128 bytes; faulting attempts are included. Some probes
therefore consume more than their actual requested helper lengths. This is a
conservative preallocation, never a claim that those bytes were measured. The
accounting version and this overreservation must be explicit in the future
permit/preview/provenance; the final adapter may instead correct the upstream
fallthrough and precompute exact requested lengths under separate tests. The
per-probe maximum from approval is enforced before either counter is consumed.
An eventual result/errors filter cannot reclaim any of this spend.

The kernel cell enforces a **single already prepaid session slice**, not a whole
SQL grant. Future admission must atomically debit all session/event/byte ceilings
from the shared grant before initializing any cell. Multiple sessions/sources
must hold disjoint nonrefundable slices whose sum fits the grant. Restart has no
permission to reconstruct a full budget: unknown spend remains charged, the
original permit/epoch must refuse replay, and another session requires a new
independently admitted slice. None of that authority integration is implemented
by this C experiment.

## Why CMPXCHG, and what is not proved

The [Linux v6.12 helper contract](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h)
prohibits `bpf_spin_lock` for tracing programs; upstream traceloop uses raw
tracepoints. The [kernel BPF ISA specification](https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html)
describes 64-bit CMPXCHG and Clang's `-mcpu=v3` atomic support. The same pinned
kernel header describes `BPF_MAP_FREEZE`: it prevents userspace map writes,
not program writes. Consequently this design uses atomic monotonic debits,
not a tracing spinlock. A new map or new program instance is outside that guard,
which is why restart/admission fencing is a separate required implementation.

Host pthread tests exercise the shared C helper under actual concurrency,
including arithmetic boundaries, byte failure after event debit, sticky stopping,
expiry, per-probe ceilings and concurrent callers sharing one allowance. Their
synthetic read counter is not a kernel helper observation. Compile/disassembly
proves instruction generation only. Neither establishes verifier acceptance,
probe semantics, kernel memory ordering, measured node overhead, permission
freshness, whole-pod identity or native sensitive-read limits.

## Complexity gate and next stages

1. Benefit: REQ-SYS-002 is required first-release opt-in behavior; its frequency
   is unmeasured. The published engine demonstrably lacks pre-read budget checks.
2. The maintainer authorized this narrowly scoped engine exception; no general
   custom eBPF or argument-mode activation was authorized by a passing model.
3. Helps argument-mode users; metadata capture has zero changes/cost.
4. Uses upstream traceloop plus documented BPF atomics; no claim that another
   product provides exactly this accounting.
5. Zero new host privileges, credentials or network paths in this experiment.
   Native execution remains limited to an owned disposable runner/VM.
6. One sticky stopped state; no refill, refund, fallback or retry lifecycle.
7. Zero tuning switches for the mechanism; approved byte/event/time ceilings
   become immutable map inputs. The eight-attempt bound is fixed.
8. Depends on the upstream program/headers, BPF atomics, verifier and pinned Clang.
9. One 40-byte map value per session plus map overhead; one lookup and at most
   eight compare/exchange attempts per debit, two debits per admitted probe.
   Atomic loads and stopped checks add their own CMPXCHG instructions. This is
   an instruction bound, not measured overhead or an accepted performance claim.
10. No installed enablement to roll back. Removing the future argument capability
    must not restart/refund existing sessions; that lifecycle test is pending.
11. Userspace counting cannot prevent an extra read. A conservative shared atomic
    debit is the smallest investigated engine change; exact charging and less
    contention may warrant a later revision after measurement.

Remaining stages, in order:

- Native verifier/load test of the full exact object on each advertised kernel/
  architecture, on a disposable runner only. Verify map-freeze behavior and deny
  zero/missing state. Observe helper calls or otherwise independently establish
  read bounds under simultaneous CPUs, failed reads and entry/exit activity.
- Fixed reviewed syscall definitions, argument decoder/provenance, per-event and
  observed-event rate bounds, whole-pod namespace/process identity and late-
  namespace/exit handling. Qualify the conservative charge against every helper
  path; do not infer coverage from the source-level helper count.
- Durable nonrefundable grant slices, exact accounting/program digest pins,
  restart/replay denial, collector cancellation/expiry/revocation and unchanged
  metadata tests. Do not feed production permits from this experiment.
- Reproducible Gadget OCI packaging and independent object/manifest digest pins;
  raw artifact type, verifier, publication, native download and current raw grants.
- Installed manual argument capture with distinct approval, successful and
  failed syscalls counted despite result filters, native raw bytes, exhaustion,
  restart, Stop/revocation/expiry and cleanup. Measure CPU, latency, memory and
  premature contention stopping under the combined workflow before enablement.

## Measured local results (2026-11-03)

- `test.py` passed arithmetic/expiry/per-probe limits and 30 rounds of 16 host
  threads sharing one allowance. On one recorded run, admitted probes ranged
  from 210 to 1,960 with 10,000 event units and 2,000,000 bytes available. The
  saturated synthetic race therefore demonstrates that the eight-attempt sticky
  contention stop can end observation substantially early. This is not a native
  throughput measurement or a production-ready availability claim.
- The compile-only ISA probe emitted 64-bit CMPXCHG using local Clang 23.1.4.
- Two full patched builds in the pinned Linux/amd64 builder, with separate source
  directories mapped to the same canonical build path, produced byte-identical
  objects: `ae6a3e19c2bc4510f4665fb7cf9258559e45c11aaf475e227d4388095c0bec84`.
  `prepare.py --compile` now requires that exact object hash.
- `make spec-check architecture-check` passed using the existing specification
  virtual environment. These are design gates, not verifier/runtime results.
- No BPF object was loaded, no tracepoint attached, no user-memory read performed
  by this experiment, no CI run dispatched and no image published. Verifier,
  native accounting, fixed syscall definitions and production grant composition
  remain the next work; host model passes do not close ADR-281.
