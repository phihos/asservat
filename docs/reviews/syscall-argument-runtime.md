# Argument engine production composition

Scope: REQ-SYS-001/002/003, ADR-281. The maintainer authorized the narrow patched
traceloop engine. This increment keeps the published metadata object, loader,
definitions and decoder unchanged. SQL admission, installed authority and public
activation are separate integration work. No workstation kernel load is allowed.

## Rate and accounting decision

The previously qualified object had cumulative event/byte limits but no observed
probe rate bound. Existing syscall output throttling runs after pairing/filtering
and cannot enforce argument observation limits. Use one shared virtual-time
bucket before cumulative debit and before any user read: interval
`ceil(1e9/effectiveRate)` ns, initial burst `effectiveRate` probes, bounded eight
CAS attempts, irreversible stop on excess or contention. All CPUs and Pod
namespaces share one value. Time advances continuously; there is no reset timer,
per-CPU allowance, restart/refill or sleep in a syscall.

`effectiveRate = min(maxEventsPerSecond, floor(maxBytesPerSecond/maxProbeBytes))`.
Reject zero. Each probe charges at most the fixed reviewed maximum, so this one
bucket conservatively enforces both authored byte and event ceilings, with a
one-second initial burst. Cheaper probes underuse the byte allowance; that is
explicit and never compensated by raising rates. The configured maxBytesPerEvent bounds actual argument memory reads; it is
separate from the deliberately conservative observation-credit charge.
The cumulative slice remains
separate and nonrefundable. A failed byte reservation keeps its event debit.
The exact rule string is pinned with program and definition digests; domain
admission owns the authoritative rule value.

The [kernel ISA](https://www.kernel.org/doc/html/v6.12/bpf/standardization/instruction-set.html)
specifies the existing 64-bit CMPXCHG primitive. The pinned
[upstream source](https://github.com/inspektor-gadget/inspektor-gadget/blob/29d60de9f7924607784915533dd5f3cc0052ee1a/gadgets/traceloop/program.bpf.c)
uses raw tracepoints; its selected atomic mechanism does not add prohibited
tracing spinlocks. This extends the existing 64-bit counter pattern with one
mutable timestamp and two immutable interval/burst values: 64-byte budget versus
40 before, at most eight additional CAS attempts per admitted probe.

## Closed definitions, read bounds and provenance

The first x86_64 subset is read, write, pread64, pwrite64, openat and close.
Unknown/all selections refuse. `captureBuffers:false` disables read/write buffer
definitions; openat path capture remains sensitive. Buffer lengths follow the
count at entry or successful return length at exit, capped 128 bytes. Strings use
one 128-byte bounded helper. Zero/negative return lengths perform no buffer read.
The prior upstream fallthrough is removed in the argument object only; each
branch invokes at most one user-memory helper. Conservative accounting remains
256 fixed plus 256 per eligible argument; the fixed table needs at most 512 bytes
per probe. With an active memory definition, authored maxBytesPerEvent below 128
refuses before arming; larger settings never authorize expanding this table.
Scalar-only selections accept 1..4096 without pointer reads. No post-read trimming
is used to pretend a smaller acquisition bound was honored.

The 160-byte base record preserves upstream offsets 0..96. Added fields occupy
former padding: TID 104, identity version 108 (value 1), task start 112 and process
start 120; both start values are kernel `start_boottime`. Missing CO-RE fields,
zero starts or non-native x86_64 execution refuse. Entry state records task start;
exit must match it and syscall number before reading remembered pointers. The
continuation adds phase 154 and TID 156, preserving 160 bytes. The decoder joins only
exact TID, entry monotonic timestamp and phase, and retains base start identities.
Interleaved threads and PID reuse cannot be joined using TGID alone. Unknown
continuations, loss or pending records at close are gaps, never empty arguments.

The decoder omits comm, pointers, unused scalar registers, unused parameter bytes
and alignment padding. Failed reads retain an explicit fault with no bytes.
Possible truncation at the 128-byte cap is conservative. Map overflow/emission
loss lacks a complete upstream counter, so overall coverage stays explicitly
unknown even when observed perf loss is zero. A sticky stopped flag does not
invent a particular exhaustion/expiry/contention reason.

## Loader and cost gate

The loader consumes only a packaged, digest-verified local ELF; the same pinned
builder and no-network unprivileged compile are reused. A local object needs no
registry or synthesized OCI wrapper. `scripts/package-argument-gadget.py` writes
it into the collector's gadgets directory with exact source pins. Image wiring
and public capability activation remain integration work.

One process-local recorder permits one Capture call, including failed starts.
Durable session/executor fencing remains admission's responsibility. Initialize
budget and definitions once, freeze userspace writes, then expose Pod namespace
and cgroup membership and attach. One perf array serves all namespaces: eight
pages per possible CPU, at most 256 CPUs (8 MiB with 4 KiB pages); at most 128
namespace/cgroup pairs. Thread maps use the already reviewed bound up to 16,384.
One existing-style /proc scan each second discovers changes; cgroup and namespace
FDs prevent inode reuse while entries are active. Cgroup IDs use the 64-bit file handle, as in the pinned upstream Gadget and
[kernel BPF selftests](https://github.com/torvalds/linux/blob/v6.12/tools/testing/selftests/bpf/cgroup_helpers.c),
read from the pinned descriptor; a pathname/inode guess is insufficient.
Kernel cgroup membership and
mount namespace must both match before argument reads. The original parent and
action deadline bound the run; shutdown detaches, drains and joins readers.
Discovery reads directory entries in batches of 128 and observes cancellation
between batches and processes. The two thread maps at 16,384 entries contain
3.75 MiB of values plus 0.25 MiB of keys before kernel hash-map overhead; the
4,096 default uses 960 KiB of values plus 64 KiB of keys. These counts are not
a measured total-memory bound.

Benefit: actual missing pre-read rates, negative-return fallback reads and absent
thread incarnation were found in source, not hypothetical policy checks. The
maintainer did not accept these specification violations. This uses existing
atomics, cilium loader, finite slice and local Pod discovery. Added production
credentials/privileges/network/API calls/watches/Jobs/configuration: zero. Added
mutable kernel state: one timestamp and one bounded membership map. No new retry,
recovery or fallback mode. One rate bucket is cheaper than separate event/byte
buckets; stop is cheaper than periodic refill. Removal disables future argument
capability without altering the metadata engine or refunding admitted work.
Native cost, verifier/CO-RE compatibility and complete installed behavior remain
qualification requirements; host tests and compilation are not substitutes.

## Component validation and remaining integration

The [retained component report](../../test/results/syscall-argument-runtime-local/final-checks.json)
records passing affected Go race tests, gadget-tag loader tests, fixture host
checks, vet, C concurrency tests, and 263,898 decoder fuzz executions in ten
seconds. Its source hashes describe that checkpoint; the later cancellation and
canonical accounting-pin changes and final source pins have
[passing frozen checkpoint checks](../../test/results/syscall-argument-runtime-local/checkpoint-checks.json). The final comment-corrected compile yields the exact 694,968-byte object SHA-256
`4c548b54bf9cc0850352d8a4e4cc23cc5ddc7d50cfbc4bfb96913f319ec1784d`.
No local eBPF program was loaded. The old eleven-case native report describes a
different object and does not qualify this one.

The disposable `collector-argument-engine` focus now prepares seventeen cases,
including negative/zero/short reads, interleaved threads, wrong cgroup and rate
exhaustion, using the production decoder. Kernel verifier acceptance, CO-RE,
pre-read behavior and measured native cost remain pending for this exact object.
Production composition must bind the canonical collector accounting rule,
program and definition digests to original admitted slices, budget engine memory,
package the object, persist typed raw evidence and qualify native download/Stop.
This component alone enables no public capability.
