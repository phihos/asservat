# Node collector role and work channel

[ADR-246](../decisions/246-node-collector-role.md) implements S-04 increment 3 of the
[S-04 plan](../reviews/s04-plan-2026-10-27.md): the A-NODE `asservat node` process, the I-02 node
work channel to the cluster connector, the capability probe and the node budgets. It records
nothing yet; increment 4 adds the first recorder.

## Components

| Package | Component | Role |
| --- | --- | --- |
| `internal/domain/collector` | C-24 | Probe facts and their assessment (`Assess`), node `Ceilings`/`Budget` (ring, frozen, upload token bucket), `StatusCadence`, closed work kinds and receipts, attested `Identity` |
| `internal/application/delivery` | C-19 | `NodeChannel`: enrollment, one current process per node, certificate lookup, bounded per-node work queue with long poll, latest report per node |
| `internal/transport/node` | C-20 | HTTP handler (connector) and client (collector) for `/internal/v1/node/{enroll,poll,status}`; wire ↔ domain conversion with closed-value validation |
| `internal/contracts/node_channel.go` | C-20 | Closed wire DTOs, `NodeDeployment` input, fixed paths and the dedicated token audience |
| `internal/adapters/kubernetes/node_attester.go` | C-21 | TokenReview plus live Pod/DaemonSet/Node checks |
| `internal/adapters/mtls/node.go` | C-21 | Connector's in-memory node issuer and server TLS config; collector's process key and leaf |
| `internal/adapters/linux` | C-23 | File probes (procfs, sysfs, statfs magics, `/proc/*/comm`) and the one BPF probe |
| `internal/adapters/gadget` | C-23 | Embedded Inspektor Gadget v0.57.0 local runtime (build tag `gadget`), stub otherwise |
| `internal/bootstrap/node.go`, `node_channel.go`, `regional_nodes.go` | bootstrap | `asservat node`, `NodeChannelServer`, the connector's optional `collector` input |

## Flow

1. The kubelet starts the DaemonSet Pod only on a host carrying `/etc/asservat-disposable-host`
   (hostPath type `File`); the process checks the file again and stops otherwise.
2. The process disables its core dumps, reads `node.json`, reads the kernel boot ID, probes the
   node once (files, then one `sched_cls` program load and a TCX link attempt against a
   non-existent interface, then the engine), generates a random epoch and a P-256 key.
3. Enrollment: `POST /internal/v1/node/enroll` with the projected token (audience
   `asservat-node:<installation>`, 600 s), an identity-free CSR, the boot ID and the epoch, over TLS
   1.3 to the pinned connector name and roots. The connector reviews the token, reads the token's
   Pod (running, undeleted, controller = the named DaemonSet with its current UID, on the token's
   node, with the collector account) and Node (UID and kubelet `bootID` equal to the claimed boot
   ID), then signs a 20-minute client leaf whose URI names cluster, node UID, Pod UID and epoch.
4. Status: one report immediately, then every 15 s (S9), sooner but at least 1 s apart when work
   receipts are pending. A report carries the facts, the per-mechanism assessment, the node budget
   and receipts. The connector keeps only the latest report per node, in memory; a node without a
   report for 45 s is not current.
5. Work: the collector long-polls (25 s hold) for work after its last sequence. Kinds are
   `armSource`, `stopSource`, `snapshot`, `peerGeneration` (no producer; refused with
   `RecorderNotImplemented`, `WorkExpired` or `WorkUnknown`) and `packetCapture`
   ([ADR-248](../decisions/248-manual-packet-capture.md), the only kind with a typed payload).
6. Renewal at one minute before expiry, with the same key and epoch. A 401 (connector restarted
   or process replaced) leads to a fresh enrollment with the same key and epoch.
7. One current process per node: any enrollment for the node by another Pod, boot or epoch
   replaces the earlier process; its certificates stop authenticating, its queued work is dropped
   and its open poll ends.

## Assessment

`Assess` requires, for both mechanisms: kernel ≥ 5.15, BTF, cgroup v2, BPF program load, host
processes visible (host PID namespace), a known runtime (containerd or CRI-O daemon observed) and
an initialized engine; packet additionally TCX (preferred) or tc, syscall additionally tracefs.
`Prerequisites` reports whether they hold. ADR-248: the packet recorder is `Available` when they
hold (hook `tc`: the gadget attaches tc `clsact` classifiers; TCX alone is not enough); syscall
recording stays `AdapterUnavailable` with `RecorderNotImplemented`.

## Manual packet capture (ADR-248)

1. The hub asks the target's region (`packet-recorder` pre-work query) whether the Pod's node
   offers the recorder; only then is a manual networkHeaders plan requestable.
2. The ADR-171 start prepares the attempt's keys at the connector and, instead of acquiring,
   `start-recording` queues `packetCapture` on the Pod's node (program, digest, duration, cap)
   and hands the keys to the connector's recording holder.
3. The node runs the pinned tcpdump gadget on the Pod's veth pairs for the duration, runs the
   hub-compiled program on each frame, cuts frames at the transport header and uploads one
   bounded PCAPNG to `/internal/v1/node/capture`.
4. The holder encrypts and stores it with the artifact producer (four write-only objects) and
   keeps the writer completion; the hub-api collect loop runs a `collect-recording` exchange and
   records the stored completion; publication verifies with the headers-only recheck.

## Limits

Enrollment: claims precheck without API calls, then 5/s globally (burst 20), one per source
address per 5 s (burst 3), 8 attestations in flight; refused with 429. At most 5,000 nodes per connector, 64 queued items and 16 per poll, 64 receipts per report, 64 KiB
per message (256 KiB per poll answer), three connections per node (15,016 in total), 20-minute leaves with at most two per
process. Node ceilings default to 256 MiB ring, 256 MiB frozen, 32 MiB/s upload with a 64 MiB
burst, and bound the container memory limit (ring + frozen + 128 MiB).

## Not yet

The regional installer provisions the connector's `collector` input (Secret, Service and public
ConfigMap `connector-nodes`, the four attestation reads; ADR decision 9), but no native run has
installed it yet. Only manual packet captures exist (no rings, policy arming or snapshots);
budget policy node limits are accepted by the schema but not yet intersected at admission. See the
ADRs.

## Exact packet source observation foundation

The explicit regional `ResolvePacketSource` operation may return one
`targets.PacketSourceObservation`: the whole target Pod UID, actual Node UID and
boot ID, collector Pod UID/process epoch, and original observation interval.
It reuses the same Pod resolution and authenticated `NodeChannel.NodeView`.
Existing `ResolvePacketRecorder` metadata answers omit `Source`, preserving old
strict wire decoders; this slice exposes no new source-query transport.
Its interval starts at the later original Pod/report observation and ends at the
earliest original Pod cutoff, report receipt plus the existing 45-second stale
bound, or caller deadline. A new Pod read cannot renew the node report. The
ordinary API target pin and metadata availability outcome remain unchanged;
missing or expired source facts cannot support sensitive dispatch.

`NodeChannel.EnqueuePacketExpected` consumes this single domain target value
directly. Under the existing queue mutex and clock it checks cancellation,
original interval, target Pod, Node UID/boot and collector Pod/epoch, current
recorder availability and the original latest-start bound. Its facts are not a
grant or permit. Already queued work retains its original latest-start bound
rather than inheriting the short source-fact deadline. Existing enrollment
replacement drops the old process queue and pending results; new epochs cannot
inherit them. Ordinary metadata `EnqueuePacket` keeps its existing behavior.

The shared `collector.ObservationBinding` and `ObservationPermit` own the local
meter values; bootstrap aliases preserve the existing gate API. The accounting
rule digest remains identical, represented as a fixed value verified against its
canonical rule string in tests. This foundation adds no authority issuer,
SQL/session mutation, sensitive wire permit or raw-predicate enablement.

Cost: zero additional SQL/API/provider calls, watches, timers, goroutines,
services, configuration, credentials or privileges. Each explicit source
answer adds one bounded five-string/two-timestamp value (128-byte Go struct on
amd64, excluding existing referenced strings and JSON encoding). Dispatch copies
that value and adds fixed comparisons under the existing mutex. These are source
size/call-count estimates, not installed CPU or end-to-end measurements. SQL
credit issuance, authenticated permit transport, node enforcement composition and
installed qualification remain pending in the policy-owned continuation.

Local verification: a controlled regression bypassing expected-source checks
failed with actual exit 1 (delivery 0.002s), demonstrating forbidden queue effects.
Restored checks passed the final delivery race (1.049s), target/context-start
races (1.006s/10.790s) and bootstrap race (56.527s). The unchanged local meter and
shared accounting-rule test passed the collector race (1.006s). Canonical
pre-push returned 0, including the actual Go import gate, specification/design
checks, vet and 231 console tests. Its first new-worktree attempt failed only
because pinned console dependencies were absent; offline `npm ci` completed
before the successful run. These are pure/local component checks, not SQL,
collector, private permit-wire or installed sensitive-observation qualification.

## Conservative prefix proof component

`packets.CheckPrefixProgram` is an unwired prerequisite for a future sensitive
predicate. It reuses the maintained typed cBPF disassembler and existing opcode/VM
validation, then checks every instruction, including unreachable instructions.
Absolute/MSH reads must fit the existing 134-byte prefix. X starts at zero and
can only be loaded from a constant <=60 or MSH (4 * low nibble <=60); TAX and
scratch-to-X are refused. Indirect reads use that global bound with uint64
arithmetic. This intentionally rejects some programs whose path-specific reads
would fit; there is no new parser, VM, branch interpreter or configuration.

`LD len` retains existing `Filter.vmFor` specialization from original Wire. Raw
x/net VM `ExtLen` returns slice length, so that unspecialized VM alone is not the
prefix evaluator. Maintained-VM tests compare full frames with their exact
min(Wire,134) prefix and the same original wire length, including len >134,
IPv4 IHL20/60 and the pinned 11-instruction `tcp[13]` program (largest read ends
at byte88). IPv6/VLAN nonmatches for that IPv4 program are not broader support
claims. Runtime complete-prefix/length validation, prompt unknown/loss handling,
SQL/permit composition and native qualification remain separate requirements.

The existing opcode-only check demonstrably permits an out-of-prefix read that
changes a full-frame match into a silent nonmatch. Component RED exited1
(0.003s); the new checker and full packets race passed (1.027s). Local amd64
benchmarks of the complete checker, including existing VM validation, measured
547–579ns/632B/22 allocations for11 instructions and 9.29–9.36us/11,112B/516
allocations for256. These are synthetic per-plan checks, not installed CPU or
packet throughput measurements. There is no added per-frame code, SQL/API/provider
call, watch, timer, goroutine, service, credential, privilege or runtime knob.
No compiler/node call site is wired by this component; raw gates remain closed.

## Packet timestamp clock domain

The pinned tcpdump program emits `CLOCK_MONOTONIC` nanoseconds. Each capture
pairs that clock once with wall reads before/after the sample, before engine
attachment; valid nonzero records retain their original relative times through
that immutable UTC mapping. The previous process-global Gadget converter used
`CLOCK_BOOTTIME`, whose suspend accounting differs. The correction adds one
MONOTONIC syscall and two wall reads per capture, with no per-packet clock reads,
wire fields, new authority interval or clock revalidation mechanism.

Sampling failure refuses before attachment. An unrepresentable nonzero packet
time emits the existing unknown-input notice when present and sets one failure
flag under the existing callback mutex. After the engine joins, both observed
and nil-notice capture return `ErrEngineUnavailable`; invalid times are never
clamped or replaced by arrival time. The existing zero-timestamp arrival fallback
is deliberately preserved as legacy behavior, not original kernel-time evidence.
The pair does not qualify wall-clock steps, uncertainty, suspend behavior or
installed failure causation. Source health, original-window and ongoing-source
qualification remain separate; this adds no event-time watermark guarantee.

## Unwired sanitized ring and original-window copy component

`adapters/packets.Ring` is a local foundation for REQ-NET-003 and
REQ-LIF-003/004, not an implemented C-12 SourceManager or Save executor.
Constructor inputs are normalized caller/admin bounds, with the original context
and hard memory cutoff retained. No source authority, renewal interval, raw
observation credit or finite policy twenty-second lease is inferred. The owner
must drive quiet advancement, observation watermarks, stop and joined closure.
`ObservedThrough(at)` records consumer-established continuous source operation
under declared clock, delivered-record cut and loss semantics. It does not
assert that every future callback has a newer timestamp. The earlier inclusive
all-future-callback prerequisite was an agent-added restriction, corrected here;
original window, no-known-gap and explicit uncertainty requirements remain.
Wall time or a packet-free interval alone proves no coverage. Actual engine
health, clock mapping and backend backlog qualification remain pending. Parser/filter/control and encoder
memory are separate from the framed historical arena.

Finite `Snapshot` still copies only available original-time records. The distinct
`BeginWindowSnapshot` reserves one full `maxCopyBytes` arena and one local snapshot
slot before pre-copying `[from,t0]` and recording its retained-arrival cut.
`Complete` copies original-window records not already copied: original time >t0
or arrival sequence after that cut. This includes buffered late pre records
available by the final locked cut, without duplicating the pre-copy or shifting
original timestamps. Later callbacks are outside the sealed delivered-record set,
not evidence of lossless physical acquisition. It copies once into
remaining capacity: no allocation growth, second slot, shifted window or general
extension. Full capacity is retained even for a quiet window and released once on
Close; aggregate node/workload reservations belong to the future owner. Pending
iteration refuses. Successful completion seals immutable records; capacity failure
is terminal and refuses iteration until cleanup. Invalid early/backward completion
refuses without advancing the source or sealing the handle. Pre/post coverage is
computed independently: later live prehistory eviction cannot erase the admitted
copy, while post eviction, gaps and early stop remain partial. First arrival
sequence fits the existing segment header; record framing/arena size is unchanged.
A coalesced eviction high-watermark detects post-admission uncopied arrivals:
these conservatively mark unknown/partial, including evicted late pre records.
This may also mark partial for unrelated newer arrivals; it is not a measured
selected-window loss count. Evicting only already-copied pre records does not
invalidate their independent copy. Sequence exhaustion refuses without refill.

The original processing context/deadline is independent of the ring's source
memory bound. Completion at or after that memory bound cannot read new post bytes;
only the existing pre-copy may survive as partial under still-valid processing
bounds. Cancellation while copying is rechecked before completion: processing
cancellation refuses output; source cancellation discards the tentative post-copy.
An after-zero window needs no new acquisition; while source memory remains valid
it can also include late original-window records already delivered by its final
cut. With closed source memory it can seal a complete pre-copy only if no newer
retained arrivals could have been omitted and no newly known unknown input
affects the original window, otherwise it stays partial. Current unknown-input
coverage also remains binding when merging late pre records; freezing the
pre-copy does not hide an intervening Gap. This reads only the existing coverage
metadata, without importing the current eviction floor into the preserved copy.
An explicit known Stop timestamp remains in the result, including after-zero
and Stop followed by Close; Close/cancellation never invents a stop timestamp.
This adds no stopped-source grace. Snapshot-to-ring lock order matches Close;
coverage returns a locked value and readers never borrow clearable storage.

This component adds no engine owner, goroutine, timer, SQL/wire/API, configuration
or permission. Existing source/session admission, actual quiet expiry and callback
join, replica ceilings, original post-window scheduling, Save, publication, native
and history/repeat composition remain pending. Ordinary sanitized collection does
not inherit sensitive raw-predicate credit/session limits.
