# Node collector role and work channel

[ADR-246](../decisions/246-node-collector-role.md) defines the A-NODE `asservat node`
process, the I-02 node work channel to the cluster connector, the capability probe and the
node budgets ([S-04 plan](../reviews/s04-plan-2026-10-27.md)). Mechanisms follow
[ADR-330](../decisions/330-event-driven-system-design.md): one long-lived stream per node,
pushed work, status on change, standard workload identity.

## Components

| Package | Component | Role |
| --- | --- | --- |
| `internal/domain/collector` | C-24 | Probe facts and their assessment (`Assess`), node `Ceilings`/`Budget` (ring, frozen, upload token bucket), closed work kinds and receipts, collector `Identity` |
| `internal/application/delivery` | C-19 | `NodeChannel`: one current stream per node, bounded per-node work queue pushed on that stream, latest status per node |
| `internal/transport/node` | C-20 | Stream handler (connector) and client (collector); wire ↔ domain conversion |
| `internal/contracts/node_channel.go` | C-20 | Wire DTOs, `NodeDeployment` input, fixed paths and the dedicated token audience |
| `internal/adapters/kubernetes/node_attester.go` | C-21 | TokenReview of the collector's projected token |
| `internal/adapters/linux` | C-23 | File probes (procfs, sysfs, statfs magics, `/proc/*/comm`) and the one BPF probe |
| `internal/adapters/gadget` | C-23 | Embedded Inspektor Gadget v0.57.0 local runtime (build tag `gadget`), stub otherwise |
| `internal/adapters/httpheaders` | C-23 | ADR-282 `http-response-headers/v1` projector: gopacket TCP reassembly and net/http HTTP/1 framing within the httpHeaders profile bounds |
| `internal/bootstrap/node.go`, `node_channel.go`, `regional_nodes.go` | bootstrap | `asservat node`, `NodeChannelServer`, the connector's optional `collector` input |

## Flow

1. Scheduling: the DaemonSet carries a required node affinity on an administrator-applied
   node label (development: `asservat.io/disposable-host=true`). Nodes without the label never
   run the collector; no host file gate is used.
2. Startup: the process disables its core dumps, reads `node.json`, probes the node once (files,
   then one `sched_cls` program load and a TCX link attempt against a non-existent interface, then
   the engine).
3. Connection: the collector opens one long-lived HTTP/2 stream to the connector over server TLS
   (pinned connector name and roots) and presents its projected ServiceAccount token (audience
   `asservat-node:<installation>`). The connector checks it once per connection with TokenReview;
   the bound token's Pod and Node claims identify the collector. No node certificate, CSR, boot-ID
   or epoch binding is involved. The kubelet rotates the token; the collector presents the current
   token when it reconnects. A connector restart only drops connections; collectors reconnect with
   jittered exponential backoff and need no re-enrollment.
4. Hello: the first message carries the protocol version and a capability list. The connector
   sends only work kinds and fields the collector announced. Both sides ignore unknown fields, so
   a DaemonSet rolling update and hub/connector/node N−1 skew work without lockstep upgrades.
5. Status: one full report after Hello, then a report only when facts, assessment, budget or
   receipts change. Liveness is the open stream itself: the connector uses HTTP/2 PING (or gRPC
   keepalive) on the connection, and stream close or a keepalive timeout is the event that marks
   the node not current. There is no application heartbeat. Liveness grants, renews or revokes no
   authority, and losing it does not stop sources. The connector keeps the latest report per node
   in memory. For optional live-runtime status the connector
   also keeps report-to-report rates in memory. Source-loss events and rows dropped by bounded
   reply encoding are cumulative; pending rows are current shared-buffer occupancy, not exact
   per-viewer lag. `read-live-runtime` aggregates current totals/rates with no node labels;
   incomplete predecessors suppress the whole rate set.
6. Work: the connector pushes work on the stream. Kinds are `armSource`, `stopSource`,
   `snapshot`, `peerGeneration` (no producer; refused with `RecorderNotImplemented`,
   `WorkExpired` or `WorkUnknown`) and `packetCapture` ([ADR-248](../decisions/248-manual-packet-capture.md),
   the only kind with a typed payload). Each item carries its operation ID; a repeated ID returns
   the existing receipt. Stop and cancel arrive as pushed work and end the matching acquisition.
7. One current stream per node: a new stream from another collector Pod on the same node
   replaces the earlier one; its queued work is returned to the connector and its stream ends.

## Assessment

`Assess` requires, for both mechanisms: kernel ≥ 5.15, BTF, cgroup v2, BPF program load, host
processes visible (host PID namespace), a known runtime (containerd or CRI-O daemon observed) and
an initialized engine; packet additionally TCX (preferred) or tc, syscall additionally tracefs.
`Prerequisites` reports whether they hold. The packet recorder is `Available` when they hold
(hook `tc`: the gadget attaches tc `clsact` classifiers; TCX alone is not enough); syscall
recording stays `AdapterUnavailable` with `RecorderNotImplemented`.

## Manual packet capture (ADR-248)

1. Target resolution ([workload-target-resolution.md](workload-target-resolution.md)) answers
   from the connector's informer cache whether the Pod's node offers the recorder; only then is a
   manual networkHeaders plan requestable.
2. The start prepares the attempt's keys at the connector and queues `packetCapture` on the
   Pod's node (program, digest, duration, cap); the keys go to the connector's recording holder.
3. The node checks the target Pod UID, runs the pinned tcpdump gadget on the Pod's veth pairs for
   the duration, runs the hub-compiled program on each frame, cuts frames at the transport header
   and streams one bounded PCAPNG back on its connection.
4. The holder encrypts and stores it with the artifact producer and reports the completion to
   the hub over the connector connection; the regional reader verifies envelope, manifest and
   index before the hub publishes ([context publication](context-publication.md)).

## Exact packet source

`ResolvePacketSource` returns one `targets.PacketSourceObservation`: the target Pod UID, its
Node UID and the collector Pod UID currently streaming for that node. It comes from the
connector's informer cache and `NodeChannel` state. `NodeChannel.EnqueuePacketExpected` checks,
under the queue mutex, cancellation, the target Pod, Node, collector Pod, recorder availability
and the original latest-start bound before queuing. A replaced collector stream returns its
queued work; it is not inherited. The facts are not a grant.

## Limits

At most 5,000 nodes per connector, one stream per node, 64 queued items per node, 64 receipts per
report and 64 KiB per message. TokenReviews for new streams are rate limited per connector (default 50/s,
burst 200); excess Hellos receive a retry-after. Node ceilings default to 256 MiB ring, 256 MiB frozen,
32 MiB/s upload with a 64 MiB burst, and bound the container memory limit
(ring + frozen + 128 MiB). Only manual packet captures exist (no rings in production, policy
arming or snapshots); budget policy node limits are accepted by the schema but not yet
intersected at admission.

## Ongoing-source resources (ADR-262)

`NodeDeployment.Ceilings` carries aggregate active-source count, input bytes/s and input burst
alongside the ring/frozen/upload limits (chart development references 16 / 16 MiB/s / 16 MiB).
All-zero input denies ongoing capacity and leaves finite work unchanged; partial node caps are
invalid. Optional node/workload budget-policy values (`SourceResources`, `maxRingBytes`,
`maxFrozenBytes`) only lower these limits; ongoing admission intersects them with the collector
ceilings. `AcceptedCapacitySource.CurrentSourceResources` returns a copy of the accepted values;
it is a resource observation, not a source permit or read permission.
[ADR-262](../decisions/262-protected-ongoing-resource-projection.md).

## Prefix proof

`packets.CheckPrefixProgram` checks a cBPF program before a sensitive predicate may use it. It
reuses the maintained typed disassembler and VM validation and checks every instruction,
including unreachable ones. Absolute/MSH reads must fit the 134-byte prefix. X starts at zero
and can be loaded only from a constant ≤ 60 or MSH (4 × low nibble ≤ 60); TAX and scratch-to-X
are refused. Indirect reads use that bound with uint64 arithmetic. Some programs whose actual
paths fit are rejected deliberately. `LD len` keeps `Filter.vmFor` specialization from the
original wire length, so a prefix evaluates exactly like the full frame. No call site is wired.

## Packet timestamps

The pinned tcpdump program emits `CLOCK_MONOTONIC` nanoseconds. Each capture pairs that clock
once with wall reads before and after the sample, before engine attachment; records keep their
original relative times through that UTC mapping. Sampling failure refuses before attachment.
An unrepresentable nonzero packet time emits the unknown-input notice and the capture returns
`ErrEngineUnavailable` after the engine joins; invalid times are never clamped or replaced by
arrival time. A zero kernel timestamp falls back to arrival time; that time is not kernel-time evidence.

## Sanitized ring and original-window copy

`adapters/packets.Ring` serves REQ-NET-003 and REQ-LIF-003/004; it is not yet driven by a C-12
source manager or Save executor. It receives normalized bounds and the original context and
memory cutoff; its owner drives quiet advancement, `ObservedThrough` watermarks, stop and joined
closure. `ObservedThrough(at)` records continuous source operation under the declared clock,
delivered-record cut and loss semantics; wall time or a packet-free interval alone proves no
coverage.

`Snapshot` copies available original-time records. `BeginWindowSnapshot` reserves one full
`maxCopyBytes` arena and one snapshot slot, pre-copies `[from, t0]` and records its
retained-arrival cut. `Complete` copies original-window records not yet copied (original time
> t0, or arrival after the cut), once, into the remaining capacity, and seals immutable records.
Capacity failure is terminal; invalid early or backward completion refuses without sealing.
Pre/post coverage is computed independently: later prehistory eviction cannot erase the admitted
copy, while post eviction, gaps and early stop make the result partial. An eviction
high-watermark conservatively marks the window partial when uncopied arrivals were evicted.
Completion at or after the memory cutoff cannot read new post bytes; only the pre-copy may
survive as partial. Processing cancellation refuses output; source cancellation discards the
tentative post-copy. A known Stop timestamp stays in the result; Close or cancellation never
invents one. Snapshot-to-ring lock order matches Close.

`runPacketRingEngine` connects the observed-engine callback contract to the ring. Its caller
keeps all reservations through engine join and ring cleanup. Notices mark known gaps and cancel
acquisition; final loss stays an explicit unknown outcome. Engine errors and cancellation stay
distinguishable. The bridge asserts no `ObservedThrough` and preserves original frame times.
