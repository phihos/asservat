# ADR-248 — Manual packet capture end to end, network headers only (S-04 increment 4)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-NET-001/003/004 (networkHeaders only), REQ-LIF-001/005 (manual sessions),
REQ-DLD-001/003, REQ-CAP-002/004; TASK-05/07/11. Plan:
[S-04 plan](../reviews/s04-plan-2026-10-27.md) §4 row 4, gate rows P3/P4/P19, open items 1, 2, 6
and 11. Builds on [ADR-243](243-packet-syscall-plans-in-preview.md) (plans, libpcap on the hub),
[ADR-244](244-native-artifact-types.md) (PCAPNG type, producer, verifier, framed download) and
[ADR-246](246-node-collector-role.md) (node collector and work channel). Migration **00098**
(00097 is ADR-249's grant table).

## Problem

ADR-243 previews packet plans but refuses every request (`RecorderUnavailable`); ADR-246's node
collector records nothing. No packet evidence can be captured, stored, published or downloaded.

## Maintainer decisions (2026-10-27)

1. The node-side capture **reuses Inspektor Gadget's published, maintained packet-capture gadget,
   pinned by image digest**, through the Gadget runtime already linked into the collector (no
   custom kernel/eBPF program, no hand-written packet parser in this repository).
2. A hub-initiated **collect** exchange on the ADR-171 pattern finishes a capture; the connector
   holds the finished, encrypted-at-connector result until collected, bounded by its budget and
   an expiry.
3. Interim **8 MiB per-capture output cap**; the builtin 16 MiB ring/preset is unchanged; the
   streaming lift is a named follow-up.
4. Nodes get no keys or object-store credentials: the node streams its headers-limited capture
   over its mTLS work channel to the connector, which encrypts and stores with the ADR-244
   producer.
5. No `hostNetwork`: Gadget enters the Pod's network namespace itself.
6. Headers only: the gadget's snapshot length limits each frame; the hub verifier rechecks that
   no packet exceeds the headers-only bound.
7. The request path accepts a manual networkHeaders packet plan only when a node recorder for the
   target's node reports the capability; otherwise `RecorderUnavailable` as before.

## Decision

1. **Engine (decision 1).** The gadget is `ghcr.io/inspektor-gadget/gadget/tcpdump:v0.57.0`,
   index `sha256:2176a5bd…e047a`, linux/amd64 manifest `sha256:38d9bd06…06981`, config
   `sha256:6379a227…84c` (the gadget.yaml of the Go module) and eBPF program
   `sha256:1e492d7c…ad5f2` (34,224 bytes). `scripts/fetch-gadget.sh` fetches these four blobs by
   digest for the image build (`/usr/lib/asservat/gadgets/tcpdump/blobs/sha256/`); the collector
   pushes them into an in-memory OCI store, which verifies size and digest, and runs the gadget
   through the documented `gadgetcontext.WithOrasReadonlyTarget` path of the local runtime with the
   `oci-handler`, `ebpf` and `SocketEnricher` operators (no registry, no pull, no signature
   lookup). Path chosen for the fewest new modules: the `ebpf` operator alone already links
   Gadget's OCI/signature packages, so adding the documented `oci-handler` adds no module
   (measured: 160 linked modules either way); a hand-written image operator would only mirror
   Gadget internals. `go.mod` gains 99 indirect modules (gopacket v1.7.4, oras-go, image-spec
   are direct) and one `replace` (Gadget's own fork of the OpenTelemetry eBPF profiler, the same
   directive as Gadget's `go.mod`, needed by the `ebpf` operator's symbolizer). The gadget's
   classifier is relocated against the socket map layout, which only the `SocketEnricher`
   operator supplies (first native run: `bad CO-RE relocation: invalid func unknown#195896080`
   without it); its optional `cwd`/`exepath` fields are off, and its process attribution never
   enters the PCAPNG.
2. **Attachment (decision 5).** The collector finds one process of the target Pod in the host
   process table by the Pod UID in its cgroup path, refuses a Pod in the host network namespace
   (`TargetHostNetwork`), and hands it to the gadget's `AttachContainer`, which enters the Pod's
   and the host's network namespaces (setns) and attaches its ingress and egress classifiers with
   tc `clsact` to the host side of each of the Pod's veth pairs. The gadget uses tc, not TCX, so
   the packet assessment now requires tc and reports hook `tc`.
3. **Filter (S2, hub-compiled).** The gadget's own `pf` parameter compiles with a second, pure-Go
   compiler (the one the feasibility lab found to reject a valid IPv6 filter), so it is not used.
   The node runs the exact hub-compiled libpcap program on every frame with the maintained
   `golang.org/x/net/bpf` interpreter, after checking its digest against the work item. libpcap's
   `len` loads are evaluated against the frame's original wire length. A program the interpreter
   cannot run exactly (`ldx len`, `neg`, ancillary loads) is refused at preview by the hub
   compiler (`packets.CheckProgram`). Cost: every frame of the Pod crosses the gadget's perf
   buffer before filtering (measured below).
4. **Headers only (decision 6).** The gadget's `snaplen` is 134 bytes: Ethernet (14) + the
   largest IPv4 header (60) + the largest TCP header (60). The published gadget can only cut at a
   fixed length, which keeps payload of frames with shorter headers, so the node cuts every frame
   at the end of its transport header using gopacket's layer decoders (no own parser) and drops
   what it cannot classify. Retained: Ethernet II + unfragmented IPv4 (options are header fields)
   or IPv6 without extension headers + TCP (with options), UDP, ICMP (8-byte header) or ICMPv6
   (4-byte header). Dropped and counted: other link/network formats (`unsupported`, e.g. ARP,
   VLAN, GRE), IPv4 fragments (`fragment`), IPv6 extension headers (`extension`), undecodable
   headers (`malformed`). The original wire length stays in each enhanced packet block.
5. **What the verifier checks (decision 6).** `packets.CheckHeadersOnly` runs on the same
   authenticated read as the ADR-244 structural PCAPNG check (no second unwrap) and requires, for
   every interface and packet: link type Ethernet, interface snapshot length ≤ 134, captured
   length = data length ≤ 134 and ≤ original length, and that gopacket decodes the packet as the
   retained formats above with its transport header ending exactly at the last captured byte (no
   payload, padding or trailer byte). A failure refuses publication.
6. **Node recording.** New work kind `packetCapture` with a typed payload (capture ID, Pod UID,
   program and digest, duration 1 s–5 min, output cap 64 KiB–8 MiB). The node reserves the cap
   from its frozen budget, runs the gadget for the duration, writes a bounded PCAPNG (one section,
   one interface, enhanced packet blocks, a closing interface statistics block with frames seen
   and not retained), takes the upload budget and posts it once to
   `/internal/v1/node/capture` (4-byte header length, a closed JSON header with counters, then
   the PCAPNG). Only the node process the capture was queued for may deliver, once, until the
   start allowance (10 s) plus the duration plus 30 s. A missing or host-network Pod is reported
   as a failure result (`TargetNotFound`, `TargetHostNetwork`) instead of an empty capture.
7. **Acceptance (decision 7).** A composition preview whose plan is one `packetCapture` action
   with profile `networkHeaders`, a manual session (ongoing `manualSession` or `onTrigger` with
   `before: 0s`) recording 1 s–5 min after it starts, is requestable when the target's region
   answers the new pre-work query `packet-recorder` with `available` (a current collector report
   for the Pod's node offers the packet recorder). Such a preview reads the same facts as pod
   status (capability, retention of the `packetCapture` evidence type, storage binding,
   processing coverage) and its plan (`recorder-preview/v1`) carries `acceptance: nodeRecorder`
   instead of `recorderUnavailable` (the value enters the execution digest). Every other plan
   keeps the ADR-243 blocker. `request_capture` checks the node again, recompiles the reviewed
   plan from the frozen composition and programs (no compiler is consulted after preview) and
   admits it with expectation native type `pcapng`, the generated action ID, native limit 8 MiB
   and the accepted recording (program, duration, cap); it refuses a request whose recording
   cannot finish 30 s before the write window ends.
8. **Interim output cap (decision 3).** The recording keeps at most
   `min(limits.maxBytes, 8 MiB)`; the preview shows that output limit. An authored output edit
   above 8 MiB (`actionMaxBytes`) is refused with its field path; the builtin profile does not
   expose that edit, so its 16 MiB preset applies unchanged and is capped. One storage frame:
   no streaming journal is needed at the connector.
9. **Start and collect (decision 2).** The ADR-171 start runs unchanged up to the committed
   local start; the regional operation `start-recording` (instead of `acquire-context`) queues the
   work on the Pod's node and moves the attempt's prepared keys (three wraps through the local key
   service, as for pod status) into the connector's recording holder. The execution stays
   `started`. When the node's result arrives, the holder streams it through the ADR-244 artifact
   producer (framed encryption, four write-only objects; plaintext is never buffered beyond one
   frame and never leaves the connector) and keeps only the writer completion. The hub-api
   process lists started recordings every 3 s (`ListStartedRecordings`) and, once their duration
   plus 2 s has passed, runs a collect exchange: it signs the capture's work as for a start, the
   region answers `collect-recording` with `pending`, `stored` (completion) or `failed`
   (`captureFailed`, `storeUnconfirmed`), and the hub records the stored completion (or the
   failure) through the existing execution facet with a current connector process observation and
   recovery proof. The holder keeps at most 64 recordings and encrypts at most 32 MiB of results at
   once; an outcome waits until its write window plus one minute.
10. **Publication and download.** Publication, retention and the publication gate use the
    expectation's evidence type (`packetCapture`); migration 00098 admits the recorder action in
    the processing lineage; the local-start CRD admits the recorder action with the 8 MiB limit
    (`scripts/start-crd.py`, `local-start.schema.json`). Download of a published PCAPNG uses the
    ADR-244 `FramedNativeSource` through the installed native download path (see qualification
    for its state).
11. **Privileges.** The collector container adds `PERFMON` (the gadget's perf buffer),
    `SYS_ADMIN` (setns into the Pod's and host's network namespace, the Gadget host
    initialization) and `SYS_PTRACE` (another user's `/proc/<pid>/ns/net`) to `BPF`, `NET_ADMIN`
    and `SYS_RESOURCE`; still not `privileged`, runtime-default seccomp, no host network.

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | First packet evidence of the product; every network incident needs it (plan P3). Not an observed production failure: no installation records packets yet. |
| 2 | Risk accepted | Yes: plan increment 4 and the maintainer's 2026-10-27 decisions above. |
| 3 | Typical deployments | Yes: the default network-connections profile. |
| 4 | Precedent | `ig run tcpdump` (the same gadget), tcpdump `-s` snaplen, Wireshark/Kubeshark per-node capture. |
| 5 | Privileges added | Per node: `PERFMON`, `SYS_ADMIN`, `SYS_PTRACE`; during a capture Gadget's socket enricher tracks the node's sockets in kernel memory (process names, not retained). Connector: holds one attempt's data keys per started recording until stored or expired, reads the target Pod's node (`get pods`, already held). Hub-api: a background collect loop using the existing execution facet and work signer; no new SQL role or credential. |
| 6 | Failure/degraded states | 0 new persisted states: `RecorderUnavailable` (existing), `captureFailed`/`storeUnconfirmed` (existing execution phases); `Recording` is the derived `started` phase. |
| 7 | Self-configuration | None: snaplen, caps, cadences and margins are constants. |
| 8 | External dependencies | Inspektor Gadget v0.57.0 runtime and its tcpdump gadget (digest-pinned), tc `clsact`, kernel BTF, gopacket v1.7.4, golang.org/x/net/bpf. |
| 9 | Cost at scale | Measured on a 4-vCPU GitHub runner (below): unfiltered generator traffic 8,187 frames/s and 0.93 MB/s on the wire with 0 lost samples; 8 MiB cap reached in 10 s at that rate; a 10 s recording delivered 10.42–10.44 s after it was queued; a 5 s recording (2.18 MB) encrypted and stored by the connector 5.77 s after it was queued (run 40481241336). Per capture: ≤ 8 MiB node memory (frozen reservation), ≤ 8 MiB connector streaming, 3 key wraps, 1 collect exchange (5 s bounded); per hub-api one list query every 3 s. Binary: collector 155.5 MB (ADR-246: 131.4 MB). |
| 10 | Upgrade/rollback | Migration 00098 only replaces the lineage trigger function (down restores it); the CRD rule only widens; older binaries never write a recording expectation; collector disable removes the recorder. |
| 11 | Smaller fix | Kernel-side truncation or filtering needs a custom gadget (excluded); the gadget's own filter compiler diverges from libpcap; a recording cannot run inside the 5-second start window, so it needs the collect exchange; the 8 MiB cap avoids the connector streaming journal. |

## Remaining limits

- **Interim cap and no rings.** At most 8 MiB per capture; no pre-trigger history (manual
  sessions start at acceptance); policy arming and snapshots are increments 6–7; the streaming
  lift (above one frame, connector-side journal) is a named follow-up.
- **Filtering cost.** All frames of the Pod reach user space before the hub-compiled filter;
  loss counters come from the gadget's perf reader (reported as a log line, counted by the
  collector).
- **Connector restart** drops held recordings; their executions stay `started` until the
  capture's retention cleanup (the collect cannot record an outcome for another connector
  process).
- **Lifecycle provenance.** A manual recording is stored without ADR-244 `actionLifecycle` save
  provenance (it is not a save from an armed source); its acquisition interval is the node's
  recording interval.
- **Capture history.** A recording appears in capture history, but `get_capture_settings`
  refuses it as unavailable (its scope is a recorder plan); repeating it with its
  filter is S-06 increment 12 / plan increment 5.
- **linux/amd64 only:** the pinned manifest is amd64; other architectures report the engine
  unavailable until their manifest is pinned.
- **Signed work fields.** The API context work keeps its fixed `pod-status`/4096 format fields;
  the expectation digest binds the recording's action and limit.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-04-increment-4-manual-packet-capture-adr-248-2026-10-27).
