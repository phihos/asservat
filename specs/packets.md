# Packet selection, rings and protocol evidence

These requirements extend the Inspektor Gadget integration; each capability is advertised only after its qualification gate passes. See [source research](../docs/research/packet-capture-flexibility.md) and the [parameters contract](contracts/packet-capture.schema.json).

## REQ-NET-001 — Composable bounded filters

The effective selector is **authorized target AND resolved peers AND user filter AND administrator ceilings**. Peer entries are ORed; optional transport/port constraints intersect that union. An empty peer resolution matches nothing, never all traffic. The peer picker lists only resources the caller may see. Selecting a peer grants no right to read its logs, files or memory or to attach a collector to it.

The optional `filter` uses tcpdump/pcap-filter syntax. The hub compiles it during preview ([ADR-243](../docs/decisions/243-packet-syscall-plans-in-preview.md)) with a statically linked, pinned libpcap on a dead `EN10MB` handle with snapshot length 65,535. The plan carries the classic BPF program and its SHA-256 digest; the node runs that exact program on each frame in user space (`golang.org/x/net/bpf`, [ADR-248](../docs/decisions/248-manual-packet-capture.md)) and never compiles. A program that evaluator cannot run exactly is refused at preview. The only bound is the compiled program: at most 4,096 instructions (`BPF_MAXINSNS`; cBPF has no backward jumps, so per-frame cost is at most the program length).

libpcap resolves host, network, Ethernet and service names while compiling, so every term that is not a supported primitive or a numeric, address, CIDR, MAC or port-range literal is refused before compilation. One exception: a port name from the IANA table shipped with the release (`http`, `https`, `domain`, `postgresql`, …) is rewritten to its number without lookup, and the preview shows the rewritten expression. No arbitrary BPF programs, tcpdump arguments or save-file paths. A `proto[offset:size]` access that ends within the fixed header of its protocol (`ether` 14, `ip` 20, `ip6` 40, `tcp` 20, `udp` 8, `icmp`/`icmp6` 8 bytes) needs ordinary capture permission. An access beyond that header tests payload bytes, so the plan records `rawBytePredicate` and needs the same approval as raw packets ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)).

A saved policy follows membership changes of its authorized peer query without new approval; changing the filter, profile or peer query is a new plan.

### SC-NET-001

Given a user filter includes `or host 203.0.113.9`, when combined with a database-only peer selection, then it cannot admit an unauthorized peer. Invalid or unsupported expressions and empty peer sets do not fall back to broad capture.

### SC-NET-007

Given filters `host db.payments.svc`, `tcp port https`, `tcp[13] & 2 != 0` and `tcp[40:4] = 0x47455420`, when previewed, then the first is refused with its term and remedy without reaching libpcap, and the second is shown rewritten to `tcp port 443`; no name is resolved. The third compiles under ordinary permission. The fourth compiles into a plan that needs approval. A different program yields a different execution digest.

## REQ-NET-002 — Kubernetes peers and continuous updates

Peers are IP/CIDR sets, pod label selectors, and Pod, Deployment, StatefulSet and Service references in the target cluster, authored by name. CIDRs compile on the hub into `(peer expression) and (user filter)` ([ADR-283](../docs/decisions/283-cidr-packet-peers.md)). Kubernetes entries are resolved by the cluster's connector from its shared informers (Pods, EndpointSlices, ReplicaSets, StatefulSets, Services) into (UID, IP) members whose host prefixes join the same program. Deployments resolve through ReplicaSets, StatefulSets through controller UIDs, Services through the union of their EndpointSlices. Cross-cluster Service discovery is not inferred.

Service references select `backends`, `virtualIP` or `both`; the UI defaults to backends and explains why. With socket-level load balancing (measured on Cilium kube-proxy replacement, docs/research/cni-qualification-cilium.md) the Pod interface carries backend addresses only, so `virtualIP` observes nothing there; an unavailable VIP profile is refused rather than claimed. Terminating and not-ready endpoints are included unless `readyOnly` is set. ExternalName and selectorless Services need an administrator-approved external endpoint profile.

`resolution: frozen` pins the members resolved at arming; a deleted or readdressed member is removed with a new program generation and a recorded gap, and a new occupant of an old address is never admitted. `follow` also admits new members of the same peer query; a peer recreated under the same name stays the same peer. Each informer change yields a new generation pushed to the node collector; there is no resolution polling. A generation is bounded only by the 4,096-instruction program limit; one that does not compile fails closed for the affected members and is recorded as a gap. During a watch break the last program stays active and provenance records a membership-unknown gap; after the relist a fresh generation is compiled. A quiet watch is healthy; bookmarks are not a freshness clock.

The collector switches generations on already attached hooks without restarting them or discarding their rings, and records each generation's activation interval per hook. Attach delays on new pods, event loss and packet loss remain recorded gaps. IP reuse and NAT make peer identity best-effort; Service VIP, backend IP and observed tuple are separate fields.

### SC-NET-002

Given a Service backend rollout and an unrelated IP reuse while a capture is armed, when membership changes, then existing hooks continue with generation-tagged output and preserved rings. Attach gaps and update lag are recorded, reused foreign IPs are excluded, and watch loss never broadens capture. Backend matching is not reported as proof that a particular VIP was used.

## REQ-NET-003 — Bounded segmented rings and snapshots

The simple preset uses a 30-second, 16 MiB per-target ring with four segments. The collector's memory limit bounds every in-memory budget on a node together:

```text
aggregate ring bytes <= collector memory limit
                        - HTTP reassembly budgets
                        - frozen snapshot bytes
                        - process overhead
```

The chart's default collector memory request yields 256 MiB of aggregate ring per node. [Actions](actions.md) use the same formula. Rings are in memory and hold only the retained representation: sanitized headers, structured HTTP headers or authorized raw packets.

The ring is `maxBytes`, `segments` and `maxAge`. `maxBytes` bounds cost; each segment holds `maxBytes ÷ segments`, including framing and encryption overhead; one segment is always writable. `maxAge` has no built-in maximum and administrators may set a ceiling. Eviction of a segment drops 1/`segments` of history; an oversized record is dropped and counted as loss. `before` cannot exceed `maxAge`, and achieved history is reported, never inferred from the requested time.

A save copies at most one ring's worth of segments plus its `after` stream, bounded by the action's output limit and charged against the node's frozen budget in the formula above; there is no separate per-action frozen size. snapshot frequency is bounded by the [workload rate limit](capacity.md#req-cap-001--workload-wide-storm-control). Under pressure a new snapshot is coalesced or refused before memory is allocated; an accepted snapshot is never corrupted. A stalled upload never grows memory or takes another workload's storage ([capacity](capacity.md)).

### SC-NET-003

Given a 16 MiB four-segment ring, rapid triggers and a stalled uploader, when segments rotate and snapshots pin old segments, then all live, frozen and node limits hold and suppression is reported. History gets shorter under traffic; the configured 30 seconds is not reported as observed coverage.

## REQ-NET-004 — Network headers, HTTP headers and raw packets

| Profile | Retained evidence | Limits and authority |
| --- | --- | --- |
| `networkHeaders` | Sanitized L2/L3/L4 headers and original wire lengths; no payload | Default. The gadget captures at most 134 bytes per frame (Ethernet + largest IPv4 + largest TCP header); the collector cuts each frame at the end of its transport header and keeps only Ethernet II with unfragmented IPv4 or extension-free IPv6 carrying TCP, UDP, ICMP or ICMPv6 ([ADR-248](../docs/decisions/248-manual-packet-capture.md)); publication rechecks every packet against the same rule |
| `httpHeaders` | Plain HTTP/1 request/response metadata and approved header fields; no packets or bodies | Sensitive acquisition; bounded parser and reviewed projection |
| `rawPackets` | PCAPNG packet prefixes with original/captured lengths | Payload approval; `snaplen` 1–65,535 (the IP total-length maximum), optionally one cap per transport; a cap bounds bytes, it does not redact |

HTTP uses bounded TCP reassembly and handles split headers, retransmission, out-of-order delivery, chunked/fixed bodies, pipelining and connection reuse. Bodies and unapproved headers are discarded before the ring; they may pass through the parser, which is why acquisition is sensitive. Classification failure never falls back to emitting bodies. Ambiguous, gapped or oversized streams produce partial/unsupported counters; trailers are discarded; upgraded/CONNECT tunnels stop parsing. A user filter that omits part of a TCP stream makes reassembly incomplete; the preview warns and provenance records the gap.

Parser bounds: `maxHeaderBytes` 32 KiB per header block (common server limits, e.g. nginx `large_client_header_buffers` 4 × 8 KiB); per-flow reassembly 2 × `maxHeaderBytes`; `maxReassemblyBytes` 16 MiB per target, part of the collector memory formula. Flow capacity is their quotient (256 flows at the defaults). A flow ends on FIN/RST or source end; when every slot is held, a new SYN evicts the least recently seen flow (conntrack-style LRU) and counts its partial record. An ongoing HTTP source captures prefixes of 65,535 bytes, the largest GRO/TSO aggregate a Pod-side hook sees, so aggregated traffic leaves no reassembly gaps.

A reviewed `projectionRef` pins allowed fields, header allowlist/redactions and analyzer digest. The initial `http-response-headers/v1` keeps method, status, Content-Type and Content-Length, and never URL, query string, Host, Authorization, Proxy-Authorization, Cookie or Set-Cookie. Unexpected values are dropped. Broader projections need administrator review. Saved windows of an ongoing source record their seen/filtered frame counts and mark the state of flows still open at the cut as unknown.

HTTP/2 needs a separately qualified frame/HPACK pack; HTTP/3 and HTTPS plaintext are unsupported. TLS metadata remains visible with network headers. Never fetch keys, intercept TLS, inject code or decrypt traffic.

### SC-NET-004

Given a header spans several packets and a body shares its last packet, when httpHeaders capture runs, then complete allowed header fields can be emitted while unique body and credential markers never enter retained evidence. Gaps, malformed framing, HTTP/2 or TLS produce visible incomplete/unsupported outcomes without raw fallback or unbounded buffers.

## REQ-NET-005 — Provenance, MCP and qualification

Each network artifact's encrypted manifest records profile/projection and engine/compiler digests, link/hook/CNI profile, target identity, filter digest, every peer generation overlapping the window with its activation interval, requested/achieved time range, wire/captured counts, loss and suppression reasons, ring/frozen/parser ceilings and actual truncation.

EXP-02/03 qualify filter compilation, peer updates, CNI/dual-stack/NAT/hostNetwork/loopback behavior, rings under stalls and HTTP secrecy/resource bounds before a capability is advertised. Unsupported environments return specific unavailable results.

Saved packet artifacts are read in the [regional reader](evidence.md#req-evd-005--analysis-isolation-and-output-classes):

- `get_extract(view=pcapSummary)` ([ADR-303](../docs/decisions/303-saved-packet-summary.md)) returns fixed directional numeric endpoint/protocol groups over the whole authenticated PCAPNG, in cursor pages under [REQ-MCP-002](mcp.md#req-mcp-002--bounded-result-contract). It is computed once per artifact version. A raw original uses the `approved-raw-pcap-summary/v1` definition ([ADR-304](../docs/decisions/304-transient-raw-packet-summary.md)) under ordinary read rights and also reports `unclassified_packets` (records without usable complete headers); this grants no raw query or download. `drops` is nullable and never claims measured network loss.
- `get_extract(view=httpHeaders)` returns the approved HTTP projection with provenance and gaps; it has no body or header-selection option.
- `query_artifact(operation=packets)` ([ADR-305](../docs/decisions/305-bounded-saved-packet-queries.md), authorization under [REQ-MCP-003](mcp.md#req-mcp-003--typed-raw-operations)) applies a filter under the acquisition rules of REQ-NET-001, compiled by the same hub compiler and run by the same evaluator, plus typed time bounds and a TCP flag mask/value. Fields come from a closed catalog (times, lengths, network/transport fields and, from a raw original, a bounded captured-frame prefix as hex). Bytes a saved frame does not contain stay unavailable; nothing is padded or inferred. A raw original needs raw authority even for header-only fields; a metadata original needs ordinary rights. Scanning streams in saved order with constant memory until the page fills or the operation deadline ends it, and returns a cursor, so a recording of any admitted size can be scanned. A page authenticates every frame it reads; a frame that fails authentication releases no page.

The UI names the profiles “Network headers”, “HTTP headers” and “Raw packets”, shows unsupported target capabilities early and lets maintainers pick peers by workload or Service. Saved packets download as native PCAPNG for Wireshark and HTTP projections as structured data ([REQ-DLD-001](artifact-downloads.md)).

### SC-NET-005

Given an HTTP-header artifact is shared with an external agent, when it queries the approved projection, then only authorized fields and coverage gaps are returned; pagination cannot reach raw packets, unapproved headers or another case.

Given an authorized reader inspects a saved raw packet recording, when the fixed summary runs, then only authenticated input contributes, truncated prefixes count as unclassified records and a unique payload marker appears only through separately authorized raw inspection.

## REQ-NET-006 — Pod scope, zero-history captures and watch health

Capture the pod network namespace once, including sidecar and loopback traffic; there is no container-level filter or permission. A hostNetwork pod needs a qualified pod-attribution mechanism; there is no host-wide fallback. Pod-loopback observation is qualified separately from veth traffic; an unavailable hook is reported before capture, never hidden behind a claim of complete pod traffic. Packet-record counts are not necessarily unique datagrams.

`before: 0s` captures the next interval with no claim of history; `after: 0s` freezes an already armed ring. At least one is positive. A positive `before` with no armed recorder reports achieved history zero.

### SC-NET-006

Given a pod with a sidecar and quiet Service membership, when a 30-second capture with before: 0s runs, then pod traffic is captured once, no historical coverage is invented, and absent change events cause no API requests or membership refreshes. An unqualified hostNetwork target is rejected without capturing neighbors.

## Lifecycle and live views

`packetCapture` defaults to ongoing ([action lifecycles](action-lifecycle.md)): a policy arms the recorder, and each admitted trigger saves a bounded before/after window while it continues. Triggers never restart the recorder, reset its ring or extend a post-window; peer changes are new generations. An onTrigger variant resolves `before` to 0s; a manual capture records forward for its `duration` (REQ-LIF-005) and never borrows a policy's ring.

[Live watch](live-watch.md) shows packet metadata and approved HTTP headers of an existing source. Live display filters narrow emitted fields only; they never change acquisition filters, peers, parser or rings. No raw bytes or bodies are shown live; save first and use a raw query.

[Guidance](guidance.md) proposes filters, profiles and ring sizes; it never widens a running filter or enables a sensor.
