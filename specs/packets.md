# Packet selection, rings and protocol evidence

These requirements extend the Inspektor Gadget integration. They are planned capabilities with explicit qualification gates, not claims that an unmodified Gadget currently supplies all of them. See [source research](../docs/research/packet-capture-flexibility.md) and the [portable parameters contract](contracts/packet-capture.schema.json).

## REQ-NET-001 — Composable bounded filters

The accepted action fixes the authorized observation target, capture profile, peer query and optional `filter` using tcpdump/pcap-filter syntax. The effective selector is **authorized target AND resolved peers AND user filter AND administrator ceilings**. Peer entries are ORed within the peer query; optional transport/port constraints intersect that union. Empty resolution matches no peers; it never means all traffic. Peer discovery is limited by administrator-approved metadata/peer scopes; the picker lists only visible resources and unavailable hidden references return a generic unavailable result. Permission to observe the authorized target does not require ownership of every network peer, but it never authorizes attaching to that peer. Peer selection grants no right to read peer logs, files or memory or attach collectors to peer pods.

Validate and compile the expression during preview using the exact pinned compiler/link type. The compiler runs on the hub ([ADR-243](../docs/decisions/243-packet-syscall-plans-in-preview.md)): a statically linked libpcap (pinned version) compiles the whitespace-normalized expression on a dead handle with link type `EN10MB` and snapshot length 65,535. The previewed and accepted plan carries the resulting classic BPF program and its digest (SHA-256 over the instructions as little-endian `struct sock_filter`); the node runs that exact program on each captured frame and never compiles an expression ([ADR-248](../docs/decisions/248-manual-packet-capture.md): the published Inspektor Gadget tcpdump gadget delivers the Pod's frames and the collector evaluates the program in user space with `golang.org/x/net/bpf`, `len` against the original wire length; a program that evaluator cannot run exactly is refused at preview). Initial bounds: 4,096 expression bytes, 256 syntax tokens (screened before libpcap; a conservative bound on syntax nodes), 256 compiled instructions, plus the verifier/instruction limits of the qualified engine profile. Reject unsupported syntax with the unsupported construct and remedy; do not silently broaden it. Do not resolve DNS names in filters; offer explicit IPs/CIDRs or Kubernetes refs. Because libpcap would resolve host, network, Ethernet and service names (and `gateway`) while compiling, every term that is not a supported primitive or a numeric, address, CIDR, MAC or port-range literal is refused before compilation. No arbitrary BPF programs, shell tcpdump arguments, save-file paths, or unbounded protocol-offset inspection. A `proto[offset]` or `proto[offset:size]` access (size 1, 2 or 4) is screened like any other term. An access that ends within the fixed header of its protocol (`ether` 14, `ip` 20, `ip6` 40, `tcp` 20, `udp` 8, `icmp`/`icmp6` 8 bytes), such as a TCP flag test, needs only ordinary capture permission. An access beyond that header can test payload bytes even when retained output is sanitized: the plan records reason `rawBytePredicate` with REQ-AUT-006 observation limits in its execution digest, the preview reports `approval_required` with blocker `ApprovalRequired`, and nothing is armed until a current adHocCapture grant covers that exact plan ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)). The recorder runs such a plan only under the grant's observation limits.

Filter preview shows normalized expression, peer count, target interfaces, effective output, privacy class, estimated ring coverage and limits. Filter/profile changes create a new reviewed plan generation. A saved policy can follow changing members of the same authorized peer query without a new approval for each rollout; widening that query cannot reuse the old approval.

### SC-NET-001

Given a user filter includes `or host 203.0.113.9`, when combined with a database-only peer selection, then it cannot admit an unauthorized peer. Invalid or unsupported expressions and empty peer sets do not fall back to broad capture.

### SC-NET-007

Given filters `host db.payments.svc`, `tcp port https`, `tcp[13] & 2 != 0` and `tcp[40:4] = 0x47455420`, when previewed, then the first two are refused with their term and the remedy and neither reaches libpcap; no name is resolved. The third compiles under ordinary permission. The fourth compiles into a plan that needs an approval and is refused with `ApprovalRequired` at submission until a covering grant exists. `ip6 and dst host 2001:db8::2` compiles on the hub, and the previewed plan carries its program digest; a different program yields a different execution digest.

## REQ-NET-002 — Kubernetes peers and continuous updates

Support bounded IP/CIDR sets, pod label selectors, Pod, Deployment, StatefulSet and Service references in the target cluster. CIDR entries are compiled on the hub into the accepted program as `(peer expression) and (user filter)` with a recorded peer-set digest ([ADR-283](../docs/decisions/283-cidr-packet-peers.md)); for CIDRs `frozen` and `follow` are equivalent. Kubernetes entries are resolved by the target region's connector into (UID, IP) members whose host prefixes join the same expression; plans are previewed with their endpoint count and members digest. The connector resolves membership from one shared, label- and namespace-scoped informer set (Pods, EndpointSlices, ReplicaSets, StatefulSets, Services) and evaluates each running recording's peer query on informer events, not on a timer. Resolve resource names to UIDs at acceptance; deletion/recreation under the same name requires a new plan. Deployment ownership resolves through ReplicaSets, StatefulSets through controller UIDs, and Service endpoints through the union of all EndpointSlices with deduplication, address family and port mapping. Cluster/namespace identity is explicit in resolved state. Cross-cluster Service discovery is not inferred.

Service refs explicitly select `backends`, `virtualIP` or `both`. Default UI selection is backends, with a visible explanation. With socket-level load balancing (measured on Cilium kube-proxy replacement, docs/research/cni-qualification-cilium.md) the Pod interface carries backend addresses only, so `virtualIP` observes nothing there. Backend selection can match traffic to those endpoints arriving through a different Service. VIP visibility depends on CNI/NAT and hook position; reject an unavailable VIP profile rather than claim Service attribution. Include terminating/not-ready endpoints by default for diagnosis, record their conditions and bound their membership lifetime; an explicit `readyOnly` choice can narrow them. ExternalName and selectorless Services require an administrator-approved external endpoint profile; never use them for arbitrary DNS/network discovery. Endpoint IP identity and stale/IP-reuse protection must be qualified for each network profile.

`resolution: frozen` pins membership at capture arming. When a member is deleted, changes its address, or its address now belongs to another object, the connector excludes that member with a new program generation and records the gap; the recording continues with the remaining members and never authorizes a new occupant of an old address. `follow` also admits new members of the same authorized peer query: each coalesced informer change yields a bounded new generation (default max 4,096 endpoints, max 16 authored peer entries). Exceeding map capacity fails closed for the affected membership. The informer cache stays valid until the watch reports an error. During a watch break the last compiled program stays active and provenance records a membership-unknown gap; after the relist completes the connector compiles a fresh generation from the relisted state. Record generation activation times and gaps.

Prepare maps and immutable filter generations, then switch the active reference on already attached capture hooks without restarting those hooks or discarding their rings. Retire old maps after in-flight readers drain. Per-hook activation is atomic, not instantaneous across every node; record generation ID/digest and activation interval per hook. No restart-induced gap is allowed for a healthy membership update, but attach delays on new pods, event-stream loss, queue overflow and other packet loss remain measured gaps. Preserve removed peers' already captured evidence under the original authorization and retention rules. This capability needs an Asservat adapter/custom packaged Gadget using the supported engine; lack of an upstream update RPC is not permission to advertise an untested seamless update.

### SC-NET-002

Given a Service backend rollout and an unrelated IP reuse while a capture is armed, when membership changes, then existing hooks continue with generation-tagged output and preserved rings. New target attach gaps and update lag are recorded, reused foreign IPs are excluded, and watch loss never broadens capture. Service backend matching is not reported as proof that a particular VIP was used.

## REQ-NET-003 — Bounded segmented rings and snapshots

The simple preset uses a 30-second, 16 MiB per-target ring, 256 MiB aggregate per node, and a separate bounded capture output limit. Advanced `ring` settings expose `maxAge`, `maxBytes`, `segmentBytes`, `maxSegments` and `medium`. The baseline medium is memory; the optional encrypted-disk ring/spool is a separately qualified administrator storage profile, not a user path or default. The historical ring contains only the selected retained representation: sanitized packets, structured HTTP headers, or explicitly authorized raw packets.

The initial maximum maxAge is one hour; administrators may narrow it. All limits apply simultaneously: allocated segment count × segmentBytes <= maxBytes, actual storage including indexes/encryption/framing overhead <= maxBytes, and oldest record age <= maxAge and retention cutoff. Reserve one writable segment in that count; segment eviction can shorten history, and an oversized record is dropped/counts as loss. Rotation does not restart capture. `before` cannot exceed maxAge; achieved coverage is reported, never inferred from desired time. Presets choose four segments by default; omission of advanced fields resolves them and displays the result.

Frozen snapshots and live rings have separate reservations. Pinning a segment consumes frozen-snapshot capacity; replacement live segments still count toward node totals. Limit concurrent snapshots (default one, hard maximum four) and frozen/unuploaded bytes (default 64 MiB per target, further bounded by node/workload policy). On pressure, coalesce or refuse a new snapshot before allocating memory; do not corrupt a previously accepted snapshot or silently exceed the ring bound. Upload bandwidth, durable bytes/object slots, parser buffers and ring memory are distinct budgets under [capacity](capacity.md). Sustained traffic or stalled S3 must neither grow memory nor steal another workload's protected storage.

### SC-NET-003

Given a 16 MiB four-segment ring, rapid triggers and a stalled uploader, when segments rotate and snapshots pin old segments, then all live/frozen/node limits hold and suppression is reported. History gets shorter under traffic; configured 30 seconds is not falsely reported as observed coverage.

## REQ-NET-004 — Network headers, HTTP headers and raw packets

`profile.kind` has three initial choices:

| Profile | Retained evidence | Limits and authority |
| --- | --- | --- |
| `networkHeaders` | Sanitized L2/L3/L4 packet headers, valid framing and original wire lengths; no application payload | Default; bounded parser drops unknown/unsafe formats, including unsafe fragments/options; network identifiers still may be personal data. ADR-248: the gadget captures at most 134 bytes per frame (Ethernet + largest IPv4 + largest TCP header); the collector cuts each frame at the end of its transport header with gopacket's decoders and keeps only Ethernet II with unfragmented IPv4 or extension-free IPv6 carrying TCP, UDP, ICMP or ICMPv6; the publication verifier rechecks every packet against the same rule |
| `httpHeaders` | Structured, projected plain HTTP/1 request/response metadata and approved header fields; no raw packet archive or bodies | SensitiveRead authority for acquisition, even if output qualifies as extract; bounded stateful parser and immutable reviewed projection |
| `rawPackets` | PCAPNG packet prefixes with original/captured lengths and truncation | Explicit payload approval and raw class; default snaplen plus optional transport-specific caps; a cap is a byte budget, never a payload-redaction guarantee |

For rawPackets, protocolSnaplen has at most one rule per transport (tcp, udp, icmp); that rule overrides the default snaplen, and unlisted/unknown transport uses the default. These are transport size caps, not HTTP-aware confidentiality rules. Both limits are 1–65,535 and may be narrowed by engine capability. Applying per-transport caps needs a qualified Gadget adapter; an upstream fixed snaplen flag alone does not provide it.

HTTP uses bounded TCP reassembly and message framing. It must handle split headers, retransmission, overlap ambiguity, out-of-order delivery, chunked/fixed-length bodies, pipelining and connection reuse. Discard bodies and unapproved headers before ring/persistent retention. They may transiently enter the trusted bounded parser, which is why acquisition is sensitive. Do not emit bodies as fallback when classification fails. Midstream/ambiguous/gapped/oversized streams produce partial/unsupported counters and drop undecodable content. Discard trailers by default; stop parsing upgraded/CONNECT tunnels. Stop processing a flow before state exceeds its budget. No packet-offset or fixed snaplen value safely identifies arbitrary HTTP headers. A user filter that omits part of a TCP stream can make reassembly incomplete; show that warning in preview and record the gap, without widening the requested filter.

A reviewed `projectionRef` pins allowed fields, header allowlist/redactions, request-target handling and analyzer digest. Initial `http-response-headers/v1` permits method, status, Content-Type and Content-Length, omits URL/query strings/Host and credentials, and emits no Authorization, Proxy-Authorization, Cookie or Set-Cookie values. Values still pass deterministic length/type/redaction checks; unexpected values are dropped, not reclassified as harmless. Broader request/header projections need administrator review and user-data retention. Users do not type regex redactors in the capture wizard.

Initial per-target parser defaults/hard maxima: 1,024 flows; 32 KiB header block; 256 KiB reassembly per flow under a shared 16 MiB total reassembly budget; 30-second idle timeout; CPU bounded by the node profile. Preview rejects a parser/ring/node allocation conflict. These maxima are explicit contract bounds requiring measurement; default sampling/overload may reduce flow coverage. A stopped direction keeps its sequence tracking (its bytes are discarded) so its FIN frees the flow slot, and a flow returns its slot once both directions stopped. When every slot is held, a new connection's SYN first closes flows with no captured frame for two seconds (at most the idle timeout) as idle-closed, partial records included; this bounds the coverage loss from connections whose FIN/RST was never captured without raising the flow cap. Transport read depth is selected by the profile to parse complete bounded headers, not a claimed protocol-dependent safe packet prefix.

An ongoing HTTP source must be explicitly authored and covered by its original
reviewed observation grant. It uses the fixed 1,500-byte acquisition prefix and
reserves its approved reassembly budget plus its ring before starting. An
ordinary 134-byte network-header source cannot acquire this capability when a
viewer opens. Source renewals retain the original grant, session end and wire-byte
accounting; saving does not renew or flush the source.

For an ongoing source, the ring contains approved records and bounded,
content-free counter deltas with the original event clock. Save selects these
entries from the original requested window. In `http-response-headers/v1`, the
optional `source_window` member identifies `counter_scope: event-window`, actual
seen/filtered frames and observed wire bytes, history continuity and completed
records clipped because their original request times fall outside the window.
Its `counters.open_at_close_flows` is null and open/pending cutoff state is
explicitly unknown: the independent source was not stopped. A response completed
after the copied cutoff may be absent even if its request was in the window.
Projected pages preserve these gaps. Output-limit drops and retained record
counts are separate from the frame counters. Finite documents omit
`source_window` and retain their existing numeric close gauge and exact encoding.

HTTP/2 requires a separately qualified frame/HPACK state pack; HTTP/3 and encrypted HTTPS plaintext are unsupported in the initial profile. TLS metadata remains possible with network headers. Never fetch keys, intercept TLS, inject code or decrypt traffic implicitly. Separate approved runtime plaintext instrumentation would be a future action with its own privilege/privacy review.

### SC-NET-004

Given a header spans several packets and a body shares its last packet, when httpHeaders capture runs, then complete allowed header fields can be emitted while unique body and credential markers never enter retained evidence. Gaps, malformed framing, HTTP/2 or TLS produce visible incomplete/unsupported outcomes without raw fallback or unbounded buffers.

## REQ-NET-005 — Provenance, MCP and qualification

Each network artifact records profile/projection and engine/compiler digests, link/hook/CNI profile, target identity, authored filter digest, resolved peer generations and activation intervals, requested/achieved time range, wire/captured counts, loss/suppression reasons, ring/frozen/parser ceilings and actual truncation. Generation history is itself bounded (default 1,024 entries per artifact); close a segment/artifact or stop with a visible limit instead of dropping provenance silently. This provenance is part of the encrypted artifact manifest.

`get_pcap_summary` describes sanitized or raw packet metadata; `get_http_headers` returns bounded structured HTTP fields from an approved projection with provenance, cursor/output limits and no body parameter. A raw original remains raw. Its fixed numeric summary may use the transient projection in [ADR-304](../docs/decisions/304-transient-raw-packet-summary.md), with dedicated ordinary aggregate authority and independent output validation. This creates no stored derivative or raw-content permission. `pcap_query` over a raw original or raw fields remains separately granted; metadata-only queries use ordinary current/retained rights. Native/subprocess analysis retains the separate-Job encrypted-scratch boundary. All external-agent disclosures retain existing client policy, audit, share and expiry checks. The UI calls the choices “Network headers”, “HTTP headers” and “Raw packets”, shows unsupported target capabilities early, and lets maintainers choose Kubernetes peers by workload/service rather than typing addresses.

EXP-02/03 must qualify filter compilation, continuous peer updates, CNI/dual-stack/NAT/hostNetwork/loopback behavior, rings under stalls and HTTP secrecy/resource bounds before capability advertisement. Unsupported environments return specific unavailable results; no blanket packet coverage claim.

Saved `get_pcap_summary` ([ADR-303](../docs/decisions/303-saved-packet-summary.md))
runs in the [regional evidence reader](evidence.md#req-evd-005--analysis-isolation-and-output-classes)
over the whole authenticated saved PCAPNG within the reader's source size limit:
fixed directional numeric endpoint/protocol groups, top 100 of at most 16,384
aggregates, no filters, DNS, payload or comments. The summary is computed once per
artifact version and reused. Packet counts
mean records in the saved file rather than unique datagrams. `drops` is nullable;
`drop_reporting` labels finite capture exclusions, snapshot output-limit exclusions
or unavailable statistics. These reported counters never establish measured
network loss. Missing statistics remain unknown and repeated cumulative statistics
are not summed.

Raw originals use the distinct `approved-raw-pcap-summary/v1` definition in
ADR-304. The authenticated source retains its actual raw prefix limits and
class. `packets` counts all saved records; required `unclassified_packets`
reports records without usable complete headers, including zero. Conversations
cover classified records only, with the same deterministic top 100 bound. No
endpoint or protocol is guessed from a missing header. Metadata results omit
this raw-only field. Raw-summary authority grants neither raw queries nor native
download and uses no raw-source share fallback.

### SC-NET-005

Given an HTTP-header artifact is shared with an external agent, when it queries the approved projection, then only authorized bounded fields and coverage gaps are returned. The tool cannot expose raw packets, unapproved headers or records from another peer generation/case through pagination.

Given an authorized reader inspects a saved raw packet recording, when the fixed
summary runs, then only authenticated input contributes to the approved numeric
output, truncated prefixes remain visible as unclassified records and a unique
payload marker appears only in separately authorized raw/native inspection.
The original remains raw; another client, changed source or expired/revoked
authority cannot reuse the summary's query or widen its output.

### Saved packet queries (REQ-NET-005 / REQ-MCP-003)

[ADR-305](../docs/decisions/305-bounded-saved-packet-queries.md) applies one bounded
query to an existing metadata or raw PCAPNG in the
[regional evidence reader](evidence.md#req-evd-005--analysis-isolation-and-output-classes).
The filter uses tcpdump/libpcap syntax, compiled by the pinned hub compiler and run
by the same Go filter VM, with a 512-byte filter cap, the acquisition screening and
instruction bounds, and no name resolution. Bracket/raw-byte predicates are
refused; packet time intervals and TCP flag mask/value use typed selectors. The
finite field catalog covers packet times/lengths, network/transport fields and a
bounded raw captured-frame prefix, with exact names/limits in the canonical
contract. Prefix bytes come from the saved frame; short saved prefixes never yield
invented headers, endpoints, flags or padding.

Any raw original requires a current exact pcap_query grant even when only header
fields are selected. Metadata-only fields from a metadata original need ordinary
rights. Raw fields unavailable from that original are refused. A covering
standalone or same-human/selected-client combined result-access grant is reused
without a second approval; original audience/client/retention checks still apply.
Neither acquisition approval nor the fixed numeric summary supplies packet-query
or download authority.

Logical scan work counts captured frame bytes visited in saved order, including
nonmatches, up to the selected scan bound (API ceiling 1 GiB). A page authenticates
the manifest and every frame it reads; the whole artifact was verified once at
publication. A frame that fails authentication releases no page. One transient
page holds at most 100 rows, 32 fields and 24 KiB. Report work/limit state without
claiming full traffic coverage.

A query creates no capture, derivative or capture-history entry. It carries an
operation ID: a retry with the same ID and selection returns the existing outcome,
a changed selection under the same ID conflicts. Raw disclosure consumes one
operation and the delivered output bytes from the grant's disclosure pool when a
page is delivered; an operation that delivers nothing consumes nothing.
Query-only grant pools need not cover the whole native source; mixed
download/query scopes retain the native full-file coverage requirement and use
one shared pool. SQL, audit rows and logs hold only bounded control selection and
identity, never projected frame bytes or rows.

## REQ-NET-006 — Pod scope, zero-history captures and watch health

Capture the pod network namespace once, including sidecar and loopback traffic; there is no container-level filter or permission. A hostNetwork pod requires a qualified pod-attribution mechanism for the requested traffic; never attach a host-wide fallback. Named endpoint/process attribution is distinct from packet scope. Preview explains shared pod networking and unsupported hooks.

Qualify and report pod-loopback observation independently from veth traffic. A successful explicit host-loopback capture does not establish automatic pod-loopback coverage. Required hooks that are unavailable must produce a visible capability/coverage limitation before capture, never a silent claim of complete pod traffic. Deduplicate multiple observation points only through a qualified method and retain counters/uncertainty; packet-record counts are not necessarily unique network datagrams.

before: 0s supports “capture the next interval” with no claim of pre-trigger history; after: 0s supports an already armed retrospective freeze. At least one is positive. The bounded ring remains the staging/rotation buffer even with zero requested history. A positive before with no armed sensor reports achieved history zero, rather than waiting and relabeling post-request traffic as history. Action timeout must include post-trigger time plus setup/finalization margin; maxFrozenBytes cannot exceed action output reservation.

Peer membership follows standard informer semantics: a quiet watch is healthy and the cached membership stays valid until an event replaces it. Only a watch error or `410 Gone` triggers a relist; bookmarks keep the resourceVersion current and are not a freshness clock. A watch break records a membership-unknown gap as in REQ-NET-002; it does not stop the recording.

### SC-NET-006

Given a pod with a sidecar and quiet Service membership, when a 30-second capture with before: 0s runs, then pod traffic is captured once under its scope, no historical coverage is invented, and absent change events cause no API requests, membership refreshes or ring shutdowns. An unqualified hostNetwork target is rejected without capturing neighbors.

## Assisted packet planning

[Guidance](guidance.md) defines explicit short surveys, per-field confidence for protocol/Service/process attribution, generated capture filters, qualified observation-point explanations and ring sizing from retained data rate. These are ordinary bounded captures and passive recommendations. Neither a preview nor a rate estimate widens a live filter, changes ring capacity, reads TLS secrets or enables a sensor. The proposed classifier scope does not expand the HTTP/1-only `httpHeaders` acquisition profile.

## Recording and save lifecycle

packetCapture defaults to ongoing under [action lifecycles](action-lifecycle.md). Policy arming starts the recorder after observation authority/reservations; triggers freeze bounded before/after windows from that source while it continues. Peer-map updates, source epochs and frozen snapshot identities remain distinct. Suppressed triggers do not start recorders, reset rings or extend an existing post-window. Expiry/stop detaches the source; peer membership changes produce new generations, never a source restart; losing upload capacity refuses/limits snapshots without growing live storage.

An explicitly selected onTrigger variant requires before: 0s and captures only the next bounded interval. The same adapters/ring representation serve that finite action, but no policy source is armed beforehand. A manual request never implicitly borrows another policy's ring or establishes persistent capture. Preview shows source activation and available history separately from per-incident output limits.

## Approved live packet views

[Live-watch projections](live-watch.md) expose qualified packet metadata and approved HTTP headers from an existing source. Live display predicates narrow emitted approved fields and are distinct from pcap acquisition filters or dynamic peer maps; editing one view does not reconfigure hooks, parser mode or rings. Report source filter generations, dropped packets, parser/sampling/subscriber gaps and unknown peer/PID/pairing. Unsupported TLS/plaintext or L7 parsing remains unavailable. Rows reach the browser over the page's Server-Sent Events stream and MCP through a long-poll read. No live raw packet bytes/bodies or arbitrary header selectors; save and use normal raw-query approval for deeper inspection. Live parser/reader CPU and scan/fanout resources must be qualified and reserved without delaying incident snapshots.

Saved sanitized/raw packet artifacts download as their native PCAPNG for Wireshark under [REQ-DLD-001](artifact-downloads.md). Structured HTTP projections download as structured data. Acquisition filters, payload approval, actual truncation and encrypted managed storage are unchanged; a query-only grant does not implicitly authorize a full raw file.
