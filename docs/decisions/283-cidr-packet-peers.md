# ADR-283 — CIDR packet peers in the hub filter (S-04 increment 9, PR 1)

Date: 2026-11-02. Status: accepted (agent decision); first slice of increment 9.
Requirements: REQ-NET-001 (effective selector, SC-NET-001), REQ-NET-002
(peer queries, frozen/follow), REQ-NET-005 (authored filter digest and
resolved peer provenance), ADR-243 (hub filter compilation), ADR-248 (node
runs the frozen program), S-04 plan increment 9 and S5.

## Context

The packet recorder accepted only the whole-pod peer default (one frozen
entry `0.0.0.0/0`, `::/0`, protocol `any`); every narrower peer query was
refused so that nothing captured more than was reviewed. The hub already
compiles one pcap-filter expression per packet action with the pinned
libpcap and the node runs exactly that classic BPF program. A CIDR peer set
is a fixed address predicate, so it can be expressed in the same program
without any new node mechanism.

## Decision

1. A peers query whose entries are all `cidrs` entries is accepted, with
   protocol `any`, `tcp`, `udp` or `icmp` and up to 32 ports (no ports with
   `icmp`). Each value is parsed with `netip.ParsePrefix` (a bare address is
   its host prefix), masked and rendered canonically; zones, names and
   duplicates after masking are refused at the entry path. Overlapping
   prefixes are kept: they are ORed and harmless. An empty entry list is
   refused (it matches no traffic and never means all traffic).
2. The hub renders `(net A or net B ...)`, then `and tcp|udp|(icmp or icmp6)`
   and `and (port p1 or ...)`, prefixes and ports sorted. With an authored
   filter the compiled expression is `(<peers>) and (<filter>)`. The authored
   filter is screened alone first and its parentheses and brackets must
   balance, so a term such as `or host 203.0.113.9` stays one operand of the
   intersection and cannot widen the peer scope (SC-NET-001). The combined
   expression passes the existing screening and compilation bounds (4,096
   bytes, 256 tokens, 256 instructions); a size refusal names fewer or
   broader prefixes as the remedy.
3. `frozen` and `follow` resolve identically for CIDRs: a prefix has no
   membership to follow. `maxEndpoints` and `maxStaleness` are validated but
   bound only Kubernetes resolution; the number of prefixes is bounded by the
   schema (16 entries × 128) and the filter bounds above.
4. Provenance: the recipe keeps the authored filter and authored peers; the
   compiled-filter record carries the combined expression and program digest
   plus an omitempty `peers` object with the canonical prefixes, protocol,
   ports, `peerSetDigest` (SHA-256 of their canonical JSON, independent of
   authored order) and `authoredFilterDigest`. The action summary's `Filter`
   is the compiled expression and `PeerPrefixes` its prefix count, shown in
   the preview and in approval reviews. Whole-pod plans add no field, so their
   scopes and digests are unchanged.
5. Acceptance replays the frozen compilation keyed by the combined
   expression, so the context plan, `RecordingFor` and `RecorderContextFor`
   reproduce the reviewed program without a compiler. Policy recorders share
   the same expansion and accept CIDR peers identically: the source runs the
   same frozen program.
6. A CIDR peer set narrows payload-reading profiles like a filter does:
   `rawPackets` and `httpHeaders` need either a filter or CIDR peers so the
   finite observation binding pins a compiled program.
7. `packetPeers` is a modeled edit for cidrs-only values. The runtime
   `preview_capture` subset accepts it with cidrs entries only, so MCP and
   console callers get a schema refusal for Kubernetes entries; this raises
   the preview_capture descriptor test budget from 32 to 36 KiB (input plus
   authored provenance; the hard per-descriptor bound remains the 60 KiB
   tools/list page). Kubernetes entries reaching the compiler through a
   catalog profile definition or a policy composition are refused with the
   remedy "Kubernetes peer selection follows in a later release; use cidrs".

Next: Kubernetes peers with `frozen` resolution, resolved by the cluster
connector with one consistent paged LIST per second (S5) into immutable
generations verified against their original freshness bound; churn in the
selected membership stops the capture rather than switching programs. `follow`
for Kubernetes peers stays deferred until open item 7 measures the LIST load;
until then it is refused with the same remedy.

## Complexity gate

1. Benefit: peer narrowing is a specified first-release capability and
   reduces retained addresses and node work. 2. No accepted risk reopened.
   3. Typical: selecting a database or external range. 4. Precedent: tcpdump
   `net` primitives; kube-proxy-style address sets. 5. No new privilege,
   credential or network access; the hub compiler and node evaluator are
   reused. 6. No new failure or fallback state: a refusal is the only
   outcome besides compilation. 7. No configuration. 8. Depends only on the
   pinned libpcap already used. 9. Cost: one compilation per preview, at most
   256 instructions per frame as before. 10. Older plans are unchanged;
   removing the feature restores the refusal. 11. A smaller fix (asking users
   to write `net` terms in the filter) cannot enforce SC-NET-001's
   non-widening intersection or record the peer set.

## PR 2 — Kubernetes peers resolved at preview (plan only)

Date: 2026-11-02. Status: accepted (agent decision).

1. Entries: `podSelector` (namespace plus 1–16 exact labels) and
   `resourceRef` (Pod, Deployment, StatefulSet, Service; a Service also takes
   `serviceMode` and `readyOnly`) are modeled in the typed `packetPeers` edit
   and in the `preview_capture` runtime subset (descriptor still within the
   36 KiB budget). The wire form lists cidrs entries first, then Kubernetes
   entries, each in authored order.
2. Namespace confinement: every Kubernetes entry must name the target's own
   namespace (the caller's eligibility covers exactly that namespace; no
   administrator peer scope exists yet). Other namespaces are refused at the
   entry's `namespace` path with the remedy to use cidrs.
3. Resolution runs in the target's region over a new pre-work query
   `resolve-packet-peers`, after current eligibility on the target. The
   connector reads only the target namespace: GETs of the named
   Deployment/StatefulSet/Service/Pod and of the ReplicaSets owning listed
   Pods (at most 16), paged consistent Pod LISTs by label selector (256 per
   page, 1,024 Pods per resolution) and paged EndpointSlice LISTs of one
   Service (64 slices). It answers only sorted unique (kind, UID, IP)
   members, at most `min(maxEndpoints, 256)`; the frame bound (32 KiB) and the
   compiled filter bounds admit no more. Closed failures cross the exchange
   as `peer-limit`, `peer-unsupported` and `peer-missing`.
4. Pure resolver (`targets.ResolvePeers`): podSelector by label subset;
   Deployment through ReplicaSets it controls; StatefulSet through its
   controller UID; Service backends are endpoints of controller-managed
   EndpointSlices owned by that Service UID whose targetRef is a listed Pod
   matching the Service selector and whose address is that Pod's IP of the
   slice family (forged or foreign slices contribute nothing); `readyOnly`
   drops endpoints whose ready condition is false (unknown counts as ready,
   as the API documents); `virtualIP` adds the cluster IPs; `both` is the
   union. Pods in phase Succeeded/Failed contribute nothing (their IPs may be
   reused). ExternalName and selectorless Services, virtual IPs of headless
   Services and hostNetwork Pods are refused (no qualified address identity).
   Exceeding the limit refuses; it never truncates.
5. Planning: the hub records its receipt time as the generation time.
   Resolved addresses become host prefixes (/32, /128) in the same
   `(net …)` expression as CIDR entries (exact duplicates merged). An empty
   resolution is refused. Only `frozen` is accepted for Kubernetes entries.
   The compiled-filter record gains `peers.kubernetes` (cluster, namespace
   and UID, endpoint count, members digest = SHA-256 of the canonical sorted
   member JSON, resolvedAt); `peerSetDigest` stays the digest of the
   compiled prefix set. The resolutions are part of the plan input, so
   `VerifyRecorderPlan` reproduces the plan; a supplied resolution that the
   plan does not use, or one from the future, is refused.
6. Gate: `AcceptableRecorder` refuses any plan with Kubernetes peer
   endpoints with RecorderUnavailable, "Kubernetes peer capture needs the
   membership verifier of the next release". The node-recorder preview path
   returns not-acceptable before asking the region, the plan-only preview
   resolves once, shows the endpoint count and members digest, and its
   RecorderUnavailable blocker carries that reason. `RecordingFor`, context
   compilation and policy recorders have no resolution and fail closed;
   composition groups, policies and catalog validation refuse Kubernetes
   entries with the remedy.
7. RBAC: the connector executor ClusterRole adds `get services` and
   `list endpointslices.discovery.k8s.io`; the chart's cluster installer
   holds `get services` unconditionally (it already held the EndpointSlice
   list). Pods, workloads and ReplicaSets use the existing target-resolution
   reads. A region installed before this change lacks the reads and answers
   unavailable, which refuses the peers.

Complexity gate (PR 2): 1. Benefit: the specified workload/Service peer
picker; no recording is enabled. 2. No accepted risk reopened. 3. Typical
(select a database Service). 4. Precedent: kube-proxy and NetworkPolicy
peer resolution over EndpointSlices/selectors. 5. Two read-only verbs on
the connector; nothing leaves the region but members. 6. No new degraded
state: refusals only. 7. No configuration. 8. Kubernetes API semantics only.
9. One query per preview with Kubernetes peers, bounded LISTs of one
namespace. 10. Older plans unchanged; removing the query restores the
refusal. 11. Documenting only would leave REQ-NET-002 unimplemented.

Open for PR 3: the connector membership verifier at arming (re-resolve and
compare the members digest within `maxStaleness`, stop on churn), lifting
the gate; then `follow` once open item 7 measures LIST load; administrator
peer scopes for other namespaces; Service port mapping; per-network-profile
IP identity qualification.
