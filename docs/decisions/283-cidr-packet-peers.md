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
