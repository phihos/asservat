# Guided evidence selection

Asservat helps maintainers and agents decide **what to capture for a diagnostic goal** and turns the answer into an editable plan. Guidance only recommends: every acquisition still goes through the ordinary preview, approval and capture flow. It builds on [actions](actions.md), [packet capture](packets.md), [execution](execution.md) and [ergonomics](ergonomics.md); the [research](../docs/research/guided-diagnostics.md) separates upstream capabilities from Asservat work. Examples and defaults here are design proposals, not measurements.

## REQ-GDE-001 — Start with the question

The browser journey is workload → goal → ranked suggestions → preview → collect or create a policy; direct selection stays available. No knowledge of debugger commands, PIDs, BPF, snaplen, profile formats or ring arithmetic is needed. Goals: `unknown`, `crash`, `memoryGrowth`, `highCPU`, `latency`, `hang`, `network`, `dns`, `probeFailure`. A goal is not a diagnosis.

A local, deterministic, versioned rule catalog over current capabilities, authorized observations and preferences produces the suggestions; no LLM, external model call or evidence upload. Each suggestion states its reason and supporting observations, what it can and cannot answer, prerequisite gaps, impact, maximum bytes/process starts, retention and approval. The order follows goal relevance and the [capture assessment](capture-assessment.md), preferring a less disruptive useful option and stating what it gives up; the rank is an order, not a score. An unavailable suggestion is never silently replaced by a more intrusive one. Guidance never runs a profiler, forces GC, stops a process, probes a port, reads files, generates traffic or runs a trial capture to decide what to show.

| Goal | Start with | Escalation when useful | Explain the limit |
| --- | --- | --- | --- |
| Unknown failure / failed probes | Events, recent logs, restart/probe timeline, resource and process/socket context | Runtime stacks, short profile or narrowly scoped traffic | Discovery cannot recover events that were never recorded |
| Crash or repeated restart | Existing core, previous logs, termination reason, build/symbol availability | Arm next-crash collection; live dump of a surviving matching process | SIGKILL/OOM may leave no core; a replacement process cannot reconstruct the dead one |
| Memory growth / OOM | cgroup limit/pressure, RSS and mappings; runtime heap summaries | Heap/allocs profiles with baselines; core for native state | RSS is neither a leak diagnosis nor a bound on core size; no forced GC by default |
| High CPU | cgroup throttling, resource timeline, process identity; short CPU profile | Runtime/thread stacks or native sampling | A core is not a CPU measurement |
| Latency / hang / deadlock | Probe timeline, process/thread state, socket counters; runtime stacks | CPU/block/mutex profiles if prerequisites hold; sequential process dumps | Sequential dumps are not a simultaneous snapshot; disabled sampling is not zero contention |
| Network / DNS | Endpoint readiness, routes/socket/counter context and L3/L4 sample | Protocol reconnaissance; DNS/HTTP projection or raw prefixes | Ports and Service declarations only suggest protocols; TLS and partial traffic limit inference |

### SC-GDE-001

Given a Go workload with a qualified CPU endpoint and high CPU, when a maintainer chooses that goal, then the first plan explains throttling context and a short CPU profile, including its approval needs. A JVM workload without a qualified pack receives a capability-specific alternative, not a fabricated pprof URL or command.

## REQ-GDE-002 — Discover processes and propose durable selectors

**Inspect processes** is an ordinary bounded capture. Existing authorized discovery evidence is reused with its age and coverage shown; a new inspection is never started silently. It covers the selected pods (default one) with cursor pagination; unreadable parts are reported as incomplete. One pod says nothing conclusive about every replica.

The `processSnapshot` projection gives a process reference, display PID in its namespace, executable path/name, start identity, parent, runtime/build identity and memory counters. `process_ref` pins the full internal identity. No argv, environment, file contents or memory. Paths and names are sensitive evidence and are escaped on display.

Suggested `matchedProcesses` selectors use exact executable/runtime/build fields. Explain that a build ID changes on upgrade and that `python`, `node` or `java` may match unrelated workers; when no safe distinction exists, show the ambiguity and offer an exact current process or an explicit broader batch. A selector preview shows matching and excluded processes, descendants, current count and the worst permitted batch; a match count is claimed complete only for a complete inventory. Logical selectors resolve again at dispatch ([dump rules](actions.md)); stale exact references fail. Nothing is dumped, attached or stopped during discovery or preview.

### SC-GDE-002

Given two `/app/worker` processes and a reloader, when inspection suggests an exact executable selector with descendants, then the user sees the matching set and bounded batch. Reloading before dispatch selects the new matching identities; reuse of an old exact PID cannot target a different process. Two indistinguishable interpreter applications remain ambiguous rather than receiving a guessed selector.

## REQ-GDE-003 — Short reconnaissance is an ordinary bounded capture

Three immutable discovery diagnostics ship in the existing catalog, with no new CRD, permission API or execution service:

| Diagnostic | Acquisition | Defaults per selected pod |
| --- | --- | --- |
| `inspect-processes/v1` | Process snapshot and socket-owner metadata | Bounded by `pids.max` × row size |
| `inspect-network/v1` | Network/process context and a network-header sample | 10 s (`duration`); no application bytes |
| `inspect-protocols/v1` | Same context plus raw packet prefixes, reduced to a fixed protocol projection | 10 s; 2,048-byte snaplen |

Surveys are manual captures: `duration` is the manual recording duration (REQ-LIF-005), each read has the 5 s I/O timeout ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D5), and they share the ordinary rate, concurrency, storage and retention limits ([ADR-335](../docs/decisions/335-usable-by-default.md) D7/D8). Packet surveys use `before: 0s` and stream forward, so no survey ring is sized, and never claim history. The 2,048-byte snaplen covers what the classifiers need (a TLS ClientHello with ML-KEM key shares, an HTTP/1 request line with ordinary headers, DNS messages); it is editable up to 65,535.

Process and header surveys need ordinary collection rights. The protocol survey reads raw prefixes, which can contain credentials and user data, so it needs the one individual approval; its observation rate defaults to 8 MiB/s (collector CPU request ÷ measured classifier cost per byte), counted on all bytes entering the classifier. Widening scope or snaplen is a new plan. A survey stops at its first limit, reports why, and is never retried or repeated automatically. Survey evidence keeps the ordinary audience and retention, so a user can return to it without sampling again. Saving a policy stores configuration, never the sampled processes or traffic.

### SC-GDE-003

Given a maintainer who may collect context but has no sensitive grant, when they inspect processes or choose the header survey, then no approval is required. Choosing protocol reconnaissance creates a single approval request. A rapid repeated click or another agent cannot start a second sensor; waiting for approval starts no raw sampler.

## REQ-GDE-004 — Show observed traffic, qualified attribution and uncertainty

The discovery report shows interval, covered pods, observed versus retained bytes, drops, truncation, stop reason, classifier version and coverage. Flows show transport, peer address/port, direction, Kubernetes peer candidates, protocol and process association, each with its own basis: `observed`, `inferred`, `ambiguous` or `unknown`.

- L3/L4 headers establish transport and addresses only; ports and `appProtocol` are hints. Qualified decoders may confirm DNS, plain HTTP/1, an HTTP/2 cleartext preface or a TLS handshake from approved raw input; other protocols stay unknown. Names, URLs, header values, TLS names and payload are not kept in the planning projection.
- TLS hides application data; offered ALPN does not prove the negotiated protocol. No decryption, key acquisition or socket uprobes.
- Packets carry no PID. Process association combines socket-owner snapshots, socket identity and process start identity; shared sockets, proxies, UDP and exited processes yield several candidates or unknown.
- Service and workload candidates come from current authorized Kubernetes metadata. One backend can belong to several Services; DNS is not Service identity and no external DNS queries are made. Hidden peers stay hidden.

Recommended observation points are limited to qualified pod-attributed hooks, with what each covers; a missing hook is a capability gap.

### SC-GDE-004

Given TLS on port 8080 to a backend selected by two Services and a socket shared by two workers, when a survey completes, then the report distinguishes TLS observation, application-protocol hints, both permitted Service candidates and ambiguous process attribution. An empty sample reports no traffic in that interval, not that the workload has no dependency.

## REQ-GDE-005 — Generate useful filters, capture modes and sizes

Recommendations produce an editable diagnostic handle for the ordinary preview. Prefer a UID-resolved Service/Deployment/StatefulSet peer with `resolution: follow` when the evidence supports it, explain backend versus VIP coverage, and keep several choices visible when Service identity is ambiguous. Generated pcap expressions are built from a bounded AST, never by concatenating untrusted names, and are intersected with pod and peer scope. A zero-match sample does not prove a filter useless.

Suggest `networkHeaders` for transport failures, `httpHeaders` for plain HTTP/1 context and `rawPackets` only when the goal needs payload prefixes. TLS/HTTP2 limits come with alternatives such as logs and profiles. Snaplen is never raised automatically.

Ring controls are **desired history** and **ring storage limit**; segment count stays editable. With retained bytes/s `r`, history `H`, burst factor `f` (default 2) and segment size `S`, recommend `N = max(2, ceil(r·H·f/S) + 1)` segments and `M = N·S` bytes; the extra segment is eviction slack. The rate is estimated from the retained representation of the proposed filter/profile, preferably by replaying an approved sample through the projection, otherwise labeled estimated or unknown. For example, 512 KiB/s, 30 s, factor 2 and 4 MiB segments give nine segments / 36 MiB per pod; at a 16 MiB ceiling four segments hold about 12 s. When `M` does not fit, offer less history, narrower peers or a smaller representation; never clamp silently while claiming the original history. Zero traffic yields an unknown estimate and the packaged default. A new ring starts empty and the preview shows its warm-up. A recommendation reserves nothing and never resizes a running capture.

### SC-GDE-005

Given the 512 KiB/s sample and a 16 MiB ceiling, when the user requests 30 s history, then the UI and MCP explain the 36 MiB estimate and offer an explicit 12 s alternative or narrower filter. A payload-bearing HTTP packet is never advertised as headers-only because snaplen is small. A burst after the survey yields a visible history gap without budget escalation.

## REQ-GDE-006 — Equal assistance for people and agents

Browser and MCP use the same catalog, projections and plan compiler, inside the existing capture workflow:

1. `list_targets` / `list_diagnostics` find scope and diagnostics, including the three inspections. `list_diagnostics(target_handle, goal, discovery_capture_ids?, preferences?, focus?)` recommends; it is passive and states missing observations.
2. A discovery runs via `preview_capture` → `request_capture` → `get_capture`; the UI offers **Inspect processes** and **Sample traffic** buttons that compose this sequence and show pods, limits, privacy and approval before acquisition.
3. `get_extract(view=discovery, capture_id, section, cursor?, limit?)` returns the approved process/flow/summary projections, never raw bytes, as pending work under [REQ-MCP-002](mcp.md#req-mcp-002--bounded-result-contract) when not yet computed.
4. `list_diagnostics` with a `goal` reads any number of authorized discovery captures and returns all applicable choices in order, paginated. Each carries a `diagnostic_handle`, rationale, gaps, cost/impact/privacy and the proposed selector/packet/ring settings. `focus` may name process or flow references from the supplied discoveries; if a durable selector also matches others, the expanded set is shown, never silently dropped. `preferences.max_bytes` and `max_ring_bytes` cap proposed output and ring; an impossible combination yields blocked choices with alternatives, never a relaxed preference.
5. Handles are stateless authenticated references to principal/client, target, catalog version and inputs; preview and submission re-check current UIDs, policy, permissions and capabilities.

Discovery planning needs artifact read rights and current collection eligibility on the target; shared-evidence recipients use the case tools and gain no inventory. Process/flow projections are evidence extracts. Untrusted names, labels and packets never become instructions, links, plugins or code. Rank is not authorization, diagnosis certainty or approval.

### SC-GDE-006

Given a browser user and an authorized agent with identical target, preferences and observations, when each asks for latency guidance, then both receive equivalent ranked plans and limits. An expired survey, hidden peer, revoked source permission, foreign handle or malicious process name cannot leak data or cause acquisition. Two retries of the same discovery capture return the original operation. Saving a future policy shows its target, trigger, approval and retained configuration before submission.

## Recommendations from capture profiles and lifecycles

Recommendations prefer [capture-profile](capture-profiles.md) components; a handle can bind the same typed composition, and preview shows its versions, edits and cost. Syscall suggestions start with metadata and explain that names and results reveal no paths or bodies; arguments are a separately approved change. Recommendations distinguish evidence collectable after a symptom from evidence that must already be recording ([lifecycle preview](action-lifecycle.md)): packet/syscall history needs an ongoing recorder, and a profile started after a failure is not history. When history is missing, suggest enabling an ongoing recorder for the next recurrence, with its cost and approval.
