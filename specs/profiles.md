# Profiles and runtime traces

Profiles are first-class evidence: they can be selected in a recipe, triggered by a policy, kept with a case, shared, compared to a baseline and queried through MCP. A profile records sampled or accumulated behavior; it is not a core, heap dump or log snapshot.

## Capability catalogue

| Runtime/source | Formats | Preparation and limits |
| --- | --- | --- |
| Go pprof | CPU, heap, allocations, goroutines, block, mutex, threadcreate; binary pprof | The application already serves pprof on an approved endpoint. Block/mutex sampling must be enabled by the application. |
| Go execution trace | Native runtime trace | Approved trace endpoint; short duration; more data and overhead |
| Any runtime (eBPF CPU sampler) | CPU stacks for native code, Go, JVM (HotSpot), Python, Node.js (V8), .NET, Ruby, PHP, Perl and BEAM; pprof | The node collector's pinned OpenTelemetry eBPF profiler ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)); kernel 5.10+ (the upstream floor); nothing attached to the target; native frames need symbols |
| JVM | JFR through `jcmd`; async-profiler only as explicit opt-in | Qualified JDK attach permissions; async-profiler loads a native agent and is operator-managed |
| .NET | EventPipe `.nettrace` | Diagnostic socket and matching tooling; not assumed pprof-compatible |
| Python | No agent-free heap profile; py-spy or `tracemalloc` only as opt-in | They attach to or modify the target; CPU comes from the eBPF sampler |
| Node.js | Inspector heap sampling, only as opt-in | No public inspector exposure; CPU comes from the eBPF sampler |

References: [Go pprof HTTP API](https://pkg.go.dev/net/http/pprof), [Go diagnostics](https://go.dev/doc/diagnostics), [async-profiler modes](https://github.com/async-profiler/async-profiler/blob/master/docs/ProfilingModes.md), [.NET trace tool](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-trace), [Node CPU profiling](https://nodejs.org/api/cli.html#--cpu-prof).

## REQ-PRF-001 — Typed profile collection

The `profile` action specifies runtime, profile type, mode (`snapshot`, `cumulative`, `delta` or `interval`), a named source, duration where meaningful and the ordinary byte/deadline limits. Go pprof CPU and heap are in the first production scope; other Go types work when the application prerequisites hold. Other runtime formats are separately qualified packs.

**eBPF sampler.** `runtime: any`, `type: cpu`, source kind `ebpfSampler`: no endpoint, nothing attached to the target, whole-pod scope as for syscall traces. The kernel program samples host-wide while any session runs on the node (the profiler has no cgroup filter); concurrent sessions share it and each receives only its own pod's samples. The collector attributes each sample by verified pod, cgroup, process-start and node-boot identity and drops uncertain samples, counting them as `unattributedSamples`. Other processes' samples are discarded in collector memory before encoding and are never written, logged or counted; the collector suppresses its own core dumps. The artifact records `detectedRuntimes` and native build IDs; missing symbols are reported.

**Endpoints.** Profile endpoints are defined by administrators in Helm values: a fixed port, or a template with an allowed port range and fixed path policy that a maintainer binds in `EvidenceRecipe.spec.endpointBindings` by declared port name or number, so an application already serving pprof needs no rollout. Endpoints resolve to the selected pod's IP or its network-namespace loopback, never the collector's own loopback; there is no DNS, address fallback or host-network endpoint. Clients never supply URLs, redirects, ports, headers or query parameters. Ambiguous port names yield `EndpointAmbiguous`. A declared port is a routing hint, not proof of the serving process. Approval and policy definitions bind the endpoint definition digest, never a concrete Pod, IP or secret.

- TLS ([ADR-299](../docs/decisions/299-named-go-endpoint-tls.md)): an endpoint may pin public CA roots and a server name. The node verifies the peer in the target netns before HTTP; no system roots, insecure mode or cleartext fallback.
- Credentials ([ADR-302](../docs/decisions/302-named-profile-endpoint-authorization.md)): the definition names the permitted workload audiences. The header value comes from a Helm-rendered Secret mounted in the connector and is attached when the connector delivers work to the node, after TLS verification; previews, plans and stored state never contain it. An unavailable credential fails only that profile with `ProfileUnavailable`.

The request originates on the target's node, which streams the bounded response over the connector connection into the encrypted artifact ([ADR-287](../docs/decisions/287-go-profile-acquisition.md)); the node holds no evidence keys. Go requests use only `/debug/pprof/<type>` (`/debug/pprof/profile` for CPU) with binary `debug=0`, never `/cmdline` or `/symbol`. A missing endpoint ends the action with `ProfileUnavailable`, a conflicting application profiler with `ProfilerBusy`; neither publishes an artifact or retries, and the reservation is released ([ADR-298](../docs/decisions/298-explicit-go-profile-refusals.md)). Asservat never injects pprof or mutates the application to enable it.

### SC-PRF-001

Given a pod with pprof bound to its network namespace localhost, when a policy requests a CPU profile through an approved endpoint, then it records the pod's response for the requested interval, with verified or explicitly unknown serving-process attribution. Redirects to node metadata or a neighboring pod are rejected, and absence of pprof is reported. A maintainer can bind an allowed template without a new administrator entry; an out-of-range port or credential audience mismatch is denied. For a Python pod with no pprof endpoint, an `ebpfSampler` CPU profile contains samples only from that pod's processes, lists `python` among its detected runtimes and counts unverifiable samples as unattributed; no sample of a neighboring pod appears in the artifact, its metadata or the collector's logs.

## REQ-PRF-002 — Overhead and mutual exclusion

Classification follows what the acquisition changes in the target ([ADR-335](../docs/decisions/335-usable-by-default.md) D5). A Go pprof GET of what the application already serves is `observe` (heap without forced GC, allocs, goroutine, block, mutex, threadcreate, and CPU intervals within the duration ceiling) and needs ordinary collection rights, in manual captures and policies. The eBPF sampler is `observe`. `forceGC=true`, changed sampling rates, execution traces, JFR/EventPipe sessions, the inspector and external profilers are `intrusive` and need the applicable approval with exact parameters. `forceGC` applies only to heap snapshots; with delta mode it is rejected at validation ([Go HTTP pprof implementation](https://go.dev/src/net/http/pprof/pprof.go)). Block/mutex profiles without enabled sampling are distinguished from zero contention.

Defaults: CPU profile 10 s, trace 5 s, both editable up to the administrator duration ceiling (default 5 minutes); output caps 16 MiB for profiles and 32 MiB for traces, each at most its publication verification bound (REQ-PRF-003), so every collectable profile is verifiable. Snapshot profiles use a 5 s I/O idle timeout ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D5), not a total deadline.

One Asservat CPU/trace recording per conflicting runtime domain runs at a time (Go allows one CPU profile and one execution trace per process). The eBPF sampler is shared per node, bounded by the node's expensive-concurrency limit ([capacity](capacity.md)). An application-owned session yields `ProfilerBusy`; Asservat never stops or overwrites it. HTTP cancellation does not prove the application stopped profiling, so an uncertain outcome is not retried. `cancel_capture` stops acquisition and upload; a stored completion wins a concurrent Stop, and whether the application stopped is reported as unknown once the request was sent.

The [assessment](capture-assessment.md) shows runtime options, sampling and interference with other profilers. A Go heap profile holds allocation samples, not a full heap. Unqualified numeric overhead is unknown.

### SC-PRF-002

Given an existing application CPU profiler, when Asservat requests a conflicting profile, then it returns `ProfilerBusy` without terminating that session; the capture is terminally failed with that reason and publishes no artifact. Given a missing endpoint, the action reports `ProfileUnavailable` without retrying. A heap request leaves GC behavior unchanged unless its approval authorizes forcing GC. A second `ebpfSampler` request for another pod on the same node shares the running sampler and contains only its pod's samples.

## REQ-PRF-003 — Format, identity and pre-analysis

Preserve the original as raw evidence in its true format (`pprof`, `go-trace`, `jfr`, `nettrace`, `speedscope`, `v8-cpuprofile` or a qualified pack). Manifests record acquisition facts: type, requested duration, mode, actual start/stop, source and endpoint digest, forced GC and target identity. Semantic facts (sample types/units, period, drops, mappings) are established once by the publisher's verification and stored as artifact metadata ([ADR-284](../docs/decisions/284-go-profile-native-types.md)); an endpoint producer does not parse the response.

Verification parses in the regional reader within one memory budget: the reader's memory request divided by its concurrent verifications. Go pprof is verified with `google/pprof` after a decompression and an [allocation-shape preflight](../docs/reviews/pprof-allocation-preflight.md) sized to that budget; Go execution traces (Go 1.22+) with `golang.org/x/exp/trace`. The collection maximum equals this bound, so no collectable profile is refused for size; unsupported shapes are refused, never truncated.

Go profile projections run in the [regional reader](evidence.md#req-evd-005--analysis-isolation-and-output-classes) ([ADR-286](../docs/decisions/286-bounded-go-analyzer-isolation.md)); analyzers that execute evidence-supplied content keep the isolated boundary used for cores. Use exact local symbols; no HTTP symbol lookup or URL fetching. Extracts are deterministic: totals, flat/cumulative hotspots, call-tree edges, allocation totals, blocking/lock summaries and symbol coverage. Trace/JFR timelines have their own extract schemas. Labels, comments, paths and goroutine metadata may be sensitive; apply field allowlists before classification. Flamegraphs render locally from sanitized data.

### SC-PRF-003

Given a profile with multiple sample types, stripped mappings and secret-bearing labels, when pre-analysis runs, then it keeps units/types distinct, reports symbol gaps, removes unapproved labels from extracts and preserves the encrypted original.

## REQ-PRF-004 — Baselines and time correlation

`profile` acquisition is onTrigger ([action lifecycles](action-lifecycle.md)): a CPU interval starts at dispatch and is never pre-trigger history. Baselines are explicit scheduled policies. Cases link profile intervals to metric/log intervals by target identity and clock uncertainty. The acquisition window stored after verification ([ADR-297](../docs/decisions/297-verified-profile-acquisition-metadata.md)) covers the HTTP acquisition; queue or storage times and workload-supplied timestamps are never substituted, and missing windows are unknown. Pod identity does not prove serving-process identity. Baselines use the same budgets, sharing and expiry as incident evidence; an expired baseline is unavailable and is never silently extended. No continuous profiling backend is required.

### SC-PRF-004

Given a trigger that starts a 10-second CPU recording, when the case timeline is built, then the profile is marked post-trigger. A baseline from the prior container restart remains separate and cannot be silently treated as the same process.

## REQ-PRF-005 — Bounded profile queries and comparison

`get_extract(view=profileSummary)` ([ADR-291](../docs/decisions/291-bounded-profile-summary.md)) returns sample type, units, duration, total, top flat/cumulative functions and symbol/completeness warnings, under ordinary read rights and the original audience; it grants no raw query or download. Totals keep their signs for delta profiles; the fraction column is null unless all values are nonnegative and the total positive.

`compare_profiles` ([ADR-295](../docs/decisions/295-two-source-profile-comparison.md)) is one operation that authorizes each source independently, requires compatible sample semantics or returns a mismatch, and aggregates every cumulative function value before ranking incident-minus-baseline deltas. `none` keeps raw signed values; `perSecond` needs positive duration and interval/delta semantics on both sides and is computed from native counts before rounding. An omitted function is not zero. Unknown build, sampling and symbols stay explicit. No claim of statistical significance from one short sample. Both sources must be readable by the same regional reader; otherwise `Unavailable`. A recipient cannot compare against an unshared baseline or learn it exists.

Results page under [REQ-MCP-002](mcp.md#req-mcp-002--bounded-result-contract).

### SC-PRF-005

Given a 10-second CPU profile and a 30-second baseline, when the user requests rate comparison, then the result identifies normalization and units. Comparing allocation bytes to CPU nanoseconds is rejected. A hidden baseline cannot be inspected through comparison errors or timing metadata.

## Approval and upload

A non-intrusive profile needs no approval: in a policy it has no expiry or run count (ADR-335 D6), and its evidence is read by the policy audience under ordinary rights; a manual one is collected under the requester's rights and downloadable by users who hold `pods/portforward` or `pods/proxy` on the workload (ADR-335 D5). An intrusive profile needs the policy's expiring grant or the one independent approval, which also covers the requester's result inspection ([investigation approval](investigation-approval.md)). Previews ([ADR-285](../docs/decisions/285-profile-preview-plans.md)) are stateless dry runs that freeze the endpoint definition and digest without dialing or reading credentials; `builtin/go-cpu/v1` selects a 10 s CPU interval and `builtin/go-profile/v1` exposes the Go profile type as an editable field. The review shows runtime, type, mode, duration, forced GC, output limit and the endpoint, and states that there is no pre-trigger history.

A profile is written in one non-resumable upload ([ADR-290](../docs/decisions/290-one-shot-profile-streaming.md)); admission reserves the maximum native size in the workload quota under the operation ID and releases the difference on completion or abort. Abandoned multipart parts are removed by the bucket's `AbortIncompleteMultipartUpload` rule. A failed upload is not retried.
