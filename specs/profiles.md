# Profiles and runtime traces

Profiles are first-class evidence: they can be selected in a recipe, triggered automatically under a policy grant, preserved with a case, shared with users/groups, compared to a baseline, and queried through MCP. A profile records sampled or accumulated behavior; it is distinct from a core, heap dump or log snapshot.

## Capability catalogue

| Runtime/source | Initial or planned formats | Preparation and limits |
| --- | --- | --- |
| Go pprof | CPU, heap, allocations, goroutines, block, mutex, threadcreate; binary pprof | Application already exposes an approved pprof endpoint or writes profiles. Block/mutex sampling must already be enabled by the application. |
| Go execution trace | Native runtime trace, separate from pprof | Approved trace endpoint; short duration; higher data volume and overhead |
| Any runtime (eBPF CPU sampler) | CPU sampled stacks for native code, Go, JVM (HotSpot), Python, Node.js (V8), .NET, Ruby, PHP, Perl and BEAM; pprof | Node collector's pinned OpenTelemetry eBPF profiler ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)); kernel 5.10+; nothing attached to the target; only the selected pod's samples leave the collector; native frames need symbols |
| JVM | JFR started through `jcmd` for allocation and lock samples; async-profiler only as an explicit opt-in | Qualified JDK attach/recording permissions; async-profiler loads a native agent into the target and is operator-managed |
| .NET | EventPipe `.nettrace` allocation and selected runtime events | Diagnostic socket and matching runtime tooling; no assumption of direct pprof compatibility |
| Python | No agent-free heap profile; py-spy or `tracemalloc` only as explicit opt-ins | They attach to or modify the target; CPU comes from the eBPF sampler |
| Node.js | Heap sampling through the inspector, only as an explicit opt-in | No public inspector exposure; CPU comes from the eBPF sampler |

Go's pprof HTTP API distinguishes binary profiles, optional GC and duration/delta parameters; some profile types require application sampling setup. [Go pprof HTTP API](https://pkg.go.dev/net/http/pprof), [Go diagnostics](https://go.dev/doc/diagnostics). JFR/async-profiler and EventPipe have their own formats and semantics. [async-profiler modes](https://github.com/async-profiler/async-profiler/blob/master/docs/ProfilingModes.md), [.NET trace tool](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-trace), [Node CPU profiling](https://nodejs.org/api/cli.html#--cpu-prof).

## REQ-PRF-001 — Typed profile collection

The `profile` action MUST specify runtime, profile type, acquisition mode (`snapshot`, `cumulative`, `delta` or `interval`), named acquisition source, duration where meaningful, and the ordinary action byte/deadline limits. Go pprof CPU and heap collection are part of the first production scope; other Go types are available when their application prerequisites are satisfied. Additional runtime formats are independently qualified capability packs.

CPU profiles for runtimes without an approved pprof endpoint come from the node collector's eBPF sampler ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)). It needs no endpoint and attaches nothing to the target. It samples host-wide only for the bounded session and MUST keep only samples whose process belongs to the selected pod, verified by pod, cgroup and process-start identity; all other samples are discarded in collector memory before encoding, encryption or output, and coverage reports dropped and unattributed samples. Output is pprof with build IDs for native mappings; missing symbols are reported. Allocation, lock and heap profiles remain per-runtime adapters.

Acquire through an administrator-approved endpoint profile or a qualified runtime adapter. Resolve endpoints to the selected pod identity; support pod IP and loopback within the target netns. A localhost endpoint MUST NOT resolve to the collector's own loopback. Do not accept arbitrary URLs, redirects, ports, headers or query parameters from an MCP client. TLS/auth credentials come from named profiles and are not captured as evidence.

The acquisition request originates on the target node and streams directly into that node's encryption path. A controller/hub HTTP proxy must not carry the plaintext profile. Named endpoint profiles are administrator-managed entries under the local collection ceiling; they pin target/port/path policy, TLS trust and credential references. To avoid per-application setup tickets, an administrator may also publish a reusable endpoint template. A maintainer binds it in `EvidenceRecipe.spec.endpointBindings` with a local binding name, template reference, approved target address mode and declared pod port name. Profile `source.profileRef` resolves to that local binding or a fully configured administrator profile; duplicate/ambiguous names are rejected. Resolve a port name across the pod specification; reject ambiguous duplicate resolutions and enforce the template's allowed port range, fixed path policy and target identity. No free URL, hostname, credential or path override is accepted. Credentialed templates must explicitly scope the credential to permitted workload identities, so a maintainer cannot redirect a privileged credential to their own listener. Approval binds the resolved template digest and endpoint parameters. Autodetection may suggest a declared port/runtime, but never activates profiling or weakens these checks.

For Go, generate only the allowlisted `/debug/pprof/<type>` paths; CPU uses `/debug/pprof/profile`. Prefer binary `debug=0`; do not call `/cmdline` or remote `/symbol` as part of profiling. Missing/disabled endpoints yield `ProfileUnavailable`. Asservat does not inject pprof into an existing binary or enable it through an unapproved application mutation.

### SC-PRF-001

Given a pod with pprof bound to its network namespace localhost, when a policy requests a CPU profile through an approved netns endpoint, then it records the pod endpoint response for the requested bounded interval, with verified or explicitly unknown serving-process attribution. Redirects to node metadata or a neighboring pod are rejected, and absence of pprof is reported explicitly. A maintainer can bind an already allowed template without an administrator creating a new per-app profile; an out-of-range port or credential audience mismatch is denied.

## REQ-PRF-002 — Overhead and mutual exclusion

Live profiling MUST be classified as intrusive for approval/budget purposes even if the mechanism is an HTTP GET. Default CPU profile duration 10 seconds, maximum 60 seconds under the administrator ceiling; default trace duration 5 seconds, maximum 15 seconds. Default profile output cap 16 MiB, maximum 64 MiB; default trace output cap 32 MiB, maximum 128 MiB. Snapshot profiles have a 5-second default acquisition deadline. Action deadlines must include setup/shutdown margin beyond timed recording duration.

Do not force GC for a heap profile by default. `forceGC=true`, changes to sample rates, attachment of an external profiler, or starting high-frequency tracing require exact approved parameters. The bounded Go HTTP adapter supports forced GC only for heap snapshots: the standard handler processes `seconds` through its delta path before the GC branch, so `forceGC=true` combined with delta mode is unavailable and must be rejected during capability validation rather than silently ignored. [Go HTTP pprof implementation](https://go.dev/src/net/http/pprof/pprof.go). Block/mutex profiles that contain no data because sampling is disabled MUST be distinguished from a valid zero-contention result.

Only one Asservat CPU/trace recording in a conflicting runtime domain may run at once. If the application already owns an incompatible profiling session, return `ProfilerBusy`; do not stop or overwrite it. Record actual start/stop, requested/observed sampling settings and cancellation outcome. HTTP cancellation does not prove the application stopped profiling, so an uncertain outcome is not automatically retried.

The shared [assessment](capture-assessment.md) considers runtime/options, sampling, current headroom and other profilers/recorders. Flag interference separately from exclusive-session admission. A Go heap pprof profile contains allocation samples rather than a complete object heap; show possible labels/paths and forced-GC effects without falsely presenting it as a full heap dump. Unqualified numeric overhead remains unknown.

### SC-PRF-002

Given an existing application CPU profiler, when Asservat requests a conflicting profile, then it returns `ProfilerBusy` without terminating that session. A heap request leaves GC behavior unchanged unless its policy grant explicitly authorizes forcing GC.

## REQ-PRF-003 — Format, identity and pre-analysis

Preserve the original profile as raw evidence, with its true format (`pprof`, `go-trace`, `jfr`, `nettrace`, `speedscope`, `v8-cpuprofile` or qualified pack identifier). Profile manifests MUST record profile type, sample value types/units, sample period when known, recording start/duration, cumulative/delta/snapshot mode, drop/overflow counters where available, target identity and binary/symbol mappings. Missing values remain unknown.

Parse profiles in the same offline analyzer boundary as cores/pcaps. Pprof uses a protobuf profile model with mappings, locations, functions, samples and labels; parse with maintained pprof tooling rather than an improvised format. Use exact local symbols; prohibit HTTP symbol lookup and analysis-time URL fetching. Produce deterministic extracts: total samples, flat/cumulative hotspots, bounded call-tree edges, allocation totals, blocking/lock wait summaries and symbol coverage. Runtime trace/JFR timelines have separate extract schemas; do not mislabel them as pprof. [pprof profile schema](https://github.com/google/pprof/blob/main/proto/profile.proto).

Arbitrary sample labels, comments, paths and thread/goroutine metadata may contain sensitive data. Apply label/field allowlists before extract classification. Retain transform/tool versions and raw provenance. Optional flamegraph views use sanitized locally rendered data with no executable content supplied by the profile.

### SC-PRF-003

Given a profile with multiple sample types, stripped mappings and secret-bearing labels, when pre-analysis runs, then it keeps units/types distinct, reports symbol gaps, removes unapproved labels from extracts and preserves the encrypted original.

## REQ-PRF-004 — Baselines and time correlation

Profiles MAY be captured periodically as low-frequency baselines through an explicit scheduled policy, or before/after an observed incident where time permits. They MUST NOT be presented as pre-trigger history unless recording already existed before the trigger. Existing JFR/runtime recording collection is a separate explicitly authorized operation and must not assume control of an application-owned recorder.

Cases link profile intervals to metric/log/probe intervals using target identity and source-clock uncertainty. A profile from a different process restart is labeled a different instance. Baseline retention consumes the same budgets and follows the same sharing/expiry rules as incident evidence. No continuous cluster-wide profiling backend is a hard dependency.

### SC-PRF-004

Given a trigger that starts a 10-second CPU recording, when the case timeline is built, then the profile is marked post-trigger. A baseline from the prior container restart remains separate and cannot be silently treated as the same process.

## REQ-PRF-005 — Bounded MCP profile queries and comparison

`get_profile_summary` MUST provide selected sample type, units, duration, total, top-N flat/cumulative functions, and symbol/completeness warnings. `compare_profiles` MUST authorize both artifacts independently, require compatible profile/sample semantics or return a mismatch, and label raw deltas versus duration-normalized rates. Default top-N 20, maximum 100. Cursors, shares, grants, output ceilings and audit rules apply normally.

Comparison MUST preserve baseline/incident identity, build changes, profiling configuration and normalization method. Do not claim statistical significance or a definitive regression from one short sample. A shared recipient cannot compare against an unshared baseline or learn its existence. Access to approved aggregates is extract access; arbitrary label/raw sample inspection needs the appropriate raw grant.

### SC-PRF-005

Given a 10-second CPU profile and a 30-second baseline, when the user requests rate comparison, then the result identifies normalization and units. Comparing allocation bytes to CPU nanoseconds is rejected. A hidden baseline cannot be inspected through comparison errors or timing metadata.

A declared port is a routing hint, not proof of its serving process. Within a pod shared networking is intentional; attribute profiles to a process only through a qualified socket/runtime check. Credential profiles must bind the pod's trusted workload identity and endpoint/TLS identity; never rely on a container port declaration as a credential audience. Endpoint ambiguity yields EndpointAmbiguous, with suggested qualified bindings, never a request to add container permissions. An expired baseline is unavailable; the UI offers an authorized compatible retained baseline or a new explicit baseline request and never silently extends retention.

Runtime `profile` acquisition is onTrigger in the initial lifecycle registry, including interval CPU sampling and retrieval of application-owned cumulative counters. The ten-second CPU profile starts at admitted dispatch; it is not a pre-trigger flight recorder. An explicit scheduled baseline is another bounded capture. Adding an Asservat-owned continuous profiling adapter later requires an ongoing lifecycle and qualification; it cannot be inferred from profile.mode or enabled during preview.

The initial [Go acquisition component](../docs/architecture/runtime-profiles.md)
streams an exact native response into the existing encrypted format. Its current
observations never renew the original admitted action deadline or permit.
Profile-specific admission, qualified named node endpoints and semantic
publication remain prerequisites; this component does not enable a public
profile capability or widen the pod-status collector.


### Passive endpoint resolution boundary

The initial internal planner supports the existing recipe bindings and fully
configured named administrator profiles. Mixed catalogs may include entries for
other namespaces or clusters; those entries cannot disable an otherwise allowed
selection or disclose their definitions through an error. Absent and out-of-scope
names both yield `ProfileUnavailable`. It rejects duplicate applicable names
across catalog kinds/scopes, binding/profile collisions and every duplicate
named-port resolution across regular and init containers, including restartable
sidecars. A single TCP declaration must satisfy the template's port range.
Administrator profiles may fix an approved numeric port without requiring a
Pod port declaration. Neither form grants process attribution.

Loopback address family is an explicit administrator definition. Pod-IP routing
uses the observed primary IP without DNS or address/Pod fallback; equivalent
IPv6 spellings in legacy Pod IP fields normalize to the same route and digest.
Absent IP does not prevent passive loopback planning. Host-network endpoints remain unavailable
until separately qualified. Planning does not test endpoint reachability.
Credentialed definitions require pinned TLS trust/server identity and an exact
permitted workload-root audience. Source and computed endpoint digests bind the
resolved public configuration and mechanism parameters, while current
observations retain their original earliest cutoffs. A pure catalog value or
matching digest is not proof of protected source acceptance or permission to
use credentials. See the [runtime-profile boundary](../docs/architecture/runtime-profiles.md).
