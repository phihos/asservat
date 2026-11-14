# Profiles and runtime traces

Profiles are first-class evidence: they can be selected in a recipe, triggered automatically under a policy grant, preserved with a case, shared with users/groups, compared to a baseline, and queried through MCP. A profile records sampled or accumulated behavior; it is distinct from a core, heap dump or log snapshot.

## Capability catalogue

| Runtime/source | Initial or planned formats | Preparation and limits |
| --- | --- | --- |
| Go pprof | CPU, heap, allocations, goroutines, block, mutex, threadcreate; binary pprof | Application already exposes an approved pprof endpoint or writes profiles. Block/mutex sampling must already be enabled by the application. |
| Go execution trace | Native runtime trace, separate from pprof | Approved trace endpoint; short duration; higher data volume and overhead |
| Any runtime (eBPF CPU sampler) | CPU sampled stacks for native code, Go, JVM (HotSpot), Python, Node.js (V8), .NET, Ruby, PHP, Perl and BEAM; pprof | Node collector's pinned OpenTelemetry eBPF profiler ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)); kernel 5.10+ (the upstream profiler's supported floor); nothing attached to the target; only the selected pod's samples leave the collector; native frames need symbols |
| JVM | JFR started through `jcmd` for allocation and lock samples; async-profiler only as an explicit opt-in | Qualified JDK attach/recording permissions; async-profiler loads a native agent into the target and is operator-managed |
| .NET | EventPipe `.nettrace` allocation and selected runtime events | Diagnostic socket and matching runtime tooling; no assumption of direct pprof compatibility |
| Python | No agent-free heap profile; py-spy or `tracemalloc` only as explicit opt-ins | They attach to or modify the target; CPU comes from the eBPF sampler |
| Node.js | Heap sampling through the inspector, only as an explicit opt-in | No public inspector exposure; CPU comes from the eBPF sampler |

Go's pprof HTTP API distinguishes binary profiles, optional GC and duration/delta parameters; some profile types require application sampling setup. [Go pprof HTTP API](https://pkg.go.dev/net/http/pprof), [Go diagnostics](https://go.dev/doc/diagnostics). JFR/async-profiler and EventPipe have their own formats and semantics. [async-profiler modes](https://github.com/async-profiler/async-profiler/blob/master/docs/ProfilingModes.md), [.NET trace tool](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-trace), [Node CPU profiling](https://nodejs.org/api/cli.html#--cpu-prof).

## REQ-PRF-001 — Typed profile collection

The `profile` action MUST specify runtime, profile type, acquisition mode (`snapshot`, `cumulative`, `delta` or `interval`), named acquisition source, duration where meaningful, and the ordinary action byte/deadline limits. Go pprof CPU and heap collection are part of the first production scope; other Go types are available when their application prerequisites are satisfied. Additional runtime formats are independently qualified capability packs.

CPU profiles for runtimes without an approved pprof endpoint come from the node collector's eBPF sampler ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)): a `profile` action with `runtime: any`, `type: cpu` and source kind `ebpfSampler`, which names no endpoint and attaches nothing to the target. The evidence scope is the whole selected pod, under the same rule as syscall traces: no container selector and no host-wide fallback. The kernel program samples host-wide while at least one session runs on the node, because the qualified profiler has no cgroup filter; concurrent sessions for different pods share that one sampler and each receives only its own pod's samples. The collector MUST attribute each sample by verified pod, cgroup, process-start and node-boot identity and MUST drop a sample whose membership is uncertain, counting it as `unattributedSamples`. Samples of other processes are discarded in collector memory before encoding, encryption or any output, are never written to disk, logs or metrics, and are not counted, so no other workload's activity is disclosed; the collector suppresses its own core dumps. The artifact is pprof with `runtime: any`, the `detectedRuntimes` it found and build IDs for native mappings; missing symbols are reported. Allocation, lock and heap profiles remain per-runtime adapters.

Acquire through an administrator-approved named endpoint or a qualified runtime adapter. Resolve endpoints to the selected pod identity; support pod IP and loopback within the target netns. A localhost endpoint MUST NOT resolve to the collector's own loopback. Do not accept arbitrary URLs, redirects, ports, headers or query parameters from an MCP client. TLS/auth credentials come from named profiles and are not captured as evidence.

The acquisition request originates on the exact target node. Under [ADR-287](../docs/decisions/287-go-profile-acquisition.md), the node uploads its bounded in-memory result directly over the existing authenticated mTLS channel to the regional connector, which encrypts it before managed storage. The admitted attempt selects the destination; no alternative destination or hub plaintext proxy is allowed. The node receives no evidence key credentials. Plaintext residency is bounded by the admitted node response limit and the acquisition/upload deadlines. Named endpoint profiles are administrator-managed entries under the local collection ceiling; they pin target/port/path policy, TLS trust and credential references. To avoid per-application setup tickets, an administrator may also publish a reusable endpoint template. A maintainer binds it in `EvidenceRecipe.spec.endpointBindings` with a local binding name, template reference, approved target address mode and either a declared pod port name or a numeric port within the template's allowed range, so an application that already serves pprof on a port needs no Deployment change or rollout. Profile `source.profileRef` resolves to that local binding or a fully configured administrator endpoint; duplicate/ambiguous names are rejected. Resolve a port name across the pod specification; reject ambiguous duplicate resolutions and enforce the template's allowed port range, fixed path policy and target identity. No free URL, hostname, credential or path override is accepted. Credentialed templates must explicitly scope the credential to permitted workload identities, so a maintainer cannot redirect a privileged credential to their own listener. Approval binds the resolved template digest and endpoint parameters. Autodetection may suggest a declared port/runtime or the conventional `6060` within the template's range, but never activates profiling or weakens these checks.

Named Go endpoints may use TLS ([ADR-299](../docs/decisions/299-named-go-endpoint-tls.md)).
A regional endpoint entry may carry explicit public certificate roots (PEM that
must parse; its size is bounded only by the configuration object, 1 MiB) and a fixed server name. Approval and recurring policy definitions
bind the trust source identity, canonical material digest and server name;
certificate bytes stay out of approval scopes. The node verifies the peer on the
socket in the target netns before HTTP, within the action deadline. No system
roots, DNS lookup, insecure mode, cleartext fallback or acquisition retry exists.
A node that does not support TLS refuses TLS captures.

Credentialed endpoints ([ADR-302](../docs/decisions/302-named-profile-endpoint-authorization.md))
keep the credential policy's public identity and exact workload-root audiences
in the named endpoint definition. The policy name is the endpoint name; manual
and recurring approval pin the definition/audience digest, never a header value
or secret digest. The header value comes from a Helm-rendered Secret mounted
into the connector and is added to the work item when the connector delivers it
to the node, after the admitted-work and audience checks. Preview and policy
compilation never read it, and queued work and persistent state stay
credential-free. The node verifies TLS before sending `Authorization`; a node
without support refuses. An unavailable credential fails only that profile with
`ProfileUnavailable` and no acquisition; other work continues.

For Go, generate only the allowlisted `/debug/pprof/<type>` paths; CPU uses `/debug/pprof/profile`. Prefer binary `debug=0`; do not call `/cmdline` or remote `/symbol` as part of profiling. Missing/disabled endpoints yield `ProfileUnavailable`. After an admitted HTTP attempt, this is a terminal failed action with `reason_code: ProfileUnavailable`; a conflicting application-owned session similarly ends with `reason_code: ProfilerBusy`. Neither result publishes an artifact or retries acquisition; the admitted reservation is released when the terminal outcome is recorded ([ADR-298](../docs/decisions/298-explicit-go-profile-refusals.md)). Asservat does not inject pprof into an existing binary or enable it through an unapproved application mutation.

### SC-PRF-001

Given a pod with pprof bound to its network namespace localhost, when a policy requests a CPU profile through an approved netns endpoint, then it records the pod endpoint response for the requested bounded interval, with verified or explicitly unknown serving-process attribution. Redirects to node metadata or a neighboring pod are rejected, and absence of pprof is reported explicitly. A maintainer can bind an already allowed template without an administrator creating a new per-app profile; an out-of-range port or credential audience mismatch is denied. For a Python pod with no pprof endpoint, an `ebpfSampler` CPU profile returns pprof samples only from that pod's processes, lists `python` among its detected runtimes and counts samples of a process whose pod membership could not be verified as unattributed instead of including them; no sample of a neighboring pod appears in the artifact, its metadata or the collector's logs.

## REQ-PRF-002 — Overhead and mutual exclusion

Classification follows what the acquisition changes in the target ([ADR-335](../docs/decisions/335-usable-by-default.md) D5). A Go pprof GET that reads what the application already serves is `observe`: heap without forced GC, allocs, goroutine, block, mutex and threadcreate snapshots or cumulative/delta reads, and CPU intervals within the administrator duration ceiling. It needs ordinary collection rights and no approval, in manual captures and in policies. `forceGC=true`, changed sampling rates, runtime execution traces, JFR/EventPipe sessions, the inspector and attaching an external profiler (async-profiler, py-spy) are `intrusive` and need the applicable approval. The eBPF CPU sampler attaches nothing to the target and is `observe`. An administrator may require approval for all profiles with `approvals.requireProfileApproval` (default off). Default CPU profile duration 10 seconds and default trace duration 5 seconds, both editable up to the administrator duration ceiling (configurable, default 5 minutes); the approval states the window, and bytes are bounded by the output cap. Default profile output cap 16 MiB and default trace output cap 32 MiB; the maximum of each equals its publication verification bound (REQ-PRF-003 below), so every collectable profile is verifiable. Snapshot profiles use a 5-second I/O idle timeout ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D5), not a total deadline, so a large goroutine profile can finish serializing. Action deadlines must include setup/shutdown margin beyond timed recording duration.

Do not force GC for a heap profile by default. `forceGC=true`, changes to sample rates, attachment of an external profiler, or starting high-frequency tracing require exact approved parameters. The bounded Go HTTP adapter supports forced GC only for heap snapshots: the standard handler processes `seconds` through its delta path before the GC branch, so `forceGC=true` combined with delta mode is unavailable and must be rejected during capability validation rather than silently ignored. [Go HTTP pprof implementation](https://go.dev/src/net/http/pprof/pprof.go). Block/mutex profiles that contain no data because sampling is disabled MUST be distinguished from a valid zero-contention result.

Only one Asservat CPU/trace recording in a conflicting runtime domain may run at once (the Go runtime allows one CPU profile and one execution trace per process). The eBPF sampler is shared per node: concurrent sessions for different pods use one sampler with per-session pod filters, and its node CPU is bounded by the node's expensive-concurrency limit ([capacity](capacity.md)). If the application already owns an incompatible profiling session, return `ProfilerBusy`; do not stop or overwrite it. Record actual start/stop, requested/observed sampling settings and cancellation outcome. HTTP cancellation does not prove the application stopped profiling, so an uncertain outcome is not automatically retried.

Finite manual profiles use the shared `cancel_capture` operation, which needs
current ordinary rights. Stop reaches the node as an event and cancels
acquisition, upload and storage; the profile reports `Cancelled` once the writer
has stopped. A stored completion wins a concurrent Stop. A cancellation before
the endpoint request reports that no profiling started; otherwise whether the
application stopped profiling is reported as unknown. Neither outcome retries or
starts a replacement acquisition. The reservation is released when the
cancellation outcome is recorded.

The shared [assessment](capture-assessment.md) considers runtime/options, sampling, current headroom and other profilers/recorders. Flag interference separately from exclusive-session admission. A Go heap pprof profile contains allocation samples rather than a complete object heap; show possible labels/paths and forced-GC effects without falsely presenting it as a full heap dump. Unqualified numeric overhead remains unknown.

### SC-PRF-002

Given an existing application CPU profiler, when Asservat requests a conflicting profile, then it returns `ProfilerBusy` without terminating that session. The same admitted capture remains terminally failed, exposes that reason in progress and publishes no artifact; the application owner can observe its original profiler still running. Given a missing or disabled reviewed endpoint, the action instead reports `ProfileUnavailable` without retrying or changing the target. A heap request leaves GC behavior unchanged unless its policy grant explicitly authorizes forcing GC. Given an eBPF sampler session already running on a node, a second `ebpfSampler` request for another pod on that node shares the running sampler and its artifact contains only that pod's samples.

## REQ-PRF-003 — Format, identity and pre-analysis

Preserve the original profile as raw evidence, with its true format (`pprof`, `go-trace`, `jfr`, `nettrace`, `speedscope`, `v8-cpuprofile` or qualified pack identifier). Profile manifests MUST record acquisition facts: profile type, requested duration, cumulative/delta/snapshot/interval mode, actual start/stop, source reference and endpoint digest, forced GC and target identity. Semantic facts (sample value types/units, sample period, drop/overflow counters, binary/symbol mappings) are established once by the publisher's bounded verification of the native bytes and stored as SQL artifact metadata, which queries reuse; a producer that does not build the profile itself, such as a Go endpoint, does not parse the response and does not record them ([ADR-284](../docs/decisions/284-go-profile-native-types.md)). Verification parses in the regional reader's memory, so one bound applies: the per-verification memory budget is the reader's memory request divided by its concurrent verifications. Go pprof is verified with `google/pprof` after a decompression capped by that budget divided by the measured parser allocation factor, and Go execution traces (Go 1.22 and later) with `golang.org/x/exp/trace` within an event count derived from the same budget. Before the object parser, a pprof [allocation-shape preflight](../docs/reviews/pprof-allocation-preflight.md) counts samples, locations, functions, labels, strings, location references, inline lines, values, comments, sample types and mappings and requires Σ(count × measured Go bytes per entry) ≤ that budget; there are no separate per-kind constants. The collection maximum equals this verification bound, so a collectable profile is never refused for size at publication. Unsupported shapes are refused at publication or analysis, never truncated; existing stored evidence and grants are not rewritten. An eBPF sampler profile also records its detected runtimes and unattributed samples; its native mappings carry build IDs, and frames it could not name stay unresolved rather than guessed. Missing values remain unknown.

Qualified bounded Go profile projections run in the [regional evidence reader](evidence.md#req-evd-005--analysis-isolation-and-output-classes) ([ADR-286](../docs/decisions/286-bounded-go-analyzer-isolation.md)). Native tools and analyzers that execute evidence-supplied content keep the isolated analysis boundary used for cores (REQ-EVD-005); choosing Go alone does not qualify a parser. Pprof uses a protobuf profile model with mappings, locations, functions, samples and labels; parse with maintained pprof tooling rather than an improvised format. Use exact local symbols; prohibit HTTP symbol lookup and analysis-time URL fetching. Produce deterministic extracts: total samples, flat/cumulative hotspots, call-tree edges (cursor pages within the output ceiling), allocation totals, blocking/lock wait summaries and symbol coverage. Runtime trace/JFR timelines have separate extract schemas; do not mislabel them as pprof. [pprof profile schema](https://github.com/google/pprof/blob/main/proto/profile.proto).

Arbitrary sample labels, comments, paths and thread/goroutine metadata may contain sensitive data. Apply label/field allowlists before extract classification. Retain transform/tool versions and raw provenance. Optional flamegraph views use sanitized locally rendered data with no executable content supplied by the profile.

### SC-PRF-003

Given a profile with multiple sample types, stripped mappings and secret-bearing labels, when pre-analysis runs, then it keeps units/types distinct, reports symbol gaps, removes unapproved labels from extracts and preserves the encrypted original.

## REQ-PRF-004 — Baselines and time correlation

Profiles MAY be captured periodically as low-frequency baselines through an explicit scheduled policy, or before/after an observed incident where time permits. They MUST NOT be presented as pre-trigger history unless recording already existed before the trigger. Existing JFR/runtime recording collection is a separate explicitly authorized operation and must not assume control of an application-owned recorder.

Cases link profile intervals to metric/log/probe intervals using target identity and source-clock uncertainty. A profile from a different process restart is labeled a different instance. Baseline retention consumes the same budgets and follows the same sharing/expiry rules as incident evidence. No continuous cluster-wide profiling backend is a hard dependency.

Collector-observed Go endpoint acquisition times are stored as artifact
metadata once publication verification succeeds
([ADR-297](../docs/decisions/297-verified-profile-acquisition-metadata.md)).
Display windows use UTC microsecond precision; the sealed original is unchanged.
The window covers HTTP acquisition, not precise sampling or cumulative counter
history. Missing windows and clock uncertainty are shown as unknown. A
preparation, queue or storage timestamp or a workload-supplied pprof timestamp
is never substituted for the acquisition window. Pod identity does not establish
serving-process identity or restart continuity: cases may show different Pods
without claiming different server processes.

### SC-PRF-004

Given a trigger that starts a 10-second CPU recording, when the case timeline is built, then the profile is marked post-trigger. A baseline from the prior container restart remains separate and cannot be silently treated as the same process.

## REQ-PRF-005 — Bounded MCP profile queries and comparison

[ADR-291](../docs/decisions/291-bounded-profile-summary.md) separates the approved summary operation from raw input disclosure. A closed pprof summary requires current ordinary read rights, and the original retained audience; it does not confer native download or arbitrary raw query authority. The original input remains raw for processing and retention. Metadata-only shares do not authorize profile summaries.

`get_extract(view=profileSummary)` MUST provide selected sample type, units, duration, total, top-N flat/cumulative functions, and symbol/completeness warnings. `compare_profiles` MUST authorize both artifacts independently, require compatible profile/sample semantics or return a mismatch, and label raw deltas versus duration-normalized rates. Default top-N 20; further rows page by cursor within the result bound. Cursors, shares, grants, output ceilings and audit rules apply normally. Summary totals, flat and cumulative values retain their signs for delta profiles. The displayed fraction is flat divided by total only when all selected sample values are nonnegative and the total is positive; otherwise it is null, not a fabricated zero or an absolute-value normalization.

The browser uses saved acquisition metadata to suggest an editable summary sample
type: `inuse_space` for heap profiles, with the existing `cpu` default for CPU or
unknown profile types. This initial selection does not establish native sample
semantics or units; units come only from the verified query result. Metadata
rerenders preserve the user's input for the same case/artifact/version, while
switching immutable sources resets the suggestion. Opening the view makes no
query or endpoint probe.

Comparison MUST preserve baseline/incident identity, build changes, profiling configuration and normalization method. Do not claim statistical significance or a definitive regression from one short sample. A shared recipient cannot compare against an unshared baseline or learn its existence. Access to approved aggregates is extract access; arbitrary label/raw sample inspection needs the appropriate raw grant.

[ADR-295](../docs/decisions/295-two-source-profile-comparison.md) fixes the
bounded Go comparison: aggregate every selected cumulative function value before
ranking absolute incident-minus-baseline deltas, then function name. Do not
subtract truncated summaries or infer that an omitted function has zero value.
`none` preserves raw signed values. `perSecond` requires positive native duration
and interval/delta semantics on both inputs; its unit is the selected native unit
per second. Calculate from native integer counts and nanosecond durations before
rounding each displayed value. Independently rounded rates may subtract to a
value different from the displayed delta; disclose this precision limit. Unknown
build, sampling configuration and symbols remain explicit. Heap and allocation
handlers may compare matching selected counters with compatible state/window
semantics; their handler names alone do not establish incompatibility.

A comparison is one operation with one authorization that covers each source
independently: current rights, original audience, client, retention and
processing restriction. Summary and comparison results are computed from the
verified native file as described for stored-evidence queries in
[REQ-EVD-005](evidence.md#req-evd-005--analysis-isolation-and-output-classes);
neither source's native size limit is enlarged by comparison. The query binds
both exact versions, role order and normalization, and both reads are charged in
one transaction. Both sources must be readable by the same regional evidence
reader; other placements return `Unavailable`, never a plaintext hub proxy.

### SC-PRF-005

Given a 10-second CPU profile and a 30-second baseline, when the user requests rate comparison, then the result identifies normalization and units. Comparing allocation bytes to CPU nanoseconds is rejected. A hidden baseline cannot be inspected through comparison errors or timing metadata.

A declared port is a routing hint, not proof of its serving process. Within a pod shared networking is intentional; attribute profiles to a process only through a qualified socket/runtime check. Credential profiles must bind the pod's trusted workload identity and endpoint/TLS identity; never rely on a container port declaration as a credential audience. Endpoint ambiguity yields EndpointAmbiguous, with suggested qualified bindings, never a request to add container permissions. An expired baseline is unavailable; the UI offers an authorized compatible retained baseline or a new explicit baseline request and never silently extends retention.

Runtime `profile` acquisition is onTrigger in the initial lifecycle registry, including interval CPU sampling and retrieval of application-owned cumulative counters. The ten-second CPU profile starts at admitted dispatch; it is not a pre-trigger flight recorder. An explicit scheduled baseline is another bounded capture. Adding an Asservat-owned continuous profiling adapter later requires an ongoing lifecycle and qualification; it cannot be inferred from profile.mode or enabled during preview.

Go endpoint acquisition streams the exact native response into the encrypted
artifact format ([runtime profiles](../docs/architecture/runtime-profiles.md));
it never extends the admitted action deadline.


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
resolved public configuration and mechanism parameters. Endpoint definitions
come from Helm-rendered regional configuration; a catalog entry grants no
credential use by itself. See the [runtime-profile boundary](../docs/architecture/runtime-profiles.md).

### Manual profile preview

A preview is a stateless dry run (ADR-330 D9) under one authorization of the
public request. History-backed repeat previews resolve the current exact target
and endpoint once and return the plan and its digest; they neither collect a
profile nor obtain an approval.


[ADR-285](../docs/decisions/285-profile-preview-plans.md) connects the passive
endpoint planner to manual preview through regional configuration. The plan
freezes the public definition and endpoint digests without dialing or reading
credentials. `builtin/go-cpu/v1` selects a ten-second CPU interval and
`builtin/go-profile/v1` exposes the Go profile type (cpu, heap, allocs,
goroutine, block, mutex) as an editable field; custom profiles may use the
supported Go modes or the eBPF CPU sampler. Plans state raw native output and,
only for intrusive profiles, the required `liveProfile` approval reason.

### Finite profile admission and custody

[ADR-296](../docs/decisions/296-finite-policy-go-profiles.md) extends finite Go
endpoint acquisition to accepted team policies. Recurring approval binds the
protected public endpoint definition/digest, source kind and selected binding
or administrator fixed port, together with exact profile type, mode, duration,
timeout, forced-GC choice and native-byte limit. It contains no future Pod,
route/IP, concrete endpoint digest or refreshed observation time. Each trigger
resolves its actual pinned Pod and verifies its concrete endpoint against that
stable scope. Ordinary replica replacement does not change collection intent;
changing the protected definition or binding does.

A non-intrusive policy profile needs no approval and has no expiry or run count
(ADR-335 D6); an intrusive one (forced GC, traces, sampling changes) needs the
expiring `policyCollection`/`liveProfile` grant. Both spend the existing
execution/native-output pools and acquire no packet or syscall observation
budgets. Profiles collected by an applied team policy are read and downloaded by
the policy's audience under ordinary evidence rights; no per-artifact human
approval is needed (ADR-335 D5). All existing finite Go mode limits and
prerequisites apply. Runtime trace remains trace format and cannot enter pprof
analysis.

A qualified manual Go endpoint acquisition is a distinct typed profile request,
never a packet recorder. Persist the reviewed composition, expanded endpoint
bindings, definition/endpoint digests, native byte ceiling and action timeout;
re-resolve the exact endpoint before starting without rewriting the reviewed
plan. A non-intrusive manual profile is collected under the requester's ordinary
rights; the requester, and other users with current evidence rights who hold
`pods/portforward` or `pods/proxy` on that workload, download it without a
second person's approval. An intrusive manual
profile needs the one independent approval; the same approval covers the
requester's selected result inspection/download ([investigation
approval](investigation-approval.md)).

The persisted approval review and shared browser/MCP response carry the profile
runtime, type, mode, optional duration, timeout, forced-GC choice, native limit
and reviewed endpoint name, address mode, port, path policy and digest. The
console presents these parameters and the absence of pre-trigger history;
profile actions carry no fabricated packet window, filter or recording ring.
This summary does not replace the canonical execution scope or probe endpoints.

Profiles are written in one non-resumable upload
([ADR-290](../docs/decisions/290-one-shot-profile-streaming.md)). Admission
reserves the maximum native size once in the workload's quota, under the
profile request's operation ID. Larger limits use multipart upload; the evidence
bucket's `AbortIncompleteMultipartUpload` lifecycle rule removes abandoned parts.
The reservation is released to the stored size on completion and fully on abort
or any other terminal outcome. A failed upload is not retried.
