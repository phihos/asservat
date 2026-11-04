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

CPU profiles for runtimes without an approved pprof endpoint come from the node collector's eBPF sampler ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)): a `profile` action with `runtime: any`, `type: cpu` and source kind `ebpfSampler`, which names no endpoint profile and attaches nothing to the target. The evidence scope is the whole selected pod, under the same rule as syscall traces: no container selector and no host-wide fallback. The kernel program samples host-wide during the bounded session only because the qualified profiler has no cgroup filter. The collector MUST attribute each sample by verified pod, cgroup, process-start and node-boot identity and MUST drop a sample whose membership is uncertain, counting it as `unattributedSamples`. Samples of other processes are discarded in collector memory before encoding, encryption or any output, are never written to disk, logs or metrics, and are not counted, so no other workload's activity is disclosed; the collector suppresses its own core dumps. The artifact is pprof with `runtime: any`, the `detectedRuntimes` it found and build IDs for native mappings; missing symbols are reported. Allocation, lock and heap profiles remain per-runtime adapters.

Acquire through an administrator-approved endpoint profile or a qualified runtime adapter. Resolve endpoints to the selected pod identity; support pod IP and loopback within the target netns. A localhost endpoint MUST NOT resolve to the collector's own loopback. Do not accept arbitrary URLs, redirects, ports, headers or query parameters from an MCP client. TLS/auth credentials come from named profiles and are not captured as evidence.

The acquisition request originates on the exact target node. Under [ADR-287](../docs/decisions/287-go-profile-acquisition.md), the node uploads its bounded in-memory result directly over the existing authenticated mTLS channel to the accepted regional connector writer, which wraps and encrypts it before managed storage. The immutable target and process-bound attempt select the destination; no alternative destination or hub plaintext proxy is allowed. The node receives no evidence key credentials. Plaintext residency is bounded by the admitted node response limit and original acquisition/upload deadlines; regional encryption uses the existing shared frame-bounded working budget. Named endpoint profiles are administrator-managed entries under the local collection ceiling; they pin target/port/path policy, TLS trust and credential references. To avoid per-application setup tickets, an administrator may also publish a reusable endpoint template. A maintainer binds it in `EvidenceRecipe.spec.endpointBindings` with a local binding name, template reference, approved target address mode and declared pod port name. Profile `source.profileRef` resolves to that local binding or a fully configured administrator profile; duplicate/ambiguous names are rejected. Resolve a port name across the pod specification; reject ambiguous duplicate resolutions and enforce the template's allowed port range, fixed path policy and target identity. No free URL, hostname, credential or path override is accepted. Credentialed templates must explicitly scope the credential to permitted workload identities, so a maintainer cannot redirect a privileged credential to their own listener. Approval binds the resolved template digest and endpoint parameters. Autodetection may suggest a declared port/runtime, but never activates profiling or weakens these checks.

[ADR-299](../docs/decisions/299-named-go-endpoint-tls.md) defines the TLS-only
implementation boundary for named Go endpoints: protected regional entries may
carry explicit public certificate roots and a fixed server name. Approval and
recurring policy definitions bind the public trust source identity, canonical
material digest and server name; certificate bytes stay outside approval/SQL
scopes. The existing exact target-netns socket performs TLS peer verification
before HTTP, within the original deadline. No system roots, DNS lookup, insecure
mode, cleartext fallback or acquisition retry is added. Credentials remain
unsupported by ADR-299 alone. ADR-302 adds a separately qualified authorization
path below. The fixed 8 KiB public PEM cap and connector-first
`profileTLS` rollout are engineering choices. The reference TLS CPU and wrong-peer
journey passed installed41916430295 at abf25590; authenticated endpoints remain
pending installed qualification. Old nodes can continue HTTP but cannot start TLS captures.


[ADR-302](../docs/decisions/302-named-profile-endpoint-authorization.md) keeps a
credential policy's public identity and exact workload-root audiences in the
protected named endpoint definition. The policy name is the endpoint name;
manual and recurring approval pin the same definition/audience digest, never a
header value or secret-payload digest. A fixed-purpose private file in the
existing immutable connector-only input bundle supplies the selected header at
final authenticated node-poll delivery after exact admitted-work and audience
checks. Preview and policy compilation never read it. Public queued work and
persistent state remain credential-free. The node must verify accepted TLS before
sending Authorization. Old nodes lacking explicit support refuse, and delivery
retains the existing 16-item/256 KiB bound using an ordered byte-bounded prefix.
An unavailable private value refuses only that original profile through the
existing zero-byte `ProfileUnavailable` result, with no acquisition or refund;
other original work and cancellations continue. Whole-request cancellation and
node process replacement still abort delivery. The reference authenticated TLS CPU/native/summary/Repeat and refusal journey
passed installed41926293863 at2bb27caf; other modes keep their separately
recorded qualification scope.

For Go, generate only the allowlisted `/debug/pprof/<type>` paths; CPU uses `/debug/pprof/profile`. Prefer binary `debug=0`; do not call `/cmdline` or remote `/symbol` as part of profiling. Missing/disabled endpoints yield `ProfileUnavailable`. After an admitted HTTP attempt, this is a terminal failed action with `reason_code: ProfileUnavailable`; a conflicting application-owned session similarly ends with `reason_code: ProfilerBusy`. Neither result publishes an artifact, retries acquisition or refunds the original admitted spend ([ADR-298](../docs/decisions/298-explicit-go-profile-refusals.md)). Asservat does not inject pprof into an existing binary or enable it through an unapproved application mutation.

### SC-PRF-001

Given a pod with pprof bound to its network namespace localhost, when a policy requests a CPU profile through an approved netns endpoint, then it records the pod endpoint response for the requested bounded interval, with verified or explicitly unknown serving-process attribution. Redirects to node metadata or a neighboring pod are rejected, and absence of pprof is reported explicitly. A maintainer can bind an already allowed template without an administrator creating a new per-app profile; an out-of-range port or credential audience mismatch is denied. For a Python pod with no pprof endpoint, an `ebpfSampler` CPU profile returns pprof samples only from that pod's processes, lists `python` among its detected runtimes and counts samples of a process whose pod membership could not be verified as unattributed instead of including them; no sample of a neighboring pod appears in the artifact, its metadata or the collector's logs.

## REQ-PRF-002 — Overhead and mutual exclusion

Live profiling MUST be classified as intrusive for approval/budget purposes even if the mechanism is an HTTP GET. Default CPU profile duration 10 seconds, maximum 60 seconds under the administrator ceiling; default trace duration 5 seconds, maximum 15 seconds. Default profile output cap 16 MiB, maximum 64 MiB; default trace output cap 32 MiB, maximum 128 MiB. Snapshot profiles have a 5-second default acquisition deadline. Action deadlines must include setup/shutdown margin beyond timed recording duration.

Do not force GC for a heap profile by default. `forceGC=true`, changes to sample rates, attachment of an external profiler, or starting high-frequency tracing require exact approved parameters. The bounded Go HTTP adapter supports forced GC only for heap snapshots: the standard handler processes `seconds` through its delta path before the GC branch, so `forceGC=true` combined with delta mode is unavailable and must be rejected during capability validation rather than silently ignored. [Go HTTP pprof implementation](https://go.dev/src/net/http/pprof/pprof.go). Block/mutex profiles that contain no data because sampling is disabled MUST be distinguished from a valid zero-contention result.

Only one Asservat CPU/trace recording in a conflicting runtime domain may run at once; the eBPF sampler is one domain per node, so at most one sampler session runs on a node. If the application already owns an incompatible profiling session, return `ProfilerBusy`; do not stop or overwrite it. Record actual start/stop, requested/observed sampling settings and cancellation outcome. HTTP cancellation does not prove the application stopped profiling, so an uncertain outcome is not automatically retried.

Finite manual profiles use the shared revision-bound `cancel_capture` lifecycle.
Current ordinary rights and the original accepted attempt remain required. A
queue acknowledgement does not establish `Cancelled`: the exact writer must
join node acquisition/upload and any in-flight managed storage before the joined
outcome is recorded. A stored completion wins a concurrent Stop. A known
pre-endpoint cancellation may report that no profiling started; an uncertain
application outcome MUST remain explicit in progress and must not authorize a
retry, replacement process, new acquisition interval or early reservation refund.

The shared [assessment](capture-assessment.md) considers runtime/options, sampling, current headroom and other profilers/recorders. Flag interference separately from exclusive-session admission. A Go heap pprof profile contains allocation samples rather than a complete object heap; show possible labels/paths and forced-GC effects without falsely presenting it as a full heap dump. Unqualified numeric overhead remains unknown.

### SC-PRF-002

Given an existing application CPU profiler, when Asservat requests a conflicting profile, then it returns `ProfilerBusy` without terminating that session. The same admitted capture remains terminally failed, exposes that reason in progress and publishes no artifact; the application owner can observe its original profiler still running. Given a missing or disabled reviewed endpoint, the action instead reports `ProfileUnavailable` without retrying or changing the target. A heap request leaves GC behavior unchanged unless its policy grant explicitly authorizes forcing GC. Given an eBPF sampler session already running on a node, a second `ebpfSampler` request for any pod on that node returns `ProfilerBusy`; a request on another node is unaffected.

## REQ-PRF-003 — Format, identity and pre-analysis

Preserve the original profile as raw evidence, with its true format (`pprof`, `go-trace`, `jfr`, `nettrace`, `speedscope`, `v8-cpuprofile` or qualified pack identifier). Profile manifests MUST record acquisition facts: profile type, requested duration, cumulative/delta/snapshot/interval mode, actual start/stop, source reference and endpoint digest, forced GC and target identity. Semantic facts (sample value types/units, sample period, drop/overflow counters, binary/symbol mappings) are established by the publisher's bounded verification of the native bytes and recomputed for each query; a producer that does not build the profile itself, such as a Go endpoint, does not parse the response and does not record them ([ADR-284](../docs/decisions/284-go-profile-native-types.md)). Go pprof is verified with `google/pprof` after a capped decompression (16 MiB) and Go execution traces (Go 1.22 and later) with `golang.org/x/exp/trace` within an event cap; a profile beyond these bounds is refused, never truncated. Go pprof verification additionally applies the fixed [allocation-shape limits](../docs/reviews/pprof-allocation-preflight.md) before the object parser: at most 100,000 samples, locations and functions each, 64 label records per sample, 300,000 string-table entries, 1,048,576 sample location references and inline lines each (4,096 per sample/location), 16 values per sample and 4,096 comment indices. A shared structural allowance additionally requires `2*samples + locations + functions + 8*labels <= 662144`; these empirical units are not a heap-memory guarantee. All limits apply together, so 100,000 samples is an upper ceiling rather than a promise for every combination of labels and stacks. The 16 sample-type and 4,096 mapping limits also apply before allocation. Unsupported shapes are refused at publication or analysis, never truncated; existing stored evidence and grants are not rewritten. An eBPF sampler profile also records its detected runtimes and unattributed samples; its native mappings carry build IDs, and frames it could not name stay unresolved rather than guessed. Missing values remain unknown.

Qualified bounded Go profile projections run in the regional acquisition worker under REQ-EVD-005 and [ADR-286](../docs/decisions/286-bounded-go-analyzer-isolation.md). Native tools and analyzers that execute evidence-supplied content retain the separate-Job boundary used for cores; choosing Go alone does not qualify a parser. Pprof uses a protobuf profile model with mappings, locations, functions, samples and labels; parse with maintained pprof tooling rather than an improvised format. Use exact local symbols; prohibit HTTP symbol lookup and analysis-time URL fetching. Produce deterministic extracts: total samples, flat/cumulative hotspots, bounded call-tree edges, allocation totals, blocking/lock wait summaries and symbol coverage. Runtime trace/JFR timelines have separate extract schemas; do not mislabel them as pprof. [pprof profile schema](https://github.com/google/pprof/blob/main/proto/profile.proto).

Arbitrary sample labels, comments, paths and thread/goroutine metadata may contain sensitive data. Apply label/field allowlists before extract classification. Retain transform/tool versions and raw provenance. Optional flamegraph views use sanitized locally rendered data with no executable content supplied by the profile.

### SC-PRF-003

Given a profile with multiple sample types, stripped mappings and secret-bearing labels, when pre-analysis runs, then it keeps units/types distinct, reports symbol gaps, removes unapproved labels from extracts and preserves the encrypted original.

## REQ-PRF-004 — Baselines and time correlation

Profiles MAY be captured periodically as low-frequency baselines through an explicit scheduled policy, or before/after an observed incident where time permits. They MUST NOT be presented as pre-trigger history unless recording already existed before the trigger. Existing JFR/runtime recording collection is a separate explicitly authorized operation and must not assume control of an application-owned recorder.

Cases link profile intervals to metric/log/probe intervals using target identity and source-clock uncertainty. A profile from a different process restart is labeled a different instance. Baseline retention consumes the same budgets and follows the same sharing/expiry rules as incident evidence. No continuous cluster-wide profiling backend is a hard dependency.

[ADR-297](../docs/decisions/297-verified-profile-acquisition-metadata.md) retains
collector-observed Go endpoint acquisition times only after complete native and
manifest verification, through existing verification audit/catalog metadata.
Display windows use explicit UTC microsecond precision; the sealed originals
remain unchanged. The window covers HTTP acquisition, not precise sampling or
cumulative counter history. Legacy windows and clock uncertainty remain unknown.
A preparation/queue/storage timestamp or workload-supplied pprof timestamp is
never substituted for a verified acquisition window. Pod identity does not
establish serving-process identity or restart continuity. Cases may show known
different Pods without claiming known different server processes. No additional
case-time artifact/key read or disclosure authority is introduced.

### SC-PRF-004

Given a trigger that starts a 10-second CPU recording, when the case timeline is built, then the profile is marked post-trigger. A baseline from the prior container restart remains separate and cannot be silently treated as the same process.

## REQ-PRF-005 — Bounded MCP profile queries and comparison

[ADR-291](../docs/decisions/291-bounded-profile-summary.md) separates the approved summary operation from raw input disclosure. A closed pprof summary requires current ordinary read rights, the original retained audience and client permission for extract/profile output; it does not confer native download or arbitrary raw query authority. The original input remains raw for processing and retention. Metadata-only shares do not authorize profile summaries; broader profile sharing remains pending.

`get_profile_summary` MUST provide selected sample type, units, duration, total, top-N flat/cumulative functions, and symbol/completeness warnings. `compare_profiles` MUST authorize both artifacts independently, require compatible profile/sample semantics or return a mismatch, and label raw deltas versus duration-normalized rates. Default top-N 20, maximum 100. Cursors, shares, grants, output ceilings and audit rules apply normally. Summary totals, flat and cumulative values retain their signs for delta profiles. The displayed fraction is flat divided by total only when all selected sample values are nonnegative and the total is positive; otherwise it is null, not a fabricated zero or an absolute-value normalization.

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

Both readers MUST retain independently current rights, original audience,
client, retention, recovery and permitted processing placement. Authenticate both
complete native files before a comparison or semantic-mismatch result. Neither
source's native size limit is enlarged by comparison. Bind both exact versions,
role order and normalization to one query. A repeated source still has two
independent key-use identities. The first implementation requires a common
qualified regional reader/store; wider placements remain unavailable until
qualified, without a plaintext hub proxy or invented credential union. Charge
both reads atomically and preserve uncertain spend. These clauses describe the
implementation contract, not completed public or installed qualification.

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

### Manual profile preview

History-backed single-profile repeat previews use a prospectively selected
eight-second composition inside the existing fifteen-second public request.
They retain initial recovery before the one readiness hint, then independently
read final exact-target and current facts after readiness; no old observation
is renewed. A fresh recovery proof must preserve the original installation,
issuer epoch and full revision. Original parent/token/policy/source expiry and
final current checks remain mandatory. This metadata composition neither
collects another profile nor obtains a new approval.


[ADR-285](../docs/decisions/285-profile-preview-plans.md) connects the passive
endpoint planner to manual preview through regional installation configuration.
The review freezes the public definition and endpoint digests without dialing
or reading credentials. `builtin/go-cpu/v1` selects a ten-second CPU interval;
custom profiles may use the supported Go modes or the eBPF CPU sampler. Plans
state raw native output and the required `liveProfile` approval reason. They
remain unavailable for submission until acquisition is implemented and qualified.

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

Policy profiles require independent raw `policyCollection`/`liveProfile`
approval and atomically spend the existing execution/native-output pools.
They do not acquire packet or syscall observation budgets. A collection grant
alone cannot authorize inspection/download of the result; current human raw
approval must independently cover the exact published artifact. All existing
finite Go mode limits and prerequisites apply. Runtime trace remains trace
format and cannot enter pprof analysis. This is an implementation contract;
installed policy-profile qualification remains pending.

A qualified manual Go endpoint acquisition is a distinct typed profile request,
never a packet recorder. Persist the reviewed composition, expanded endpoint
bindings, definition/endpoint digests, native byte ceiling and action timeout;
re-resolve the exact endpoint before starting without rewriting the reviewed
observation. `liveProfile` requires raw approval regardless of the installation's
optional all-recordings approval setting. Existing same-human result-access
children govern raw inspection/download; capture-time raw sharing stays refused
until its separate approval contract is implemented.

The persisted approval review and shared browser/MCP response carry the profile
runtime, type, mode, optional duration, timeout, forced-GC choice, native limit
and reviewed endpoint name, address mode, port, path policy and digest. The
console presents these parameters and the absence of pre-trigger history;
profile actions carry no fabricated packet window, filter or recording ring.
This summary does not replace the canonical execution scope or probe endpoints.

For native limits above 8 MiB, [ADR-290](../docs/decisions/290-one-shot-profile-streaming.md)
requires atomic final and temporary multipart reservations and a single durable
binding to the accepted connector process before storage. Its non-resumable
writer may keep transition bookkeeping locally, but never reconstruct or retry
an uncertain write or refund temporary charges before verified writer quiescence
and complete backend inventory cleanup. Cancellation/Stop, no replacement
profiling, protected publication and native download remain full workflow
acceptance requirements; component checks do not qualify them.

Fresh qualified capacity roots select the immutable `go-profile/v1` protocol
marker to fund the maximum native trace, one bounded additional response, and
multipart temporary obligations within the authored workload slice. Legacy roots
retain their original limits and charges; schema upgrade alone never enlarges
their grants or funding. See ADR-290 for exact window, key and retirement costs.
