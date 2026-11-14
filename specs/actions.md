# Evidence actions and runtime recipes

## Catalogue and classification

Sensitivity and impact are independent. A read-only file can contain a credential; a small command can restart a service. `extract` means an approved deterministic projection, not public data. All newly collected bytes initially have class `raw` until a declared transformation qualifies an extract; metadata uses an explicit field allowlist.

| Action | Execution mode | Inputs and output | Impact / prerequisites |
| --- | --- | --- | --- |
| `kubernetesSnapshot` | On trigger | Redacted Pod/workload spec/status, Events, EndpointSlices and rollout lineage | Low; excludes Secret bodies and unapproved env/annotation values |
| `logs` | On trigger | Time window, streams, before/after context; bounded text/JSON | Low I/O; raw until projected/redacted |
| `processSnapshot` | On trigger | PID tree, thread states, limits, maps, status, cgroups, FD metadata | Low/moderate; paths, command lines and FD targets can be sensitive |
| `fileRead` | On trigger | Exact container-root or target `/proc` path; bounded bytes | Sensitive read; pseudo files may block or have side effects |
| `packetCapture` | Ongoing; save on trigger | Target netns, pcap filter, dynamic Kubernetes peers, bounded segmented rings and network/HTTP/raw profiles | Network observation; default sanitized network headers; HTTP inspection and raw payload need sensitive grants |
| `syscallTrace` | Ongoing; save on trigger | All pod processes/threads, syscall names/results, bounded windows/rings/events | Metadata without user-memory reads; argument/buffer mode requires sensitive-observation approval; [contract](syscalls.md) |
| `networkSnapshot` | On trigger | Routes, addresses, socket counters, conntrack context if scoped | Low/moderate; host-wide conntrack is not a default workload action |
| `runtimeDiagnostic` | On trigger | Typed runtime operation: stack/report/profile/heap/core | Capability and version specific; can pause or allocate substantial memory |
| `kernelCore` | On trigger (natural crash) | Kernel-delivered crash stream | Post-crash; opt-in, local interception and byte/time budgets |
| `liveCore` | On trigger | Bound process + explicit dump recipe | Intrusive; ptrace/stop duration; approval required |
| `command` | On trigger | Absolute executable/argv, pod-resolved runtime roots, working directory, limits | Treat as mutating/credential-bearing; approval required; no default shell |
| `httpDiagnostic` | On trigger | Named preconfigured endpoint, method GET, response bound | May expose pprof/metrics; SSRF-safe endpoint policy, no arbitrary URL |
| `artifactCollect` | On trigger | Runtime-produced report/core path, readiness condition | Exact allowed path; incomplete files distinguished |
| `profile` | On trigger | Go pprof CPU/heap/allocs/goroutine/block/mutex, runtime traces, JFR/EventPipe, qualified sampled profiles and the node collector's eBPF CPU sampler for any runtime ([ADR-201](../docs/decisions/201-ebpf-cpu-profiles.md)) | Named endpoint or sampler, rate/overhead budget. A pprof GET that changes no runtime setting is `observe`; forced GC, sampling changes, traces and attaching profilers are intrusive; details in [profiles](profiles.md) |

[Action lifecycles](action-lifecycle.md) define arming, incident saves, manual sessions and the explicit post-trigger-only variants. Mode is independent of sensitivity; an ongoing recorder needs authority and capacity before its first observation.

[Capture assessment](capture-assessment.md) evaluates the selected mechanisms together. The catalogue descriptions are initial mechanism guidance; neither an observe authorization class nor a small output cap predicts production overhead. Warn about application/kernel work outside collector resource limits and about possible sensitive contents before execution.

## REQ-ACT-001 — Execution plans and partial results

[Capture profiles](capture-profiles.md) compile versioned reusable building blocks into this same recipe model; there is no separate executor or approval path.

A recipe resolves into source arming plus an incident graph. Ongoing sources have no dependsOn edges; incoming dependencies from onTrigger actions wait for their incident snapshots. A recipe MUST be an acyclic graph of typed actions (no count cap; capacity admission bounds their cost) with explicit IDs, dependencies and required/optional flags. Byte limits and timeouts default from the tables below. Impact is derived from the action kind and its parameters; an authored `impact` may only raise it, never lower it. Defaults run independent snapshots in parallel, then costly diagnostics; two actions that pause the same process MUST serialize. Never delay all light evidence waiting for a heap dump. Before expensive acquisition, reserve the resources and storage defined in [capacity](capacity.md); grants alone cannot authorize work that lacks safe capacity.

Every action MUST end in `Succeeded`, `Partial`, `Skipped`, `Denied`, `TimedOut`, `Failed`, `TargetGone`, `Unsupported` or `Indeterminate`, with reason and timing. Failed optional actions do not discard successful artifacts. A capture MUST distinguish a partial action set from fully successful collection. An intrusive action with unknown execution outcome MUST NOT be retried automatically.

### Finite logs implementation contract (ADR-308)

[ADR-308](../docs/decisions/308-finite-whole-pod-logs.md) defines finite whole-pod
API logs, raw saved `get_extract(view=logs)` pages and native JSONL. Current/available previous
regular/init/ephemeral sources share aggregate action limits. Portable stream
provenance is combined; exact stdout/stderr selection is Unsupported without
qualified split capability. Preserve original bytes, nullable source timestamps,
empty lines and explicit coverage gaps; API history is not a complete log archive.
The action's byte cap includes encoding/framing. Saved pages require current
read/raw/client rights and exact query approval, independently of native download.
No generic text redaction or per-container permission surface is introduced.
The count-only log detector does not fulfill this action.

### SC-ACT-001

Given a recipe with logs, `/proc` and a heap dump, when the heap dump times out, then logs and `/proc` are retained, the case reports partial evidence and the dump is not described as complete or retried automatically.

## REQ-ACT-002 — File access and pseudo files

`fileRead` MUST distinguish `podRoots`, `targetProc`, and `runtimeOutput`. For container files, use an opened target root descriptor and kernel-enforced beneath/in-root resolution; reject path traversal and magic-link escape. For `targetProc`, map logical `/proc/self/...` to the selected target process, and validate any explicit PID against the approved process scope. The manifest records logical path, resolved process identity, timestamps, byte count, truncation and errno.

Default allowlist includes status/stat/limits/maps/smaps_rollup/cgroup and selected net counters. `/proc/*/mem`, `environ`, application configuration and credential locations require an explicit sensitive-file grant/approved policy. Device files, FIFOs, sockets, debugfs, sysrq, `/dev/kmsg`, arbitrary host paths and recursive directory reads are denied by default. Ordinary symlinks may resolve only within the pinned container root; proc magic links need a dedicated reviewed adapter, never generic following. An approved custom command is the explicit escape hatch for exceptional application-specific reads, with its stronger impact classification.

Pseudo files can report zero length or block: enforce byte and wall-clock limits independently of stat size. Use a killable worker; the worker count is derived from the collector's CPU/thread budget, because a worker stuck in uninterruptible kernel I/O keeps its thread; cancellation cannot guarantee immediate termination of uninterruptible kernel I/O. Report lingering workers and stop scheduling new ones. Do not assert atomic snapshots of live files.

### SC-ACT-002

Given a workload that swaps a requested symlink to `/proc/1/root/etc/shadow`, when the collector opens the path, then confinement rejects the escape. Given a zero-size pseudo file with content, bounded reading still collects it; an endless/blocking source cannot exhaust collector workers.

## REQ-ACT-003 — Custom commands

Custom commands MUST use an absolute executable and argv array; no shell interpolation, template expression execution or inherited collector environment. A command grant binds argv/recipe digest, target, working directory, allowed environment names, deadline, output cap and execution count. Sensitive environment values are references, never recorded in CRDs or audit arguments.

Prefer Kubernetes `pods/exec` for binaries already present in the target container, preserving runtime cgroup/UID behavior. A reviewed node runtime adapter can supply a tool where necessary, but MUST explicitly establish target namespaces, credentials, capabilities, seccomp, cgroup placement, FD closure and filesystem view. `setns` alone is not adequate confinement. Never run arbitrary user commands with the node collector's root/host identity. Distroless workloads may report `ExecutableUnavailable`.

Capture stdout/stderr independently through bounded evidence pipes, never ordinary service logs or termination messages (REQ-EVD-008); store exit status and cancellation outcome, and kill only the created execution/process group where supported. Do not promise rollback of application side effects or cancellation of all descendants. Built-in diagnostic recipes are preferred; free custom commands remain a high-impact feature.

### SC-ACT-003

Given argv containing `$(...)`, semicolons or backticks, when the command executes, then those bytes are ordinary arguments. An approved command cannot inherit host storage credentials or run with collector capabilities. An ambiguous timeout records `Indeterminate`, not safe-to-retry.

## REQ-ACT-004 — Packet rings and payload policy

Inspektor Gadget MUST be invoked through a private authenticated integration with pinned allowed gadget digests and target filters fixed by the compiled plan. Packet bytes MUST reach a node-local sanitizer/encryption path before leaving the node; the hub/controller MUST NOT relay plaintext packet streams. Qualify this integration before selecting a remote API path that could transmit raw packets.

The default `networkHeaders` profile MUST parse and retain only approved L2/L3/L4 headers. Fixed snaplen does not establish that property. Limit parser depth/extension chains; drop unsupported or ambiguous packets and count them. Preserve original/captured lengths and indicate omitted payload. A raw bounded packet may exist transiently inside the trusted capture process, but MUST NOT enter the retained ring, logs or uploads in networkHeaders mode.

Rings default to 30 seconds and 16 MiB per target, bounded by the node's collector memory as defined in [packet capture](packets.md#req-net-003--bounded-segmented-rings-and-snapshots). They stay in locked collector memory, never on disk. A saved window is encrypted as it leaves memory ([action lifecycles](action-lifecycle.md)). Record actual oldest/newest timestamps, dropped packets and gaps; a full byte cap means less than 30 seconds of coverage.

Payload captures require an appropriate grant before the ring is armed, including pre-trigger time. A later grant cannot retroactively authorize a raw ring. TLS plaintext collection/key logging is a separate optional grant and runtime-specific capability. Application TLS remains encrypted in ordinary pcap. Network-header-only inputs cannot yield HTTP bodies or complete Zeek application logs. The distinct httpHeaders profile retains approved structured plain HTTP/1 fields through bounded reassembly. Filter syntax, live Service/workload peers, segment sizing, protocol limits and MCP behavior are normative in [packet capture](packets.md).

### SC-ACT-004

Given IPv4/IPv6 packets with short headers and secret payloads, when networkHeaders captures them, then the retained artifact contains none of the payload markers. Unknown encapsulations are dropped with counters. A trigger without an armed ring reports no pre-trigger coverage.

## REQ-ACT-005 — Core collection and size behavior

The core helper MUST enforce opt-in/deny checks, process-identity checks, a nonzero `core_pipe_limit`, elapsed time and input byte limits. Before declaring interception ready, the node collector holds a cached data key, rotated with its connector certificate ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D3) and used for fewer than 2^32 AES-GCM encryptions (NIST SP 800-38D), and a local token bucket that applies the workload rate limit on the crash path. Admission takes one token locally; the pipe helper never waits on the hub. An expired key or empty bucket refuses promptly. The core is registered and audited once at upload under its crash ID; after a collector restart the hub reconciles by crash ID, so a core is never charged twice. Without immediate capacity, reject the natural core stream promptly rather than queueing the crashed process or draining it for a signature. A stopped stream MUST be marked `truncated` and `analyzable: unknown/false` until tested; a prefix of an ELF core is not a valid complete core. No promise of a core after SIGKILL/OOM.

Use initial-namespace kernel identity (`%P`, not a namespace-local `%p` alone) and revalidate process start/boot/target binding locally. Bound socket connection, admission acknowledgement, input reads, writes and final acknowledgement under one absolute monotonic deadline; per-chunk timeout renewal is insufficient. A full local listen queue must refuse or wait only within that bound. Entry into the qualified helper resource boundary is a readiness prerequisite; a collector cgroup alone does not constrain a kernel-launched helper or kernel dumping work. Enforce the helper's input ceiling independently of RLIMIT_CORE, which does not cap pipe delivery.

The local protocol must distinguish accepted handoff from completed evidence. Require explicit successful end-of-input/finalization; EOF, process exit or an initial admission report alone cannot certify a complete core. Preserve partial/indeterminate outcomes with actual received bytes and bounded reasons for cap, timeout or lost receiver. A token taken for a core whose stream terminated uncertainly stays charged until the crash ID's outcome is known. Runtime-pack analysis must still establish whether an incomplete artifact is usable.

`liveCore` requires a grant and MUST record observed stop/resume timing where measurable, watchdog outcome, target health observations and whether normal execution resumed. Never rewrite target probes automatically. First-party default policies do not send fatal signals to healthy processes.

### SC-ACT-005

Given a core larger than the configured input cap or a stalled upload, when the deadline is reached, then the helper exits within the qualified shutdown budget, the artifact is partial or aborted, and the workload's reaping is not held indefinitely. An OOMKill yields context with `NoKernelCore`, not an empty "successful core".

## REQ-ACT-006 — Runtime pack qualification

Each runtime pack MUST declare supported runtime versions/architectures, preparation, executables and licences, process impact, scratch behavior, sensitive output fields and analysis limitations. Store actual binary/tool/image digests. `py-spy`/thread dumps are not cores; GPU dumps, JVM heaps, .NET dumps and ELF cores have distinct media/format identifiers. Tools needing seekable output require capped tmpfs or encrypted scratch; no unbounded plaintext node files.

### SC-ACT-006

Given an unsupported .NET diagnostic port, missing Java attach tools, stripped binary or unavailable GPU driver, when the recipe runs, then it reports the specific missing capability while preserving other evidence. It never installs tools from the internet into the workload.

## Proposed default ceilings

Defaults are starting points to validate, not benchmark results. There is no built-in maximum on these values: capacity admission and the per-workload storage share bound stored bytes ([ADR-335](../docs/decisions/335-usable-by-default.md) D2), and an approved grant binds its own deadline and output cap. Administrators may set ceilings as Helm values that apply on `helm upgrade`; they override user values, and users cannot raise ceilings through a grant request alone. Every read or write that makes no progress for 5 s fails (the I/O timeout of [ADR-330](../docs/decisions/330-event-driven-system-design.md) D5); total time follows from bytes ÷ the node profile's qualified throughput.

| Evidence | Default cap (reason) | Time bound |
| --- | --- | --- |
| One file | 1 MiB (`/proc` and configuration files fit; stored bytes) | I/O timeout; bytes ÷ throughput |
| Log window | Kubelet `containerLogMaxSize` (default 10 MiB) per current and previous log of each container, the most the kubelet logs API returns | I/O timeout; bytes ÷ throughput |
| Process/network metadata | 4 MiB (stored bytes) | I/O timeout |
| Custom stdout + stderr | 4 MiB combined (stored bytes) | The approved grant's deadline |
| Packet recording | 256 MiB (stored bytes); policy window 30 s before + 30 s after; manual `duration` 60 s | Window or duration + finalization margin (upload bytes ÷ qualified upload throughput + I/O timeout); payload explicitly granted |
| Syscall recording | 64 MiB (stored bytes); policy window 30 s before + 10 s after; manual `duration` 60 s | As packet recording |
| Native/Rust/Go core | Target container memory limit plus ELF overhead (a core cannot exceed the process's resident address space) | Input cap ÷ qualified local encrypt/spool throughput (the crashed process is not reaped while its pipe is open) |
| .NET heap/native dump | As native core | As native core |
| JVM/Node heap snapshot | Disabled in default recipes; when enabled, the heap within the container memory limit, admitted only under the memory-headroom gate | Bytes ÷ qualified throughput |
| Python core | As native core | As native core |
| GPU dump, or a core larger than the node-local spool/memory budget | Disabled | Dedicated node-pool profile; qualification experiment required |

A manual recording `duration` is always finite (maintainer decision); the administrator manual-duration maximum defaults to 1 hour and is configurable. A post-trigger window may extend up to the capture's configured duration (ADR-335 D8), with no separate maximum. These limits sacrifice completeness before sacrificing a node. Runtime class names are operator-defined evidence profiles, not automatically Kubernetes `RuntimeClass` names. Aggregate recipe, node, workload and installation-wide quotas also apply. These byte/time bounds do not promise a complete dump: a bandwidth/CPU profile that cannot fit them must report an infeasible plan, require an explicit adjustment or use already reserved encrypted staging under the same process-stop deadline. See [capacity admission](capacity.md).

## REQ-ACT-007 — Pod fanout, process selection and artifact readiness

Resolve process-bearing actions inside the authorized pod, without a container selector. podMainProcesses means runtime-identified initial processes of all currently available pod containers, excluding the sandbox and known Asservat-created diagnostic workers; allPodProcesses additionally includes qualified descendants; pod membership and the pod's `pids.max` cgroup limit bound enumeration. Resolve host PID, start time and cgroup identity through CRI/kernel adapters, never assume namespace PID 1 is the application. A liveCore selectedPID action is an advanced ad hoc process choice: require podUID, nodeBootID, hostPID and startTimeTicks in processIdentity. The UI fills this from an authorized process listing; a bare PID is invalid. Reject selectedPID in recurring recipes at policy acceptance. No process may escape pod membership or be substituted after restart.

One fileRead path is applied to each available pod root or selected process, preserving separate origins. Missing files are explicit per-source outcomes; do not merge same-path contents across containers. Commands resolve the exact executable in each eligible runtime root without executing it during preview; show fanout and require approval for every possible start. Runtime-specific operations apply only where the qualified pack proves compatibility and record other sources as Unsupported. New runtime members at dispatch must fit the approved template, image constraints, count/byte/start budgets; otherwise skip/replan, never implicitly multiply authority. REQ-TGT-006 defines aggregate bounds.

artifactCollect uses confined pinned descriptors and bounded waiting. settleFor only means size/mtime were unchanged, not completeness. Record inode/file generation, before/after stat and readiness basis; require a qualified format parser or trusted producer completion marker before claiming Complete. A file replaced, still growing, or left by a prior process is partial/unattributed until proved otherwise. Never delete application-owned output files as implicit cleanup. httpDiagnostic restricts path/method to its resolved endpoint profile; absolute URLs, query/fragment overrides, redirects and path escapes cannot bypass it.

Per-action WaitingApproval is distinct from Queued/Running. Independently authorized context starts promptly and is not repeated when approval arrives. A pending approval stays decidable until the request changes or is cancelled, or until an optional requester-set `notAfter` (ADR-335 D9: human waits are minutes to days); when `notAfter` passes undecided, unstarted work becomes Skipped with ApprovalDeadlineExpired; keep useful results and explain Partial. An approved action's own deadline starts at approval. No silent retarget, deadline extension or Retry for an uncertain start. An explicit new request is required if the incident/process is no longer current.

### SC-ACT-007

Given a shared-process pod and an ad hoc worker dump, when only a PID is supplied or that process restarts, then admission/execution refuses the ambiguous target. Given slow approval and useful logs, the logs remain visible while the dump waits and after its requester-set `notAfter` passes undecided. A stable-size half-written runtime file is not labeled complete.

## REQ-ACT-008 — Reload-safe process selectors and multi-process dumps

Live dumps support three modes within the authorized pod: podMainProcesses (runtime-discovered main processes), selectedPID (one exact process identity), and matchedProcesses (logical selector resolved at dispatch). A logical selector ANDs supplied executablePath, executableName, runtime and buildIDs; buildIDs is a bounded OR set. executableName means the basename of the verified executable path, not a truncated process display name. Paths/names are exact, not shell globs; runtime identification must be qualified, not guessed from a display name. At least one predicate is required. This is a process selector, not a container selector or additional permission boundary. No argv/environment regex or arbitrary discovery command is introduced.

includeDescendants adds verified descendants of each matching root, only within the same pod's proven runtime membership. Deduplicate overlapping roots/descendants by full process identity. A parent that disappeared before ancestry was observed is not reconstructed by matching a reused PID; report ancestry uncertainty. Renamed executables, deleted mappings or unavailable runtime identity produce explicit match/coverage limitations. Preview shows current match count and the allowed future selector, so an approver sees whether approval pins today's process or permits the matching replacement after reload.

For matchedProcesses, the grant binds the selector, pod/workload scope, image/build constraints and finite batch limits. A manual request pins pod UIDs but may resolve fresh matching processes before its first dispatch within the original deadline; an automatic policy resolves each new occurrence similarly. Freeze the bounded process set in one accepted episode record before reservations/starts, record its enumeration interval (not an atomic operating-system snapshot), then bind each child attempt to node boot, pod UID, runtime identity, host PID and start time. Before every attach the collector checks that identity locally, without a hub round trip; authorization is the operation's single decision (REQ-EXE-002). Reload before resolution can select the new PID. Exit/reload after resolution yields TargetGone/Partial for that child; it does not add a replacement to the running batch or retry an uncertain dump. A later fresh occurrence/request can resolve again under unchanged budgets.

batch declares maxProcesses, maxBytesPerProcess, maxStopPerProcess, maxTotalStop and consistency: sequential. These bound the target's pause time and stored bytes; there is no separate built-in process-count maximum. Omitted batch for podMainProcesses covers every resolved main process of the Pod, sidecars included, bounded by the aggregate byte cap and maxTotalStop; selectedPID resolves to one. If a resolved set exceeds the bound, reject the expensive batch with TooManyProcesses before stopping any process; never choose arbitrary workers silently. Show a suggested narrower process selector or a reviewed larger profile. An empty set returns NoMatchingProcess, with no dummy successful artifact.

Reserve the batch's starts, bytes and stop budget before the first attach; maxBytesPerProcess × maxProcesses must fit the action cap. The whole batch is one occurrence under the workload rate limit (REQ-TRG-004); its contents are bounded by the batch limits, with no further per-start or rolling counters. A start with an unknown outcome stays charged until its outcome is known (ADR-330 D7). Processes are dumped one at a time, each released before the next; the batch stops before maxTotalStop or the action deadline, keeping completed dumps. Sequential dumps are not a simultaneous snapshot.

### SC-ACT-008

Given /app/bin/worker reloads from PID 420 to 621 before dispatch, when a selector-based request is still authorized and fresh, then 621 is resolved and pinned. Given two matching workers within approved batch limits, each receives its own attributed dump under one aggregate budget. A third match causes pre-start rejection at maxProcesses: 2; PID reuse after resolution never redirects an existing attempt. Sequential dumps record distinct times and do not claim a simultaneous snapshot.

## Discovery identity projections

The `processSnapshot.include: identity` option supplies qualified executable/runtime/build, parent and start identity for [guided process selection](guidance.md). The `networkSnapshot.include: socketOwners` option requests qualified process/socket associations. Both remain pod-scoped and bounded; neither permits argv/environment, command execution, memory reads or attaching a debugger. Unsupported or racing fields remain explicit gaps. A runtime classification must not execute an application binary to identify it. New options are part of the existing action schema, not a new permission or container selector.

The three discovery recipes use these existing actions and packet profiles. Accepted analysis plans bind immutable classifier/projection digests; fixed protocol projections require no arbitrary user raw-query grant, while sensitive acquisition still requires its reviewed observation grant. No additional live TCP tracer is silently started by `socketOwners`; connection-event enrichment requires a separately qualified bounded adapter included in the reviewed recipe/profile.
