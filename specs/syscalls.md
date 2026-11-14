# Bounded syscall evidence

`syscallTrace` is a typed evidence action and a capture-profile building block. Inspektor Gadget traceloop is the selected engine; [research](../docs/research/capture-profile-feasibility.md) separates what upstream provides from the Asservat adapter. No overhead figure has been measured.

## REQ-SYS-001 — Pod-wide tracing with precise event semantics

Trace `allPodProcesses`: existing and new processes and threads of the selected authorized pod, including forks, execs and reloads while armed. There is no container selector or host-wide fallback. Verify pod/cgroup, namespace, process-start and node-boot identity before attributing an event. Exclude Asservat workers and the sandbox process. The eBPF tracked-thread map is sized to the pod cgroup's `pids.max` (the kernel thread limit), capped by the collector memory share; overflow or uncertain membership is a reported coverage gap, never wider scope.

`syscalls` is `{mode: all}` or an include list of names from the qualified ABI table; `result` is `all` or `errors`. Unknown names or missing ABI coverage fail visibly, not as an empty trace. Records carry process/thread identity, syscall name/number/ABI, entry/exit times, duration where paired, success/errno and non-pointer scalar results. Unfinished, unmatched, restarted and nonreturning calls are marked as such. Capture order is not a causal order across CPUs or nodes.

`metadata` mode reads no user memory: no argv, environment, paths, buffers, pointer return values or argument-derived predicates. The adapter enforces this at acquisition, not by later redaction. There is no ptrace/strace fallback or runtime injection; an unsupported node/ABI/mode disables the capability.

### SC-SYS-001

Given two workers fork and exec replacements during an armed trace, when events arrive, then only current pod members are attributed with distinct process/thread start identities. PID reuse, an exiting thread or a missing entry event cannot assign the call to a replacement process. Metadata mode never reads or persists a synthetic secret passed to write().

## REQ-SYS-002 — Finite rings, loss accounting and sensitive arguments

Parameters are `before`/`after`, a segmented ring ([REQ-NET-003](packets.md#req-net-003--bounded-segmented-rings-and-snapshots), whose memory formula also covers syscall rings), `maxEventsPerSecond`, `maxTrackedThreads`, `mode` and the syscall filter. The shipped ongoing metadata profile uses before 30 s, after 10 s, four 2 MiB segments, 10,000 events/s and one snapshot; these are the rate and ring bounds the maintainer keeps for recorders (ADR-335 D6/D8). A saved window copies the ring plus the `after` stream, bounded by the action's output limit; there is no lifetime event total. The `after` window may be as long as the capture's configured duration (ADR-335 D8). A manual capture records forward for its `duration` (default 60 s, administrator maximum 1 hour) at the same rate cap, streaming to storage up to the action's output limit (REQ-LIF-005). Administrators set the per-node event-rate ceiling (default derived from qualified collector throughput, portable 100,000 events/s) in Helm values; ring memory per node comes from the collector memory formula.

Kernel-side admission and bounded maps limit work before any user-memory read or formatting. The rate cap counts every eligible probe, including events later dropped by an `errors` filter. Output/ring capacity, lost perf/ring events, map overflow, truncated arguments, missed entry/exit, suppressed intervals and early stops are separate counters; unknown loss is reported as unknown, never zero. Under pressure the engine drops visibly; it never blocks workload syscalls waiting for upload. Circuit breakers react to kernel/ring overflow events, otherwise to the configured metrics source ([ADR-330](../docs/decisions/330-event-driven-system-design.md) D1).

`arguments` mode adds `maxBytesPerEvent` (at most 4 KiB: Linux `PATH_MAX` and the verifier-bounded `bpf_probe_read_user` scratch size) and `captureBuffers`. Reads follow the adapter's closed ABI allowlist; no arbitrary dereference, nested pointers or address-space dumps. Paths and argument strings are sensitive even with `captureBuffers: false`. No raw argument value enters control fields or audit. The reviewed observation budget the maintainer requires is the rate (`maxEventsPerSecond`), the per-event read bytes and, for a finite session, its duration; an expiring grant plus the ring bound a policy recorder (REQ-LIF-004, [ADR-335](../docs/decisions/335-usable-by-default.md) D6). There is no lifetime event total. Restarts never extend a session's end.

Argument mode needs approval: the policy's expiring grant for automatic recorders, the one individual approval for manual traces ([ADR-249](../docs/decisions/249-sensitive-acquisition-grants.md)). Metadata mode needs ordinary collection rights. No syscall evidence authorizes changing seccomp policy, sending signals or injecting calls.

### SC-SYS-002

Given a busy pod exceeds an event-rate or ring limit, when tracing continues to receive probes, then bounded admission drops visibly before extra sensitive reads. Another workload keeps its capacity. Argument collection cannot begin while approval is pending, and a finite argument session cannot extend itself by restarting. Filtering only errors still counts sensitive observations of eventual successes.

## REQ-SYS-003 — Evidence, projections and MCP

`syscallTrace` is the manifest kind and privacy evidence type; it defaults to potentially personal data. Provenance records engine/decoder/ABI digests, pod/process origins, windows, mode, filters, budgets and loss. Raw arguments are encrypted raw evidence.

- `get_extract(view=syscallSummary)` returns per-syscall counts, errors and duration aggregates over the whole recorded file, computed once per artifact version.
- `get_extract(view=syscallEvents)` returns a paginated metadata timeline with no argument option.
- `query_artifact(operation=syscalls)` ([ADR-306](../docs/decisions/306-bounded-saved-syscall-queries.md)) selects names/errors in a saved argument recording and returns whole recorded events with their arguments, under [REQ-MCP-003](mcp.md#req-mcp-003--typed-raw-operations). It never traces live, dereferences addresses or acquires.

All three run in the [regional reader](evidence.md#req-evd-005--analysis-isolation-and-output-classes) with the canonical native decoder and page under [REQ-MCP-002](mcp.md#req-mcp-002--bounded-result-contract). Pages read frames in order until full or until the per-request reader-time bound elapses; a page authenticates every frame it reads, and a frame that fails authentication releases no page. Native `decimal:`, `base64:` and `unavailable:fault` values are returned verbatim, so zero, empty bytes, read faults and truncation stay distinct. When the format does not establish loss or truncation, report null and a coverage gap; never infer complete observation from a quiet or filtered page. Metadata projections omit arguments, paths, pointers and buffers and grant no raw query or download.

Guidance may recommend a narrow include list for a goal. Names and recorded strings are untrusted data.

### SC-SYS-003

Given an argument trace with a synthetic credential buffer, when a reader asks for summary/events, then only the metadata projection is returned. A hostile argument string is never executed or fetched, and expired source evidence cannot be revived by a summary or history repeat.

Given that saved original and a covering `query_artifact(operation=syscalls)` authority, browser and MCP return matching recorded argument events. A download-only grant or a metadata source cannot supply them. A retry with the same key returns the original outcome without new charge. Zero, empty bytes, read faults and truncated values remain distinct; expired or revoked authority prevents delivery.

## Lifecycle, stop and live views

`syscallTrace` defaults to ongoing ([action lifecycles](action-lifecycle.md)): a policy arms the source and admitted triggers save bounded windows while it continues. Rate and thread limits apply even without triggers; ring eviction shortens history and is reported. Stop, expiry, loss and policy-generation changes produce source gaps. An onTrigger variant resolves `before` to 0s; manual ongoing requests are finite sessions of their `duration`.

Stop of a finite recording ([ADR-313](../docs/decisions/313-manual-recording-stop.md)) is an idempotent state change with one audit row that reaches the node as an event; the node stops and reports its final counts, which settle the reservation. A stored result wins over a concurrent Stop. Argument `ended_at` is the observation end, bounded by the kernel-enforced original deadline.

The argument engine is a narrowly patched, reproducibly built, digest-pinned traceloop program ([ADR-281](../docs/decisions/281-syscall-arguments-engine-limit.md)); the plan pins program, definition and accounting digests, and publication checks the JSONL against them.

[Live watch](live-watch.md) shows syscall/PID/error/duration metadata of a running source with typed display filters; no user memory, arguments or paths, and no change to what is observed.
