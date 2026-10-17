# ADR-201 — eBPF CPU profiles for every runtime

Date: 2026-10-17. Status: accepted; design only, no adapter implemented.
Requirements: REQ-PRF-001/002/003; first-class runtime profiles (product decision).
Amends the capability catalogue in [profiles](../../specs/profiles.md).

## Context

Runtime profiles were planned as one adapter per runtime: Go pprof endpoints,
JFR or async-profiler for the JVM, EventPipe for .NET, py-spy for Python and V8
profiles for Node.js, each separately qualified. Most of these attach to or
modify the target process, need runtime-specific permissions, and multiply the
qualification work.

Grafana Alloy's `pyroscope.ebpf` profiles every process on a node from the
kernel, across interpreted and JIT runtimes, without loading anything into the
target. It uses the OpenTelemetry eBPF profiler
(`go.opentelemetry.io/ebpf-profiler`, contributed by Elastic; Alloy pins a
Grafana fork). Research, read 2026-10-17:

- **Coverage:** native code (`.eh_frame` unwinding, no frame pointers needed),
  Go (`.gopclntab`), HotSpot JDK 7+, Python 3.6–3.14, Node.js V8 8.1+,
  .NET 6–10, Ruby, PHP, Perl and BEAM, by reading runtime memory.
- **Licence and maintenance:** Go code Apache-2.0, embedded eBPF programs
  GPL-2.0; weekly tags, maintainers from Datadog, Elastic and Grafana. The
  public API is explicitly unstable.
- **Requirements:** kernel 5.10+ on amd64/arm64; BTF optional; capabilities of
  the BPF, PERFMON, SYS_PTRACE class, which the node collector already holds for
  packet and syscall capture.
- **Limits:** sampling is host-wide, and upstream has no PID or cgroup filter;
  native frames are left as file and offset unless symbolized; it records CPU
  only. No eBPF path sees JVM, .NET, V8 or Python heap allocations without the
  target's cooperation.
- **Upstream claim, not our measurement:** "1% CPU and 250MB memory are our
  upper limits in testing".

Sources: the [profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler),
[Alloy pyroscope.ebpf](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/),
[Alloy pyroscope.java](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.java/),
[JEP 451](https://openjdk.org/jeps/451).

## Decision

1. **CPU profiles for every runtime come from one eBPF sampler** in the node
   collector: the upstream OpenTelemetry eBPF profiler, pinned to a reviewed
   weekly tag and qualified per supported kernel. It needs no endpoint and
   attaches nothing to the target, so the workload keeps Pod Security
   `restricted` and needs no setup.
2. **Pod scope, as for syscall traces.** The evidence scope is the whole
   selected pod: no container selector and no host-wide fallback
   ([syscalls](../../specs/syscalls.md)). The kernel program samples host-wide
   during the bounded session only because the profiler has no cgroup filter.
   The collector attributes each sample by verified pod, cgroup, process-start
   and node-boot identity and fails closed: a sample whose membership is
   uncertain is dropped and counted as `unattributedSamples`. Samples of other
   processes are discarded in collector memory before encoding, encryption or
   output, are never written to disk, logs or metrics, and are not counted, so
   no other workload's CPU activity is disclosed. The collector suppresses its
   own core dumps. A cgroup filter contributed upstream would move this into the
   kernel; Asservat does not depend on a fork.
3. **Output is pprof** built by the collector's own reporter, with build IDs for
   native mappings, so developers can symbolize locally. Missing symbols are
   reported, as for cores.
4. **Contracts.** The `profile` action accepts source kind `ebpfSampler` with
   `runtime: any` and `type: cpu`, and names no endpoint profile. Profile
   metadata gains `runtime: any`, `detectedRuntimes` (including Ruby, PHP, Perl
   and BEAM) and an `ebpfSampler` acquisition with `unattributedSamples`
   ([action](../../specs/contracts/action.schema.json) and
   [profile](../../specs/contracts/profile.schema.json) schemas, example
   `examples/profile-metadata-ebpf.json`).
5. **Allocation, lock and heap profiles stay per runtime:** Go pprof endpoints
   (first production scope, unchanged) and JFR started through `jcmd` for the
   JVM. async-profiler, py-spy, Python `tracemalloc` and Node heap sampling
   modify or attach to the target; they are explicit opt-ins under REQ-PRF-002's
   approved external-profiler parameters, never defaults.
6. **Approval and limits are unchanged.** The eBPF session is live profiling,
   classified intrusive for approval and budget, with REQ-PRF-002's duration and
   output limits. Only one Asservat eBPF session runs per node at a time.

## Consequences

- One adapter replaces the per-runtime CPU adapters for Java, Python, Node.js,
  .NET, Ruby, PHP and native code; Go keeps its pprof endpoint path.
- Host-wide sampling during a session costs node CPU and briefly holds other
  pods' stacks in collector memory. Overhead must be measured in qualification;
  the upstream figure is not an Asservat claim.
- The binary embeds the GPL-2.0 eBPF objects; distribution must ship their
  licence and point to their source. The dependency is recorded in
  [technology](../technology.md) and [build or reuse](../architecture/build-or-reuse.md).
- The unstable API means pinned versions and an adapter test per upgrade.
- An ongoing (continuous) eBPF recorder is possible later but needs its own
  lifecycle and accounting under the action-lifecycle rules.

## Progress

- Decision recorded; no adapter, kernel qualification or overhead measurement yet.
