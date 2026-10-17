# eBPF CPU profiler research

Research for [ADR-201](../decisions/201-ebpf-cpu-profiles.md), read 2026-10-17.
These are upstream facts and claims, not Asservat measurements. Items marked
*unverified* were not checked against a primary source.

## How Grafana Alloy profiles non-Go runtimes

| Component | Mechanism | Needs | Touches the target |
| --- | --- | --- | --- |
| `pyroscope.ebpf` | Whole-host eBPF stack sampling, 19 Hz default; optional off-CPU and probe-point stacks | Root in the host PID namespace, or capabilities BPF, PERFMON, SYS_PTRACE, CHECKPOINT_RESTORE (kernel 5.9+, else SYS_ADMIN), SYS_RESOURCE, DAC_READ_SEARCH, SYSLOG; read-only tracefs; a writable symbol cache | No |
| `pyroscope.java` | async-profiler copied into the target through `/proc/<pid>/root` and started with `asprof` over the HotSpot attach socket | Root, host PID namespace, PERFMON, SYS_PTRACE, SYS_RESOURCE, SYS_ADMIN; target allows attach and an executable temp mount | Yes: loads a native agent |
| `pyroscope.scrape` | Pulls pprof HTTP endpoints | None | No |

Sources: [pyroscope.ebpf](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/),
[pyroscope.java](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.java/),
[pyroscope.scrape](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.scrape/),
[async-profiler in containers](https://github.com/async-profiler/async-profiler/blob/master/docs/ProfilingInContainer.md).
JDK 21+ warns when a native agent is loaded into a running JVM and a future JDK
will block it by default; jcmd and JFR are unaffected
([JEP 451](https://openjdk.org/jeps/451)).

## The library

Alloy's `go.mod` replaces `go.opentelemetry.io/ebpf-profiler` with a Grafana
fork (`github.com/grafana/opentelemetry-ebpf-profiler`). Grafana's own eBPF
module was removed from the AGPL-3.0 Pyroscope repository in
[PR #4324](https://github.com/grafana/pyroscope/pull/4324).

Upstream [OpenTelemetry eBPF profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler):

- **Licence:** Go code Apache-2.0; eBPF C programs GPL-2.0, committed in
  compiled form and embedded with `go:embed`.
- **Maintenance:** weekly tags `v0.0.YYYYWW`; maintainers from Datadog and
  Elastic, with Grafana as approver.
- **Stability:** VERSIONING.md says the public API should not be considered
  stable; the controller is under `internal/`.
- **Runtimes:** native code via `.eh_frame` (no frame pointers needed), Go via
  `.gopclntab`, HotSpot JDK 7+, Python 3.6–3.14, Node.js V8 8.1+, .NET 6–10,
  Ruby 2.5–4.0, PHP 7.3–8.5, Perl 5.28–5.42, BEAM OTP 27–28. Version ranges come
  from the fork's version checks and may differ slightly upstream.
- **Kernel:** 5.10+ on amd64 and arm64; BTF optional.
- **Scope:** no PID or cgroup filter upstream; sampling is host-wide. The fork
  skips non-target processes by container ID, but perf sampling stays
  host-wide (inferred from the code).
- **Output:** OTLP Profiles (alpha); Alloy builds pprof directly with
  `github.com/google/pprof/profile` in its own reporter. Native frames are left
  as file and offset unless symbolized on the node.
- **Overhead claim:** "1% CPU and 250MB memory are our upper limits in
  testing" (README). Not an Asservat measurement.

## Allocation profiles

No usable eBPF path sees JVM, .NET, V8 or Python heap allocations without the
target's cooperation. Upstream memory profiling (PRs #1744–#1747) records
probe points that the allocator itself must emit. Remaining options are
per runtime: Go pprof `allocs`/`heap`, JVM JFR started through `jcmd`, .NET
EventPipe allocation events (*unverified*), and Python `tracemalloc` or Node
inspector heap sampling, which modify the target (*unverified*).
