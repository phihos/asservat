# Design

## Overview

Asservat records evidence from workloads in many Kubernetes clusters so that
developers can debug problems that do not reproduce in a lab. This document is
the whole specification: what the system guarantees, how its parts work and
what is deliberately left out. Change it together with the code.

## Components

| Component | Runs as | Does |
| --- | --- | --- |
| Hub | One Deployment in one cluster | Authenticates users, records requests and approvals, pushes work to agents, encrypts and stores evidence, opens files for their viewers, serves console, REST API and MCP |
| Node agent | DaemonSet in every cluster (host PID namespace, `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`, `SYS_RESOURCE`, `SYSLOG`, `SETUID`, `SETGID`) | Holds one outbound stream to the hub, records evidence from the pods of its node, answers the hub's questions about its cluster |
| PostgreSQL | Bundled or external | Captures, tasks, watches, artifact index, audit log |
| Evidence store | Volume or S3 bucket | Encrypted artifact bytes |

Both components are the same binary (`asservat hub`, `asservat agent`). The
agent's image, which every node pulls, is the hub's without the viewers'
tools (Wireshark's sharkd, graphviz, Go's trace tool) and without those
that read the stacks of Python and .NET programs from a core (pystack and
dotnet-dump, each with a runtime of its own): the same tag with
`-agent`. The published images' layers are compressed with zstd, which
containerd, CRI-O and Docker from version 23 read. They are published for
amd64 and arm64: each architecture's images are built on a machine of that
architecture and pushed under the tag with `-amd64` or `-arm64` at its
end, and the tags without it are lists that point to both, so that a node
pulls its own.

## Capture lifecycle

1. A user requests a capture: cluster, namespace, workload and one or more
   **recordings**, each an evidence kind with its parameters.
2. The hub checks the permission and asks an agent of the cluster for the
   workload's running pods. Each pod becomes a **task** for the agent on the
   pod's node.
3. A capture with a sensitive recording waits in `PendingApproval` until an
   administrator approves or denies it, as a whole. Any other capture is
   `Queued` at once.
4. The hub pushes each task over the node agent's stream. Every stream starts
   with the node's open tasks: the agent starts those it missed, stops those
   that were cancelled or deleted meanwhile, and reports a task as failed
   that was running when the agent restarted.
5. The agent makes all recordings of the pod at once, streams the files to
   the hub and reports the task as `Completed` or `Failed`. A task is
   `Completed` if at least one recording succeeded and names those that
   failed. The capture is `Completed` if at least one pod succeeded; its
   message then tells how many pods and how many recordings failed, and the
   console shows it in the list.
6. The requester or an administrator downloads the files. When the retention
   ends the hub deletes the capture and its files.

While a capture runs, the agent reports how each recording of each pod gets
on (waiting, running, completed, failed), and the hub says how much of the
time frame is left. Files appear as their recordings end.

A running capture can be **stopped**: the recordings that run over time end
at once and keep what they have, and the capture completes. A profile that
runs over time cannot be cut short and is abandoned, except a JVM's flight
recording, which keeps what it has. A capture can also be
cancelled while it waits or runs, which abandons the recordings in progress,
and deleted at any time.

The recordings of a capture share everything but their kind and parameters:

- the same pods and the same start;
- one time frame, `durationSeconds`, for those that run over time (`pcap`,
  `strace`, `pprof` and followed `logs`); it defaults to 30 seconds if one
  of the first three is requested;
- one approval, needed if any recording is sensitive, before which none of
  them starts;
- one trigger, when they belong to a watch.

A capture holds at most one recording of each kind, because two would write
the same files. A core dump and a system call trace both attach to the
process, which only one can do at a time: the trace starts when the core is
written. A request with a single `kind` and `params` is the short form of
one recording.

## Watches

A watch is a standing capture request for problems nobody is present for:
whenever a pod of the workload meets the watch's condition, the capture is
made for that pod.

| Condition (`when.kind`) | Met when | The capture finds |
| --- | --- | --- |
| `crash` (the default) | A container terminates with an exit code other than zero, which includes being killed for exceeding its memory limit | What the crashed container left behind, see below |
| `restart` | A container is started again, whatever ended it: a failure, a clean exit, a failed liveness probe | The pod as it runs again |
| `not-ready` | The pod was ready and no longer is: its readiness probe fails | The pod in that state |
| `log` | A container writes a log line that the regular expression `pattern` matches; `container` limits it to one container | The pod from that moment |
| `memory` | A container's memory use is above `above`: a share of its limit (`80%`) or a size (`500Mi`) | The container before the kernel ends it |
| `cpu` | A container's CPU use is above `above`: a number of CPUs (`1.5`) or a share of its limit (`90%`) | The container while it is busy |
| `throttled` | A container is held back by its CPU limit in more than `above` (`25%`) of the time | The container while it wants more CPU than it gets |
| `memory-growth` | A container's memory grows by more than `above` (`100Mi`) within `seconds` | A leak while it grows |
| `pressure` | A container stalls for `of` (`memory`, `cpu` or `io`) in more than `above` (`20%`) of the time | The container while it waits for the resource |
| `threads` | A container has more than `above` threads and processes | The container with its threads |
| `open-files` | A container's processes hold more than `above` files open | The container with its open files |
| `tcp-retransmits` | The pod sends more than `above` TCP segments per second again | The pod while packets are lost |
| `tcp-failures` | More than `above` of the pod's TCP connection attempts per second fail | The pod while it cannot connect |
| `event` | Kubernetes warns about the pod with an event of type `Warning`: of `reason` (`Unhealthy`, `BackOff`, `FailedMount`), or of any | The pod while Kubernetes has trouble with it |
| `time` | The time `at` comes, and with `every` again after each so many seconds | All pods of the workload at that time |
| `alert` | The Prometheus alert `name` fires, as Alertmanager tells the hub | The pod that the alert names, or all pods of the workload, while the alert fires |

1. A user creates a watch: a capture request, with one or more recordings,
   a condition, and the number of times to record (default 1). The
   permission is the same as for a capture. A watch
   for evidence that needs approval waits until an administrator approves
   it, by the same rules as a capture. The approval precedes the event, so
   it covers the captures that the watch creates.
2. The hub sends the cluster's watches to its agents, and again whenever they
   change or an agent connects. Each agent follows the pods of its node
   through one Kubernetes watch, however many watches wait, and tells each
   watch of its workload's pods.
3. The agent reports a pod that meets the condition, and the hub creates the
   capture for that pod, as the user who created the watch, after checking
   that user's permission again. Containers of a pod that is being deleted
   do not count.
4. The watch ends after it has recorded as often as asked, or when its
   creator or an administrator deletes it.

For a log condition the agent follows the logs of the watched pods on its
node from the moment it sees the pod. It reads the files that the container
runtime writes on the node (`/var/log/pods`), told of every change by the
kernel (inotify), so the lines do not travel through the kubelet and the API
server while the watch waits. The capture's reason quotes the line, cut at
200 characters. After a report the pod's further lines are passed over for
the watch's time frame (30 seconds where it has none), because they belong
to the incident that is being recorded. Where the agent cannot read the
files (a runtime that keeps them elsewhere, a static pod, a line of more
than 64 KiB) it follows the Kubernetes log stream instead; a stream that
ends is opened again after a pause that grows up to a minute, as nothing
tells when it can be read again.

The conditions about what a container uses, from `memory` to
`tcp-failures`, take `seconds`, for how long the use must stay above (for
`memory-growth`: the time within which it grows), and `container`. The agent measures every 5
seconds from the container's own accounting, the files of its cgroup,
which it reaches through the container's main process; this needs cgroup
v2. Use is a level and no event: the kernel only tells when a container
reaches its own limits, which is too late. Memory is counted as Kubernetes
does (without file cache that can be dropped). A condition is met once the
use has been above for as long as asked, and again only after it has been
below; a pod that is already above when the watch starts is recorded. A
share of a limit that the container does not have is never met. Pressure is
the kernel's own account of stalled tasks over the last 10 seconds, threads
are the cgroup's count of tasks, open files are counted in `/proc` for the
container's processes, and the TCP counters are those of the pod's network
namespace, which all its containers share.

A watch for an alert leaves the query to Prometheus, as an alerting rule,
and lets Alertmanager tell the hub when it fires: a webhook receiver for
`POST /api/alerts` with the hub's alert token (`hub.alertToken`) as bearer
token. So nothing is polled, and the hub knows neither the address nor the
credentials of Prometheus. Without the token the hub accepts no alerts and
no watches for them. An alert meets the watches that name its `alertname`;
its labels `namespace` and `cluster`, where it has them, must be the
watch's. Its label `pod` names the pod to record; without it all pods of
the workload are recorded. Alertmanager repeats a notification while the
alert fires: one start of one alert (its fingerprint) is recorded once per
watch. The capture's reason is the alert's `summary` or `description`. Who
holds the alert token can make these watches record, as their creators and
only what they asked for.

For the Prometheus operator the chart can install the receiver as an
`AlertmanagerConfig` (`hub.alertmanagerConfig`), with a route that sends
every alert at once and on its own: a watch records the moment an alert
fires, not the end of the wait that gathers a group. The operator lets the
alerts go on to the other routes. An Alertmanager passes such an object
only the alerts of its own namespace unless its
`alertmanagerConfigMatcherStrategy` is `None`.

For events the agent watches the warnings about each watched pod on its
node, which the API server sends as they come; a warning that repeats is
one event whose count rises, and each rise meets the condition. Warnings
from before the watch are passed over. A pod is watched from when it is
bound to the node, so warnings about its start are told; those about its
scheduling come before that and are not.

The hub keeps the times: it sleeps until the next time of any watch and
records all pods of the workload then, as the watch's creator. A time that
came while the hub was down is recorded when it starts, however late; of a
time that repeats, only the last one that came. A time that cannot be
recorded, as while no agent of the cluster is connected, is tried again
every minute until it can or the watch's next time comes; one that is
refused, as when the watch's creator may no longer record there, is given
up and logged.

Any watch records at once when its creator or an administrator asks it to
(`POST /api/watches/{id}/record`, optionally with a `pod`; **Record now**
in the console): of all pods of its workload or the one named, as one of
its count. With what the watch keeps running, the files reach back before
that moment, which a capture that starts now cannot do.

Except after a crash, the pod is alive when its capture starts: the
recordings that run over time (CPU profile, memory growth, system calls)
then show it in the state that met the condition, and a core dump is taken
of the running process.

### What reaches back before the moment

A recording that starts when the condition is met shows what follows, and
after a crash only the restarted process. Some recordings can therefore be
kept running while the watch waits, so that their files begin
`beforeSeconds` before the moment (the time frame if not given):

| Kind | Kept running | Cost while the watch waits |
| --- | --- | --- |
| `pcap` | Unless `before=false` | A `tcpdump` per watched pod and its packet headers in the agent's memory |
| `cpu` | Unless `before=false` | The profiler runs on the node: about 1 % of a CPU and some 100 MiB of the agent's memory |
| `memory` | Only with `before=true` | The same, and every page fault on the node takes a few microseconds longer |
| `strace` | Only with `before=true` | The traced process is slowed for as long as the watch waits, much if it makes many system calls; nothing else can attach to it, so such a watch takes no core dump of it |

The agent keeps the samples of a profile by the second, and the packets
and the lines of a trace with their times, and drops what is older than
the window; packets and system calls are held in memory, at most 16 MiB of
each per pod. A capture of the watch takes the seconds before it and then
the time frame after it, in one file; after a crash only the seconds
before, which the agent sets aside when it reports the crash, since the
process is gone. A trace then ends with the lines of the process's death. A recording that is not
kept running starts with the capture, as in a capture made by hand. A watch
ends with the report of its last time; the agent goes on observing it for
its time frame and half a minute more, so that the capture which that
report starts still finds what was kept running.

Some kinds behave differently in a watch's capture:

| Kind | Triggered capture holds |
| --- | --- |
| `pcap` | The packets from before the condition was met, and unless a crash ended the pod's container those of the time frame after it, cut after their headers unless the watch was approved for `payload=true`. The agent runs `tcpdump` in every watched pod and keeps them in memory, at most 16 MiB per pod (about 150,000 packet headers), oldest dropped first |
| `logs` | After a crash: the current and the previous instance of each container, so that the crashed one is included whether or not it has restarted |

| `coredump` | After a crash: the core that the kernel wrote of the crashed process, see below |

An agent that starts or reconnects takes the pods' state at that moment as
its baseline: what happened while it was away is not recorded, and its
packet buffers start empty. Agents older than the hub take every watch for
a crash watch.

### Cores of crashed processes

The kernel hands the core of every process that dies of a fatal signal to
one program per node, named by the sysctl `kernel.core_pattern`. With
`agent.coreHandler.enabled`, the agent makes a copy of its binary in a
directory on the node (`agent.coreHandler.hostPath`) that program while it
runs, and restores the previous setting when it stops. It also raises
`kernel.core_pipe_limit` from 0 to 16, so that the kernel waits for the
handler.

- The handler keeps a core only if the process belongs to a pod of an
  approved `coredump` watch; the agent marks those pods in the directory.
  Every other core it passes on to the handler that the node had before,
  such as apport or systemd-coredump, run as the kernel would have run it:
  the agent's pattern asks the kernel for the values that the node's
  handler takes as well, and the agent's handler gives them on with the
  core. A node that wrote cores to files (a pattern without `|`) writes
  none of unwatched processes while the agent's handler is installed, and
  neither does one whose handler's values do not fit behind the agent's in
  the 127 characters of a core pattern, which the agent logs.
- A later core of the same container replaces the earlier one. The handler
  stops writing when less than 10 % of the node's disk is free, which is the
  kubelet's default eviction threshold.
- With each core the handler keeps the program's files that the core maps,
  while the crashed process and its container's files are still there
  (the kernel waits for the handler). The agent describes the core with
  them: by then the container is gone, and its next instance may not run
  yet.
- The capture that the crash triggers uploads the pod's cores and deletes
  them from the node. Until then they rest there unencrypted.
- A process that the kernel kills for exceeding a memory limit leaves no
  core, and neither does one that exits by itself.

## Choosing without knowing

A user picks what to record from what the cluster shows, and never has to
know a name, a process ID or the syntax of a filter. The console offers
namespaces, workloads and containers as lists, and two inspections of the
chosen workload's pods. Both are answered by the pods' node agents, need the
same permission as a capture and store nothing.

- **Processes.** The programs that run in each container, with how many
  processes run them and how much memory the largest one holds, read from the
  nodes' `/proc`. A core dump or system call trace takes the container's main
  process, or with `process=<executable>` every process that runs that
  program. Arguments, environment and files are not read.
- **Traffic.** The agents record the packet headers of the pods for 5 seconds
  (at most 30, because the request stays open meanwhile) and sort them into
  flows: traffic that comes in on a port of the pod, with the number of
  peers; traffic that the pod sends to a peer's port; and traffic inside the
  pod. The opening packet of a connection decides which side serves, then
  the ports that the pod listens on, then the lower port. A peer is named if
  it is a Service or pod that the user may know: of the same namespace, or
  of any for an administrator. Every flow carries the packet filter that
  selects it. The filter for incoming traffic names only the port, because
  the peers change; the one for outgoing traffic names the peer's address
  too. The console turns ticked flows into the capture's filter. The sample
  is written to the audit log. No packets in a sample does not mean that the
  workload has no connections.

- **Profile endpoints.** An agent asks every TCP port that a pod listens on
  for the index or information page of each family of endpoints it knows,
  with a two-second limit. That starts no profiling. It also reads from the
  node's `/proc` whether a container runs a HotSpot JVM, which can be asked
  for its own diagnostics, and says why a JVM cannot be asked; nothing is
  written or signalled for that. It is written to the audit log.

The same inspections are MCP tools (`list_processes`, `sample_traffic`,
`find_profile_endpoints`).

### Known profile endpoints

Profiling over HTTP is a convention of some runtimes and libraries, not of
all languages. Asservat knows these:

| Served by | Recognized by | Endpoints |
| --- | --- | --- |
| Go `net/http/pprof`; libraries for other languages that serve the same paths and index, such as pprof-rs or pypprof | `/debug/pprof/` | CPU profile, heap, allocations, goroutine stacks, blocking, mutex contention, execution trace |
| C and C++ with gperftools or brpc | `/pprof/symbol` | CPU profile, heap, heap growth |
| Java with Spring Boot Actuator | `/actuator` | Thread dump; heap dump (memory, needs approval) |
| .NET with dotnet-monitor | `/info` | Trace; heap objects without contents; memory dump (needs approval) |
| A HotSpot JVM itself, without an endpoint | The process has HotSpot's `libjvm.so` loaded | Thread dump; class histogram; heap dump (memory, needs approval); flight recording for the time frame |

Because Asservat knows what each returns, only those that return memory
need approval. An endpoint outside this list can return anything, so
requesting one by `port` and `path` needs approval. Applications without
such an endpoint (most Python, Node.js, Ruby and PHP services, and Java or
.NET ones without the tools above) get a CPU profile and a profile of
memory growth by sampling (`cpu` and `memory`, below); what a process holds
by allocation site, blocking and traces need the runtime's own endpoint.

### A JVM's own diagnostics

A HotSpot JVM answers diagnostic commands over a socket in its `/tmp`, the
attach mechanism that `jcmd` and `jstack` use, so a Java program needs no
Actuator. This is the one case in which Asservat writes into a workload's
container and signals its process, by the maintainer's decision
(2026-11-23). The diagnostics are requested like endpoints, with the
container in place of a port (`<container>/<endpoint>`):

| Endpoint | Command | File | Cost |
| --- | --- | --- | --- |
| `jvm-threads` | `Thread.print -l` | `jvm-threaddump.txt` | A stop of milliseconds |
| `jvm-histogram` | `GC.class_histogram` | `jvm-histogram.txt` | The JVM stops for a full collection and a walk of its heap: seconds for a heap of gigabytes |
| `jvm-heapdump` (needs approval) | `GC.heap_dump` | `jvm-heapdump.hprof` | The JVM stops as for the histogram and while it writes the dump, which takes about the size of the live heap of the container's ephemeral storage until the agent has read it |
| `jvm-recording` | `JFR.start`, then `JFR.stop` when the time frame ends or the capture is stopped | `jvm-recording.jfr`, for JDK Mission Control; its samples open in the console | The flight recorder's own while it runs, which its makers give as about 1 % of CPU time; its file is written at the end |

1. The agent tells a JVM from the node's `/proc`: a process of the
   container, its main process first, that has HotSpot's `libjvm.so`
   mapped as code, none of OpenJ9's libraries, and that handles SIGQUIT.
   Only such a process is ever signalled, because SIGQUIT ends a process
   that does not handle it. An OpenJ9 JVM (IBM Semeru), which attaches
   differently, a JVM started with `-XX:+DisableAttachMechanism` (on its
   command line or in `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`,
   `_JAVA_OPTIONS`) or with `-Xrs` are told as such and left alone.
2. If the JVM's socket (`/tmp/.java_pid<pid>`) is not there, the agent
   writes the empty marker file `/tmp/.attach_pid<pid>` into the container
   and sends the JVM SIGQUIT, which makes it open the socket. It waits for
   the socket as long as the JDK's own client does, 10 seconds, told by the
   kernel (inotify), and removes the marker. It signals once: a JVM
   that is opening its socket prints its threads at a second signal.
   Diagnostics asked at the same time take turns for this step by a lock
   (flock) on the container's `/tmp`, which writes nothing there, so that
   only the first signals. A JVM that does not find the marker
   prints its threads to its standard output instead, as at any SIGQUIT.
   The JVM keeps the socket open from then on.
3. The agent sends one of the commands above. It has no way to send
   another: not the socket's `load`, which loads an agent library into the
   JVM, nor a command that changes its flags.
4. A heap dump and a flight recording are written by the JVM itself, to a
   file in the container's `/tmp` with a name that cannot be guessed. The
   agent reads it from there and deletes it in every outcome, also when
   the capture is cancelled meanwhile. The JVM ends a recording by itself
   a minute after the time frame, should the agent be gone; that file
   then stays. The flight recorder leaves an empty directory in `/tmp`
   until the JVM ends.

The JVM takes requests only from its own user and group (JDK 8; later
versions also from root). The agent therefore starts itself again as that
user, for which it has the capabilities `SETUID` and `SETGID`; that child
has no capabilities (unless the JVM runs as root, as the agent does), is
handed the container's `/tmp` and the JVM's
process as open files, and signals the JVM itself, since the agent may not
signal other users' processes. The container's `/tmp` is opened within
the container's root (`openat2` with `RESOLVE_IN_ROOT`, Linux 5.6), so a
link there cannot lead the agent to the node's files, and neither the
socket nor the JVM's file is followed if it is a link.

This needs a `/tmp` in the container that the JVM can write: with a
read-only root file system and no volume there, the JVM cannot open its
socket. It works with HotSpot from JDK 8 on (tested with 8, 11, 17, 21
and 25); a flight recording needs a JVM that has the flight recorder
(OpenJDK 8 from update 262).

### CPU profiles by sampling

The kind `cpu` needs nothing from the application. For the time frame the
agent runs the OpenTelemetry eBPF profiler, which it contains as a library:
programs in the node's kernel take the stack of whatever runs on a CPU, 99
times per second, and unwind native code (Go, C, C++, Rust) as well as the
interpreters and virtual machines of Python, Java, Node.js, Ruby, PHP, Perl,
.NET and Erlang, without attaching to a process or loading anything into
it. The profiler samples the whole node; the agent keeps the samples of the
recorded pods' containers and drops the rest. It runs only while a
recording wants it. While it runs, its programs and maps in the kernel
count as the agent's memory, over 100 MiB; when the last sampled recording
ends, the agent has them and the profiler's heap released.

Each pod yields `sampled-cpu.pprof`, in pprof's format, with the process
name and ID as labels of every sample, so pprof can narrow to one process.
Interpreted and Go functions are named by the profiler. For other native
code the agent reads the names from the binaries' symbol tables in the
container; a function of a stripped binary appears as `file+0xaddress`,
except for the functions it exports.

### Memory growth by sampling

The kind `memory` uses the same profiler to show which code makes a pod's
memory grow. The kernel gives a process a page of memory when the process
first touches it, which is a page fault. For the time frame the profiler
takes the stack at every page fault (a probe on the kernel's
`handle_mm_fault`), and the agent keeps those of the recorded pods. Each
pod yields `sampled-memory.pprof`, which counts page faults and the bytes
they bring in, one page per fault, by the application's stack; the
kernel's own frames are left out.

This is the way to see memory from outside that costs the application
nearly nothing and works for every runtime. Tracing every `malloc` and
`free` instead (as bcc's memleak does) would also tell what is still held,
but slows a program that allocates much several times over, and misses
runtimes with their own heap such as Go and Java.

!!! warning
    The profile shows growth while it records. Memory that was taken
    before, and memory that an allocator hands out again without asking the
    kernel, cause no page fault and do not appear: a core dump shows what a
    process holds. A fault that brings in a huge page counts as one page.
    While it records, every page fault on the node takes a few microseconds
    longer, also those of other pods.

!!! note
    The node needs Linux 5.10 or later. On an older kernel the recording
    fails and says so; the other recordings of the capture are not affected.

## Evidence kinds

The agent runs standard tools from the node, so the files are in each tool's
own format and nothing is injected into the pod. The one exception is a
JVM's own diagnostics, for which a marker file is written into the
container and the JVM is signalled (see above); no code is loaded there
either:

| Kind | How | Sensitive |
| --- | --- | --- |
| `pod-state` | Kubernetes API: pod object and events | No |
| `logs` | Kubernetes API: per container; `tailLines`, `previous`, followed for `durationSeconds` | No |
| `pcap` | `tcpdump` in the pod's network namespace; `filter`; every packet is cut after its transport header unless `payload=true`. The agent's own connections to the hub are left out | With `payload=true` |
| `strace` | `strace -f` on the container's main process, or on every process of `process`; buffer contents omitted unless `strings=true`. The trace rests in the agent's scratch directory and is uploaded when it is complete, so that the traced process does not wait for the way to the hub | With `strings=true` |
| `cpu` | Samples of the pod's processes by eBPF programs in the node's kernel, for `durationSeconds`; all containers of the pod | No |
| `memory` | Stacks of the pod's processes at their page faults, taken by an eBPF program in the node's kernel, for `durationSeconds`; all containers of the pod | No |
| `pprof` | HTTP GET of profile endpoints inside the pod's network namespace, all at once: `endpoints` lists known ones as `<port>/<endpoint>`; or `port` and `path` name another one. A JVM's own diagnostics, `<container>/<endpoint>` in the same list, are asked over its attach socket | For an endpoint that returns memory, and for one that Asservat does not know |
| `coredump` | `gcore` on the container's main process, or on every process of `process`; the process pauses while the core is written. gdb's description of the core, for a Go program with Delve's goroutines, is stored next to it | Yes |

The main process of a container is the oldest process in the container's
cgroup whose parent is outside of it. The agent tells a container's
cgroup by the container's ID in its path, except for its own container,
whose cgroup the kernel shows it without one: there it takes the processes
whose cgroup reads like its own.

## Looking at files in the browser

A file can be looked at in the console without downloading it. Each kind of
file gets a viewer that follows the tool people use for it, and the hub does
the reading with that tool's own engine where one exists, so the viewer
shows what the tool would show.

| File | Viewer | Read by |
| --- | --- | --- |
| Packet capture | Like Wireshark's main window: display filter with validation and field completion, packet list with the colouring rules, packet details and bytes side by side or stacked, follow stream; conversations, endpoints, protocol hierarchy and expert information, whose rows filter the list | Wireshark's `sharkd` in the hub |
| Logs | Like the log panels of Lens and the Kubernetes dashboard: numbered lines with timestamps, search by text or regular expression, only the matching lines, the selected line wrapped (JSON spread out). The JVM's class histogram, text as well, opens in it | The browser |
| Pod object, events | Like the detail panels of Lens and the Kubernetes dashboard: properties, conditions, containers with their states, volumes; events as a table; the object as a folding JSON tree with a filter | The browser |
| System call trace | A table of calls, narrowed by system call, process, failure, duration and text, with interrupted calls joined; and the summary that `strace -c` prints | The browser |

| Profile in pprof's format (`*.pprof`) | pprof's own web interface: flame graph, top, graph, peek; against a base, another profile of the same kind from the user's captures, the difference (pprof's `-diff_base`) | pprof in the hub (`dot` draws the graph) |
| JVM flight recording (`*.jfr`) | pprof's web interface, as for a profile: the hub turns what the recorder sampled into a profile with two kinds of value, where the threads ran (`samples`, of `jdk.ExecutionSample`) and where they allocated (`allocated`, of `jdk.ObjectAllocationSample` or, before JDK 16, the events about allocation buffers). The recording's other events (locks, garbage collection, I/O) are for JDK Mission Control; a recording without such samples says so instead of opening | The hub, then pprof |
| .NET trace (`*.nettrace`) | pprof's web interface, as for a profile: the hub turns the runtime's samples of the threads' stacks into a profile, with the methods' names that the trace holds. This is the view of PerfView's thread time stacks and of `dotnet-trace report`; the trace's other events are not shown | The hub, then pprof |
| Go execution trace (`trace.out`) | Go's own trace tool (`go tool trace`): goroutine analysis, the trace viewer, blocking and scheduler profiles, user tasks and regions | Go's trace tool in the hub |
| Goroutine dump, thread dump | Like the tools that analyse them (panicparse, the thread dump analysers of Java IDEs): the same stacks together with their number, by state, with search | The browser |

| Heap dump of Java (`*.hprof`) or of .NET (`*.gcdump`) | Like the first views of a heap analyser (VisualVM, Eclipse MAT, PerfView): a summary, the histogram of classes with the number and size of their objects, narrowed by name and sorted, the biggest single objects, and for Java the kinds of GC roots and the threads' stacks | The hub |
| Core dump | Like a debugger's view of a stopped program (Visual Studio Code): threads, for a Go program goroutines, call stack, the frame's variables, instructions and registers, modules, memory map | gdb, and Delve for a Go program, on the node, when the core is recorded |

The hub reads a heap dump itself, once and as a stream, so its memory does
not grow with the dump: it counts the objects of each class and keeps no
object. The sizes are the objects' own ("shallow"), computed as heap
analysers do; for a JVM with compressed references, which is taken to be so
when the objects lie within 32 GiB, they are the figures of the JVM's own
class histogram. What an object keeps alive ("retained size", dominators,
paths to GC roots) needs the whole object graph in memory and stays with an
analyser on the user's machine.

A .NET heap dump (gcdump) holds the objects' types and sizes without
their contents; the hub counts them per type, as `dotnet-gcdump report`
does.

A flight recording is read with Grafana's parser for it
(`github.com/grafana/jfr-parser`, the one Pyroscope takes recordings in
with), of which the hub uses the part that reads events, not the one that
makes profiles for Pyroscope.

A .NET trace is read in the format that .NET 5 to 10 write ("Nettrace"
version 4). Its samples are taken of every managed thread at an interval,
whether the thread ran or waited, so the profile shows thread time, not
CPU time; for CPU time, the sampled profile (`cpu`) is the one to take.
Frames outside of compiled .NET methods are shown as `[native code]`.

The memory dumps of .NET download only: reading their managed objects
needs the .NET SDK's tools, which would add several hundred megabytes to
the image.

A core is a memory image: without the program's executable and libraries a
debugger shows addresses, not functions. Those files are on the node while
the pod exists, and they are not evidence. So the agent has gdb describe
every core right after recording it, reading the program's files through a
process of the same container (for a crashed process, the files that the
core handler kept), and uploads the description as `<core>.analysis.json` next to
the core. The viewer shows that file; it does not browse the core's memory.
Variables appear where the program carries debug information. gdb unwinds
the stacks of Go programs poorly and knows nothing of goroutines: for a Go
program, Delve (as a library in the agent) adds the goroutines with their
state, call stacks and variables, and the viewer lists them before the
threads. It describes at most 10000 goroutines, those running on a thread
first, because the viewer reads at most 64 MiB and a goroutine takes about
4 KiB. Most Go programs in containers are built without debug information
(`-ldflags="-s -w"`), where Delve finds no goroutines. Every Go program
carries its line table, though, which names the function, file and line of
each address and the calls that the compiler inlined, and the runtime keeps
frame pointers. For such a program the agent finds the runtime's list of
goroutines by what it looks like in memory, walks their stacks and those of
the threads along the frame pointers and names the frames from the line
table (Go 1.20 and later on amd64 and arm64; inlined calls as their own
frames). These stacks have functions, files and lines, but no variables,
and the viewer says so. Where neither works, gdb's description stands
alone.

A core of a Python program shows gdb the interpreter, whose threads all
stand in its evaluation loop. What the program did is in the interpreter's
memory. pystack (in the hub's image, with a Python of its own) reads it from the
core and the interpreter's files, stripped or not: the describer adds the
interpreter's threads with their Python frames (function, file, line,
arguments and local variables) as `runtimeStacks`, and the viewer lists
them before the machine's threads, as it does goroutines. The threads
have no names: a core holds none, and pystack would give each the name of
whatever process has its number where the core is read. Other language
runtimes are added in the same form. A runtime knows its threads by
their numbers inside the container, and a core that the agent takes
numbers them as the node does: the description holds both numbers of each
thread, so that a runtime's thread is told to be the core's, and the hub
keeps them when it describes a core again.

The tools that read a runtime's stacks, pystack and dotnet-dump, are a
third of an image that has them, and every node would pull them for the
few cores of such programs. So the agent's image has neither: the agent
describes a core of a Python or .NET program with gdb and notes in the
description which runtime's stacks it awaits. The hub gets the core and
the program's files anyway. When the files have arrived, the last of a
core's uploads, it adds the awaited stacks from them and stores the
description in place of the agent's, which takes seconds for Python and up
to a minute for .NET; a viewer or `read_artifact` that opens the core
meanwhile waits for it, and after a restart of the hub the first opening
does the work. The hub decrypts the core into its work directory for this,
which so needs room for the largest such core. Where a tool fails, as
when a server does not answer, the description stays gdb's and goes on
awaiting the stacks: the hub tries again when the core is opened after it
has started anew, not at every opening. dotnet-dump
reads cores of its own processor only: the .NET cores of a cluster of
another architecture than the hub's are described without managed stacks.

A core of a .NET program shows gdb the runtime: threads in `libcoreclr.so`
and in code that the runtime compiled, which has no symbols. dotnet-dump
(in the hub's image, with a .NET runtime of its own under `/opt/asservat-dotnet`)
reads the runtime's memory, and the describer adds the managed threads in
the same form: the methods of each stack, the source lines where the image
has the program's PDBs, and the exception that a thread holds with its
message. It gives no arguments or local variables, and of a thread's name
only what the runtime uses the thread for. The frames that the runtime
itself marks on a stack are left out. dotnet-dump reads the memory with a
helper library that belongs to each build of the runtime
(`libmscordaccore.so`) and that it loads into itself: the library's code
runs in the hub. So it is never taken from the workload's
image, though every image has it. Microsoft's symbol server has the helper
of each runtime that Microsoft built, under the build ID of that runtime's
`libcoreclr.so`: the describer sends `msdl.microsoft.com` this build ID,
follows its redirect to Azure's blob storage (`*.blob.core.windows.net`)
and keeps the download in its work directory until unused for a week.
Nothing verifies the download beyond HTTPS: Microsoft publishes no
checksum or signature for it. It is fetched only where debuginfod servers
are named, the same switch as for the other downloads, and dotnet-dump's
own asking of that server is turned off. The assemblies and PDBs of the
image are data and are read from it. A core from gcore or the kernel does
not hold the pages of mapped files that the process did not change, which
dotnet-dump needs of the assemblies and of the runtime's libraries: the
describer gives it a copy of the core in the work directory with those
pages appended from the files, and removes the copy afterwards. While a
.NET core is described, the work directory so needs room for the core
once more and about 100 MiB; on a filesystem that shares the blocks of a
copy, as Btrfs, for the 100 MiB only. Described without
managed stacks are: a runtime that Microsoft's server does not have, as
those that distributions build from source; a program that maps no
`libcoreclr.so` because it carries the runtime in its executable
(NativeAOT, single-file programs); a core of another processor than the
hub's, whose helper is another file; and every .NET
core where no server may be asked. The helper of a runtime that was built for musl, as in Alpine
images, loads only into a tool that itself runs on musl: the hub's image
has the tool's runtime a second time for that, built for musl (under
`/opt/asservat-dotnet-musl`, about 85 MB), and the describer runs that one
when the helper asks for musl's C library.

gdb walks a stack by the unwind tables of the functions on it. musl, the C
library of Alpine images, carries none, and no frame pointers: a thread
that waits in it, as most threads of a core do, ends there for gdb, and
the program's own functions stay unseen, though the program has its
symbols. For a frame in a module without unwind tables (told by the size
of its `.eh_frame` beside its code) an unwinder in the description script
takes the first word above the stack pointer that is the address after a
call instruction as the caller's return address, and gdb walks on by the
caller's own tables (amd64 and arm64). On arm64 that word does not tell
where the caller's stack begins, which its tables count from: there the
frame pointer does, which arm64 compilers keep by default, and a caller
built without one is walked wrongly from there on. The frames found so are marked `≈`
in the viewer: a reading of the stack, most likely right, not certain.

The stacks of a stripped program in another language show
addresses unless gdb finds its debug information: with `debuginfodURLs`
(`--debuginfod-urls`) it fetches that from debuginfod servers, by default
from the elfutils project's server, which asks those of Debian, Fedora,
Arch and others, and from Ubuntu's. The describer asks the servers itself,
for the debug files of the stripped files a core maps, and gdb asks none:
gdb's own client waited minutes on a server that neither answered nor
closed. A server that does not answer within 10 seconds is not asked
again for that core; what no server has is asked for again after a day.
The servers are sent the build IDs of the programs and libraries of the
cores that are described, which name compiled files and hold nothing of a
process; an installation without a way out sets the list empty. The
downloads rest in the scratch directory and are removed when unused for
a week.

No debuginfod server knows the programs of RHEL's universal base images,
Rocky, Alma, Amazon Linux 2023 or Alpine, but these publish their debug
information as packages. Where debuginfod servers are named, the describer
fetches those too, for the stripped programs and libraries of a core,
telling the distribution by the container's `/etc/os-release`. For the RPM
distributions it downloads the list of packages of the release's debug
repositories (from `cdn-ubi.redhat.com`, `dl.rockylinux.org`,
`repo.almalinux.org`, `cdn.amazonlinux.com`), which names the build IDs
that each debug package covers, looks the build IDs up in it and downloads
the packages that have them: the vendor learns the names of those
packages, no build ID. The list is asked for anew after a day. For Alpine
it reads from the container's list of installed packages which packages
own the files and asks `dl-cdn.alpinelinux.org` for the debug package
(`<origin>-dbg`) of each in its version. The debug files are unpacked with
`bsdtar` into the scratch directory, kept there until unused for a week,
and given to gdb as further debug directories. A server that does not
answer, or sends nothing more, within 10 seconds is given up, and the core
is described without. Much is not there to be found: the universal base
images' repositories and Rocky's list only the latest build of each
package, so that an image built before a library's last update finds
nothing for that library; Alpine builds debug packages for some ninety
sources only (musl, OpenSSL, Python, curl among them, not BusyBox) and
keeps the latest revision of each only. Alma and Amazon Linux keep every
build. What an image's own package manager installed is found; a program
built outside of the distribution is not.

The agent also uploads the program's files next to the core, as
`<core>.files.tar`: the executable and the libraries that the core maps
(not the data files a program may map as well), at the paths the program
saw them, with the links by which the program asks for its libraries, and
with `/etc/os-release` and Alpine's list of installed packages, by which
the debug packages are found, and for a .NET program with the managed
assemblies that the core maps and their PDBs (some 28 MiB for an ASP.NET
program). The agent follows the links of a container's
paths itself, within the container's root: the kernel would follow a link
to an absolute path on the node, and a container could so lead the agent
to the node's files (the kind of fault behind CVE-2019-14271 in `docker cp`
and CVE-2019-1002101 in `kubectl cp`). gdb follows links as the kernel
does, so it reads the program's files through a directory of links that
the agent makes for each core: one by each name of a mapped file or a
library asked for, to the file that the name leads to in the container.
Unpacked, they are what a debugger needs to open the core where
it is downloaded to (`gdb -ex 'set sysroot <dir>' <dir>/<program> <core>`).
The hub unpacks such an archive, which a cluster's agent sent and is not
trusted, with every name followed within the directory it unpacks into
(Go's `os.Root`): links of the archive cannot lead a later entry out of
it. The tools the hub starts take no code from its work directory.
They also let the hub describe a core again: a description names the
version of the describer that made it, and when the viewer opens a core
whose description is from an older one, the hub describes it anew from the
stored core and files, in its work directory, and stores the new
description in place of the old. That can take a minute or more with
debug information to download: the answer to the viewer begins with a
space for every beat of the hub's streams, so that a proxy keeps waiting,
and the work goes on if the viewer is closed. A capture from before the files were
kept stays as it was described, and the viewer says so. For the binary
files that have a viewer in the hub, MCP's `read_artifact` returns what the
viewer shows, as text: a core, by its own name or its description's, as
why the process stopped, then the stacks of its program as its runtime
sees them, those with the same state and stack told once with their
number, then the machine's threads, and not the memory map, which is most
of a description; a profile, a .NET trace and a flight recording as pprof's list of the
60 functions with the most weight, a heap dump as its 60 largest classes,
its biggest objects and its threads' stacks, a packet capture as its
protocols, conversations and Wireshark's expert information, or with a
display filter as the packets that match. The viewers that read in
the browser fetch the file like a download and read at most 64 MiB of it,
because the text and an index of its lines stay in the browser's memory.

A viewer's address names the spot it shows (the packet and display filter,
the log line, the trace entry, the stack, the base of a comparison), so a
copied link leads there. Logs, packets and system calls of a capture share
a clock: for a selected line, packet, call or event, the page offers the
capture's other such files at that moment, and each opens at the first
entry from then on. A trace's times of day are placed on the capture's day.
The file's name in the viewer's bar is the choice among the capture's files
that have a viewer.

A packet capture or a profile is not sent to the browser. It is opened as a
**view**.
The browser opens it with an event stream; the view lives as long as that stream, so nothing has to guess when somebody
stopped looking, and it ends early when the capture is deleted or its
retention ends. The viewer's questions about the file go to the view and
only its opener may ask them. For a packet capture, the hub decrypts the
file into its work directory (`--work-dir`, an `emptyDir` in the chart),
starts one `sharkd` for the view, and removes the file's name as soon as
`sharkd` has it open. Of `sharkd`'s requests, the hub passes on those that
read the loaded capture and no others; of its statistics, those that count
packets. A profile is parsed in the hub's
memory by pprof's library, which hands the hub the pages of its web
interface; the view serves them, except those that write pprof's settings
or read the profiled program's binary. Go's trace tool is no library: the
hub builds it from the toolchain's source (`cmd/trace`) into the image,
runs one for the view on a loopback port, and passes its pages on. The tool
writes its links from the root of its own server, so the hub rewrites them
to the view's pages. It reads the whole trace into memory; the decrypted
file is removed once it serves.

## Look

An Asservat is a piece of evidence in custody. The mark is the yellow
numbered marker that is set next to evidence, and marker yellow is the one
loud colour: it means "recorded here" and the next step to take. Every
capture has a number, counted up per installation, shown on such a marker:
outlined while the capture holds no files, filled once it does. Headings,
numbers and states are set in Barlow Condensed capitals, text in IBM Plex
Sans, hashes, sizes and filters in IBM Plex Mono; the hub serves the fonts
itself (`/assets/`), so the console fetches nothing from elsewhere. The
look covers the console and the viewers, and a viewer is the console's
page with a file on it. Every page has the same bar, in the theme of the
system, none dark by itself. Under the bar every viewer has the same rows:
the views of the file with the count of what is shown at their right end,
then what narrows the list, the search first, then the file. A list is
rows of one height under small capital headings, as in the console's
tables, and what is selected is marker yellow. A view that is read like a
page, as a pod's state or a heap dump's summary, is a sheet on the ground
as a capture is in the console's list. A viewer keeps the panes of the tool
that people know for its kind of file (Wireshark's three, a debugger's
threads and stack beside a frame) and every colour that tells something:
Wireshark's colouring rules colour the packets, its display filter is
green or red, its expert severities have their colours, a log's levels
colour the line's text, a warning event is tinted. Colour that only
decorated is gone. A viewer shows its capture's number on a marker beside the file's
name. The pages that pprof and Go's trace tool draw themselves keep their
layout and the colours of their graphs, and are light in either theme; the
hub adds a stylesheet to them that sets them in Asservat's type and gives
pprof's bar the look of a viewer's row. pprof draws a function's box as
wide as its share, so that a small one cannot hold its name: the row above
its page says how the name is read (point at the box) and how the box is
made wide (click it), which pprof itself does not say.

The list of captures shows one line per capture: its number, state, what
was recorded and why, where, when and by whom. It lists the newest 50 and
more on request, and a find box narrows it by any of those words. An open
capture shows each pod with its recordings in the order they were asked
for, and under each recording the files it made, with their full names,
what each file is, its size, and the ways to it: **Open** where a viewer
exists, and **Download**. The hub tells which recording a file is from by
the name the agent gave it; the files of a profile endpoint are named by
the application and are those that remain. Deleting a capture that holds
files asks first.

## Permissions

- A user is identified by a name and groups, from a static token or an OIDC ID
  token. These are the subjects that the clusters' RBAC knows.
- A browser signs in at the OIDC issuer (authorization code flow with PKCE).
  The hub verifies the ID token and keeps the name and groups in a session
  cookie that it signs with a key derived from the master key. The session
  lasts 12 hours, so the groups are at most that old.
- The console and the MCP tools offer namespaces, workloads and containers
  from the cluster; nothing of that is typed. A user is offered the
  namespaces in which they may capture. Where there is none, the console
  says so in the first step of a new capture, names the right that is
  missing (`pods/exec`) and does not go on to the next step.
- A user may list and capture the workloads of a namespace if a
  `SubjectAccessReview` in that cluster allows them to create `pods/exec` in
  the namespace. Exec already exposes memory, files and traffic of a pod, so
  capturing grants nothing new, and permissions stay in Kubernetes RBAC.
- Members of the administrator groups may capture everywhere, approve or deny
  sensitive captures, manage clusters and read the audit log.
- An administrator cannot approve their own request unless the installation
  allows it (`hub.allowSelfApproval`, for a single administrator). Where it
  does, an administrator's sensitive requests and watches start without a
  separate approval and are recorded as approved by themselves.
- A capture and its files are visible to its requester and to administrators.
  Its requester, or an administrator, can share it: it is then also there,
  to look at and to download, for everyone who may capture in its
  namespace, which the cluster's RBAC tells at every access as it does for
  a new capture. Nobody else learns that it exists, and only its requester
  and administrators change, stop or delete it. Sharing and taking it back
  are in the audit log, as is every file that a colleague opens.

## Security

- **Threat model.** Operators keep everyone who is not an Asservat
  administrator out of the Asservat namespaces. Whoever can write there, and
  any cluster administrator, is trusted.
- **Clusters** are configuration of the hub (`hub.clusters`: a name and a
  join token each), like its users. Nothing registers a cluster at run time.
- **Agents** authenticate with their cluster's join token. A token can upload files for the pods of open captures of its
  own cluster, report their status and answer queries about that cluster,
  and nothing else. Use HTTPS between clusters.
- **Evidence at rest** is encrypted by the hub: AES-256-GCM in 64 KiB chunks
  with a random key per file, wrapped by the master key from the hub's Secret.
  Losing the master key loses the evidence.
- **Audit.** Requests, watches and the captures they
  trigger, approvals, denials, stops, cancellations, deletions, expiries and
  every download and every file opened in a viewer are recorded with the
  actor. Administrators read the log on the console's audit log page,
  newest first, or from `GET /api/audit`.
- A file that is open in a viewer rests decrypted in the hub's work
  directory until the program that reads it has opened it, and in that
  program's memory while the view lasts. The program (`sharkd` for packet
  captures) parses recorded traffic inside the hub's container. A profile
  is only ever decrypted into the hub's memory, and so is a heap dump, as
  a stream of which the hub keeps the counts per class.
- A core file rests unencrypted on the node until its upload ends, then it
  is deleted: in the agent's scratch volume, or for a crashed process in the
  core handler's directory.

## Mechanisms

- **No polling.** The hub pushes commands on the agents' open streams and
  change hints to browsers over Server-Sent Events. Agents learn of crashes
  from a Kubernetes watch. The retention loop sleeps until the next expiry.
- **Streams through proxies.** A proxy in front of the hub ends a connection
  that stays silent (HAProxy after 50 seconds by default, nginx and cloud
  load balancers after 60). The hub therefore writes a line every 20
  seconds into each open stream that has nothing to say: an empty comment
  into an event stream, a command that asks for nothing to an agent.
- **Metrics.** With `hub.metrics.enabled` the hub serves its own figures
  for Prometheus at `/metrics` on a port of its own, which the ingress does
  not reach and which asks for no sign-in: the agents connected per
  cluster, captures by state, watches, the stored evidence and the files
  open in viewers. They are counted when they are asked for and name
  clusters and states, no workload, namespace or person. A cluster with
  fewer agents connected than it has nodes is what to alert on: it shows
  otherwise only when evidence is wanted. Agents serve nothing.
- **One hub replica.** Connected agents and event streams are in memory.
  Captures, approvals and queued tasks are in PostgreSQL and survive a restart;
  agents reconnect by themselves. A task that ends while the hub is away,
  as during an upgrade, reports its result when its agent's stream to the
  hub is open again, and counts as running until then. A file that rests
  on the node, as a core or a trace that was set aside does, is uploaded
  again from its beginning then. What a tool writes while it runs (packets,
  a profile from an endpoint) cannot be read again: a restart that cuts
  such an upload off loses it, and its recording is reported as failed.
- **The agent's own traffic.** An agent dials the hub from the source ports
  61000 to 61063, above Linux's default range for outgoing connections, and
  every packet capture, packet buffer and traffic sample leaves TCP on
  those ports out. A capture of a pod through which the agent's connection
  passes (the hub's pod, a pod on the host's network) would otherwise
  record its own upload.
- **Limits.** `read_artifact` over MCP returns 64 KiB of a text file per
  call, and 60 functions of a profile, classes of a heap dump or packets
  and conversations of a packet capture, so that a
  result fits a model's context. A watch's packet buffer is 16 MiB per pod
  because it lives in the agent's memory. A capture's duration is what the
  user requests. There are no other built-in limits; add one only with a
  measured reason.

## Not built yet

No known gaps are listed at present. What use of Asservat shows to be
missing goes here, in rough order of value.

## Decided against (maintainer, 2026-11-25)

These were looked into and are not to be built unless the maintainer asks
for them again:

- What a process holds in memory by allocation site, for applications that
  serve no profile endpoint. Looked into on 2026-11-24 and not built, for
  want of a way that pays: a Go program records its allocations by itself
  only where it links the runtime's memory profile, which the linker turns
  off in programs that never ask for it, the ones without an endpoint among
  them (`runtime.disableMemoryProfiling`); the profiler's own heap probe
  needs probe points in the allocator that applications do not carry; and
  following every `malloc` and `free` of a process from the kernel slows
  programs that allocate much and needs kernel programs of Asservat's own.
  What there is instead: memory growth by sampling for every language, the
  heap dump and class histogram of a JVM, and the heap profile of a Go
  program that does serve an endpoint.
- Several hub replicas. An agent holds one stream to one hub, and a view of
  a file lives in the hub that opened it, so replicas would have to pass
  requests on to one another. Against that stands what one hub costs: a
  restart, as in every upgrade, takes it away for some seconds (four,
  measured on a three-node cluster), captures, watches and queued tasks are
  in PostgreSQL and survive it, a recording that ends meanwhile reports when
  the hub is back, and agents return within seconds.
