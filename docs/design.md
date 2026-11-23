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
| Node agent | DaemonSet in every cluster (host PID namespace, `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`, `SYS_RESOURCE`, `SYSLOG`) | Holds one outbound stream to the hub, records evidence from the pods of its node, answers the hub's questions about its cluster |
| PostgreSQL | Bundled or external | Captures, tasks, watches, artifact index, audit log |
| Evidence store | Volume or S3 bucket | Encrypted artifact bytes |

Both components are the same binary and image (`asservat hub`, `asservat agent`).

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
runs over time cannot be cut short and is abandoned. A capture can also be
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

1. A user creates a watch: a capture request, with one or more recordings,
   a condition, and the number of times to record (default 1). The
   permission is the same as for a capture. A watch
   for evidence that needs approval waits until an administrator approves
   it, by the same rules as a capture. The approval precedes the event, so
   it covers the captures that the watch creates.
2. The hub sends the cluster's watches to its agents, and again whenever they
   change or an agent connects. Each agent follows the workload's pods on its
   node through a Kubernetes watch.
3. The agent reports a pod that meets the condition, and the hub creates the
   capture for that pod, as the user who created the watch, after checking
   that user's permission again. Containers of a pod that is being deleted
   do not count.
4. The watch ends after it has recorded as often as asked, or when its
   creator or an administrator deletes it.

For a log condition the agent follows the logs of the watched pods on its
node through the Kubernetes log stream, from the moment it sees the pod. The
capture's reason quotes the line, cut at 200 characters. After a report the
pod's further lines are passed over for the watch's time frame (30 seconds
where it has none), because they belong to the incident that is being
recorded. A stream that ends is opened again after a pause that grows up to
a minute; nothing tells when it can be read again.

Except after a crash, the pod is alive when its capture starts: the
recordings that run over time (CPU profile, memory growth, system calls)
then show it in the state that met the condition, and a core dump is taken
of the running process.

Some kinds behave differently in a watch's capture:

| Kind | Triggered capture holds |
| --- | --- |
| `pcap` | The packets of the `durationSeconds` before the condition was met, cut after their headers unless the watch was approved for `payload=true`. The agent runs `tcpdump` in every watched pod and keeps them in memory, at most 16 MiB per pod (about 150,000 packet headers), oldest dropped first |
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
  Every other core on the node is dropped while the agent's handler is
  installed, including those the node's own handler would have stored.
- A later core of the same container replaces the earlier one. The handler
  stops writing when less than 10 % of the node's disk is free, which is the
  kubelet's default eviction threshold.
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
  with a two-second limit. That starts no profiling. It is written to the
  audit log.

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

Because Asservat knows what each returns, only those that return memory
need approval. An endpoint outside this list can return anything, so
requesting one by `port` and `path` needs approval. Applications without
such an endpoint (most Python, Node.js, Ruby and PHP services, and Java or
.NET ones without the tools above) get a CPU profile and a profile of
memory growth by sampling (`cpu` and `memory`, below); what a process holds
by allocation site, blocking and traces need the runtime's own endpoint.

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
own format and nothing is injected into the pod:

| Kind | How | Sensitive |
| --- | --- | --- |
| `pod-state` | Kubernetes API: pod object and events | No |
| `logs` | Kubernetes API: per container; `tailLines`, `previous`, followed for `durationSeconds` | No |
| `pcap` | `tcpdump` in the pod's network namespace; `filter`; every packet is cut after its transport header unless `payload=true`. The agent's own connections to the hub are left out | With `payload=true` |
| `strace` | `strace -f` on the container's main process, or on every process of `process`; buffer contents omitted unless `strings=true` | With `strings=true` |
| `cpu` | Samples of the pod's processes by eBPF programs in the node's kernel, for `durationSeconds`; all containers of the pod | No |
| `memory` | Stacks of the pod's processes at their page faults, taken by an eBPF program in the node's kernel, for `durationSeconds`; all containers of the pod | No |
| `pprof` | HTTP GET of profile endpoints inside the pod's network namespace, all at once: `endpoints` lists known ones as `<port>/<endpoint>`; or `port` and `path` name another one | For an endpoint that returns memory, and for one that Asservat does not know |
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
| Logs | Like the log panels of Lens and the Kubernetes dashboard: a dark terminal with timestamps, search by text or regular expression, only the matching lines, the selected line wrapped (JSON spread out) | The browser |
| Pod object, events | Like the detail panels of Lens and the Kubernetes dashboard: properties, conditions, containers with their states, volumes; events as a table; the object as a folding JSON tree with a filter | The browser |
| System call trace | A table of calls, narrowed by system call, process, failure, duration and text, with interrupted calls joined; and the summary that `strace -c` prints | The browser |

| Profile in pprof's format (`*.pprof`) | pprof's own web interface: flame graph, top, graph, peek; against a base, another profile of the same kind from the user's captures, the difference (pprof's `-diff_base`) | pprof in the hub (`dot` draws the graph) |
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
process of the same container (for a crashed process, the container's next
instance), and uploads the description as `<core>.analysis.json` next to
the core. The viewer shows that file; it does not browse the core's memory.
Variables appear where the program carries debug information. gdb unwinds
the stacks of Go programs poorly and knows nothing of goroutines: for a Go
program, Delve (as a library in the agent) adds the goroutines with their
state, call stacks and variables, and the viewer lists them before the
threads. It describes at most 10000 goroutines, those running on a thread
first, because the viewer reads at most 64 MiB and a goroutine takes about
4 KiB; where Delve cannot read the program, for instance a stripped one,
gdb's description stands alone. The stacks of a stripped program show
addresses. With `agent.debuginfodURLs` (`--debuginfod-urls`) gdb fetches the
missing symbols from those debuginfod servers; this is off by default
because the agent then sends them the build IDs of the programs it describes
and of their libraries. The downloads rest in the agent's scratch directory,
where the debuginfod client removes those unused for a week. As text, the
description is also readable for AI agents over MCP. For the binary files
that have a viewer in the hub, MCP's `read_artifact` returns what the
viewer shows, as text: a profile and a .NET trace as pprof's list of the
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
look covers the console and the viewers. A viewer keeps what makes its
tool familiar: the layout, and colour where it carries meaning (Wireshark's
colouring rules and filter validity, the levels of a log, the dark ground of
a terminal and of a debugger). Type, palette, corners, tabs and tables are
Asservat's, and what is selected is marker yellow in every viewer. A viewer
shows its capture's number on a marker beside the file's name. The pages
that pprof and Go's trace tool draw themselves keep their layout and
colours; the hub adds a stylesheet to them that sets them in Asservat's
type.

## Permissions

- A user is identified by a name and groups, from a static token or an OIDC ID
  token. These are the subjects that the clusters' RBAC knows.
- A browser signs in at the OIDC issuer (authorization code flow with PKCE).
  The hub verifies the ID token and keeps the name and groups in a session
  cookie that it signs with a key derived from the master key. The session
  lasts 12 hours, so the groups are at most that old.
- The console and the MCP tools offer namespaces, workloads and containers
  from the cluster; nothing of that is typed. A user is offered the
  namespaces in which they may capture.
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
  actor.
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
- **One hub replica.** Connected agents and event streams are in memory.
  Captures, approvals and queued tasks are in PostgreSQL and survive a restart;
  agents reconnect by themselves.
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

These are known gaps, in rough order of value:

- What a process holds in memory by allocation site, for applications that
  serve no profile endpoint.
- More conditions for watches: memory or CPU use, a Prometheus alert.
- Passing the cores of unwatched processes on to the node's previous core
  handler.
- Sharing a capture with other users or teams.
- Several hub replicas.
