# Design

## Overview

Asservat records evidence from workloads in many Kubernetes clusters so that
developers can debug problems that do not reproduce in a lab. This document is
the whole specification: what the system guarantees, how its parts work and
what is deliberately left out. Change it together with the code.

## Components

| Component | Runs as | Does |
| --- | --- | --- |
| Hub | One Deployment in one cluster | Authenticates users, records requests and approvals, pushes work to agents, encrypts and stores evidence, serves console, REST API and MCP |
| Node agent | DaemonSet in every cluster (host PID namespace, `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`) | Holds one outbound stream to the hub, records evidence from the pods of its node, answers the hub's questions about its cluster |
| PostgreSQL | Bundled or external | Clusters, captures, tasks, artifact index, audit log |
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
   failed. The capture is `Completed` if at least one pod succeeded.
6. The requester or an administrator downloads the files. When the retention
   ends the hub deletes the capture and its files.

A capture can be cancelled while it waits or runs, and deleted afterwards.

The recordings of a capture share everything but their kind and parameters:

- the same pods and the same start;
- one time frame, `durationSeconds`, for those that run over time (`pcap`,
  `strace`, `pprof` and followed `logs`); it defaults to 30 seconds if one
  of the first three is requested;
- one approval, needed if any recording is sensitive, before which none of
  them starts;
- one trigger, when they belong to a crash watch.

A capture holds at most one recording of each kind, because two would write
the same files. A core dump and a system call trace both attach to the
process, which only one can do at a time: the trace starts when the core is
written. A request with a single `kind` and `params` is the short form of
one recording.

## Crash watches

A watch is a standing capture request for problems nobody is present for:
whenever a container of the workload crashes, the capture is made for the
crashed pod.

1. A user creates a watch: a capture request, with one or more recordings,
   plus the number of crashes to record (default 1). The permission is the
   same as for a capture. A watch
   for evidence that needs approval waits until an administrator approves
   it, by the same rules as a capture. The approval precedes the crash, so
   it covers the captures that the watch creates.
2. The hub sends the cluster's watches to its agents, and again whenever they
   change or an agent connects. Each agent follows the workload's pods on its
   node through a Kubernetes watch.
3. A crash is a container that terminated with an exit code other than zero,
   which includes being killed for exceeding its memory limit. Containers of
   a pod that is being deleted do not count. The agent reports the crash and
   the hub creates the capture for that pod, as the user who created the
   watch, after checking that user's permission again.
4. The watch ends after its last crash, or when its creator or an
   administrator deletes it.

Two kinds behave differently in a triggered capture:

| Kind | Triggered capture holds |
| --- | --- |
| `pcap` | The packets of the `durationSeconds` before the crash, cut after their headers unless the watch was approved for `payload=true`. The agent runs `tcpdump` in every watched pod and keeps them in memory, at most 16 MiB per pod (about 150,000 packet headers), oldest dropped first |
| `logs` | The current and the previous instance of each container, so that the crashed one is included whether or not it has restarted |

| `coredump` | The core that the kernel wrote of the crashed process, see below |

An agent that starts or reconnects takes the pods' state at that moment as
its baseline: crashes while it was away are not recorded, and its packet
buffers start empty.

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

The same inspections are MCP tools (`list_processes`, `sample_traffic`).

## Evidence kinds

The agent runs standard tools from the node, so the files are in each tool's
own format and nothing is injected into the pod:

| Kind | How | Sensitive |
| --- | --- | --- |
| `pod-state` | Kubernetes API: pod object and events | No |
| `logs` | Kubernetes API: per container; `tailLines`, `previous`, followed for `durationSeconds` | No |
| `pcap` | `tcpdump` in the pod's network namespace; `filter`; every packet is cut after its transport header unless `payload=true` | With `payload=true` |
| `strace` | `strace -f` on the container's main process, or on every process of `process`; buffer contents omitted unless `strings=true` | With `strings=true` |
| `pprof` | HTTP GET inside the pod's network namespace on `port` and `path` | No |
| `coredump` | `gcore` on the container's main process, or on every process of `process`; the process pauses while the core is written | Yes |

The main process of a container is the oldest process in the container's
cgroup whose parent is outside of it.

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
  allows it (`hub.allowSelfApproval`, for a single administrator).
- A capture and its files are visible to its requester and to administrators.

## Security

- **Threat model.** Operators keep everyone who is not an Asservat
  administrator out of the Asservat namespaces. Whoever can write there, and
  any cluster administrator, is trusted.
- **Agents** authenticate with their cluster's join token; the hub stores only
  its SHA-256. A token can upload files for the pods of open captures of its
  own cluster, report their status and answer queries about that cluster,
  and nothing else. Use HTTPS between clusters.
- **Evidence at rest** is encrypted by the hub: AES-256-GCM in 64 KiB chunks
  with a random key per file, wrapped by the master key from the hub's Secret.
  Losing the master key loses the evidence.
- **Audit.** Cluster changes, requests, watches and the captures they
  trigger, approvals, denials, cancellations, deletions, expiries and every
  download are recorded with the actor.
- A core file rests unencrypted on the node until its upload ends, then it
  is deleted: in the agent's scratch volume, or for a crashed process in the
  core handler's directory.

## Mechanisms

- **No polling.** The hub pushes commands on the agents' open streams and
  change hints to browsers over Server-Sent Events. Agents learn of crashes
  from a Kubernetes watch. The retention loop sleeps until the next expiry.
- **One hub replica.** Connected agents and event streams are in memory.
  Captures, approvals and queued tasks are in PostgreSQL and survive a restart;
  agents reconnect by themselves.
- **Limits.** `read_artifact` over MCP returns 64 KiB per call so that a
  result fits a model's context. A watch's packet buffer is 16 MiB per pod
  because it lives in the agent's memory. A capture's duration is what the
  user requests. There are no other built-in limits; add one only with a
  measured reason.

## Not built yet

These are known gaps, in rough order of value:

- Other triggers than a crash (alerts, failing probes, a log line).
- Passing the cores of unwatched processes on to the node's previous core
  handler.
- Sharing a capture with other users or teams.
- Server-side analysis of binary evidence for AI agents (packet summaries,
  profile summaries).
- Several hub replicas.
