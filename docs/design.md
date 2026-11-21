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

1. A user requests a capture: cluster, namespace, workload, evidence kind and
   its parameters.
2. The hub checks the permission and asks an agent of the cluster for the
   workload's running pods. Each pod becomes a **task** for the agent on the
   pod's node.
3. A sensitive capture waits in `PendingApproval` until an administrator
   approves or denies it. Any other capture is `Queued` at once.
4. The hub pushes each task over the node agent's stream. Every stream starts
   with the node's open tasks: the agent starts those it missed, stops those
   that were cancelled or deleted meanwhile, and reports a task as failed
   that was running when the agent restarted.
5. The agent records, streams the files to the hub and reports the task as
   `Completed` or `Failed`. The capture is `Completed` if at least one pod
   succeeded.
6. The requester or an administrator downloads the files. When the retention
   ends the hub deletes the capture and its files.

A capture can be cancelled while it waits or runs, and deleted afterwards.

## Crash watches

A watch is a standing capture request for problems nobody is present for:
whenever a container of the workload crashes, the capture is made for the
crashed pod.

1. A user creates a watch: a capture request plus the number of crashes to
   record (default 1). The permission is the same as for a capture. Evidence
   that needs approval cannot be watched for.
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
| `pcap` | The packet headers of the `durationSeconds` before the crash. The agent runs `tcpdump` in every watched pod and keeps them in memory, at most 16 MiB per pod (about 150,000 packets), oldest dropped first |
| `logs` | The current and the previous instance of each container, so that the crashed one is included whether or not it has restarted |

An agent that starts or reconnects takes the pods' state at that moment as
its baseline: crashes while it was away are not recorded, and its packet
buffers start empty.

## Evidence kinds

The agent runs standard tools from the node, so the files are in each tool's
own format and nothing is injected into the pod:

| Kind | How | Sensitive |
| --- | --- | --- |
| `pod-state` | Kubernetes API: pod object and events | No |
| `logs` | Kubernetes API: per container; `tailLines`, `previous`, followed for `durationSeconds` | No |
| `pcap` | `tcpdump` in the pod's network namespace; `filter`; every packet is cut after its transport header unless `payload=true` | With `payload=true` |
| `strace` | `strace -f` on the container's main process; buffer contents omitted unless `strings=true` | With `strings=true` |
| `pprof` | HTTP GET inside the pod's network namespace on `port` and `path` | No |
| `coredump` | `gcore` on the container's main process; the process pauses while the core is written | Yes |

The main process of a container is the oldest process in the container's
cgroup whose parent is outside of it.

## Permissions

- A user is identified by a name and groups, from a static token or an OIDC ID
  token. These are the subjects that the clusters' RBAC knows.
- A browser signs in at the OIDC issuer (authorization code flow with PKCE).
  The hub verifies the ID token and keeps the name and groups in a session
  cookie that it signs with a key derived from the master key. The session
  lasts 12 hours, so the groups are at most that old.
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
- A core file rests unencrypted in the agent's scratch volume on the node
  until its upload ends, then it is deleted.

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

- Other triggers than a crash (alerts, failing probes, a log line), and
  watches for evidence that needs approval (packet payload before a crash).
- Core dumps of crashed processes (needs a node-level core handler).
- Sharing a capture with other users or teams.
- Server-side analysis of binary evidence for AI agents (packet summaries,
  profile summaries).
- Several hub replicas.
