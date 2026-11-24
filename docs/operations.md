# Operating Asservat

## Overview

This guide covers what you need to run Asservat beyond the install steps in the
[README](../README.md): what to back up, how to upgrade, how much the
components use, and where to look when something does not work. The
[design](./design.md) explains why things work the way they do.

## What to back up

An installation keeps its state in three places. You need all three to restore
evidence.

| What | Where | What is lost without it |
| --- | --- | --- |
| The master key | Secret `<release>-hub`, key `master-key` | Every stored file. Each file is encrypted with its own key, and those keys are wrapped with the master key. |
| The database | The chart's PostgreSQL (`<release>-postgres`), or your own (`hub.database.existingSecret`) | Captures, watches, approvals, the index of files and the audit log. |
| The evidence | The hub's volume (`hub.storage.size`), or your S3 bucket (`hub.storage.s3`) | The recorded files themselves. |

!!! warning
    Back up the master key when you install, and keep it apart from the
    evidence. The chart creates it once and keeps it across upgrades and
    `helm uninstall` (`helm.sh/resource-policy: keep`), but nothing can
    recreate it. Evidence without its master key cannot be read by anyone.

Save the master key:

```sh
kubectl -n <namespace> get secret <release>-hub -o jsonpath='{.data.master-key}' > master-key.b64
```

Back up the chart's PostgreSQL with `pg_dump`:

```sh
kubectl -n <namespace> exec <release>-postgres-0 -- pg_dump -U asservat asservat > asservat.sql
```

To restore, install the chart with the saved Secret in place, load the dump
into the empty database, and put the evidence volume or bucket back. The hub
finds the files by the names in the database.

Evidence is deleted when its retention ends (`hub.retention`, 7 days by
default), so a backup of the evidence is only worth as much as its age
allows. If you record evidence for an incident you must keep, download it:
a local copy is outside Asservat's control and its retention.

## Upgrading

Upgrade the hub's cluster first, then the others. Use the chart that belongs
to the image you install: the chart passes flags to the binary, and an older
binary rejects flags it does not know.

```sh
helm upgrade <release> charts/asservat -n <namespace> -f values.yaml
```

What happens during an upgrade:

- **The hub restarts once.** There is one hub replica, so the console and API
  are away for some seconds. Captures, approvals, watches and queued tasks are
  in PostgreSQL and survive.
- **Agents reconnect by themselves** and take up their watches again.
- **A recording that ends while the hub is away** reports its result when the
  hub is back. Files that rest on the node (core dumps, system call traces)
  are uploaded again then. A packet capture or a profile whose upload the
  restart cuts off is lost, and its recording shows as failed.
- **Open viewers close.** Reload the page to open the file again.
- **An agent that restarts** ends the recordings running on its node. Their
  tasks show as failed with a message that says so.

!!! note
    The database schema is brought up to date by the hub when it starts.
    There is no separate migration step, and a newer hub can read what an
    older one stored. Going back to an older hub after an upgrade is not
    tested.

Descriptions of core dumps improve between versions. When you open a core
dump that an older version described, the hub describes it again from the
stored core and program files. This can take a minute, and the viewer waits
for it.

## Sizing

The numbers below were measured on a three-node cluster. The chart requests
what the components use when idle and sets no limits; set limits that fit
what you record.

| Component | Idle | While working |
| --- | --- | --- |
| Node agent (per node) | 1 millicore, 10 MiB | Runs `tcpdump`, `strace` or `gdb` inside its pod while recording. The sampling profiler takes about 100 MiB while a CPU profile or memory growth is recorded, and gives it back afterwards. |
| Hub | 2 millicores, 36 MiB | Each open packet capture runs a reader of about 150 MiB. Describing a core dump runs `gdb`, and for Python and .NET programs their own tools. |
| PostgreSQL (chart's own) | 10 millicores, 180 MiB | Grows with the audit log, which is kept after captures are deleted. |

Plan disk space for three things:

- **Evidence storage** (`hub.storage.size`, 20 GiB by default): the sum of
  what you record within the retention. A core dump is about as large as the
  process's memory.
- **The hub's work directory** (an `emptyDir`): room for the largest core dump
  of a Python or .NET program, because the hub decrypts it there to read its
  stacks, and for a core dump that is described again.
- **Each node**: a core dump rests in the agent's scratch volume, or for a
  crashed process in the core handler's directory (`agent.coreHandler.hostPath`),
  until its upload ends. The core handler stops writing when less than 10 %
  of the node's disk is free.

The agent image, which every node pulls, is about 60 MiB to pull. The hub
image is several times that: it carries the viewers' tools and the runtimes
that read Python and .NET stacks. Layers are compressed with zstd, which containerd, CRI-O and Docker from
version 23 can read.

## Network

| From | To | Why |
| --- | --- | --- |
| Every node agent | The hub (`agent.hubURL`) | One outbound stream per agent: commands down, evidence up. Workload clusters need no inbound access. Use HTTPS between clusters. |
| The hub | PostgreSQL, and your S3 endpoint if you use one | State and evidence. |
| The hub | Your OIDC issuer, if configured | Sign-in. |
| The hub and agents | The servers in `debuginfodURLs`, distributions' package servers, and Microsoft's symbol server | Debug information for stripped programs, and the helper library for .NET stacks. Set `debuginfodURLs: []` to download nothing; core dumps are then described without. |
| Alertmanager | The hub (`/api/alerts`) | Only if you use watches that record when an alert fires. |

A proxy in front of the hub must allow long-lived connections. The hub
writes a line into every idle stream every 20 seconds, so the usual idle
timeouts of 50 to 60 seconds do not cut them.

## Troubleshooting

### A cluster shows no connected agents

Open **Clusters** in the console. If a cluster lists no nodes, look at an
agent's log:

```sh
kubectl -n <namespace> logs ds/<release>-agent --tail=20
```

- `401 Unauthorized` or `unknown cluster token`: the agent's join token does
  not match the one in `hub.clusters` for that cluster.
- `connection refused` or a timeout: `agent.hubURL` is wrong, or something
  between the cluster and the hub blocks the connection.
- A certificate error: the hub's certificate is not publicly trusted. Set
  `agent.caCert` to its CA certificate.

### A capture stays in "Awaiting approval"

Core dumps, packet captures with payload, system call traces with data and
memory dumps need an administrator's approval. An administrator cannot
approve their own request unless `hub.allowSelfApproval` is set, which is
meant for installations with a single administrator.

### A recording failed

Open the capture in the console. Each recording shows what the agent said.
Common causes:

- **The pod ended before the recording did.** The files recorded up to then
  are kept.
- **No profile endpoint answered.** The application serves none on the
  ports the pod listens on. Use "CPU profile" or "Memory growth" instead,
  which need nothing from the application.
- **A JVM cannot be asked.** It runs OpenJ9, or was started with attach
  disabled or with `-Xrs`. The message says which.

### A crash left no core dump

A crash watch for core dumps needs the agents' core handler
(`agent.coreHandler.enabled=true`) and an approved watch before the crash.
A process that the kernel kills for exceeding its memory limit leaves no
core dump, and neither does one that exits by itself. On the node, the file
`last-core` in the handler's directory says what the handler did with the
last core dump it was given.

### A core dump shows addresses instead of function names

The program is stripped and its debug information could not be found. Check
that the hub and agents can reach the servers in `debuginfodURLs`. Programs
built outside a distribution's packages have no debug information to fetch;
for Go programs Asservat reads function names from the binary itself.

### The audit log

Administrators see who requested, approved, downloaded and opened what under
**Audit log** in the console, or from `GET /api/audit`. The log is kept after
the captures it describes are deleted.

## Further reading

- [Design](./design.md): how each kind of evidence is recorded, the
  permission model and the security properties.
- [README](../README.md): installation and a tour of the console.
