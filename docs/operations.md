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

!!! warning
    The chart keeps the master key and the database password by looking
    them up in the cluster when it renders. Tools that render without a
    cluster (`helm template | kubectl apply`, Argo CD) get new ones at
    every render: applying that replaces the master key, and the stored
    evidence can no longer be read. Install and upgrade with `helm`
    itself, or keep the Secret out of what such a tool applies.

Save the master key:

```sh
kubectl -n <namespace> get secret <release>-hub -o jsonpath='{.data.master-key}' > master-key.b64
```

Back up the chart's PostgreSQL with `pg_dump`:

```sh
kubectl -n <namespace> exec <release>-postgres-0 -- pg_dump -U asservat asservat > asservat.sql
```

Back up the evidence on the hub's volume (with an S3 bucket, use your
bucket's own backup instead):

```sh
kubectl -n <namespace> exec deploy/<release>-hub -- sh -c 'cd /data && tar -cf - -- *' > evidence.tar
```

### Restore

The end-to-end test runs these steps on every change: it deletes the hub's
database, volumes and Secret and brings a capture back with its file.

1. Put the master key back before you install. The Secret belongs to the
   chart's release, so mark it as Helm's; the chart then keeps the key and
   fills in the rest:

```sh
kubectl -n <namespace> create secret generic <release>-hub \
  --from-literal=master-key="$(base64 -d < master-key.b64)"
kubectl -n <namespace> label secret <release>-hub app.kubernetes.io/managed-by=Helm
kubectl -n <namespace> annotate secret <release>-hub \
  meta.helm.sh/release-name=<release> meta.helm.sh/release-namespace=<namespace>
```

2. Install the chart with your values:

```sh
helm install <release> charts/asservat -n <namespace> -f values.yaml
```

3. Stop the hub and load the dump into a database that is empty. The hub
   creates its tables when it starts, so the database it has just made has to
   go first:

```sh
kubectl -n <namespace> scale deploy/<release>-hub --replicas=0
kubectl -n <namespace> exec <release>-postgres-0 -- psql -U asservat postgres -c 'DROP DATABASE asservat'
kubectl -n <namespace> exec <release>-postgres-0 -- psql -U asservat postgres -c 'CREATE DATABASE asservat OWNER asservat'
kubectl -n <namespace> exec -i <release>-postgres-0 -- psql -U asservat asservat < asservat.sql
```

4. Start the hub and put the evidence back. The hub finds the files by the
   names in the database:

```sh
kubectl -n <namespace> scale deploy/<release>-hub --replicas=1
kubectl -n <namespace> rollout status deploy/<release>-hub
kubectl -n <namespace> exec -i deploy/<release>-hub -- tar -C /data -xf - < evidence.tar
```

!!! note
    `DROP DATABASE` fails while the hub is still connected. Wait until the
    hub's pod is gone after scaling it down.

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
- **Agents reconnect by themselves** and take up their watches again. An
  agent waits five seconds at the most between two tries and gives a try
  that meets no answer three, so it is back at the latest eight seconds
  after the hub answers again. Until then the hub refuses requests for its
  cluster ("no agent of this cluster is connected").
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
    older one stored: after every change, the published images of the
    commit before are installed, recorded with and upgraded, and what was
    recorded before has to read the same after. Going back to an older hub
    after an upgrade is not tested.

Descriptions of core dumps improve between versions. When you open a core
dump that an older version described, the hub describes it again from the
stored core and program files. This can take a minute, and the viewer waits
for it.

### Removing Asservat from a node

When the agents stop, they put the node's `kernel.core_pattern` back as it
was. With the core handler enabled, its directory on the node
(`agent.coreHandler.hostPath`, `/var/lib/asservat` by default) stays: it
holds the handler's program and any core that was not uploaded yet,
readable by root only. Delete it on each node after you uninstall. An agent
that was killed instead of stopped could not put the pattern back; the next
agent on that node does, so let the agents start once more before you
remove the directory, or set the pattern yourself.

## Sizing

The numbers below were measured on a three-node cluster. The chart requests
what the components use when idle and sets no limits; set limits that fit
what you record.

| Component | Idle | While working |
| --- | --- | --- |
| Node agent (per node) | 1 millicore, 10 MiB | Runs `tcpdump`, `strace` or `gdb` inside its pod while recording. The sampling profiler takes about 100 MiB while a CPU profile or memory growth is recorded, and gives it back afterwards. |
| Hub | 2 millicores, 36 MiB | Each open packet capture runs a reader of about 150 MiB. Describing a core dump runs `gdb`, and for Python and .NET programs their own tools. |
| PostgreSQL (chart's own) | 10 millicores, 180 MiB | Grows with the audit log, which is kept after captures are deleted. |

The hub's idle cost grows with the nodes whose agents are connected, by
about 30 KiB each: with 1,000 connections held open it used 78 MiB and
1 millicore, with 5,000 it used 194 MiB and 3 millicores, and answered the
API as fast as before. These connections were simulated on one machine.

A capture costs the hub by the pods it records. With agents that were
simulated but did their part, a status at the start and the end and a
file of 64 KiB for each pod, one capture took the hub 0.8 seconds of
processor time and 116 MiB at its peak for 500 pods, 3.4 seconds and
352 MiB for 2,000, and 8.8 seconds and 777 MiB for 5,000; it was complete
after 4, 17 and about 45 seconds, most of which PostgreSQL spends
committing the pods' reports one after another. The memory is what the files take while they arrive, about
150 KiB for each that is being stored at that moment.

An agent's cost while recording grows with the pods it records on its
node, since each recording runs its own `tcpdump` or `strace`. Measured
with 200 pods on one node (8 CPUs), all recorded at once for 5 seconds: a
capture of logs, pod state and packet headers was complete after 12 seconds
and took the agent's memory to 285 MiB at its peak, about 1.4 MiB for each
pod; system call traces of all 200 were complete after 12 seconds as well.
Two minutes later the agent was back at 26 MiB.

A watch for packets keeps one `tcpdump` running for each pod it watches, so
that a capture can begin before the moment it waited for. On the same node
a watch on all 200 pods held the agent at 329 MiB, about 1.6 MiB for each
pod, and at 2 millicores while nothing happened. When all 200 containers
were killed at once, the watch made a capture for each. The memory is
taken as long as the watch waits: watch the workloads you expect to fail,
not every pod of a cluster.

Plan disk space for three things:

- **Evidence storage** (`hub.storage.size`, 20 GiB by default): the sum of
  what you record within the retention. A core dump takes about as much as the
  memory its process used. Its size as shown and as downloaded is that of
  everything the process mapped, which can be far more: what the process
  never touched is not stored. The file's size in the console says on
  hover what the hub stores of it, and `asservat_evidence_bytes` counts
  that.
- **The hub's work directory** (an `emptyDir`): room for the largest core dump
  of a Python or .NET program, because the hub decrypts it there to read its
  stacks, and for a core dump that is described again.
- **Each node**: a core dump rests unencrypted in the agent's scratch volume,
  or for a crashed process in the core handler's directory
  (`agent.coreHandler.hostPath`), until its upload ends, and is deleted then.
  It holds the process's memory, so keep that directory readable by root only. The core handler stops writing when less than 10 %
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

### The agent's log says "Failed to load" while a profile is recorded

The sampling profiler reads the programs of every process on the node, not
only of the pods it records, and logs each one it cannot read, such as
`Failed to load /app/erts-17.0.2/bin/beam.smp ... symbol not found`. These
lines come from the profiler itself, as warnings or errors. In a profile
only the stacks of the program that a line names are incomplete.

### The audit log

Administrators see who requested, approved, downloaded and opened what under
**Audit log** in the console, or from `GET /api/audit`. The log is kept after
the captures it describes are deleted.

## Further reading

- [Design](./design.md): how each kind of evidence is recorded, the
  permission model and the security properties.
- [README](../README.md): installation and a tour of the console.
