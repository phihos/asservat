# ADR-309: Bounded whole-Pod process discovery

Status: implementation in progress; installed qualification pending.

REQ-ACT-007 and REQ-GDE-002 require an ordinary, explicit process discovery
capture. A PID from a process name or the lowest PID in a Pod cgroup cannot
supply the runtime-identified initial process, especially in shared process
namespaces. This increment adds the process inventory foundation for guidance,
file and core workflows. It does not implement those entire workflows or claim
qualified socket ownership, runtime detection or build-ID extraction.

Use `inspect-processes/v1` through existing capture preview, current ordinary
collection eligibility, quotas, audit, one-use dispatch, encrypted custody and
independent publication. It is finite, on trigger, whole Pod, with a 2 MiB native
JSON ceiling, five-second action and ten-second recipe. No live listing endpoint,
container selector, implicit acquisition, argv/environment or user-memory read.
Native download remains mandatory; saved views use the existing
`get_target_discovery` contract and current evidence plus target eligibility.

The installer explicitly selects `containerd`. CRI lists pin the exact Pod
sandbox and full container IDs; nonverbose ContainerStatus pins restart/state.
Containerd's published Tasks.Get with empty ExecID and fixed `k8s.io` namespace
supplies each initial PID. The existing pinned containerd API dependency is
reused. CRI verbose status would return OCI argv/environment; it is never a
fallback. CRI-O is Unsupported until a metadata-only PID source is qualified.

Add only the selected runtime socket and read-only host cgroup hierarchy to the
existing collector. A read-only socket mount **does not restrict runtime RPCs**:
a compromised collector could exercise the daemon's broader API. This is an
accepted implementation cost of exact runtime identity, not a claim of runtime
API confinement. Application code issues bounded List/Status/Tasks.Get only.
Target callers cannot select socket paths. Workload Pods remain Restricted;
the collector remains privileged:false with its existing capability set,
including SYS_ADMIN/SYS_PTRACE, and its disposable-host qualification barrier.

A joined locked thread uses the existing argument-reader pattern to enter the
node cgroup namespace, then restore it. This changes the reading view, not
application cgroup membership. Restoration failure retires the thread and
returns no inventory. Runtime metadata, kernel PID/start ticks, full cgroup
path/inode and node boot are checked before and after the finite read. A changed
main/runtime identity aborts the artifact; no PID or Pod substitution. Exited
sources and disappearing descendants are explicit gaps. Paths and IDs remain
potentially sensitive evidence and are escaped in the UI. Recorded identities
are observations; every later process-affecting action must revalidate them.

Configured limits are 64 runtime instances and 256 processes per Pod, with fair
bounded slices. Two initial filtered runtime lists replace the early one-list
estimate. At most 128 nonverbose status and 128 Tasks.Get reads follow (258 RPCs
total); each uses the original action deadline, at most five seconds. There are
no retries, watches or runtime autodetection. At most 256 cgroup directories and
256 retained process rows are enumerated; limits produce explicit coverage.
One joined acquisition goroutine and two setns calls per action; zero idle
process-discovery goroutines, connections, timers or API calls. The runtime
connection is opened for the action and closed after join. Existing finite
collector memory/storage reservations and connector holder limits are shared;
these configured bounds are not measured resource qualification.

Complexity review: the missing capability is an accepted first-release outcome,
not a hypothetical incident restriction; it benefits ordinary diagnostics.
Existing CRI/containerd and Gadget namespace patterns provide precedent. Added
cost is two collector mounts and the daemon exposure above, no new dependency,
credential, Kubernetes RBAC, table, service, helper executable or BPF image.
Complete/partial and changed-target refusal use existing capture outcomes.
Runtime selection is installation wiring, not a tuning framework. Removing it
removes both added mounts and leaves old collectors unchanged. A kernel-only
PID heuristic or a verbose-OCI fallback would not satisfy the selected
identity/privacy contract. Actual combined resource, authority and installed
workflow qualification remains required before claiming feature delivery.

References: [actions](../../specs/actions.md), [targeting](../../specs/targets.md),
[guidance](../../specs/guidance.md), [node collector](../architecture/node-collector.md),
[upstream Gadget installation](https://inspektor-gadget.io/docs/v0.54.1/reference/install-kubernetes/)
and [local manager](https://inspektor-gadget.io/docs/v0.54.1/spec/operators/localmanager/).

Saved process projections remain class `extract` under REQ-GDE-006. The native
inventory is class `metadata` because its explicit field set excludes arguments
and user memory; those classifications do not make either source public.
`get_target_discovery` requires current workload-maintainer rights and the
original retained audience, with no share fallback. It spends two configured
query units and one authenticated native batch; the 256 MiB worker declaration
is a candidate bound, not a measured resource result. Cursors bind the original
capture, artifact, protected version and section. Paging and size refusals follow
full authenticated EOF; a row is never split, rewritten or silently skipped.

`cancel_capture` uses a distinct process-stop scope and joined process/writer
receipt through the existing signed control channel. Queue acknowledgement is
not termination. Stop before dispatch prevents a late start; after dispatch the
original runtime reader, namespace restoration, body reader and writer must join
before `Cancelled`. Stored results win over a late cancellation. Original
storage/query charges, deadlines and uncertain outcomes remain unchanged.
No new durable cancellation journal, role, timer or background watcher is added.

This version accepts one manual process action. Policy process acquisition and
mixed process compositions remain explicitly unsupported; file/core actions,
network-flow attribution and arbitrary process targeting remain separate work.
The collector shares the existing 64 active finite-acquisition slots and frozen
byte budget. The connector shares 64 held captures and its 32 MiB store FIFO.
A process result has one at-most-2-MiB source buffer; connector node/boot checks
and the independent encrypted-writer native checker both parse those bytes.
They do not refetch the source. Actual combined memory/CPU under the full
collector load and installed containerd/namespace behaviour still need proof.

Initial installation adds `processSnapshot` to the seed policy's supported
human-client evidence types. Existing explicit administrator policy lists are
unchanged. The five-type seed on this branch must become the six-type union
when the separately qualified logs seed is integrated; neither list may be
silently overwritten.

The installed reference is a separate pending qualification: two regular
Restricted containers with private argument/environment canaries, one ordinary
capture, native JSON download, and explicit MCP plus real React saved reads of
the same original. Each read uses two configured units and one three-key batch;
the original eight-record installer backing is retained, with four read units
required for these two queries. A second finite capture attempts Stop only when
Running is observed. Natural completion before cancellation is reported as an
unqualified installed blocked-source case. Repeat restores the original saved
recipe into a fresh preview; it does not claim a repeated acquisition. The
existing 20-minute hosted bound and inner 18-minute two-cluster bound are
unchanged. No collector is run on the workstation.
