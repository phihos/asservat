# ADR-246 — Node collector role and work channel (S-04 increment 3)

Date: 2026-10-27. Status: accepted; implemented; qualification below.
Requirements: REQ-ARC-003/004 (A-NODE, I-02), REQ-CAP-002/004 (node limits), REQ-NET-001 and
REQ-SYS-001 (capability truthfulness only; no recorder). Plan:
[S-04 plan](../reviews/s04-plan-2026-10-27.md) §2 rows P1/P2, §3 S1 (embedded engine) and S9
(15-second status), §4 row 3, §5 (test environment). Architecture:
[node collector](../architecture/node-collector.md). No migration.

## Problem

Every packet and syscall recorder of S-04 runs on the node. No node process exists: the connector
reads pod status through the Kubernetes API, and every product Pod is Restricted. Before any
recorder can be built (increment 4), the node needs an identity the connector can verify, a
private channel for work and status, an honest statement of what its kernel supports, and node
budgets for rings, frozen snapshots and uploads. None of these may run on a developer
workstation: kind shares the host kernel, so a privileged collector there would be a kernel-global
experiment (AGENTS.md).

## Decision

1. **Role.** `asservat node` is a DaemonSet in its own collector namespace, the only namespace
   with the privileged Pod Security exception (`enforce/audit/warn: privileged`); workload
   namespaces stay `restricted`. The chart template `collector.yaml` is off by default
   (`collector.enabled: false`), requires `mode: cluster` or `combined`, an exact image digest,
   the installation and cluster UUIDs and the connector's endpoint, server name and PEM roots.
   The collector account has no RBAC binding and no automounted token.
2. **Disposable-host guard (plan §5.2).** Every collector Pod mounts the host file
   `/etc/asservat-disposable-host` as a hostPath of type `File`, so the kubelet does not start it
   on a host without that file, and the process checks the file again before reading any input.
   Only the `native.yml` collector job (on its fresh GitHub-hosted runner) and disposable VM images
   create it; `scripts/test-collector.py` refuses to start without it. The guard is removed when
   the collector is qualified for production use, by a later, separately reviewed change.
3. **Identity (reuse of ADR-071/221).** The existing Pod-bound token and identity-free CSR model,
   applied to a DaemonSet instead of an admitted Job: a projected token with the dedicated
   audience `asservat-node:<installation>` (600 s), an in-memory P-256 key per process, the
   shared strict CSR check (`mtls.EnrollmentKey`) and a random epoch per process start. The
   connector reviews the token and reads the token's Pod, its controlling DaemonSet (by its
   current UID) and its Node (UID and kubelet `bootID`, which must equal the boot ID the process
   read from its kernel). It signs a 20-minute client leaf (URI
   `urn:asservat:node:<cluster>:<node UID>:<pod UID>:<epoch>`) with a P-256 issuer held only in
   the connector process's memory. A connector restart therefore invalidates every node
   certificate; collectors re-enroll after a 401. There is no SQL state, audit object or signing
   budget: unlike a download worker, a node certificate unlocks no evidence, key or disclosure,
   only this channel, and the per-node registry keeps one current process.
4. **Channel (I-02).** Outbound HTTPS from node to connector, TLS 1.3, server verified against the
   pinned roots and name only. `POST /internal/v1/node/enroll` (token, no client certificate),
   `/poll` and `/status` (client certificate verified by TLS against the connector's node issuer
   and mapped to the node's current process). Closed JSON wire with canonical decoding, 64 KiB
   per message. Poll is a 25-second long poll returning at most 16 items after the node's last
   sequence; kinds `armSource`, `stopSource`, `snapshot`, `peerGeneration` carry only their
   identity in this version, and typed payloads arrive with the increments that produce them.
   Receipts in the next status remove answered items. One current process per node: another Pod,
   boot or epoch enrolling for the node replaces the earlier process, whose certificates stop
   authenticating, whose queue is dropped and whose open poll ends.
5. **Status cadence (S9).** One report at once after enrollment, then every 15 seconds, sooner
   (but at least 1 second apart, which the connector enforces) when receipts are pending. The
   connector keeps the latest report per node in memory and treats a node without a report for
   45 seconds as not current. It logs one line per enrollment and per assessment change.
6. **Embedded engine (S1).** The collector image is the product binary built with the `gadget`
   tag, which links Inspektor Gadget v0.57.0's local runtime (`pkg/runtime/local`); every other
   build carries a stub reporting the engine as not linked. Its host initialization calls
   `os.Exit` when debugfs or tracefs is missing (and on WSL2), so the adapter checks those facts
   first and reports the engine uninitialized instead. No gadget image is loaded and no registry is
   contacted. The full operator set needed to run a gadget (ebpf operator, OCI handler, gadget
   context) is not linked yet: measured below, it costs far more and is increment 4's decision.
7. **Capability probe.** Once per process: kernel release (≥ 5.15), BTF
   (`/sys/kernel/btf/vmlinux`), cgroup v2, debugfs/tracefs/bpffs (statfs magic on read-only host
   mounts), host processes visible (`kubelet` in `/proc`, host PID namespace), runtime daemon
   (`containerd` or `crio` in `/proc/*/comm`), then one BPF probe: load a two-instruction
   `sched_cls` program and create a TCX ingress link for it against interface index 2³¹−1, which
   a TCX kernel answers with ENODEV without attaching anything. Each fact is `supported`,
   `unsupported`, `denied` (missing privilege) or `unknown`. `Assess` names every missing fact as
   a reason; packet prefers TCX over tc, syscall needs tracefs. Every mechanism reports
   `AdapterUnavailable` with `RecorderNotImplemented` in this build, whatever the probe says.
8. **Node budgets.** `collector.Ceilings` (ring, frozen, upload rate and burst) with a
   no-partial-effect `Budget`: ring and frozen reservations up to the ceiling, an upload token
   bucket that never refills beyond the burst and never consumes on refusal. The local
   administrator's collector-wide ceilings are Helm values (256 MiB ring, 256 MiB frozen,
   32 MiB/s, 64 MiB burst) and set the container memory limit (ring + frozen + 128 MiB).
   EvidenceBudgetPolicy `spec.node` gains optional `maxRingBytes` and `maxFrozenBytes` (≤ 4 GiB);
   `Ceilings.Intersect` takes the tighter value, so policy limits can only lower the ceiling
   (specs/capacity.md: never multiplied). The plan row says "CapacityReservation node limits";
   the node limits live in the EvidenceBudgetPolicy (`CapacityNodeLimits`), and that is where they
   were added. Status reports carry ceilings and usage (zero: nothing reserves yet).
9. **Connector composition.** `NodeChannelServer` (bootstrap) is the listener RunRegional starts
   when its deployment input carries the optional `collector` section (collector namespace,
   DaemonSet, account; server certificate files `node-server.pem`/`node-server-key.pem`; port
   8444). The attestation reads use the observer account. The installer does not yet provision
   that section; until it does, no installed connector serves nodes.

## Privileges added (the key cost)

| Where | Added | Not added |
| --- | --- | --- |
| Each node | 1 Pod; root (uid 0) container that is **not** `privileged`; capabilities `BPF`, `NET_ADMIN`, `SYS_RESOURCE` (all others dropped); host PID namespace; 4 read-only hostPath mounts (the guard file, `/sys/kernel/debug`, `/sys/kernel/tracing`, `/sys/fs/bpf`); runtime-default seccomp and AppArmor; read-only root filesystem; process core dumps disabled | No host network or IPC, no container-runtime socket, no host root filesystem, no Kubernetes API permission, no SQL/evidence/key credential, no `SYS_ADMIN`/`SYS_PTRACE`/`PERFMON` (increments 4 and 10 add what attaching needs, with their measurements) |
| Cluster | 1 namespace with the privileged Pod Security exception | No change to any workload namespace |
| Connector | 1 in-cluster TLS listener (8444); reads: `create tokenreviews`, `get nodes`, `get pods` and `get daemonsets` in the collector namespace; an in-memory issuer key | No write permission, no new SQL role, no hub-facing change |
| Network | Per node 1 kept-alive TLS connection (long poll) plus a status request every 15 s, both node → connector | No inbound connection to nodes |

## Complexity gate (AGENTS.md)

| # | Question | Answer |
|---|---|---|
| 1 | Frequency/harm | Prerequisite of every S-04 recorder; without it no packet or syscall evidence exists. Not an observed failure. |
| 2 | Risk accepted | Yes: plan §2 P1/P2 (maintainer decision 2026-10-26 that all specification features ship) and the architecture's A-NODE privileged DaemonSet. |
| 3 | Typical deployments | Yes: every cluster that records packets or syscalls runs one collector per node. |
| 4 | Precedent | Cilium, Falco, Tetragon, Inspektor Gadget and Retina all run one privileged agent per node; Gadget documents embedding its runtime through a Go API (S1). Bound service-account tokens with Pod/Node claims are the Kubernetes mechanism for workload identity (ADR-071/221 reuse). |
| 5 | Privileges added | See the table: per node 3 capabilities, host PID, 4 read-only hostPaths, no API permission; per cluster 1 privileged namespace; per connector 4 reads and 1 listener. |
| 6 | Failure/degraded states | 2, as the plan's gate row: `NotEnrolled` (no current process for a node; derived, not stored) and `AdapterUnavailable` per mechanism. The current/not-current report flag is derived at read time. |
| 7 | Self-configuration | No knob tunes the channel itself (all timings are constants). The ceilings are the local administrator's resource limits required by specs/capacity.md. |
| 8 | External dependencies | Kernel features (BTF, cgroup v2, TCX ≥ 6.6 or tc), Kubernetes ≥ 1.30 bound-token node claims, kubelet `bootID`, Inspektor Gadget v0.57.0 and cilium/ebpf v0.22.0 (both pinned). |
| 9 | Cost at scale | Per node: 1 Pod (64 MiB request, idle Go process with the engine linked), 1 TLS connection, 4 small requests per minute (one status ≈ 1–2 KiB). Per connector at 5,000 nodes: ≈ 333 status writes/s into memory, ≤ 10,016 connections, 1 TokenReview + 3 GETs per enrollment (once per process start and every ≈ 19 minutes per node: ≈ 4.4 enrollments/s at 5,000 nodes, ≈ 17.5 API calls/s). No watch, no SQL, no hub traffic. Binary: the gadget-tagged collector binary is 131.4 MB vs 91.4 MB without (+40 MB, 17 more linked modules; go.mod gains Inspektor Gadget and 25 indirect modules, cilium/ebpf directly). The full gadget runtime (ebpf operator, OCI handler, gadget context) measured 169 indirect modules, two forked `replace` directives and a 92 MB binary on its own, which is why it is deferred to increment 4. |
| 10 | Upgrade/rollback | Helm toggle off removes the namespace and DaemonSet; no workload object changes (tested natively). No migration; the budget-policy fields are optional. The connector input section is optional and absent by default. |
| 11 | Smaller fix | A per-capture privileged Job cannot hold a ring and re-attaches for every capture (plan P1). Reusing the download-worker SQL enrollment would add an audit object, signing budget and SQL state per node process for a certificate that unlocks no evidence. Polling status without long-poll work delivery would add up to 15 s to every trigger. |

Benefit established; the privileges are the minimum the probe needs and are quantified above:
proceed.

## Remaining limits

- **No recorder or work producer**: every mechanism is `AdapterUnavailable`; increment 4 adds the
  packet gadget, the attach path and the privileges it needs.
- **Installer provisioning** of the connector's `collector` input (server Secret and Service, the
  four attestation reads, the chart's endpoint and roots) is not implemented; the native suite
  hosts the connector's real listener component in the test process.
- **Budget policy node limits** are accepted and intersectable but not yet read at admission
  (increment 6 reserves rings).
- **Engine**: only the local runtime's host initialization is exercised; no gadget runs.
- **S-03 node-local readers (backlog, not implemented).** ADR-241 refused the resource options
  that need node-local cgroup files (CPU throttling, memory growth rate, PSI) and stdout/stderr
  stream filters for log triggers, pending a node-local reader. This role is the intended host
  for both: it already runs once per node in the host PID namespace with an attested identity and
  a status/work channel to the connector, so detector readings would travel as typed work and
  receipts on this channel instead of a second node agent. Each needs its own read-only host
  mount (the host cgroup v2 hierarchy for cgroup files, `/var/log/pods` for container log
  streams), which this increment does not add, and its own gate answers (exposure of other
  tenants' cgroup and log files on the node, read cost per tracked Pod per poll).
- **Probe once per process**: kernel facts do not change without a reboot (which is a new
  process); the engine and BPF facts are not re-probed.

## Qualification

Results are in [implementation progress](../implementation-progress.md#s-04-increment-3-node-collector-role-adr-246-2026-10-27).
