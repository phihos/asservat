# Node collector role and work channel

[ADR-246](../decisions/246-node-collector-role.md) implements S-04 increment 3 of the
[S-04 plan](../reviews/s04-plan-2026-10-27.md): the A-NODE `asservat node` process, the I-02 node
work channel to the cluster connector, the capability probe and the node budgets. It records
nothing yet; increment 4 adds the first recorder.

## Components

| Package | Component | Role |
| --- | --- | --- |
| `internal/domain/collector` | C-24 | Probe facts and their assessment (`Assess`), node `Ceilings`/`Budget` (ring, frozen, upload token bucket), `StatusCadence`, closed work kinds and receipts, attested `Identity` |
| `internal/application/delivery` | C-19 | `NodeChannel`: enrollment, one current process per node, certificate lookup, bounded per-node work queue with long poll, latest report per node |
| `internal/transport/node` | C-20 | HTTP handler (connector) and client (collector) for `/internal/v1/node/{enroll,poll,status}`; wire ↔ domain conversion with closed-value validation |
| `internal/contracts/node_channel.go` | C-20 | Closed wire DTOs, `NodeDeployment` input, fixed paths and the dedicated token audience |
| `internal/adapters/kubernetes/node_attester.go` | C-21 | TokenReview plus live Pod/DaemonSet/Node checks |
| `internal/adapters/mtls/node.go` | C-21 | Connector's in-memory node issuer and server TLS config; collector's process key and leaf |
| `internal/adapters/linux` | C-23 | File probes (procfs, sysfs, statfs magics, `/proc/*/comm`) and the one BPF probe |
| `internal/adapters/gadget` | C-23 | Embedded Inspektor Gadget v0.57.0 local runtime (build tag `gadget`), stub otherwise |
| `internal/bootstrap/node.go`, `node_channel.go`, `regional_nodes.go` | bootstrap | `asservat node`, `NodeChannelServer`, the connector's optional `collector` input |

## Flow

1. The kubelet starts the DaemonSet Pod only on a host carrying `/etc/asservat-disposable-host`
   (hostPath type `File`); the process checks the file again and stops otherwise.
2. The process disables its core dumps, reads `node.json`, reads the kernel boot ID, probes the
   node once (files, then one `sched_cls` program load and a TCX link attempt against a
   non-existent interface, then the engine), generates a random epoch and a P-256 key.
3. Enrollment: `POST /internal/v1/node/enroll` with the projected token (audience
   `asservat-node:<installation>`, 600 s), an identity-free CSR, the boot ID and the epoch, over TLS
   1.3 to the pinned connector name and roots. The connector reviews the token, reads the token's
   Pod (running, undeleted, controller = the named DaemonSet with its current UID, on the token's
   node, with the collector account) and Node (UID and kubelet `bootID` equal to the claimed boot
   ID), then signs a 20-minute client leaf whose URI names cluster, node UID, Pod UID and epoch.
4. Status: one report immediately, then every 15 s (S9), sooner but at least 1 s apart when work
   receipts are pending. A report carries the facts, the per-mechanism assessment, the node budget
   and receipts. The connector keeps only the latest report per node, in memory; a node without a
   report for 45 s is not current.
5. Work: the collector long-polls (25 s hold) for work after its last sequence. Kinds are
   `armSource`, `stopSource`, `snapshot`, `peerGeneration` (no producer; refused with
   `RecorderNotImplemented`, `WorkExpired` or `WorkUnknown`) and `packetCapture`
   ([ADR-248](../decisions/248-manual-packet-capture.md), the only kind with a typed payload).
6. Renewal at one minute before expiry, with the same key and epoch. A 401 (connector restarted
   or process replaced) leads to a fresh enrollment with the same key and epoch.
7. One current process per node: any enrollment for the node by another Pod, boot or epoch
   replaces the earlier process; its certificates stop authenticating, its queued work is dropped
   and its open poll ends.

## Assessment

`Assess` requires, for both mechanisms: kernel ≥ 5.15, BTF, cgroup v2, BPF program load, host
processes visible (host PID namespace), a known runtime (containerd or CRI-O daemon observed) and
an initialized engine; packet additionally TCX (preferred) or tc, syscall additionally tracefs.
`Prerequisites` reports whether they hold. ADR-248: the packet recorder is `Available` when they
hold (hook `tc`: the gadget attaches tc `clsact` classifiers; TCX alone is not enough); syscall
recording stays `AdapterUnavailable` with `RecorderNotImplemented`.

## Manual packet capture (ADR-248)

1. The hub asks the target's region (`packet-recorder` pre-work query) whether the Pod's node
   offers the recorder; only then is a manual networkHeaders plan requestable.
2. The ADR-171 start prepares the attempt's keys at the connector and, instead of acquiring,
   `start-recording` queues `packetCapture` on the Pod's node (program, digest, duration, cap)
   and hands the keys to the connector's recording holder.
3. The node runs the pinned tcpdump gadget on the Pod's veth pairs for the duration, runs the
   hub-compiled program on each frame, cuts frames at the transport header and uploads one
   bounded PCAPNG to `/internal/v1/node/capture`.
4. The holder encrypts and stores it with the artifact producer (four write-only objects) and
   keeps the writer completion; the hub-api collect loop runs a `collect-recording` exchange and
   records the stored completion; publication verifies with the headers-only recheck.

## Limits

Enrollment: claims precheck without API calls, then 5/s globally (burst 20), one per source
address per 5 s (burst 3), 8 attestations in flight; refused with 429. At most 5,000 nodes per connector, 64 queued items and 16 per poll, 64 receipts per report, 64 KiB
per message (256 KiB per poll answer), three connections per node (15,016 in total), 20-minute leaves with at most two per
process. Node ceilings default to 256 MiB ring, 256 MiB frozen, 32 MiB/s upload with a 64 MiB
burst, and bound the container memory limit (ring + frozen + 128 MiB).

## Not yet

The regional installer provisions the connector's `collector` input (Secret, Service and public
ConfigMap `connector-nodes`, the four attestation reads; ADR decision 9), but no native run has
installed it yet. Only manual packet captures exist (no rings, policy arming or snapshots);
budget policy node limits are accepted by the schema but not yet intersected at admission. See the
ADRs.
