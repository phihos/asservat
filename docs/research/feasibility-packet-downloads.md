# Packet recording and encrypted-download feasibility

Executed 2026-10-09 after the maintainer authorized the first mechanism spikes. [Sources, executable tests and raw results](../../experiments/feasibility/README.md) are retained. This report adds partial measured evidence to EXP-02/05/10/19 and native-download qualification. It does **not** complete those broad release gates or start product implementation. HTTP sanitization (EXP-03) and pod files/commands (EXP-04) were not exercised.

## Conclusions and decisions

1. **Keep Inspektor Gadget**, but plan an explicit Asservat integration for peer generations and observation-point coverage. Actual pod traffic capture works in the tested environment. Unmodified Gadget is not the complete recorder described by the specification.
2. **Keep actual libpcap compilation.** One valid IPv6 expression failed Gadget's bundled compiler. The libpcap-produced programs passed the separate kernel execution corpus through the same cbpfc translation dependency used by Gadget. The remaining work is integrating that compilation path into the pinned Gadget operator and qualifying broader syntax/link types.
3. **Continue with independently compressed, complete Tink-encrypted frames and an encrypted index.** The approach preserved a real PCAPNG and supported a bounded near-end read of a 2 GiB stream. Use **8 MiB native frames as the next prototype baseline**, subject to broader workload measurements. This is not a production format freeze or a new accepted manifest enum.
4. **Keep native downloads in the first complete product slice.** The lab demonstrated the essential capture/store/download/open path. A download implementation must withhold its final delivery batch until full-file final integrity checks succeed; a late server error after sending every byte is insufficient.
5. **Keep bounded rings and separate snapshot reservations.** The tested model resisted a snapshot storm without growing its payload buffers or corrupting an accepted snapshot. Actual allocator/metadata costs, Gadget wiring and workload scheduling still require qualification.

## Environment and scope

The disposable KVM VM had two vCPUs, 2 GiB RAM, Ubuntu 24.04, Linux 6.8.0-142 with BTF, K3s v1.37.1+k3s1 and containerd 2.3.4-k3s1. Two small Python Deployments and a UDP Service ran in a namespace enforcing Pod Security Restricted. All packet payloads were generated for this experiment. The Gadget v0.57.0 CLI and tcpdump image were pinned; the [environment record](../../experiments/feasibility/results/vm-environment.txt) records the workload and gadget digests.

Host-side Go tests used the actual AWS SDK against a pinned SeaweedFS 4.48 S3 fixture on a private Docker internal network, with no published service or public egress. This is a convenient maintained **test backend**, not Ceph qualification or a production storage selection. A TLS test server implemented delivery using an explicitly synthetic, in-memory access authority. No real evidence, existing cluster, host capture interface, host crash setting, paid infrastructure or external account was used.

The lab used encrypted local staging while preparing multipart uploads. It did not test a fully piped collector-to-S3 path, node-loss durability or production spool admission. KMS wrapping, the SQL/audit/copy ledgers, OIDC, multicluster relays and CSI analysis storage remain absent. Release SHA lists were fetched over upstream HTTPS; independent detached-signature verification remains a supply-chain gate.

## Packet results

| Check | Actual result | Limit / implication |
| --- | --- | --- |
| Real pod/veth capture | Gadget produced a 101,968-byte PCAPNG with 1,012 records from the synthetic pod traffic. tshark opened it | One amd64/K3s/containerd/flannel environment; this does not qualify every CNI, node or target type |
| Native file journey | Original and downloaded PCAPNG both had SHA-256 `00a762cb5cc6951c4bbcdfd7ed08a6403623c7d8a6f96b4bffa1282921a87b8f`; tshark read all 1,012 downloaded records | Native-tool readability and exact bytes proven for this artifact. The full production UI/identity workflow is not implemented |
| Capture-expression comparison | All 11 libpcap sample expectations matched; Gadget's compiler rejected `ip6 and dst host 2001:db8::2` with an out-of-bounds jump error | The comparison test's successful execution is **not** a Gadget parity pass. [Case results](../../experiments/feasibility/results/filter-parity.json) retain the failure |
| Kernel execution of libpcap output | All 11 translated programs passed the VM verifier and `BPF_PROG_TEST_RUN` with expected results | Ethernet IPv4/IPv6 TCP/UDP samples, no actual Gadget operator injection or universal grammar claim |
| Service endpoint generations | One attached TCX observer/program stayed in place while a real Service backend changed. Final run counted 360 packets under the old peer, 594 under the new peer, zero under an intentionally empty generation and 220 after resuming | Standalone map adapter, direct-backend synthetic traffic and periodic relists. It does not establish production watch freshness, packet-event generation provenance or absence of all transition loss |
| NAT/observation point | Gadget output included both the Service VIP and backend addresses. An initial cni0 probe driven only by Service-VIP traffic did not establish new-generation coverage | Keep `backends`/`virtualIP`/`both` explicit and qualify hook position; do not use a successful map swap to claim Service attribution |
| Readiness during rollout | The first direct-backend probe stopped on UDP connection refusal; the final probe counted six transient send errors and still completed | Endpoint readiness is not a guarantee that the application is already listening. Diagnose and report those failures; do not terminate observation merely because the observed workload fails |
| Loopback | Default host attachment found no usable interface; explicit `--iface lo` captured 400 records for 200 generated datagrams | Loopback can yield ingress/egress observations of the same datagram. Explicit VM host-loopback attachment does not establish automatic pod-loopback coverage or hostNetwork attribution |

Source context: [Gadget Go API](https://inspektor-gadget.io/docs/main/api/golang/), [pinned compiler](https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.57.0/pkg/libpcap-compiler/cbpf.go), [TC handler](https://github.com/inspektor-gadget/inspektor-gadget/blob/v0.57.0/pkg/tchandler/tracer.go) and [kernel map replacement](https://docs.kernel.org/bpf/map_of_maps.html). The observations above come from this lab, not from interpreting documentation as proof of integration.

## Storage and transfer results

The candidate uses one data object containing complete independent Tink streams, one per zstd-compressed frame, and a separately encrypted authenticated index object. Data and index use fresh independent keysets. The index binds native/cipher offsets, sizes and checksums; frame AAD binds experiment identity, sequence and native offset. This is storage composition using library primitives, not custom nonce or AEAD segment cryptography. The real product still needs cluster/media/schema scope, wrapped keys, provenance, retention and commit contracts.

| Final 2 GiB incompressible-stream run | Observation |
| --- | --- |
| Native bytes / frames | 2,147,483,648 bytes / 256 × 8 MiB frames |
| Ciphertext / encrypted index | 2,147,632,640 bytes / 65,601 bytes |
| Encode plus multipart upload | 22.43 seconds |
| Retrieve last 1 MiB | 26.95 ms; 8,389,190 ciphertext bytes read |
| Full verified native retrieval | 7.49 seconds |
| Test-process peak RSS | 136,188 KiB, approximately 133 MiB |

These are single local measurements after the final integrity correction, with fixed synthetic data, an explicit one-CPU storage fixture and ciphertext-only staging. They are not a supported throughput promise. The test generated the source incrementally, checked the high-offset bytes independently and verified the whole native SHA-256 during complete retrieval. [Exact result](../../experiments/feasibility/results/large-stream.json).

The separate 64 MiB comparison tried 8/16/32 MiB frames on compressible and incompressible streams. A 1 MiB native read at offset 49 MiB required roughly 8/16/32 MiB of incompressible ciphertext respectively. The single-stream baseline read 53,477,377 ciphertext bytes to reach and return that range. Frame size trades read amplification and memory against compression/metadata efficiency. Keep the smaller measured frame as the next baseline; include real diagnostic-shaped synthetic datasets before freezing it. [Measurements](../../experiments/feasibility/results/storage-measurements.json), [baseline](../../experiments/feasibility/results/sequential-baseline.json).

Negative tests covered wrong/malformed ranges, multiple-range rejection, If-Range mismatch, source/index corruption, inconsistent index offsets/identity, decompression expansion, cancellation, expired/revoked resumes, byte-budget concurrency, a mid-transfer 1 MiB cutoff, interrupted multipart abort and final checksum failure. The final checksum test exposed an implementation trap: detecting failure after emitting all declared bytes may leave the client with an apparently complete HTTP response. The corrected experiment checks the full checksum before releasing the final bounded batch. Range-only reads verify their authenticated indexed frames; completing a resumed local file still requires the whole-file checksum.

The test grant is not a substitute for real authorization. It has no OIDC, group revocation, distributed leases, transactional pre-reservation, audit commit or failover. The storage code also lacks the production orphan ledger and conditional-create protocol; its deliberate corruption tests overwrite fixture objects. Do not promote this package into product code without implementing those boundaries.

## Ring and storm results

The race-tested model uses a 16 KiB live payload/framing buffer and a separately reserved 16 KiB frozen copy. During 100,000 writes, 10,000 competing snapshot attempts were refused while the accepted snapshot remained byte-identical. Oversized records were rejected, old segments were evicted, concurrent writes/saves remained race-free and duplicate release did not release capacity twice.

This validates a bounded-copy implementation option, not the full REQ-NET-003 gate. It deliberately does not claim a 32 KiB RSS ceiling: Go metadata, allocator overhead, packet parsing, queues and SDK buffers need separate accounting. Actual capture-rate pressure, node-wide budgets, upload stalls, fairness and retention enforcement remain required integration tests.

## Remaining work before enabling these product capabilities

1. Integrate libpcap bytecode, peer generation maps and generation-tagged output into one pinned Gadget adapter/image. Test packet and syscall coexistence, target rollout/UID reuse, IPv6, multiple EndpointSlices, stale watches, empty/deleted/reassigned peers and actual transition loss.
2. Qualify each observation profile, including pod loopback, CNI/NAT/VIP behavior and unsupported hostNetwork cases. Measure impact and gaps; never advertise generic complete pod capture based on a veth-only test.
3. Specify and test the persistent framed artifact format, encrypted index/page bounds, key wrapping, conditional commit, immutable versions, orphan cleanup, restore and copy-ledger charging. The current `tink-streaming-aead/v1` enum must not be reused for the experimental layout.
4. Exercise real Ceph RGW and KMS, slow/interrupted connections, regional relays, multiple users, current SQL/OIDC authority and incident-priority scheduling. The basic native file workflow must remain available while advanced analysis is unavailable.
5. The next two mechanism spikes were outside this pass and have since produced [SQL/crash-path findings](feasibility-control-crash.md). Those limited transaction/kernel results do not complete production authority, durable wrapped-key or Kubernetes-attribution qualification.

The appropriate next product step remains the first authorized context-capture/download vertical slice after those foundational risks are resolved. No collector capability or complete EXP release gate is marked ready from these results alone.
