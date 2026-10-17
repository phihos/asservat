# Packet and native-download feasibility lab

Executed 2026-10-09. This is isolated experimental code, not the Asservat collector or a production storage format. The [findings](../../docs/research/feasibility-packet-downloads.md) separate successful tests, failed assumptions and remaining work. All traffic, files, credentials and byte streams are synthetic.

## What ran

| Boundary | Actual evidence | What this does not establish |
| --- | --- | --- |
| Packet engine | Gadget v0.57.0 ran in a disposable Ubuntu/KVM VM with K3s 1.37.1, containerd and Restricted workload pods; native PCAPNG opens in tshark | Supported CNI/kernel matrix, multicluster authority, hostNetwork attribution or pod-loopback coverage |
| Filter language | 11 real libpcap compiler cases; one rejected by Gadget's default compiler; all 11 libpcap programs translated and passed VM kernel verifier/test-run checks | Universal filter grammar, link types, variable headers, hostile compiler input or final Gadget operator injection |
| Dynamic peers | One TCX program/attachment remained across actual EndpointSlice backend replacement, empty membership and resume | It is a standalone observer with periodic relists and synthetic direct-backend traffic, not the finished Gadget adapter, watch freshness protocol or loss qualification |
| Ring pressure | 100,000 writes, 10,000 overlapping snapshot refusals, stable frozen data, age eviction and concurrent access under Go's race detector | The model bounds payload/framing buffers; allocator/metadata accounting, actual Gadget ring plumbing, privacy deadlines and fair upload scheduling remain unqualified |
| Object storage | Actual AWS SDK requests to an isolated SeaweedFS S3 fixture, multipart commit/abort, encrypted data/index objects and authenticated native range decoding | Ceph RGW qualification, KMS, production commit/restore, audit/copy ledgers, bucket policy or backend versioning |
| Developer's file | Gadget PCAPNG → encrypted multipart S3 → TLS download → native tshark open, exact SHA-256 preserved | Production UI/OIDC/SQL and distributed relay integration; the test authority is deliberately in memory |
| Large file | 2 GiB generated stream, encrypted staging only, bounded high-offset range and full checksum-verified retrieval | Production throughput, representative real-core compression, long slow clients or multi-user fairness |

The final ordinary suite has 11 passing tests and three explicitly skipped measurement tests. Those three ran separately in `final-measure`, `final-large` and `final-baseline`, with independent exit/source-hash records. See [test log](results/final-test.log), [large-file result](results/large-stream.json), [measurements](results/storage-measurements.json), [sequential baseline](results/sequential-baseline.json), [kernel filter check](results/kernel-filter-probe.log), [map generations](results/mapprobe.json) and [native-tool check](results/local-tool-validation.txt).

## Safety and ownership

`vm/lab.py` creates a new user-owned QEMU/KVM machine. Its root disk and SSH keys live outside the repository in an owner-only cache directory. No workstation `core_pattern`, BPF hook, capture interface, libvirt domain or existing Kubernetes cluster is changed. The workload manifest enforces Pod Security Restricted. Administrative commands and BPF attachment run only inside the disposable VM. VM probe binaries also require an explicit guard file. Kernel crash tests did not run in this pass.

`services.py` creates only its named/labelled Docker network and S3 fixture: internal network, no published service, 768 MiB/one CPU limit, read-only root filesystem, dropped capabilities and an anonymous data volume. The test runner verifies the fixture label/state and uses its explicit private address. Credentials are synthetic constants, not production secrets. The object-store fixture cannot reach the public network. This is isolation, not proof that its code never attempts telemetry. It is not a new production dependency or a replacement for the selected Ceph reference.

The workstation's nearly full `/tmp` was left untouched. Go temporary build/test files and bounded encrypted staging used the lab cache on the main disk. No paid resource was created. Image/binary SHA-256 values were checked against upstream HTTPS release lists; this run did not independently validate detached supply-chain signatures.

## Reproduce the host-side suite

Prerequisites: supported Go 1.27, C compiler/libpcap development files, Python, Docker, enough disk for encrypted staging and the pinned fixture image. Inspect scripts first; no host package installation is automated. Commands from the workspace root:

```sh
python3 experiments/feasibility/services.py up
python3 experiments/feasibility/run.py test
python3 experiments/feasibility/run.py measure
python3 experiments/feasibility/run.py large
python3 experiments/feasibility/run.py baseline
python3 experiments/feasibility/services.py down
```

The checked-in Gadget PCAPNG is synthetic. Ordinary tests can use it without restarting Kubernetes. `large` writes at most one 2 GiB ciphertext staging file plus the object-store copy before cleanup; frame/index buffers remain bounded. Separate measurement processes make their memory peaks interpretable. Timings are local observations, not a benchmark ranking.

The SQL grant, current-group mapping, OIDC token verifier, real KMS, production manifest/schema, region relay and reservation ledger are **not implemented here**. The in-memory test grant exercises cutoff, expiry, byte accounting and concurrent spends only. A passing test must not be used to advertise those product capabilities.

## Reproduce the VM probes

Use `vm/lab.py up`, then `pin` after cloud-init prints the host public key to the local serial console. Pinning is from that console, not blind SSH trust. `lab.py ssh <command>` addresses only the recorded VM. An existing disk/key/run record is refused; select a fresh `ASSERVAT_LAB_STATE` directory for another lab. The [VM preparation notes](vm/README.md) record pinned downloads, package prerequisites, workload and probe commands. `lab.py down` verifies process ownership before stopping this VM. Remove only this lab's private cache directory after shutdown if the images are no longer needed.

Test sources and results are retained; disposable infrastructure and private keys were removed at the end of the recorded run. The [execution manifest](results/execution.json) records hashes, outcomes and cleanup. No product TASK or entire EXP gate is marked complete by these limited experiments.
