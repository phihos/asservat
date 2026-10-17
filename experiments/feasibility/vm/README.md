# Disposable VM preparation and probes

These commands belong **inside the new disposable VM**, unless explicitly described as host commands. Never run BPF probes or installation commands on the workstation. See the [lab boundary](../README.md).

`lab.py up` downloads the pinned Ubuntu 24.04 image, validates its upstream HTTPS SHA-256, creates a 10 GiB sparse overlay and boots a two-vCPU/2 GiB VM with user-mode networking and a loopback-only SSH forward. The [image record](../results/vm-image.json) and [environment](../results/vm-environment.txt) give the exact tested inputs. No host folder, Docker socket or existing kubeconfig is shared with the guest.

Inside the VM, install the distribution packages `clang llvm libbpf-dev libpcap-dev tcpdump tshark iproute2 python3 gcc make linux-tools-generic`. The standalone `bpftool` package name had no installation candidate in this image; `linux-tools-generic` supplies the relevant tools. Package installation logs are retained. Download the recorded [Gadget release](../results/gadget-cli.json) and [K3s release](../results/k3s-release.json), verify their SHA-256 lists, install only inside the VM, and launch:

```sh
systemd-run --unit asservat-k3s /usr/local/bin/k3s server --disable traefik --disable servicelb --disable metrics-server --disable local-storage --write-kubeconfig-mode=600
k3s kubectl apply -f /root/workload.yaml
k3s kubectl -n asservat-lab rollout status deployment/sender --timeout=90s
k3s kubectl -n asservat-lab rollout status deployment/sink --timeout=90s
```

Copy the checked-in [workload](workload.yaml) to that path using the lab SSH channel. Its tested Python image digest is recorded in the environment file; use that digest when reproducing rather than relying on the authored convenience tag. Only the VM's synthetic namespace is observed.

Pull/verify the Gadget tcpdump image once, record its digest, then disable pulling for the run. The recorded image is `ghcr.io/inspektor-gadget/gadget/tcpdump@sha256:2176a5bd659841ad7bdbed1633a52b744ccb4232f3fd567e2388361ddd8e047a`.

```sh
/opt/ig/ig run ghcr.io/inspektor-gadget/gadget/tcpdump:v0.57.0 --help
/opt/ig/ig run ghcr.io/inspektor-gadget/gadget/tcpdump:v0.57.0 --disallow-pulling --runtimes=containerd --containerd-socketpath=/run/k3s/containerd/containerd.sock --k8s-namespace=asservat-lab --pf 'udp dst port 58888' --snaplen 65535 --output pcap-ng --timeout 5 > /root/gadget-pods.pcapng
tshark -r /root/gadget-pods.pcapng
```

[gadget-loopback.sh](gadget-loopback.sh) explicitly selects the VM's `lo` interface and generates its own bounded datagrams. The earlier [default-attachment experiment](gadget-packets.sh) is retained because it failed to capture that traffic. Explicit host-loopback success does not prove pod-loopback attachment/attribution.

On the host, build only the portable VM executables from `experiments/feasibility/go` with `CGO_ENABLED=0 go build ./cmd/filterprobe` and `CGO_ENABLED=0 go build ./cmd/mapprobe` using a disk-backed `TMPDIR`. Transfer those executables, the generated `results/filter-programs.json`, and [peers.bpf.c](peers.bpf.c) into `/root` in the VM. Then:

```sh
touch /root/ASSERVAT_DISPOSABLE_VM
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c /root/peers.bpf.c -o /root/peers.bpf.o
/root/filterprobe
/root/mapprobe > /root/mapprobe.json &
probe=$!
sleep 4
k3s kubectl -n asservat-lab rollout restart deployment/sink
k3s kubectl -n asservat-lab rollout status deployment/sink --timeout=45s
wait "$probe"
```

`filterprobe` loads/test-runs sample programs without attaching them to traffic. `mapprobe` attaches one observer to VM `cni0`, relists the actual EndpointSlices and changes an inner-map reference. It sends synthetic traffic directly to the resolved backends so the selected hook's addressing is explicit. It briefly activates an empty membership map. Connection refusals during readiness/rollout are counted rather than mistaken for a probe crash. It does not implement a production Kubernetes watch, resource ownership resolver, Gadget event stream or permission lease.

The previous Service-VIP traffic setup failed to establish new-generation coverage at this hook, and the first direct-backend attempt stopped on a transient connection refusal. Both logs are retained; the final passing probe narrows its claim to the tested direct-backend observation point. It is not proof of seamless packet coverage across arbitrary NAT/CNI profiles.
