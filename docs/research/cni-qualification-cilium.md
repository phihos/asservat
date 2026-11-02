# CNI qualification: Cilium (S-04 row 17, EXP-02 subset)

Measured on 2026-11-02 by the native `collector-cilium` suite
(`scripts/test-collector.py cilium`, native.yml run 41516602345) for that
runner environment only. This is not a claim about other kernels, Cilium
versions or multi-node clusters.

## Environment

- GitHub-hosted `ubuntu-24.04`, kernel `7.0.0-1017-azure`, BTF, cgroup v2,
  4 vCPUs.
- kind single node `kindest/node@sha256:a1ed56cf…`, Kubernetes v1.37.0,
  `disableDefaultCNI`, `kubeProxyMode: none`, `ipFamily: dual`.
- Cilium 1.20.3 chart (`sha256 0805a527…`, digest-pinned agent and operator
  images), kube-proxy replacement `True`, encryption `Wireguard`, IPAM
  `kubernetes`, Envoy/L7 proxy and Hubble disabled.
- Capture path: the published tcpdump gadget v0.57.0 (tc hook on the target
  Pod's interface), networkHeaders projection.

## Results

| Observation | Measured |
|---|---|
| Node collector suite (enrollment, probes, filtered/unfiltered/encrypted captures, restart, uninstall) | passes unchanged on Cilium |
| IPv4 / IPv6 TCP packets on the backend Pod (10 s) | 20,477 / 20,471; no lost samples |
| Service VIP on the backend Pod's interface | 0 packets |
| Service VIP or Service port 80 on the client Pod's interface | 0 packets; the client side carries the backend address and port 8080 (35,316 packets) |
| Pod loopback traffic (127.0.0.1:9090 inside the target Pod) | 0 packets: not observable at the Pod interface hook |
| hostNetwork target | refused with `TargetHostNetwork`, no packet captured |
| Payload marker in any capture | absent (headers-only recheck passes) |
| Filtered capture (`tcp port 8080`) | 19,705 retained of 39,450 seen, tshark agrees |

## Consequences

- With socket-level load balancing (Cilium kube-proxy replacement) a Service
  is translated at `connect()`, so no Pod interface carries the cluster IP.
  A `virtualIP` peer selection matches nothing at the Pod hook; `backends`
  (the default) is the selection that observes such traffic.
- Traffic a Pod sends to itself over loopback is outside the Pod-interface
  observation point on this profile, as on kindnet.
- Not exercised: inter-node WireGuard (single node), native routing versus
  tunnel modes, other CNIs, NAT/egress gateways. A multi-node profile is the
  next step if inter-node encryption needs a measured claim.
