package integration

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// packetAddresses counts what one headers-only PCAPNG shows: IPv4 and IPv6
// TCP packets on port, packets carrying any of the marked addresses, and
// packets on the loopback probe port.
type packetAddresses struct {
	IPv4, IPv6, Marked, Loopback int
}

func countPacketAddresses(t *testing.T, b []byte, port, loopbackPort layers.TCPPort, marked ...netip.Addr) packetAddresses {
	t.Helper()
	rd, err := pcapgo.NewNgReader(bytes.NewReader(b), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	var c packetAddresses
	for {
		data, _, err := rd.ReadPacketData()
		if err == io.EOF {
			return c
		}
		if err != nil {
			t.Fatal(err)
		}
		pkt := gopacket.NewPacket(data, rd.LinkType(), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		var src, dst netip.Addr
		v6 := false
		if ip, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			src, _ = netip.AddrFromSlice(ip.SrcIP.To4())
			dst, _ = netip.AddrFromSlice(ip.DstIP.To4())
		} else if ip, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			src, _ = netip.AddrFromSlice(ip.SrcIP)
			dst, _ = netip.AddrFromSlice(ip.DstIP)
			v6 = true
		}
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp == nil {
			continue
		}
		switch {
		case tcp.SrcPort == loopbackPort || tcp.DstPort == loopbackPort:
			c.Loopback++
		case tcp.SrcPort == port || tcp.DstPort == port:
			if v6 {
				c.IPv6++
			} else {
				c.IPv4++
			}
		}
		for _, m := range marked {
			if src == m || dst == m {
				c.Marked++
				break
			}
		}
	}
}

// cniQualificationNative is the EXP-02 subset of S-04 row 17 on the Cilium
// profile (kube-proxy replacement, WireGuard, dual stack). It measures what
// the published tc gadget on the target Pod's interface sees, and records it
// for the runner environment only: IPv4 and IPv6 pod traffic, whether a
// Service VIP or its backend address appears on either side, whether the
// Pod's own loopback traffic is visible, and that a hostNetwork target is
// refused. Payload bytes must never reach the capture.
func cniQualificationNative(t *testing.T, ctx context.Context, k kubernetes.Interface, ch *delivery.NodeChannel, view delivery.NodeView, workload, busybox, work string, results map[string]any) {
	t.Helper()
	sink := &testPacketSink{results: map[string]collector.PacketResult{}, pcap: map[string][]byte{}, at: map[string]time.Time{}}
	ch.SetPacketSink(sink)
	wait := func(what string, limit time.Duration, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for !ok() {
			if time.Now().After(deadline) || ctx.Err() != nil {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	running := func(namespace, name string) *core.Pod {
		t.Helper()
		var pod *core.Pod
		wait(name+" Pod Running", 3*time.Minute, func() bool {
			p, err := k.CoreV1().Pods(namespace).Get(ctx, name, meta.GetOptions{})
			if err == nil && p.Status.Phase == core.PodRunning && p.Status.PodIP != "" {
				pod = p
				return true
			}
			return false
		})
		return pod
	}
	addresses := func(p *core.Pod) (v4, v6 netip.Addr) {
		for _, ip := range p.Status.PodIPs {
			a, err := netip.ParseAddr(ip.IP)
			if err != nil {
				continue
			}
			if a.Is4() {
				v4 = a
			} else {
				v6 = a
			}
		}
		if !v4.IsValid() || !v6.IsValid() {
			t.Fatalf("pod %s is not dual-stack: %+v", p.Name, p.Status.PodIPs)
		}
		return v4, v6
	}
	// The web Pod also polls its own loopback on 9090, the probe for the
	// pod loopback path that the veth hook cannot observe.
	webSpec := restrictedPod("cni-web", busybox, "mkdir -p /tmp/www && printf '%s' \""+packetMarker+"\" > /tmp/www/index.html && httpd -p 8080 -h /tmp/www && httpd -p 9090 -h /tmp/www && "+
		"while true; do wget -q -O /dev/null http://127.0.0.1:9090/ && echo lo ; sleep 0.2; done")
	if _, err := k.CoreV1().Pods(workload).Create(ctx, webSpec, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	web := running(workload, "cni-web")
	web4, web6 := addresses(web)
	svc, err := k.CoreV1().Services(workload).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "cni-web"}, Spec: core.ServiceSpec{
		Selector: map[string]string{"app": "cni-web"}, IPFamilyPolicy: ptr.To(core.IPFamilyPolicyRequireDualStack),
		Ports: []core.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: core.ProtocolTCP}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var vips []netip.Addr
	var vip4, vip6 netip.Addr
	for _, ip := range svc.Spec.ClusterIPs {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatal(err)
		}
		vips = append(vips, a)
		if a.Is4() {
			vip4 = a
		} else {
			vip6 = a
		}
	}
	if !vip4.IsValid() || !vip6.IsValid() {
		t.Fatalf("Service is not dual-stack: %v", svc.Spec.ClusterIPs)
	}
	if _, err := k.CoreV1().Pods(workload).Create(ctx, restrictedPod("cni-client", busybox,
		"while true; do wget -q -O /dev/null http://"+web4.String()+":8080/ && echo d4 ; wget -q -O /dev/null 'http://["+web6.String()+"]:8080/' && echo d6 ; "+
			"wget -q -O /dev/null http://"+vip4.String()+":80/ && echo v4 ; wget -q -O /dev/null 'http://["+vip6.String()+"]:80/' && echo v6 ; done"), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	client := running(workload, "cni-client")

	capture := func(name string, pod *core.Pod, duration time.Duration) (collector.PacketResult, []byte) {
		t.Helper()
		p := collector.PacketCapture{CaptureID: uuid.NewString(), PodUID: string(pod.UID), Duration: duration, MaxBytes: collector.MaxPacketCaptureBytes}
		if _, err := ch.EnqueuePacket(view.Identity.NodeUID, p, time.Now().Add(collector.PacketCaptureStartWithin)); err != nil {
			t.Fatal(err)
		}
		var r collector.PacketResult
		var b []byte
		wait(name+" result", duration+90*time.Second, func() bool {
			var ok bool
			r, b, _, ok = sink.get(p.CaptureID)
			return ok
		})
		_ = os.WriteFile(filepath.Join(work, "cni-"+name+".pcapng"), b, 0o644)
		return r, b
	}
	headersOnly := func(name string, r collector.PacketResult, b []byte) {
		t.Helper()
		if r.Failure != "" || r.Retained == 0 {
			t.Fatalf("%s capture %+v", name, r)
		}
		if bytes.Contains(b, []byte(packetMarker)) {
			t.Fatalf("%s: the payload marker reached the capture", name)
		}
		if n, err := packets.CheckHeadersOnly(bytes.NewReader(b)); err != nil || uint64(n) != r.Retained {
			t.Fatalf("%s headers-only recheck: %d packets, %v (retained %d)", name, n, err, r.Retained)
		}
	}

	// 1. The backend side: the web Pod's interface under dual-stack traffic,
	// direct and through the Service.
	r, b := capture("backend", web, 10*time.Second)
	headersOnly("backend", r, b)
	server := countPacketAddresses(t, b, 8080, 9090, vips...)
	// 2. The client side: does socket-level load balancing leave the VIP or
	// the backend address on the client Pod's interface?
	rc, bc := capture("client", client, 10*time.Second)
	headersOnly("client", rc, bc)
	atClient := countPacketAddresses(t, bc, 8080, 9090, vips...)
	clientVIP := countPacketAddresses(t, bc, 80, 9090, vips...)
	// Positive controls: every request kind succeeded during the captures,
	// so a zero VIP or loopback count is the hook's view, not failed traffic.
	succeeded := func(pod string, tokens ...string) map[string]int {
		t.Helper()
		logs, err := k.CoreV1().Pods(workload).GetLogs(pod, &core.PodLogOptions{TailLines: ptr.To[int64](4000)}).DoRaw(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n := map[string]int{}
		for _, line := range strings.Fields(string(logs)) {
			n[line]++
		}
		for _, token := range tokens {
			if n[token] == 0 {
				t.Fatalf("%s: no successful %q request in its recent log: %v", pod, token, n)
			}
		}
		return n
	}
	clientOK := succeeded("cni-client", "d4", "d6", "v4", "v6")
	webOK := succeeded("cni-web", "lo")
	results["cni"] = map[string]any{
		"successfulRequests": map[string]int{"direct4": clientOK["d4"], "direct6": clientOK["d6"], "vip4": clientOK["v4"], "vip6": clientOK["v6"], "loopback": webOK["lo"]},
		"profile":            "cilium kubeProxyReplacement wireguard dual-stack (single node: inter-node WireGuard not exercised)",
		"backend": map[string]any{"ipv4Packets": server.IPv4, "ipv6Packets": server.IPv6, "serviceVIPPackets": server.Marked, "loopbackPackets": server.Loopback,
			"seen": r.Seen, "retained": r.Retained, "lostSamples": r.LostSamples},
		"client": map[string]any{"backendPort8080Packets": atClient.IPv4 + atClient.IPv6, "servicePort80Packets": clientVIP.IPv4 + clientVIP.IPv6, "serviceVIPPackets": atClient.Marked,
			"seen": rc.Seen, "retained": rc.Retained, "lostSamples": rc.LostSamples},
	}
	t.Logf("cni backend: %+v; client: port 8080 %+v, port 80 %+v", server, atClient, clientVIP)
	if server.IPv4 == 0 || server.IPv6 == 0 {
		t.Fatalf("dual-stack traffic not observed on the backend interface: %+v", server)
	}

	// 3. A hostNetwork target is refused, never captured as the node's traffic.
	host := "asservat-cni-hostnet"
	if _, err := k.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: host,
		Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	hostPod := restrictedPod("hostnet", busybox, "exec sleep 3600")
	hostPod.Spec.HostNetwork = true
	if _, err := k.CoreV1().Pods(host).Create(ctx, hostPod, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	hp := running(host, "hostnet")
	p := collector.PacketCapture{CaptureID: uuid.NewString(), PodUID: string(hp.UID), Duration: 2 * time.Second, MaxBytes: collector.MinPacketCaptureBytes}
	if _, err := ch.EnqueuePacket(view.Identity.NodeUID, p, time.Now().Add(collector.PacketCaptureStartWithin)); err != nil {
		t.Fatal(err)
	}
	wait("hostNetwork result", 60*time.Second, func() bool { _, _, _, ok := sink.get(p.CaptureID); return ok })
	// The refusal may carry the empty PCAPNG header; it holds no packet.
	if hr, hb, _, _ := sink.get(p.CaptureID); hr.Failure != collector.ReasonTargetHostNet || hr.Seen != 0 || hr.Retained != 0 || bytes.Contains(hb, []byte(packetMarker)) {
		t.Fatalf("hostNetwork target %+v (%d bytes)", hr, len(hb))
	}
	results["cni"].(map[string]any)["hostNetwork"] = string(collector.ReasonTargetHostNet)

	_ = k.CoreV1().Namespaces().Delete(ctx, host, meta.DeleteOptions{})
	_ = k.CoreV1().Services(workload).Delete(ctx, "cni-web", meta.DeleteOptions{})
	for _, name := range []string{"cni-client", "cni-web"} {
		_ = k.CoreV1().Pods(workload).Delete(ctx, name, meta.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	}
}
