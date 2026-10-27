package integration

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/collector"
	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// The synthetic payload the web Pod serves. It must never appear in a
// networkHeaders capture.
const packetMarker = "ASSERVAT-SYNTHETIC-PAYLOAD-MARKER-0123456789"

// testPacketSink keeps delivered captures in memory for the native test.
type testPacketSink struct {
	mu      sync.Mutex
	results map[string]collector.PacketResult
	pcap    map[string][]byte
	at      map[string]time.Time
}

func (s *testPacketSink) DeliverPacket(_ context.Context, _ collector.Identity, r collector.PacketResult, body io.Reader) error {
	b, err := io.ReadAll(body)
	if err != nil || int64(len(b)) != r.CapturedBytes {
		return io.ErrUnexpectedEOF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.CaptureID], s.pcap[r.CaptureID], s.at[r.CaptureID] = r, b, time.Now()
	return nil
}

func (s *testPacketSink) get(id string) (collector.PacketResult, []byte, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[id]
	return r, s.pcap[id], s.at[id], ok
}

func restrictedPod(name, image string, args ...string) *core.Pod {
	return &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"app": name}}, Spec: core.PodSpec{
		SecurityContext:               &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To[int64](65532), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		TerminationGracePeriodSeconds: ptr.To[int64](1),
		Containers: []core.Container{{Name: name, Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"sh", "-c"}, Args: args,
			SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}
}

// packetCaptureNative runs ADR-248's native proof on the runner: synthetic
// HTTP traffic between Restricted Pods, a capture with a libpcap-compiled
// filter through the real collector and gadget, and the headers-only,
// filter and count checks on the delivered PCAPNG.
func packetCaptureNative(t *testing.T, ctx context.Context, k kubernetes.Interface, admin *rest.Config, ch *delivery.NodeChannel, view delivery.NodeView, workload, busybox, work, s3 string, results map[string]any) {
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
	if !view.PacketRecorderAvailable() {
		t.Fatalf("packet recorder not available on the runner: %+v", view.Report.Mechanisms)
	}
	web, err := k.CoreV1().Pods(workload).Create(ctx, restrictedPod("web", busybox,
		"mkdir -p /tmp/www && printf '%s' \""+strings.Repeat(packetMarker, 8)+"\" > /tmp/www/index.html && httpd -p 8080 -h /tmp/www && httpd -p 9090 -h /tmp/www && exec sleep 3600"), meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var webIP string
	wait("web Pod Running", 3*time.Minute, func() bool {
		p, err := k.CoreV1().Pods(workload).Get(ctx, "web", meta.GetOptions{})
		if err == nil && p.Status.Phase == core.PodRunning && p.Status.PodIP != "" {
			webIP = p.Status.PodIP
			return true
		}
		return false
	})
	if _, err := k.CoreV1().Pods(workload).Create(ctx, restrictedPod("client", busybox,
		"while true; do wget -q -O /dev/null http://"+webIP+":8080/ ; wget -q -O /dev/null http://"+webIP+":9090/ ; done"), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("client Pod Running", 3*time.Minute, func() bool {
		p, err := k.CoreV1().Pods(workload).Get(ctx, "client", meta.GetOptions{})
		return err == nil && p.Status.Phase == core.PodRunning
	})
	// The hub's compiler: statically linked libpcap 1.11.0 (build tag libpcap).
	filter, err := pcap.NewCompiler().CompileFilter("tcp port 8080")
	if err != nil {
		t.Fatalf("hub filter compiler: %v", err)
	}
	digest := [32]byte(compiler.FilterProgramDigest(filter.Program))
	capture := func(name string, program bool, duration time.Duration, maxBytes int64) (collector.PacketResult, []byte, time.Duration) {
		t.Helper()
		p := collector.PacketCapture{CaptureID: uuid.NewString(), PodUID: string(web.UID), Duration: duration, MaxBytes: maxBytes}
		if program {
			p.Program, p.ProgramDigest = filter.Program, digest
		}
		queued := time.Now()
		if _, err := ch.EnqueuePacket(view.Identity.NodeUID, p, queued.Add(collector.PacketCaptureStartWithin)); err != nil {
			t.Fatal(err)
		}
		var r collector.PacketResult
		var b []byte
		var at time.Time
		wait(name+" result", duration+90*time.Second, func() bool {
			var ok bool
			r, b, at, ok = sink.get(p.CaptureID)
			return ok
		})
		_ = os.WriteFile(filepath.Join(work, name+".pcapng"), b, 0o644)
		return r, b, at.Sub(queued)
	}

	// 1. Filtered capture: only port 8080 is retained.
	r, b, latency := capture("filtered", true, 10*time.Second, collector.MaxPacketCaptureBytes)
	if r.Failure != "" || r.Retained == 0 || r.Filtered == 0 || r.ProgramDigest != digest {
		t.Fatalf("filtered capture %+v", r)
	}
	if bytes.Contains(b, []byte(packetMarker)) {
		t.Fatal("the payload marker reached the capture")
	}
	n, err := packets.CheckHeadersOnly(bytes.NewReader(b))
	if err != nil || uint64(n) != r.Retained {
		t.Fatalf("headers-only recheck: %d packets, %v (retained %d)", n, err, r.Retained)
	}
	rd, err := pcapgo.NewNgReader(bytes.NewReader(b), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	other, truncated := 0, 0
	for {
		data, ci, err := rd.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp == nil || (tcp.SrcPort != 8080 && tcp.DstPort != 8080) {
			other++
		}
		if ci.Length > ci.CaptureLength {
			truncated++
		}
	}
	if other != 0 || truncated == 0 {
		t.Fatalf("filter effect: %d packets outside port 8080; %d truncated", other, truncated)
	}
	filtered := map[string]any{"seen": r.Seen, "retained": r.Retained, "filtered": r.Filtered, "unsupported": r.Unsupported, "lostSamples": r.LostSamples,
		"wireBytes": r.WireBytes, "capturedBytes": r.CapturedBytes, "truncatedPackets": truncated, "seconds": r.EndedAt.Sub(r.StartedAt).Seconds(),
		"queueToDeliverySeconds": latency.Seconds(), "programInstructions": len(filter.Program), "engineVersion": r.EngineVersion}
	if out, err := exec.CommandContext(ctx, "tshark", "-r", filepath.Join(work, "filtered.pcapng"), "-T", "fields", "-e", "tcp.port").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		filtered["tsharkPackets"] = len(lines)
		if uint64(len(lines)) != r.Retained {
			t.Fatalf("tshark read %d packets, retained %d", len(lines), r.Retained)
		}
		for _, l := range lines {
			if !strings.Contains(l, "8080") {
				t.Fatalf("tshark packet outside port 8080: %q", l)
			}
		}
	} else {
		filtered["tshark"] = "unavailable: " + err.Error()
	}
	results["packetFiltered"] = filtered

	// 2. Unfiltered capture under the same generator: runner throughput and
	// the 8 MiB output cap.
	r, b, latency = capture("unfiltered", false, 10*time.Second, collector.MaxPacketCaptureBytes)
	if r.Failure != "" || r.Retained == 0 || r.CapturedBytes > collector.MaxPacketCaptureBytes || int64(len(b)) != r.CapturedBytes {
		t.Fatalf("unfiltered capture %+v", r)
	}
	if n, err := packets.CheckHeadersOnly(bytes.NewReader(b)); err != nil || uint64(n) != r.Retained || bytes.Contains(b, []byte(packetMarker)) {
		t.Fatalf("unfiltered headers-only recheck: %d, %v", n, err)
	}
	seconds := r.EndedAt.Sub(r.StartedAt).Seconds()
	results["packetUnfiltered"] = map[string]any{"seen": r.Seen, "retained": r.Retained, "outputFull": r.OutputFull, "unsupported": r.Unsupported, "lostSamples": r.LostSamples,
		"wireBytes": r.WireBytes, "capturedBytes": r.CapturedBytes, "seconds": seconds, "framesPerSecond": strconv.FormatFloat(float64(r.Seen)/seconds, 'f', 0, 64),
		"wireBytesPerSecond": strconv.FormatFloat(float64(r.WireBytes)/seconds, 'f', 0, 64), "queueToDeliverySeconds": latency.Seconds()}

	// 3. ADR-248's connector path with the real node: the connector holder
	// queues the capture, encrypts the node's PCAPNG with the artifact
	// producer into S3, the verifier rechecks headers-only and the native
	// read returns the exact bytes.
	if s3 != "" {
		recordingEncryptedNative(t, ctx, admin, ch, sink, web, filter.Program, s3, work, results)
		ch.SetPacketSink(sink)
	}

	// 3b. A Pod that does not run on the node is reported, not captured.
	p := collector.PacketCapture{CaptureID: uuid.NewString(), PodUID: uuid.NewString(), Duration: 2 * time.Second, MaxBytes: collector.MinPacketCaptureBytes}
	if _, err := ch.EnqueuePacket(view.Identity.NodeUID, p, time.Now().Add(collector.PacketCaptureStartWithin)); err != nil {
		t.Fatal(err)
	}
	wait("missing target result", 60*time.Second, func() bool { _, _, _, ok := sink.get(p.CaptureID); return ok })
	if r, _, _, _ := sink.get(p.CaptureID); r.Failure != collector.ReasonTargetNotFound || r.Seen != 0 {
		t.Fatalf("missing target %+v", r)
	}
	for _, name := range []string{"client", "web"} {
		_ = k.CoreV1().Pods(workload).Delete(ctx, name, meta.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	}
}
