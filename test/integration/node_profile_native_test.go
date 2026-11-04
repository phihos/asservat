package integration

import (
	"asservat.local/asservat/internal/adapters/diagnostics"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"github.com/google/pprof/profile"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

type nativeProfileSink struct {
	mu         sync.Mutex
	results    map[string]collector.ProfileResult
	bodies     map[string][]byte
	deliveries map[string]int
}

func (s *nativeProfileSink) DeliverProfile(_ context.Context, _ collector.Identity, r collector.ProfileResult, body io.Reader) error {
	b, err := io.ReadAll(body)
	if err != nil || int64(len(b)) != r.Outcome.NativeBytes {
		return io.ErrUnexpectedEOF
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.CaptureID] = r
	s.bodies[r.CaptureID] = b
	if s.deliveries == nil {
		s.deliveries = map[string]int{}
	}
	s.deliveries[r.CaptureID]++
	return nil
}

func (s *nativeProfileSink) count(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deliveries[id]
}
func (s *nativeProfileSink) get(id string) (collector.ProfileResult, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[id]
	return r, s.bodies[id], ok
}

// profileCaptureNative uses the actual collector in a separate Restricted Go
// workload's namespace. These are component authority fixtures, not admission
// or installed approval/publication qualification.
func profileCaptureNative(t *testing.T, ctx context.Context, k kubernetes.Interface, ch *delivery.NodeChannel, view delivery.NodeView, namespace, image, work string, results map[string]any) {
	t.Helper()
	wait := func(label string, timeout time.Duration, check func() bool) {
		t.Helper()
		until := time.Now().Add(timeout)
		for !check() {
			if ctx.Err() != nil || time.Now().After(until) {
				t.Fatal("profile wait", label, ctx.Err())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	pod := nativeProfileWorkloadPod("profile-workload", image)
	created, err := k.CoreV1().Pods(namespace).Create(ctx, pod, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wait("workload Ready", time.Minute, func() bool {
		p, err := k.CoreV1().Pods(namespace).Get(ctx, created.Name, meta.GetOptions{})
		if err != nil {
			return false
		}
		for _, c := range p.Status.Conditions {
			if c.Type == core.PodReady && c.Status == core.ConditionTrue {
				created = p
				return true
			}
		}
		return false
	})
	ns, err := k.CoreV1().Namespaces().Get(ctx, namespace, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sink := &nativeProfileSink{results: map[string]collector.ProfileResult{}, bodies: map[string][]byte{}}
	ch.SetProfileSink(sink)
	enqueue := func(kind, mode, addressMode string, address netip.Addr, port uint16, duration time.Duration) (collector.Work, collector.ProfileCapture) {
		t.Helper()
		current, ok := ch.NodeByUID(view.Identity.NodeUID)
		if !ok || !current.RecorderAvailable(collector.MechanismProfile) {
			t.Fatal("profile mechanism unavailable")
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		id := uuid.NewString()
		p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: current.Identity.Epoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: addressMode, Address: address, Port: port, Host: "localhost", Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: uuid.NewString(), ArtifactID: uuid.NewString(), AttemptID: uuid.NewString(), MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: namespace, NamespaceUID: string(ns.UID), Name: created.Name, UID: string(created.UID), NodeName: created.Spec.NodeName}, NodeUID: current.Identity.NodeUID, NodeBootID: current.Identity.BootID, SourceRef: "fixture-pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: kind, Mode: mode, Duration: duration}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(duration + 5*time.Second)}}
		w, err := ch.EnqueueProfile(ctx, p, now.Add(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return w, p
	}
	await := func(id string) (collector.ProfileResult, []byte) {
		t.Helper()
		var r collector.ProfileResult
		var b []byte
		wait(id, 40*time.Second, func() bool { var ok bool; r, b, ok = sink.get(id); return ok })
		return r, b
	}
	qualify := func(name string, r collector.ProfileResult, b []byte) {
		t.Helper()
		if r.Failure != "" || !r.Outcome.ResponseComplete || len(b) == 0 {
			t.Fatal("profile acquisition failed", name, r)
		}
		parsed, err := profile.ParseData(b)
		if err != nil || parsed.CheckValid() != nil || len(parsed.Sample) == 0 {
			t.Fatal("native profile invalid or empty", name, err)
		}
		path := filepath.Join(work, "profile-"+name+".pb.gz")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "go", "tool", "pprof", "-symbolize=none", "-top", path)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("native local tool: %v %s", err, out)
		}
		results["profile-"+name] = map[string]any{"bytes": len(b), "sha256": fmt.Sprintf("%x", sha256.Sum256(b)), "samples": len(parsed.Sample), "started": r.Outcome.StartedAt, "completed": r.Outcome.CompletedAt, "localTool": "go tool pprof -symbolize=none -top", "nodeUID": view.Identity.NodeUID, "podUID": string(created.UID)}
	}
	_, cpu := enqueue("cpu", "interval", "targetLoopback", netip.MustParseAddr("127.0.0.1"), 6060, 2*time.Second)
	r, b := await(cpu.CaptureID)
	qualify("cpu-loopback", r, b)
	_, heap := enqueue("heap", "snapshot", "podIP", netip.MustParseAddr(created.Status.PodIP), 8080, 0)
	r, b = await(heap.CaptureID)
	qualify("heap-pod-ip", r, b)
	_, trace := enqueue("runtimeTrace", "interval", "targetLoopback", netip.MustParseAddr("127.0.0.1"), 6060, 2*time.Second)
	r, b = await(trace.CaptureID)
	if r.Failure != "" || !r.Outcome.ResponseComplete || diagnostics.CheckGoTrace(bytes.NewReader(b)) != nil {
		t.Fatal("genuine native trace failed", r)
	}
	results["profile-trace-loopback"] = map[string]any{"bytes": len(b), "sha256": fmt.Sprintf("%x", sha256.Sum256(b)), "parser": "production Go trace verifier"}
	_, redirect := enqueue("cpu", "interval", "targetLoopback", netip.MustParseAddr("127.0.0.1"), 6070, time.Second)
	r, b = await(redirect.CaptureID)
	if r.Failure == "" || len(b) != 0 {
		t.Fatal("redirect followed", r)
	}
	results["profileRedirectRefused"] = true
	wait("uncertain redirect original deadline", 10*time.Second, func() bool { return !time.Now().Before(redirect.Request.Deadline) })
	control := func(command string) profileWorkloadState {
		t.Helper()
		state, err := profileWorkloadControl(ctx, k, namespace, created.Name, string(created.UID), command)
		if err != nil {
			t.Fatal("original profile workload control", command, err)
		}
		return state
	}
	// The application owner controls its own profiler through fixture-only paths.
	// Collector requests remain the same fixed approved /debug/pprof/profile GET.
	ownerNeedsStop := true
	defer func() {
		if !ownerNeedsStop {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := profileWorkloadControl(cleanup, k, namespace, created.Name, string(created.UID), "stop"); err != nil {
			t.Error("profile fixture owner cleanup", err)
		}
	}()
	before := control("start")
	if !before.OwnerRunning || !before.RuntimeBusy {
		t.Fatal("fixture owner did not hold actual runtime CPU profiler")
	}
	_, busy := enqueue("cpu", "interval", "targetLoopback", netip.MustParseAddr("127.0.0.1"), 6060, time.Second)
	r, b = await(busy.CaptureID)
	if r.Failure != collector.ReasonCaptureBusy || r.Outcome.ResponseComplete || r.Outcome.NativeBytes != 0 || len(b) != 0 {
		t.Fatal("application-owned busy profile lost typed refusal or delivered native output", r)
	}
	// Keep the application's profiler running through the original uncertain
	// lifetime. No stop or retry is inferred from the failure or HTTP cancellation.
	wait("busy original deadline", 10*time.Second, func() bool { return !time.Now().Before(busy.Request.Deadline) })
	after := control("state")
	if !after.OwnerRunning || !after.RuntimeBusy || after.ProfileRequests != before.ProfileRequests+1 || sink.count(busy.CaptureID) != 1 {
		t.Fatal("refusal stopped the application profiler or retried acquisition", before, after, sink.count(busy.CaptureID))
	}
	results["profileApplicationOwnedBusyPreserved"] = true
	stopped := control("stop")
	if stopped.OwnerRunning || stopped.RuntimeBusy {
		t.Fatal("fixture owner did not stop its own profiler")
	}
	ownerNeedsStop = false
	before = control("missing")
	_, missing := enqueue("cpu", "interval", "targetLoopback", netip.MustParseAddr("127.0.0.1"), 6060, time.Second)
	r, b = await(missing.CaptureID)
	if r.Failure != collector.ReasonProfileUnavailable || r.Outcome.ResponseComplete || r.Outcome.NativeBytes != 0 || len(b) != 0 {
		t.Fatal("missing endpoint lost typed unavailable or delivered native output", r)
	}
	wait("unavailable original deadline", 10*time.Second, func() bool { return !time.Now().Before(missing.Request.Deadline) })
	after = control("state")
	if after.OwnerRunning || after.RuntimeBusy || after.ProfileRequests != before.ProfileRequests+1 || sink.count(missing.CaptureID) != 1 {
		t.Fatal("unavailable endpoint retried acquisition or invented a profiler", before, after, sink.count(missing.CaptureID))
	}
	results["profileUnavailableNoNativeOrRetry"] = true
	control("normal")
	w, cancelled := enqueue("cpu", "interval", "targetLoopback", netip.MustParseAddr("127.0.0.1"), 6060, 10*time.Second)
	time.Sleep(2 * time.Second)
	stop, end := context.WithTimeout(ctx, 5*time.Second)
	until, _ := stop.Deadline()
	_, err = ch.EnqueueProfileCancel(stop, view.Identity.NodeUID, cancelled.CaptureID, w.ID, until)
	end()
	if err != nil {
		t.Fatal("cancel enqueue", err)
	}
	r, b = await(cancelled.CaptureID)
	if r.Failure == "" || !r.Outcome.MayHaveStarted || len(b) != 0 {
		t.Fatal("cancel fabricated success or lost uncertain start", r)
	}
	results["profileCancellationUncertain"] = true
}

func nativeProfileWorkloadPod(name, image string) *core.Pod {
	pod := restrictedPod(name, image)
	pod.Spec.Containers[0].Command = []string{"/profile-native"}
	pod.Spec.Containers[0].Args = nil
	pod.Spec.Containers[0].Ports = []core.ContainerPort{{Name: "diagnostics", ContainerPort: 6060}, {Name: "health", ContainerPort: 8080}}
	pod.Spec.Containers[0].Resources = core.ResourceRequirements{Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("64Mi")}, Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("16Mi")}}
	pod.Spec.Containers[0].ReadinessProbe = &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)}}, PeriodSeconds: 1}
	return pod
}
