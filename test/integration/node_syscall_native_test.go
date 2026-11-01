package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// syscallSourceNative runs ADR-273's native proof on the runner: an ongoing
// syscall metadata source on a Restricted Pod through the real collector and
// pinned traceloop eBPF program, then one saved window as JSON Lines. The
// source work is synthetic test authority, delivered in-process.
func syscallSourceNative(t *testing.T, ctx context.Context, k kubernetes.Interface, ch *delivery.NodeChannel, view delivery.NodeView, workload, busybox, work string, results map[string]any) {
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
	if !view.RecorderAvailable(collector.MechanismSyscall) {
		t.Fatalf("syscall recorder not available on the runner: %+v", view.Report.Mechanisms)
	}
	pod, err := k.CoreV1().Pods(workload).Create(ctx, restrictedPod("syscalls", busybox, "while true; do cat /proc/self/stat > /dev/null; usleep 100000; done"), meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wait("syscall Pod Running", 3*time.Minute, func() bool {
		p, err := k.CoreV1().Pods(workload).Get(ctx, pod.Name, meta.GetOptions{})
		return err == nil && p.Status.Phase == core.PodRunning
	})

	names := []string{"openat", "read"}
	filter := collector.SyscallFilter{Names: names, MaxEvents: 100_000, MaxTrackedThreads: 4096}
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := view.Identity
	resources := collector.SourceResources{PolicyUID: "synthetic-syscall-policy"}
	b := collector.SourceBinding{AudienceDigest: [32]byte{9}, RootID: uuid.NewString(), PolicyUID: "synthetic-syscall-policy", AcceptanceID: uuid.NewString(), SourceID: uuid.NewString(), Fence: uuid.NewString(),
		ActionID: "syscalls", PodUID: string(pod.UID), NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch,
		Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ProgramDigest: delivery.SyscallFilterDigest(filter), ResourceDigest: delivery.SourceResourcesDigest(resources)}
	source := collector.PacketSource{Permit: collector.SourcePermit{Binding: b, StartedAt: now, HardUntil: now.Add(2 * time.Minute), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second),
		Credit: 64 << 20, BytesPerSecond: 10_000 * collector.SyscallEventCredit},
		Ring:      collector.SourceRingLimits{MaxAge: 30 * time.Second, MaxBytes: 8 << 20, SegmentBytes: 2 << 20, MaxSegments: 4, MaxFrozenBytes: 4 << 20, MaxConcurrentSnapshots: 1},
		Resources: resources, Syscalls: &filter}
	call, cancel := context.WithTimeout(ctx, 4*time.Second)
	_, err = ch.EnqueueSourceExpected(call, targets.PacketSourceObservation{PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, source)
	cancel()
	if err != nil {
		t.Fatal("syscall source", err)
	}
	wait("syscall source reported", time.Minute, func() bool {
		v, ok := ch.NodeByUID(id.NodeUID)
		if !ok || v.Report == nil {
			return false
		}
		for _, s := range v.Report.Sources {
			if s.SourceID == b.SourceID && s.ObservedBytes > 0 {
				return true
			}
		}
		return false
	})
	if err := waitFor(ctx, 6*time.Second); err != nil {
		t.Fatal(err)
	}

	issued := time.Now().UTC().Truncate(time.Microsecond)
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(delivery.SourceBindingDigest(b)), SourceID: b.SourceID, Fence: b.Fence, SnapshotID: uuid.NewString(), SourceStartedAt: now, SourceHardUntil: source.Permit.HardUntil,
		T0: issued, IssuedAt: issued, StartBy: issued.Add(5 * time.Second), ProcessingUntil: issued.Add(20 * time.Second), Before: 5 * time.Second, After: time.Second, MaxBytes: 1 << 20}
	snapshot := collector.SourceSnapshot{Binding: b, CaptureID: uuid.NewString(), AttemptID: uuid.NewString(), ExpectationDigest: [32]byte{3}, Request: request}
	call, cancel = context.WithTimeout(ctx, 4*time.Second)
	_, err = ch.EnqueueSourceSnapshot(call, snapshot)
	cancel()
	if err != nil {
		t.Fatal("syscall snapshot", err)
	}
	var r collector.PacketResult
	var native []byte
	wait("syscall snapshot result", time.Minute, func() bool {
		var ok bool
		r, native, _, ok = sink.get(snapshot.CaptureID)
		return ok
	})
	_ = os.WriteFile(filepath.Join(work, "syscalls.jsonl"), native, 0o644)
	if r.Failure != "" || r.NativeType != artifact.SyscallRecordsArtifact || r.Snapshot == nil || r.Retained == 0 || int64(len(native)) != r.CapturedBytes {
		t.Fatalf("syscall snapshot result %+v (%d bytes)", r, len(native))
	}
	from, until := request.T0.Add(-request.Before), request.T0.Add(request.After)
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSuffix(string(native), "\n"), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("event %q: %v", line, err)
		}
		for key := range e {
			switch key {
			case "identity", "syscall", "abi", "timestamp", "duration_ns", "outcome", "errno":
			default:
				t.Fatalf("event field %q outside the metadata schema: %s", key, line)
			}
		}
		name, _ := e["syscall"].(string)
		at, err := time.Parse(time.RFC3339Nano, e["timestamp"].(string))
		identity, _ := e["identity"].(map[string]any)
		if err != nil || at.Before(from) || at.After(until) || identity["pod_uid"] != string(pod.UID) || e["abi"] != "x86_64" || name != "openat" && name != "read" {
			t.Fatalf("event outside window, pod or selection: %s", line)
		}
		counts[name]++
	}
	if counts["openat"] == 0 || counts["read"] == 0 {
		t.Fatalf("syscall window lacks the workload's calls: %v", counts)
	}
	results["syscallSnapshot"] = map[string]any{"retained": r.Retained, "outputFull": r.OutputFull, "bytes": len(native), "counts": counts, "coverage": r.Snapshot.SourceSnapshotCoverage}

	call, cancel = context.WithTimeout(ctx, 4*time.Second)
	_, err = ch.EnqueueSourceStop(call, b, time.Now().Add(3*time.Second))
	cancel()
	if err != nil {
		t.Fatal("syscall source stop", err)
	}
}

func waitFor(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
