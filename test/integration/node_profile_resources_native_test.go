package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The malformed body tests maximum acquisition residency, not valid trace
// publication. The actual production parser must refuse it. This fixture has
// no SQL publisher and makes no claim about an installed catalog transaction.
type blockedNativeProfileSink struct {
	small   *nativeProfileSink
	entered chan collector.ProfileResult
	joined  chan struct{}
	release chan struct{}
}

func (s *blockedNativeProfileSink) DeliverProfile(ctx context.Context, peer collector.Identity, r collector.ProfileResult, body io.Reader) error {
	if r.Outcome.NativeBytes != artifact.MaxGoTraceBytes {
		return s.small.DeliverProfile(ctx, peer, r, body)
	}
	defer func() { s.joined <- struct{}{} }()
	// Read enough to establish the malformed event stream, then stop consuming
	// the body so the actual node upload retains the complete native buffer.
	prefix := make([]byte, 64<<10)
	if _, err := io.ReadFull(body, prefix); err != nil {
		return err
	}
	if !artifact.GoTraceHeader(prefix) || diagnostics.CheckGoTrace(bytes.NewReader(prefix)) == nil {
		return errors.New("resource fixture did not provide an invalid trace")
	}
	s.entered <- r
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return errors.New("malformed resource fixture is never publication eligible")
}

func profileResourcesNative(t *testing.T, ctx context.Context, k kubernetes.Interface, ch *delivery.NodeChannel, original delivery.NodeView, namespace, image, collectorNamespace string, results map[string]any) {
	t.Helper()
	wait := func(label string, limit time.Duration, ready func() bool) {
		t.Helper()
		until := time.Now().Add(limit)
		for !ready() {
			if ctx.Err() != nil || !time.Now().Before(until) {
				t.Fatal("profile resource wait", label, ctx.Err())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	current := func() delivery.NodeView {
		t.Helper()
		v, ok := ch.NodeByUID(original.Identity.NodeUID)
		if !ok || !v.Current || v.Identity != original.Identity || v.Report == nil {
			t.Fatal("resource test replaced or lost the original collector")
		}
		return v
	}
	collectorPod, err := k.CoreV1().Pods(collectorNamespace).Get(ctx, original.Identity.PodName, meta.GetOptions{})
	if err != nil || string(collectorPod.UID) != original.Identity.PodUID {
		t.Fatal("resource collector identity", err)
	}
	observedImage, err := profilePodImage(collectorPod, "node")
	if err != nil {
		t.Fatal(err)
	}
	var memoryLimit int64
	for _, c := range collectorPod.Spec.Containers {
		if c.Name == "node" {
			memoryLimit = c.Resources.Limits.Memory().Value()
		}
	}
	if memoryLimit <= 0 {
		t.Fatal("collector has no fixed memory limit")
	}
	onNode := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", collectorPod.Spec.NodeName}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("resource observation %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	container := onNode("crictl", "ps", "-q", "--label", "io.kubernetes.pod.uid="+string(collectorPod.UID), "--label", "io.kubernetes.container.name=node")
	var inspected struct {
		Info struct{ Pid int } `json:"info"`
	}
	if err := json.Unmarshal([]byte(onNode("crictl", "inspect", container)), &inspected); err != nil || inspected.Info.Pid <= 1 {
		t.Fatal("resource collector process", err)
	}
	memory := func() (rss, peak int64) {
		t.Helper()
		for _, line := range strings.Split(onNode("cat", fmt.Sprintf("/proc/%d/status", inspected.Info.Pid)), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] != "VmRSS:" && fields[0] != "VmHWM:" {
				continue
			}
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || fields[2] != "kB" {
				t.Fatal("resource memory format", line)
			}
			if fields[0] == "VmRSS:" {
				rss = n * 1024
			} else {
				peak = n * 1024
			}
		}
		if rss <= 0 || peak < rss {
			t.Fatal("missing RSS/peak memory")
		}
		return
	}
	baseline, baselinePeak := memory()
	ns, err := k.CoreV1().Namespaces().Get(ctx, namespace, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var pods [3]*core.Pod
	for i := range pods {
		pod := nativeProfileWorkloadPod(fmt.Sprintf("profile-resource-%d", i), image)
		pods[i], err = k.CoreV1().Pods(namespace).Create(ctx, pod, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range pods {
		wait("synthetic target ready", time.Minute, func() bool {
			p, err := k.CoreV1().Pods(namespace).Get(ctx, pods[i].Name, meta.GetOptions{})
			if err != nil {
				return false
			}
			for _, c := range p.Status.Conditions {
				if c.Type == core.PodReady && c.Status == core.ConditionTrue {
					pods[i] = p
					return true
				}
			}
			return false
		})
	}
	small := &nativeProfileSink{results: map[string]collector.ProfileResult{}, bodies: map[string][]byte{}}
	sink := &blockedNativeProfileSink{small: small, entered: make(chan collector.ProfileResult, 2), joined: make(chan struct{}, 2), release: make(chan struct{})}
	var released bool
	defer func() {
		if !released {
			close(sink.release)
		}
	}()
	ch.SetProfileSink(sink)
	enqueue := func(pod *core.Pod, limit int64) collector.Work {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		id := uuid.NewString()
		p := collector.ProfileCapture{CaptureID: id, CollectorEpoch: original.Identity.Epoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("127.0.0.1"), Port: 6071, Host: "localhost", Request: execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: uuid.NewString(), ArtifactID: uuid.NewString(), AttemptID: uuid.NewString(), MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: namespace, NamespaceUID: string(ns.UID), Name: pod.Name, UID: string(pod.UID), NodeName: pod.Spec.NodeName}, NodeUID: original.Identity.NodeUID, NodeBootID: original.Identity.BootID, SourceRef: "malformed-resource-fixture", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "runtimeTrace", Mode: "interval", Duration: 15 * time.Second}, NativeLimit: limit, NotBefore: now, Deadline: now.Add(25 * time.Second)}}
		w, err := ch.EnqueueProfile(ctx, p, now.Add(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	started := time.Now()
	first, second := enqueue(pods[0], artifact.MaxGoTraceBytes), enqueue(pods[1], artifact.MaxGoTraceBytes)
	for range 2 {
		select {
		case r := <-sink.entered:
			if r.Failure != "" || !r.Outcome.ResponseComplete || r.Outcome.NativeBytes != artifact.MaxGoTraceBytes {
				t.Fatal("maximum native acquisition incomplete", r)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("maximum native acquisition did not reach blocked upload")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Two uploads share the existing three-connection pool with control. Allow
	// one original long-poll interval for its status/refusal lane, without
	// inventing another connection or extending either capture's deadlines.
	third := enqueue(pods[2], 16<<20)
	wait("aggregate refusal", collector.PollHold+5*time.Second, func() bool {
		r, b, ok := small.get(third.Profile.CaptureID)
		if !ok {
			return false
		}
		if r.Failure != collector.ReasonCaptureBusy || r.Outcome.MayHaveStarted || len(b) != 0 {
			t.Fatal("over-budget request acquired native bytes", r)
		}
		return true
	})
	wait("held aggregate reservation", 5*time.Second, func() bool { return current().Report.Budget.FrozenReserved == 2*artifact.MaxGoTraceBytes })
	rss, peak := memory()
	if rss < artifact.MaxGoTraceBytes || peak > memoryLimit {
		t.Fatal("maximum acquisition memory outside installed limit", rss, peak, memoryLimit)
	}
	if current().Report.Budget.FrozenReserved != 2*artifact.MaxGoTraceBytes {
		t.Fatal("refusal lost held reservations")
	}
	stopped := time.Now()
	uploadUntil := first.Profile.Request.Deadline.Add(delivery.PacketUploadMargin)
	if other := second.Profile.Request.Deadline.Add(delivery.PacketUploadMargin); other.Before(uploadUntil) {
		uploadUntil = other
	}
	var cancellationWork []collector.Work
	for _, w := range []collector.Work{first, second} {
		stop, cancel := context.WithTimeout(ctx, 5*time.Second)
		until, _ := stop.Deadline()
		cancelWork, err := ch.EnqueueProfileCancel(stop, original.Identity.NodeUID, w.Profile.CaptureID, w.ID, until)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		cancellationWork = append(cancellationWork, cancelWork)
	}
	// A later actual report proves node upload goroutines returned and released
	// local reservations. RSS may stay resident under Go's allocator afterwards.
	acceptedStops := map[string]bool{}
	var joinedReport collector.Report
	wait("cancelled uploads joined before original expiry", min(20*time.Second, time.Until(uploadUntil)), func() bool {
		v := current()
		joined, err := profileResourceStopJoined(*v.Report, stopped, uploadUntil, cancellationWork, acceptedStops)
		if err != nil {
			t.Fatal(err)
		}
		if joined {
			joinedReport = *v.Report
		}
		return joined
	})
	close(sink.release)
	released = true
	for range 2 {
		select {
		case <-sink.joined:
		case <-time.After(5 * time.Second):
			t.Fatal("resource sink did not join")
		}
	}
	after, afterPeak := memory()
	results["profileMaximumAcquisitionResources"] = map[string]any{"scope": "malformed input acquisition and parser refusal; no installed publication proof", "collectorImage": observedImage, "collectorPID": inspected.Info.Pid, "nativeBytesPerAttempt": artifact.MaxGoTraceBytes, "heldAttempts": 2, "heldReservationBytes": 2 * artifact.MaxGoTraceBytes, "baselineRSSBytes": baseline, "baselinePeakRSSBytes": baselinePeak, "blockedRSSBytes": rss, "peakRSSBytes": max(peak, afterPeak), "afterJoinRSSBytes": after, "installedMemoryLimitBytes": memoryLimit, "aggregateExcessRefused": true, "semanticPublicationEligible": false, "nodeEpoch": original.Identity.Epoch, "elapsedSeconds": time.Since(started).Seconds(), "cancelJoinSeconds": time.Since(stopped).Seconds(), "stopRequestedAt": stopped, "joinedReportObservedAt": joinedReport.ObservedAt, "originalUploadUntil": uploadUntil, "acceptedStopReceipts": len(acceptedStops)}
}

// An enqueued Stop and deadline cleanup are not interchangeable. Require exact
// node acknowledgements plus a zero-reservation snapshot before either original
// upload deadline, so a delayed control request cannot turn expiry into Stop.
func profileResourceStopJoined(r collector.Report, stopped, uploadUntil time.Time, work []collector.Work, accepted map[string]bool) (bool, error) {
	if !r.ObservedAt.After(stopped) {
		return false, nil
	}
	if !r.ObservedAt.Before(uploadUntil) {
		return false, errors.New("upload expiry cannot qualify explicit Stop")
	}
	for _, receipt := range r.Receipts {
		for _, w := range work {
			if receipt.WorkID != w.ID || receipt.Sequence != w.Sequence {
				continue
			}
			if receipt.Outcome != collector.OutcomeAccepted || receipt.Reason != "" {
				return false, errors.New("exact profile Stop was refused")
			}
			accepted[w.ID] = true
		}
	}
	for _, w := range work {
		if !accepted[w.ID] {
			return false, nil
		}
	}
	return len(work) == 2 && r.Budget.FrozenReserved == 0, nil
}
