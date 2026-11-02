package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// ringDiskNative is ADR-278's node-local qualification on the runner, with
// the chart's ring volume enabled at ceiling bytes:
//
//  1. byte cap: one encrypted-disk ring that fits is admitted, a second one
//     that does not fit is refused with MediumUnavailable before anything is
//     reserved, and the volume stays far below the kubelet's emptyDir limit;
//  2. restart: after a SIGKILL of the collector process (container restart,
//     same Pod, the emptyDir survives) the new process removes the earlier
//     process's sealed segments on start and the old source is gone;
//  3. full volume: a real ENOSPC on seal closes the ring with
//     MediumUnavailable and leaves no partial segment as history.
//
// For 3 the test mounts a 1 MiB tmpfs over the Pod's emptyDir directory on
// the kind node before a second container restart, so the restarted process
// sees a genuinely full filesystem without the kubelet's asynchronous
// eviction being involved. That is node manipulation by the test only; the
// chart and the collector are unchanged. Source work is synthetic test
// authority delivered in-process, as in the other native phases.
func ringDiskNative(t *testing.T, ctx context.Context, k kubernetes.Interface, ch *delivery.NodeChannel, collectorNS string, ceiling int64, workload, busybox string, results map[string]any) {
	t.Helper()
	out := map[string]any{"ceilingBytes": ceiling}
	results["ringDisk"] = out
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
	current := func() (delivery.NodeView, bool) {
		v := ch.Nodes()
		if len(v) != 1 || v[0].Report == nil {
			return delivery.NodeView{}, false
		}
		return v[0], true
	}
	pods, err := k.CoreV1().Pods(collectorNS).List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=asservat-node"})
	if err != nil || len(pods.Items) != 1 {
		t.Fatal("collector Pod", err)
	}
	collectorPod := pods.Items[0]
	node := collectorPod.Spec.NodeName // the kind node's container name
	volume := "/var/lib/kubelet/pods/" + string(collectorPod.UID) + "/volumes/kubernetes.io~empty-dir/ring-disk"
	onNode := func(args ...string) (string, error) {
		b, err := exec.CommandContext(ctx, "docker", append([]string{"exec", node}, args...)...).CombinedOutput()
		return strings.TrimSpace(string(b)), err
	}
	must := func(args ...string) string {
		t.Helper()
		s, err := onNode(args...)
		if err != nil {
			t.Fatalf("%v on the node: %v: %s", args, err, s)
		}
		return s
	}
	// entries lists the volume as "path size mode" lines.
	entries := func() []string {
		s := must("find", volume, "-mindepth", "1", "-printf", "%P %s %m\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	used := func() int64 {
		f := strings.Fields(must("du", "-sb", volume))
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	restartCount := func() int32 {
		p, err := k.CoreV1().Pods(collectorNS).Get(ctx, collectorPod.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if p.UID != collectorPod.UID || p.Status.Phase != core.PodRunning || p.Status.Reason == "Evicted" {
			t.Fatalf("collector Pod replaced or evicted: uid %s phase %s reason %s", p.UID, p.Status.Phase, p.Status.Reason)
		}
		for _, c := range p.Status.ContainerStatuses {
			if c.Name == "node" {
				return c.RestartCount
			}
		}
		t.Fatal("no node container status")
		return 0
	}
	// crash kills the collector process with SIGKILL (no shutdown path can
	// remove its files) and waits for the restarted container's new epoch.
	crash := func(old delivery.NodeView) delivery.NodeView {
		t.Helper()
		before := restartCount()
		id := must("crictl", "ps", "-q", "--label", "io.kubernetes.pod.uid="+string(collectorPod.UID), "--label", "io.kubernetes.container.name=node")
		var inspect struct {
			Info struct {
				Pid int `json:"pid"`
			} `json:"info"`
		}
		if err := json.Unmarshal([]byte(must("crictl", "inspect", id)), &inspect); err != nil || inspect.Info.Pid <= 1 {
			t.Fatal("collector pid", err, inspect.Info.Pid)
		}
		must("kill", "-9", strconv.Itoa(inspect.Info.Pid))
		started := time.Now()
		var next delivery.NodeView
		wait("restarted collector process", 3*time.Minute, func() bool {
			v, ok := current()
			if ok && v.Identity.Epoch != old.Identity.Epoch {
				next = v
				return true
			}
			return false
		})
		if next.Identity.PodUID != string(collectorPod.UID) {
			t.Fatalf("expected a container restart in Pod %s, got %+v", collectorPod.UID, next.Identity)
		}
		wait("container restart count", 30*time.Second, func() bool { return restartCount() == before+1 })
		t.Logf("collector restarted after %v: epoch %s -> %s", time.Since(started), old.Identity.Epoch, next.Identity.Epoch)
		return next
	}
	containerLog := func() string {
		b, err := k.CoreV1().Pods(collectorNS).GetLogs(collectorPod.Name, &core.PodLogOptions{Container: "node", LimitBytes: ptr.To[int64](16 << 10)}).DoRaw(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	receipt := func(w collector.Work) (collector.Receipt, collector.Report) {
		t.Helper()
		var rc collector.Receipt
		var report collector.Report
		wait("receipt for "+string(w.Kind), 30*time.Second, func() bool {
			v, ok := current()
			if !ok {
				return false
			}
			for _, r := range v.Report.Receipts {
				if r.WorkID == w.ID && r.Sequence == w.Sequence {
					rc, report = r, *v.Report
					return true
				}
			}
			return false
		})
		return rc, report
	}

	// Synthetic HTTP traffic to the target Pod.
	web := restrictedPod("ring-web", busybox, "mkdir -p /tmp/www && printf '%s' \""+packetMarker+"\" > /tmp/www/index.html && httpd -f -p 8080 -h /tmp/www")
	if _, err := k.CoreV1().Pods(workload).Create(ctx, web, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	var target *core.Pod
	wait("ring-web Running", 3*time.Minute, func() bool {
		p, err := k.CoreV1().Pods(workload).Get(ctx, "ring-web", meta.GetOptions{})
		if err == nil && p.Status.Phase == core.PodRunning && p.Status.PodIP != "" {
			target = p
			return true
		}
		return false
	})
	if _, err := k.CoreV1().Pods(workload).Create(ctx, restrictedPod("ring-client", busybox, "while true; do wget -q -O /dev/null http://"+target.Status.PodIP+":8080/; sleep 0.2; done"), meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	var client *core.Pod
	wait("ring-client Running", 3*time.Minute, func() bool {
		p, err := k.CoreV1().Pods(workload).Get(ctx, "ring-client", meta.GetOptions{})
		if err == nil && p.Status.Phase == core.PodRunning && p.Status.PodIP != "" {
			client = p
			return true
		}
		return false
	})

	// 4 MiB segments, three of them: one ring needs 12,599,296 sealed bytes
	// on the volume, so exactly one fits the 16 MiB ceiling. A four-second
	// segment slice seals segments under light traffic.
	plan := collector.SourceRingLimits{MaxAge: 12 * time.Second, MaxBytes: 12 << 20, SegmentBytes: 4 << 20, MaxSegments: 3, MaxFrozenBytes: 4 << 20, MaxConcurrentSnapshots: 1, EncryptedDisk: true}
	limits := packets.RingLimits{MaxAge: plan.MaxAge, MaxBytes: plan.MaxBytes, SegmentBytes: plan.SegmentBytes, MaxSegments: plan.MaxSegments, MaxFrozenBytes: plan.MaxFrozenBytes, MaxConcurrentSnapshots: plan.MaxConcurrentSnapshots}
	sealedRing, resident := packets.SealedRingBytes(limits), packets.MemoryRingBytes(limits, true)
	if sealedRing > ceiling || 2*sealedRing <= ceiling {
		t.Fatalf("ring plan %d sealed bytes does not fit exactly once into %d", sealedRing, ceiling)
	}
	sealedFile := plan.SegmentBytes + 12 + 16
	out["plan"] = map[string]any{"segmentBytes": plan.SegmentBytes, "segments": plan.MaxSegments, "sealedRingBytes": sealedRing, "residentBytes": resident}
	resources := collector.SourceResources{PolicyUID: "synthetic-ringdisk-policy"}
	type armed struct {
		binding collector.SourceBinding
		source  collector.PacketSource
	}
	dispatch := func(a armed) collector.Work {
		t.Helper()
		v, _ := current()
		b := a.binding
		now := time.Now().UTC().Truncate(time.Microsecond)
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		w, err := ch.EnqueueSourceExpected(call, targets.PacketSourceObservation{PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: v.Identity.Epoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, a.source)
		if err != nil {
			t.Fatal("enqueue source", err)
		}
		return w
	}
	arm := func(view delivery.NodeView) armed {
		id := view.Identity
		now := time.Now().UTC().Truncate(time.Microsecond)
		b := collector.SourceBinding{AudienceDigest: [32]byte{9}, RootID: uuid.NewString(), PolicyUID: resources.PolicyUID, AcceptanceID: uuid.NewString(), SourceID: uuid.NewString(), Fence: uuid.NewString(),
			ActionID: "packets", PodUID: string(target.UID), NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch,
			Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: delivery.SourceResourcesDigest(resources)}
		return armed{b, collector.PacketSource{Permit: collector.SourcePermit{Binding: b, StartedAt: now, HardUntil: now.Add(3 * time.Minute), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(collector.SourceLeafLifetime),
			Credit: 64 << 20, BytesPerSecond: 1 << 20}, Ring: plan, Resources: resources}}
	}
	// renew is the quiet leaf renewal of the same incarnation.
	renew := func(a *armed) {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		a.source.Permit.IssuedAt, a.source.Permit.DispatchUntil, a.source.Permit.LeafUntil = now, now.Add(5*time.Second), now.Add(collector.SourceLeafLifetime)
		if rc, _ := receipt(dispatch(*a)); rc.Outcome != collector.OutcomeAccepted {
			t.Fatalf("renewal %+v", rc)
		}
	}
	snapshot := func(a armed, before time.Duration) (collector.Work, string, error) {
		issued := time.Now().UTC().Truncate(time.Microsecond)
		request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(delivery.SourceBindingDigest(a.binding)), SourceID: a.binding.SourceID, Fence: a.binding.Fence, SnapshotID: uuid.NewString(),
			SourceStartedAt: a.source.Permit.StartedAt, SourceHardUntil: a.source.Permit.HardUntil,
			T0: issued, IssuedAt: issued, StartBy: issued.Add(5 * time.Second), ProcessingUntil: issued.Add(20 * time.Second), Before: before, After: time.Second, MaxBytes: 1 << 20}
		s := collector.SourceSnapshot{Binding: a.binding, CaptureID: uuid.NewString(), AttemptID: uuid.NewString(), ExpectationDigest: [32]byte{3}, Request: request}
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		w, err := ch.EnqueueSourceSnapshot(call, s)
		return w, s.CaptureID, err
	}
	sourceStatus := func(r collector.Report, id string) (collector.SourceStatus, bool) {
		for _, s := range r.Sources {
			if s.SourceID == id {
				return s, true
			}
		}
		return collector.SourceStatus{}, false
	}

	// 1. Byte cap.
	view, _ := current()
	if !strings.Contains(containerLog(), "encrypted disk available=true") {
		t.Fatal("the collector did not find its ring volume")
	}
	first := arm(view)
	rc, report := receipt(dispatch(first))
	firstOutcome := rc.Outcome
	if rc.Outcome != collector.OutcomeAccepted || report.Budget.RingReserved != resident {
		t.Fatalf("first disk ring: %+v, ring reserved %d (want %d)", rc, report.Budget.RingReserved, resident)
	}
	second := arm(view)
	rc, report = receipt(dispatch(second))
	if rc.Outcome != collector.OutcomeRefused || rc.Reason != collector.ReasonMediumUnavailable {
		t.Fatalf("second disk ring beyond the volume ceiling: %+v", rc)
	}
	if _, listed := sourceStatus(report, second.binding.SourceID); listed || report.Budget.RingReserved != resident {
		t.Fatalf("refused ring reserved memory or became a source: reserved %d, sources %+v", report.Budget.RingReserved, report.Sources)
	}
	out["byteCap"] = map[string]any{"first": string(firstOutcome), "second": string(rc.Outcome) + "/" + string(rc.Reason), "ringReservedAfterRefusal": report.Budget.RingReserved}

	// 2. Sealed segments on the volume, readable by their own process.
	var files []string
	wait("two sealed segments on the ring volume", 40*time.Second, func() bool {
		files = files[:0]
		for _, e := range entries() {
			f := strings.Fields(e)
			if len(f) == 3 && strings.Count(f[0], "/") == 1 {
				// A file being written may be shorter; none is longer.
				size, err := strconv.ParseInt(f[1], 10, 64)
				if err != nil || size > sealedFile || f[2] != "600" {
					t.Fatalf("sealed segment %q: want at most %d bytes, mode 600", e, sealedFile)
				}
				if size == sealedFile {
					files = append(files, f[0])
				}
			}
		}
		return len(files) >= 2
	})
	renew(&first)
	peak := used()
	if peak > sealedRing || peak > ceiling {
		t.Fatalf("ring volume holds %d bytes, above the ring's %d or the ceiling %d", peak, sealedRing, ceiling)
	}
	// The client/server IPv4 address pair is in every captured header; it
	// must be in the snapshot (positive control) and in no sealed file.
	pairs := addressPairs(t, client.Status.PodIP, target.Status.PodIP)
	// Rotation evicts a sealed file every slice, so a listed one may be gone.
	inspected := 0
	for _, f := range files {
		raw, err := exec.CommandContext(ctx, "docker", "exec", node, "cat", volume+"/"+f).Output()
		if err != nil || int64(len(raw)) != sealedFile {
			continue
		}
		inspected++
		for _, p := range pairs {
			if bytes.Contains(raw, p) {
				t.Fatalf("sealed segment %s holds plaintext packet headers", f)
			}
		}
	}
	if inspected == 0 {
		t.Fatal("no complete sealed segment could be read back for inspection")
	}
	w, captureID, err := snapshot(first, 10*time.Second)
	if err != nil {
		t.Fatal("enqueue snapshot", err)
	}
	if rc, _ = receipt(w); rc.Outcome != collector.OutcomeAccepted {
		t.Fatalf("snapshot of the disk ring: %+v", rc)
	}
	var saved collector.PacketResult
	var native []byte
	wait("disk ring snapshot", time.Minute, func() bool {
		var ok bool
		saved, native, _, ok = sink.get(captureID)
		return ok
	})
	if saved.Failure != "" || saved.Retained == 0 || bytes.Contains(native, []byte(packetMarker)) || !bytes.Contains(native, pairs[0]) && !bytes.Contains(native, pairs[1]) {
		t.Fatalf("disk ring snapshot %+v", saved)
	}
	if n, err := packets.CheckHeadersOnly(bytes.NewReader(native)); err != nil || uint64(n) != saved.Retained {
		t.Fatalf("disk ring snapshot headers-only recheck: %d, %v", n, err)
	}
	out["sealed"] = map[string]any{"files": files, "fileBytes": sealedFile, "inspectedForPlaintext": inspected, "volumeBytes": peak, "snapshotRetained": saved.Retained, "snapshotBytes": len(native)}

	// 3. Crash restart: the volume survives, the keys do not; the new
	// process removes the earlier ring on start.
	ringDirs := map[string]bool{}
	for _, f := range files {
		ringDirs[strings.Split(f, "/")[0]] = true
	}
	if len(ringDirs) != 1 {
		t.Fatalf("expected the one admitted ring directory, got %v", files)
	}
	beforeCrash := entries()
	if len(beforeCrash) < 2 {
		t.Fatalf("the ring volume is not populated before the crash: %v", beforeCrash)
	}
	view = crash(view)
	left := entries()
	logs := containerLog()
	if len(left) != 0 || !strings.Contains(logs, "encrypted disk available=true removedEarlier=1") {
		t.Fatalf("after restart the volume holds %v; log: %s", left, logs)
	}
	if _, listed := sourceStatus(*view.Report, first.binding.SourceID); listed || view.Report.Budget.RingReserved != 0 {
		t.Fatalf("the old source survived the restart: %+v", view.Report)
	}
	if _, _, err = snapshot(first, 10*time.Second); !errors.Is(err, delivery.ErrNodeUnavailable) {
		t.Fatal("a snapshot of the old process's source was not refused as unavailable:", err)
	}
	out["restart"] = map[string]any{"volumeEntriesBefore": beforeCrash, "signal": "SIGKILL", "samePod": true, "removedEarlier": 1, "volumeEntriesAfter": len(left), "oldSourceListed": false}

	// 4. Full volume: a 1 MiB tmpfs over the emptyDir, then a restart so the
	// new process's ring directory lives on it. The first seal of a 4 MiB
	// segment hits ENOSPC.
	must("mount", "-t", "tmpfs", "-o", "size=1m,mode=0777", "tmpfs", volume)
	unmounted := false
	defer func() {
		if !unmounted {
			_, _ = onNode("umount", "-l", volume)
		}
	}()
	view = crash(view)
	id := must("crictl", "ps", "-q", "--label", "io.kubernetes.pod.uid="+string(collectorPod.UID), "--label", "io.kubernetes.container.name=node")
	var inspect struct {
		Info struct {
			Pid int `json:"pid"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(must("crictl", "inspect", id)), &inspect); err != nil {
		t.Fatal(err)
	}
	mounted := false
	for _, line := range strings.Split(must("cat", "/proc/"+strconv.Itoa(inspect.Info.Pid)+"/mountinfo"), "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == contracts.NodeRingDiskPath && strings.Contains(line, " - tmpfs ") {
			mounted = true
		}
	}
	if !mounted {
		t.Fatal("the restarted collector does not see the tmpfs ring volume")
	}
	third := arm(view)
	rc, _ = receipt(dispatch(third))
	if rc.Outcome != collector.OutcomeAccepted {
		t.Fatalf("disk ring on the small volume: %+v", rc)
	}
	var closed collector.SourceStatus
	wait("ring closed by a failed seal", 40*time.Second, func() bool {
		v, ok := current()
		if !ok {
			return false
		}
		s, listed := sourceStatus(*v.Report, third.binding.SourceID)
		if listed && s.Closed {
			closed = s
			return true
		}
		return false
	})
	logs = containerLog()
	stopped := "source " + third.binding.SourceID + " stopped: " + packets.ErrMediumUnavailable.Error()
	if !closed.InputUnknown || closed.ObservedBytes == 0 || !strings.Contains(logs, stopped) {
		t.Fatalf("closed source %+v; log: %s", closed, logs)
	}
	left = entries()
	if len(left) != 0 {
		t.Fatalf("a partial segment or the ring directory remained: %v", left)
	}
	if w, captureID, err = snapshot(third, 10*time.Second); err != nil {
		t.Fatal("enqueue snapshot", err)
	}
	if rc, _ = receipt(w); rc.Outcome != collector.OutcomeRefused {
		t.Fatalf("snapshot of the closed ring: %+v", rc)
	}
	if _, _, _, ok := sink.get(captureID); ok {
		t.Fatal("the closed ring delivered history")
	}
	wait("ring reservation released", 30*time.Second, func() bool {
		v, ok := current()
		return ok && v.Report.Budget.RingReserved == 0
	})
	out["fullVolume"] = map[string]any{"tmpfsBytes": 1 << 20, "outcome": "closed", "inputUnknown": closed.InputUnknown, "observedBytes": closed.ObservedBytes, "log": stopped, "volumeEntriesAfter": 0, "snapshot": string(rc.Reason)}
	if _, err := onNode("umount", "-l", volume); err != nil {
		t.Fatal("umount", err)
	}
	unmounted = true
	restartCount() // still the same Pod, never evicted

	for _, name := range []string{"ring-client", "ring-web"} {
		_ = k.CoreV1().Pods(workload).Delete(ctx, name, meta.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	}
}

// addressPairs returns the 8-byte IPv4 source/destination field of both
// directions between a and b, as it appears in every packet header.
func addressPairs(t *testing.T, a, b string) [2][]byte {
	t.Helper()
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil || !x.Is4() || !y.Is4() {
		t.Fatalf("IPv4 Pod addresses %q %q", a, b)
	}
	xb, yb := x.As4(), y.As4()
	return [2][]byte{append(xb[:], yb[:]...), append(yb[:], xb[:]...)}
}
