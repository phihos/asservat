package integration

// These phases run ONLY inside TestNodeCollectorWithRealKubernetes on its
// guarded disposable host. Work/permits are synthetic authority; transport,
// packaged Gadget, source clock, projection, native output and joins are real.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/node"
	"github.com/google/uuid"
)

type nativeLiveQualification struct {
	calls, bytes int
	elapsed      time.Duration
}

func (n *nativeLiveQualification) phase(t *testing.T, parent context.Context) (context.Context, func()) {
	t.Helper()
	left := 45*time.Second - n.elapsed
	if left <= 0 {
		t.Fatal("native LIVE phases exceeded original45s incremental budget")
	}
	ctx, cancel := context.WithTimeout(parent, left)
	started := time.Now()
	return ctx, func() { n.elapsed += time.Since(started); cancel() }
}
func (n *nativeLiveQualification) read(ctx context.Context, ch *delivery.NodeChannel, q collector.LiveRead) (v.NodeReply, error) {
	n.calls++
	if n.calls > 43 {
		return v.NodeReply{}, v.ErrCapacity
	}
	call, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	out, err := ch.ReadLive(call, q)
	if err != nil {
		return out, err
	}
	wire, err := node.WireLiveReply(q.Epoch(), out)
	if err != nil {
		return v.NodeReply{}, err
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return v.NodeReply{}, err
	}
	n.bytes += len(raw)
	if len(raw) > 24<<10 || n.bytes > 43*(24<<10) {
		return v.NodeReply{}, v.ErrCapacity
	}
	return out, nil
}
func nativeLiveRequest(view delivery.NodeView, work collector.Work) collector.LiveRead {
	p := work.Packet
	id := view.Identity
	m := collector.ManualLiveSource{RootID: uuid.NewString(), CaptureID: p.CaptureID, AttemptID: uuid.NewString(), ActionID: "native-live", WorkID: work.ID, ExecutorPodUID: uuid.NewString(), ExecutorEpoch: uuid.NewString(), PodUID: p.PodUID, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}}
	projection := v.Packet
	if p.Syscalls != nil {
		projection = v.Syscall
	}
	if p.HTTP != nil {
		projection = v.HTTP
	}
	if p.Observation != nil {
		b := p.Observation.Binding
		m.ObservationKind = "packet"
		m.ObservationSessionID = b.SessionID
		m.ObservationFence = b.Fence
	}
	if p.Arguments != nil {
		b := p.Arguments.Binding
		m.ObservationKind = "arguments"
		m.ObservationSessionID = b.SessionID
		m.ObservationFence = b.Fence
	}
	return collector.LiveRead{Manual: &m, Inspect: true, ClusterID: "50000000-0000-4000-8000-000000000001", NamespaceUID: uuid.NewString(), WorkloadUID: uuid.NewString(), Projection: projection, PrivacyUntil: work.NotAfter.Add(p.Duration), Head: true, Limit: 20, ReplyBytes: 24 << 10}
}
func nativeLiveRows(t *testing.T, q collector.LiveRead, out v.NodeReply) {
	t.Helper()
	clock := "monotonic"
	if q.Projection == v.Syscall {
		clock = "boottime"
	}
	if out.SourceID != q.SourceID() || out.Fence != q.Fence() || out.BootID != q.Boot() || out.Clock != clock || out.Sample <= 0 {
		t.Fatal("LIVE runtime/source clock mismatch", out)
	}
	for _, row := range out.Rows {
		if row.Nanos <= 0 || row.Clock != clock || row.Row.SourceID != q.SourceID() || row.Row.PodUID != q.Pod() || row.Row.Projection != q.Projection || !row.Row.Valid(time.Now()) {
			t.Fatal("LIVE row outside original source", row)
		}
		raw, _ := json.Marshal(row.Row)
		for _, marker := range []string{packetMarker, "ASSERVAT-LIVE-PRIVATE-CANARY", "authorization", "cookie", "shop.example", "/proc/self/stat"} {
			if bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(marker))) {
				t.Fatal("nonapproved live field", marker)
			}
		}
		if row.Row.HTTP != nil {
			for _, h := range row.Row.HTTP.Headers {
				if h.Name != "content-type" && h.Name != "content-length" {
					t.Fatal("unapproved header", h.Name)
				}
			}
		}
	}
}

// Reuses an already-admitted finite capture, never retries its acquisition.
// Inspect is bounded to four original-holder observations; two reads activate
// only the approved metadata cohort. Returned times are learned from the node.
func (n *nativeLiveQualification) manual(t *testing.T, ctx context.Context, ch *delivery.NodeChannel, view delivery.NodeView, w collector.Work, stop bool) collector.ManualLiveSource {
	t.Helper()
	q := nativeLiveRequest(view, w)
	var head v.NodeReply
	var err error
	for i := 0; i < 4; i++ {
		head, err = n.read(ctx, ch, q)
		if err == nil {
			break
		}
	}
	if err != nil || head.Manual == nil || len(head.Rows) != 0 {
		t.Fatal("actual finite LIVE inspection", err)
	}
	original := *head.Manual
	if !original.SameBinding(*q.Manual) || original.StartedAt.Before(w.NotAfter.Add(-collector.PacketCaptureStartWithin)) || original.HardUntil.Sub(original.StartedAt) > w.Packet.Duration {
		t.Fatal("finite LIVE original times", original)
	}
	q.Manual = &original
	q.Inspect = false
	q.Head = false
	q.WaitMS = 1000
	rows := 0
	for i := 0; i < 2; i++ {
		out, e := n.read(ctx, ch, q)
		if e != nil {
			t.Fatal("finite LIVE rows", e)
		}
		nativeLiveRows(t, q, out)
		rows += len(out.Rows)
		q.AfterSequence = out.Position.Sequence
	}
	if rows == 0 {
		t.Fatal("no actual finite approved live rows", q.Projection)
	}
	wrong := q
	changed := original
	changed.WorkID = uuid.NewString()
	wrong.Manual = &changed
	wrong.WaitMS = 0
	if _, e := n.read(ctx, ch, wrong); e == nil {
		t.Fatal("foreign finite work was observed")
	}
	if stop {
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, e := ch.EnqueuePacketCancel(call, view.Identity.NodeUID, w.Packet.CaptureID, w.ID, time.Now().Add(2*time.Second))
		cancel()
		if e != nil {
			t.Fatal("exact finite stop", e)
		}
	}
	return original
}
func (n *nativeLiveQualification) ended(t *testing.T, ctx context.Context, ch *delivery.NodeChannel, view delivery.NodeView, w collector.Work, original collector.ManualLiveSource) {
	t.Helper()
	q := nativeLiveRequest(view, w)
	q.Manual = &original
	q.Inspect = false
	if _, e := n.read(ctx, ch, q); e == nil {
		t.Fatal("original ended finite source still readable")
	}
}
func nativeLiveEnqueue(ctx context.Context, ch *delivery.NodeChannel, view delivery.NodeView, p collector.PacketCapture, startBy time.Time) (collector.Work, error) {
	if p.Observation == nil && p.Arguments == nil {
		return ch.EnqueuePacket(view.Identity.NodeUID, p, startBy)
	}
	now := time.Now()
	id := view.Identity
	return ch.EnqueuePacketExpected(ctx, targets.PacketSourceObservation{PodUID: p.PodUID, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, p, startBy)
}
func nativeArgumentCanary(body []byte) bool {
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		var e artifact.ArgumentEventLine
		if json.Unmarshal(line, &e) != nil || e.Record != "event" {
			continue
		}
		for _, a := range e.Event.Arguments {
			if a.Name == "buffer" && strings.HasPrefix(a.Value, "base64:") {
				b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a.Value, "base64:"))
				if err == nil && bytes.Contains(b, []byte("ASSERVAT-LIVE-PRIVATE-CANARY")) {
					return true
				}
			}
		}
	}
	return false
}
func nativeHTTPProjection() collector.HTTPProjection {
	return collector.HTTPProjection{MaxFlows: 16, MaxHeaderBytes: 8 << 10, MaxFlowBytes: 64 << 10, MaxTotalBytes: 1 << 20, IdleTimeout: 10 * time.Second}
}
func nativeHTTPFinite(view delivery.NodeView, pod string, program []planning.BPFInstruction) collector.PacketCapture {
	now := time.Now().UTC()
	p := collector.PacketCapture{CaptureID: uuid.NewString(), PodUID: pod, Program: program, ProgramDigest: [32]byte(compiler.FilterProgramDigest(program)), Duration: 8 * time.Second, MaxBytes: 1 << 20, Raw: &collector.RawPrefix{Snaplen: artifact.MaxRawSnaplen}}
	h := nativeHTTPProjection()
	p.HTTP = &h
	id := view.Identity
	p.Observation = &collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{3}, ProgramDigest: p.ProgramDigest, ExpectationDigest: [32]byte{2}, AccountingRule: collector.ObservationAccountingRule(), SessionID: uuid.NewString(), Fence: uuid.NewString(), CaptureID: p.CaptureID, ActionID: "native-live-http", PodUID: pod, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch}, StartedAt: now, StartBy: now.Add(5 * time.Second), SessionUntil: now.Add(13 * time.Second), LeaseUntil: now.Add(13 * time.Second), Duration: p.Duration, Sequence: 1, Credit: 64 << 20, BytesPerSecond: 16 << 20}
	return p
}
func nativeHTTPSource(view delivery.NodeView, pod string, program []planning.BPFInstruction) collector.PacketSource {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := view.Identity
	resources := collector.SourceResources{PolicyUID: "synthetic-reviewed-http-policy"}
	h := nativeHTTPProjection()
	b := collector.SourceBinding{RootID: uuid.NewString(), PolicyUID: resources.PolicyUID, AcceptanceID: uuid.NewString(), SourceID: uuid.NewString(), Fence: uuid.NewString(), ActionID: "native-live-http", ObservationGrantID: uuid.NewString(), AudienceDigest: [32]byte{9}, PodUID: pod, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ProgramDigest: [32]byte(compiler.FilterProgramDigest(program)), ResourceDigest: delivery.SourceResourcesDigest(resources)}
	return collector.PacketSource{HTTP: &h, Permit: collector.SourcePermit{Binding: b, StartedAt: now, IssuedAt: now, HardUntil: now.Add(30 * time.Second), StartBy: now.Add(5 * time.Second), DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 128 << 20, BytesPerSecond: 16 << 20}, Program: program, Resources: resources, Ring: collector.SourceRingLimits{MaxAge: 15 * time.Second, MaxBytes: 16 << 20, SegmentBytes: 4 << 20, MaxSegments: 4, MaxFrozenBytes: 8 << 20, MaxConcurrentSnapshots: 1}}
}
func (n *nativeLiveQualification) sourceRows(t *testing.T, ctx context.Context, ch *delivery.NodeChannel, s collector.PacketSource, projection string) collector.LiveRead {
	t.Helper()
	b := s.Permit.Binding
	q := collector.LiveRead{Binding: b, ClusterID: "50000000-0000-4000-8000-000000000001", NamespaceUID: uuid.NewString(), WorkloadUID: uuid.NewString(), Projection: projection, PrivacyUntil: s.Permit.HardUntil, Head: true, Limit: 20, ReplyBytes: 24 << 10}
	var head v.NodeReply
	var err error
	attempts := 4
	if projection == v.Syscall {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		head, err = n.read(ctx, ch, q)
		if err == nil {
			break
		}
	}
	if err != nil || len(head.Rows) != 0 {
		t.Fatal("actual source passive head", err)
	}
	nativeLiveRows(t, q, head)
	q.Head = false
	q.WaitMS = 1000
	q.AfterSequence = head.Position.Sequence
	count := 0
	for i := 0; i < 2; i++ {
		out, e := n.read(ctx, ch, q)
		if e != nil {
			t.Fatal("actual ongoing live rows", e)
		}
		nativeLiveRows(t, q, out)
		count += len(out.Rows)
		q.AfterSequence = out.Position.Sequence
	}
	if count == 0 {
		t.Fatal("ongoing source yielded no approved rows", projection)
	}
	return q
}

// Closed alone is an ACK, not a join. In this serial phase the original
// report proves no other source/frozen reservation, so a newer exact-source
// report with zero reservations proves finishLocked observed engineExited.
func nativeHTTPJoinedReport(view delivery.NodeView, source collector.PacketSource, after time.Time) (collector.SourceStatus, bool) {
	b := source.Permit.Binding
	id := view.Identity
	if !view.Current || id.NodeUID != b.NodeUID || id.BootID != b.BootID || id.PodUID != b.CollectorPodUID || id.Epoch != b.CollectorEpoch || view.Report == nil || !view.ReportedAt.After(after) || !view.Report.ObservedAt.After(after) || view.Report.Budget.RingReserved != 0 || view.Report.Budget.FrozenReserved != 0 {
		return collector.SourceStatus{}, false
	}
	for _, s := range view.Report.Sources {
		if s.SourceID == b.SourceID && s.Closed && s.Fence == b.Fence && s.Credit == source.Permit.Credit && s.IssuedAt.Equal(source.Permit.IssuedAt) && s.LeafUntil.Equal(source.Permit.LeafUntil) && s.ObservedBytes > 0 {
			return s, true
		}
	}
	return collector.SourceStatus{}, false
}
func (n *nativeLiveQualification) http(t *testing.T, parent context.Context, ch *delivery.NodeChannel, view delivery.NodeView, pod string, program []planning.BPFInstruction, sink *testPacketSink, results map[string]any) {
	t.Helper()
	ctx, done := n.phase(t, parent)
	defer done()
	if view.Report == nil || len(view.Report.Sources) != 0 || view.Report.Budget.RingReserved != 0 || view.Report.Budget.FrozenReserved != 0 {
		t.Fatal("serial HTTP phase lacks original zero-reservation/source baseline")
	}
	source := nativeHTTPSource(view, pod, program)
	b := source.Permit.Binding
	call, cancel := context.WithDeadline(ctx, source.Permit.DispatchUntil)
	_, e := ch.EnqueueSourceExpected(call, targets.PacketSourceObservation{PodUID: pod, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, ObservedAt: source.Permit.IssuedAt, FreshUntil: source.Permit.DispatchUntil}, source)
	cancel()
	if e != nil {
		t.Fatal("synthetic reviewed HTTP source dispatch", e)
	}
	q := n.sourceRows(t, ctx, ch, source, v.HTTP)
	p := nativeHTTPFinite(view, pod, program)
	w, e := nativeLiveEnqueue(ctx, ch, view, p, p.Observation.StartBy)
	if e != nil {
		t.Fatal(e)
	}
	original := n.manual(t, ctx, ch, view, w, false)
	var r collector.PacketResult
	var body []byte
	nativeLiveWait(t, ctx, "finite HTTP terminal upload", func() bool { var ok bool; r, body, _, ok = sink.get(p.CaptureID); return ok })
	// An upload follows the actual engine return; the cancel ACK alone is not join.
	if r.Failure != "" || r.WorkID != w.ID || !r.StartedAt.Equal(original.StartedAt) || r.EndedAt.Before(r.StartedAt) || r.NativeType != artifact.HTTPHeadersArtifact {
		t.Fatal("finite HTTP original terminal", r)
	}
	limits := httpheaders.Limits{MaxFlows: p.HTTP.MaxFlows, MaxHeaderBytes: p.HTTP.MaxHeaderBytes, MaxFlowBytes: p.HTTP.MaxFlowBytes, MaxTotalBytes: p.HTTP.MaxTotalBytes, IdleTimeout: p.HTTP.IdleTimeout}
	finiteCount, err := httpheaders.CheckProjection(bytes.NewReader(body), limits, p.MaxBytes)
	if err != nil || finiteCount == 0 {
		t.Fatal("finite HTTP observer lost native evidence", finiteCount, err)
	}
	n.ended(t, ctx, ch, view, w, original)
	issued := time.Now().UTC().Truncate(time.Microsecond)
	// The synthetic HTTP load reaches about 1 MB/s (native run 42475454686
	// refused a 1 MiB copy of the 3 s pre-window at window: CaptureBusy), so
	// the source ring, frozen copy and saved output allow 8 MiB.
	snapshot := collector.SourceSnapshot{Binding: b, CaptureID: uuid.NewString(), AttemptID: uuid.NewString(), ExpectationDigest: [32]byte{4}, Request: artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(delivery.SourceBindingDigest(b)), SourceID: b.SourceID, Fence: b.Fence, SnapshotID: uuid.NewString(), SourceStartedAt: source.Permit.StartedAt, SourceHardUntil: source.Permit.HardUntil, T0: issued, IssuedAt: issued, StartBy: issued.Add(5 * time.Second), ProcessingUntil: issued.Add(10 * time.Second), Before: 3 * time.Second, MaxBytes: 8 << 20}}
	snapshot.Request.HTTP = artifact.RecordingHTTP{MaxFlows: p.HTTP.MaxFlows, MaxHeaderBytes: p.HTTP.MaxHeaderBytes, MaxFlowBytes: p.HTTP.MaxFlowBytes, MaxTotalBytes: p.HTTP.MaxTotalBytes, IdleMillis: p.HTTP.IdleTimeout.Milliseconds()}
	call, cancel = context.WithTimeout(ctx, 4*time.Second)
	snapshotWork, e := ch.EnqueueSourceSnapshot(call, snapshot)
	cancel()
	if e != nil {
		t.Fatal("HTTP saved native dispatch", e)
	}
	var saved collector.PacketResult
	var native []byte
	waitFrom := time.Now()
	nativeLiveWaitDiagnosed(t, ctx, "HTTP source saved window", func() bool { var ok bool; saved, native, _, ok = sink.get(snapshot.CaptureID); return ok }, func() string {
		return nativeSourceDiagnosis(ch, b, snapshotWork.ID, waitFrom, n.elapsed)
	})
	if saved.Failure != "" || saved.NativeType != artifact.HTTPHeadersArtifact || saved.Snapshot == nil {
		t.Fatal("HTTP source saved window", saved)
	}
	savedCount, e := httpheaders.CheckProjection(bytes.NewReader(native), limits, snapshot.Request.MaxBytes)
	if e != nil || savedCount == 0 {
		t.Fatal("HTTP saved native canonical check", savedCount, e)
	}
	stopAt := time.Now()
	call, cancel = context.WithTimeout(ctx, 3*time.Second)
	_, e = ch.EnqueueSourceStop(call, b, time.Now().Add(2*time.Second))
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	var stopped collector.SourceStatus
	var closedObserved time.Time
	nativeLiveWait(t, ctx, "explicit HTTP stop joined/closed report and original reservation release", func() bool {
		current, ok := ch.NodeByUID(b.NodeUID)
		if !ok {
			return false
		}
		stopped, ok = nativeHTTPJoinedReport(current, source, stopAt)
		if ok {
			closedObserved = current.Report.ObservedAt
		}
		return ok
	})
	q.Head = true
	q.WaitMS = 0
	if _, e = n.read(ctx, ch, q); e == nil {
		t.Fatal("stopped HTTP source still serves rows")
	}
	results["liveHTTPNode"] = map[string]any{"scope": "real Gadget/private node transport; synthetic source/reviewer authority, not SQL/public C3", "sourceID": b.SourceID, "originalGrantID": b.ObservationGrantID, "originalHardUntil": source.Permit.HardUntil, "sourceClosedObservedAt": closedObserved, "naturalStopped": stopped.Stopped, "observedWireBytes": stopped.ObservedBytes, "savedNativeBytes": len(native), "savedNativeSHA256": sha256.Sum256(native), "finiteNativeRecords": finiteCount, "savedNativeRecords": savedCount, "finiteEndedAt": r.EndedAt}
}
func nativeLiveWait(t *testing.T, ctx context.Context, name string, ready func() bool) {
	t.Helper()
	nativeLiveWaitDiagnosed(t, ctx, name, ready, nil)
}

// nativeLiveWaitDiagnosed reports diagnose() with the failure, so a timeout
// names the node-side state instead of only the context error.
func nativeLiveWaitDiagnosed(t *testing.T, ctx context.Context, name string, ready func() bool, diagnose func() string) {
	t.Helper()
	for !ready() {
		select {
		case <-ctx.Done():
			if diagnose != nil {
				t.Fatal(name, ctx.Err(), diagnose())
			}
			t.Fatal(name, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// nativeSourceDiagnosis names the snapshot work's receipt and the source's
// latest reported status; it carries no evidence bytes.
func nativeSourceDiagnosis(ch *delivery.NodeChannel, b collector.SourceBinding, workID string, waitFrom time.Time, phaseElapsed time.Duration) string {
	view, ok := ch.NodeByUID(b.NodeUID)
	if !ok || view.Report == nil {
		return "no current node report"
	}
	out := fmt.Sprintf("waited=%s earlier-phases=%s report-seq=%d observed=%s", time.Since(waitFrom).Round(time.Millisecond), phaseElapsed.Round(time.Millisecond), view.Report.Sequence, view.Report.ObservedAt.Format(time.RFC3339Nano))
	for _, r := range view.Report.Receipts {
		if r.WorkID == workID {
			out += fmt.Sprintf(" receipt=%s/%s", r.Outcome, r.Reason)
		}
	}
	for _, src := range view.Report.Sources {
		if src.SourceID == b.SourceID {
			out += fmt.Sprintf(" source closed=%t stopped=%t inputUnknown=%t observed=%d/%d leafUntil=%s snapshotUntil=%s", src.Closed, src.Stopped, src.InputUnknown, src.ObservedBytes, src.Credit, src.LeafUntil.Format(time.RFC3339Nano), src.SnapshotUntil.Format(time.RFC3339Nano))
		}
	}
	return out
}
func nativeSyscallCapture(view delivery.NodeView, pod string, args bool) collector.PacketCapture {
	now := time.Now().UTC()
	p := collector.PacketCapture{CaptureID: uuid.NewString(), PodUID: pod, Duration: 8 * time.Second, MaxBytes: 1 << 20, Syscalls: &collector.SyscallFilter{Names: []string{"read"}, MaxEvents: 10000, MaxTrackedThreads: 128}, MaxEventsPerSecond: 1000}
	if args {
		p.Syscalls.Names = []string{"write"}
		defs, _ := syscalls.ArgumentDefinitions(p.Syscalls.Names, true, 128)
		raw, _ := hex.DecodeString(gadget.ArgumentObjectSHA256)
		var program [32]byte
		copy(program[:], raw)
		id := view.Identity
		p.Arguments = &collector.ArgumentObservationPermit{Binding: collector.ArgumentObservationBinding{Scope: [32]byte{3}, ProgramDigest: program, DefinitionDigest: syscalls.ArgumentDefinitionDigest(defs), ExpectationDigest: [32]byte{2}, AccountingRule: collector.ArgumentObservationAccountingRule(), SessionID: uuid.NewString(), Fence: uuid.NewString(), CaptureID: p.CaptureID, ActionID: "native-live-args", PodUID: pod, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch}, StartedAt: now, StartBy: now.Add(5 * time.Second), SessionUntil: now.Add(13 * time.Second), LeaseUntil: now.Add(13 * time.Second), Duration: p.Duration, Sequence: 1, EventCredit: 10000, ByteCredit: 8 << 20, EventsPerSecond: 1000, BytesPerSecond: 1 << 20, MaxProbeBytes: int64(syscalls.ArgumentMaxProbeBytes(defs)), MaxBytesPerEvent: 128, MaxTrackedThreads: 128, CaptureBuffers: true}
	}
	return p
}
func (n *nativeLiveQualification) syscalls(t *testing.T, parent context.Context, ch *delivery.NodeChannel, view delivery.NodeView, pod string, sink *testPacketSink, results map[string]any) {
	t.Helper()
	ctx, done := n.phase(t, parent)
	defer done()
	for _, args := range []bool{false, true} {
		p := nativeSyscallCapture(view, pod, args)
		startBy := time.Now().Add(5 * time.Second)
		if args {
			startBy = p.Arguments.StartBy
		}
		w, e := nativeLiveEnqueue(ctx, ch, view, p, startBy)
		if e != nil {
			t.Fatal("finite syscall dispatch", e)
		}
		original := n.manual(t, ctx, ch, view, w, !args)
		var r collector.PacketResult
		var body []byte
		nativeLiveWait(t, ctx, "finite syscall terminal upload", func() bool { var ok bool; r, body, _, ok = sink.get(p.CaptureID); return ok })
		if r.WorkID != w.ID || (args && (r.Failure != "" || r.Retained == 0)) || (!args && r.Failure != collector.ReasonCaptureFailed) || !r.StartedAt.Equal(original.StartedAt) || r.EndedAt.Before(r.StartedAt) {
			t.Fatal("finite syscall original terminal", r)
		}
		if args && !nativeArgumentCanary(body) {
			t.Fatal("native argument fixture did not actually capture canary")
		}
		n.ended(t, ctx, ch, view, w, original)
		name := "liveFiniteSyscalls"
		if args {
			name = "liveFiniteArguments"
		}
		results[name] = map[string]any{"nativeBytes": len(body), "retained": r.Retained, "originalStart": original.StartedAt, "originalHardEnd": original.HardUntil, "nativeEnd": r.EndedAt, "stopRequested": !args, "scope": "real original engine+private node transport; accepted authority/observation permit synthetic; terminal upload follows engine join, no reservation refund inferred"}
	}
}
func TestNativeLiveQualificationTypedPlans(t *testing.T) {
	marker := artifact.ArgumentEventLine{Record: "event", Event: artifact.RawArgumentEvent{Arguments: []artifact.ArgumentValue{{Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte("ASSERVAT-LIVE-PRIVATE-CANARY"))}}}}
	raw, _ := json.Marshal(marker)
	if !nativeArgumentCanary(raw) || nativeArgumentCanary([]byte(`{"record":"event"}`)) {
		t.Fatal("native encoded argument canary validator")
	}
	id := collector.Identity{NodeUID: uuid.NewString(), BootID: uuid.NewString(), PodUID: uuid.NewString(), Epoch: uuid.NewString()}
	view := delivery.NodeView{Identity: id}
	pod := uuid.NewString()
	program := []planning.BPFInstruction{{Code: 6, K: 65535}}
	source := nativeHTTPSource(view, pod, program)
	if !source.Valid() || source.Permit.Binding.ObservationGrantID == "" {
		t.Fatal("HTTP original reviewed source plan invalid")
	}
	after := time.Now()
	report := collector.Report{ObservedAt: after.Add(time.Second), Sources: []collector.SourceStatus{{SourceID: source.Permit.Binding.SourceID, Fence: source.Permit.Binding.Fence, Closed: true, Credit: source.Permit.Credit, IssuedAt: source.Permit.IssuedAt, LeafUntil: source.Permit.LeafUntil, ObservedBytes: 1}}}
	current := delivery.NodeView{Identity: id, Current: true, ReportedAt: after.Add(time.Second), Report: &report}
	if got, ok := nativeHTTPJoinedReport(current, source, after); !ok || got.Stopped || !got.SourceStoppedAt.IsZero() {
		t.Fatal("closed join report mislabeled naturalstop")
	}
	for name, edit := range map[string]func(*delivery.NodeView){
		"old arrival": func(v *delivery.NodeView) { v.ReportedAt = after }, "old observation": func(v *delivery.NodeView) { v.Report.ObservedAt = after },
		"unjoined source": func(v *delivery.NodeView) { v.Report.Budget.RingReserved = 1 }, "unjoined snapshot": func(v *delivery.NodeView) { v.Report.Budget.FrozenReserved = 1 },
		"wrong fence": func(v *delivery.NodeView) { v.Report.Sources[0].Fence = uuid.NewString() }, "credit changed": func(v *delivery.NodeView) { v.Report.Sources[0].Credit++ },
		"leaf changed": func(v *delivery.NodeView) {
			v.Report.Sources[0].LeafUntil = v.Report.Sources[0].LeafUntil.Add(time.Second)
		}, "open": func(v *delivery.NodeView) { v.Report.Sources[0].Closed = false },
		"replacement": func(v *delivery.NodeView) { v.Identity.Epoch = uuid.NewString() },
	} {
		t.Run(name, func(t *testing.T) {
			v := current
			r := report
			r.Sources = append([]collector.SourceStatus(nil), report.Sources...)
			v.Report = &r
			edit(&v)
			if _, ok := nativeHTTPJoinedReport(v, source, after); ok {
				t.Fatal("nonjoined/foreign report accepted")
			}
		})
	}
	for _, p := range []collector.PacketCapture{nativeHTTPFinite(view, pod, program), nativeSyscallCapture(view, pod, false), nativeSyscallCapture(view, pod, true)} {
		if !p.Valid() {
			t.Fatal("finite native plan invalid", p)
		}
		w := collector.Work{ID: uuid.NewString(), NotAfter: time.Now().Add(5 * time.Second), Packet: &p}
		q := nativeLiveRequest(view, w)
		if !q.Valid() {
			t.Fatal("passive native request invalid")
		}
		if q.Manual.ObservationKind == "" && (p.Arguments != nil || p.Observation != nil) {
			t.Fatal("sensitive permit omitted")
		}
	}
}
