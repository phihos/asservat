package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type fakeRecordingNodes struct {
	available bool
	work      []collector.Work
}

func (n *fakeRecordingNodes) NodeByName(name string) (delivery.NodeView, bool) {
	adapter := collector.AdapterUnavailable
	if n.available {
		adapter = collector.AdapterAvailable
	}
	r := &collector.Report{Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: adapter}}}
	return delivery.NodeView{Identity: collector.Identity{NodeName: name, NodeUID: "node-1"}, Report: r, Current: true}, name == "worker"
}

func (n *fakeRecordingNodes) EnqueuePacket(uid string, p collector.PacketCapture, startBy time.Time) (collector.Work, error) {
	w := collector.Work{ID: "33333333-3333-4333-8333-333333333333", Sequence: 1, Kind: collector.WorkPacketCapture, NotAfter: startBy, Packet: &p}
	n.work = append(n.work, w)
	return w, nil
}

type fakePodNodes struct{ err error }

func (p fakePodNodes) PodNode(context.Context, artifact.PinnedPod) (string, error) {
	return "worker", p.err
}

func recordingExpectation(now time.Time) artifact.ContextExpectation {
	return artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.PCAPNGArtifact, CaptureUID: "11111111-1111-4111-8111-111111111111", PodUID: "pod-uid", NamespaceUID: "ns-uid",
		Registration: artifact.Registration{Location: artifact.Location{AttemptID: "22222222-2222-4222-8222-222222222222"}, AnchorAt: now, WriteUntil: now.Add(time.Minute)},
		Recording:    &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), DurationMillis: 2000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSnaplen}}
}

// ADR-248: the holder queues only on an available node, binds collects to the
// exact attempt and expectation, records a node failure without storing, and
// gives the keys away exactly once.
func TestConnectorRecordingsQueueCollectAndFail(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	nodes := &fakeRecordingNodes{available: true}
	h := NewConnectorRecordings(nodes, fakePodNodes{}, clock, func(string) {})
	e := recordingExpectation(now)
	pin := artifact.PinnedPod{UID: "pod-uid", NamespaceUID: "ns-uid", Namespace: "app", Name: "web"}
	if a, err := h.PacketRecorder(context.Background(), targets.RecorderRequest{}); err == nil || a.Outcome != "" {
		t.Fatal("invalid request answered")
	}
	p := h.Prepare(&objectstore.PreparedArtifact{}, e)
	queued, err := p.StartRecording(context.Background(), pin, now, now.Add(time.Second))
	if err != nil || !queued.Equal(now) || len(nodes.work) != 1 || nodes.work[0].Packet.Duration != 2*time.Second || nodes.work[0].Packet.ProgramDigest != [32]byte{} {
		t.Fatal(queued, err, nodes.work)
	}
	if _, err := p.StartRecording(context.Background(), pin, now, now.Add(time.Second)); !errors.Is(err, value.ErrDenied) {
		t.Fatal("the prepared keys were handed over twice")
	}
	w := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	if c, err := h.Collect(w); err != nil || c.State != evidence.RecordingPending {
		t.Fatal(c, err)
	}
	other := w
	other.AttemptID = "44444444-4444-4444-8444-444444444444"
	if _, err := h.Collect(other); err == nil {
		t.Fatal("a collect for another attempt answered")
	}
	result := collector.PacketResult{WorkID: nodes.work[0].ID, CaptureID: e.CaptureUID, StartedAt: now, EndedAt: now.Add(2 * time.Second), CapturedBytes: 260, Snaplen: 134, Failure: collector.ReasonTargetNotFound}
	if err := h.DeliverPacket(context.Background(), collector.Identity{NodeUID: "other-node"}, result, bytes.NewReader(make([]byte, 260))); err == nil {
		t.Fatal("another node delivered")
	}
	if err := h.DeliverPacket(context.Background(), collector.Identity{NodeUID: "node-1"}, result, bytes.NewReader(make([]byte, 260))); err != nil {
		t.Fatal(err)
	}
	if c, err := h.Collect(w); err != nil || c.State != evidence.RecordingFailed || c.Failure != "captureFailed" || !c.Valid(e.Registration) {
		t.Fatal(c, err)
	}
	// Expired outcomes are dropped.
	now = now.Add(2 * time.Minute)
	if _, err := h.Collect(w); err == nil {
		t.Fatal("expired outcome kept")
	}

	// An unavailable node refuses before anything is queued.
	nodes.available = false
	h2 := NewConnectorRecordings(nodes, fakePodNodes{}, clock, func(string) {})
	e.CaptureUID = "55555555-5555-4555-8555-555555555555"
	e.Registration.WriteUntil = now.Add(time.Minute)
	if _, err := h2.Prepare(&objectstore.PreparedArtifact{}, e).StartRecording(context.Background(), pin, now, now.Add(time.Second)); err == nil || len(nodes.work) != 1 {
		t.Fatal("queued on an unavailable node", err)
	}
	if a, err := h2.PacketRecorder(context.Background(), targets.RecorderRequest{Target: targets.Request{}, Pin: pin}); err == nil && a.Outcome == targets.RecorderAvailable {
		t.Fatal("unavailable recorder reported available")
	}
	h3 := NewConnectorRecordings(&fakeRecordingNodes{available: true}, fakePodNodes{err: errors.New("gone")}, clock, func(string) {})
	if _, err := h3.Prepare(&objectstore.PreparedArtifact{}, e).StartRecording(context.Background(), pin, now, now.Add(time.Second)); err == nil {
		t.Fatal("queued for a Pod that is not running")
	}
}

func TestLegacyRecordingStartCannotQueueRawPredicate(t *testing.T) {
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	nodes := &fakeRecordingNodes{available: true}
	holder := NewConnectorRecordings(nodes, fakePodNodes{}, func() time.Time { return now }, func(string) {})
	e := recordingExpectation(now)
	e.Recording.Filter = &artifact.RecordingFilter{Expression: "tcp[13] & 2 != 0", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}
	keys := &objectstore.PreparedArtifact{}
	prepared := holder.Prepare(keys, e)
	pin := artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID, Namespace: "app", Name: "web"}
	queued, err := prepared.StartRecording(context.Background(), pin, now, now.Add(time.Second))
	if !errors.Is(err, value.ErrUnavailable) || !queued.IsZero() || len(nodes.work) != 0 {
		t.Fatal("legacy start bypassed required observation permit", queued, err, len(nodes.work))
	}
	if prepared.prepared != keys {
		t.Fatal("refused legacy raw start transferred prepared ownership")
	}
	prepared.Close()
	if prepared.prepared != nil {
		t.Fatal("caller could not close refused preparation")
	}
}
