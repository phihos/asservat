package bootstrap

import (
	"bytes"
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
)

// manualCancelNodes reports packet and syscall recorders and records the
// node Stop items queued for exact original work.
type manualCancelNodes struct {
	fakeRecordingNodes
	stops       int
	stoppedWork string
}

func (n *manualCancelNodes) NodeByName(name string) (delivery.NodeView, bool) {
	r := &collector.Report{Mechanisms: []collector.Availability{
		{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable},
		{Mechanism: collector.MechanismSyscall, Prerequisites: true, Adapter: collector.AdapterAvailable},
	}}
	return delivery.NodeView{Identity: collector.Identity{NodeName: name, NodeUID: "node-1"}, Report: r, Current: true}, name == "worker"
}

func (n *manualCancelNodes) EnqueuePacketCancel(_ context.Context, _, _, work string, _ time.Time) (collector.Work, error) {
	n.stops++
	n.stoppedWork = work
	return collector.Work{ID: "66666666-6666-4666-8666-666666666666"}, nil
}

func manualStop(e artifact.ContextExpectation) collector.RecordingStop {
	return collector.RecordingStop{RootID: "77777777-7777-4777-8777-777777777777", ClusterID: e.Registration.Location.ClusterID, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID,
		WriterPodUID: "88888888-8888-4888-8888-888888888888", WriterEpoch: "99999999-9999-4999-8999-999999999999", ExpectationDigest: evidence.ContextExpectationDigest(e), WriteUntil: e.Registration.WriteUntil}
}

// ADR-313: a manual packet or syscall metadata session stops through the
// node's exact original work item. Cancelled needs the original node result
// and its joined handling; the early-stop failure stores nothing.
func TestRegionalManualRecordingStopJoinsOriginalResult(t *testing.T) {
	for _, mode := range []string{"packet-metadata", "syscall-metadata"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			nodes := &manualCancelNodes{}
			h := NewConnectorRecordings(nodes, fakePodNodes{}, func() time.Time { return now }, func(string) {})
			e := recordingExpectation(now)
			e.Registration.Location.ClusterID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			if mode == "syscall-metadata" {
				e.NativeType = artifact.SyscallRecordsArtifact
				e.Recording = &artifact.Recording{Kind: "syscallTrace", Profile: "metadata", Snaplen: artifact.RecordingSyscallSnaplen, Composition: []byte("{}"), DurationMillis: 2000, MaxBytes: artifact.RecordingNativeLimit,
					Syscalls: &artifact.RecordingSyscalls{Names: []string{"read"}, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 64}}
			}
			pin := artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID, Namespace: "app", Name: "web"}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if _, err := h.Prepare(&objectstore.PreparedArtifact{}, e).StartRecording(ctx, pin, now, now.Add(time.Second)); err != nil || len(nodes.work) != 1 {
				t.Fatal("start", err, nodes.work)
			}
			collect := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
			stop := manualStop(e)
			if err := h.CancelRecording(ctx, stop); err != nil || nodes.stops != 1 || nodes.stoppedWork != nodes.work[0].ID {
				t.Fatal("stop did not target the original work", err, nodes.stops, nodes.stoppedWork)
			}
			if err := h.CancelRecording(ctx, stop); err != nil || nodes.stops != 1 {
				t.Fatal("stop replay queued again", err)
			}
			if c, err := h.Collect(collect); err != nil || c.State != evidence.RecordingPending {
				t.Fatal("queued stop invented a joined proof", c, err)
			}
			result := collector.PacketResult{WorkID: nodes.work[0].ID, CaptureID: e.CaptureUID, NativeType: e.NativeType, StartedAt: now, EndedAt: now, Failure: collector.ReasonCaptureFailed}
			if mode == "packet-metadata" {
				result.NativeType = ""
			}
			if err := h.DeliverPacket(ctx, collector.Identity{NodeUID: "other-node"}, result, bytes.NewReader(nil)); err == nil {
				t.Fatal("replacement node result accepted")
			}
			if c, _ := h.Collect(collect); c.State != evidence.RecordingPending {
				t.Fatal("replacement result terminated the session")
			}
			if err := h.DeliverPacket(ctx, collector.Identity{NodeUID: "node-1"}, result, bytes.NewReader(nil)); err != nil {
				t.Fatal(err)
			}
			c, err := h.Collect(collect)
			if err != nil || c.State != evidence.RecordingCancelled || c.RecordingCancellation == nil || !c.Valid(e.Registration) || c.Completion.Copies != (artifact.Copies{}) {
				t.Fatal("missing joined cancellation", c, err)
			}
			p := *c.RecordingCancellation
			if p.CaptureID != stop.CaptureID || p.AttemptID != stop.AttemptID || p.WriterPodUID != stop.WriterPodUID || p.WriterEpoch != stop.WriterEpoch || p.ExpectationDigest != stop.ExpectationDigest {
				t.Fatal("proof differs from the original writer stop", p)
			}
			now = now.Add(time.Second)
			if replay, err := h.Collect(collect); err != nil || replay.RecordingCancellation == nil || *replay.RecordingCancellation != p {
				t.Fatal("cancellation proof renewed", replay, err)
			}
			changed := stop
			changed.WriterEpoch = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			if err := h.CancelRecording(ctx, changed); err == nil {
				t.Fatal("replacement writer accepted")
			}
		})
	}
}

// A Stop that arrives before the start fences the delayed start but never
// claims the session stopped.
func TestRegionalManualRecordingStopFencesDelayedStart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	nodes := &manualCancelNodes{}
	h := NewConnectorRecordings(nodes, fakePodNodes{}, func() time.Time { return now }, func(string) {})
	e := recordingExpectation(now)
	e.Registration.Location.ClusterID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := h.CancelRecording(ctx, manualStop(e)); err != nil || nodes.stops != 0 {
		t.Fatal(err, nodes.stops)
	}
	pin := artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}
	if _, err := h.Prepare(&objectstore.PreparedArtifact{}, e).StartRecording(ctx, pin, now, now.Add(time.Second)); err == nil || len(nodes.work) != 0 {
		t.Fatal("late start escaped stop", err)
	}
	collect := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(e)}
	if c, err := h.Collect(collect); err != nil || c.State != evidence.RecordingPending {
		t.Fatal("tombstone claimed a joined stop", c, err)
	}
}
