package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type expectedRecordingNodes struct {
	fakeRecordingNodes
	source   targets.PacketSourceObservation
	expected int
}

func (n *expectedRecordingNodes) EnqueuePacketExpected(_ context.Context, source targets.PacketSourceObservation, p collector.PacketCapture, startBy time.Time) (collector.Work, error) {
	n.source = source
	n.expected++
	return n.EnqueuePacket(source.NodeUID, p, startBy)
}
func TestPolicyRecordingHolderPinsFrozenProgramAndOriginalPermit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := recordingExpectation(now)
	e.PodUID = "55555555-5555-4555-8555-555555555555"
	e.ActionID = "a0123456789abcdef01234567"
	e.Recording.Filter = &artifact.RecordingFilter{Expression: "tcp[13] & 2 != 0", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}
	program := []planning.BPFInstruction{{Code: 6, K: 65535}}
	source := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	original := collector.ObservationPermit{Binding: collector.ObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte(compiler.FilterProgramDigest(program)), ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(e)), AccountingRule: collector.ObservationAccountingRule(), SessionID: "66666666-6666-4666-8666-666666666666", Fence: "77777777-7777-4777-8777-777777777777", CaptureID: e.CaptureUID, ActionID: e.ActionID, PodUID: e.PodUID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, CollectorEpoch: source.CollectorEpoch}, StartedAt: now, SessionUntil: now.Add(5 * time.Second), LeaseUntil: now.Add(5 * time.Second), StartBy: now.Add(2 * time.Second), Duration: 2 * time.Second, Sequence: 1, Credit: 1 << 20, BytesPerSecond: 1 << 20}
	for _, test := range []struct {
		name   string
		change func(*collector.ObservationPermit, *artifact.ContextExpectation, *targets.PacketSourceObservation)
	}{
		{"valid", func(*collector.ObservationPermit, *artifact.ContextExpectation, *targets.PacketSourceObservation) {}},
		{"program", func(p *collector.ObservationPermit, _ *artifact.ContextExpectation, _ *targets.PacketSourceObservation) {
			p.Binding.ProgramDigest = [32]byte{9}
		}},
		{"frozen-expectation", func(_ *collector.ObservationPermit, e *artifact.ContextExpectation, _ *targets.PacketSourceObservation) {
			e.Recording.MaxBytes = 64 << 10
		}},
		{"source-epoch", func(_ *collector.ObservationPermit, _ *artifact.ContextExpectation, s *targets.PacketSourceObservation) {
			s.CollectorEpoch = "replacement"
		}},
		{"expired-facts", func(_ *collector.ObservationPermit, _ *artifact.ContextExpectation, s *targets.PacketSourceObservation) {
			s.FreshUntil = now
		}},
		{"expired-start", func(p *collector.ObservationPermit, _ *artifact.ContextExpectation, _ *targets.PacketSourceObservation) {
			p.StartBy = now
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			nodes := &expectedRecordingNodes{}
			// This resolver must never be consulted: the same-work source has already
			// resolved the actual Pod/node graph and the expected queue rechecks it.
			h := NewConnectorRecordings(nodes, nil, func() time.Time { return now }, func(string) {})
			current := e
			current.Recording = e.Recording.Clone()
			receipt, s := original, source
			test.change(&receipt, &current, &s)
			keys := &objectstore.PreparedArtifact{}
			p := h.Prepare(keys, current)
			queued, err := p.StartPolicyRecording(t.Context(), artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), s, receipt)
			if test.name != "valid" {
				if err == nil || nodes.expected != 0 || len(nodes.work) != 0 || p.prepared != keys {
					t.Fatalf("refusal consumed keys or queued: %v/%d", err, nodes.expected)
				}
				p.Close()
				return
			}
			if err != nil || !queued.Equal(now) || nodes.expected != 1 || len(nodes.work) != 1 || p.prepared != nil || nodes.source != source {
				t.Fatal("typed queue", queued, err, nodes.expected)
			}
			work := nodes.work[0]
			if work.Packet.Observation == nil || *work.Packet.Observation != original || !work.NotAfter.Equal(original.StartBy) {
				t.Fatal("permit or cutoff changed", work)
			}
			if _, err = p.StartPolicyRecording(t.Context(), artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), source, original); err == nil || nodes.expected != 1 {
				t.Fatal("repeated start", err)
			}
		})
	}
}
