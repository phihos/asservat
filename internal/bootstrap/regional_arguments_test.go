package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

func regionalArgumentFixture(now time.Time) (artifact.ContextExpectation, targets.PacketSourceObservation, collector.ArgumentObservationPermit) {
	e := recordingExpectation(now)
	e.PodUID, e.ActionID = "55555555-5555-4555-8555-555555555555", "a0123456789abcdef01234567"
	e.NativeType, e.DataClass = artifact.SyscallArgumentsArtifact, "raw"
	e.Recording = &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 2000, MaxBytes: artifact.RecordingNativeLimit,
		Syscalls:  &artifact.RecordingSyscalls{Names: []string{"read", "write"}, ErrorsOnly: true, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 16},
		Arguments: &artifact.RecordingArguments{ProgramDigest: artifact.Digest{2}, DefinitionDigest: artifact.Digest{3}, AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1 << 20, CaptureBuffers: true}}
	s := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	p := collector.ArgumentObservationPermit{Binding: collector.ArgumentObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte{2}, DefinitionDigest: [32]byte{3}, ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(e)), AccountingRule: collector.ArgumentObservationAccountingRule(), SessionID: "66666666-6666-4666-8666-666666666666", Fence: "77777777-7777-4777-8777-777777777777", CaptureID: e.CaptureUID, ActionID: e.ActionID, PodUID: e.PodUID, NodeUID: s.NodeUID, BootID: s.BootID, CollectorPodUID: s.CollectorPodUID, CollectorEpoch: s.CollectorEpoch}, StartedAt: now, SessionUntil: now.Add(4 * time.Second), LeaseUntil: now.Add(4 * time.Second), StartBy: now.Add(2 * time.Second), Duration: 2 * time.Second, Sequence: 1, EventCredit: 1000, ByteCredit: 1 << 20, EventsPerSecond: 100, BytesPerSecond: 1 << 20, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxTrackedThreads: 16, CaptureBuffers: true}
	return e, s, p
}

func TestRegionalArgumentStartKeepsExactPermitAndFrozenRecording(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e, source, permit := regionalArgumentFixture(now)
	nodes := &expectedRecordingNodes{}
	h := NewConnectorRecordings(nodes, nil, func() time.Time { return now }, func(string) {})
	keys := &objectstore.PreparedArtifact{}
	p := h.Prepare(keys, e)
	// The caller cannot mutate the independently retained accepted expectation.
	e.Recording.Composition[0] = '['
	e.Recording.Syscalls.Names[0] = "close"
	e.Recording.Arguments.MaxBytesPerEvent++
	pin := artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}
	if _, err := p.StartRecording(t.Context(), pin, now, now.Add(time.Second)); err == nil || p.prepared != keys {
		t.Fatal("generic start bypassed the argument permit", err)
	}
	queued, err := p.StartArgumentRecording(t.Context(), pin, now, now.Add(time.Second), source, permit)
	if err != nil || !queued.Equal(now) || nodes.expected != 1 || len(nodes.work) != 1 || p.prepared != nil || nodes.source != source {
		t.Fatal("argument enqueue", queued, err, nodes.expected)
	}
	w := nodes.work[0]
	if !w.NotAfter.Equal(permit.StartBy) || !w.Packet.Valid() || w.Packet.Arguments == nil || *w.Packet.Arguments != permit || w.Packet.Observation != nil || w.Packet.Program != nil || w.Packet.ProgramDigest != [32]byte{} || w.Packet.Syscalls.Names[0] != "read" || !w.Packet.Syscalls.ErrorsOnly || w.Packet.Syscalls.MaxEvents != 1000 || w.Packet.MaxBytes != artifact.RecordingNativeLimit {
		t.Fatal("original permit, selection, or limits changed", w.Packet)
	}
	p.Close()
	held := h.held[e.CaptureUID]
	if held == nil || held.prepared != keys || held.nodeUID != source.NodeUID || held.workID != w.ID || held.digest != artifact.Digest(permit.Binding.ExpectationDigest) || !held.expires.Equal(e.Registration.WriteUntil.Add(recordingRetain)) {
		t.Fatal("writer ownership or original cutoff lost", held)
	}
}

func TestRegionalArgumentStartRefusesMismatchedAcceptedFacts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []string{"program", "definitions", "accounting", "expectation", "capture", "action", "pod", "node", "boot", "collector", "epoch", "probe", "read-width", "byte-rate", "event-rate", "threads", "buffers", "duration", "source-expired", "start-expired", "write-cutoff", "class", "type", "pin", "cancelled", "deadline", "after-lock-expiry", "capacity", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			e, source, permit := regionalArgumentFixture(now)
			pin := artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}
			until := now.Add(time.Second)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "program":
				permit.Binding.ProgramDigest[0]++
			case "definitions":
				permit.Binding.DefinitionDigest[0]++
			case "accounting":
				permit.Binding.AccountingRule[0]++
			case "expectation":
				permit.Binding.ExpectationDigest[0]++
			case "capture":
				permit.Binding.CaptureID = "other"
			case "action":
				permit.Binding.ActionID = "other"
			case "pod":
				source.PodUID = "other"
			case "node":
				source.NodeUID = "other"
			case "boot":
				source.BootID = "other"
			case "collector":
				source.CollectorPodUID = "other"
			case "epoch":
				source.CollectorEpoch = "other"
			case "probe":
				permit.MaxProbeBytes = 256
			case "read-width":
				permit.MaxBytesPerEvent++
			case "byte-rate":
				permit.BytesPerSecond++
			case "event-rate":
				permit.EventsPerSecond++
			case "threads":
				permit.MaxTrackedThreads++
			case "buffers":
				permit.CaptureBuffers = false
			case "duration":
				permit.Duration -= time.Second
			case "source-expired":
				source.FreshUntil = now
			case "start-expired":
				permit.StartBy = now
			case "write-cutoff":
				e.Registration.WriteUntil = permit.SessionUntil.Add(-time.Microsecond)
				permit.Binding.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
			case "class":
				e.DataClass = "metadata"
				permit.Binding.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
			case "type":
				e.NativeType = artifact.SyscallRecordsArtifact
				permit.Binding.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
			case "pin":
				pin.NamespaceUID = "other"
			case "cancelled":
				cancel()
			case "deadline":
				until = now
			}
			nodes := &expectedRecordingNodes{}
			calls := 0
			h := NewConnectorRecordings(nodes, nil, func() time.Time {
				calls++
				if mode == "after-lock-expiry" && calls > 1 {
					return until
				}
				return now
			}, func(string) {})
			if mode == "capacity" {
				for i := range maxHeldRecordings {
					h.held[fmt.Sprint(i)] = &heldRecording{expires: now.Add(time.Minute)}
				}
			}
			if mode == "duplicate" {
				h.held[e.CaptureUID] = &heldRecording{expires: now.Add(time.Minute)}
			}
			keys := &objectstore.PreparedArtifact{}
			p := h.Prepare(keys, e)
			_, err := p.StartArgumentRecording(ctx, pin, now, until, source, permit)
			if err == nil || nodes.expected != 0 || p.prepared != keys {
				t.Fatal("refusal affected queue or writer", err, nodes.expected)
			}
		})
	}
}

type uncertainArgumentNodes struct{ expectedRecordingNodes }

func (n *uncertainArgumentNodes) EnqueuePacketExpected(ctx context.Context, s targets.PacketSourceObservation, p collector.PacketCapture, until time.Time) (collector.Work, error) {
	_, _ = n.expectedRecordingNodes.EnqueuePacketExpected(ctx, s, p, until)
	return collector.Work{}, errors.New("lost queue reply")
}
func TestRegionalArgumentStartUnknownReplyCannotReuseWriter(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e, source, permit := regionalArgumentFixture(now)
	nodes := &uncertainArgumentNodes{}
	h := NewConnectorRecordings(nodes, nil, func() time.Time { return now }, func(string) {})
	p := h.Prepare(&objectstore.PreparedArtifact{}, e)
	for range 2 {
		if _, err := p.StartArgumentRecording(t.Context(), artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), source, permit); err == nil {
			t.Fatal("unknown reply accepted")
		}
	}
	if nodes.expected != 1 || len(nodes.work) != 1 || p.prepared != nil || len(h.held) != 1 || h.held[e.CaptureUID].workID != "" || h.held[e.CaptureUID].resultJoined {
		t.Fatal("unknown enqueue refilled writer", nodes.expected)
	}
}
func TestRegionalArgumentStartConcurrentCallsTransferWriterOnce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e, source, permit := regionalArgumentFixture(now)
	nodes := &expectedRecordingNodes{}
	h := NewConnectorRecordings(nodes, nil, func() time.Time { return now }, func(string) {})
	p := h.Prepare(&objectstore.PreparedArtifact{}, e)
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.StartArgumentRecording(t.Context(), artifact.PinnedPod{UID: e.PodUID, NamespaceUID: e.NamespaceUID}, now, now.Add(time.Second), source, permit)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 || nodes.expected != 1 || p.prepared != nil {
		t.Fatal("writer transferred repeatedly", accepted, nodes.expected)
	}
}
