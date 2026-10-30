package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func TestSourceSnapshotActualChannelDeliversOriginalWindowOnce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	clk := &clock{t: now}
	ch, err := NewNodeChannel(sourceNodeAttester{}, &fakeIssuer{}, clk.now, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, id, err := ch.Enroll(t.Context(), "127.0.0.1", []byte("token"), []byte("csr"), boot, epochA)
	if err != nil {
		t.Fatal(err)
	}
	peer := NodePeer{NodeUID: id.NodeUID, Epoch: id.Epoch}
	sink := &recordingSink{}
	ch.SetPacketSink(sink)
	uuid := "33333333-3333-4333-8333-333333333333"
	b := collector.SourceBinding{RootID: uuid, PolicyUID: "policy", AcceptanceID: uuid, SourceID: uuid, Fence: uuid, ActionID: "packets", PodUID: uuid, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}, AudienceDigest: [32]byte{7}}
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(SourceBindingDigest(b)), SourceID: uuid, Fence: uuid, SnapshotID: uuid, SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(5 * time.Second), ProcessingUntil: now.Add(time.Minute), Before: 30 * time.Second, MaxBytes: 65536}
	snapshot := collector.SourceSnapshot{AttemptID: uuid, WriterPodUID: uuid, WriterEpoch: uuid, Binding: b, CaptureID: uuid, ExpectationDigest: [32]byte{5}, Request: q}
	ctx, cancel := context.WithDeadline(t.Context(), q.StartBy)
	defer cancel()
	work, err := ch.EnqueueSourceSnapshot(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := collector.PacketResult{WorkID: work.ID, CaptureID: uuid, StartedAt: artifact.SourceSnapshotAnchor(q), EndedAt: now, Seen: 1, Retained: 1, CapturedBytes: 3, Snaplen: 134, Snapshot: &artifact.SourceSnapshotOutcome{NativeSHA256: artifact.Digest(sha256.Sum256([]byte("abc"))), SourceSnapshotCoverage: artifact.SourceSnapshotCoverage{Request: q, AcceptedExpectationDigest: artifact.Digest(snapshot.ExpectationDigest), NativeBytes: 3, Retained: 1, CompletedAt: now}}}
	// Acquisition precedes dispatch. Delivery uses original processing cutoff,
	// not the already expired five-second enqueue interval.
	clk.add(20 * time.Second)
	if err = ch.DeliverPacket(t.Context(), peer, epochA, result, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatal("typed snapshot never reached existing output sink", err)
	}
	if len(sink.got) != 1 || string(sink.body[0]) != "abc" || !sink.got[0].StartedAt.Equal(q.T0.Add(-q.Before)) {
		t.Fatal("changed original window", sink.got)
	}
	if err = ch.DeliverPacket(t.Context(), peer, epochA, result, bytes.NewReader([]byte("abc"))); err == nil {
		t.Fatal("snapshot result delivered twice")
	}
}

func TestSourceSnapshotCancellationNeedsExactAcceptedNodeReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	clk := &clock{t: now}
	channel, err := NewNodeChannel(sourceNodeAttester{}, &fakeIssuer{}, clk.now, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, id, err := channel.Enroll(t.Context(), "127.0.0.1", []byte("token"), []byte("csr"), boot, epochA)
	if err != nil {
		t.Fatal(err)
	}
	peer := NodePeer{NodeUID: id.NodeUID, Epoch: id.Epoch}
	uuid := "33333333-3333-4333-8333-333333333333"
	b := collector.SourceBinding{RootID: uuid, PolicyUID: "policy", AcceptanceID: uuid, SourceID: uuid, Fence: uuid, ActionID: "packets", PodUID: uuid, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}, AudienceDigest: [32]byte{7}}
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(SourceBindingDigest(b)), SourceID: uuid, Fence: uuid, SnapshotID: uuid, SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	x := collector.SourceSnapshot{Binding: b, CaptureID: uuid, AttemptID: uuid, WriterPodUID: uuid, WriterEpoch: uuid, ExpectationDigest: [32]byte{5}, Request: q}
	// Cancellation after the original start cutoff does not need a new source
	// observation or a currently renewable source leaf.
	clk.add(20 * time.Second)
	until := clk.now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	work, err := channel.EnqueueSourceSnapshotCancel(ctx, x, until)
	if err != nil {
		t.Fatal(err)
	}
	if _, joined := channel.SourceSnapshotCancellation(x, work.ID); joined {
		t.Fatal("enqueue fabricated join")
	}
	report := report(1, clk.now())
	report.Receipts = []collector.Receipt{{WorkID: work.ID, Sequence: work.Sequence + 1, Outcome: collector.OutcomeAccepted}}
	if err = channel.Report(peer, epochA, report); err != nil {
		t.Fatal(err)
	}
	if _, joined := channel.SourceSnapshotCancellation(x, work.ID); joined {
		t.Fatal("wrong sequence acknowledged cancellation")
	}
	clk.add(collector.StatusMinimumSpacing)
	report.Sequence++
	report.ObservedAt = clk.now()
	report.Receipts[0].Sequence = work.Sequence
	report.Receipts[0].Outcome = collector.OutcomeRefused
	if err = channel.Report(peer, epochA, report); err != nil {
		t.Fatal(err)
	}
	if _, joined := channel.SourceSnapshotCancellation(x, work.ID); joined {
		t.Fatal("refused control fabricated join")
	}
	clk.add(collector.StatusMinimumSpacing)
	report.Sequence++
	report.ObservedAt = clk.now()
	report.Receipts[0].Outcome = collector.OutcomeAccepted
	if err = channel.Report(peer, epochA, report); err != nil {
		t.Fatal(err)
	}
	if at, joined := channel.SourceSnapshotCancellation(x, work.ID); !joined || !at.Equal(clk.now()) {
		t.Fatal("exact joined receipt lost", at, joined)
	}
	// A later report without receipts cannot lose the acknowledged join.
	clk.add(collector.StatusMinimumSpacing)
	report.Sequence++
	report.ObservedAt = clk.now()
	report.Receipts = nil
	if err = channel.Report(peer, epochA, report); err != nil {
		t.Fatal(err)
	}
	if _, joined := channel.SourceSnapshotCancellation(x, work.ID); !joined {
		t.Fatal("joined receipt expired with next status")
	}
	wrong := x
	wrong.AttemptID = "44444444-4444-4444-8444-444444444444"
	if _, joined := channel.SourceSnapshotCancellation(wrong, work.ID); joined {
		t.Fatal("another attempt borrowed join")
	}
}
