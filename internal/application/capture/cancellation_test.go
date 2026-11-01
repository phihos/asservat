package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
)

type cancellationFixture struct {
	f           *investigationFixture
	work        SnapshotCancellationWork
	persisted   bool
	dispatches  int
	deliveryErr error
}

func (f *cancellationFixture) RequestCaptureCancellation(_ context.Context, check value.CancellationCheck) (SnapshotCancellationWork, error) {
	if !check.Valid(f.f.now) {
		return SnapshotCancellationWork{}, value.ErrDenied
	}
	f.persisted = true
	return f.work, nil
}
func (f *cancellationFixture) CancelSourceSnapshot(_ context.Context, cluster string, snapshot collector.SourceSnapshot) error {
	if !f.persisted || cluster != f.work.ClusterID || !snapshot.Equal(*f.work.Snapshot) {
		panic("dispatch preceded durable request or changed snapshot")
	}
	f.dispatches++
	return f.deliveryErr
}
func TestCaptureCancellationPersistsBeforeUnknownDeliveryAndNeverClaimsJoined(t *testing.T) {
	f := newInvestigationFixture()
	b := collector.SourceBinding{RootID: fixtureID(1), PolicyUID: "policy", AcceptanceID: fixtureID(21), SourceID: fixtureID(22), Fence: fixtureID(23), PodUID: fixtureID(24), NodeUID: fixtureID(25), BootID: fixtureID(26), CollectorPodUID: fixtureID(27), CollectorEpoch: fixtureID(28), ActionID: "traffic", Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}, AudienceDigest: [32]byte{4}}
	snapshot := collector.SourceSnapshot{Binding: b, CaptureID: fixtureID(31), AttemptID: fixtureID(32), ExpectationDigest: [32]byte{5}, Request: artifact.SourceSnapshotRequest{SourceID: b.SourceID, Fence: b.Fence, SnapshotID: fixtureID(33), SourceBindingDigest: artifact.Digest{6}, SourceStartedAt: f.now.Add(-time.Minute), SourceHardUntil: f.now.Add(time.Minute), T0: f.now, IssuedAt: f.now, StartBy: f.now.Add(5 * time.Second), ProcessingUntil: f.now.Add(20 * time.Second), Before: time.Second, MaxBytes: 64 << 10}}
	if !snapshot.Valid() {
		t.Fatal("valid snapshot fixture required")
	}
	original := snapshot
	lost := errors.New("unknown delivery")
	port := &cancellationFixture{f: f, deliveryErr: lost, work: SnapshotCancellationWork{ClusterID: fixtureID(4), Snapshot: &snapshot, Decision: value.Cancellation{CaptureID: snapshot.CaptureID, Phase: "Running", Revision: 2, Requested: true, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}}}
	service := CaptureCancellation{RootID: fixtureID(1), InstallationID: fixtureID(2), Ledger: port, Dispatcher: port, Recovery: f, Now: func() time.Time { return f.now }}
	request := value.CancellationRequest{CaptureID: snapshot.CaptureID, ExpectedRevision: 1, IdempotencyKey: "cancel-original"}
	out, err := service.Cancel(t.Context(), fixtureIdentityResolverHandle{f}, request)
	if !errors.Is(err, lost) || !out.Requested || out.Phase != "Running" || port.dispatches != 1 || !snapshot.Equal(original) {
		t.Fatal("unknown enqueue claimed closure or changed source", out, err)
	}
	port.work.Snapshot = nil
	port.work.Decision.Phase = "Cancelled"
	port.deliveryErr = nil
	out, err = service.Cancel(t.Context(), fixtureIdentityResolverHandle{f}, request)
	if err != nil || out.Phase != "Cancelled" || port.dispatches != 1 {
		t.Fatal("durable no-start cancellation unnecessarily dispatched", out, err)
	}
}
