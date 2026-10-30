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

type groupCancelPort struct {
	f         *investigationFixture
	work      SnapshotCancellationWork
	persisted bool
	calls     int
	lost      error
}

func (p *groupCancelPort) RequestCaptureCancellation(_ context.Context, check value.CancellationCheck) (SnapshotCancellationWork, error) {
	if !check.Valid(p.f.now) {
		return SnapshotCancellationWork{}, value.ErrDenied
	}
	p.persisted = true
	return p.work, nil
}

func (p *groupCancelPort) CancelSourceSnapshot(_ context.Context, _ string, snapshot collector.SourceSnapshot) error {
	if !p.persisted {
		panic("group dispatch preceded atomic durable cancellation")
	}
	p.calls++
	if p.calls == 1 {
		return p.lost
	}
	return nil
}

func TestGroupCancellationValidatesCohortAndKeepsUnknownChildrenPending(t *testing.T) {
	for _, name := range []string{"unknown-first-delivery", "wrong-parent", "duplicate-child", "invalid-last-child"} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			parent := fixtureID(80)
			lost := errors.New("unknown first child delivery")
			p := &groupCancelPort{f: f, lost: lost, work: SnapshotCancellationWork{Decision: value.Cancellation{CaptureID: parent, Phase: "Running", Revision: 5, Requested: true, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}, Group: &SnapshotCancellationGroup{ParentCaptureID: parent}}}
			for n := 0; n < 2; n++ {
				b := collector.SourceBinding{RootID: fixtureID(1), PolicyUID: "policy", AcceptanceID: fixtureID(21), SourceID: fixtureID(22 + n), Fence: fixtureID(25 + n), PodUID: fixtureID(28 + n), NodeUID: fixtureID(31), BootID: fixtureID(32), CollectorPodUID: fixtureID(33), CollectorEpoch: fixtureID(34), ActionID: "traffic", Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}, AudienceDigest: [32]byte{4}}
				x := collector.SourceSnapshot{Binding: b, CaptureID: fixtureID(40 + n), AttemptID: fixtureID(43 + n), WriterPodUID: fixtureID(46 + n), WriterEpoch: fixtureID(49 + n), ExpectationDigest: [32]byte{5}, Request: artifact.SourceSnapshotRequest{SourceID: b.SourceID, Fence: b.Fence, SnapshotID: fixtureID(52 + n), SourceBindingDigest: artifact.Digest{6}, SourceStartedAt: f.now.Add(-time.Minute), SourceHardUntil: f.now.Add(time.Minute), T0: f.now, IssuedAt: f.now, StartBy: f.now.Add(5 * time.Second), ProcessingUntil: f.now.Add(20 * time.Second), Before: time.Second, MaxBytes: 64 << 10}}
				if !x.Valid() {
					t.Fatal("invalid group cancellation fixture")
				}
				p.work.Group.Targets = append(p.work.Group.Targets, SnapshotCancellationTarget{ClusterID: fixtureID(4), Snapshot: x})
			}
			switch name {
			case "wrong-parent":
				p.work.Group.ParentCaptureID = fixtureID(99)
			case "duplicate-child":
				p.work.Group.Targets[1] = p.work.Group.Targets[0]
			case "invalid-last-child":
				p.work.Group.Targets[1].Snapshot.AttemptID = ""
			}
			s := CaptureCancellation{RootID: fixtureID(1), InstallationID: fixtureID(2), Ledger: p, Dispatcher: p, Recovery: f, Now: func() time.Time { return f.now }}
			out, err := s.Cancel(t.Context(), fixtureIdentityResolverHandle{f}, value.CancellationRequest{CaptureID: parent, ExpectedRevision: 1, IdempotencyKey: "parent-stop"})
			if name == "unknown-first-delivery" {
				if !errors.Is(err, lost) || p.calls != 2 || !out.Requested || out.Phase != "Running" || out.CaptureID != parent {
					t.Fatal("unknown delivery hid a sibling or claimed joined", out, err, p.calls)
				}
			} else if err == nil || p.calls != 0 {
				t.Fatal("invalid cohort partially dispatched", out, err, p.calls)
			}
		})
	}
}
