package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"errors"
	"testing"
	"time"
)

func (f *cancellationFixture) CancelProcesses(_ context.Context, cluster string, stop collector.ProcessStop) error {
	if !f.persisted || f.work.Processes == nil || !f.work.Processes.Equal(stop) || cluster != stop.ClusterID {
		panic("process stop changed original persisted identity")
	}
	f.dispatches++
	return f.deliveryErr
}
func TestProcessCancellationDispatchesOnlyPersistedOriginalAndKeepsUnknownPending(t *testing.T) {
	f := newInvestigationFixture()
	stop := collector.ProcessStop{RootID: fixtureID(1), ClusterID: fixtureID(4), CaptureID: fixtureID(31), AttemptID: fixtureID(32), WriterPodUID: fixtureID(33), WriterEpoch: fixtureID(34), ExpectationDigest: artifact.Digest{1}, WriteUntil: f.now.Add(time.Minute)}
	lost := errors.New("unknown delivery")
	port := &cancellationFixture{f: f, deliveryErr: lost, work: SnapshotCancellationWork{ClusterID: stop.ClusterID, Processes: &stop, Decision: value.Cancellation{CaptureID: stop.CaptureID, Phase: "Running", Revision: 2, Requested: true, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}}}
	service := CaptureCancellation{RootID: stop.RootID, InstallationID: fixtureID(2), Ledger: port, Dispatcher: port, Recovery: f, Now: func() time.Time { return f.now }}
	request := value.CancellationRequest{CaptureID: stop.CaptureID, ExpectedRevision: 1, IdempotencyKey: "process-stop"}
	out, err := service.Cancel(t.Context(), fixtureIdentityResolverHandle{f}, request)
	if !errors.Is(err, lost) || !out.Requested || out.Phase != "Running" || out.ApplicationStopUnknown || port.dispatches != 1 {
		t.Fatal("process stop was not delivered or invented source join", out, err, port.dispatches)
	}
	original := port.work
	for _, mode := range []string{"mixed-profile", "mixed-recording", "wrong-root", "wrong-writer-scope", "profile-uncertainty"} {
		t.Run(mode, func(t *testing.T) {
			port.work = original
			changed := stop
			port.work.Processes = &changed
			switch mode {
			case "mixed-profile":
				port.work.Profile = &collector.ProfileStop{}
			case "mixed-recording":
				port.work.Recording = &collector.RecordingStop{}
			case "wrong-root":
				changed.RootID = fixtureID(99)
			case "wrong-writer-scope":
				changed.ClusterID = fixtureID(98)
			case "profile-uncertainty":
				port.work.Decision.ApplicationStopUnknown = true
			}
			if _, err := service.Cancel(t.Context(), fixtureIdentityResolverHandle{f}, request); err == nil || port.dispatches != 1 {
				t.Fatal("invalid process cancellation dispatched", mode)
			}
		})
	}
}
