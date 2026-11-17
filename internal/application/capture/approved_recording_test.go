package capture

import (
	"context"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

type availableRecording struct{ fixture *investigationFixture }

func (a availableRecording) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return a.fixture.svc.Targets.ResolvePod(ctx, r)
}
func (availableRecording) PacketRecorder(context.Context, targets.PodResolution) error { return nil }

// SQL separately qualifies retained immutable reads and current-grant locking.
// This port deliberately returns the original expired blueprint to the service.
type retainedRecording struct {
	*investigationFixture
	seen []value.Admission
}

var reachedRecordingAdmission = errors.New("test reached recording admission")

func (f *retainedRecording) AdmitReviewedContext(_ context.Context, _ value.ContextPreview, a value.Admission) (value.Accepted, error) {
	f.seen = append(f.seen, a)
	return value.Accepted{}, reachedRecordingAdmission
}

var _ identities.CurrentIdentity = fixtureIdentityResolverHandle{}
