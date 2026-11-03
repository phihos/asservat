package evidence

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/targets"
)

// ProfileRecorder transfers one prepared artifact to the regional holder after
// the original local start was consumed. The endpoint request is the exact
// reviewed query, independently resolved again before the one node enqueue.
// started and until are the original committed start's times; neither retry nor
// endpoint resolution creates a new start interval.
type ProfileRecorder interface {
	StartProfile(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, endpoint targets.ProfileEndpointRequest) (time.Time, error)
}
