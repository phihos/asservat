package bootstrap

import (
	"context"

	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// ResolveSourceSnapshots reuses exact retained source reports. There is no Pod
// lookup, acquisition, report freshness renewal, or partial-selection response.
func (t reportedTargets) ResolveSourceSnapshots(ctx context.Context, requests []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error) {
	if ctx == nil || ctx.Err() != nil || !contextstart.ValidSourceSnapshotBatch(requests, contextstart.SourceSnapshotQueryBatchLimit) {
		return nil, targets.ErrInvalid
	}
	out := make([]targets.SourceSnapshotResolution, len(requests))
	for index, request := range requests {
		value, err := t.ResolveSourceSnapshot(ctx, request)
		if err != nil {
			return nil, err
		}
		out[index] = value
	}
	for _, value := range out {
		if ctx.Err() != nil || t.recordings == nil || !value.Valid(t.recordings.now()) {
			return nil, targets.ErrUnavailable
		}
	}
	return out, nil
}
