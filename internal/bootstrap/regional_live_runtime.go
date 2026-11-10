package bootstrap

import (
	"context"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

// ResolveLiveRuntime returns only this connector's aggregate current reports.
// It performs no Kubernetes, SQL or object-store read and grants no authority.
func (t reportedTargets) ResolveLiveRuntime(ctx context.Context, request collector.LiveRuntimeRequest) (collector.LiveRuntimeSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || !request.Valid() || t.recordings == nil || t.recordings.nodes == nil || t.recordings.now == nil {
		return collector.LiveRuntimeSnapshot{}, targets.ErrUnavailable
	}
	source, ok := t.recordings.nodes.(interface {
		LiveRuntime(string) collector.LiveRuntimeSnapshot
	})
	if !ok {
		return collector.LiveRuntimeSnapshot{}, targets.ErrUnavailable
	}
	out := source.LiveRuntime(request.ClusterID)
	if ctx.Err() != nil || out.ClusterID != request.ClusterID || !out.Valid(t.recordings.now()) {
		return collector.LiveRuntimeSnapshot{}, targets.ErrUnavailable
	}
	return out, nil
}
