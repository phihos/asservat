package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/targets"
)

// SourceSnapshotQueryBatchLimit fits maximum retained provenance plus status in
// the existing 32KiB query frame. Sixteen selected sources use two exchanges.
const SourceSnapshotQueryBatchLimit = 8
const queryResolveSourceSnapshots = "resolve-source-snapshots"

type SourceSnapshotBatchResolver interface {
	ResolveSourceSnapshots(context.Context, []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error)
}

// ValidSourceSnapshotBatch permits distinct action sources on the same Pod.
// It does not grant current source or caller authority.
func ValidSourceSnapshotBatch(requests []targets.SourceSnapshotTarget, limit int) bool {
	if len(requests) == 0 || len(requests) > limit {
		return false
	}
	first := requests[0].Request
	seen := make(map[string]bool, len(requests))
	for _, request := range requests {
		target := request.Request
		if !request.Valid() || target.ClusterID != first.ClusterID || target.Namespace != first.Namespace || target.Workload != first.Workload || seen[request.SourceID] {
			return false
		}
		seen[request.SourceID] = true
	}
	return true
}

// ResolveSourceSnapshots retains the complete selection or returns an error.
// All chunks share the caller's original five-second bound; a later chunk may
// not freshen earlier reports or substitute another Pod/process/source.
func (t Targets) ResolveSourceSnapshots(ctx context.Context, requests []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error) {
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil || !ValidSourceSnapshotBatch(requests, 16) {
		return nil, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := make([]targets.SourceSnapshotResolution, 0, len(requests))
	for start := 0; start < len(requests); start += SourceSnapshotQueryBatchLimit {
		batch := requests[start:min(start+SourceSnapshotQueryBatchLimit, len(requests))]
		var values []targets.SourceSnapshotResolution
		until, err := t.Router.Query(call, batch[0].Request.ClusterID, queryResolveSourceSnapshots, batch, &values)
		if err != nil {
			return nil, err
		}
		if call.Err() != nil || len(values) != len(batch) {
			return nil, targets.ErrUnavailable
		}
		for index, value := range values {
			value, valid := validateSourceSnapshot(value, batch[index], until, t.Now())
			if !valid {
				return nil, targets.ErrUnavailable
			}
			out = append(out, value)
		}
	}
	now := t.Now()
	for index, value := range out {
		if _, valid := validateSourceSnapshot(value, requests[index], value.FreshUntil, now); !valid || call.Err() != nil {
			return nil, targets.ErrUnavailable
		}
	}
	return out, nil
}
