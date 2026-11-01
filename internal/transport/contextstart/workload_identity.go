package contextstart

import (
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"time"
)

// ResolveWorkloadIdentity discovers only the current named root. Authorization
// must precede source lookup and every metadata response at the application.
func (t Targets) ResolveWorkloadIdentity(ctx context.Context, r targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error) {
	var out targets.WorkloadIdentityResolution
	if !r.Valid() {
		return out, targets.ErrInvalid
	}
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil {
		return out, targets.ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	until, err := t.Router.Query(call, r.ClusterID, queryResolveWorkloadIdentity, r, &out)
	if err != nil {
		return targets.WorkloadIdentityResolution{}, err
	}
	now := t.Now()
	if call.Err() != nil || !now.Before(until) || !out.Valid(now) || out.Reference != r || out.ClusterID != r.ClusterID || out.Namespace.Name != r.Namespace || r.Kind != "Pod" && (out.Workload.Kind != r.Kind || out.Workload.Name != r.Name) {
		return targets.WorkloadIdentityResolution{}, targets.ErrUnavailable
	}
	return out, nil
}
