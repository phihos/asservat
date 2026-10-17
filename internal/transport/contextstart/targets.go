package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// Targets is the hub's investigation target port over idle regional standbys
// (ADR-179). The hub reads no workload cluster; each resolution is the
// region's delegated proof, capped at its checked receiver validity.
type Targets struct {
	Router *Router
	Now    func() time.Time
}

func (t Targets) query(ctx context.Context, cluster, method string, in any) (targets.PodResolution, error) {
	var out targets.PodResolution
	if t.Router == nil || t.Now == nil || ctx == nil || ctx.Err() != nil {
		return out, targets.ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	until, err := t.Router.Query(call, cluster, method, in, &out)
	if err != nil {
		return targets.PodResolution{}, err
	}
	out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	if out.ExecutionClass != artifact.ContextAPIExecution || out.Request.ClusterID != cluster || !out.Valid(t.Now()) {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

// ResolveWorkload resolves a named workload to one current Pod. A Pod name is
// resolved under its actual owner, so only the Pod name is compared then.
func (t Targets) ResolveWorkload(ctx context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	if !r.Valid() {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	out, err := t.query(ctx, r.ClusterID, queryResolveWorkload, r)
	if err != nil {
		return out, err
	}
	q := out.Request
	if q.Namespace.Name != r.Namespace || (r.Kind == "Pod" && q.PodName != r.Name) || (r.Kind != "Pod" && (q.Workload.Kind != r.Kind || q.Workload.Name != r.Name)) {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

// ResolvePod re-pins one exact Pod; the region never reselects another.
func (t Targets) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	if !r.Valid() {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	out, err := t.query(ctx, r.ClusterID, queryResolvePod, r)
	if err != nil {
		return out, err
	}
	if out.Request != r {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	return out, nil
}
