package evidence

import (
	"context"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// NativeApprovedContextRead is the closed acquisition-worker projection branch.
// It uses the query batch's independently bound one-use keys, never a download
// session. The hub receives only the fixed approved DTO or one httpHeaders
// page (ADR-282), never native plaintext.
type NativeApprovedContextRead interface {
	ReadApprovedContext(context.Context, NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.ProjectionResult, error)
}
type NativeApprovedProfileComparisonRead interface {
	ReadApprovedProfileComparison(context.Context, [2]NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.ProjectionResult, error)
}

// NativeComparisonSourcesMatch checks both complete immutable sources against
// the command's closed pair and independent operation proofs. It grants no keys.
func NativeComparisonSourcesMatch(sources [2]NativeContextSource, scope query.ContextProjectionScope, o value.NativeOperation) bool {
	b, bok := scope.BaselineScope()
	i, iok := scope.IncidentScope()
	if !bok || !iok || o.Kind != value.NativeProjection || o.Baseline == (value.NativeProjectionSource{}) {
		return false
	}
	for n, s := range [2]query.ContextProjectionScope{b, i} {
		proof, path, version := o.Processing, o.Path, o.SourceVersion
		if n == 0 {
			proof, path, version = o.Baseline.Processing, o.Baseline.Path, o.Baseline.SourceVersion
		}
		if version != s.Version || !sources[n].Valid(version) || !CanonicalProjectionExpectationBound(sources[n]) || !projectionExpectation(sources[n].Expectation, s) || proof.RootID != s.RootID || proof.Location != sources[n].Expectation.Registration.Location || proof.CaptureID != s.CaptureID || path.TargetClusterID != s.ClusterID || path.StoreID != sources[n].Expectation.Registration.StoreID {
			return false
		}
	}
	return true
}

// Both purposes share the same process owner, active-read exclusion, joined
// shutdown and framed transport. Only the approved reader is installed here;
// this worker cannot invoke a native-download reader or retain native metadata.
func NewRegionalApprovedResult(ctx context.Context, worker value.WorkerCredentialTarget, reader NativeApprovedContextRead, now func() time.Time) (*RegionalContextResult, error) {
	if ctx == nil || ctx.Err() != nil || !worker.Valid() || worker.Parent().Purpose != value.AcquisitionProjection || reader == nil || now == nil || !now().Before(worker.RunUntil) {
		return nil, artifact.ErrInvalid
	}
	work, cancel := context.WithDeadline(ctx, worker.RunUntil)
	r := &RegionalContextResult{ctx: work, cancel: cancel, worker: worker, approved: reader, now: now, done: make(chan struct{})}
	context.AfterFunc(work, r.Close)
	return r, nil
}

func (r *RegionalContextResult) ReadApproved(ctx context.Context, o value.NativeOperation, source NativeContextSource, scope query.ContextProjectionScope) (query.ProjectionResult, error) {
	return r.readApproved(ctx, o, source, nil, scope)
}

func (r *RegionalContextResult) ReadApprovedComparison(ctx context.Context, o value.NativeOperation, sources [2]NativeContextSource, scope query.ContextProjectionScope) (query.ProjectionResult, error) {
	return r.readApproved(ctx, o, sources[1], &sources[0], scope)
}

func (r *RegionalContextResult) readApproved(ctx context.Context, o value.NativeOperation, source NativeContextSource, baseline *NativeContextSource, scope query.ContextProjectionScope) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	// Pod status keeps its historical source check; an httpHeaders scope
	// requires exactly its published extract (ADR-282).
	kind := scope.NativeType == artifact.PodStatusArtifact && source.podStatus() ||
		(scope.NativeType == artifact.PCAPNGArtifact || scope.NativeType == artifact.RawPCAPNGArtifact || scope.NativeType == artifact.HTTPHeadersArtifact || scope.NativeType == artifact.PprofArtifact || scope.NativeType == artifact.SyscallRecordsArtifact || scope.NativeType == artifact.SyscallArgumentsArtifact) && projectionExpectation(source.Expectation, scope)
	if o.Kind != value.NativeProjection || !scope.Valid() || scope.Version != o.SourceVersion || o.Generation < 1 || o.Generation > scope.ReadBatches() || !source.Valid(scope.Version) || !kind || o.Processing.Location != source.Expectation.Registration.Location || o.Path.StoreID != source.Expectation.Registration.StoreID {
		return zero, query.ErrUnavailable
	}
	paired := scope.Comparison != (query.ProfileComparisonWindow{})
	if paired {
		if baseline == nil || !NativeComparisonSourcesMatch([2]NativeContextSource{*baseline, source}, scope, o) {
			return zero, query.ErrUnavailable
		}
	} else if baseline != nil || o.Baseline != (value.NativeProjectionSource{}) {
		return zero, query.ErrUnavailable
	}
	call, leave, e := r.enter(ctx, o)
	if e != nil {
		return zero, e
	}
	defer leave()
	r.mu.Lock()
	index := o.Generation - 1
	if r.approved == nil || r.projectionBatches[index] != "" {
		r.mu.Unlock()
		return zero, query.ErrUnavailable
	}
	// A failed or uncertain read remains spent in this process. SQL separately
	// fences the same batch, so a reconnect cannot replenish any key or read slot.
	r.projectionBatches[index] = o.ParentID
	reader := r.approved
	r.mu.Unlock()
	var p query.ProjectionResult
	if paired {
		compare, ok := reader.(NativeApprovedProfileComparisonRead)
		if !ok {
			return zero, query.ErrUnavailable
		}
		p, e = compare.ReadApprovedProfileComparison(call, [2]NativeContextSource{cloneNativeSource(*baseline), cloneNativeSource(source)}, o, scope, o.Until)
	} else {
		p, e = reader.ReadApprovedContext(call, cloneNativeSource(source), o, scope, o.Until)
	}
	if e != nil {
		return zero, collapsed("approved", query.ErrUnavailable, e)
	}
	if call.Err() != nil || !r.now().Before(o.Until) || !p.Valid(scope) {
		p.Clear()
		return zero, stepped("approved-result", query.ErrUnavailable)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		p.Clear()
		return zero, query.ErrUnavailable
	}
	return p, nil
}
