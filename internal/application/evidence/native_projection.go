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
// session. The hub receives only the fixed approved DTO, not native plaintext.
type NativeApprovedContextRead interface {
	ReadApprovedContext(context.Context, NativeContextSource, value.NativeOperation, query.ContextProjectionScope, time.Time) (query.PodStatusProjection, error)
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

func (r *RegionalContextResult) ReadApproved(ctx context.Context, o value.NativeOperation, source NativeContextSource, scope query.ContextProjectionScope) (query.PodStatusProjection, error) {
	var zero query.PodStatusProjection
	if o.Kind != value.NativeProjection || !scope.Valid() || scope.Version != o.SourceVersion || o.Generation < 1 || o.Generation > query.ContextMaxReadBatches || !source.Valid(scope.Version) || o.Processing.Location != source.Expectation.Registration.Location || o.Path.StoreID != source.Expectation.Registration.StoreID {
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
	p, e := reader.ReadApprovedContext(call, cloneNativeSource(source), o, scope, o.Until)
	if e != nil || call.Err() != nil || !r.now().Before(o.Until) || !p.Valid() || p.NamespaceUID != scope.NamespaceUID || p.PodUID != scope.PodUID {
		return zero, query.ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return zero, query.ErrUnavailable
	}
	return p, nil
}
