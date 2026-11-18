package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

type workerRuntimeLeaseKey struct{}

// Schedule consumes the lease's one scheduling decision for provider
// maintenance and audited work. It supplies only process admission, never
// authority; blocking work still checks its own current authority.
func (p *WorkerRuntimeAdmissionLease) Schedule() error {
	if p == nil || p.self != p || p.owner == nil {
		return value.ErrUnavailable
	}
	s := p.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	t := p.ticket
	if t.purpose != workerWrapRefresh && t.purpose != workerUnwrapRefresh && t.purpose != workerAuthorityAudit && t.purpose != workerCleanup {
		return value.ErrUnavailable
	}
	// Reusing a consumed scheduling decision is not a new operation.
	if t.scheduled || s.closed || s.root.Err() != nil || t.ctx.Err() != nil || s.active != t {
		t.cancel()
		return value.ErrUnavailable
	}
	t.scheduled = true
	return nil
}

func (s *WorkerRuntimeAdmission) ClaimAuthorityAudit(ctx context.Context) bool {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil {
		return false
	}
	p, ok := ctx.Value(workerRuntimeLeaseKey{}).(*WorkerRuntimeAdmissionLease)
	if !ok || p == nil || p.self != p || p.owner != s {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := p.ticket
	if s.closed || s.root.Err() != nil || s.active != t || t.purpose != workerAuthorityAudit || !t.scheduled || t.auditTaken || t.ctx.Err() != nil || ctx.Err() != nil {
		return false
	}
	t.auditTaken = true
	return true
}
