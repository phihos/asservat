package fleet

import (
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"time"
)

// ConnectorOperationAuditor retains fixed resources, never a revision cache.
// The private journal must match the exact already-admitted business intent
// before every object effect. Its SQL role cannot admit an arbitrary operation.
// Per-intent selection does not extend that intent's original writer interval.
type ConnectorOperationAuditor struct {
	policy           value.OperationLifecyclePolicy
	journal          app.OperationJournal
	acknowledgements app.OperationAcknowledgements
	legacy           app.OperationObjects
	closed           app.ClosedOperationObjects
	completions      app.OperationCompletions
	now              func() time.Time
}

func NewConnectorOperationAuditor(p value.OperationLifecyclePolicy, j app.OperationJournal, a app.OperationAcknowledgements, l app.OperationObjects, c app.ClosedOperationObjects, w app.OperationCompletions, now func() time.Time) (*ConnectorOperationAuditor, error) {
	if !value.CompatibleConnectorPolicy(p, p) {
		return nil, app.ErrUnavailable
	}
	if _, e := app.NewHealthyOperationAuditor(p, j, a, l, c, w, now); e != nil {
		return nil, e
	}
	q := *p.History
	p.History = &q
	return &ConnectorOperationAuditor{p, j, a, l, c, w, now}, nil
}
func (s *ConnectorOperationAuditor) forIntent(in value.OperationIntent) (*app.HealthyOperationAuditor, error) {
	if s == nil || !in.Valid() || in.Lifecycle == nil || value.OperationLane(in.Name) != "identity" || !value.CompatibleConnectorPolicy(s.policy, in.Lifecycle.Policy) {
		return nil, app.ErrUnavailable
	}
	return app.NewHealthyOperationAuditor(in.Lifecycle.Policy, s.journal, s.acknowledgements, s.legacy, s.closed, s.completions, s.now)
}
func (s *ConnectorOperationAuditor) Begin(ctx context.Context, in value.OperationIntent) error {
	a, e := s.forIntent(in)
	if e != nil {
		return e
	}
	return a.Begin(ctx, in)
}
func (s *ConnectorOperationAuditor) Finish(ctx context.Context, out value.OperationOutcome) error {
	a, e := s.forIntent(out.Intent)
	if e != nil {
		return e
	}
	return a.Finish(ctx, out)
}
