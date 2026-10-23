package analysis

import (
	"asservat.local/asservat/internal/domain/authorization"
)

// SharedBudget removes only placement from a resource profile. The installer
// declares the finite work/history budget before worker configuration exists;
// an actual plan binds its accepted placement to the exact charged workload.
func (p ContextQueryResourceProfile) SharedBudget() ContextQueryResourceProfile {
	p.Path = ContextProjectionPath{Purpose: ContextProjectionPurpose}
	return p
}

func (p ContextQueryResourceProfile) SharedBudgetValid() bool {
	return authorization.UUID(p.ID) && p.Source.Valid() && p.Qualification.Valid() &&
		p.Path == (ContextProjectionPath{Purpose: ContextProjectionPurpose}) &&
		p.Lifetime > 0 && p.Lifetime <= ContextMaxQueryTime && p.Worker.Valid() &&
		p.Worker.Runtime >= p.Lifetime && p.Cost.Valid() &&
		p.PollLimit > 0 && p.PollLimit <= 1000000 &&
		p.ControlTransitionLimit > 0 && p.ControlTransitionLimit <= 1000000
}

func (p ContextQueryResourceProfile) WithSharedPath(path ContextProjectionPath) (ContextQueryResourceProfile, error) {
	if !p.SharedBudgetValid() || !path.Valid() {
		return ContextQueryResourceProfile{}, ErrUnavailable
	}
	p.Path = path
	return p, nil
}
