package execution

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
)

// initiatingIdentity consumes the already checked request-owned principal; it
// is local hub composition, never an identity restored from stored metadata.
type initiatingIdentity struct {
	Identity identity.Identity
	Now      func() time.Time
}

func (i initiatingIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if ctx == nil || ctx.Err() != nil || i.Now == nil || !i.Identity.Valid(i.Now()) {
		return identity.Identity{}, value.ErrDenied
	}
	return i.Identity, nil
}

func (c APIExecutionCheck) initiatorValid(now time.Time) bool {
	w := c.Work
	if w.Initiator == nil {
		return c.Initiator == nil
	}
	i := c.Initiator
	e := w.Accepted.Expectation
	return e.Snapshot != nil && e.Lifecycle != nil && e.Lifecycle.TriggerKind == "recordingSave" && i != nil && i.Eligible && i.Principal == *w.Initiator && i.VerifiedIdentity.Principal == *w.Initiator && i.VerifiedIdentity.Valid(now) && i.Target == c.Plan.Input.Target.Target() && !c.ValidUntil.After(i.ValidUntil)
}
