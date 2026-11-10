package privacy

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"time"
)

type ProcessingInventoryReader interface {
	ReadProcessingInventory(context.Context, value.ProcessingAuthority, value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error)
}

// ProcessingRuleInventory uses the same current privacy-operator authority as
// changes. It neither initializes processing nor grants evidence access.
type ProcessingRuleInventory struct {
	RootID, InstallationID string
	Policies               ProcessingPolicyReader
	Recovery               ProcessingRecoveryReader
	Inventory              ProcessingInventoryReader
	Now                    func() time.Time
}

func (s ProcessingRuleInventory) List(ctx context.Context, current ProcessingIdentity, q value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error) {
	var zero value.ProcessingInventoryPage
	if ctx == nil || ctx.Err() != nil || current == nil || !q.Valid() || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || s.Policies == nil || s.Recovery == nil || s.Inventory == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	window := identity.Check(started, identity.SQLFenced)
	if d, ok := ctx.Deadline(); ok {
		window = window.Narrow(d)
	}
	until := window.Until()
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	changes := ProcessingChanges{RootID: s.RootID, InstallationID: s.InstallationID, Policies: s.Policies, Recovery: s.Recovery, Now: s.Now}
	authority, err := changes.authority(call, current, started, until)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	call, cancel := context.WithDeadline(call, authority.ValidUntil)
	defer cancel()
	out, err := s.Inventory.ReadProcessingInventory(call, authority, q)
	if err != nil || out.RootID != s.RootID || !out.Valid(q, s.Now()) || out.ObservedAt.Before(started) || out.ValidUntil.After(authority.ValidUntil) {
		return zero, value.ErrUnavailable
	}
	// SQL rechecks the original recovery/source/backing observation after its
	// locks. Recheck only the caller here; never obtain another authority window.
	final, err := current.ResolveIdentity(call)
	if err != nil || !authority.Valid(s.Now()) || !final.Valid(s.Now()) || !sameProcessingIdentity(authority.Identity, final) {
		return zero, value.ErrUnavailable
	}
	out.ValidUntil = identity.Earlier(out.ValidUntil, final.ValidUntil)
	if call.Err() != nil || !out.Valid(q, s.Now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
