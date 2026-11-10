package privacy

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type ProcessingDiscoveryReader interface {
	ReadProcessingDiscovery(context.Context, value.ProcessingAuthority, value.ProcessingDiscoveryQuery) (value.ProcessingDiscoveryPage, error)
}

// ProcessingEvidenceDiscovery uses current privacy operator authority for the
// retained catalog projection. Each page starts a new bounded observation.
type ProcessingEvidenceDiscovery struct {
	RootID, InstallationID string
	Policies               ProcessingPolicyReader
	Recovery               ProcessingRecoveryReader
	Discovery              ProcessingDiscoveryReader
	Now                    func() time.Time
}

func (s ProcessingEvidenceDiscovery) Search(ctx context.Context, caller ProcessingIdentity, q value.ProcessingDiscoveryQuery) (value.ProcessingDiscoveryPage, error) {
	var zero value.ProcessingDiscoveryPage
	if ctx == nil || ctx.Err() != nil || caller == nil || !q.Valid() || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || s.Policies == nil || s.Recovery == nil || s.Discovery == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	window := identity.Check(started, identity.SQLFenced)
	if deadline, ok := ctx.Deadline(); ok {
		window = window.Narrow(deadline)
	}
	call, stop := context.WithDeadline(ctx, window.Until())
	defer stop()
	processing := ProcessingChanges{RootID: s.RootID, InstallationID: s.InstallationID, Policies: s.Policies, Recovery: s.Recovery, Now: s.Now}
	authority, err := processing.authority(call, caller, started, window.Until())
	if err != nil {
		return zero, err
	}
	call, narrow := context.WithDeadline(call, authority.ValidUntil)
	defer narrow()
	page, err := s.Discovery.ReadProcessingDiscovery(call, authority, q)
	if err != nil || page.RootID != s.RootID || page.ObservedAt.Before(started) || page.ValidUntil.After(authority.ValidUntil) || !page.Valid(q, s.Now()) {
		return zero, value.ErrUnavailable
	}
	final, err := processing.continueAuthority(call, caller, authority)
	if err != nil {
		return zero, err
	}
	page.ValidUntil = identity.Earlier(page.ValidUntil, final.ValidUntil)
	if call.Err() != nil || !page.Valid(q, s.Now()) {
		return zero, value.ErrUnavailable
	}
	return page, nil
}
