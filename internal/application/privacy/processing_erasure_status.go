package privacy

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type ProcessingErasureStatusReader interface {
	ReadProcessingErasureStatus(context.Context, value.ProcessingAuthority, string) (value.ProcessingErasureStatus, error)
}

type ProcessingErasureStatus struct {
	RootID, InstallationID string
	Policies               ProcessingPolicyReader
	Recovery               ProcessingRecoveryReader
	Status                 ProcessingErasureStatusReader
	Now                    func() time.Time
}

func (s ProcessingErasureStatus) Get(ctx context.Context, current ProcessingIdentity, requestID string) (value.ProcessingErasureStatus, error) {
	var zero value.ProcessingErasureStatus
	if ctx == nil || ctx.Err() != nil || current == nil || !authorization.UUID(requestID) ||
		!authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || s.Policies == nil || s.Recovery == nil || s.Status == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	window := identity.Check(started, identity.SQLFenced)
	if d, ok := ctx.Deadline(); ok {
		window = window.Narrow(d)
	}
	call, stop := context.WithDeadline(ctx, window.Until())
	defer stop()
	changes := ProcessingChanges{RootID: s.RootID, InstallationID: s.InstallationID, Policies: s.Policies, Recovery: s.Recovery, Now: s.Now}
	authority, err := changes.authority(call, current, started, window.Until())
	if err != nil {
		return zero, err
	}
	call, cancel := context.WithDeadline(call, authority.ValidUntil)
	defer cancel()
	out, err := s.Status.ReadProcessingErasureStatus(call, authority, requestID)
	if err != nil || !out.ObservedAt.Equal(started) || out.ValidUntil.After(authority.ValidUntil) || !out.Valid(requestID, s.Now()) {
		return zero, value.ErrUnavailable
	}
	final, err := changes.continueAuthority(call, current, authority)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	out.ValidUntil = identity.Earlier(out.ValidUntil, final.ValidUntil)
	if call.Err() != nil || !out.Valid(requestID, s.Now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
