package privacy

import (
	"context"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type ProcessingReportReader interface {
	ReadProcessingReport(context.Context, value.ProcessingAuthority, value.ProcessingReportQuery) (value.ProcessingReportPage, error)
}

// Each page authorizes the current operator once and carries that observation
// through the existing fenced SQL read and final request identity check.
type ProcessingReport struct {
	RootID, InstallationID string
	Policies               ProcessingPolicyReader
	Recovery               ProcessingRecoveryReader
	Reports                ProcessingReportReader
	Now                    func() time.Time
}

func (s ProcessingReport) Get(ctx context.Context, caller ProcessingIdentity, query value.ProcessingReportQuery) (value.ProcessingReportPage, error) {
	var zero value.ProcessingReportPage
	query = query.Normalized()
	if ctx == nil || ctx.Err() != nil || caller == nil || !query.Valid() ||
		!authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || s.Policies == nil || s.Recovery == nil || s.Reports == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	if query.CreatedBefore.After(started) {
		return zero, value.ErrUnavailable
	}
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
	page, err := s.Reports.ReadProcessingReport(call, authority, query)
	revision := value.ProcessingReportRevision{UID: authority.Policy.Revision.UID, Generation: authority.Policy.Revision.Generation, Digest: hex.EncodeToString(authority.Policy.Revision.Digest[:])}
	if err != nil || page.RootID != s.RootID || page.InstallationID != s.InstallationID ||
		page.PolicyRevision != revision || query.CreatedBefore.IsZero() && !page.SelectionCreatedBefore.Equal(started) ||
		!page.ObservedAt.Equal(started) || page.ValidUntil.After(authority.ValidUntil) || !page.Valid(query, s.Now()) {
		return zero, value.ErrUnavailable
	}
	final, err := processing.continueAuthority(call, caller, authority)
	if err != nil {
		return zero, err
	}
	page.ValidUntil = identity.Earlier(page.ValidUntil, final.ValidUntil)
	if call.Err() != nil || !page.Valid(query, s.Now()) {
		return zero, value.ErrUnavailable
	}
	return page, nil
}
