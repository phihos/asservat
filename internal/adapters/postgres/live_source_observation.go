package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
)

// ReadLiveSourceObservation checks the source's original prepaid observation
// grant, not a viewer disclosure grant. Only the cutoff leaves this adapter.
// It is composed after ordinary maintainer and original-audience checks using
// the existing hub grant/source read duties, never a new SQL credential.
func (s *AccessGrants) ReadLiveSourceObservation(ctx context.Context, sourceID, expectedGrantID string) (time.Time, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(sourceID) || !authorization.UUID(expectedGrantID) {
		return time.Time{}, authorization.ErrGrantInvalid
	}
	var until time.Time
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadLiveSourceObservation(ctx, custodydb.ReadLiveSourceObservationParams{RootID: id(s.root), SourceID: id(sourceID), GrantID: id(expectedGrantID)})
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		until, err = liveSourceObservationUntil(row, s.root, sourceID, expectedGrantID, now.Time)
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return time.Time{}, grantError(err)
	}
	return until, nil
}

func liveSourceObservationUntil(row custodydb.ReadLiveSourceObservationRow, root, sourceID, grantID string, now time.Time) (time.Time, error) {
	var binding collector.SourceBinding
	if queryDecode(row.BindingJson, 8192, &binding) != nil || !binding.Valid() || binding.RootID != root || binding.SourceID != sourceID || binding.ObservationGrantID != grantID {
		return time.Time{}, authorization.ErrGrantScope
	}
	g, err := grantFromRow(row.AccessGrant)
	if err != nil || g.ID != grantID || g.RootID != root || uid(row.AccessGrant.PolicyAcceptanceID) != binding.AcceptanceID || g.Policy == nil || g.Policy.Observation == nil || !bytes.Equal(row.AuthorityDigest, binding.Scope[:]) || artifact.Digest(binding.Scope) != g.Policy.Authority.ScopeDigest || row.StartedAt.Time.After(now) || row.PolicyObservedAt.Time.After(now) || !now.Before(row.PolicyFreshUntil.Time) {
		return time.Time{}, authorization.ErrGrantScope
	}
	if err = authorization.CheckPolicyGrantAttachment(g, g.Policy.Authority, row.AuthoredGrantRef, now); err != nil {
		return time.Time{}, err
	}
	a := g.Policy.Authority
	if a.PolicyUID != binding.PolicyUID || a.ClusterID != uid(row.SourceClusterID) || a.NamespaceUID != row.SourceNamespaceUid || a.WorkloadUID != row.SourceWorkloadUid || row.BytesPerSecond < 1 || row.BytesPerSecond > g.Policy.Observation.MaxBytesPerSecond || row.HardUntil.Time.After(row.StartedAt.Time.Add(time.Duration(g.Policy.Observation.MaxSessionSeconds)*time.Second)) {
		return time.Time{}, authorization.ErrGrantScope
	}
	until := identity.Earlier(row.HardUntil.Time, identity.Earlier(row.PolicyFreshUntil.Time, identity.Earlier(g.ExpiresAt, g.PolicyNotAfter)))
	if !now.Before(until) {
		return time.Time{}, authorization.ErrGrantExpired
	}
	return until, nil
}
