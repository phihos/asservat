package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

var _ app.InitialRuntimeOwnerBridgeEffects = (*InitialRuntimeBridgeSQL)(nil)

// A private scalar copy of the independently read native source. No slices,
// caller data or later observation can replace its exact original comparison.
type initialRuntimeOwnerFleet struct {
	installation, issuer string
	revision             identity.Revision
	observed, until      time.Time
}

func (s *InitialRuntimeBridgeSQL) WithInitialRuntimeOwnerBridge(ctx context.Context, a fleet.Administration, effect func(context.Context) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || effect == nil || !a.Valid(time.Now()) || a.Suspended {
		return cfg.ErrUnavailable
	}
	if a.InstallationID != s.record.Scope.InstallationID || a.IssuerEpoch != s.record.Scope.IssuerEpoch || a.Revision.UID != s.record.Claim.FleetSource.UID {
		return cfg.ErrChanged
	}
	// Administration's collections are validated above and never retained or
	// consulted afterward. Authority comparisons use only this copied tuple.
	source := initialRuntimeOwnerFleet{installation: a.InstallationID, issuer: a.IssuerEpoch, revision: a.Revision, observed: a.ObservedAt, until: a.FreshUntil}
	call, stop := context.WithDeadline(ctx, source.until)
	defer stop()
	return s.withInitialRuntimeBridge(call, &source, effect)
}

func ownerBridgeEarlier(first time.Time, rest ...time.Time) time.Time {
	for _, next := range rest {
		first = identity.Earlier(first, next)
	}
	return first
}

// This check runs after each potentially blocking lock and after the joined
// callback. The row remains locked; database time supplies no new source age.
func (s initialRuntimeOwnerFleet) current(ctx context.Context, q *custodydb.Queries, row custodydb.FleetCurrentTrust, until time.Time) error {
	n, err := q.CurrentTime(ctx)
	if err != nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	return s.check(row, until, n.Time)
}

func (s initialRuntimeOwnerFleet) check(row custodydb.FleetCurrentTrust, until, now time.Time) error {
	if uid(row.InstallationID) != s.installation || uid(row.IssuerEpoch) != s.issuer || row.SourceUid != s.revision.UID || row.SourceGeneration != s.revision.Generation || !bytes.Equal(row.SourceDigest, s.revision.Digest[:]) {
		return cfg.ErrChanged
	}
	if row.Suspended || row.RecoveryBlocked || !s.revision.Valid() || !identity.Fresh(s.observed, s.until, now, 5*time.Second) || !identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, now, 30*time.Second) || !now.Before(until) || until.After(s.until) || until.After(row.FreshUntil.Time) {
		return cfg.ErrUnavailable
	}
	return nil
}
