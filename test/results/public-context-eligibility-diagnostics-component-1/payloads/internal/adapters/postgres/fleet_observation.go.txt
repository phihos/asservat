package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	port "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FleetObservation struct{ claims *EnrollmentClaims }

var _ port.FleetTrustProjection = (*FleetObservation)(nil)

func NewFleetObservation(ctx context.Context, pool *pgxpool.Pool, installation string) (*FleetObservation, error) {
	c, err := NewEnrollmentClaims(ctx, pool, installation)
	if err != nil {
		return nil, err
	}
	return &FleetObservation{c}, nil
}
func (s *FleetObservation) ObserveAdministration(ctx context.Context, basis value.ObservationBasis, a value.Administration) error {
	if s == nil || s.claims == nil || ctx == nil || basis.InstallationID != s.claims.installation || basis.Database.SchemaVersion != currentSchemaVersion || !basis.Valid() || a.InstallationID != basis.InstallationID || !a.Valid(a.ObservedAt) {
		return value.ErrInvalid
	}
	a.ObservedAt, a.FreshUntil = ownerTime(a.ObservedAt), ownerTime(a.FreshUntil)
	// The SQL operation consumes the basis selected before the native source
	// read. Neither waiting for a lock nor classifying a failure renews it.
	until := time.Now().Add(5 * time.Second)
	for _, end := range []time.Time{basis.FreshUntil, a.FreshUntil} {
		if end.Before(until) {
			until = end
		}
	}
	original, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	ctx = original
	var comparison custodydb.FleetCurrentTrust
	lockContention := false
	err := s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		comparison, lockContention = custodydb.FleetCurrentTrust{}, false
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !a.Valid(now.Time) || !basis.Current(now.Time) {
			return value.ErrDenied
		}
		// The unlocked row only supplies a possible ADR155 classification.
		// The fixed producer alone chooses its lock and validates the version.
		before, readErr := q.ReadFleetTrust(ctx, id(a.InstallationID))
		if readErr != nil && !errors.Is(readErr, pgx.ErrNoRows) {
			return readErr
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		candidate := readErr == nil && unchangedFleetObservation(a, before, now.Time)
		if !a.Valid(now.Time) || !basis.Current(now.Time) {
			return value.ErrDenied
		}
		disposition, err := q.ObserveFleetAdministration(ctx, custodydb.ObserveFleetAdministrationParams{
			InstallationID: id(a.InstallationID), SemanticVersion: basis.SemanticVersion, PostmasterAt: ts(basis.Database.StartedAt), DatabaseOid: pgtype.Uint32{Uint32: basis.Database.DatabaseOID, Valid: true}, BasisUntil: ts(basis.FreshUntil), IssuerEpoch: id(a.IssuerEpoch), SourceUid: a.Revision.UID, SourceGeneration: a.Revision.Generation, SourceDigest: a.Revision.Digest[:], Suspended: a.Suspended, ObservedAt: ts(a.ObservedAt), FreshUntil: ts(a.FreshUntil),
		})
		if err != nil {
			return err
		}
		switch disposition {
		case 1:
		case 2:
			return value.ErrConflict
		case 3:
			if candidate {
				comparison, lockContention = before, true
			}
			// The fixed producer catches only its authority row-lock timeout. Abort
			// the surrounding transaction before independent ADR155 confirmation.
			return value.ErrUnavailable
		default:
			return value.ErrDenied
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if ctx.Err() != nil || !a.Valid(now.Time) || !basis.Current(now.Time) {
			return value.ErrDenied
		}
		return nil
	})
	// A failure in the observation-row write, ambiguous COMMIT or stale version
	// cannot acquire this exception. Only the original authority-lock abort can.
	if err != nil && lockContention && s.confirmFleetObservationContention(ctx, basis, a, comparison) {
		return value.ErrObservationPersistenceContended
	}
	return err
}
func (s *FleetObservation) FenceAdministration(ctx context.Context, basis value.ObservationBasis, started time.Time) error {
	if s == nil || s.claims == nil || ctx == nil || !basis.Valid() || basis.Database.SchemaVersion != currentSchemaVersion || basis.InstallationID != s.claims.installation || started.Year() < 2020 || started.Year() > 9999 {
		return value.ErrInvalid
	}
	started = ownerTime(started)
	// Structural basis validity deliberately suffices here. A failed source may
	// already have consumed its positive interval; the separately bounded fence
	// only restricts the original version and cannot affect a newer semantic root.
	return s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if started.After(now.Time) {
			return value.ErrInvalid
		}
		_, err = q.FenceFleetObservation(ctx, custodydb.FenceFleetObservationParams{InstallationID: id(s.claims.installation), SemanticVersion: basis.SemanticVersion, PostmasterAt: ts(basis.Database.StartedAt), DatabaseOid: pgtype.Uint32{Uint32: basis.Database.DatabaseOID, Valid: true}, ObservationStarted: ts(started)})
		return err
	})
}
