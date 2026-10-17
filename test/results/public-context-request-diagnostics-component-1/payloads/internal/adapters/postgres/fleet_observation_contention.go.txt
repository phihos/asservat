package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Public database incarnation facts only, not an activation/recovery proof.
// The effective recovery view remains mandatory on both row observations.
type fleetObservationIncarnation struct {
	postmaster time.Time
	database   uint32
	primary    bool
	at         time.Time
}

func readFleetObservationIncarnation(ctx context.Context, pool *pgxpool.Pool) (fleetObservationIncarnation, error) {
	var out fleetObservationIncarnation
	err := pool.QueryRow(ctx, `SELECT pg_postmaster_start_time(), (SELECT oid FROM pg_database WHERE datname=current_database()), NOT pg_is_in_recovery(), clock_timestamp()`).Scan(&out.postmaster, &out.database, &out.primary, &out.at)
	return out, err
}
func sameFleetObservationIncarnation(a, b fleetObservationIncarnation) bool {
	return a.primary && b.primary && a.database != 0 && a.database == b.database && !a.postmaster.IsZero() && a.postmaster.Equal(b.postmaster)
}

func fleetObservationLockTimeout(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

// Both callers check database time after the actual potentially blocking row
// read. This validates only a failed unchanged observation classification.
func unchangedFleetObservation(a value.Administration, row custodydb.FleetCurrentTrust, now time.Time) bool {
	if !a.Valid(now) || a.Suspended || row.Suspended || row.RecoveryBlocked || row.InstallationID != id(a.InstallationID) || row.IssuerEpoch != id(a.IssuerEpoch) || row.SourceUid != a.Revision.UID || row.SourceGeneration != a.Revision.Generation || !bytes.Equal(row.SourceDigest, a.Revision.Digest[:]) {
		return false
	}
	if !row.ObservedAt.Valid || !row.FreshUntil.Valid || row.ObservedAt.InfinityModifier != 0 || row.FreshUntil.InfinityModifier != 0 || row.ObservedAt.Time.After(now) || !now.Before(row.FreshUntil.Time) || !row.ObservedAt.Time.Before(row.FreshUntil.Time) || row.FreshUntil.Time.Sub(row.ObservedAt.Time) > 30*time.Second {
		return false
	}
	return !a.ObservedAt.Before(row.ObservedAt.Time) && (!a.ObservedAt.Equal(row.ObservedAt.Time) || !a.FreshUntil.After(row.FreshUntil.Time))
}

func sameFleetObservationRow(a, b custodydb.FleetCurrentTrust) bool {
	return a.InstallationID == b.InstallationID && a.IssuerEpoch == b.IssuerEpoch && a.SourceUid == b.SourceUid && a.SourceGeneration == b.SourceGeneration && bytes.Equal(a.SourceDigest, b.SourceDigest) && a.Suspended == b.Suspended && a.RecoveryBlocked == b.RecoveryBlocked && a.ObservedAt.Valid == b.ObservedAt.Valid && a.ObservedAt.InfinityModifier == b.ObservedAt.InfinityModifier && a.ObservedAt.Time.Equal(b.ObservedAt.Time) && a.FreshUntil.Valid == b.FreshUntil.Valid && a.FreshUntil.InfinityModifier == b.FreshUntil.InfinityModifier && a.FreshUntil.Time.Equal(b.FreshUntil.Time)
}

func (s *FleetObservation) confirmFleetObservationContention(ctx context.Context, basis value.ObservationBasis, a value.Administration, before custodydb.FleetCurrentTrust) bool {
	if ctx.Err() != nil {
		return false
	}
	until := a.FreshUntil
	if basis.FreshUntil.Before(until) {
		until = basis.FreshUntil
	}
	if before.FreshUntil.Time.Before(until) {
		until = before.FreshUntil.Time
	}
	// WithDeadline also preserves an earlier original caller cutoff. This
	// confirmation cannot manufacture a fresh five-second observation interval.
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	q := custodydb.New(s.claims.ledger.pool)
	after, err := q.ReadFleetTrust(call, id(a.InstallationID))
	if err != nil || call.Err() != nil || !sameFleetObservationRow(before, after) {
		return false
	}
	current, err := s.ReadAdministrationBasis(call)
	if err != nil || call.Err() != nil || current.SemanticVersion != basis.SemanticVersion || current.Database.DatabaseOID != basis.Database.DatabaseOID || current.Database.SchemaVersion != basis.Database.SchemaVersion || !current.Database.StartedAt.Equal(basis.Database.StartedAt) {
		return false
	}
	now, err := q.CurrentTime(call)
	return err == nil && call.Err() == nil && basis.Current(now.Time) && unchangedFleetObservation(a, after, now.Time)
}
