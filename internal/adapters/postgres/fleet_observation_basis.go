package postgres

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ReadAdministrationBasis precedes the independent native source read. The raw
// version may be read while fleet freshness is unavailable; it supplies no
// recovery, source or effect authority and holds no lock across native work.
func (s *FleetObservation) ReadAdministrationBasis(ctx context.Context) (value.ObservationBasis, error) {
	var out value.ObservationBasis
	if s == nil || s.claims == nil || ctx == nil || ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	started := ownerTime(time.Now())
	call, cancel := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer cancel()
	until, _ := call.Deadline()
	out.InstallationID, out.ObservedAt, out.FreshUntil = s.claims.installation, started, ownerTime(until)
	var at time.Time
	var primary bool
	// ADR-226: a lossless PostgreSQL restart re-activates before the version is
	// read. The function changes nothing on an ordinary pass.
	if _, err := s.claims.ledger.pool.Exec(call, `SELECT public.reactivate_restarted_database($1)`, out.InstallationID); err != nil {
		return value.ObservationBasis{}, value.ErrUnavailable
	}
	err := s.claims.ledger.pool.QueryRow(call, `SELECT COALESCE(t.semantic_version,0),
 pg_catalog.pg_postmaster_start_time(),
 (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
 NOT pg_catalog.pg_is_in_recovery(),pg_catalog.clock_timestamp()
 FROM (SELECT $1::uuid AS installation_id) i
 LEFT JOIN public.fleet_trust t ON t.installation_id=i.installation_id`, out.InstallationID).
		Scan(&out.SemanticVersion, &out.Database.StartedAt, &out.Database.DatabaseOID, &primary, &at)
	out.Database.StartedAt = ownerTime(out.Database.StartedAt)
	out.Database.SchemaVersion = currentSchemaVersion
	if err != nil || call.Err() != nil || !primary || !out.Current(at) || !out.Current(time.Now()) {
		return value.ObservationBasis{}, value.ErrUnavailable
	}
	return out, nil
}
