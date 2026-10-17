package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ReadOwnerObservationCandidates is a separate complete observation-routing
// read using the original accepted candidate limit. It never changes the old
// fixed-limit context-start reader and reuses the existing read credential.
// It acquires recovery before the owner configuration shared lock. No writes,
// addresses, certificate claims or human authority are produced by discovery.
func (s *OwnerEnrollments) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	var out value.APIContextOwnerCandidates
	if s == nil || ctx == nil || ctx.Err() != nil {
		return out, value.ErrInvalid
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	call, stop := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer stop()
	original, _ := call.Deadline()
	err := s.current(call, false, start, func(q *custodydb.Queries, c value.OwnerConfigurationObservation, r value.RecoveryState, n time.Time) error {
		if c.Configuration.Pool.NativeCandidateLimit == 0 {
			return value.ErrUnavailable
		}
		rows, e := q.ListOwnerObservationCandidates(call, custodydb.ListOwnerObservationCandidatesParams{InstallationID: id(c.Configuration.Pool.InstallationID), ClusterID: id(c.Configuration.Pool.ClusterID), IssuerEpoch: id(c.Configuration.Pool.IssuerEpoch), CandidateLimit: int32(c.Configuration.Pool.NativeCandidateLimit + 1)})
		if e != nil {
			return e
		}
		if len(rows) > c.Configuration.Pool.NativeCandidateLimit {
			return value.ErrUnavailable
		}
		until := identity.Earlier(original, identity.Earlier(c.FreshUntil, r.FreshUntil))
		out = value.APIContextOwnerCandidates{Pool: c.Configuration.Pool, ObservedAt: start, ValidUntil: until}
		for _, row := range rows {
			out.Owners = append(out.Owners, value.OwnerBinding{InstallationID: out.Pool.InstallationID, ClusterID: out.Pool.ClusterID, IssuerEpoch: out.Pool.IssuerEpoch, PodUID: uid(row.PodUid), ProcessEpoch: uid(row.ProcessEpoch)})
		}
		actual, e := q.CurrentTime(call)
		if e != nil {
			return e
		}
		if call.Err() != nil || !out.Valid(actual.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil || call.Err() != nil || !out.Valid(time.Now()) {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	return out, nil
}

var _ app.OwnerObservationCandidatesReader = (*OwnerEnrollments)(nil)
