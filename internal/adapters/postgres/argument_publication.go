package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgtype"
)

// AcceptedArgumentSource reconstructs historical native provenance from the
// immutable prepaid session. It does not require a still-live acquisition lease
// and never authorizes another start. Publication authority is checked separately.
func (s *ContextPublications) AcceptedArgumentSource(ctx context.Context, e artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error) {
	var out artifact.ArgumentSourceProvenance
	if e.Validate() != nil || e.NativeType != artifact.SyscallArgumentsArtifact || !authorization.UUID(e.CaptureUID) {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: id(s.root), CaptureID: id(e.CaptureUID)})
		if err != nil {
			return err
		}
		out, err = argumentSourceProvenance(row, e)
		return err
	})
	return out, err
}
func argumentSourceProvenance(row custodydb.PolicyObservationSession, e artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error) {
	var zero artifact.ArgumentSourceProvenance
	if !argumentObservationMatches(row, e) {
		return zero, privacy.ErrFence
	}
	// EndedAt is terminal bookkeeping, excluded from the original scope. An old
	// ended session is valid provenance for retained output, never a live permit.
	row.EndedAt = pgtype.Timestamptz{}
	p, err := argumentObservationPermit(row)
	if err != nil {
		return zero, err
	}
	b := p.Binding
	out := artifact.ArgumentSourceProvenance{PodUID: b.PodUID, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, SessionID: b.SessionID, Fence: b.Fence, StartedAt: p.StartedAt, StartBy: p.StartBy, Until: p.SessionUntil}
	if !out.Valid() {
		return zero, privacy.ErrFence
	}
	return out, nil
}
