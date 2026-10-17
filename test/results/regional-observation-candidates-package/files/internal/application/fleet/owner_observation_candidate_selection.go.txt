package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerObservationCandidateSource requires both purpose-fixed readers before
// startup. Legacy context-start callers keep their separate original port.
// The production source is the existing scoped owner registry, not a callback
// selected by an incoming observation request.
type OwnerObservationCandidateSource interface {
	APIContextOwnerCandidatesReader
	OwnerObservationCandidatesReader
}

// OwnerObservationCandidateSelection retains the original immutable pool.
// Omission selects the legacy fixed-sixteen reader; an explicit installed
// limit selects the complete limit-plus-one reader. Neither failure permits
// fallback, and no result or call is cached as current authority.
type OwnerObservationCandidateSelection struct {
	pool   value.OwnerPool
	source OwnerObservationCandidateSource
}

func NewOwnerObservationCandidateSelection(pool value.OwnerPool, source OwnerObservationCandidateSource) (*OwnerObservationCandidateSelection, error) {
	if !pool.Valid() || pool.NativeBootstrap != value.OwnerBootstrapProfile || source == nil {
		return nil, value.ErrInvalid
	}
	return &OwnerObservationCandidateSelection{pool: pool, source: source}, nil
}

func (s *OwnerObservationCandidateSelection) BoundTo(pool value.OwnerPool) bool {
	return s != nil && s.source != nil && s.pool == pool
}

// ReadOwnerObservationCandidates delegates with the original context unchanged.
// Consumers still verify the returned original dates and exact current peer.
func (s *OwnerObservationCandidateSelection) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	var out value.APIContextOwnerCandidates
	if s == nil || s.source == nil || ctx == nil || ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	var err error
	maximum := s.pool.NativeCandidateLimit
	if maximum == 0 {
		maximum = 16
		out, err = s.source.ReadContextStartOwners(ctx)
	} else {
		out, err = s.source.ReadOwnerObservationCandidates(ctx)
	}
	if err != nil {
		return value.APIContextOwnerCandidates{}, err
	}
	if ctx.Err() != nil || out.Pool != s.pool || len(out.Owners) > maximum {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	out.Owners = append([]value.OwnerBinding(nil), out.Owners...)
	return out, nil
}
