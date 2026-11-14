package fleet

import (
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
