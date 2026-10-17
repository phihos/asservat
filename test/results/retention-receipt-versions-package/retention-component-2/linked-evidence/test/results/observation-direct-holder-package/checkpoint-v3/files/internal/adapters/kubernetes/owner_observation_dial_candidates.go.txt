package kubernetes

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerObservationDialCandidates is public routing provenance, not authority.
// Addresses originate in one complete same-RV EndpointSlice sequence. Every
// contacted actual leaf still needs the independently current SQL and concrete
// initial/final native proof before a dedicated token can be disclosed.
type OwnerObservationDialCandidates struct {
	Groups    value.OwnerObservationCandidateGroups
	Addresses map[string][]string
}

func (s *OwnerEndpoints) ReadOwnerObservationDialCandidates(ctx context.Context, candidates value.APIContextOwnerCandidates) (OwnerObservationDialCandidates, error) {
	groups, addresses, err := s.ownerObservationDialCandidates(ctx, candidates)
	if err != nil {
		return OwnerObservationDialCandidates{}, err
	}
	return OwnerObservationDialCandidates{Groups: groups, Addresses: addresses}, nil
}
