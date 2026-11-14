package mtls

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

type branchObservationCandidates struct {
	legacy, installed observationCandidatesFunc
}

func (s branchObservationCandidates) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.legacy(ctx)
}
func (s branchObservationCandidates) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.installed(ctx)
}
