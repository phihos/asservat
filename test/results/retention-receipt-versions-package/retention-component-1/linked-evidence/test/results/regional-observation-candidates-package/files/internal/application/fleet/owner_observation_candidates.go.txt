package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// OwnerObservationCandidatesReader returns a complete current original-pool
// set under its explicit accepted bound. It supplies no Ready-route, activated
// peer proof or permission. Callers retain every original candidate identity;
// grouping by Pod cannot infer a preferred/latest process or widen freshness.
type OwnerObservationCandidatesReader interface {
	ReadOwnerObservationCandidates(context.Context) (value.APIContextOwnerCandidates, error)
}

// This filter never proves a process or supplies a forwarding address. Actual
// selected peer/current route/native proof remain necessary before lookup.
type OwnerObservationCandidateGroupsReader interface {
	ReadyOwnerObservationCandidates(context.Context, value.APIContextOwnerCandidates) (value.OwnerObservationCandidateGroups, error)
}
