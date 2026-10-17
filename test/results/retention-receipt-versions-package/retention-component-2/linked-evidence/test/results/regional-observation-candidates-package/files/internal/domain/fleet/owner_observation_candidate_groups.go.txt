package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// A group retains every original SQL process binding for one presently Ready
// Pod. It is a routing candidate only, not a chosen/current process identity.
type OwnerObservationCandidateGroup struct {
	PodUID string
	Owners []OwnerBinding
}

// OwnerObservationCandidateGroups retains both the complete SQL observation
// and the original complete EndpointSlice LIST interval. Missing retained Pods
// may be omitted only after that LIST completes; unknown/partial LIST is error.
// An empty Ready intersection is unavailable, never a successful observation.
type OwnerObservationCandidateGroups struct {
	Candidates              APIContextOwnerCandidates
	Groups                  []OwnerObservationCandidateGroup
	EndpointResourceVersion string
	ObservedAt, ValidUntil  time.Time
}

func (o OwnerObservationCandidateGroups) Valid(now time.Time) bool {
	if !o.Candidates.Valid(now) || o.Candidates.Pool.NativeCandidateLimit == 0 || len(o.Groups) == 0 || len(o.Groups) > len(o.Candidates.Owners) || !identity.Text(o.EndpointResourceVersion, 128) || !identity.Fresh(o.ObservedAt, o.ValidUntil, now, 5*time.Second) || o.ObservedAt.Before(o.Candidates.ObservedAt) || o.ValidUntil.After(o.Candidates.ValidUntil) {
		return false
	}
	original := make(map[OwnerBinding]bool, len(o.Candidates.Owners))
	present := make(map[string]int, len(o.Groups))
	for _, b := range o.Candidates.Owners {
		original[b] = true
	}
	for i, g := range o.Groups {
		if !authorization.UUID(g.PodUID) || len(g.Owners) == 0 || len(g.Owners) > len(original) || i > 0 && o.Groups[i-1].PodUID >= g.PodUID {
			return false
		}
		seen := make(map[OwnerBinding]bool, len(g.Owners))
		for _, b := range g.Owners {
			if b.PodUID != g.PodUID || !original[b] || seen[b] {
				return false
			}
			seen[b] = true
		}
		present[g.PodUID] = len(g.Owners)
	}
	for _, b := range o.Candidates.Owners {
		if _, ok := present[b.PodUID]; ok {
			present[b.PodUID]--
		}
	}
	for _, n := range present {
		if n != 0 {
			return false
		}
	}
	return true
}

func (o OwnerObservationCandidateGroups) Clone() OwnerObservationCandidateGroups {
	o.Candidates.Owners = append([]OwnerBinding(nil), o.Candidates.Owners...)
	o.Groups = append([]OwnerObservationCandidateGroup(nil), o.Groups...)
	for i := range o.Groups {
		o.Groups[i].Owners = append([]OwnerBinding(nil), o.Groups[i].Owners...)
	}
	return o
}
