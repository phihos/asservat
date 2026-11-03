package artifact

import "time"

// ArgumentSourceProvenance is independent verifier input read from the original
// immutable observation session. It is neither public approval scope nor native
// header-supplied authority. Its old dates never authorize another acquisition.
type ArgumentSourceProvenance struct {
	PodUID, NodeUID, BootID, CollectorPodUID, CollectorEpoch, SessionID, Fence string
	StartedAt, StartBy, Until                                                  time.Time
}

func (p ArgumentSourceProvenance) Valid() bool {
	for _, id := range []string{p.PodUID, p.NodeUID, p.BootID, p.CollectorPodUID, p.CollectorEpoch, p.SessionID, p.Fence} {
		if len(id) < 1 || len(id) > 128 {
			return false
		}
	}
	return !p.StartedAt.IsZero() && p.StartBy.After(p.StartedAt) && !p.StartBy.After(p.StartedAt.Add(10*time.Second)) && p.Until.After(p.StartBy) && !p.Until.After(p.StartedAt.Add(70*time.Second))
}
