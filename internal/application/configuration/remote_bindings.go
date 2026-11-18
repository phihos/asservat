package configuration

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

// refreshRemoteBindings rereads the joined clusters' AccessBinding
// deliveries (ADR-329) within three seconds. A read failure stops this epoch
// before another acceptance. The supervisor retries with a full baseline.
func (s *bindingRun) refreshRemoteBindings(ctx context.Context) error {
	if s.r.RemoteBindings == nil {
		return nil
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	deliveries, err := s.r.RemoteBindings.RemoteBindings(call)
	if err != nil {
		return reconcileStep("remote-bindings", err)
	}
	if s.remoteBindings == nil {
		s.remoteBindings = map[string]value.RemoteBindings{}
	}
	now := s.r.Now()
	for _, d := range deliveries {
		if d.ClusterID == s.r.NamespaceClusterID || !d.Valid() || d.ObservedAt.After(now.Add(time.Second)) {
			continue
		}
		if old, ok := s.remoteBindings[d.ClusterID]; ok && !d.ObservedAt.After(old.ObservedAt) {
			continue
		}
		d.Bindings = slices.Clone(d.Bindings)
		slices.SortFunc(d.Bindings, func(a, b value.Binding) int { return cmp.Compare(a.Resource.UID, b.Resource.UID) })
		s.remoteBindings[d.ClusterID] = d
	}
	return nil
}

// remoteBindingBases adds the joined clusters' AccessBindings to the batch
// exactly like the hub cluster's (ADR-329), in cluster order. The last
// delivery stays in effect until a newer one replaces it: connector liveness
// is a health signal, not authority, and new remote actions need the
// connector anyway.
func (s *bindingRun) remoteBindingBases(now time.Time, out *inheritanceState) {
	for _, cluster := range slices.Sorted(maps.Keys(s.remoteBindings)) {
		for _, b := range s.remoteBindings[cluster].Bindings {
			if p, ok := bindingBasis(b, now); ok {
				out.Bases = append(out.Bases, p)
			}
		}
	}
}
