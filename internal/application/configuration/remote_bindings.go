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
func (s *bindingRun) refreshRemoteBindings(ctx context.Context) (bool, error) {
	if s.r.RemoteBindings == nil {
		return false, nil
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	deliveries, err := s.r.RemoteBindings.RemoteBindings(call)
	if err != nil {
		return false, reconcileStep("remote-bindings", err)
	}
	next := make(map[string]value.RemoteBindings, len(deliveries))
	changed := false
	for _, d := range deliveries {
		if d.ClusterID == s.r.NamespaceClusterID {
			continue
		}
		if !d.Valid() {
			if old, ok := s.remoteBindings[d.ClusterID]; ok {
				next[d.ClusterID] = old
			}
			continue
		}
		if old, ok := s.remoteBindings[d.ClusterID]; ok {
			if old.Digest == d.Digest && (d.Digest != ([32]byte{}) || d.ObservedAt.Equal(old.ObservedAt)) {
				old.ObservedAt = d.ObservedAt
				next[d.ClusterID] = old
				continue
			}
		}
		changed = true
		d.Bindings = slices.Clone(d.Bindings)
		slices.SortFunc(d.Bindings, func(a, b value.Binding) int { return cmp.Compare(a.Resource.UID, b.Resource.UID) })
		next[d.ClusterID] = d
	}
	changed = changed || len(next) != len(s.remoteBindings)
	s.remoteBindings = next
	return changed, nil
}

// remoteBindingBases adds the joined clusters' AccessBindings to the batch
// exactly like the hub cluster's (ADR-329), in cluster order. The last
// delivery stays in effect until a newer one replaces it: connector liveness
// is a health signal, not authority, and new remote actions need the
// connector anyway.
func (s *bindingRun) remoteBindingBases(now time.Time, out *inheritanceState) {
	for _, cluster := range slices.Sorted(maps.Keys(s.remoteBindings)) {
		delivery := s.remoteBindings[cluster]
		if delivery.Unavailable {
			out.UnavailableClusters = append(out.UnavailableClusters, cluster)
			continue
		}
		for _, b := range delivery.Bindings {
			s.appendBindingBasis(out, b, now)
		}
	}
}
