package configuration

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// refreshRemoteBindings rereads the joined clusters' AccessBinding
// deliveries (ADR-329) within three seconds. A failed read, the hub
// cluster's own row and an invalid delivery keep the previous state, whose
// allows lapse with its ADR-311 window.
func (s *bindingRun) refreshRemoteBindings(ctx context.Context) {
	if s.r.RemoteBindings == nil {
		return
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	deliveries, err := s.r.RemoteBindings.RemoteBindings(call)
	if err != nil {
		return
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
}

// remoteBindingBases adds the joined clusters' AccessBindings to the batch
// exactly like the hub cluster's (ADR-329), in cluster order. A delivery's
// allows grant only within its ADR-311 window from ObservedAt; its denies
// stay until a later delivery removes them, so a connector outage never
// lifts a deny. A cluster whose bases do not fit the stream's remaining
// budget contributes nothing. Continuity is never claimed across deliveries.
func (s *bindingRun) remoteBindingBases(now time.Time, out *inheritanceState, bases, rows *int) {
	for _, cluster := range slices.Sorted(maps.Keys(s.remoteBindings)) {
		d := s.remoteBindings[cluster]
		fresh := identity.Check(d.ObservedAt, identity.Recheck).Valid(now)
		var add []value.PermissionBasis
		added := 0
		for _, b := range d.Bindings {
			if b.Invalid || (b.Resource.Deleting && b.Effect == "Allow") || (!b.NotAfter.IsZero() && !now.Before(b.NotAfter)) || b.Effect != "Deny" && !fresh {
				continue
			}
			p := value.PermissionBasis{Resource: b.Resource, Scope: b.Scope, Effect: b.Effect, Subjects: slices.Clone(b.Subjects), Roles: slices.Clone(b.Roles), NotAfter: b.NotAfter, Automation: b.Automation}
			p.ScopeDigest = PermissionScopeDigest(p)
			add = append(add, p)
			added += len(b.Subjects) * len(b.Roles)
		}
		if *bases+len(add) > 1024 || *rows+added > 4096 {
			continue
		}
		*bases, *rows = *bases+len(add), *rows+added
		out.Bases = append(out.Bases, add...)
	}
}
