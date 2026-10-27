package configuration

import (
	"cmp"
	"maps"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// NamespaceJournal holds one cluster's namespaces that carry an observed key,
// built from a complete LIST and advanced by every watch transition in order
// (ADR-242). Each transition is applied, and reconciled by the coordinator,
// before the next one, so an A -> B -> A ownership change cannot be skipped
// while the journal lives. A new LIST starts a new journal: it never claims
// continuity with the previous one.
type NamespaceJournal struct {
	cluster  string
	keys     value.NamespaceKeys
	byUID    map[string]value.ObservedNamespace
	observed time.Time
	poisoned bool
}

func cloneNamespace(n value.ObservedNamespace) value.ObservedNamespace {
	n.Labels, n.Annotations = maps.Clone(n.Labels), maps.Clone(n.Annotations)
	return n
}

func NewNamespaceJournal(l value.NamespaceList) (*NamespaceJournal, error) {
	if !authorization.UUID(l.ClusterID) || !identity.Text(l.ResourceVersion, 128) || !l.Keys.Valid() || l.ObservedAt.IsZero() || len(l.Namespaces) > value.MaxObservedNamespaces {
		return nil, value.ErrInvalid
	}
	j := &NamespaceJournal{cluster: l.ClusterID, keys: l.Keys, byUID: map[string]value.ObservedNamespace{}, observed: l.ObservedAt}
	names := map[string]bool{}
	for _, n := range l.Namespaces {
		if !n.Valid(l.Keys, true) || names[n.Name] {
			return nil, value.ErrInvalid
		}
		if _, exists := j.byUID[n.UID]; exists {
			return nil, value.ErrInvalid
		}
		names[n.Name] = true
		j.byUID[n.UID] = cloneNamespace(n)
	}
	return j, nil
}

func (j *NamespaceJournal) Keys() value.NamespaceKeys { return j.keys }

// Apply processes one watch transition. A namespace without observed keys is
// not tracked; an invalid or inconsistent transition poisons the journal.
func (j *NamespaceJournal) Apply(e value.NamespaceEvent) error {
	fail := func() error { j.poisoned = true; return value.ErrChanged }
	if j.poisoned || !identity.Text(e.ResourceVersion, 128) {
		return fail()
	}
	if e.Type == "BOOKMARK" {
		if e.Namespace != nil {
			return fail()
		}
		return nil
	}
	n := e.Namespace
	if n == nil || n.ResourceVersion != e.ResourceVersion || !identity.Text(n.Name, 63) || !identity.Text(n.UID, 64) {
		return fail()
	}
	old, exists := j.byUID[n.UID]
	if exists && old.Name != n.Name {
		return fail()
	}
	switch e.Type {
	case "ADDED", "MODIFIED":
		if len(n.Labels)+len(n.Annotations) == 0 {
			delete(j.byUID, n.UID)
			return nil
		}
		if !n.Valid(j.keys, true) {
			return fail()
		}
		for uid, other := range j.byUID {
			if uid != n.UID && other.Name == n.Name {
				return fail()
			}
		}
		if !exists && len(j.byUID) >= value.MaxObservedNamespaces {
			return fail()
		}
		j.byUID[n.UID] = cloneNamespace(*n)
	case "DELETED":
		delete(j.byUID, n.UID)
	default:
		return fail()
	}
	return nil
}

// Fresh records that a watch session started at at ended cleanly after all
// of its transitions were applied: the journal is current as of at.
func (j *NamespaceJournal) Fresh(at time.Time) {
	if at.After(j.observed) {
		j.observed = at
	}
}

// ObservedAt is the start of the latest LIST or clean watch session.
func (j *NamespaceJournal) ObservedAt() time.Time { return j.observed }

// Observation is the current namespace state, sorted by UID. live keeps the
// resourceVersions for source bases; the accepted form omits them.
func (j *NamespaceJournal) Observation(live bool) *value.NamespaceObservation {
	if j == nil || j.poisoned {
		return nil
	}
	o := &value.NamespaceObservation{ClusterID: j.cluster, Keys: value.NamespaceKeys{Labels: slices.Clone(j.keys.Labels), Annotations: slices.Clone(j.keys.Annotations)}}
	for _, n := range j.byUID {
		n = cloneNamespace(n)
		if !live {
			n.ResourceVersion = ""
		}
		o.Namespaces = append(o.Namespaces, n)
	}
	slices.SortFunc(o.Namespaces, func(a, b value.ObservedNamespace) int { return cmp.Compare(a.UID, b.UID) })
	return o
}
