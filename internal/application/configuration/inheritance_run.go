package configuration

import (
	"cmp"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
)

// Inheritance is the source-derived part of one prepared permission batch.
type Inheritance struct {
	Bases              []value.PermissionBasis
	UnavailableSources []string
	SourcesUnavailable bool
	Namespaces         *value.NamespaceObservation
	// RemoteNamespaces are the minimized current observations of joined
	// clusters other than the hub's (ADR-247), sorted by cluster.
	RemoteNamespaces []value.NamespaceObservation `json:",omitempty"`
	// Workloads are the minimized current workload observations (ADR-247),
	// in (cluster, selection) order.
	Workloads []value.WorkloadObservation `json:",omitempty"`
	// ReviewSources are the accepted decision-time sources (ADR-245), for
	// every cluster: their reviews run in the target cluster's connector.
	ReviewSources []value.ReviewSource `json:",omitempty"`
}

// namespaceItem is one ordered delivery of the namespace feed: a complete
// LIST, a watch transition or the start time of a cleanly ended session.
type namespaceItem struct {
	historyLost bool
	list        *value.NamespaceList
	event       *value.NamespaceEvent
	fresh       time.Time
}

// runNamespaceFeed lists the namespaces once, then follows them with finite
// watch sessions resumed from the last delivered cursor. A transient watch
// failure resumes from the same cursor, which keeps continuity; expired
// history (value.ErrChanged) needs a new LIST and so a new journal. Items are
// delivered in order and each is processed before the next is read.
func runNamespaceFeed(ctx context.Context, o NamespaceObserver, keys value.NamespaceKeys, now func() time.Time, out chan<- namespaceItem) {
	send := func(it namespaceItem) bool {
		select {
		case out <- it:
			return true
		case <-ctx.Done():
			return false
		}
	}
	pause := func() bool {
		t := time.NewTimer(time.Second)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}
	for ctx.Err() == nil {
		list, err := o.ListNamespaces(ctx, keys)
		if err != nil {
			if !pause() {
				return
			}
			continue
		}
		if !send(namespaceItem{list: &list}) {
			return
		}
		cursor := list.ResourceVersion
		for ctx.Err() == nil {
			start := now()
			w, err := o.WatchNamespaces(ctx, cursor, keys)
			if err == nil {
				for {
					var e value.NamespaceEvent
					if e, err = w.Next(ctx); err != nil {
						break
					}
					if e.Type != "BOOKMARK" && !send(namespaceItem{event: &e}) {
						w.Close()
						return
					}
					cursor = e.ResourceVersion
				}
				w.Close()
				if errors.Is(err, io.EOF) {
					if !send(namespaceItem{fresh: start}) {
						return
					}
					continue
				}
			}
			if errors.Is(err, value.ErrChanged) {
				if !send(namespaceItem{historyLost: true}) {
					return
				}
				break
			}
			if !pause() {
				return
			}
		}
	}
}

// namespaceFeed is the running feed of one key set.
type namespaceFeed struct {
	keys   value.NamespaceKeys
	items  chan namespaceItem
	cancel context.CancelFunc
	done   chan struct{}
}

func (f *namespaceFeed) stop() {
	if f != nil {
		f.cancel()
		<-f.done
	}
}

// syncSources records the latest source list and (re)starts the namespace
// feed when the observed key set changed. Without a namespace observer, or
// with more than 32 keys, there is no observation. While the source list is
// incomplete the feed follows only the ClusterAccessBinding selector keys.
func (s *bindingRun) syncSources(ctx context.Context, snapshot value.Snapshot) {
	s.sources, s.sourcesComplete = snapshot.Sources, snapshot.SourcesComplete
	s.clusterBindings = snapshot.ClusterBindings
	if s.r.Namespaces == nil {
		return
	}
	sources := snapshot.Sources
	if !snapshot.SourcesComplete {
		sources = nil
	}
	keys := namespaceKeys(sources, snapshot.ClusterBindings, s.r.NamespaceClusterID)
	if s.feed != nil && slices.Equal(s.feed.keys.Labels, keys.Labels) && slices.Equal(s.feed.keys.Annotations, keys.Annotations) {
		return
	}
	s.restartFeed(ctx, keys)
}

func (s *bindingRun) restartFeed(ctx context.Context, keys value.NamespaceKeys) {
	s.feed.stop()
	s.feed, s.namespaces = nil, nil
	s.continuity++
	if len(keys.Labels)+len(keys.Annotations) == 0 || !keys.Valid() {
		return
	}
	child, cancel := context.WithCancel(ctx)
	f := &namespaceFeed{keys: keys, items: make(chan namespaceItem, 1), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		runNamespaceFeed(child, s.r.Namespaces, keys, s.r.Now, f.items)
	}()
	s.feed = f
}

func (s *bindingRun) feedItems() <-chan namespaceItem {
	if s.feed == nil {
		return nil
	}
	return s.feed.items
}

// namespaceItem applies one feed delivery. A transition that changes the
// derived inheritance is accepted before the next one is read. A trust or
// storage error ends the epoch before any later transition is accepted.
func (s *bindingRun) namespaceItem(ctx context.Context, it namespaceItem) error {
	switch {
	case it.historyLost:
		s.namespaces = nil
	case it.list != nil:
		j, err := NewNamespaceJournal(*it.list)
		if err != nil {
			s.restartFeed(ctx, s.feed.keys)
		} else {
			s.namespaces, s.continuity = j, s.continuity+1
		}
	case it.event != nil:
		if s.namespaces == nil {
			return nil
		}
		if err := s.namespaces.Apply(*it.event); err != nil {
			s.restartFeed(ctx, s.feed.keys)
		} else if it.event.Type == "BOOKMARK" {
			return nil
		}
	default:
		if s.namespaces != nil {
			s.namespaces.Fresh(it.fresh)
		}
		return nil
	}
	return s.accept(ctx, true)
}

type inheritanceState struct {
	Inheritance
	included map[string]int
}

// inheritance derives the source part of the next batch at now. A source is
// unavailable (its accepted assignments kept, granting nothing) while its
// cluster's namespace metadata is unknown; it grants nothing, and its
// assignments are retired, when it is disabled or unsupported.
func (s *bindingRun) inheritance(now time.Time) inheritanceState {
	out := inheritanceState{included: map[string]int{}}
	// ADR-329: joined clusters' AccessBindings do not depend on the hub
	// cluster's PermissionSource list.
	s.remoteBindingBases(now, &out)
	// ClusterAccessBindings are read with every LIST (ADR-335 D14).
	for _, b := range s.clusterBindings {
		p, ok := bindingBasis(b, now)
		if !ok {
			continue
		}
		if len(b.NamespaceSelector) == 0 {
			out.Bases = append(out.Bases, p)
			continue
		}
		// A selector-narrowed binding has one basis per selected namespace.
		// While its cluster's labels are unknown an allow grants nothing
		// and a deny covers every namespace.
		namespaces, known := SelectedNamespaces(b.NamespaceSelector, s.observation(b.Scope.ClusterID, now))
		if !known && p.Effect == "Deny" {
			out.Bases = append(out.Bases, p)
		}
		for _, ns := range namespaces {
			q := p
			q.Scope.Namespace = ns
			q.ScopeDigest = PermissionScopeDigest(q)
			out.Bases = append(out.Bases, q)
		}
	}
	if !s.sourcesComplete {
		out.SourcesUnavailable = true
		return out
	}
	out.ReviewSources = value.ReviewSources(s.sources)
	var live *value.NamespaceObservation
	if s.namespaces != nil {
		live = s.namespaces.Observation(true)
		// The recorded observation is what the preview evaluates against;
		// it is withdrawn once older than the positive freshness interval.
		if now.Before(s.namespaces.ObservedAt().Add(authorization.PermissionObservationInterval)) {
			out.Namespaces = s.namespaces.Observation(false)
		}
	}
	sources := slices.Clone(s.sources)
	slices.SortFunc(sources, func(a, b value.Source) int { return cmp.Compare(a.Resource.UID, b.Resource.UID) })
	remote := slices.Sorted(maps.Keys(s.remote))
	for _, cluster := range remote {
		if r := s.remote[cluster]; now.Before(r.observedAt.Add(authorization.PermissionObservationInterval)) {
			out.RemoteNamespaces = append(out.RemoteNamespaces, minimizedObservation(*r.live))
		}
	}
	for _, key := range slices.Sorted(maps.Keys(s.workloads)) {
		if w := s.workloads[key]; now.Before(w.observedAt.Add(authorization.PermissionObservationInterval)) {
			out.Workloads = append(out.Workloads, minimizedWorkloads(*w.live))
		}
	}
	for _, src := range sources {
		if src.Type == "workloadMetadata" {
			s.inheritWorkloads(&out, src)
			continue
		}
		cluster, observed := s.r.NamespaceClusterID, live
		// ADR-247: another joined cluster's source is evaluated against its
		// connector's journal. Its versions change only with an observed
		// value, so exact comparison keeps assignments across unrelated
		// writes; continuity is never claimed across reads.
		other := src.ClusterID != s.r.NamespaceClusterID
		if other {
			cluster, observed = src.ClusterID, nil
			if r := s.remote[src.ClusterID]; r != nil {
				observed = r.live
			}
		}
		grants, reason := NamespaceGrants(src, cluster, observed)
		switch reason {
		case "":
		case value.MetadataUnavailable, value.MetadataNotObserved:
			out.UnavailableSources = append(out.UnavailableSources, src.Resource.UID)
			if n, ok := s.included[src.Resource.UID]; ok {
				out.included[src.Resource.UID] = n
			}
			continue
		default:
			continue
		}
		previous, ok := s.included[src.Resource.UID]
		continuous := ok && previous == s.continuity && !other
		for _, g := range grants {
			out.Bases = append(out.Bases, SourceBasis(src, g, continuous))
		}
		out.included[src.Resource.UID] = s.continuity
	}
	return out
}

// observation is the current namespace observation of cluster: the hub's
// own feed or a joined cluster's connector journal (ADR-247), which lapses
// like the recorded RemoteNamespaces.
func (s *bindingRun) observation(cluster string, now time.Time) *value.NamespaceObservation {
	if cluster != s.r.NamespaceClusterID {
		if r := s.remote[cluster]; r != nil && now.Before(r.observedAt.Add(authorization.PermissionObservationInterval)) {
			return r.live
		}
		return nil
	}
	if s.namespaces == nil {
		return nil
	}
	return s.namespaces.Observation(true)
}

// inheritanceDigest identifies the derived state independent of continuity
// flags, which never change what is accepted.
func inheritanceDigest(i inheritanceState) [32]byte {
	d, _ := permissionInputDigest(i.Inheritance.withoutContinuity())
	return d
}

// Continuity affects assignment retention during an acceptance, but does not
// change the observed contents of the inputs.
func (i Inheritance) withoutContinuity() Inheritance {
	i.Bases = slices.Clone(i.Bases)
	for n := range i.Bases {
		i.Bases[n].Continuous = false
	}
	return i
}

// minimizedObservation drops the versions, as the accepted form does.
func minimizedObservation(o value.NamespaceObservation) value.NamespaceObservation {
	o.Namespaces = slices.Clone(o.Namespaces)
	for i := range o.Namespaces {
		o.Namespaces[i] = cloneNamespace(o.Namespaces[i])
		o.Namespaces[i].ResourceVersion = ""
	}
	return o
}

func minimizedWorkloads(o value.WorkloadObservation) value.WorkloadObservation {
	o.Workloads = slices.Clone(o.Workloads)
	for i := range o.Workloads {
		o.Workloads[i].ObservedNamespace = cloneNamespace(o.Workloads[i].ObservedNamespace)
		o.Workloads[i].ResourceVersion = ""
	}
	return o
}

// inheritWorkloads adds one workloadMetadata source's bases (ADR-247): its
// connector journal's exact versions, never continuity; unavailable while
// the journal is unknown.
func (s *bindingRun) inheritWorkloads(out *inheritanceState, src value.Source) {
	var observed *value.WorkloadObservation
	if w := s.workloads[workloadKey(src.ClusterID, WorkloadSelectionOf(src))]; w != nil {
		observed = w.live
	}
	grants, reason := WorkloadGrants(src, observed)
	switch reason {
	case "":
	case value.MetadataUnavailable, value.MetadataNotObserved:
		out.UnavailableSources = append(out.UnavailableSources, src.Resource.UID)
		return
	default:
		return
	}
	for _, g := range grants {
		out.Bases = append(out.Bases, WorkloadBasis(src, g))
	}
}
