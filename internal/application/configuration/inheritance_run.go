package configuration

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	list  *value.NamespaceList
	event *value.NamespaceEvent
	fresh time.Time
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
			if errors.Is(err, value.ErrChanged) || !pause() {
				break
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
// with more than 32 keys, there is no observation.
func (s *bindingRun) syncSources(ctx context.Context, snapshot value.Snapshot) {
	s.sources, s.sourcesComplete = snapshot.Sources, snapshot.SourcesComplete
	if s.r.Namespaces == nil || !snapshot.SourcesComplete {
		return
	}
	keys := SourceKeys(snapshot.Sources, s.r.NamespaceClusterID)
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
// derived inheritance is accepted before the next one is read; when that is
// impossible now, continuity is dropped instead, so that the next acceptance
// compares exact namespace resourceVersions and retires what changed.
func (s *bindingRun) namespaceItem(ctx context.Context, it namespaceItem) error {
	switch {
	case it.list != nil:
		j, err := NewNamespaceJournal(*it.list)
		if err != nil {
			s.restartFeed(ctx, s.feed.keys)
			return nil
		}
		s.namespaces, s.continuity = j, s.continuity+1
	case it.event != nil:
		if s.namespaces == nil {
			return nil
		}
		if err := s.namespaces.Apply(*it.event); err != nil {
			s.restartFeed(ctx, s.feed.keys)
			return nil
		}
	default:
		if s.namespaces != nil {
			s.namespaces.Fresh(it.fresh)
		}
		return nil
	}
	now := s.r.Now()
	if inheritanceDigest(s.inheritance(now)) == s.lastInheritance {
		return nil
	}
	if !s.journal.Ready(now) || !now.Before(s.trustUntil) {
		s.continuity++
		return nil
	}
	return s.accept(ctx, false)
}

type inheritanceState struct {
	Inheritance
	included map[string]int
}

// inheritance derives the source part of the next batch at now. A source is
// unavailable (its accepted assignments kept, granting nothing) while its
// cluster's namespace metadata is unknown or older than its
// maxDecisionAgeSeconds; it grants nothing, and its assignments are retired,
// when it is disabled, unsupported or too wide. Sources are taken in UID
// order; one whose namespaces exceed the batch's remaining basis or
// assignment budget grants nothing (TooManyNamespaces).
func (s *bindingRun) inheritance(now time.Time) inheritanceState {
	out := inheritanceState{included: map[string]int{}}
	if !s.fence.Initialized {
		// The first acceptance binds the reviewed explicit baseline only.
		return out
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
	bases, rows := s.journal.Budget(now)
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
			s.inheritWorkloads(&out, src, now, &bases, &rows)
			continue
		}
		cluster, observed := s.r.NamespaceClusterID, live
		var observedAt time.Time
		if s.namespaces != nil {
			observedAt = s.namespaces.ObservedAt()
		}
		// ADR-247: another joined cluster's source is evaluated against its
		// connector's journal. Its versions change only with an observed
		// value, so exact comparison keeps assignments across unrelated
		// writes; continuity is never claimed across reads.
		other := src.ClusterID != s.r.NamespaceClusterID
		if other {
			cluster, observed, observedAt = src.ClusterID, nil, time.Time{}
			if r := s.remote[src.ClusterID]; r != nil {
				observed, observedAt = r.live, r.observedAt
			}
		}
		grants, reason := NamespaceGrantsWith(src, cluster, observed, value.SourceEvidence{Guard: s.guards[src.ClusterID], Directory: s.directories[src.Mapping.Issuer], Now: now})
		if reason == "" && observed != nil && !now.Before(observedAt.Add(src.MaxDecisionAge)) {
			reason = value.MetadataUnavailable
		}
		switch reason {
		case "":
		case value.MetadataUnavailable, value.MetadataNotObserved, value.GuardUnavailable, value.DirectoryUnavailable:
			out.UnavailableSources = append(out.UnavailableSources, src.Resource.UID)
			if n, ok := s.included[src.Resource.UID]; ok {
				out.included[src.Resource.UID] = n
			}
			continue
		default:
			continue
		}
		added := 0
		for _, g := range grants {
			added += len(g.Subjects)
		}
		if bases+len(grants) > 1024 || rows+added > 4096 {
			continue
		}
		bases, rows = bases+len(grants), rows+added
		previous, ok := s.included[src.Resource.UID]
		continuous := ok && previous == s.continuity && !other
		for _, g := range grants {
			out.Bases = append(out.Bases, SourceBasis(src, g, continuous))
		}
		out.included[src.Resource.UID] = s.continuity
	}
	return out
}

// inheritanceDigest identifies the derived state independent of continuity
// flags, which never change what is accepted.
func inheritanceDigest(i inheritanceState) [32]byte {
	v := i.Inheritance
	v.Bases = slices.Clone(v.Bases)
	for n := range v.Bases {
		v.Bases[n].Continuous = false
	}
	b, _ := json.Marshal(v)
	return sha256.Sum256(b)
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
// the journal, guard proof or directory is unknown or older than the
// source's maxDecisionAgeSeconds.
func (s *bindingRun) inheritWorkloads(out *inheritanceState, src value.Source, now time.Time, bases, rows *int) {
	var observed *value.WorkloadObservation
	var observedAt time.Time
	if w := s.workloads[workloadKey(src.ClusterID, WorkloadSelectionOf(src))]; w != nil {
		observed, observedAt = w.live, w.observedAt
	}
	grants, reason := WorkloadGrantsWith(src, observed, value.SourceEvidence{WorkloadGuard: s.workloadGuards[src.ClusterID], Directory: s.directories[src.Mapping.Issuer], Now: now})
	if reason == "" && !now.Before(observedAt.Add(src.MaxDecisionAge)) {
		reason = value.MetadataUnavailable
	}
	switch reason {
	case "":
	case value.MetadataUnavailable, value.MetadataNotObserved, value.GuardUnavailable, value.DirectoryUnavailable:
		out.UnavailableSources = append(out.UnavailableSources, src.Resource.UID)
		return
	default:
		return
	}
	added := 0
	for _, g := range grants {
		added += len(g.Subjects)
	}
	if *bases+len(grants) > 1024 || *rows+added > 4096 {
		return
	}
	*bases, *rows = *bases+len(grants), *rows+added
	for _, g := range grants {
		out.Bases = append(out.Bases, WorkloadBasis(src, g))
	}
}
