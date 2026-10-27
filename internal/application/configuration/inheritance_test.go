package configuration

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

const inheritanceCluster = journalID

func inheritanceSource() value.Source {
	return value.Source{Resource: value.Resource{ClusterID: inheritanceCluster, Namespace: "asservat", NamespaceUID: "control", Kind: "PermissionSource", Name: "owners", UID: "source", Generation: 1, ResourceVersion: "source-rv", SpecDigest: artifact.Digest{7}},
		Enabled: true, Type: "namespaceMetadata", ClusterID: inheritanceCluster, Role: "workload-maintainer", NamespaceSelector: map[string]string{"managed": "true"}, MaxDecisionAge: 30 * time.Second, MaxNamespaces: 10,
		Protection: value.Protection{Mode: "administratorManaged", ReviewRef: "platform-review"},
		Mapping:    value.Mapping{Field: "annotation", Key: "owner", Mode: "valueMap", Issuer: "https://id.example.test", Values: map[string][]string{"payments": {"team-b", "team-a"}, "Payments": {"team-c"}}}}
}

func observedNamespace(name, uid, rv, owner string) value.ObservedNamespace {
	n := value.ObservedNamespace{Name: name, UID: uid, ResourceVersion: rv, Labels: map[string]string{"managed": ValueDigest("true")}}
	if owner != "" {
		n.Annotations = map[string]string{"owner": ValueDigest(owner)}
	}
	return n
}

func inheritanceObservation() *value.NamespaceObservation {
	return &value.NamespaceObservation{ClusterID: inheritanceCluster, Keys: value.NamespaceKeys{Labels: []string{"managed"}, Annotations: []string{"owner"}}, Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "ns-rv", "payments")}}
}

func TestNamespaceGrantsMapOnlyConfiguredValues(t *testing.T) {
	grants, reason := NamespaceGrants(inheritanceSource(), inheritanceCluster, inheritanceObservation())
	if reason != "" || len(grants) != 1 || grants[0].Namespace != (value.NamespaceRef{Name: "payments", UID: "payments-uid"}) || grants[0].ResourceVersion != "ns-rv" ||
		!slices.Equal(grants[0].Subjects, []value.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-a"}, {Kind: "Group", Issuer: "https://id.example.test", ID: "team-b"}}) {
		t.Fatalf("configured owners not granted: %q %+v", reason, grants)
	}
	for name, c := range map[string]struct {
		mutate func(*value.Source, *value.NamespaceObservation)
		reason string
	}{
		"unknown value": {func(_ *value.Source, o *value.NamespaceObservation) {
			o.Namespaces[0].Annotations["owner"] = ValueDigest("other")
		}, ""},
		"comma list": {func(_ *value.Source, o *value.NamespaceObservation) {
			o.Namespaces[0].Annotations["owner"] = ValueDigest("payments,payroll")
		}, ""},
		"oversized value":    {func(_ *value.Source, o *value.NamespaceObservation) { o.Namespaces[0].Annotations["owner"] = "" }, ""},
		"missing annotation": {func(_ *value.Source, o *value.NamespaceObservation) { o.Namespaces[0].Annotations = nil }, ""},
		"label spoof": {func(_ *value.Source, o *value.NamespaceObservation) {
			o.Namespaces[0].Annotations = nil
			o.Keys.Labels = []string{"managed", "owner"}
			o.Namespaces[0].Labels["owner"] = ValueDigest("payments")
		}, ""},
		"missing selector": {func(_ *value.Source, o *value.NamespaceObservation) { delete(o.Namespaces[0].Labels, "managed") }, ""},
		"selector mismatch": {func(_ *value.Source, o *value.NamespaceObservation) {
			o.Namespaces[0].Labels["managed"] = ValueDigest("false")
		}, ""},
		"excluded namespace": {func(s *value.Source, _ *value.NamespaceObservation) { s.ExcludedNamespaces = []string{"payments"} }, ""},
		"deleting namespace": {func(_ *value.Source, o *value.NamespaceObservation) { o.Namespaces[0].Deleting = true }, ""},
		"disabled":           {func(s *value.Source, _ *value.NamespaceObservation) { s.Enabled = false }, value.SourceDisabled},
		"deleting source":    {func(s *value.Source, _ *value.NamespaceObservation) { s.Resource.Deleting = true }, value.SourceDisabled},
		"directory mode":     {func(s *value.Source, _ *value.NamespaceObservation) { s.Mapping.Mode = "groupID" }, value.SourceUnsupported},
		"guarded mode":       {func(s *value.Source, _ *value.NamespaceObservation) { s.Protection.Mode = "admissionEnforced" }, value.SourceUnsupported},
		"exec source":        {func(s *value.Source, _ *value.NamespaceObservation) { s.Type = "kubernetesExec" }, value.SourceUnsupported},
		"workload source":    {func(s *value.Source, _ *value.NamespaceObservation) { s.Type = "workloadMetadata" }, value.SourceUnsupported},
		"other cluster": {func(s *value.Source, _ *value.NamespaceObservation) {
			s.ClusterID = "22222222-2222-4222-8222-222222222222"
		}, value.SourceUnsupported},
		"unobserved key": {func(s *value.Source, _ *value.NamespaceObservation) { s.Mapping.Key = "team" }, value.MetadataNotObserved},
		"too many namespaces": {func(s *value.Source, o *value.NamespaceObservation) {
			s.MaxNamespaces = 1
			o.Namespaces = append(o.Namespaces, observedNamespace("payments-2", "z-uid", "rv", "payments"))
		}, value.SourceTooManyNamespaces},
	} {
		t.Run(name, func(t *testing.T) {
			s, o := inheritanceSource(), inheritanceObservation()
			c.mutate(&s, o)
			if grants, reason := NamespaceGrants(s, inheritanceCluster, o); len(grants) != 0 || reason != c.reason {
				t.Fatalf("got %q %+v", reason, grants)
			}
		})
	}
	if _, reason := NamespaceGrants(inheritanceSource(), inheritanceCluster, nil); reason != value.MetadataUnavailable {
		t.Fatal("missing observation was not unavailable", reason)
	}
}

func TestNamespaceJournalAppliesEveryTransition(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	keys := value.NamespaceKeys{Labels: []string{"managed"}, Annotations: []string{"owner"}}
	j, err := NewNamespaceJournal(value.NamespaceList{ClusterID: inheritanceCluster, ResourceVersion: "10", Keys: keys, ObservedAt: now, Namespaces: []value.ObservedNamespace{observedNamespace("payments", "p", "1", "payments")}})
	if err != nil {
		t.Fatal(err)
	}
	changed := observedNamespace("payments", "p", "11", "payroll")
	if err = j.Apply(value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "11", Namespace: &changed}); err != nil {
		t.Fatal(err)
	}
	plain := value.ObservedNamespace{Name: "plain", UID: "q", ResourceVersion: "12"}
	if err = j.Apply(value.NamespaceEvent{Type: "ADDED", ResourceVersion: "12", Namespace: &plain}); err != nil {
		t.Fatal(err)
	}
	o := j.Observation(false)
	if len(o.Namespaces) != 1 || o.Namespaces[0].Annotations["owner"] != ValueDigest("payroll") || o.Namespaces[0].ResourceVersion != "" || !o.Valid() {
		t.Fatalf("journal state %+v", o)
	}
	if live := j.Observation(true); live.Namespaces[0].ResourceVersion != "11" {
		t.Fatal("live observation lost the namespace version")
	}
	j.Fresh(now.Add(-time.Second))
	j.Fresh(now.Add(time.Second))
	if !j.ObservedAt().Equal(now.Add(time.Second)) {
		t.Fatal("freshness moved backwards or not forward")
	}
	renamed := observedNamespace("other", "p", "13", "payments")
	if err = j.Apply(value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "13", Namespace: &renamed}); err == nil || j.Observation(false) != nil {
		t.Fatal("inconsistent transition did not poison the journal")
	}
}

// namespaceFixture is a NamespaceObserver whose first watch session
// delivers events and later sessions wait for cancellation.
type namespaceFixture struct {
	mu      sync.Mutex
	list    value.NamespaceList
	listErr error
	events  []value.NamespaceEvent
	now     func() time.Time
	watches int
}

func (f *namespaceFixture) ListNamespaces(_ context.Context, keys value.NamespaceKeys) (value.NamespaceList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.list
	l.Keys, l.ObservedAt = keys, f.now()
	return l, f.listErr
}
func (f *namespaceFixture) WatchNamespaces(context.Context, string, value.NamespaceKeys) (NamespaceWatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watches++
	if f.watches == 1 {
		return &namespaceFixtureWatch{events: f.events}, nil
	}
	return &namespaceFixtureWatch{}, nil
}

type namespaceFixtureWatch struct{ events []value.NamespaceEvent }

func (w *namespaceFixtureWatch) Close() {}
func (w *namespaceFixtureWatch) Next(ctx context.Context) (value.NamespaceEvent, error) {
	if len(w.events) > 0 {
		e := w.events[0]
		w.events = w.events[1:]
		return e, nil
	}
	<-ctx.Done()
	return value.NamespaceEvent{}, ctx.Err()
}

func inheritanceRun(t *testing.T, events ...value.NamespaceEvent) (*reconciliationFixture, *namespaceFixture, *bindingRun, context.Context) {
	t.Helper()
	f, r := reconciliationTest(t)
	// The feed reads the clock from its own goroutine.
	var clock sync.Mutex
	advance := r.Now
	r.Now = func() time.Time { clock.Lock(); defer clock.Unlock(); return advance() }
	f.storeFence.Initialized = true
	f.snapshot.Sources, f.snapshot.SourcesComplete = []value.Source{inheritanceSource()}, true
	ns := &namespaceFixture{list: value.NamespaceList{ClusterID: inheritanceCluster, ResourceVersion: "10", Namespaces: []value.ObservedNamespace{observedNamespace("payments", "payments-uid", "1", "payments")}}, events: events, now: r.Now}
	r.Namespaces, r.NamespaceClusterID = ns, inheritanceCluster
	ctx, cancel := context.WithCancel(context.Background())
	s := &bindingRun{r: r}
	t.Cleanup(func() { cancel(); s.feed.stop() })
	if err := s.start(ctx); err != nil {
		t.Fatal(err)
	}
	return f, ns, s, ctx
}

func nextNamespaceItem(t *testing.T, s *bindingRun) namespaceItem {
	t.Helper()
	select {
	case it := <-s.feedItems():
		return it
	case <-time.After(2 * time.Second):
		t.Fatal("namespace feed delivered nothing")
	}
	return namespaceItem{}
}

func inheritedOwners(b value.PermissionBatch) ([]string, bool) {
	var owners []string
	continuous := true
	for _, p := range b.Bases {
		if p.Resource.Kind != "PermissionSource" {
			continue
		}
		continuous = continuous && p.Continuous
		for _, s := range p.Subjects {
			owners = append(owners, p.Scope.Namespace.Name+"/"+s.ID)
		}
	}
	return owners, continuous
}

func TestReconcilerAcceptsEveryInheritedOwnershipTransition(t *testing.T) {
	payroll := observedNamespace("payments", "payments-uid", "2", "payroll")
	back := observedNamespace("payments", "payments-uid", "3", "payments")
	f, _, s, ctx := inheritanceRun(t, value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "2", Namespace: &payroll}, value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "3", Namespace: &back})
	if len(f.accepted) != 1 || len(f.accepted[0].UnavailableSources) != 1 || f.accepted[0].UnavailableSources[0] != "source" {
		t.Fatal("source without a namespace observation was not kept unavailable", f.accepted)
	}
	for range 3 {
		if err := s.namespaceItem(ctx, nextNamespaceItem(t, s)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.accepted) != 4 {
		t.Fatalf("transitions coalesced: %d acceptances", len(f.accepted))
	}
	for i, want := range []struct {
		owners     []string
		continuous bool
	}{{[]string{"payments/team-a", "payments/team-b"}, false}, {nil, true}, {[]string{"payments/team-a", "payments/team-b"}, true}} {
		b := f.accepted[i+1]
		owners, continuous := inheritedOwners(b)
		if !slices.Equal(owners, want.owners) || len(owners) > 0 && continuous != want.continuous || len(b.UnavailableSources) != 0 || b.Namespaces == nil {
			t.Fatalf("acceptance %d: %v continuous=%v %+v", i+1, owners, continuous, b)
		}
		if b.Namespaces.Namespaces[0].ResourceVersion != "" {
			t.Fatal("accepted observation kept a resource version")
		}
	}
	if f.accepted[1].InputDigest == f.accepted[3].InputDigest {
		// Same owners, but a different namespace version: still a new input.
		t.Fatal("namespace version change hidden from the input digest")
	}
}

func TestReconcilerDropsContinuityWhenATransitionCannotBeAccepted(t *testing.T) {
	payroll := observedNamespace("payments", "payments-uid", "2", "payroll")
	f, _, s, ctx := inheritanceRun(t, value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "2", Namespace: &payroll})
	if err := s.namespaceItem(ctx, nextNamespaceItem(t, s)); err != nil {
		t.Fatal(err)
	}
	// The binding list is no longer current: the transition cannot be
	// committed now, so the next acceptance must not claim continuity.
	s.trustUntil = time.Time{}
	if err := s.namespaceItem(ctx, nextNamespaceItem(t, s)); err != nil {
		t.Fatal(err)
	}
	if len(f.accepted) != 2 {
		t.Fatal("transition accepted without a current binding list")
	}
	s.trustUntil = s.r.Now().Add(5 * time.Second)
	back := observedNamespace("payments", "payments-uid", "3", "payments")
	if err := s.namespaces.Apply(value.NamespaceEvent{Type: "MODIFIED", ResourceVersion: "3", Namespace: &back}); err != nil {
		t.Fatal(err)
	}
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if owners, continuous := inheritedOwners(f.accepted[2]); len(owners) != 2 || continuous {
		t.Fatal("skipped transition still claimed continuity", owners)
	}
}

func TestInheritanceUnavailableStatesKeepNothingCurrent(t *testing.T) {
	f, ns, s, ctx := inheritanceRun(t)
	if err := s.namespaceItem(ctx, nextNamespaceItem(t, s)); err != nil {
		t.Fatal(err)
	}
	if owners, _ := inheritedOwners(f.accepted[len(f.accepted)-1]); len(owners) != 2 {
		t.Fatal("observed source not granted")
	}
	// Older than maxDecisionAgeSeconds: kept, but unavailable.
	stale := s.inheritance(s.namespaces.ObservedAt().Add(30 * time.Second))
	if len(stale.Bases) != 0 || !slices.Equal(stale.UnavailableSources, []string{"source"}) || stale.included["source"] != s.included["source"] {
		t.Fatalf("stale observation still granted: %+v", stale)
	}
	// An unreadable source list keeps every source unavailable.
	s.sourcesComplete = false
	if all := s.inheritance(s.r.Now()); !all.SourcesUnavailable || len(all.Bases) != 0 {
		t.Fatal("incomplete source list still granted")
	}
	s.sourcesComplete = true
	// A disabled source grants nothing and is not kept.
	disabled := inheritanceSource()
	disabled.Enabled = false
	s.sources = []value.Source{disabled}
	if off := s.inheritance(s.r.Now()); len(off.Bases) != 0 || len(off.UnavailableSources) != 0 {
		t.Fatal("disabled source kept or granted")
	}
	// A namespace LIST that keeps failing never produces an observation.
	ns.mu.Lock()
	ns.listErr = errors.New("synthetic outage")
	ns.mu.Unlock()
	s.sources = []value.Source{inheritanceSource()}
	s.restartFeed(ctx, SourceKeys(s.sources, inheritanceCluster))
	if out := s.inheritance(s.r.Now()); out.Namespaces != nil || !slices.Equal(out.UnavailableSources, []string{"source"}) {
		t.Fatal("restarted feed granted before a new LIST")
	}
}

func TestInheritanceRespectsTheBatchBudget(t *testing.T) {
	_, _, s, ctx := inheritanceRun(t)
	if err := s.namespaceItem(ctx, nextNamespaceItem(t, s)); err != nil {
		t.Fatal(err)
	}
	for uid := range 1023 {
		s.journal.byUID[string(rune('a'+uid%26))+string(rune(uid))] = s.journal.byUID["binding"]
	}
	if out := s.inheritance(s.r.Now()); len(out.Bases) != 0 || len(out.UnavailableSources) != 0 {
		t.Fatal("over-budget source granted or kept", len(out.Bases))
	}
}

// ADR-245: decision-time sources of every cluster are accepted configuration
// with no subject, carried in the batch; an unreadable source list carries
// none (the store then keeps them without renewal).
func TestInheritanceCarriesDecisionTimeSources(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	exec := value.Source{Resource: value.Resource{Kind: "PermissionSource", UID: "exec", ResourceVersion: "1", Generation: 1, SpecDigest: artifact.Digest{9}}, Enabled: true, Type: value.SourceKubernetesExec,
		ClusterID: "22222222-2222-4222-8222-222222222222", Role: "workload-maintainer", MaxDecisionAge: 30 * time.Second, MaxNamespaces: 10, IdentityMappingRef: "company",
		AdmissionParity: value.AdmissionParity{Mode: "noAdditionalRestrictions", ReviewRef: "platform-review"}}
	disabled := exec
	disabled.Resource.UID, disabled.Enabled = "off", false
	s.sources = []value.Source{inheritanceSource(), exec, disabled}
	out := s.inheritance(s.r.Now())
	if len(out.ReviewSources) != 1 || out.ReviewSources[0].Resource.UID != "exec" || out.ReviewSources[0].Check != value.ReviewPodExec {
		t.Fatalf("review sources %+v", out.ReviewSources)
	}
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if b := f.accepted[len(f.accepted)-1]; len(b.ReviewSources) != 1 || b.Validate(b.ObservedAt) != nil {
		t.Fatalf("accepted batch %+v", b.ReviewSources)
	}
	s.sourcesComplete = false
	if all := s.inheritance(s.r.Now()); !all.SourcesUnavailable || len(all.ReviewSources) != 0 {
		t.Fatal("unreadable source list carried review sources")
	}
}
