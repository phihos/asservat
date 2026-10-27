package configuration

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

func workloadSource() value.Source {
	s := inheritanceSource()
	s.Type, s.ClusterID, s.NamespaceSelector = "workloadMetadata", remoteCluster, nil
	s.WorkloadSelector = map[string]string{"managed": "true"}
	s.Protection = value.Protection{Mode: "admissionEnforced", ReviewRef: "platform-review", GuardRef: "workload-guard"}
	return s
}

func observedWorkload(name, uid, namespace, rv, owner string) value.ObservedWorkload {
	return value.ObservedWorkload{Kind: "Deployment", Namespace: value.NamespaceRef{Name: namespace, UID: namespace + "-uid"}, ObservedNamespace: observedNamespace(name, uid, rv, owner)}
}

func workloadEvidence(now time.Time) value.SourceEvidence {
	return value.SourceEvidence{Now: now, WorkloadGuard: &value.NamespaceGuardProof{ClusterID: remoteCluster, Name: "workload-guard", LabelKeys: []string{"managed"}, AnnotationKeys: []string{"owner"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}
}

// REQ-PER-005 / ADR-247: one basis per workload of the selection, only with
// a current workload guard proof covering every key.
func TestWorkloadGrantsRequireGuardAndSelection(t *testing.T) {
	now := time.Now()
	src := workloadSource()
	sel := WorkloadSelectionOf(src)
	if !slices.Equal(sel.Keys.Labels, []string{"managed"}) || !slices.Equal(sel.Keys.Annotations, []string{"owner"}) {
		t.Fatalf("selection keys %+v", sel)
	}
	o := &value.WorkloadObservation{ClusterID: remoteCluster, Selection: sel, Workloads: []value.ObservedWorkload{
		observedWorkload("api", "a", "shared", "j:0", "payments"), observedWorkload("web", "b", "shared", "j:0", "other"), observedWorkload("job", "c", "excluded", "j:0", "payments")}}
	src.ExcludedNamespaces = []string{"excluded"}
	grants, reason := WorkloadGrantsWith(src, o, workloadEvidence(now))
	if reason != "" || len(grants) != 1 || grants[0].Workload != (value.WorkloadRef{Kind: "Deployment", Name: "api", UID: "a"}) || grants[0].Namespace.UID != "shared-uid" {
		t.Fatalf("workload grants %q %+v", reason, grants)
	}
	b := WorkloadBasis(src, grants[0])
	other := WorkloadBasis(src, value.WorkloadGrant{Namespace: grants[0].Namespace, Workload: value.WorkloadRef{Kind: "Deployment", Name: "x", UID: "x"}, ResourceVersion: "j:0", Subjects: grants[0].Subjects})
	if len(b.Scope.Workloads) != 1 || b.Key() == other.Key() {
		t.Fatal("workload bases share a key or lack their workload scope")
	}
	for name, c := range map[string]struct {
		mutate func(*value.Source, *value.SourceEvidence)
		reason string
	}{
		"no guard":        {func(_ *value.Source, e *value.SourceEvidence) { e.WorkloadGuard = nil }, value.GuardUnavailable},
		"other guard":     {func(_ *value.Source, e *value.SourceEvidence) { e.WorkloadGuard.Name = "namespace-guard" }, value.SourceUnsupported},
		"unguarded key":   {func(_ *value.Source, e *value.SourceEvidence) { e.WorkloadGuard.AnnotationKeys = nil }, value.SourceUnsupported},
		"admin managed":   {func(s *value.Source, _ *value.SourceEvidence) { s.Protection.Mode = "administratorManaged" }, value.SourceUnsupported},
		"namespace scope": {func(s *value.Source, _ *value.SourceEvidence) { s.NamespaceSelector = map[string]string{"x": "y"} }, value.SourceUnsupported},
		"other selection": {func(s *value.Source, _ *value.SourceEvidence) {
			s.WorkloadSelector = map[string]string{"managed": "no"}
		}, value.MetadataNotObserved},
		"no selector":     {func(s *value.Source, _ *value.SourceEvidence) { s.WorkloadSelector = nil }, value.SourceUnsupported},
		"too many":        {func(s *value.Source, _ *value.SourceEvidence) { s.MaxNamespaces = 0 }, value.SourceUnsupported},
		"group ID no dir": {func(s *value.Source, _ *value.SourceEvidence) { s.Mapping.Mode, s.Mapping.Values = "groupID", nil }, value.DirectoryUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			s, e := workloadSource(), workloadEvidence(now)
			c.mutate(&s, &e)
			if g, r := WorkloadGrantsWith(s, o, e); len(g) != 0 || r != c.reason {
				t.Fatalf("got %q %+v", r, g)
			}
		})
	}
	// A pod label or a workload outside the selector value never grants.
	unselected := observedWorkload("spoof", "d", "shared", "j:0", "payments")
	unselected.Labels["managed"] = ValueDigest("false")
	if g, _ := WorkloadGrantsWith(src, &value.WorkloadObservation{ClusterID: remoteCluster, Selection: sel, Workloads: []value.ObservedWorkload{unselected}}, workloadEvidence(now)); len(g) != 0 {
		t.Fatal("workload outside the selector granted")
	}
}

type workloadReaderFixture struct {
	list  value.WorkloadList
	err   error
	proof value.NamespaceGuardProof
}

func (f *workloadReaderFixture) RemoteWorkloads(_ context.Context, cluster string, sel value.WorkloadSelection) (value.WorkloadList, error) {
	l := f.list
	l.ClusterID, l.Selection = cluster, sel
	return l, f.err
}
func (f *workloadReaderFixture) WorkloadGuard(context.Context, string) (value.NamespaceGuardProof, error) {
	return f.proof, f.err
}

// The reconciler accepts one workload-scoped basis per granted workload with
// its journal version, and records the minimized observation.
func TestReconcilerInheritsWorkloadJournal(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	now := s.r.Now()
	r := &workloadReaderFixture{list: value.WorkloadList{Journal: "j", ObservedAt: now, Workloads: []value.ObservedWorkload{observedWorkload("api", "a", "shared", "j:3", "payments")}},
		proof: *workloadEvidence(now).WorkloadGuard}
	s.r.Workloads, s.r.WorkloadGuards, s.sources = r, r, []value.Source{workloadSource()}
	s.refreshWorkloads(ctx)
	s.refreshEvidence(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	b := f.accepted[len(f.accepted)-1]
	var found bool
	for _, p := range b.Bases {
		if p.Resource.Kind == "PermissionSource" {
			found = p.Scope.ClusterID == remoteCluster && len(p.Scope.Workloads) == 1 && p.Scope.Workloads[0].UID == "a" && p.ObservationVersion == "j:3" && !p.Continuous
		}
	}
	if !found || len(b.Workloads) != 1 || b.Workloads[0].Workloads[0].ResourceVersion != "" || b.Validate(s.r.Now()) != nil {
		t.Fatalf("workload basis not accepted: %+v", b)
	}
	s.workloadGuards = nil
	r.err = errors.New("guard lost")
	s.refreshEvidence(ctx)
	if err := s.accept(ctx, false); err != nil {
		t.Fatal(err)
	}
	if b := f.accepted[len(f.accepted)-1]; !slices.Equal(b.UnavailableSources, []string{"source"}) {
		t.Fatalf("lost workload guard still granted: %+v", b)
	}
}

type workloadObserverFixture struct {
	mu     sync.Mutex
	items  map[string][]value.ObservedWorkload
	events map[string][]WorkloadEvent
}

func (f *workloadObserverFixture) ListWorkloads(_ context.Context, kind string, _ value.WorkloadSelection) (string, []value.ObservedWorkload, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return "1", slices.Clone(f.items[kind]), nil
}
func (f *workloadObserverFixture) WatchWorkloads(_ context.Context, kind, _ string, _ value.WorkloadSelection) (WorkloadWatch, error) {
	return &workloadWatchFixture{f: f, kind: kind}, nil
}
func (f *workloadObserverFixture) NamespaceUIDs(context.Context) (map[string]string, error) {
	return map[string]string{"shared": "shared-uid"}, nil
}

type workloadWatchFixture struct {
	f    *workloadObserverFixture
	kind string
}

func (w *workloadWatchFixture) Close() {}
func (w *workloadWatchFixture) Next(ctx context.Context) (WorkloadEvent, error) {
	w.f.mu.Lock()
	if e := w.f.events[w.kind]; len(e) > 0 {
		w.f.events[w.kind] = e[1:]
		w.f.mu.Unlock()
		return e[0], nil
	}
	w.f.mu.Unlock()
	select {
	case <-ctx.Done():
		return WorkloadEvent{}, ctx.Err()
	case <-time.After(50 * time.Millisecond):
		return WorkloadEvent{}, io.EOF
	}
}

// The connector workload journal keeps a workload's version across
// unrelated writes and changes it with A -> B -> A; namespaces resolve.
func TestWorkloadJournalServiceVersions(t *testing.T) {
	sel := WorkloadSelectionOf(workloadSource())
	api := func(rv, owner string) *value.ObservedWorkload {
		w := observedWorkload("api", "a", "shared", rv, owner)
		w.Namespace.UID = ""
		return &w
	}
	f := &workloadObserverFixture{items: map[string][]value.ObservedWorkload{"Deployment": {*api("1", "payments")}}, events: map[string][]WorkloadEvent{}}
	s := &WorkloadJournalService{Observer: f, Now: time.Now}
	defer s.Close()
	read := func() WorkloadJournalSnapshot {
		t.Helper()
		for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if v, err := s.Snapshot(context.Background(), sel); err == nil {
				return v
			}
		}
		t.Fatal("journal never available")
		return WorkloadJournalSnapshot{}
	}
	first := read()
	if len(first.Workloads) != 1 || first.Workloads[0].Namespace.UID != "shared-uid" || first.Workloads[0].ResourceVersion != first.Journal+":1" {
		t.Fatalf("first snapshot %+v", first)
	}
	f.mu.Lock()
	f.events["Deployment"] = []WorkloadEvent{{Type: "MODIFIED", ResourceVersion: "2", Workload: api("2", "payments")}}
	f.mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	if v := read(); v.Journal != first.Journal || v.Workloads[0].ResourceVersion != first.Workloads[0].ResourceVersion {
		t.Fatalf("unrelated write changed the version: %+v", v)
	}
	f.mu.Lock()
	f.events["Deployment"] = []WorkloadEvent{{Type: "MODIFIED", ResourceVersion: "3", Workload: api("3", "other")}, {Type: "MODIFIED", ResourceVersion: "4", Workload: api("4", "payments")}}
	f.mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	if v := read(); v.Journal != first.Journal || v.Workloads[0].ResourceVersion != first.Journal+":3" {
		t.Fatalf("A -> B -> A kept the version: %+v", v)
	}
}
