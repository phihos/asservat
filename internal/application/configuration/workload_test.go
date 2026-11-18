package configuration

import (
	"context"
	"slices"
	"testing"

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

// REQ-PER-005 / ADR-247: one basis per workload of the selection.
func TestWorkloadGrantsRequireSelection(t *testing.T) {
	src := workloadSource()
	sel := WorkloadSelectionOf(src)
	if !slices.Equal(sel.Keys.Labels, []string{"managed"}) || !slices.Equal(sel.Keys.Annotations, []string{"owner"}) {
		t.Fatalf("selection keys %+v", sel)
	}
	o := &value.WorkloadObservation{ClusterID: remoteCluster, Selection: sel, Workloads: []value.ObservedWorkload{
		observedWorkload("api", "a", "shared", "j:0", "payments"), observedWorkload("web", "b", "shared", "j:0", "other"), observedWorkload("job", "c", "excluded", "j:0", "payments")}}
	src.ExcludedNamespaces = []string{"excluded"}
	grants, reason := WorkloadGrants(src, o)
	if reason != "" || len(grants) != 1 || grants[0].Workload != (value.WorkloadRef{Kind: "Deployment", Name: "api", UID: "a"}) || grants[0].Namespace.UID != "shared-uid" {
		t.Fatalf("workload grants %q %+v", reason, grants)
	}
	b := WorkloadBasis(src, grants[0])
	other := WorkloadBasis(src, value.WorkloadGrant{Namespace: grants[0].Namespace, Workload: value.WorkloadRef{Kind: "Deployment", Name: "x", UID: "x"}, ResourceVersion: "j:0", Subjects: grants[0].Subjects})
	if len(b.Scope.Workloads) != 1 || b.Key() == other.Key() {
		t.Fatal("workload bases share a key or lack their workload scope")
	}
	for name, c := range map[string]struct {
		mutate func(*value.Source)
		reason string
	}{
		"admin managed":   {func(s *value.Source) { s.Protection.Mode = "administratorManaged" }, value.SourceUnsupported},
		"namespace scope": {func(s *value.Source) { s.NamespaceSelector = map[string]string{"x": "y"} }, value.SourceUnsupported},
		"other selection": {func(s *value.Source) { s.WorkloadSelector = map[string]string{"managed": "no"} }, value.MetadataNotObserved},
		"no selector":     {func(s *value.Source) { s.WorkloadSelector = nil }, value.SourceUnsupported},
		"no values":       {func(s *value.Source) { s.Mapping.Values = nil }, value.SourceUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			s := workloadSource()
			c.mutate(&s)
			if g, r := WorkloadGrants(s, o); len(g) != 0 || r != c.reason {
				t.Fatalf("got %q %+v", r, g)
			}
		})
	}
	// A pod label or a workload outside the selector value never grants.
	unselected := observedWorkload("spoof", "d", "shared", "j:0", "payments")
	unselected.Labels["managed"] = ValueDigest("false")
	if g, _ := WorkloadGrants(src, &value.WorkloadObservation{ClusterID: remoteCluster, Selection: sel, Workloads: []value.ObservedWorkload{unselected}}); len(g) != 0 {
		t.Fatal("workload outside the selector granted")
	}
}

type workloadReaderFixture struct {
	list value.WorkloadList
	err  error
}

func (f *workloadReaderFixture) RemoteWorkloads(_ context.Context, cluster string, sel value.WorkloadSelection) (value.WorkloadList, error) {
	l := f.list
	l.ClusterID, l.Selection = cluster, sel
	return l, f.err
}

// The reconciler accepts one workload-scoped basis per granted workload with
// its journal version, and records the minimized observation.
func TestReconcilerInheritsWorkloadJournal(t *testing.T) {
	f, _, s, ctx := inheritanceRun(t)
	now := s.r.Now()
	r := &workloadReaderFixture{list: value.WorkloadList{Journal: "j", ObservedAt: now, Workloads: []value.ObservedWorkload{observedWorkload("api", "a", "shared", "j:3", "payments")}}}
	s.r.Workloads, s.sources = r, []value.Source{workloadSource()}
	s.refreshWorkloads(ctx)
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
}
