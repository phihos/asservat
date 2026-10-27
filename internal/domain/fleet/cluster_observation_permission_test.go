package fleet

import (
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ADR-247: a permission namespace page carries only requested keys, journal
// versions of its own journal and items in UID order.
func TestClusterObservationPermissionNamespacePage(t *testing.T) {
	r, _, now := clusterObservationFixture()
	r.Purpose, r.Namespace, r.Workload, r.Keys, r.AnnotationKeys = ObservePermissionNamespaces, cfg.NamespaceRef{}, cfg.WorkloadRef{}, []string{"team"}, []string{"owner"}
	if !r.Valid(now) {
		t.Fatal("permission namespace request denied")
	}
	const journal = "61000000-0000-4000-8000-0000000000aa"
	digest := strings.Repeat("a", 64)
	item := func(uid string) cfg.ObservedNamespace {
		return cfg.ObservedNamespace{Name: "ns-" + uid, UID: uid, ResourceVersion: journal + ":1", Labels: map[string]string{"team": digest}}
	}
	page := func(items ...cfg.ObservedNamespace) ClusterObservationResult {
		return ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: artifact.Digest{1}, Interval: ClusterObservationInterval{now, now.Add(time.Second)},
			PermissionNamespaces: &ClusterPermissionNamespacePage{Journal: journal, ObservedAt: now, Items: items}}
	}
	if !page(item("a"), item("b")).Matches(r, artifact.Digest{1}, now) {
		t.Fatal("valid page denied")
	}
	foreign := item("c")
	foreign.ResourceVersion = "other:1"
	unrequested := item("d")
	unrequested.Labels["other"] = digest
	for name, v := range map[string]ClusterObservationResult{"order": page(item("b"), item("a")), "foreign-version": page(foreign), "unrequested-key": page(unrequested)} {
		if v.Matches(r, artifact.Digest{1}, now) {
			t.Fatal("invalid page accepted", name)
		}
	}
	r.Namespace = cfg.NamespaceRef{Name: "x", UID: "y"}
	if r.Valid(now) {
		t.Fatal("permission namespace request selected a namespace")
	}
}

// ADR-247: a workload request names a selection whose selector keys are
// observed labels; a guard request names nothing.
func TestClusterObservationPermissionWorkloadRequests(t *testing.T) {
	r, _, now := clusterObservationFixture()
	r.Purpose, r.Namespace, r.Workload = ObservePermissionWorkloads, cfg.NamespaceRef{}, cfg.WorkloadRef{}
	r.Selector, r.Keys, r.AnnotationKeys = map[string]string{"team": "a"}, []string{"team"}, []string{"owner"}
	if !r.Valid(now) {
		t.Fatal("workload request denied")
	}
	unobserved := r.Clone()
	unobserved.Selector = map[string]string{"other": "a"}
	none := r.Clone()
	none.Selector = nil
	guard := r.Clone()
	guard.Purpose = ObservePermissionWorkloadGuard
	for name, x := range map[string]ClusterObservationRequest{"unobserved-selector": unobserved, "no-selector": none, "guard-with-selection": guard} {
		if x.Valid(now) {
			t.Fatal("invalid request accepted", name)
		}
	}
	guard.Selector, guard.Keys, guard.AnnotationKeys = nil, nil, nil
	if !guard.Valid(now) {
		t.Fatal("workload guard request denied")
	}
}
