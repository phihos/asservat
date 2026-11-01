package authorization

import "testing"

func TestWorkloadScopeCannotInventPodOrConsumePodReview(t *testing.T) {
	i, p, _, now := fixture()
	target := WorkloadTarget{p.Target.ClusterID, p.Target.NamespaceUID, p.Target.WorkloadUID}
	wp := WorkloadProjection{Target: target, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}
	if r := WorkloadScopeEligibility(i, wp, CollectContext, target, now); !r.Eligible {
		t.Fatal(r)
	}
	emptyPod := p.Target
	emptyPod.PodUID = ""
	if emptyPod.Valid() {
		t.Fatal("concrete target validation relaxed")
	}
	p.Target = emptyPod
	if r := ScopeEligibility(i, p, CollectContext, emptyPod, now); r.Eligible {
		t.Fatal("workload projection authorized concrete capture")
	}
	wp.Allows = append([]CurrentAssignment(nil), wp.Allows...)
	wp.Allows[0].Reviewed = true
	if r := WorkloadScopeEligibility(i, wp, CollectContext, target, now); r.Eligible {
		t.Fatal("one Pod's decision-time permission authorized future replicas")
	}
	wp.Allows[0].Reviewed = false
	wp.Denies = append([]CurrentAssignment(nil), wp.Allows...)
	if r := WorkloadScopeEligibility(i, wp, CollectContext, target, now); r.Eligible || r.Reason != "ExplicitDeny" {
		t.Fatal("whole-workload deny lost", r)
	}
}
