package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clusterobservation"
)

// capacityRegionView is one synthetic region's own namespace and workload.
type capacityRegionView struct {
	guard     artifact.Digest
	namespace cfg.NamespaceRef
	workload  cfg.WorkloadRef
}

type capacityRegionExchange func(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)

func (f capacityRegionExchange) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	return f(ctx, r)
}

// capacityRegionAnswer is region view's guarded answer to request r, labelled
// with the answering region's cluster.
func capacityRegionAnswer(t *testing.T, r fleet.ClusterObservationRequest, cluster string, v capacityRegionView) fleet.ClusterObservationResult {
	t.Helper()
	answered := r
	answered.ClusterID = cluster
	answered.Namespace, answered.Workload = v.namespace, v.workload
	digest, err := clusterobservation.RequestDigest(answered)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	child := fleet.ClusterObservationInterval{ObservedAt: r.RequestedAt, FreshUntil: r.NotAfter}
	return fleet.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: cluster, Purpose: r.Purpose, RequestDigest: digest,
		Interval: fleet.ClusterObservationInterval{ObservedAt: now, FreshUntil: r.NotAfter},
		Guard:    &fleet.ClusterNamespaceGuardObservation{Digest: v.guard, Keys: []string{"team"}, Interval: child},
		Workload: &fleet.ClusterExactWorkloadObservation{Namespace: v.namespace, NamespaceResourceVersion: "10", Labels: map[string]string{"team": "regional"}, NamespaceInterval: child, Workload: v.workload, WorkloadResourceVersion: "11", Interval: child}}
}

// Two joined regions use the same namespace and Deployment names with
// different UIDs, observed through one shared holder client (as installed).
// Each cluster's reader sends only its own cluster ID, accepts only that
// cluster's answer and labels the facts with it; an answer from the other
// region is refused rather than relabelled.
func TestCapacityRemoteObservationSameNamesKeepsEachClusterSeparate(t *testing.T) {
	root, a, b := observationForwardID(800), observationForwardID(801), observationForwardID(802)
	regions := map[string]capacityRegionView{
		a: {guard: artifact.Digest{1}, namespace: cfg.NamespaceRef{Name: "regional-apps", UID: "namespace-a"}, workload: cfg.WorkloadRef{Kind: "Deployment", Name: "regional-app", UID: "workload-a"}},
		b: {guard: artifact.Digest{2}, namespace: cfg.NamespaceRef{Name: "regional-apps", UID: "namespace-b"}, workload: cfg.WorkloadRef{Kind: "Deployment", Name: "regional-app", UID: "workload-b"}},
	}
	misroute := false
	asked := map[string]int{}
	shared := capacityRegionExchange(func(_ context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
		asked[r.ClusterID]++
		answering := r.ClusterID
		if misroute {
			answering = map[string]string{a: b, b: a}[r.ClusterID]
		}
		return capacityRegionAnswer(t, r, answering, regions[answering]), nil
	})
	readers := map[string]*capacityRemoteObservation{}
	for _, cluster := range []string{a, b} {
		read, err := newCapacityRemoteObservation(shared, root, cluster, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		readers[cluster] = read
	}
	ctx := context.Background()
	for _, cluster := range []string{a, b} {
		v := regions[cluster]
		guard, workload, err := readers[cluster].ReadCapacityGuardedWorkload(ctx, v.namespace, v.workload, []string{"team"})
		if err != nil {
			t.Fatal(cluster, err)
		}
		if guard.ClusterID != cluster || guard.Digest != v.guard || workload.Namespace.ClusterID != cluster || workload.Namespace.Namespace != v.namespace || workload.Workload != v.workload {
			t.Fatal("cluster facts mixed", cluster, guard, workload)
		}
	}
	if asked[a] != 1 || asked[b] != 1 {
		t.Fatal("request cluster not each reader's own", asked)
	}
	misroute = true
	for _, cluster := range []string{a, b} {
		v := regions[cluster]
		if _, _, err := readers[cluster].ReadCapacityGuardedWorkload(ctx, v.namespace, v.workload, []string{"team"}); err == nil {
			t.Fatal("another region's answer accepted for", cluster)
		}
	}
}
