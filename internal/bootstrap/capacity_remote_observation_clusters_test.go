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
