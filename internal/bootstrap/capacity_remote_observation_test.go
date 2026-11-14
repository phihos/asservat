package bootstrap

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clusterobservation"
)

func capacityRemoteBoundaryFixture(t *testing.T, workload bool) (fleet.ClusterObservationRequest, fleet.ClusterObservationResult, time.Time) {
	t.Helper()
	n := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	r := fleet.ClusterObservationRequest{ID: "00000000-0000-4000-8000-000000000001", Challenge: "00000000-0000-4000-8000-000000000002", RootID: "00000000-0000-4000-8000-000000000003", ClusterID: "00000000-0000-4000-8000-000000000004", Purpose: fleet.ObserveCapacityNamespaceGuard, RequestedAt: n, NotAfter: n.Add(5 * time.Second)}
	if workload {
		r.Purpose = fleet.ObserveCapacityWorkload
		r.Namespace = cfg.NamespaceRef{Name: "workloads", UID: "original-namespace"}
		r.Workload = cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "original-workload"}
		r.Keys = []string{"team"}
	}
	digest, err := clusterobservation.RequestDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	child := fleet.ClusterObservationInterval{ObservedAt: n.Add(-time.Second), FreshUntil: n.Add(4 * time.Second)}
	v := fleet.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: digest, Interval: fleet.ClusterObservationInterval{ObservedAt: n, FreshUntil: n.Add(3 * time.Second)}}
	if workload {
		v.Workload = &fleet.ClusterExactWorkloadObservation{Namespace: r.Namespace, NamespaceResourceVersion: "10", Labels: map[string]string{"team": "original"}, NamespaceInterval: child, Workload: r.Workload, WorkloadResourceVersion: "11", Interval: child}
	} else {
		v.Guard = &fleet.ClusterNamespaceGuardObservation{Digest: artifact.Digest{1}, Keys: []string{"team"}, Interval: child}
	}
	return r, v, n.Add(time.Second)
}
