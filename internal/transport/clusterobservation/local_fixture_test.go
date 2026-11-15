package clusterobservation

import (
	"fmt"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

func localID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func localRequest() fleet.ClusterObservationRequest {
	now := time.Now().UTC()
	return fleet.ClusterObservationRequest{ID: localID(10), Challenge: localID(11), RootID: localID(1), ClusterID: localID(12), Purpose: fleet.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}
}

func localResult(r fleet.ClusterObservationRequest) fleet.ClusterObservationResult {
	d, _ := RequestDigest(r)
	return fleet.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: d, Interval: fleet.ClusterObservationInterval{ObservedAt: time.Now().UTC(), FreshUntil: r.NotAfter}, Namespaces: &fleet.ClusterNamespaceCandidatePage{ResourceVersion: "10", Items: []cfg.NamespaceRef{}}}
}
