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

func TestCapacityRemoteConversionPreservesChildOriginalStartAndEarliestEnd(t *testing.T) {
	for _, workload := range []bool{false, true} {
		r, v, n := capacityRemoteBoundaryFixture(t, workload)
		until := n.Add(time.Second)
		out, err := capacityCheckedObservation(r, v, until, n)
		if err != nil || !out.Interval.FreshUntil.Equal(until) || out.Interval.ObservedAt != v.Interval.ObservedAt {
			t.Fatal("bounded original envelope rejected or rewritten", err)
		}
		if workload {
			if out.Workload.NamespaceInterval.ObservedAt != v.Workload.NamespaceInterval.ObservedAt || out.Workload.Interval.ObservedAt != v.Workload.Interval.ObservedAt || out.Workload.NamespaceInterval.FreshUntil != until || out.Workload.Interval.FreshUntil != until {
				t.Fatal("workload child escaped caller bound")
			}
			out.Workload.Labels["team"] = "mutated"
			if v.Workload.Labels["team"] != "original" || v.Workload.Interval.FreshUntil == until {
				t.Fatal("conversion retained mutable original source")
			}
		} else {
			if out.Guard.Interval.ObservedAt != v.Guard.Interval.ObservedAt || out.Guard.Interval.FreshUntil != until {
				t.Fatal("guard child escaped caller bound")
			}
			out.Guard.Keys[0] = "mutated"
			if v.Guard.Keys[0] != "team" || v.Guard.Interval.FreshUntil == until {
				t.Fatal("conversion retained mutable original guard")
			}
		}
	}
}

func TestCapacityRemoteConversionRejectsChangedUnknownAndExpiredResponses(t *testing.T) {
	for _, name := range []string{"challenge", "target", "digest", "expired-caller", "expired-child", "extended-envelope", "unknown-union", "missing-result"} {
		t.Run(name, func(t *testing.T) {
			r, v, n := capacityRemoteBoundaryFixture(t, true)
			until := n.Add(time.Second)
			switch name {
			case "challenge":
				v.Challenge = "00000000-0000-4000-8000-000000000099"
			case "target":
				v.Workload.Workload.UID = "changed"
			case "digest":
				v.RequestDigest = artifact.Digest{2}
			case "expired-caller":
				until = n
			case "expired-child":
				v.Workload.Interval.FreshUntil = n
			case "extended-envelope":
				v.Interval.FreshUntil = r.NotAfter.Add(time.Microsecond)
			case "unknown-union":
				v.Guard = &fleet.ClusterNamespaceGuardObservation{}
			case "missing-result":
				v = fleet.ClusterObservationResult{}
			}
			out, err := capacityCheckedObservation(r, v, until, n)
			if err == nil || out.Workload != nil || out.Guard != nil {
				t.Fatal("unknown or changed result became a current capacity observation")
			}
		})
	}
}
