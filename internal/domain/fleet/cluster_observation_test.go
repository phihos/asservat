package fleet

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func clusterObservationFixture() (ClusterObservationRequest, ClusterObservationResult, time.Time) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	r := ClusterObservationRequest{ID: "00000000-0000-4000-8000-000000000001", Challenge: "00000000-0000-4000-8000-000000000002", RootID: "00000000-0000-4000-8000-000000000003", ClusterID: "00000000-0000-4000-8000-000000000004", Purpose: ObserveCapacityWorkload, RequestedAt: now, NotAfter: now.Add(4 * time.Second), Namespace: cfg.NamespaceRef{Name: "team", UID: "namespace-original"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "application", UID: "workload-original"}, Keys: []string{"team"}}
	interval := ClusterObservationInterval{now, now.Add(3 * time.Second)}
	v := ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: artifact.Digest{1}, Interval: interval, Workload: &ClusterExactWorkloadObservation{Namespace: r.Namespace, NamespaceResourceVersion: "100", Labels: map[string]string{"team": ""}, NamespaceInterval: interval, Workload: r.Workload, WorkloadResourceVersion: "101", Interval: interval}}
	return r, v, now
}

func TestClusterObservationPreservesExactSelectionAndOriginalInterval(t *testing.T) {
	r, v, now := clusterObservationFixture()
	if !v.Matches(r, artifact.Digest{1}, now) {
		t.Fatal("valid exact observation denied")
	}
	for name, mutate := range map[string]func(*ClusterObservationResult){
		"request":            func(v *ClusterObservationResult) { v.RequestID = r.Challenge },
		"challenge":          func(v *ClusterObservationResult) { v.Challenge = r.ID },
		"cluster":            func(v *ClusterObservationResult) { v.ClusterID = r.RootID },
		"purpose":            func(v *ClusterObservationResult) { v.Purpose = ObserveCapacityNamespaces },
		"digest":             func(v *ClusterObservationResult) { v.RequestDigest = artifact.Digest{2} },
		"namespace-replaced": func(v *ClusterObservationResult) { v.Workload.Namespace.UID = "replacement" },
		"workload-replaced":  func(v *ClusterObservationResult) { v.Workload.Workload.UID = "replacement" },
		"unrequested-label":  func(v *ClusterObservationResult) { v.Workload.Labels["other"] = "secret" },
		"missing-label-set":  func(v *ClusterObservationResult) { v.Workload.Labels = nil },
		"union":              func(v *ClusterObservationResult) { v.Namespaces = &ClusterNamespaceCandidatePage{} },
		"future":             func(v *ClusterObservationResult) { v.Interval.ObservedAt = now.Add(time.Nanosecond) },
		"renew-on-receipt":   func(v *ClusterObservationResult) { v.Interval.FreshUntil = now.Add(4 * time.Second) },
		"short-child":        func(v *ClusterObservationResult) { v.Workload.NamespaceInterval.FreshUntil = now.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			request, out, n := clusterObservationFixture()
			mutate(&out)
			if out.Matches(request, artifact.Digest{1}, n) {
				t.Fatal("contrary observation accepted")
			}
		})
	}
	if v.Matches(r, artifact.Digest{1}, now.Add(3*time.Second)) {
		t.Fatal("expired original observation accepted")
	}
	// An already-current local observation may predate the new challenge. Its
	// original end remains binding; the response cannot restart that interval.
	v.Workload.NamespaceInterval = ClusterObservationInterval{now.Add(-time.Second), now.Add(2 * time.Second)}
	// The dependent workload keeps that same original namespace cutoff.
	v.Workload.Interval.FreshUntil = now.Add(2 * time.Second)
	v.Interval.FreshUntil = now.Add(2 * time.Second)
	if !v.Matches(r, artifact.Digest{1}, now) {
		t.Fatal("unchanged original current observation denied")
	}
	v.Interval.FreshUntil = now.Add(3 * time.Second)
	if v.Matches(r, artifact.Digest{1}, now) {
		t.Fatal("older child's interval renewed")
	}
}

func TestClusterObservationRequestCannotSelectAnotherPurposeOrUnboundedRead(t *testing.T) {
	r, _, now := clusterObservationFixture()
	for name, change := range map[string]func(*ClusterObservationRequest){
		"secret":            func(r *ClusterObservationRequest) { r.Workload.Kind = "Secret" },
		"arbitrary-purpose": func(r *ClusterObservationRequest) { r.Purpose = "kubernetes-get" },
		"empty-keys":        func(r *ClusterObservationRequest) { r.Keys = nil },
		"duplicate-keys":    func(r *ClusterObservationRequest) { r.Keys = append(r.Keys, r.Keys[0]) },
		"extra-cursor":      func(r *ClusterObservationRequest) { r.Continue = "page" },
		"extra-kind":        func(r *ClusterObservationRequest) { r.Kind = "Deployment" },
		"renewed-bound":     func(r *ClusterObservationRequest) { r.NotAfter = now.Add(5*time.Second + time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r.Clone()
			change(&candidate)
			if candidate.Valid(now) {
				t.Fatal("unsupported or unbounded request accepted")
			}
		})
	}
	r.Purpose = ObserveCapacityNamespaces
	r.Namespace = cfg.NamespaceRef{}
	r.Workload = cfg.WorkloadRef{}
	r.Keys = nil
	if !r.Valid(now) {
		t.Fatal("candidate discovery denied")
	}
	v := ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: artifact.Digest{1}, Interval: ClusterObservationInterval{now, now.Add(time.Second)}, Namespaces: &ClusterNamespaceCandidatePage{ResourceVersion: "100", Items: []cfg.NamespaceRef{}}}
	if !v.Matches(r, artifact.Digest{1}, now) {
		t.Fatal("successful empty candidate page denied")
	}
	v.Namespaces.Items = nil
	if v.Matches(r, artifact.Digest{1}, now) {
		t.Fatal("missing page interpreted as empty success")
	}
}

// ADR-197: the guarded workload carries exactly its guard and its workload;
// the guard's keys must be the requested keys, and both intervals bound it.
func TestClusterObservationGuardedWorkloadCarriesGuardAndWorkload(t *testing.T) {
	fixture := func() (ClusterObservationRequest, ClusterObservationResult, time.Time) {
		r, v, now := clusterObservationFixture()
		r.Purpose, v.Purpose = ObserveCapacityGuardedWorkload, ObserveCapacityGuardedWorkload
		v.Guard = &ClusterNamespaceGuardObservation{Digest: artifact.Digest{7}, Keys: []string{"team"}, Interval: v.Interval}
		return r, v, now
	}
	r, v, now := fixture()
	if !r.Valid(now) || !v.Matches(r, artifact.Digest{1}, now) {
		t.Fatal("valid guarded workload denied")
	}
	for name, mutate := range map[string]func(*ClusterObservationResult){
		"no-guard":      func(v *ClusterObservationResult) { v.Guard = nil },
		"no-workload":   func(v *ClusterObservationResult) { v.Workload = nil },
		"other-keys":    func(v *ClusterObservationResult) { v.Guard.Keys = []string{"other"} },
		"empty-digest":  func(v *ClusterObservationResult) { v.Guard.Digest = artifact.Digest{} },
		"short-guard":   func(v *ClusterObservationResult) { v.Guard.Interval.FreshUntil = now.Add(time.Second) },
		"third-member":  func(v *ClusterObservationResult) { v.Namespaces = &ClusterNamespaceCandidatePage{} },
		"plain-purpose": func(v *ClusterObservationResult) { v.Purpose = ObserveCapacityWorkload },
	} {
		t.Run(name, func(t *testing.T) {
			request, out, n := fixture()
			mutate(&out)
			if out.Matches(request, artifact.Digest{1}, n) {
				t.Fatal("contrary guarded observation accepted")
			}
		})
	}
	// A plain workload request never accepts the extra guard member.
	plain, single, n := clusterObservationFixture()
	single.Guard = v.Guard
	if single.Matches(plain, artifact.Digest{1}, n) {
		t.Fatal("plain workload accepted a guard member")
	}
}
