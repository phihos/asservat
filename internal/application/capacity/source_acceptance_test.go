package capacity

import (
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func sourceObservationFixture(s CapacitySnapshot) CapacitySourceObservation {
	v := make([]CapacitySourceVersion, 0, len(s.Pools)+len(s.Policies))
	for _, p := range s.Pools {
		v = append(v, sourceVersion(p.Resource, p.Resource.SpecDigest))
	}
	for _, p := range s.Policies {
		v = append(v, sourceVersion(p.Resource, p.Resource.SpecDigest))
	}
	d, e := CapacitySourceDigest(s, v)
	if e != nil {
		panic(e)
	}
	return CapacitySourceObservation{Snapshot: s, Versions: v, Digest: d}
}
func TestCapacitySourceCanonicalMembershipAndInvalidation(t *testing.T) {
	s, _, now := capacitySelectionFixture()
	o := sourceObservationFixture(s)
	if !o.Valid(now) {
		t.Fatal("valid complete source rejected")
	}
	o.Versions = slices.Clone(o.Versions)
	slices.Reverse(o.Versions)
	if !o.Valid(now) {
		t.Fatal("LIST order changed semantic source")
	}
	o.Snapshot.PoolResourceVersion = "new-list"
	o.Snapshot.PolicyResourceVersion = "different-list"
	o.Snapshot.Pools[0].Resource.ResourceVersion = "status-only"
	if !o.Valid(now) {
		t.Fatal("opaque LIST or status version changed semantic source")
	}
	for _, change := range []func(*CapacitySourceObservation){
		func(v *CapacitySourceObservation) { v.Versions = v.Versions[:1] },
		func(v *CapacitySourceObservation) { v.Versions[1] = v.Versions[0] },
		func(v *CapacitySourceObservation) { v.Versions[0].Generation++ },
		func(v *CapacitySourceObservation) { v.Versions[0].Spec[0]++ },
		func(v *CapacitySourceObservation) { v.Digest = artifact.Digest{} },
	} {
		x := o
		x.Versions = slices.Clone(o.Versions)
		change(&x)
		if x.Valid(now) {
			t.Fatal("changed membership or desired bytes accepted")
		}
	}
	// A raw invalidating spec is retained independently of the typed nil budget.
	o.Snapshot.Pools[0].Resource.SpecDigest = artifact.Digest{}
	o.Snapshot.Pools[0].Budget = nil
	for i := range o.Versions {
		if o.Versions[i].Kind == "EvidenceStoragePool" {
			o.Versions[i].Spec[0]++
		}
	}
	d, e := CapacitySourceDigest(o.Snapshot, o.Versions)
	if e != nil || d == o.Digest {
		t.Fatalf("invalidating desired change disappeared: %v", e)
	}
}
func TestCapacitySelectedDigestExcludesUnrelatedButKeepsSharedCommitments(t *testing.T) {
	s, _, _ := capacitySelectionFixture()
	first, e := SelectedCapacitySourceDigest(s, "pool")
	if e != nil {
		t.Fatal(e)
	}
	other := s.Pools[0]
	other.Resource.Name, other.Resource.UID = "foreign", "foreign-uid"
	other.Budget = nil
	other.Resource.SpecDigest = artifact.Digest{}
	s.Pools = append(s.Pools, other)
	got, e := SelectedCapacitySourceDigest(s, "pool")
	if e != nil || got != first {
		t.Fatal("unrelated malformed pool changed retained plan")
	}
	s.Policies[0].Resource.Generation++
	s.Policies[0].Resource.SpecDigest[0]++
	got, e = SelectedCapacitySourceDigest(s, "pool")
	if e != nil || got == first {
		t.Fatal("assigned policy change omitted")
	}
	s.Policies[0].Budget = nil
	if _, e = SelectedCapacitySourceDigest(s, "pool"); e == nil {
		t.Fatal("invalid shared commitment accepted")
	}
}
func TestCapacitySourceDigestBindsTheDecodedBudgetUsedBySQL(t *testing.T) {
	s, _, now := capacitySelectionFixture()
	o := sourceObservationFixture(s)
	// A consumer must not be able to change the compiled quantities while
	// retaining the raw-spec digest from an earlier concrete source read.
	o.Snapshot.Policies[0].Budget.NamespaceAccounts++
	if o.Valid(now) {
		t.Fatal("changed decoded budget retained accepted digest")
	}
}

func enrollmentObservationFacts() (AcceptedCapacitySource, CapacityNamespaceProtection, CapacityWorkloadObservation, AcceptedCapacityPermissions, EnrollmentObservation, time.Time) {
	s, ns, now := capacitySelectionFixture()
	prior, _ := enrollmentFixture(now)
	prior.Key.ClusterID = capacityTestCluster
	prior.Key.NamespaceUID = ns.Namespace.UID
	o := sourceObservationFixture(s)
	a := AcceptedCapacitySource{Format: CapacityAcceptedSourceFormat, RootID: prior.Key.RootID, InstallationID: prior.Recovery.InstallationID, QualificationID: prior.Recovery.InstallationID, Revision: 1, QualificationDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{5}, Observation: o, ObservedAt: now, FreshUntil: s.FreshUntil}
	g := CapacityNamespaceProtection{ClusterID: capacityTestCluster, Digest: artifact.Digest{6}, Keys: []string{"team"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	w := CapacityWorkloadObservation{Namespace: ns, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: prior.Key.WorkloadUID}, WorkloadResourceVersion: "workload-rv", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	p := AcceptedCapacityPermissions{RootID: prior.Key.RootID, Epoch: prior.PermissionEpoch, Sequence: prior.PermissionSequence, TrustDigest: prior.PermissionTrust, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Scopes: []AcceptedCapacityScope{{BasisKey: "accepted-basis", BasisUID: "basis-uid", ClusterID: capacityTestCluster, NamespaceUID: ns.Namespace.UID, ScopeDigest: artifact.Digest{7}}}}
	return a, g, w, p, prior, now
}
func TestCapacityEnrollmentCompositionPreservesEveryOriginalBound(t *testing.T) {
	for _, phase := range []string{"source", "namespace-guard", "namespace", "workload", "permissions", "recovery"} {
		t.Run(phase, func(t *testing.T) {
			a, g, w, p, prior, now := enrollmentObservationFacts()
			end := now.Add(21 * time.Millisecond)
			switch phase {
			case "source":
				a.FreshUntil = end
			case "namespace-guard":
				g.FreshUntil = end
			case "namespace":
				w.Namespace.FreshUntil = end
				w.FreshUntil = end
			case "workload":
				w.FreshUntil = end
			case "permissions":
				p.FreshUntil = end
			case "recovery":
				prior.Recovery.FreshUntil = end
			}
			o, _, e := ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", now)
			if e != nil || !o.FreshUntil.Equal(end) {
				t.Fatalf("original %s deadline lost: %v", phase, e)
			}
			if _, _, e = ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", end); e == nil {
				t.Fatal("expired phase renewed by other current observations")
			}
		})
	}
}
func TestCapacityEnrollmentHeartbeatCannotRefreshWorkloadOrPermission(t *testing.T) {
	a, g, w, p, prior, now := enrollmentObservationFacts()
	if _, _, e := ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", now); e != nil {
		t.Fatal(e)
	}
	w.Workload.UID = "replacement"
	p.Scopes[0].WorkloadUIDs = []string{prior.Key.WorkloadUID}
	if _, _, e := ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", now); e == nil {
		t.Fatal("old accepted exact-workload scope covered replacement")
	}
	w.Workload.UID = prior.Key.WorkloadUID
	p.Scopes[0].NamespaceUID = "other"
	if _, _, e := ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", now); e == nil {
		t.Fatal("foreign namespace enrollment accepted")
	}
	p.Scopes[0].NamespaceUID = w.Namespace.Namespace.UID
	w.ObservedAt = now.Add(-6 * time.Second)
	w.FreshUntil = now.Add(-time.Second)
	a.Revision++
	if _, _, e := ComposeEnrollmentObservation(a, g, w, p, prior.Recovery, "original", now); e == nil {
		t.Fatal("new source sequence refreshed old workload observation")
	}
}
