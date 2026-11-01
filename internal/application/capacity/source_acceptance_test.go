package capacity

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
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

func TestOngoingResourcesRequireOriginalAcceptedCurrentBudget(t *testing.T) {
	a, _, _, _, _, now := enrollmentObservationFacts()
	name := a.Observation.Snapshot.Policies[0].Resource.Name
	if limits, err := a.CurrentSourceResources(now, name); err != nil || limits != (SourceResourceLimits{}) {
		t.Fatal("absent optional lowering limits changed old accepted source", limits, err)
	}
	want := SourceResourceLimits{Node: collector.PolicyLimits{RingBytes: 64 << 20, FrozenBytes: 32 << 20, SourceLimits: collector.SourceLimits{MaxActiveSources: 4, InputBytesPerSecond: 2 << 20, InputBurstBytes: 1 << 20}}, Workload: collector.SourceLimits{MaxActiveSources: 2}}
	a.Observation.Snapshot.Policies[0].SourceResources = &want
	// A caller editing decoded desired values cannot use the old accepted digest.
	if _, err := a.CurrentSourceResources(now, name); err == nil {
		t.Fatal("unaccepted DTO edit passed")
	}
	a.Observation = sourceObservationFixture(a.Observation.Snapshot)
	got, err := a.CurrentSourceResources(now, name)
	if err != nil || got != want {
		t.Fatal("accepted limits lost", got, err)
	}
	got.Node.MaxActiveSources = 999
	if next, err := a.CurrentSourceResources(now, name); err != nil || next != want {
		t.Fatal("returned value aliases accepted source")
	}
	for _, check := range []struct {
		at   time.Time
		name string
	}{{a.FreshUntil, name}, {now, "foreign-policy"}} {
		if _, err := a.CurrentSourceResources(check.at, check.name); err == nil {
			t.Fatal("expired or foreign policy accepted")
		}
	}
	a.Revision = 0
	if _, err := a.CurrentSourceResources(now, name); err == nil {
		t.Fatal("unaccepted observation supplied limits")
	}
}

func TestSourceResourcesDoNotChangeStoredProjection(t *testing.T) {
	s, _, _ := capacitySelectionFixture()
	name := s.Pools[0].Resource.Name
	before, _, err := CanonicalProtectedPoolPlan(s, name)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := SelectedCapacitySourceDigest(s, name)
	if err != nil {
		t.Fatal(err)
	}
	complete := sourceObservationFixture(s)
	s.Policies[0].SourceResources = &SourceResourceLimits{Node: collector.PolicyLimits{SourceLimits: collector.SourceLimits{MaxActiveSources: 4}, RingBytes: 64 << 20}}
	after, _, err := CanonicalProtectedPoolPlan(s, name)
	if err != nil {
		t.Fatal(err)
	}
	next, err := SelectedCapacitySourceDigest(s, name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || selected != next {
		t.Fatal("resource-only enrichment changed existing storage projection")
	}
	if sourceObservationFixture(s).Digest == complete.Digest {
		t.Fatal("complete accepted source omitted resource caps")
	}
}
