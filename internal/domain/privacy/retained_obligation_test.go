package privacy

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func obligationFixture() (RetainedArtifact, PolicySnapshot) {
	id := "11111111-1111-4111-8111-111111111111"
	anchor := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	reg := artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: anchor, WriteUntil: anchor.Add(time.Minute), ExpiresAt: anchor.Add(5 * time.Hour), DeleteBy: anchor.Add(6 * time.Hour)}
	r := RetainedArtifact{RootID: id, Registration: reg, OriginPolicies: []artifact.RetentionRule{{UID: "original", Generation: 1, Digest: artifact.Digest{1}}}, Input: Input{Target: authorization.Target{ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 18000, AnchorAt: anchor}, Effective: Deadlines{AnchorAt: anchor, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}}
	p := ScopedPolicy{Name: "baseline", Policy: Policy{Revision: identity.Revision{UID: "original", Generation: 2, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
	s := PolicySnapshot{SourceClusterID: id, ControlNamespaceUID: "control", Hub: true, Revision: identity.Revision{UID: "source", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: anchor, FreshUntil: anchor.Add(5 * time.Second), Policies: []ScopedPolicy{p}}
	return r, s
}
func TestHistoricalObligationAppliesExpiredSourceWithoutMakingAuthority(t *testing.T) {
	r, s := obligationFixture()
	if s.Valid(s.ObservedAt.Add(time.Hour)) {
		t.Fatal("fixture not expired")
	}
	policies, err := HistoricalSourcePolicies(s, r)
	if err != nil {
		t.Fatal(err)
	}
	d, refs, err := ApplyRetainedObligation(r, policies)
	if err != nil || !d.DeleteBy.Equal(r.Input.AnchorAt.Add(2*time.Hour)) || !d.ExpiresAt.Equal(d.DeleteBy.Add(-5*time.Minute)) || len(refs) != 1 || refs[0].Generation != 2 {
		t.Fatal("historical limit lost", d, refs, err)
	}
	r.Effective = d
	r.OriginPolicies = refs
	policies[0].MaximumSeconds = 86400
	policies[0].DefaultSeconds = 86400
	policies[0].Revision.Generation = 3
	again, _, err := ApplyRetainedObligation(r, policies)
	if err != nil || again != d {
		t.Fatal("relaxation extended retained dates", again, err)
	}
	policies[0].DeletionBudgetSeconds = 3 * 3600
	closed, _, err := ApplyRetainedObligation(r, policies)
	if err != nil || !closed.ExpiresAt.Equal(d.AnchorAt) || closed.DeleteBy != d.DeleteBy {
		t.Fatal("insufficient cleanup window left readable time", closed, err)
	}
}
func TestHistoricalSelectionRequiresKnownRelationships(t *testing.T) {
	for _, mode := range []string{"bound-label-moved", "new-label", "cluster-excluded", "local-other-cluster", "rollback", "same-generation-change", "empty"} {
		t.Run(mode, func(t *testing.T) {
			r, s := obligationFixture()
			wantCount := 1
			wantError := false
			switch mode {
			case "bound-label-moved":
				s.Policies[0].Scope.NamespaceLabels = map[string]string{"owner": "different"}
				s.Policies[0].Policy.Baseline = false
			case "new-label":
				s.Policies[0].Policy.Revision.UID = "new"
				s.Policies[0].Scope.NamespaceLabels = map[string]string{"owner": "team"}
				s.Policies[0].Policy.Baseline = false
				wantError = true
			case "cluster-excluded":
				s.Policies[0].Policy.Revision.UID = "new"
				s.Policies[0].Scope.ClusterIDs = []string{"22222222-2222-4222-8222-222222222222"}
				s.Policies[0].Scope.NamespaceLabels = map[string]string{"owner": "team"}
				s.Policies[0].Policy.Baseline = false
				wantCount = 0
			case "local-other-cluster":
				s.Hub = false
				s.SourceClusterID = "22222222-2222-4222-8222-222222222222"
				s.Policies[0].Policy.Baseline = false
				wantCount = 0
			case "rollback":
				r.OriginPolicies[0].Generation = 3
				wantError = true
			case "same-generation-change":
				s.Policies[0].Policy.Revision.Generation = 1
				wantError = true
			case "empty":
				s.Policies = nil
				wantCount = 0
			}
			p, err := HistoricalSourcePolicies(s, r)
			if wantError {
				if err == nil {
					t.Fatal("unknown source history accepted")
				}
				return
			}
			if err != nil || len(p) != wantCount {
				t.Fatal("wrong known scope", p, err)
			}
		})
	}
}
func TestHistoricalObligationDoesNotNeedAnAllowingPolicyIntersection(t *testing.T) {
	r, s := obligationFixture()
	p := s.Policies[0].Policy
	p.Baseline = false
	other := p
	other.Revision.UID = "additional"
	other.PurposeRef = "different-purpose"
	other.MaximumSeconds = 3600
	other.DeletionBudgetSeconds = 600
	d, _, err := ApplyRetainedObligation(r, []Policy{p, other})
	if err != nil || !d.DeleteBy.Equal(r.Input.AnchorAt.Add(time.Hour)) || !d.ExpiresAt.Equal(d.DeleteBy.Add(-10*time.Minute)) {
		t.Fatal("incompatible allows prevented restrictive cleanup", d, err)
	}
	unchanged, refs, err := ApplyRetainedObligation(r, nil)
	if err != nil || unchanged != r.Effective || len(refs) != 0 {
		t.Fatal("empty source rewrote old duty")
	}
}
