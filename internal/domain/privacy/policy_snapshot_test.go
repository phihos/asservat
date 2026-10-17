package privacy

import (
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func retentionObservationFixture() ([]PolicySnapshot, SelectorFacts, time.Time) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cluster := "11111111-1111-4111-8111-111111111111"
	revision := identity.Revision{UID: "control", Generation: 1, Digest: artifact.Digest{1}}
	policy := ScopedPolicy{Name: "baseline", Policy: Policy{Revision: identity.Revision{UID: "baseline-uid", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
	snapshot := PolicySnapshot{SourceClusterID: cluster, ControlNamespaceUID: "hub-ns", Hub: true, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: []ScopedPolicy{policy}}
	facts := SelectorFacts{Target: authorization.Target{ClusterID: cluster, NamespaceUID: "namespace-uid", WorkloadUID: "workload-uid", PodUID: "pod-uid"}, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), NamespaceKeys: []string{"privacy.example.test/class"}, NamespaceLabels: map[string]string{"privacy.example.test/class": "user-data"}, WorkloadKeys: []string{"privacy.example.test/scope"}, WorkloadLabels: map[string]string{"privacy.example.test/scope": "internal"}}
	return []PolicySnapshot{snapshot}, facts, now
}
func TestRetentionMatchingIntersectsHubLocalAndProtectedSelectors(t *testing.T) {
	sources, f, now := retentionObservationFixture()
	narrow := sources[0].Policies[0]
	narrow.Name = "internal-user-data"
	narrow.Policy.Baseline = false
	narrow.Policy.Revision.UID = "narrow-uid"
	narrow.Policy.MaximumSeconds = 1800
	narrow.Scope = PolicyScope{ClusterIDs: []string{f.Target.ClusterID}, NamespaceLabels: map[string]string{"privacy.example.test/class": "user-data"}, WorkloadLabels: map[string]string{"privacy.example.test/scope": "internal"}}
	sources[0].Policies = append(sources[0].Policies, narrow)
	local := sources[0]
	local.Hub = false
	local.ControlNamespaceUID = "collector-ns"
	local.Policies = []ScopedPolicy{sources[0].Policies[0]}
	local.Policies[0].Name = "local"
	local.Policies[0].Policy.Revision.UID = "local-uid"
	local.Policies[0].Policy.Baseline = false
	local.Policies[0].Policy.MaximumSeconds = 1200
	sources = append(sources, local)
	matched, until, err := MatchPolicies(sources, f, now)
	if err != nil || len(matched) != 3 || !until.Equal(now.Add(5*time.Second)) {
		t.Fatal("matching intersection", len(matched), err)
	}
	set := PolicySet{Target: f.Target, Revision: f.Revision, ObservedAt: now, FreshUntil: until, Complete: true, Policies: matched}
	resolved, err := Resolve(set, Input{Target: f.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: now}, now)
	if err != nil || resolved.MaximumSeconds != 1200 || len(resolved.Policies) != 3 || !resolved.ExpiresAt.Equal(now.Add(900*time.Second)) {
		t.Fatal("weaker retention won", resolved, err)
	}
	// Namespace AND workload dimensions; values within cluster IDs are ORed.
	f.WorkloadLabels["privacy.example.test/scope"] = "external"
	matched, _, err = MatchPolicies(sources, f, now)
	if err != nil || len(matched) != 2 {
		t.Fatal("selector AND failed", err)
	}
}
func TestRetentionMatchingRejectsUnknownProvenanceAndIncompleteBaseline(t *testing.T) {
	for _, mode := range []string{"unprotected-namespace", "unprotected-workload", "stale-facts", "stale-source", "no-hub", "two-hubs", "no-baseline", "two-baselines", "wrong-local-cluster", "duplicate-source", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			sources, f, now := retentionObservationFixture()
			narrow := sources[0].Policies[0]
			narrow.Name = "narrow"
			narrow.Policy.Baseline = false
			narrow.Policy.Revision.UID = "narrow"
			narrow.Scope.NamespaceLabels = map[string]string{"privacy.example.test/class": "unmatched"}
			narrow.Scope.WorkloadLabels = map[string]string{"privacy.example.test/scope": "unmatched"}
			sources[0].Policies = append(sources[0].Policies, narrow)
			switch mode {
			case "unprotected-namespace":
				f.NamespaceKeys = nil
				f.NamespaceLabels = nil
			case "unprotected-workload":
				f.WorkloadKeys = nil
				f.WorkloadLabels = nil
			case "stale-facts":
				f.FreshUntil = now
			case "stale-source":
				sources[0].FreshUntil = now
			case "no-hub":
				sources[0].Hub = false
				sources[0].Policies[0].Policy.Baseline = false
			case "two-hubs":
				second := sources[0]
				second.ControlNamespaceUID = "other"
				sources = append(sources, second)
			case "no-baseline":
				sources[0].Policies = sources[0].Policies[1:]
			case "two-baselines":
				second := sources[0].Policies[0]
				second.Name = "second"
				second.Policy.Revision.UID = "second"
				sources[0].Policies = append(sources[0].Policies, second)
			case "wrong-local-cluster":
				second := sources[0]
				second.SourceClusterID = "22222222-2222-4222-8222-222222222222"
				second.Hub = false
				second.Policies = nil
				sources = append(sources, second)
			case "duplicate-source":
				sources = append(sources, sources[0])
			case "overflow":
				for i := 0; i < 64; i++ {
					p := sources[0].Policies[0]
					p.Name = fmt.Sprintf("p-%d", i)
					p.Policy.Revision.UID = p.Name
					p.Policy.Baseline = false
					p.Scope.ClusterIDs = []string{f.Target.ClusterID}
					sources[0].Policies = append(sources[0].Policies, p)
				}
			}
			if _, _, err := MatchPolicies(sources, f, now); err == nil {
				t.Fatal("incomplete provenance or policy overflow accepted")
			}
		})
	}
}
func TestRetentionMatchingAbsenceIsProtectedAndReturnedRulesAreCopied(t *testing.T) {
	sources, f, now := retentionObservationFixture()
	narrow := sources[0].Policies[0]
	narrow.Name = "narrow"
	narrow.Policy.Revision.UID = "narrow"
	narrow.Policy.Baseline = false
	narrow.Scope.NamespaceLabels = map[string]string{"privacy.example.test/class": "user-data"}
	sources[0].Policies = append(sources[0].Policies, narrow)
	f.NamespaceLabels = nil // Qualified absence, not a failed or partial metadata read.
	policies, _, err := MatchPolicies(sources, f, now)
	if err != nil || len(policies) != 1 {
		t.Fatal("qualified absent label failed", err)
	}
	sources[0].Policies[0].Policy.Rules = []Rule{{Name: "short", PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, MaxAgeSeconds: 1000}}
	policies, _, err = MatchPolicies(sources, f, now)
	if err != nil {
		t.Fatal(err)
	}
	sources[0].Policies[0].Policy.Rules[0].PrivacyClasses[0] = "verifiedNonPersonal"
	if policies[0].Rules[0].PrivacyClasses[0] != "potentialPersonalData" {
		t.Fatal("caller mutated matched rules")
	}
}

func TestRetainedPoliciesFollowOriginalUIDAfterLabelsChange(t *testing.T) {
	sources, f, now := retentionObservationFixture()
	narrow := sources[0].Policies[0]
	narrow.Name = "original-owner-scope"
	narrow.Policy.Baseline = false
	narrow.Policy.Revision.UID = "narrow-uid"
	narrow.Scope.NamespaceLabels = map[string]string{"privacy.example.test/class": "user-data"}
	original := artifact.RetentionRule{UID: narrow.Policy.Revision.UID, Generation: 1, Digest: artifact.Digest(narrow.Policy.Revision.Digest)}
	narrow.Policy.Revision.Generation = 2
	narrow.Policy.Revision.Digest[0]++
	narrow.Policy.MaximumSeconds = 600
	sources[0].Policies = append(sources[0].Policies, narrow)
	f.NamespaceLabels["privacy.example.test/class"] = "different"
	fresh, _, err := MatchPolicies(sources, f, now)
	if err != nil || len(fresh) != 1 {
		t.Fatal("new collection used old scope", err)
	}
	retained, _, err := MatchRetainedPolicies(sources, f, []artifact.RetentionRule{original}, now)
	if err != nil || len(retained) != 2 || retained[1].MaximumSeconds != 600 {
		t.Fatal("retained evidence escaped original stricter rule", retained, err)
	}
	// Current labels are not needed to establish an original policy relationship.
	f.NamespaceLabels = nil
	f.NamespaceKeys = nil
	if _, _, err = MatchRetainedPolicies(sources, f, []artifact.RetentionRule{original}, now); err != nil {
		t.Fatal("original relationship required current labels", err)
	}
	sources[0].Policies[1].Policy.Revision.Generation = 1
	if _, _, err = MatchRetainedPolicies(sources, f, []artifact.RetentionRule{original}, now); err == nil {
		t.Fatal("reused generation with changed definition")
	}
	sources[0].Policies = sources[0].Policies[:1]
	if _, _, err = MatchRetainedPolicies(sources, f, []artifact.RetentionRule{original}, now); err != nil {
		t.Fatal("deleted override lost existing ledger obligation", err)
	}
}
