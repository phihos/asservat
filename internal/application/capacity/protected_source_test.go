package capacity

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

const capacityTestCluster = "10000000-0000-4000-8000-000000000001"

func capacitySelectionFixture() (CapacitySnapshot, cfg.NamespaceMetadata, time.Time) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	ref := func(kind, name, uid string) cfg.Resource {
		return cfg.Resource{ClusterID: capacityTestCluster, Namespace: "control", NamespaceUID: "control-uid", Kind: kind, Name: name, UID: uid, ResourceVersion: "rv-opaque", Generation: 1, SpecDigest: artifact.Digest{1}}
	}
	policy := PolicyBudgetInput{Name: "policy", Pool: "pool", Cluster: capacityTestCluster, Protected: BudgetAmount{16, 16}, Hard: BudgetAmount{32, 32}, Context: BudgetAmount{1, 1}, NamespaceMaximum: BudgetAmount{64, 64}, NamespaceAccounts: 4}
	pool := PoolBudgetInput{Name: "pool", Capacity: BudgetAmount{128, 128}, Safety: BudgetAmount{16, 16}, System: BudgetAmount{8, 8}, Burst: BudgetAmount{40, 40}, Slots: []ProtectedSlotInput{{Policy: "policy", Workloads: 4, Protected: BudgetAmount{16, 16}}}}
	s := CapacitySnapshot{ClusterID: capacityTestCluster, ControlNamespace: cfg.NamespaceRef{Name: "control", UID: "control-uid"}, PoolResourceVersion: "p-100", PolicyResourceVersion: "b-200", ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(4 * time.Second), Pools: []PoolObservation{{Resource: ref("EvidenceStoragePool", "pool", "pool-uid"), StorageProfile: "evidence", Assurance: "qualifiedReservedBackend", Budget: &pool}}, Policies: []BudgetPolicyObservation{{Resource: ref("EvidenceBudgetPolicy", "policy", "policy-uid"), Pool: "pool", Scope: &BudgetScope{ClusterID: capacityTestCluster, NamespaceLabels: map[string]string{"team": "one"}}, Budget: &policy}}}
	ns := cfg.NamespaceMetadata{ClusterID: capacityTestCluster, Namespace: cfg.NamespaceRef{Name: "app", UID: "app-uid"}, ResourceVersion: "n-42", ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Labels: map[string]string{"team": "one"}}
	return s, ns, now
}

func TestCapacitySelectionIsolatesUnrelatedMalformedPool(t *testing.T) {
	s, ns, now := capacitySelectionFixture()
	broken := s.Pools[0]
	broken.Resource.Name, broken.Resource.UID, broken.Resource.SpecDigest = "broken", "broken-uid", artifact.Digest{}
	broken.Budget = nil
	s.Pools = append(s.Pools, broken)
	foreign := s.Policies[0]
	foreign.Resource.Name, foreign.Resource.UID, foreign.Resource.SpecDigest = "other", "other-uid", artifact.Digest{}
	foreign.Pool = "broken"
	foreign.Scope = &BudgetScope{ClusterID: capacityTestCluster, NamespaceLabels: map[string]string{"team": "two"}}
	foreign.Budget = nil
	s.Policies = append(s.Policies, foreign)
	got, e := SelectBudget(s, ns, []string{"team"}, now)
	if e != nil || got.Policy.Name != "policy" || got.Pool.Name != "pool" {
		t.Fatalf("unrelated malformed pool blocked exact scope: %v", e)
	}
	// Changing the known nonmatching scope into a match must not silently skip
	// malformed contents and select whichever other profile happens to work.
	s.Policies[1].Scope.NamespaceLabels["team"] = "one"
	if _, e = SelectBudget(s, ns, []string{"team"}, now); !errors.Is(e, ErrAmbiguousBudgetProfile) {
		t.Fatalf("invalid matching profile hidden: %v", e)
	}
}
func TestCapacitySelectionUnknownScopeAndSharedPoolFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*CapacitySnapshot)
	}{
		{"unknown-scope", func(s *CapacitySnapshot) {
			p := s.Policies[0]
			p.Resource.Name, p.Resource.UID = "other", "other-uid"
			p.Scope = nil
			p.Budget = nil
			s.Policies = append(s.Policies, p)
		}},
		{"invalid-shared-commitment", func(s *CapacitySnapshot) {
			p := s.Policies[0]
			p.Resource.Name, p.Resource.UID = "other", "other-uid"
			p.Scope = &BudgetScope{ClusterID: capacityTestCluster, NamespaceLabels: map[string]string{"team": "two"}}
			p.Budget = nil
			s.Policies = append(s.Policies, p)
		}},
		{"duplicate-pool-name", func(s *CapacitySnapshot) { p := s.Pools[0]; p.Resource.UID = "other"; s.Pools = append(s.Pools, p) }},
		{"missing-pool-list", func(s *CapacitySnapshot) { s.PoolResourceVersion = "" }},
		{"deleting-policy", func(s *CapacitySnapshot) { s.Policies[0].Resource.Deleting = true }},
		{"best-effort-is-not-qualification", func(s *CapacitySnapshot) { s.Pools[0].Assurance = "bestEffort" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, ns, now := capacitySelectionFixture()
			test.change(&s)
			if _, e := SelectBudget(s, ns, []string{"team"}, now); e == nil {
				t.Fatal("unsafe selection accepted")
			}
		})
	}
}
func TestCapacitySelectionRetainsIndependentOriginalEnds(t *testing.T) {
	s, ns, now := capacitySelectionFixture()
	s.FreshUntil = now.Add(25 * time.Millisecond)
	p, e := SelectBudget(s, ns, []string{"team"}, now)
	if e != nil || !p.FreshUntil.Equal(s.FreshUntil) {
		t.Fatalf("original source end lost: %v", e)
	}
	if _, e = SelectBudget(s, ns, []string{"team"}, s.FreshUntil); e == nil {
		t.Fatal("expired source used with fresh namespace")
	}
	if _, e = SelectBudget(s, ns, []string{"different"}, now); e == nil {
		t.Fatal("unprotected selector accepted")
	}
	ns.Labels["team"] = "none"
	if _, e = SelectBudget(s, ns, []string{"team"}, now); !errors.Is(e, ErrCapacityNotAllocated) {
		t.Fatalf("missing match classification: %v", e)
	}
}
func TestCapacitySelectionCopiesMutableSourceMaps(t *testing.T) {
	s, ns, now := capacitySelectionFixture()
	p, e := SelectBudget(s, ns, []string{"team"}, now)
	if e != nil {
		t.Fatal(e)
	}
	s.Policies[0].Scope.NamespaceLabels["team"] = "changed"
	s.Pools[0].Budget.Slots[0].Protected = BudgetAmount{1, 1}
	if p.Scope.NamespaceLabels["team"] != "one" || p.Compiled.Protected() != (BudgetAmount{64, 64}) {
		t.Fatal("source mutation changed accepted compiler result")
	}
}
