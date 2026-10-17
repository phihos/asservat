package capacity

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestCapacityPoolPlanCarriesCompleteCommitmentsAndOneSharedBurst(t *testing.T) {
	s, _, _ := capacitySelectionFixture()
	second := s.Policies[0]
	second.Resource.Name, second.Resource.UID = "second", "second-uid"
	b := *second.Budget
	b.Name = "second"
	b.Cluster = "10000000-0000-4000-8000-000000000002"
	second.Budget = &b
	second.Scope = &BudgetScope{ClusterID: b.Cluster, NamespaceLabels: map[string]string{"team": "two"}}
	s.Policies = append(s.Policies, second)
	s.Pools[0].Budget.Slots[0].Workloads = 2
	s.Pools[0].Budget.Slots = append(s.Pools[0].Budget.Slots, ProtectedSlotInput{Policy: "second", Workloads: 2, Protected: b.Protected})
	p, e := CompileProtectedPoolPlan(s, "pool")
	if e != nil {
		t.Fatal(e)
	}
	if p.Protected != (BudgetAmount{64, 64}) || p.AccountLimit != 4 || p.NamespaceLimit != 4 || len(p.Clusters) != 2 || len(p.Policies) != 2 || p.Burst != (BudgetAmount{40, 40}) {
		t.Fatal("complete pool commitments lost")
	}
	for _, c := range p.Clusters {
		if c.ProtectedBytes != 32 || c.ByteLimit != 72 || c.AccountLimit != 2 {
			t.Fatal("cluster borrowed another cluster's commitment")
		}
	}
	// Cluster maxima overlap in the one shared burst; the root is deliberately
	// smaller than their sum and remains the serialization point for spending it.
	if p.Clusters[0].ByteLimit+p.Clusters[1].ByteLimit <= p.Capacity.Bytes {
		t.Fatal("fixture did not exercise shared burst intersection")
	}
	s.Policies[0].Scope.NamespaceLabels["team"] = "changed"
	if p.Policies[0].Scope.NamespaceLabels["team"] != "one" {
		t.Fatal("mutable source changed frozen plan")
	}
}
func TestCapacityPoolPlanCanonicalBytesIgnoreOnlyObservationsAndListOrder(t *testing.T) {
	s, _, _ := capacitySelectionFixture()
	first, d, e := CanonicalProtectedPoolPlan(s, "pool")
	if e != nil || d == (artifact.Digest{}) {
		t.Fatal(e)
	}
	s.PoolResourceVersion = "new-list"
	s.Policies[0].Resource.ResourceVersion = "new-status"
	next, nd, e := CanonicalProtectedPoolPlan(s, "pool")
	if e != nil || !bytes.Equal(first, next) || d != nd {
		t.Fatal("observation-only update rewrote permanent plan")
	}
	s.Policies[0].Resource.Generation++
	s.Policies[0].Resource.SpecDigest[0]++
	_, changed, e := CanonicalProtectedPoolPlan(s, "pool")
	if e != nil || changed == d {
		t.Fatal("desired source change omitted")
	}
}
func TestCapacityPoolPlanClosedWireShapeMatchesSQLCompiler(t *testing.T) {
	s, _, _ := capacitySelectionFixture()
	b, _, e := CanonicalProtectedPoolPlan(s, "pool")
	if e != nil {
		t.Fatal(e)
	}
	var p map[string]any
	if json.Unmarshal(b, &p) != nil {
		t.Fatal("invalid compiler JSON")
	}
	for _, name := range []string{"Format", "Name", "UID", "Generation", "Digest", "StorageProfile", "Capacity", "Safety", "System", "Burst", "Protected", "AccountLimit", "NamespaceLimit", "Policies", "Clusters"} {
		if _, ok := p[name]; !ok {
			t.Fatalf("missing closed field %s", name)
		}
	}
	if len(p) != 15 || p["Format"] != ProtectedPoolPlanFormat {
		t.Fatal("unexpected closed pool shape")
	}
	// Actual SQL equality is a separate native regression; this unit only fixes
	// the complete protocol field set instead of accepting open arbitrary maps.
}
