package capacity

import (
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The values become one pool and one policy per cluster; a helm upgrade
// with another value is a higher generation of the same records.
func TestValuesSourceObservation(t *testing.T) {
	now := time.Now()
	remote := "40000000-0000-4000-8000-000000000009"
	s := &ValuesSource{Installation: "40000000-0000-4000-8000-000000000001", Cluster: capacityTestCluster, Control: cfg.NamespaceRef{Name: "asservat", UID: "ns-uid"},
		Revision: 3, Values: CapacityValues{EvidenceBytes: 128 << 30}, Clusters: []string{capacityTestCluster, remote}, Now: func() time.Time { return now }}
	o, err := s.ReadCapacitySource(t.Context())
	if err != nil || !o.Valid(now) || len(o.Snapshot.Policies) != 2 || o.Snapshot.Pools[0].Assurance != "bestEffort" {
		t.Fatal(err, o)
	}
	ns := cfg.NamespaceMetadata{ClusterID: remote, Namespace: cfg.NamespaceRef{Name: "app", UID: "app-uid"}, ResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(time.Second),
		Labels: EligibleNamespace("app", "asservat", nil)}
	selected, err := SelectBudget(o.Snapshot, ns, []string{EligibilityLabel}, now)
	if err != nil || selected.Budget.Cluster != remote {
		t.Fatal("eligible namespace not selected", err)
	}
	ns.Labels = EligibleNamespace("app", "asservat", map[string]string{EligibilityLabel: "disabled"})
	if _, err = SelectBudget(o.Snapshot, ns, []string{EligibilityLabel}, now); err == nil {
		t.Fatal("opted-out namespace selected")
	}
	for _, name := range []string{"asservat", "kube-system"} {
		if EligibleNamespace(name, "asservat", nil)[EligibilityLabel] != "disabled" {
			t.Fatal("system or release namespace eligible", name)
		}
	}
	s.Revision, s.Values.ShareBytes = 4, 8<<30
	next, err := s.ReadCapacitySource(t.Context())
	if err != nil || next.Snapshot.Pools[0].Resource.UID != o.Snapshot.Pools[0].Resource.UID || next.Snapshot.Pools[0].Resource.Generation != 4 || next.Digest == o.Digest {
		t.Fatal("upgrade did not produce a new generation of the same pool", err)
	}
}
