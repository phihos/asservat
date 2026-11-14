package kubernetes

import (
	"encoding/json"
	"testing"

	wire "asservat.local/asservat/api/v1alpha1"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Helm renders EvidenceBudgetPolicy before the generated cluster ID exists:
// an empty scope.clusterID reads as this hub cluster, an explicit one stays.
func TestHubScopedPolicyFillsEmptyClusterID(t *testing.T) {
	const hub, other = "40000000-0000-4000-8000-000000000001", "40000000-0000-4000-8000-000000000002"
	v, err := newCapacityValidator()
	if err != nil {
		t.Fatal(err)
	}
	spec := func(cluster string) permissionObject {
		s := capacityProbeSpec("EvidenceBudgetPolicy", cluster).(wire.EvidenceBudgetPolicySpec)
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return permissionObject{Spec: b}
	}
	r := cfg.Resource{Name: "synthetic-capacity-probe"}
	empty := v.policyObservation(hubScopedPolicy(spec(""), hub), r)
	if empty.Budget == nil || empty.Scope == nil || empty.Scope.ClusterID != hub || empty.Budget.Cluster != hub {
		t.Fatal("empty clusterID not scoped to the hub", empty)
	}
	explicit := v.policyObservation(hubScopedPolicy(spec(other), hub), r)
	if explicit.Scope == nil || explicit.Scope.ClusterID != other {
		t.Fatal("explicit clusterID replaced", explicit)
	}
	if string(hubScopedPolicy(permissionObject{Spec: []byte(`{"scope":{"clusterID":"","clusterID":""}}`)}, hub).Spec) != `{"scope":{"clusterID":"","clusterID":""}}` {
		t.Fatal("duplicate-key spec rewritten")
	}
}
