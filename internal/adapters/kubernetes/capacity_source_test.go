package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	port "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func capacityObjects(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	amount := func(n int64) wire.CapacityAmount { return wire.CapacityAmount{Bytes: n, Objects: n} }
	upload := wire.CapacityUpload{BytesPerSecond: 4096, BurstBytes: 4096}
	pool := wire.EvidenceStoragePoolSpec{StorageProfileRef: "evidence", Capacity: amount(128), SafetyHeadroom: amount(16), SystemReserve: amount(8), SharedBurst: amount(40), ProtectedAllocations: []wire.CapacityProtectedAllocation{{BudgetPolicyRef: "context", WorkloadSlots: 4, ProtectedPerWorkload: amount(16)}}, Upload: upload, MaxUploadRequestsPerSecond: 10, CapacityAssurance: "qualifiedReservedBackend"}
	policy := wire.EvidenceBudgetPolicySpec{PoolRef: "pool", Scope: wire.CapacityPolicyScope{ClusterID: permissionCluster, NamespaceSelector: wire.Selector{MatchLabels: map[string]string{"team": "one"}}}, NamespaceEnvelope: wire.CapacityNamespaceEnvelope{MaxWorkloadAccounts: 4, MaxStoredBytes: 64, MaxObjects: 64}, Workload: wire.CapacityWorkloadLimits{Protected: amount(16), HardLimit: amount(32), ContextReserve: amount(1), Dump: wire.CapacityDumpLimits{Burst: 1, MinimumIntervalSeconds: 60, MaxStartsPerRollingHour: 10, MaxInputBytesPerRollingHour: 1 << 20}, MaxConcurrentExpensive: 1, MaxQueuedExpensive: 1, MaxQueueAgeSeconds: 30, Upload: upload, MaxUploadRequestsPerSecond: 10, MaxSpoolBytes: 4096, OnFull: "RejectNewExpensive"}, Node: wire.CapacityNodeLimits{MaxConcurrentExpensive: 1, MaxQueuedExpensive: 2, Upload: upload, MaxSpoolBytes: 4096, ImpactProfileRef: "context", UnhealthySamples: 3, SampleIntervalSeconds: 5, RecoveryHealthySeconds: 60}}
	object := func(kind, name, uid string, spec any) map[string]any {
		b, e := json.Marshal(spec)
		if e != nil {
			t.Fatal(e)
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			t.Fatal("fixture JSON")
		}
		return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind, "metadata": map[string]any{"name": name, "namespace": permissionControl.Name, "uid": uid, "generation": 1, "resourceVersion": "opaque:capacity"}, "spec": m, "status": map[string]any{"phase": "Ready", "accepted": true}}
	}
	return object("EvidenceStoragePool", "pool", "pool-uid", pool), object("EvidenceBudgetPolicy", "context", "policy-uid", policy)
}
func capacityTestNamespace(now time.Time) cfg.NamespaceMetadata {
	return cfg.NamespaceMetadata{ClusterID: permissionCluster, Namespace: cfg.NamespaceRef{Name: "app", UID: "app-uid"}, ResourceVersion: "opaque:ns", ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Labels: map[string]string{"team": "one"}}
}
func TestCapacitySourcePreservesMatchingAndIgnoresStatus(t *testing.T) {
	pool, policy := capacityObjects(t)
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/evidencestoragepools") {
			permissionReply(w, permissionList("EvidenceStoragePool", "pool-list", "", pool))
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/evidencebudgetpolicies") {
			permissionReply(w, permissionList("EvidenceBudgetPolicy", "policy-list", "", policy))
			return true
		}
		return false
	})
	f.clock.Store(time.Now().UTC().UnixNano())
	s, e := NewCapacitySource(f.client)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.ReadCapacitySource(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	selected, e := port.SelectBudget(a.Snapshot, capacityTestNamespace(f.client.now()), []string{"team"}, f.client.now())
	if e != nil || selected.Compiled.Protected() != (port.BudgetAmount{Bytes: 64, Objects: 64}) {
		t.Fatalf("current source: %v", e)
	}
	policy["status"] = map[string]any{"phase": "anything", "observedGeneration": 999}
	policy["metadata"].(map[string]any)["resourceVersion"] = "later-status"
	pool["status"] = map[string]any{"qualified": true, "capacity": 1 << 60}
	b, e := s.ReadCapacitySource(context.Background())
	if e != nil || b.Digest != a.Digest {
		t.Fatalf("status mutated desired acceptance: %v", e)
	}
	policy["spec"].(map[string]any)["namespaceEnvelope"].(map[string]any)["maxWorkloadAccounts"] = 3
	c, e := s.ReadCapacitySource(context.Background())
	if e != nil || c.Digest == a.Digest {
		t.Fatalf("desired source mutation omitted: %v", e)
	}
}
func TestCapacitySourceRetainsInvalidNonmatchingSettings(t *testing.T) {
	pool, policy := capacityObjects(t)
	brokenPool, brokenPolicy := capacityObjects(t)
	brokenPool["metadata"].(map[string]any)["name"] = "other-pool"
	brokenPool["metadata"].(map[string]any)["uid"] = "other-pool-uid"
	brokenPool["spec"].(map[string]any)["capacity"] = "invalid"
	brokenPolicy["metadata"].(map[string]any)["name"] = "other-policy"
	brokenPolicy["metadata"].(map[string]any)["uid"] = "other-policy-uid"
	brokenPolicy["spec"].(map[string]any)["poolRef"] = "other-pool"
	brokenPolicy["spec"].(map[string]any)["scope"].(map[string]any)["namespaceSelector"] = map[string]any{"matchLabels": map[string]string{"team": "two"}}
	brokenPolicy["spec"].(map[string]any)["workload"] = "invalid"
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/evidencestoragepools") {
			permissionReply(w, permissionList("EvidenceStoragePool", "pool-list", "", pool, brokenPool))
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/evidencebudgetpolicies") {
			permissionReply(w, permissionList("EvidenceBudgetPolicy", "policy-list", "", policy, brokenPolicy))
			return true
		}
		return false
	})
	f.clock.Store(time.Now().UTC().UnixNano())
	s, e := NewCapacitySource(f.client)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.ReadCapacitySource(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if a.Snapshot.Pools[1].Budget != nil || a.Snapshot.Policies[1].Budget != nil || a.Snapshot.Policies[1].Scope == nil {
		t.Fatal("invalid or safely excluding scope lost")
	}
	if _, e = port.SelectBudget(a.Snapshot, capacityTestNamespace(f.client.now()), []string{"team"}, f.client.now()); e != nil {
		t.Fatalf("unrelated bad source disabled exact target: %v", e)
	}
	brokenPolicy["spec"].(map[string]any)["scope"] = "unknown"
	b, e := s.ReadCapacitySource(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if b.Digest == a.Digest {
		t.Fatal("invalidating change lost from projection")
	}
	if _, e = port.SelectBudget(b.Snapshot, capacityTestNamespace(f.client.now()), []string{"team"}, f.client.now()); e == nil {
		t.Fatal("unknown scope silently excluded")
	}
}
func TestCapacitySourcePreservesCallerDeadline(t *testing.T) {
	pool, policy := capacityObjects(t)
	var f permissionFixture
	f = newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/evidencestoragepools") {
			permissionReply(w, permissionList("EvidenceStoragePool", "pool-list", "", pool))
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/evidencebudgetpolicies") {
			permissionReply(w, permissionList("EvidenceBudgetPolicy", "policy-list", "", policy))
			return true
		}
		return false
	})
	f.clock.Store(time.Now().UTC().UnixNano())
	s, e := NewCapacitySource(f.client)
	if e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(2 * time.Second)
	call, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()
	a, e := s.ReadCapacitySource(call)
	if e != nil {
		t.Fatal(e)
	}
	if !a.Snapshot.FreshUntil.Equal(end) || a.Digest == (artifact.Digest{}) {
		t.Fatal("source lost original caller deadline")
	}
	f.clock.Store(end.Add(time.Nanosecond).UnixNano())
	if a.Snapshot.Valid(f.client.now()) {
		t.Fatal("old observation renewed by another clock read")
	}
}
