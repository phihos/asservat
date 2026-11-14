package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
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

func TestCapacitySourceRetainsOngoingLimitsInProtectedDesiredDigest(t *testing.T) {
	pool, policy := capacityObjects(t)
	spec := policy["spec"].(map[string]any)
	node := spec["node"].(map[string]any)
	workload := spec["workload"].(map[string]any)
	node["maxActiveSources"], node["inputBytesPerSecond"], node["inputBurstBytes"] = 4, 2<<20, 1<<20
	workload["maxActiveSources"] = 2
	node["maxRingBytes"], node["maxFrozenBytes"] = 64<<20, 32<<20
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
	reader, err := NewCapacitySource(f.client)
	if err != nil {
		t.Fatal(err)
	}
	a, err := reader.ReadCapacitySource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := a.Snapshot.Policies[0].SourceResources
	if got == nil || got.Node.MaxActiveSources != 4 || got.Node.InputBytesPerSecond != 2<<20 || got.Node.InputBurstBytes != 1<<20 || got.Workload.MaxActiveSources != 2 || got.Node.RingBytes != 64<<20 || got.Node.FrozenBytes != 32<<20 {
		t.Fatal("protected decoder discarded source caps", got)
	}
	node["maxActiveSources"] = 3
	b, err := reader.ReadCapacitySource(context.Background())
	if err != nil || b.Digest == a.Digest {
		t.Fatal("source cap edit did not change accepted desired digest", err)
	}
	node["maxActiveSources"] = -1
	c, err := reader.ReadCapacitySource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Snapshot.Policies[0].Budget != nil {
		t.Fatal("invalid cap supplied typed budget")
	}
}

// The pool and budget policy exactly as charts/asservat/templates/hub-capacity.yaml
// renders them from examples/helm/context-trial-profile.yaml (an absent
// scope.clusterID means the hub), with the metadata a real API server adds.
func TestCapacitySourceReadsHelmRenderedObjects(t *testing.T) {
	const poolSpec = `{"capacity":{"bytes":8589934592,"objects":16000},"capacityAssurance":"qualifiedReservedBackend","maxUploadRequestsPerSecond":20,"protectedAllocations":[{"budgetPolicyRef":"trial-apps","protectedPerWorkload":{"bytes":1073741824,"objects":2000},"workloadSlots":2}],"safetyHeadroom":{"bytes":1073741824,"objects":2000},"sharedBurst":{"bytes":1073741824,"objects":2000},"storageProfileRef":"trial-dedicated","systemReserve":{"bytes":2147483648,"objects":6000},"upload":{"burstBytes":16777216,"bytesPerSecond":16777216}}`
	const policySpec = `{"namespaceEnvelope":{"maxObjects":6000,"maxStoredBytes":3221225472,"maxWorkloadAccounts":2},"node":{"impactProfileRef":"standard-node","maxConcurrentExpensive":1,"maxQueuedExpensive":1,"maxSpoolBytes":16777216,"recoveryHealthySeconds":60,"sampleIntervalSeconds":5,"unhealthySamples":3,"upload":{"burstBytes":8388608,"bytesPerSecond":8388608}},"poolRef":"trial","scope":{"namespaceSelector":{"matchLabels":{"asservat-trial":"true"}}},"workload":{"contextReserve":{"bytes":12353536,"objects":32},"dump":{"burst":1,"maxInputBytesPerRollingHour":1048576,"maxStartsPerRollingHour":1,"minimumIntervalSeconds":900},"hardLimit":{"bytes":1610612736,"objects":3000},"maxConcurrentExpensive":1,"maxQueueAgeSeconds":30,"maxQueuedExpensive":1,"maxSpoolBytes":16777216,"maxUploadRequestsPerSecond":10,"onFull":"RejectNewExpensive","protected":{"bytes":1073741824,"objects":2000},"upload":{"burstBytes":8388608,"bytesPerSecond":8388608}}}`
	object := func(kind, name, uid, spec string) map[string]any {
		var m map[string]any
		if json.Unmarshal([]byte(spec), &m) != nil {
			t.Fatal("fixture JSON")
		}
		meta := map[string]any{"name": name, "namespace": permissionControl.Name, "uid": uid, "generation": 1, "resourceVersion": "1234",
			"creationTimestamp": "2026-11-13T10:00:00Z",
			"labels":            map[string]string{"app.kubernetes.io/name": "asservat", "app.kubernetes.io/component": "capacity", "app.kubernetes.io/managed-by": "Helm", "helm.sh/chart": "asservat-0.1.0-dev.1"},
			"annotations":       map[string]string{"meta.helm.sh/release-name": "asservat", "meta.helm.sh/release-namespace": permissionControl.Name},
			"managedFields":     []any{map[string]any{"manager": "helm", "operation": "Update", "apiVersion": "asservat.io/v1alpha1", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:spec": map[string]any{}}}}}
		return map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind, "metadata": meta, "spec": m}
	}
	pool, policy := object("EvidenceStoragePool", "trial", "pool-uid", poolSpec), object("EvidenceBudgetPolicy", "trial-apps", "policy-uid", policySpec)
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/evidencestoragepools") {
			permissionReply(w, permissionList("EvidenceStoragePool", "1300", "", pool))
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/evidencebudgetpolicies") {
			permissionReply(w, permissionList("EvidenceBudgetPolicy", "1300", "", policy))
			return true
		}
		return false
	})
	f.clock.Store(time.Now().UTC().UnixNano())
	s, e := NewCapacitySource(f.client)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.ReadCapacitySource(context.Background())
	if e != nil {
		var fixed interface{ FixedStep() string }
		step := ""
		if errors.As(e, &fixed) {
			step = fixed.FixedStep()
		}
		t.Fatalf("Helm-rendered capacity source refused at %q: %v", step, e)
	}
	if !got.Valid(f.client.now()) || len(got.Snapshot.Pools) != 1 || len(got.Snapshot.Policies) != 1 {
		t.Fatal("Helm-rendered capacity source observation is invalid")
	}
}
