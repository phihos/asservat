package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-196 step 5: the join creates the slot's guarded sources and topology
// and appends the entry by CAS; a rerun is exact, and another entry for the
// same cluster or a full catalog is refused.
func TestJoinRegionalClusterCreatesSlotAndAppendsExactly(t *testing.T) {
	installation := ownerID(1)
	catalogName := contracts.OwnerClusterCatalogName(installation)
	catalogPath := "/api/v1/namespaces/hub/configmaps/" + catalogName
	var mu sync.Mutex
	objects := map[string]map[string]any{}
	empty, _ := json.Marshal(contracts.OwnerClusterCatalog{Format: contracts.OwnerClusterCatalogFormat, Clusters: []contracts.OwnerPublicCluster{}})
	objects[catalogPath] = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": catalogName, "namespace": "hub", "uid": ownerID(50), "resourceVersion": "1"}, "data": map[string]any{contracts.OwnerClusterCatalogFile: string(empty)}}
	status := func(w http.ResponseWriter, code int, reason meta.StatusReason) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code)})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		switch r.Method {
		case http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&body)
			m := body["metadata"].(map[string]any)
			key := r.URL.Path + "/" + m["name"].(string)
			if _, ok := objects[key]; ok {
				status(w, 409, meta.StatusReasonAlreadyExists)
				return
			}
			m["uid"], m["generation"], m["resourceVersion"] = ownerID(len(objects)+10), 1, "1"
			objects[key] = body
			_ = json.NewEncoder(w).Encode(body)
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&body)
			old, ok := objects[r.URL.Path]
			if !ok {
				status(w, 404, meta.StatusReasonNotFound)
				return
			}
			if body["metadata"].(map[string]any)["resourceVersion"] != old["metadata"].(map[string]any)["resourceVersion"] {
				status(w, 409, meta.StatusReasonConflict)
				return
			}
			body["metadata"].(map[string]any)["resourceVersion"] = "2"
			objects[r.URL.Path] = body
			_ = json.NewEncoder(w).Encode(body)
		default:
			if o, ok := objects[r.URL.Path]; ok {
				_ = json.NewEncoder(w).Encode(o)
				return
			}
			status(w, 404, meta.StatusReasonNotFound)
		}
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	cluster := ownerID(5)
	plan := ClusterJoinPlan{Control: cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}, Installation: installation, Slot: 1, Admins: []cfg.KubernetesActor{{Kind: "Group", Name: "synthetic-admins"}},
		Catalog:  contracts.WorkerObjectReference{Name: catalogName, UID: ownerID(50)},
		Topology: contracts.RetentionTopologySettings{SchemaVersion: "retention-topology/v1", Revision: 1, RootID: ownerID(3), TargetClusterID: cluster, Hub: contracts.RetentionPolicySource{ClusterID: ownerID(4), ControlNamespaceUID: ownerID(2), ProtectionSHA256: strings.Repeat("ab", 32)}},
		Entry: contracts.OwnerPublicCluster{ClusterID: cluster, Standby: 1, Captures: 1, Settings: contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, ClusterID: cluster},
			Trust: contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, ClusterID: cluster, Revision: 1, Keys: []contracts.APIContextWorkPublicKey{{ID: "work-v1"}}}}}
	first, err := JoinRegionalCluster(context.Background(), config, plan)
	if err != nil {
		t.Fatal(err)
	}
	if first.Capability.Source.Name != contracts.OwnerClusterSourceName(installation, 1, "capability") || first.WorkTrust.Guard.PolicyUID == "" || first.Topology.Name != contracts.OwnerClusterSourceName(installation, 1, "topology") || len(first.Topology.SHA256) != 64 {
		t.Fatal("slot sources", first)
	}
	read := func() contracts.OwnerClusterCatalog {
		mu.Lock()
		defer mu.Unlock()
		c, err := contracts.DecodeOwnerClusterCatalog(strings.NewReader(objects[catalogPath]["data"].(map[string]any)[contracts.OwnerClusterCatalogFile].(string)))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := read(); len(c.Clusters) != 1 || !equalJSON(c.Clusters[0], first) {
		t.Fatal("catalog entry not appended")
	}
	again, err := JoinRegionalCluster(context.Background(), config, plan)
	if err != nil || !equalJSON(again, first) || len(read().Clusters) != 1 {
		t.Fatal("rerun not exact", err)
	}
	changed := plan
	changed.Entry.Standby = 2
	if _, err = JoinRegionalCluster(context.Background(), config, changed); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("another entry for the joined cluster accepted", err)
	}
	other := plan
	other.Entry.ClusterID, other.Entry.Settings.ClusterID, other.Entry.Trust.ClusterID, other.Topology.TargetClusterID = ownerID(6), ownerID(6), ownerID(6), ownerID(6)
	if _, err = JoinRegionalCluster(context.Background(), config, other); err == nil {
		t.Fatal("a second cluster joined beyond the slot")
	}
}
