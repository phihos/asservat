package kubernetes

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	wire "asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func installerCapacityObjectSettings(t *testing.T) contracts.InstallerCapacitySettings {
	t.Helper()
	pool, policy := capacityObjects(t)
	var p wire.EvidenceStoragePoolSpec
	var b wire.EvidenceBudgetPolicySpec
	raw, _ := json.Marshal(pool["spec"])
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(policy["spec"])
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.Scope.ClusterID = ""
	return contracts.InstallerCapacitySettings{Pool: "pool", Policy: "context", NamespaceKeys: []string{"team"}, PoolSpec: &p, PolicySpec: &b,
		Backends: []contracts.InstallerCapacityBackend{{StorageProfile: "evidence", Usable: contracts.InstallerCapacityAmount{Bytes: 128, Objects: 128}}}}
}

type installerCapacityAPI struct {
	mu            sync.Mutex
	objects       map[string]map[string]any
	reads, writes int
	failCreate    bool
	control       cfg.NamespaceRef
}

func (f *installerCapacityAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		f.reads++
	} else if r.Method == http.MethodPost {
		f.writes++
	} else {
		w.WriteHeader(405)
		return
	}
	if r.URL.Path == "/api/v1/namespaces/"+f.control.Name {
		json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": f.control.Name, "uid": f.control.UID, "resourceVersion": "ns1"}})
		return
	}
	key := r.URL.Path
	if r.Method == http.MethodPost {
		var object map[string]any
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if decoder.Decode(&object) != nil {
			w.WriteHeader(400)
			return
		}
		metadata := object["metadata"].(map[string]any)
		key += "/" + metadata["name"].(string)
		if f.objects[key] != nil {
			w.WriteHeader(409)
			return
		}
		metadata["uid"], metadata["resourceVersion"], metadata["generation"] = ownerID(8+len(f.objects)), "object1", 1
		f.objects[key] = object
		if f.failCreate {
			f.failCreate = false
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(201)
	}
	if object := f.objects[key]; object != nil {
		json.NewEncoder(w).Encode(object)
		return
	}
	if r.Method == http.MethodGet && (strings.HasSuffix(key, "/evidencestoragepools") || strings.HasSuffix(key, "/evidencebudgetpolicies")) {
		items := []any{}
		kind := "EvidenceStoragePoolList"
		if strings.HasSuffix(key, "/evidencebudgetpolicies") {
			kind = "EvidenceBudgetPolicyList"
		}
		for objectKey, object := range f.objects {
			if strings.HasPrefix(objectKey, key+"/") {
				items = append(items, object)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind, "metadata": map[string]any{"resourceVersion": "list1"}, "items": items})
		return
	}
	w.WriteHeader(404)
	json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
}
func installerCapacityTestAPI(t *testing.T) (*installerCapacityAPI, *rest.Config) {
	t.Helper()
	f := &installerCapacityAPI{objects: map[string]map[string]any{}, control: cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	return f, config
}
