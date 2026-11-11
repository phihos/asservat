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
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	capacityapp "asservat.local/asservat/internal/application/capacity"
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
func TestInstallerCapacityObjectsCreateExactSourcesAndReopen(t *testing.T) {
	f, config := installerCapacityTestAPI(t)
	settings := installerCapacityObjectSettings(t)
	for n := 0; n < 2; n++ {
		if err := EnsureInstallerCapacityObjects(context.Background(), config, f.control, ownerID(1), permissionCluster, settings); err != nil {
			t.Fatal(err)
		}
	}
	if f.reads != 8 || f.writes != 2 || settings.PolicySpec.Scope.ClusterID != "" {
		t.Fatal("replay rewrote an object or mutated the original operator input", f.writes)
	}
	client, err := NewPermissionClient(config, permissionCluster, f.control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewCapacitySource(client)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := source.ReadCapacitySource(context.Background())
	if err != nil {
		t.Fatal("production source reader rejected installed desired objects", err)
	}
	plan, err := capacityapp.CompileProtectedPoolPlan(observed.Snapshot, settings.Pool)
	if err != nil || len(plan.Clusters) != 1 || plan.Clusters[0].ClusterID != permissionCluster || plan.Policies[0].Scope.NamespaceLabels["team"] != "one" || plan.UID != ownerID(8) {
		t.Fatal("producer/consumer pool identity, selector or budget mismatch", plan, err)
	}
}
func TestInstallerCapacityObjectsRefuseMalformedScopeBeforeAPI(t *testing.T) {
	for _, name := range []string{"half-pair", "foreign-cluster", "foreign-pool", "unprotected-selector", "malformed-schema", "unbalanced-pool", "unqualified-backend"} {
		t.Run(name, func(t *testing.T) {
			f, config := installerCapacityTestAPI(t)
			s := installerCapacityObjectSettings(t)
			switch name {
			case "half-pair":
				s.PoolSpec = nil
			case "foreign-cluster":
				s.PolicySpec.Scope.ClusterID = ownerID(4)
			case "foreign-pool":
				s.PolicySpec.PoolRef = "other"
			case "unprotected-selector":
				s.PolicySpec.Scope.NamespaceSelector.MatchLabels["unknown"] = "one"
			case "malformed-schema":
				s.PolicySpec.Node.SampleIntervalSeconds = -1
			case "unbalanced-pool":
				s.PoolSpec.Capacity.Bytes = 1
			case "unqualified-backend":
				s.Backends[0].Usable.Bytes = 1
			}
			if err := EnsureInstallerCapacityObjects(context.Background(), config, f.control, ownerID(1), permissionCluster, s); !errors.Is(err, cfg.ErrInvalid) || f.reads+f.writes != 0 {
				t.Fatal("invalid operator inputs reached API", err, f.reads, f.writes)
			}
		})
	}
	// Existing preprovided-source profiles do not introduce any lookup or effect.
	if err := EnsureInstallerCapacityObjects(nil, nil, cfg.NamespaceRef{}, "", "", contracts.InstallerCapacitySettings{}); err != nil {
		t.Fatal(err)
	}
}
func TestInstallerCapacityObjectsRefuseUnknownOrChangedRetainedObjects(t *testing.T) {
	for _, name := range []string{"unmarked", "other-installation", "changed-spec", "deleted", "wrong-namespace-uid"} {
		t.Run(name, func(t *testing.T) {
			f, config := installerCapacityTestAPI(t)
			s := installerCapacityObjectSettings(t)
			if err := EnsureInstallerCapacityObjects(context.Background(), config, f.control, ownerID(1), permissionCluster, s); err != nil {
				t.Fatal(err)
			}
			key := "/apis/asservat.io/v1alpha1/namespaces/hub/evidencestoragepools/pool"
			object := f.objects[key]
			metadata := object["metadata"].(map[string]any)
			switch name {
			case "unmarked":
				delete(metadata, "annotations")
			case "other-installation":
				metadata["annotations"].(map[string]any)["asservat.io/installation-id"] = ownerID(5)
			case "changed-spec":
				object["spec"].(map[string]any)["capacity"].(map[string]any)["bytes"] = json.Number("127")
			case "deleted":
				metadata["deletionTimestamp"] = "2026-11-11T00:00:00Z"
			case "wrong-namespace-uid":
				f.control.UID = ownerID(5)
			}
			control := cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}
			if err := EnsureInstallerCapacityObjects(context.Background(), config, control, ownerID(1), permissionCluster, s); !errors.Is(err, cfg.ErrChanged) || f.writes != 2 {
				t.Fatal("adopted/updated retained or replaced source", name, err, f.writes)
			}
		})
	}
}

func TestInstallerCapacityObjectsUnknownCreateDoesNotReplayPOST(t *testing.T) {
	f, config := installerCapacityTestAPI(t)
	f.failCreate = true
	settings := installerCapacityObjectSettings(t)
	if err := EnsureInstallerCapacityObjects(context.Background(), config, f.control, ownerID(1), permissionCluster, settings); !errors.Is(err, cfg.ErrUnavailable) || f.writes != 1 || len(f.objects) != 1 {
		t.Fatal("unknown create repeated or lost its original object", err, f.writes)
	}
	if err := EnsureInstallerCapacityObjects(context.Background(), config, f.control, ownerID(1), permissionCluster, settings); err != nil || f.writes != 2 {
		t.Fatal("exact later reopen duplicated the first create", err, f.writes)
	}
}
