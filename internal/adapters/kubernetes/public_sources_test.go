package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-185: the producer creates the settings and the empty guarded catalog,
// keeps existing settings, and refuses a guard it did not write. ADR-194: a
// promoted owner also gets the unconfigured worker configuration and the
// download environment, each guarded.
func TestPublicSourcesCreateAndRefuseForeignGuard(t *testing.T) {
	for _, mode := range []string{"plain", "foreign", "promoted"} {
		foreign := mode == "foreign"
		var mu sync.Mutex
		objects := map[string]map[string]any{}
		uid := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			key := r.URL.Path
			if r.Method == http.MethodPost {
				key += "/" + body["metadata"].(map[string]any)["name"].(string)
				if objects[key] != nil {
					w.WriteHeader(409)
					_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
					return
				}
				uid++
				m := body["metadata"].(map[string]any)
				m["uid"] = fmt.Sprintf("10000000-0000-4000-8000-%012x", uid)
				m["resourceVersion"], m["generation"] = "1", 1
				objects[key] = body
			}
			if objects[key] == nil {
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
				return
			}
			_ = json.NewEncoder(w).Encode(objects[key])
		}))
		defer server.Close()
		installation := ownerID(1)
		guard := contracts.OwnerClusterCatalogName(installation) + "-guard"
		if foreign {
			objects["/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+guard] = map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy", "metadata": map[string]any{"name": guard, "uid": ownerID(9), "generation": 1}, "spec": admission.ValidatingAdmissionPolicySpec{}}
		}
		config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
		control := cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}
		admins := []cfg.KubernetesActor{{Kind: "User", Name: "system:serviceaccount:install:runner"}}
		browser := contracts.BrowserSettings{SchemaVersion: "browser-settings/v1", Revision: 1, RootID: ownerID(3), SessionEpoch: ownerID(4)}
		var environment *contracts.DownloadEnvironmentSettings
		if mode == "promoted" {
			environment = &contracts.DownloadEnvironmentSettings{Format: contracts.DownloadEnvironmentFormat, RootID: ownerID(6), InstallationID: installation, RecoveryEpoch: ownerID(7), Revision: 1,
				PermittedRegions: []string{}, Paths: []contracts.DownloadEnvironmentPath{}, Clients: []contracts.DownloadEnvironmentClient{}, Operators: []contracts.ProcessingOperator{{Issuer: "https://idp.synthetic.invalid", ClientID: "asservat", Kind: "user", ID: "operator"}}}
		}
		out, err := EnsurePublicSources(context.Background(), config, control, installation, admins, browser, contracts.IdentitySettings{SchemaVersion: "identity-settings/v1", Revision: 1}, environment)
		if foreign {
			if !errors.Is(err, cfg.ErrChanged) {
				t.Fatal("adopted a foreign guard", err)
			}
			continue
		}
		if err != nil || out.BrowserRootID != ownerID(3) || out.BrowserSettings.Name != contracts.OwnerBrowserSettingsName(installation) || out.ClusterCatalog.Source.Name != contracts.OwnerClusterCatalogName(installation) || out.ClusterCatalog.Guard.Name != guard || out.ClusterCatalog.Guard.PolicyUID == "" || out.ClusterCatalog.Guard.BindingUID == "" {
			t.Fatal("public sources", err, out)
		}
		catalog := objects["/api/v1/namespaces/hub/configmaps/"+contracts.OwnerClusterCatalogName(installation)]["data"].(map[string]any)[contracts.OwnerClusterCatalogFile].(string)
		if catalog != `{"format":"`+contracts.OwnerClusterCatalogFormat+`","clusters":[]}` {
			t.Fatal("first catalog is not empty", catalog)
		}
		worker := objects["/api/v1/namespaces/hub/configmaps/"+contracts.OwnerWorkerConfigurationName(installation)]
		if mode == "plain" && (worker != nil || out.WorkerConfiguration.Source.Name != "") {
			t.Fatal("download sources created without promotion")
		}
		if mode == "promoted" {
			if worker["data"].(map[string]any)["worker-profile.json"] != contracts.UnconfiguredWorkerConfiguration(installation) || out.WorkerConfiguration.Guard.Name != contracts.OwnerWorkerConfigurationName(installation)+"-guard" || out.WorkerConfiguration.Guard.PolicyUID == "" ||
				out.DownloadEnvironment.Source.Name != contracts.OwnerDownloadEnvironmentName(installation) || out.DownloadEnvironment.Guard.Name != contracts.OwnerDownloadEnvironmentName(installation)+"-guard" || out.DownloadEnvironment.Guard.BindingUID == "" {
				t.Fatal("promoted download sources", out)
			}
		}
		// A rerun keeps the existing settings and the exact guard.
		if environment != nil {
			environment.Revision = 2
		}
		again, err := EnsurePublicSources(context.Background(), config, control, installation, admins, contracts.BrowserSettings{RootID: ownerID(5)}, contracts.IdentitySettings{}, environment)
		if err != nil || !reflect.DeepEqual(again, out) {
			t.Fatal("rerun replaced original sources", err)
		}
	}
}
