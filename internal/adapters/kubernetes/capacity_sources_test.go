package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-190: the capacity sources are created once; a rerun reopens the exact
// objects, and a probe namespace already carrying a selector key is refused.
func TestCapacitySourcesCreateReopenAndRefuseLabeledProbe(t *testing.T) {
	installation := ownerID(1)
	_, _, probeName, sourceName, _ := CapacitySourceNames(installation)
	for _, labeled := range []bool{false, true} {
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
				m["uid"] = strings.Replace("10000000-0000-4000-8000-0000000000xx", "xx", string(rune('a'+uid/10))+string(rune('0'+uid%10)), 1)
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
		if labeled {
			objects["/api/v1/namespaces/"+probeName] = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": probeName, "uid": ownerID(9), "labels": map[string]any{"team": "x"}}}
		}
		config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
		control := cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}
		admins := []cfg.KubernetesActor{{Kind: "User", Name: "system:serviceaccount:install:runner"}}
		worker := contracts.WorkerObjectReference{Name: "worker", UID: ownerID(3)}
		owner := contracts.WorkerObjectReference{Name: "owner", UID: ownerID(6)}
		processing := contracts.DownloadEnvironmentSettings{Format: contracts.DownloadEnvironmentFormat, RootID: ownerID(4), InstallationID: installation, RecoveryEpoch: ownerID(5), Revision: 1, PermittedRegions: []string{}, Paths: []contracts.DownloadEnvironmentPath{}, Clients: []contracts.DownloadEnvironmentClient{}, Operators: []contracts.ProcessingOperator{{ClientID: "console", Issuer: "https://issuer.invalid/realms/x", Kind: "User", ID: "operator"}}}
		out, err := EnsureCapacitySources(context.Background(), config, control, installation, admins, worker, owner, []string{"team"}, processing)
		if labeled {
			if !errors.Is(err, cfg.ErrChanged) {
				t.Fatal("adopted a probe namespace carrying a selector key", err)
			}
			continue
		}
		if err != nil || out.Guard.PolicyUID == "" || out.NamespaceGuard.PolicyUID == "" || out.ProcessingGuard.PolicyUID == "" || out.ProbeNamespace.Name != probeName || out.ProbeAccount.Name != CapacityProbeAccount || out.ProcessingSource.Name != sourceName {
			t.Fatal("capacity sources", err, out)
		}
		role := objects["/apis/rbac.authorization.k8s.io/v1/clusterroles/"+probeName]
		if raw, _ := json.Marshal(role["rules"]); string(raw) != `[{"apiGroups":[""],"resourceNames":["`+probeName+`"],"resources":["namespaces"],"verbs":["get","update"]}]` {
			t.Fatal("probe account holds more than its own namespace", string(raw))
		}
		again, err := EnsureCapacitySources(context.Background(), config, control, installation, admins, worker, owner, []string{"team"}, processing)
		if err != nil || !reflect.DeepEqual(again, out) {
			t.Fatal("rerun did not reopen the exact sources", err)
		}
	}
}
