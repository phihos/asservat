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
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-189: the permission guard is created once with its pin; a rerun reopens
// the exact objects and a foreign policy under the fixed name is refused.
func TestPermissionGuardCreateReopenAndRefuseForeign(t *testing.T) {
	installation := ownerID(1)
	control := contracts.WorkerObjectReference{Name: "hub", UID: ownerID(2)}
	deployment := contracts.PermissionControlDeployment{Namespace: control, StatusUsers: []string{"system:serviceaccount:hub:worker"},
		Guard: contracts.OwnerDeploymentGuard{Name: contracts.PermissionGuardName(installation), Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "system:serviceaccount:install:runner"}}}}
	plan := PermissionAdministrationOf(deployment)
	for _, foreign := range []bool{false, true} {
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
				m["uid"] = strings.Replace("10000000-0000-4000-8000-00000000000x", "x", string(rune('0'+uid)), 1)
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
		if foreign {
			name := contracts.PermissionGuardName(installation)
			objects["/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+name] = map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy", "metadata": map[string]any{"name": name, "uid": ownerID(9), "generation": 1}, "spec": admission.ValidatingAdmissionPolicySpec{}}
		}
		config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
		guard, err := EnsurePermissionGuard(context.Background(), config, plan)
		if foreign {
			if !errors.Is(err, cfg.ErrChanged) {
				t.Fatal("adopted a foreign permission guard", err)
			}
			continue
		}
		if err != nil || guard.Name != contracts.PermissionGuardName(installation) || guard.PolicyUID == "" || guard.BindingUID == "" || guard.PolicyGeneration != 1 || !reflect.DeepEqual(guard.Administrators, deployment.Guard.Administrators) {
			t.Fatal("permission guard", err, guard)
		}
		again, err := EnsurePermissionGuard(context.Background(), config, plan)
		if err != nil || !reflect.DeepEqual(again, guard) {
			t.Fatal("rerun did not reopen the exact guard", err)
		}
	}
}
