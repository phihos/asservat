package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestSmallKeycloakStateStoreUsesOnlyNamedReadsAndOneStrictCreate(t *testing.T) {
	gets, posts := 0, 0
	var retained *core.Secret
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if (r.URL.Path == "/api/v1/namespaces/hub/secrets/trial-postgres-state" || r.URL.Path == "/apis/apps/v1/namespaces/hub/deployments/trial-keycloak") && r.Method == http.MethodGet {
			gets++
			http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
			return
		}
		if r.URL.Path == "/api/v1/namespaces/hub/secrets/state" && r.Method == http.MethodGet {
			gets++
			if retained == nil {
				http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
			} else {
				_ = json.NewEncoder(w).Encode(retained)
			}
			return
		}
		if r.URL.Path == "/api/v1/namespaces/hub/secrets" && r.Method == http.MethodPost && r.URL.Query().Get("fieldValidation") == "Strict" {
			posts++
			retained = &core.Secret{}
			if err := json.NewDecoder(r.Body).Decode(retained); err != nil {
				t.Error(err)
			}
			retained.UID = types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
			retained.ResourceVersion = "1"
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(retained)
			return
		}
		t.Errorf("unexpected Kubernetes request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	}))
	defer server.Close()
	settings := contracts.SmallKeycloakSettings{Namespace: "hub", SecretName: "state"}
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	store, err := NewSmallKeycloakStateStore(config, settings, "trial-postgres-state", "trial-keycloak", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(t.Context()); !apierrors.IsNotFound(err) {
		t.Fatal("missing state changed classification", err)
	}
	if exists, err := store.DatabaseStateExists(t.Context()); err != nil || exists {
		t.Fatal("missing DB state changed classification", err)
	}
	secret := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Namespace: "hub", Name: "state"}, Data: map[string][]byte{"private": []byte("synthetic-private")}}
	if _, err = store.Create(t.Context(), secret); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(t.Context()); err != nil {
		t.Fatal(err)
	}
	if gets != 4 || posts != 1 {
		t.Fatalf("unexpected bounded request count GET=%d POST=%d", gets, posts)
	}
	external, err := NewSmallKeycloakStateStore(config, settings, "", "trial-keycloak", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = external.DatabaseStateExists(t.Context()); err == nil || gets != 5 {
		t.Fatal("invented external database emptiness from Kubernetes")
	}
	secret.Name = "foreign"
	if _, err = store.Create(t.Context(), secret); err == nil || posts != 1 {
		t.Fatal("created unselected Secret")
	}
}

func TestSmallKeycloakStateStoreRejectsOversizedOrUnknownJSON(t *testing.T) {
	for _, body := range []string{`{"kind":"Secret","apiVersion":"v1","unknown":"field"}`, strings.Repeat(" ", contracts.SmallKeycloakStateMaxBytes) + `{}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		store, err := NewSmallKeycloakStateStore(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, contracts.SmallKeycloakSettings{Namespace: "hub", SecretName: "state"}, "db-state", "trial-keycloak", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Read(t.Context()); err == nil {
			t.Fatal("accepted oversized/unknown state JSON")
		}
		server.Close()
	}
}

func TestSmallKeycloakStateExternalDatabaseProofRequiresMissingDeployment(t *testing.T) {
	for _, status := range []int{200, 404, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls, proofs := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/apis/apps/v1/namespaces/hub/deployments/trial-keycloak" {
					t.Error("unselected observation")
				}
				w.Header().Set("Content-Type", "application/json")
				if status == 200 {
					_, _ = w.Write([]byte(`{"kind":"Deployment","apiVersion":"apps/v1"}`))
					return
				}
				w.WriteHeader(status)
				if status == 404 {
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`))
				} else {
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","reason":"Forbidden","code":403}`))
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			proof := func(context.Context) (bool, error) { proofs++; return false, nil }
			store, err := NewSmallKeycloakStateStore(config, contracts.SmallKeycloakSettings{Namespace: "hub", SecretName: "state"}, "", "trial-keycloak", proof)
			if err != nil {
				t.Fatal(err)
			}
			exists, err := store.DatabaseStateExists(t.Context())
			if calls != 1 {
				t.Fatal("unexpected repeated observation")
			}
			switch status {
			case 200:
				if err != nil || !exists || proofs != 0 {
					t.Fatal("retained workload reached external SQL or replacement")
				}
			case 404:
				if err != nil || exists || proofs != 1 {
					t.Fatal("missing workload did not require exact external proof")
				}
			case 403:
				if err == nil || proofs != 0 {
					t.Fatal("unavailable workload observation fell through to SQL")
				}
			}
			if status == 404 {
				store.externalPresence = func(context.Context) (bool, error) { return false, errors.New("unavailable proof") }
				if _, err = store.DatabaseStateExists(t.Context()); err == nil {
					t.Fatal("unavailable external database observation admitted initialization")
				}
			}
		})
	}
}
