package kubernetes

import (
	"encoding/json"
	"encoding/pem"
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
		if r.URL.Path == "/api/v1/namespaces/hub/secrets/trial-postgres-state" && r.Method == http.MethodGet {
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
	store, err := NewSmallKeycloakStateStore(config, settings, "trial-postgres-state")
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
	if gets != 3 || posts != 1 {
		t.Fatalf("unexpected bounded request count GET=%d POST=%d", gets, posts)
	}
	external, err := NewSmallKeycloakStateStore(config, settings, "")
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := external.DatabaseStateExists(t.Context()); err != nil || exists || gets != 3 {
		t.Fatal("external database state is not observable through Kubernetes")
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
		store, err := NewSmallKeycloakStateStore(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, contracts.SmallKeycloakSettings{Namespace: "hub", SecretName: "state"}, "db-state")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Read(t.Context()); err == nil {
			t.Fatal("accepted oversized/unknown state JSON")
		}
		server.Close()
	}
}
