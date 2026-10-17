package kubernetes

import (
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// A single-object fake API with resourceVersion compare-and-swap semantics.
type secretAPI struct {
	mu     sync.Mutex
	object core.Secret
	puts   int
}

func (a *secretAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path != "/api/v1/namespaces/connector/secrets/cluster-credential" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPut {
		var in core.Secret
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &in) != nil || in.ResourceVersion != a.object.ResourceVersion {
			w.WriteHeader(http.StatusConflict)
			return
		}
		rv, _ := strconv.Atoi(a.object.ResourceVersion)
		a.object.Data, a.object.ResourceVersion = in.Data, strconv.Itoa(rv+1)
		a.puts++
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.object)
}

func TestClusterCredentialSecretCompareAndSwap(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	initial, _ := json.Marshal(fleetapp.ClusterCredentialSecret{Generation: 1, Seed: seed, RotatedAt: time.Now().UTC()})
	api := &secretAPI{object: core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "cluster-credential", Namespace: "connector", UID: types.UID("10000000-0000-4000-8000-000000000001"), ResourceVersion: "1"}, Data: map[string][]byte{clusterCredentialSecretKey: initial}}}
	server := httptest.NewTLSServer(api)
	defer server.Close()
	client, err := newBoundedAPI(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewClusterCredentialSecret(client, "connector", "cluster-credential", "10000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	state, version, err := store.ReadClusterCredential(t.Context())
	if err != nil || version != "1" || state.Generation != 1 {
		t.Fatal("read", state.Generation, version, err)
	}
	state.PendingSeed = make([]byte, ed25519.SeedSize)
	next, err := store.WriteClusterCredential(t.Context(), version, state)
	if err != nil || next != "2" || api.puts != 1 {
		t.Fatal("pending write", next, err)
	}
	// A stale version (another writer won) is refused without a write.
	if _, err = store.WriteClusterCredential(t.Context(), version, state); err == nil || api.puts != 1 {
		t.Fatal("stale compare-and-swap accepted", err)
	}
	other, _ := NewClusterCredentialSecret(client, "connector", "cluster-credential", "10000000-0000-4000-8000-000000000099")
	if _, _, err = other.ReadClusterCredential(t.Context()); err == nil {
		t.Fatal("replaced Secret UID accepted")
	}
	invalid := state
	invalid.Seed = nil
	if _, err = store.WriteClusterCredential(t.Context(), next, invalid); err == nil || api.puts != 1 {
		t.Fatal("invalid state written", err)
	}
}
