package integration

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

// Exercise the production HTTP transport through the enrolled fleet's idle
// database lease renewal. No binding event is delivered during this interval.
func idleKubernetesBindingWatch(t *testing.T, cluster string, extras ...http.HandlerFunc) *kubernetes.PermissionClient {
	t.Helper()
	control := cfg.NamespaceRef{Name: "asservat", UID: cluster}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/asservat":
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]string{"name": control.Name, "uid": control.UID, "resourceVersion": "1"}})
		case "/apis/asservat.io/v1alpha1/accessbindings":
			if r.URL.Query().Get("watch") != "true" || r.URL.Query().Get("resourceVersion") != "1" {
				t.Error("unexpected binding watch", r.URL)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			if len(extras) > 0 {
				extras[0](w, r)
			} else {
				http.NotFound(w, r)
			}
		}
	}))
	t.Cleanup(server.Close)
	client, err := kubernetes.NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
