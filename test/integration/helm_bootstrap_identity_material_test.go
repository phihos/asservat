package integration

import (
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestHelmBundledIdentityReadsStrictOriginalWireMaterial(t *testing.T) {
	settings := contracts.SmallKeycloakSettings{Namespace: "bootstrap", SecretName: "install-keycloak-state", Hostname: "https://identity.example", Realm: "asservat", Origin: "https://console.example", ConsoleClientID: "asservat-console", BrowserAudience: "asservat-api", MCPClientID: "asservat-mcp", MCPRedirectURIs: []string{"http://127.0.0.1:42000/callback"}, ProcessingOperators: true, Database: contracts.SmallKeycloakDatabase{Host: "install-postgres.bootstrap.svc", Port: 5432, Database: "keycloak", Username: "keycloak"}}
	source, err := bootstrap.BuildSmallKeycloakMaterial(settings, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source.UID, source.ResourceVersion = "original-state", "1"
	reads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/bootstrap/secrets/install-keycloak-state" {
			t.Error("nonexact source read")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(source)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := api.CoreV1().Secrets(settings.Namespace).Get(t.Context(), settings.SecretName, meta.GetOptions{})
	if err != nil || typed.Kind != "" || typed.APIVersion != "" || bootstrap.ValidateSmallKeycloakMaterial(settings, typed) == nil {
		t.Fatal("typed decoder did not reproduce lost wire GVK", err)
	}
	reads = 0
	actual, err := readHelmBundledKeycloakMaterial(t.Context(), config, settings)
	if err != nil || actual.Kind != "Secret" || actual.APIVersion != "v1" || actual.UID != source.UID || reads != 1 {
		t.Fatal("strict original wire material rejected", err, reads)
	}
	for _, change := range []func(){func() { source.Kind = "ConfigMap" }, func() { source.Kind = "Secret"; source.UID = "" }, func() { source.UID = "original-state"; source.Data[contracts.SmallKeycloakSettingsFile] = []byte(`{}`) }} {
		change()
		reads = 0
		if _, err := readHelmBundledKeycloakMaterial(t.Context(), config, settings); err == nil || reads != 1 {
			t.Fatal("changed original source accepted or retried", err, reads)
		}
	}
}
