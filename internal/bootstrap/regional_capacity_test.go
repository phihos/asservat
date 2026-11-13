package bootstrap

import (
	"net/http/httptest"
	"os"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ADR-197 CI continuation run 10: the guarded read's metadata calls shared
// the native reader's limiter and starved its final bracket. The two capacity
// clients must each keep their own fixed limiter.
func TestRegionalCapacityClientsKeepSeparateLimiters(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	files, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	in := &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}}
	control := cfg.NamespaceRef{Name: "connector", UID: runtimeID}
	probe := cfg.NamespaceRef{Name: "connector-capacity-probe", UID: runtimeID}
	observer, metadata, err := regionalCapacityClients(in, &regionalAPIStats{}, runtimeID, control, probe)
	if err != nil {
		t.Fatal(err)
	}
	if observer.SharesLimiter(metadata) {
		t.Fatal("capacity metadata shares the native reader's limiter")
	}
	copied, err := kube.NewPermissionClientFrom(observer, probe)
	if err != nil || !copied.SharesLimiter(observer) {
		t.Fatal("a scoped copy must report its shared limiter", err)
	}
}
