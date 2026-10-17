package kubernetes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// The endpoint is actual loopback TLS; its provider responses and all original
// namespace/activation facts remain synthetic. This qualifies only when the
// endpoint enters original construction, not provider behavior or installation.
func TestHandoverProviderFixtureBindsEndpointBeforeOriginalInput(t *testing.T) {
	provider := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(provider.Close)
	selected := contracts.ConfigurationKeyService{Endpoint: provider.URL, Roots: [][]byte{append([]byte(nil), provider.Certificate().Raw...)}, AuditMount: "transit", AuditKey: "configuration-audit"}
	_, preparer, original := handoverConflictProviderFixture(t, &selected)
	input, err := preparer.inputConfiguration(original)
	if err != nil || !equalJSON(input.KeyService, selected) {
		t.Fatal("provider endpoint did not enter the actual original input", err)
	}
	selected.Endpoint = "https://replaced.example.test"
	selected.Roots[0][0] ^= 1
	again, err := preparer.inputConfiguration(original)
	if err != nil || !equalJSON(again.KeyService, input.KeyService) {
		t.Fatal("caller mutation replaced the protected original provider", err)
	}
	if _, _, _, _, err = preparer.currentHandover(context.Background()); err != nil {
		t.Fatal("selected original provider broke retained native input proof", err)
	}
}
