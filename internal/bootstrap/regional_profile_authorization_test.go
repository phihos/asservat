package bootstrap

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/planning"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRegionalProfileAuthorizationPrivateFileAndPublicSource(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	source := planning.GoEndpointSource{ClusterID: "00000000-0000-4000-8000-000000000001", ResourceUID: "00000000-0000-4000-8000-000000000002", Name: "pprof", Digest: artifact.Digest{1}}
	r := &regionalProfileAuthorizationReader{inputs: &providerInputs{files: root}, policies: map[string]planning.GoEndpointSource{source.Name: source}}
	a := contracts.RegionalProfileAuthorization{Format: contracts.RegionalProfileAuthorizationFormat, Entries: []contracts.RegionalProfileAuthorizationEntry{{Name: "pprof", Authorization: []byte("Bearer synthetic-private-sentinel")}}}
	raw, _ := json.Marshal(a)
	if err = os.WriteFile(filepath.Join(dir, contracts.RegionalProfileAuthorizationFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.load(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer r.close()
	got, err := r.ReadProfileAuthorization(t.Context(), source)
	if err != nil || string(got) != "Bearer synthetic-private-sentinel" {
		t.Fatal("selected private value unavailable", err)
	}
	got[0] = 'X'
	again, err := r.ReadProfileAuthorization(t.Context(), source)
	if err != nil || again[0] != 'B' {
		t.Fatal("value aliases earlier delivery", err)
	}
	source.Digest[0]++
	if _, err = r.ReadProfileAuthorization(t.Context(), source); err == nil {
		t.Fatal("different accepted policy read material")
	}
	source.Digest[0]--
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = r.ReadProfileAuthorization(ctx, source); err == nil {
		t.Fatal("cancelled read allowed")
	}
	a.Entries[0].Name = "another"
	raw, _ = json.Marshal(a)
	os.WriteFile(filepath.Join(dir, contracts.RegionalProfileAuthorizationFile), raw, 0600)
	if held, err := r.ReadProfileAuthorization(t.Context(), source); err != nil || string(held) != "Bearer synthetic-private-sentinel" {
		t.Fatal("projection replacement changed immutable startup material", err)
	}
	fresh := &regionalProfileAuthorizationReader{inputs: r.inputs, policies: r.policies}
	if err := fresh.load(t.Context()); err == nil {
		t.Fatal("unknown entry allowed at startup")
	}
	r.close()
	if _, err := r.ReadProfileAuthorization(t.Context(), source); err == nil {
		t.Fatal("closed provider retained authority")
	}
}

func TestRegionalProfileAuthorizationStartupBindingAndLegacyZeroRead(t *testing.T) {
	cluster := "00000000-0000-4000-8000-000000000001"
	empty := regionalConfig{ConnectorConfig: contracts.ConnectorConfig{ClusterID: cluster, Executor: &contracts.ConnectorExecutorConfig{}}}
	if r, err := newRegionalProfileAuthorizationReader(t.Context(), &providerInputs{}, empty); err != nil || r != nil {
		t.Fatal("legacy startup required a credential file", err)
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	empty.Executor.ProfileEndpoints = []contracts.RegionalProfileEndpoint{{Name: "pprof", Kind: "profile", AddressMode: "targetLoopback", Port: 6060, LoopbackFamily: "ipv4", TLS: &contracts.RegionalProfileEndpointTLS{ServerName: "localhost", RootsPEM: roots}, Credential: &contracts.RegionalProfileEndpointCredential{Audiences: []contracts.RegionalProfileEndpointAudience{{ClusterID: cluster, NamespaceUID: "00000000-0000-4000-8000-000000000002", WorkloadKind: "Pod", WorkloadUID: "00000000-0000-4000-8000-000000000003"}}}}}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	in := &providerInputs{files: root}
	if _, err := newRegionalProfileAuthorizationReader(t.Context(), in, empty); err == nil {
		t.Fatal("missing startup material accepted")
	}
	a := contracts.RegionalProfileAuthorization{Format: contracts.RegionalProfileAuthorizationFormat, Entries: []contracts.RegionalProfileAuthorizationEntry{{Name: "pprof", Authorization: []byte("Bearer synthetic")}}}
	b, _ := json.Marshal(a)
	os.WriteFile(filepath.Join(dir, contracts.RegionalProfileAuthorizationFile), b, 0600)
	r, err := newRegionalProfileAuthorizationReader(t.Context(), in, empty)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	for _, source := range r.policies {
		if value, err := r.ReadProfileAuthorization(t.Context(), source); err != nil || string(value) != "Bearer synthetic" {
			t.Fatal("accepted named input unavailable", err)
		}
	}
}
