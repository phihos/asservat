package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// The provider endpoint and CA exist before the original preparer binds them.
// Responses model exact setup recipes over actual TLS; they are explicitly
// synthetic provider state, not a real OpenBao or scoped-IAM qualification.
type ownerOperationProviderFixture struct {
	mu        sync.Mutex
	responses map[string]any
	endpoint  contracts.ConfigurationKeyService
	reader    *providerconfig.SetupReader
	requests  atomic.Int32
	deny      atomic.Bool
}

func newOwnerOperationProviderFixture(t *testing.T) *ownerOperationProviderFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(880001), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	f := &ownerOperationProviderFixture{responses: map[string]any{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != "synthetic-owner-inspection" || r.URL.RawQuery != "" || f.deny.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		data, ok := f.responses[strings.TrimPrefix(r.URL.Path, "/v1/")]
		f.mu.Unlock()
		if !ok {
			t.Error("unselected provider GET", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "auth": nil, "wrap_info": nil, "lease_id": "", "lease_duration": 0, "renewable": false})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.endpoint = contracts.ConfigurationKeyService{Endpoint: server.URL, Roots: [][]byte{der}, AuditMount: "transit", AuditKey: "owner-audit"}
	f.reader, err = providerconfig.NewSetupReader(contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{der}}, []byte("synthetic-owner-inspection"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.reader.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (p *ownerOperationProviderFixture) input(t *testing.T, f *ownerIdentityOperationFixture) contracts.OwnerDeployment {
	t.Helper()
	installOwnerBootstrapAPI(t, f)
	producer, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal("original public selection constructor", err)
	}
	t.Cleanup(producer.Close)
	selectedInput, err := producer.Complete(context.Background())
	if err != nil || selectedInput.Status != OwnerBootstrapComplete {
		t.Fatal("original public selection", err)
	}
	in := selectedInput.Input
	selection := f.resources.ownerProvider
	recipe, err := providerconfig.OwnerProviderRecipeFor(in, selection.AuthMount, selection.AuthMountAccessor, f.root.input.ServiceAccount, selection.AuditCredentials, time.Now())
	if err != nil {
		t.Fatal("original owner authentication recipe", err)
	}
	f.accepted.mu.Lock()
	accepted := f.accepted.value.Configuration.Clone()
	f.accepted.mu.Unlock()
	setup, err := providerconfig.OwnerSetupRecipeFor(in, recipe.Profile, accepted.Pool, accepted.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal("original owner setup recipe", err)
	}
	mapOf := func(value any) map[string]any {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal("public provider recipe")
		}
		return out
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.responses["sys/mounts/auth/"+selection.AuthMount] = map[string]any{"type": "kubernetes", "accessor": selection.AuthMountAccessor, "config": map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 2764800, "token_type": "default-service"}}
	auth := mapOf(setup.AuthConfiguration)
	auth["token_reviewer_jwt_set"] = true
	p.responses["auth/"+selection.AuthMount+"/config"] = auth
	p.responses["sys/mounts/"+in.KeyService.AuditMount] = map[string]any{"type": "transit"}
	p.responses[in.KeyService.AuditMount+"/keys/"+in.KeyService.AuditKey] = map[string]any{"name": in.KeyService.AuditKey, "type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true, "latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0}
	for _, r := range recipe.Roles {
		p.responses["auth/"+selection.AuthMount+"/role/"+r.Name] = r.Role
		p.responses["sys/policies/acl/"+r.Name] = map[string]any{"name": r.Name, "policy": string(r.Policy)}
	}
	p.responses["sys/mounts/"+in.KeyService.PKIMount] = map[string]any{"type": "pki"}
	var roots []byte
	for _, der := range accepted.IssuerRoots {
		roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	p.responses[in.KeyService.PKIMount+"/cert/ca"] = map[string]any{"certificate": string(roots)}
	for _, r := range setup.PKIRoles {
		p.responses[in.KeyService.PKIMount+"/roles/"+r.Name] = r.Role
	}
	return in
}
