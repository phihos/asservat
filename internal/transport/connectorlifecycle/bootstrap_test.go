package connectorlifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// bootstrapKeys is a synthetic proof port: the CSR bytes are the raw key.
type bootstrapKeys struct{ digestKeys }

func (bootstrapKeys) BootstrapKey(csr []byte) (ed25519.PublicKey, artifact.Digest, error) {
	return ed25519.PublicKey(csr), app.ClusterBootstrapKeyDigest(ed25519.PublicKey(csr)), nil
}
func (bootstrapKeys) BootstrapSecretDigest(_, _, secret string) (artifact.Digest, error) {
	return sha256.Sum256([]byte(secret)), nil
}

type bootstrapServices struct {
	scriptedServices
	slot value.PeerBinding
	read bool
}

func (s *bootstrapServices) Bootstrap(ctx context.Context, region *Region, r value.ClusterBootstrapRequest, key ed25519.PublicKey) (value.ClusterBootstrapResult, error) {
	if err := region.BindBootstrap(s.slot); err != nil {
		return value.ClusterBootstrapResult{}, err
	}
	if region.BindBootstrap(s.slot) == nil {
		return value.ClusterBootstrapResult{}, ErrChannel // binds once only
	}
	if _, err := region.ReadConnectorIdentityConfiguration(ctx); err != nil {
		return value.ClusterBootstrapResult{}, err
	}
	s.read = true
	now := time.Now()
	return value.ClusterBootstrapResult{LineageID: "10000000-0000-4000-8000-000000000099", Generation: 1, KeyDigest: r.KeyDigest, IssuedAt: now, ValidUntil: now.Add(time.Hour)}, nil
}

// ADR-193: the bootstrap opening is verified before any reply, the hub binds
// the conversation to the claimed slot once, and a source outside that slot
// is refused.
func TestBootstrapConversationOverRealHTTP2(t *testing.T) {
	local := localReader{}
	services := &bootstrapServices{slot: local.binding()}
	h, err := NewHandler(&acceptPresenter{}, bootstrapKeys{}, services, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(server.URL, "example.com", roots)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 5
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	b := local.binding()
	open := func(signer ed25519.PrivateKey) func([]byte) (Opening, error) {
		return func(exporter []byte) (Opening, error) {
			r := value.ClusterBootstrapRequest{InstallationID: b.InstallationID, BootstrapID: "10000000-0000-4000-8000-000000000011", RootID: "10000000-0000-4000-8000-000000000007", ClusterID: b.ClusterID, PeerID: b.PeerID, IssuerEpoch: b.IssuerEpoch,
				KeyDigest: app.ClusterBootstrapKeyDigest(public), SecretDigest: sha256.Sum256([]byte("synthetic-secret")), RequestedAt: time.Now().UTC().Truncate(time.Microsecond)}
			signature, err := app.SignClusterBootstrapRequest(signer, r, exporter)
			return Opening{Purpose: PurposeBootstrap, Bootstrap: &BootstrapOpening{Secret: "synthetic-secret", CSRDER: public, Request: r, Signature: signature}}, err
		}
	}
	result, err := client.Run(context.Background(), open(private), local)
	if err != nil || result.Kind != "result" || result.Bootstrap == nil || result.Bootstrap.Generation != 1 || !services.read {
		t.Fatal("bootstrap conversation", result, err)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	services.read = false
	if _, err = client.Run(context.Background(), open(other), local); err == nil || services.read {
		t.Fatal("signature of another key accepted", err)
	}
	services.slot.PeerID = "10000000-0000-4000-8000-0000000000ee"
	if result, err = client.Run(context.Background(), open(private), local); err != nil || result.Kind != "failure" || services.read {
		t.Fatal("source outside the claimed slot accepted", result, err)
	}
}
