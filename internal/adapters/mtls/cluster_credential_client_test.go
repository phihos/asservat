package mtls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clustercredential"
)

// Applies decisions like the SQL adapter; real PostgreSQL is qualified separately.
type clusterExchangeStore struct {
	lineage value.ClusterCredentialLineage
	creds   map[int64]*value.ClusterCredential
}

func (s *clusterExchangeStore) Decide(_ context.Context, r value.ClusterCredentialRequest, decide fleetapp.ClusterCredentialDecider) (value.ClusterCredentialPresentation, error) {
	now := time.Now().UTC()
	d, err := decide(s.lineage, s.creds[r.Generation], s.creds[s.lineage.Current], now)
	if err != nil {
		return value.ClusterCredentialPresentation{}, err
	}
	if d.Kind == value.ClusterFork {
		s.lineage.Fenced = "fork"
		return value.ClusterCredentialPresentation{}, value.ErrClusterCredentialFenced
	}
	return value.ClusterCredentialPresentation{Profile: s.lineage.Profile, LineageID: s.lineage.ID, Operation: r.Operation, Generation: s.lineage.Current, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}

func TestClusterCredentialExchangeOverRealTLS(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	profile := value.ClusterCredentialProfile{RootID: "10000000-0000-4000-8000-000000000001", PeerID: "10000000-0000-4000-8000-000000000002", InstallationID: "10000000-0000-4000-8000-000000000003", ClusterID: "10000000-0000-4000-8000-000000000004"}
	now := time.Now().UTC()
	store := &clusterExchangeStore{lineage: value.ClusterCredentialLineage{Profile: profile, ID: "10000000-0000-4000-8000-000000000005", Policy: value.DefaultClusterCredentialPolicy(), Current: 1}, creds: map[int64]*value.ClusterCredential{1: {Generation: 1, PublicKey: public, IssuedAt: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}}}
	h, err := clustercredential.NewHandler(fleetapp.ClusterCredentialVerifier{Store: store}, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClusterCredentialClient(server.URL, "example.com", roots)
	if err != nil {
		t.Fatal(err)
	}
	request := func() value.ClusterCredentialRequest {
		return value.ClusterCredentialRequest{Operation: value.ClusterAdmission, Profile: profile, Generation: 1, PodUID: "10000000-0000-4000-8000-000000000010", ProcessEpoch: "10000000-0000-4000-8000-000000000011", ClientKey: artifact.Digest{1}, ServerKey: artifact.Digest{2}, RequestedAt: time.Now().UTC().Truncate(time.Microsecond)}
	}
	signer := func(r value.ClusterCredentialRequest) func([]byte) ([]byte, error) {
		return func(exporter []byte) ([]byte, error) {
			return fleetapp.SignClusterCredentialRequest(private, r, exporter)
		}
	}
	r := request()
	reply, err := client.Exchange(context.Background(), r, signer(r))
	if err != nil || reply.Generation != 1 || reply.LineageID != store.lineage.ID {
		t.Fatal("exporter-bound admission over TLS", reply, err)
	}
	// A signature produced for any other connection's exporter is refused.
	r = request()
	captured, _ := fleetapp.SignClusterCredentialRequest(private, r, make([]byte, 32))
	if _, err = client.Exchange(context.Background(), r, func([]byte) ([]byte, error) { return captured, nil }); !errors.Is(err, value.ErrClusterCredentialDenied) {
		t.Fatal("relayed signature accepted", err)
	}
	// Untrusted hub roots never reach the handler.
	other, err := NewClusterCredentialClient(server.URL, "example.com", x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	r = request()
	if _, err = other.Exchange(context.Background(), r, signer(r)); !errors.Is(err, value.ErrClusterCredentialDenied) {
		t.Fatal("unpinned hub accepted", err)
	}
	store.lineage.Fenced = "revoked"
	r = request()
	if _, err = client.Exchange(context.Background(), r, signer(r)); !errors.Is(err, value.ErrClusterCredentialFenced) {
		t.Fatal("permanent fence not distinguishable", err)
	}
	if _, err = NewClusterCredentialClient("http://"+server.Listener.Addr().String(), "example.com", roots); err == nil {
		t.Fatal("plain HTTP endpoint accepted")
	}
}
