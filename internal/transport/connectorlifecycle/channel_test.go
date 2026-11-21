package connectorlifecycle

import (
	"asservat.local/asservat/internal/contracts"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// acceptTokens attributes the synthetic token to the test cluster.
type acceptTokens struct{ calls int }

func (p *acceptTokens) VerifyConnector(_ context.Context, token string) (value.ConnectorCluster, error) {
	p.calls++
	if token != "synthetic-token" {
		return value.ConnectorCluster{}, value.ErrDenied
	}
	b := localReader{}.binding()
	return value.ConnectorCluster{RootID: "10000000-0000-4000-8000-000000000007", PeerID: b.PeerID, InstallationID: b.InstallationID, ClusterID: b.ClusterID}, nil
}

func syntheticToken() ([]byte, error) { return []byte("synthetic-token"), nil }

// scriptedServices answers the read-only purposes; foreign answers for
// another installation or owner.
type scriptedServices struct {
	foreign bool
}

func (s *scriptedServices) AuthenticateOwner(_ context.Context, c value.OwnerCertificate) (OwnerAuthentication, error) {
	if s.foreign {
		c.Digest = artifact.Digest{0xee} // the hub answers for another owner
	}
	return OwnerAuthentication{Owner: value.AuthenticatedOwner{Certificate: c}}, nil
}

// localReader names the test connector's binding.
type localReader struct{}

func (localReader) binding() value.PeerBinding {
	return value.PeerBinding{InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}
}

func testProcess() value.ConnectorProcessIdentity {
	return value.ConnectorProcessIdentity{Binding: localReader{}.binding(), PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
}

func TestDelegatedLifecycleChannelOverRealHTTP2(t *testing.T) {
	services := &scriptedServices{}
	h, err := NewHandler(&acceptTokens{}, services, 2)
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
	client, err := NewClient(server.URL, roots, syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := NewClient(server.URL, roots, func() ([]byte, error) { return []byte("other-token"), nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, opening := range []Opening{
		{Purpose: PurposeSettings},
		{Purpose: PurposeSettings, Protocol: contracts.ConnectorProtocolMajor + 1},
		{Purpose: "owner-candidates", Protocol: 1, Process: testProcess()},
	} {
		opening.OperationID = "10000000-0000-4000-8000-000000000008"
		frame, err := client.Run(t.Context(), opening, nil)
		var mismatch *ProtocolMismatch
		if !errors.As(err, &mismatch) || mismatch.Announced != opening.Protocol || mismatch.Required != contracts.ConnectorProtocolMajor || frame.Settings != nil {
			t.Fatalf("%s negotiation for major %d: frame=%+v error=%v", opening.Purpose, opening.Protocol, frame, err)
		}
	}
	process := testProcess()
	base := Opening{Purpose: PurposeAccessBindings, Protocol: contracts.ConnectorProtocolMajor, OperationID: "10000000-0000-4000-8000-000000000008", Process: process}
	// A token of another cluster never reaches the services.
	if _, err = stranger.Run(context.Background(), base, nil); err == nil {
		t.Fatal("foreign token accepted")
	}
	// A process of another peer is refused for this token.
	other := base
	other.Process.Binding.PeerID = "10000000-0000-4000-8000-0000000000ff"
	if _, err = client.Run(context.Background(), other, nil); err == nil {
		t.Fatal("opening for another peer accepted")
	}
	unknown := base
	unknown.Purpose = "enroll"
	if _, err = client.Run(context.Background(), unknown, nil); err == nil {
		t.Fatal("removed purpose accepted")
	}
	var result HubFrame
	// ADR-172 owner reads.
	ownerOpening := func(purpose Purpose, owner *value.OwnerCertificate) Opening {
		o := base
		o.Purpose, o.Owner = purpose, owner
		return o
	}
	ownerCert := value.OwnerCertificate{Binding: value.OwnerBinding{InstallationID: process.Binding.InstallationID}, Usage: "server", Digest: artifact.Digest{7}}
	if result, err = client.Run(context.Background(), ownerOpening(PurposeOwnerAuthentication, &ownerCert), nil); err != nil || result.Kind != "result" || result.Owner == nil || result.Owner.Owner.Certificate != ownerCert {
		t.Fatal("owner authentication", result, err)
	}
	services.foreign = true
	if result, err = client.Run(context.Background(), ownerOpening(PurposeOwnerAuthentication, &ownerCert), nil); err != nil || result.Kind != "failure" {
		t.Fatal("answer for another owner returned", result, err)
	}
	services.foreign = false
	clientCert := ownerCert
	clientCert.Usage = "client"
	for _, bad := range []Opening{ownerOpening(PurposeOwnerAuthentication, nil), ownerOpening(PurposeOwnerAuthentication, &clientCert), ownerOpening(PurposeAccessBindings, &ownerCert)} {
		if _, err = client.Run(context.Background(), bad, nil); err == nil {
			t.Fatal("owner opening without a server certificate, or one on another purpose, accepted")
		}
	}
}

// The token is verified before a concurrency slot is taken or the opening is
// read: an invalid token is refused while its body stays open, and it never
// holds the only slot.
func TestHandlerVerifiesTokenBeforeSlotAndOpening(t *testing.T) {
	h, err := NewHandler(&acceptTokens{}, &scriptedServices{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	body, writer := io.Pipe()
	defer writer.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL+Path, body)
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Authorization", "Bearer other-token")
	done := make(chan int, 1)
	go func() {
		resp, err := server.Client().Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case code := <-done:
		if code != http.StatusUnauthorized {
			t.Fatal("invalid token status", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("invalid token waited for the opening")
	}
	if len(h.slots) != 0 {
		t.Fatal("invalid token held a slot")
	}
}
