package connectorlifecycle

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type digestKeys struct{}

func (digestKeys) EnrollmentKey(csr []byte) (artifact.Digest, error) { return sha256.Sum256(csr), nil }

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

// scriptedServices drives the remote reader like the ADR-153 runner would.
type scriptedServices struct {
	phases  []value.ConnectorLifecyclePhase
	sources int
	foreign bool // answer registration with another process
}

func (s *scriptedServices) Enroll(ctx context.Context, native *Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	if _, err := native.ReadConnectorIdentityConfiguration(ctx); err != nil {
		return value.ConnectorCredentialProcess{}, err
	}
	now := time.Now().UTC()
	op, err := native.BeginConnectorLifecycle(ctx, app.ConnectorLifecycleRequest{Binding: value.ConnectorLifecycleBinding{ID: id, Purpose: value.ConnectorLifecycleEnroll, Process: r.Process, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}, Request: r})
	if err != nil {
		return value.ConnectorCredentialProcess{}, err
	}
	defer op.Close()
	for _, phase := range []value.ConnectorLifecyclePhase{value.ConnectorLifecycleInitial, value.ConnectorLifecycleBeforeEffect, value.ConnectorLifecycleBeforeActivation, value.ConnectorLifecycleFinal} {
		if _, err = op.Read(ctx, phase); err != nil {
			return value.ConnectorCredentialProcess{}, err
		}
		s.phases = append(s.phases, phase)
	}
	return value.ConnectorCredentialProcess{BootstrapID: id, Binding: r.Process.Binding}, nil
}
func (s *scriptedServices) Issue(context.Context, *Region, string, string, value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	return value.IssuedConnectorCredential{}, errors.New("unused")
}

func (s *scriptedServices) OwnerCandidates(context.Context, *Region) (value.APIContextOwnerCandidates, error) {
	now := time.Now().UTC()
	return value.APIContextOwnerCandidates{ObservedAt: now, ValidUntil: now.Add(time.Second)}, nil
}

func (s *scriptedServices) OwnerObservationCandidates(ctx context.Context, region *Region) (value.APIContextOwnerCandidates, error) {
	return s.OwnerCandidates(ctx, region)
}

func (s *scriptedServices) OwnerRegistration(context.Context, *Region, value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	return value.OwnerRegistrationObservation{}, errors.New("unused")
}

func (s *scriptedServices) Recovery(_ context.Context, region *Region) (value.RecoveryState, error) {
	now := time.Now().UTC()
	installation := region.Presented().InstallationID
	if s.foreign {
		installation = "10000000-0000-4000-8000-0000000000ee" // another installation's state
	}
	return value.RecoveryState{InstallationID: installation, IssuerEpoch: installation, Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(time.Second)}, nil
}

func (s *scriptedServices) AuthenticateOwner(_ context.Context, _ *Region, c value.OwnerCertificate) (OwnerAuthentication, error) {
	if s.foreign {
		c.Digest = artifact.Digest{0xee} // the hub answers for another owner
	}
	return OwnerAuthentication{Owner: value.AuthenticatedOwner{Certificate: c}}, nil
}

func (s *scriptedServices) Registration(ctx context.Context, region *Region, c value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	for range 2 {
		if _, err := region.ReadConnectorIdentitySource(ctx); err != nil {
			return app.ConnectorLeafRegistration{}, err
		}
		s.sources++
	}
	process := region.process
	if s.foreign {
		process.ProcessEpoch = "10000000-0000-4000-8000-0000000000fe"
	}
	return app.ConnectorLeafRegistration{Certificate: c, Process: process}, nil
}

// localReader answers in-cluster; corrupt makes it return another binding.
type localReader struct{ corrupt bool }

func (l localReader) binding() value.PeerBinding {
	return value.PeerBinding{InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}
}
func (l localReader) ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error) {
	var s value.ConnectorIdentitySource
	s.Observation.Profile.Binding = l.binding()
	if l.corrupt {
		s.Observation.Profile.Binding.PeerID = "10000000-0000-4000-8000-0000000000ff"
	}
	return s, nil
}
func (l localReader) ReadConnectorIdentityConfiguration(ctx context.Context) (app.ConnectorIdentityConfiguration, error) {
	s, _ := localReader{}.ReadConnectorIdentitySource(ctx)
	return app.ConnectorIdentityConfiguration{Source: s}, nil
}

type localOperation struct {
	req     app.ConnectorLifecycleRequest
	corrupt bool
}

// Like the Kubernetes reader, the local side requires every context to end
// no later than the begun operation's original NotAfter.
func bounded(ctx context.Context, notAfter time.Time) bool {
	d, ok := ctx.Deadline()
	return ok && !d.After(notAfter)
}

func (l localReader) BeginConnectorLifecycle(ctx context.Context, r app.ConnectorLifecycleRequest) (app.ConnectorLifecycleOperation, error) {
	if !bounded(ctx, r.Binding.NotAfter) {
		return nil, value.ErrInvalid
	}
	return &localOperation{r, l.corrupt}, nil
}
func (o *localOperation) Read(ctx context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	if !bounded(ctx, o.req.Binding.NotAfter) {
		return value.ConnectorLifecycleObservation{}, value.ErrInvalid
	}
	b := o.req.Binding
	if o.corrupt {
		b.ID = "10000000-0000-4000-8000-0000000000ff"
	}
	return value.ConnectorLifecycleObservation{Binding: b, Phase: phase, Until: b.NotAfter}, nil
}
func (o *localOperation) Close() {}

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
	client, err := NewClient(server.URL, "example.com", roots, syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := NewClient(server.URL, "example.com", roots, func() ([]byte, error) { return []byte("other-token"), nil })
	if err != nil {
		t.Fatal(err)
	}
	process := value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}, PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
	request := value.ConnectorProcessRequest{Process: process, ClientCSRDER: make([]byte, 64), ServerCSRDER: append(make([]byte, 63), 1)}
	enroll := Opening{Purpose: value.ConnectorLifecycleEnroll, OperationID: "10000000-0000-4000-8000-000000000008", Request: request}
	result, err := client.Run(context.Background(), enroll, localReader{})
	if err != nil || result.Kind != "result" || result.Process == nil || result.Process.Binding != process.Binding || len(services.phases) != 4 {
		t.Fatal("delegated enrollment", result, err, services.phases)
	}
	// A token of another cluster never reaches the lifecycle.
	services.phases = nil
	if _, err = stranger.Run(context.Background(), enroll, localReader{}); err == nil || len(services.phases) != 0 {
		t.Fatal("foreign token accepted", err)
	}
	// An observation for another binding is refused by the hub reader.
	result, err = client.Run(context.Background(), enroll, localReader{corrupt: true})
	if err != nil || result.Kind != "failure" || len(services.phases) != 0 {
		t.Fatal("foreign observation accepted", result, err)
	}
	// Registration: a renewal presentation plus this process's own leaf; the
	// hub reads the delegated source and returns only that process's record.
	cert := value.ConnectorCredentialCertificate{Binding: process.Binding, Usage: "client", Digest: artifact.Digest{1}}
	register := func(c *value.ConnectorCredentialCertificate) Opening {
		o := enroll
		o.Purpose, o.Certificate = PurposeRegistration, c
		return o
	}
	result, err = client.Run(context.Background(), register(&cert), localReader{})
	if err != nil || result.Kind != "result" || result.Registration == nil || result.Registration.Certificate != cert || services.sources != 2 {
		t.Fatal("delegated registration", result, err, services.sources)
	}
	services.foreign = true
	if result, err = client.Run(context.Background(), register(&cert), localReader{}); err != nil || result.Kind != "failure" {
		t.Fatal("another process's registration returned", result, err)
	}
	services.foreign, services.sources = false, 0
	if result, err = client.Run(context.Background(), register(&cert), localReader{corrupt: true}); err != nil || result.Kind != "failure" || services.sources != 0 {
		t.Fatal("foreign source accepted", result, err)
	}
	// ADR-172 owner reads under the same renewal presentation.
	ownerOpening := func(purpose value.ConnectorLifecyclePurpose, owner *value.OwnerCertificate) Opening {
		o := enroll
		o.Purpose, o.Owner = purpose, owner
		return o
	}
	if result, err = client.Run(context.Background(), ownerOpening(PurposeOwnerCandidates, nil), localReader{}); err != nil || result.Kind != "result" || result.Owners == nil {
		t.Fatal("owner candidates", result, err)
	}
	if result, err = client.Run(context.Background(), ownerOpening(PurposeRecovery, nil), localReader{}); err != nil || result.Kind != "result" || result.Recovery == nil {
		t.Fatal("recovery state", result, err)
	}
	services.foreign = true
	if result, err = client.Run(context.Background(), ownerOpening(PurposeRecovery, nil), localReader{}); err != nil || result.Kind != "failure" {
		t.Fatal("another installation's recovery state returned", result, err)
	}
	services.foreign = false
	ownerCert := value.OwnerCertificate{Binding: value.OwnerBinding{InstallationID: process.Binding.InstallationID}, Usage: "server", Digest: artifact.Digest{7}}
	if result, err = client.Run(context.Background(), ownerOpening(PurposeOwnerAuthentication, &ownerCert), localReader{}); err != nil || result.Kind != "result" || result.Owner == nil || result.Owner.Owner.Certificate != ownerCert {
		t.Fatal("owner authentication", result, err)
	}
	services.foreign = true
	if result, err = client.Run(context.Background(), ownerOpening(PurposeOwnerAuthentication, &ownerCert), localReader{}); err != nil || result.Kind != "failure" {
		t.Fatal("answer for another owner returned", result, err)
	}
	services.foreign = false
	clientCert := ownerCert
	clientCert.Usage = "client"
	for _, bad := range []Opening{ownerOpening(PurposeOwnerAuthentication, nil), ownerOpening(PurposeOwnerAuthentication, &clientCert), ownerOpening(PurposeOwnerCandidates, &ownerCert), ownerOpening(PurposeRecovery, &ownerCert)} {
		if _, err = client.Run(context.Background(), bad, localReader{}); err == nil {
			t.Fatal("owner opening without a server certificate, or one on another purpose, accepted")
		}
	}
	other := cert
	other.Binding.PeerID = "10000000-0000-4000-8000-0000000000ff"
	for _, bad := range []Opening{register(&other), register(nil)} {
		if _, err = client.Run(context.Background(), bad, localReader{}); err == nil {
			t.Fatal("registration opening for another peer or without a leaf accepted")
		}
	}
}
