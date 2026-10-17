package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

type regionalSecret struct {
	state fleetapp.ClusterCredentialSecret
}

func (s *regionalSecret) ReadClusterCredential(context.Context) (fleetapp.ClusterCredentialSecret, string, error) {
	return s.state, "1", nil
}
func (s *regionalSecret) WriteClusterCredential(context.Context, string, fleetapp.ClusterCredentialSecret) (string, error) {
	return "", errors.New("unused")
}

type regionalNoExchange struct{}

func (regionalNoExchange) ExchangeClusterCredential(context.Context, value.ClusterCredentialRequest, func([]byte) ([]byte, error)) (int64, error) {
	return 0, errors.New("unused")
}

// verifyingPresenter checks the exporter-bound Ed25519 signature like the hub.
type verifyingPresenter struct {
	public ed25519.PublicKey
	seen   []value.ClusterCredentialRequest
}

func (p *verifyingPresenter) Present(_ context.Context, r value.ClusterCredentialRequest, sig, exporter []byte) (value.ClusterCredentialPresentation, error) {
	if !fleetapp.VerifyClusterCredentialRequest(p.public, r, sig, exporter) {
		return value.ClusterCredentialPresentation{}, value.ErrClusterCredentialDenied
	}
	p.seen = append(p.seen, r)
	now := time.Now()
	return value.ClusterCredentialPresentation{Profile: r.Profile, LineageID: "10000000-0000-4000-8000-000000000009", Operation: r.Operation, Generation: r.Generation, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}

type regionalServices struct {
	usage              string
	ownerConfiguration value.OwnerConfiguration
	candidates         value.APIContextOwnerCandidates
	registration       value.OwnerRegistrationObservation
}

func (s *regionalServices) Enroll(ctx context.Context, native *connectorlifecycle.Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	now := time.Now().UTC()
	op, err := native.BeginConnectorLifecycle(ctx, fleetapp.ConnectorLifecycleRequest{Binding: value.ConnectorLifecycleBinding{ID: id, Purpose: value.ConnectorLifecycleEnroll, Process: r.Process, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}, Request: r})
	if err != nil {
		return value.ConnectorCredentialProcess{}, err
	}
	defer op.Close()
	if _, err = op.Read(ctx, value.ConnectorLifecycleInitial); err != nil {
		return value.ConnectorCredentialProcess{}, err
	}
	return value.ConnectorCredentialProcess{BootstrapID: id, Binding: r.Process.Binding}, nil
}

func (s *regionalServices) Issue(_ context.Context, region *connectorlifecycle.Region, _, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	s.usage = usage
	return value.IssuedConnectorCredential{Certificate: value.ConnectorCredentialCertificate{Binding: r.Process.Binding, Usage: usage, Digest: [32]byte{9}}}, nil
}

func (s *regionalServices) OwnerCandidates(context.Context, *connectorlifecycle.Region) (value.APIContextOwnerCandidates, error) {
	now := time.Now().UTC()
	out := s.candidates
	out.ObservedAt, out.ValidUntil = now, now.Add(time.Second)
	return out, nil
}

func (s *regionalServices) OwnerObservationCandidates(ctx context.Context, region *connectorlifecycle.Region) (value.APIContextOwnerCandidates, error) {
	return s.OwnerCandidates(ctx, region)
}

func (s *regionalServices) OwnerRegistration(_ context.Context, _ *connectorlifecycle.Region, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	if s.registration.Certificate != c {
		return value.OwnerRegistrationObservation{}, value.ErrDenied
	}
	return s.registration, nil
}

func (s *regionalServices) Recovery(_ context.Context, region *connectorlifecycle.Region) (value.RecoveryState, error) {
	now := time.Now().UTC()
	installation := region.Presented().Profile.InstallationID
	return value.RecoveryState{InstallationID: installation, IssuerEpoch: installation, Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(time.Second)}, nil
}

func (s *regionalServices) AuthenticateOwner(_ context.Context, _ *connectorlifecycle.Region, c value.OwnerCertificate) (connectorlifecycle.OwnerAuthentication, error) {
	now := time.Now().UTC()
	cfg := value.OwnerConfigurationObservation{Configuration: s.ownerConfiguration, ObservedAt: now, FreshUntil: now.Add(2 * time.Second)}
	owner := value.AuthenticatedOwner{Certificate: c, EnrollmentID: regionalPod, Pool: cfg.Configuration.Pool, Pod: "owner-0", ReplicaSetUID: regionalEpoch, ConfigurationRevision: cfg.Configuration.Revision, ProtectionDigest: cfg.Configuration.ProtectionDigest, VerifiedAt: now, ValidUntil: now.Add(4 * time.Second)}
	return connectorlifecycle.OwnerAuthentication{Owner: owner, Configuration: cfg}, nil
}

func (s *regionalServices) Registration(ctx context.Context, region *connectorlifecycle.Region, c value.ConnectorCredentialCertificate) (fleetapp.ConnectorLeafRegistration, error) {
	src, err := region.ReadConnectorIdentitySource(ctx)
	if err != nil {
		return fleetapp.ConnectorLeafRegistration{}, err
	}
	// The scripted hub answers for the process that presented.
	p := region.Presented()
	return fleetapp.ConnectorLeafRegistration{Certificate: c, Process: value.ConnectorProcessIdentity{Binding: src.Observation.Profile.Binding, PodUID: regionalPod, ProcessEpoch: regionalEpoch}, Revision: src.Observation.Profile.Revision, ObservedAt: p.CheckedAt}, nil
}

const (
	regionalPod   = "10000000-0000-4000-8000-000000000005"
	regionalEpoch = "10000000-0000-4000-8000-000000000006"
)

type regionalTestLocal struct{ binding value.PeerBinding }

func (l regionalTestLocal) ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error) {
	var s value.ConnectorIdentitySource
	s.Observation.Profile.Binding = l.binding
	return s, nil
}
func (l regionalTestLocal) ReadConnectorIdentityConfiguration(ctx context.Context) (fleetapp.ConnectorIdentityConfiguration, error) {
	s, _ := l.ReadConnectorIdentitySource(ctx)
	return fleetapp.ConnectorIdentityConfiguration{Source: s}, nil
}

type regionalTestOperation struct {
	b value.ConnectorLifecycleBinding
}

func (regionalTestLocal) BeginConnectorLifecycle(_ context.Context, r fleetapp.ConnectorLifecycleRequest) (fleetapp.ConnectorLifecycleOperation, error) {
	return &regionalTestOperation{r.Binding}, nil
}
func (o *regionalTestOperation) Read(_ context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	return value.ConnectorLifecycleObservation{Binding: o.b, Phase: phase, Until: o.b.NotAfter}, nil
}
func (o *regionalTestOperation) Close() {}

func regionalCSR(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// regionalLifecycleFixture serves the real channel handler over TLS 1.3/h2
// with a verifying presenter and scripted hub duties.
func regionalLifecycleFixture(t *testing.T) (*RegionalLifecycle, *regionalServices, value.ConnectorProcessRequest) {
	t.Helper()
	r, services, request, _, _ := regionalLifecycleSetup(t)
	return r, services, request
}

func regionalLifecycleSetup(t *testing.T) (*RegionalLifecycle, *regionalServices, value.ConnectorProcessRequest, *verifyingPresenter, *regionalSecret) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	profile := value.ClusterCredentialProfile{RootID: "10000000-0000-4000-8000-000000000007", PeerID: "10000000-0000-4000-8000-000000000004", InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002"}
	secret := &regionalSecret{fleetapp.ClusterCredentialSecret{Generation: 3, Seed: seed, RotatedAt: time.Now()}}
	presenter := &verifyingPresenter{public: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)}
	services := &regionalServices{}
	h, err := connectorlifecycle.NewHandler(presenter, mtls.EnrollmentProof{}, services, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := connectorlifecycle.NewClient(server.URL, "example.com", roots)
	if err != nil {
		t.Fatal(err)
	}
	process := value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: profile.InstallationID, ClusterID: profile.ClusterID, IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: profile.PeerID, Role: value.ConnectorPeer}, PodUID: regionalPod, ProcessEpoch: regionalEpoch}
	r := &RegionalLifecycle{Client: client, Local: regionalTestLocal{process.Binding}, Credential: fleetapp.ClusterCredentialRotator{Profile: profile, Policy: value.DefaultClusterCredentialPolicy(), Store: secret, Exchange: regionalNoExchange{}, Now: time.Now}, Now: time.Now}
	request := value.ConnectorProcessRequest{Process: process, ClientCSRDER: regionalCSR(t), ServerCSRDER: regionalCSR(t)}
	return r, services, request, presenter, secret
}

func TestRegionalLifecyclePresentsCurrentGenerationOverRealHTTP2(t *testing.T) {
	r, services, request, presenter, secret := regionalLifecycleSetup(t)
	seed := secret.state.Seed
	process := request.Process
	got, err := r.Enroll(context.Background(), "10000000-0000-4000-8000-000000000008", request)
	if err != nil || got.Binding != process.Binding || len(presenter.seen) != 1 || presenter.seen[0].Generation != 3 || presenter.seen[0].Operation != value.ClusterAdmission {
		t.Fatal("regional enrollment", got, err, presenter.seen)
	}
	issued, err := r.IssueProcess(context.Background(), "10000000-0000-4000-8000-00000000000a", "server", request)
	if err != nil || services.usage != "server" || presenter.seen[1].Operation != value.ClusterRenewal {
		t.Fatal("regional renewal", err, services.usage)
	}
	// The registry lookup presents the process that requested the leaf.
	registration, err := r.ConnectorLeafRegistration(context.Background(), issued.Certificate)
	if err != nil || registration.Process != process || len(presenter.seen) != 3 || presenter.seen[2].PodUID != process.PodUID {
		t.Fatal("regional registration", registration, err)
	}
	unknown := issued.Certificate
	unknown.Digest = [32]byte{8}
	if _, err = r.ConnectorLeafRegistration(context.Background(), unknown); err == nil || len(presenter.seen) != 3 {
		t.Fatal("leaf this adapter never received was looked up", err)
	}
	// A pending rotation stops presentations until it completes.
	secret.state.PendingSeed = seed
	if _, err = r.Enroll(context.Background(), "10000000-0000-4000-8000-00000000000b", request); err == nil || len(presenter.seen) != 3 {
		t.Fatal("presented while a rotation was pending", err)
	}
	secret.state.PendingSeed = nil
	// A process for another peer is refused before any connection.
	other := request
	other.Process.Binding.PeerID = "10000000-0000-4000-8000-0000000000ff"
	if _, err = r.Enroll(context.Background(), "10000000-0000-4000-8000-00000000000c", other); err == nil || len(presenter.seen) != 3 {
		t.Fatal("foreign profile presented", err)
	}
}

// fakeOwnerSession stands for an actual verified TLS session to a hub owner.
type fakeOwnerSession struct {
	certificate value.OwnerCertificate
	reject      bool
	seen        value.OwnerConfigurationObservation
}

func (f *fakeOwnerSession) OwnerCertificate() (value.OwnerCertificate, error) {
	return f.certificate, nil
}
func (f *fakeOwnerSession) VerifyCurrentOwner(c value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	f.seen = c
	if f.reject {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return f.certificate, nil
}

// ADR-172: owner reads are presented by the admitted process; an owner is
// authenticated only when this side's own session verifies against the hub's
// returned configuration.
func TestRegionalLifecycleOwnerReadsRequireLocalSessionVerification(t *testing.T) {
	r, services, request := regionalLifecycleFixture(t)
	if _, err := r.ReadContextStartOwners(context.Background()); err == nil {
		t.Fatal("owner read before any admitted process")
	}
	if _, err := r.RecoveryState(context.Background()); err == nil {
		t.Fatal("recovery read before any admitted process")
	}
	if _, err := r.Enroll(context.Background(), "10000000-0000-4000-8000-000000000008", request); err != nil {
		t.Fatal(err)
	}
	der := make([]byte, 8)
	const id = "10000000-0000-4000-8000-000000000010"
	pool := value.OwnerPool{InstallationID: request.Process.Binding.InstallationID, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 9443, NativePort: 9444}
	services.candidates = value.APIContextOwnerCandidates{Pool: pool, Owners: []value.OwnerBinding{{InstallationID: pool.InstallationID, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}}}
	if recovery, err := r.RecoveryState(context.Background()); err != nil || recovery.InstallationID != request.Process.Binding.InstallationID {
		t.Fatal("delegated recovery state", recovery, err)
	}
	owners, err := r.ReadContextStartOwners(context.Background())
	if err != nil || len(owners.Owners) != 1 || owners.Pool != pool {
		t.Fatal("owner candidates", owners, err)
	}
	services.ownerConfiguration = value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{5}, IssuerRoots: [][]byte{der}}
	now := time.Now().UTC()
	certificate := value.OwnerCertificate{Binding: value.OwnerBinding{InstallationID: request.Process.Binding.InstallationID, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}, Usage: "server", Digest: artifact.Digest{3}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute)}
	session := &fakeOwnerSession{certificate: certificate}
	if !services.ownerConfiguration.Valid() {
		t.Fatal("synthetic owner configuration invalid")
	}
	owner, err := r.AuthenticateOwner(context.Background(), session)
	if err != nil || owner.Certificate != certificate || !session.seen.Configuration.Equal(services.ownerConfiguration) {
		t.Fatal("owner authentication", owner, err)
	}
	session.reject = true
	if _, err = r.AuthenticateOwner(context.Background(), session); err == nil {
		t.Fatal("hub answer authenticated a session that failed local verification")
	}
}

// ADR-197: the region's capacity owner reads are read-only conversations
// presented by its admitted process; a registration answer must name exactly
// the requested owner certificate.
func TestRegionalLifecycleCapacityOwnerReads(t *testing.T) {
	r, services, request := regionalLifecycleFixture(t)
	if _, err := r.ReadOwnerObservationCandidates(context.Background()); err == nil {
		t.Fatal("observation candidates before any admitted process")
	}
	if _, err := r.Enroll(context.Background(), "10000000-0000-4000-8000-000000000008", request); err != nil {
		t.Fatal(err)
	}
	const id = "10000000-0000-4000-8000-000000000010"
	pool := value.OwnerPool{InstallationID: request.Process.Binding.InstallationID, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 9443, NativePort: 9444}
	services.candidates = value.APIContextOwnerCandidates{Pool: pool, Owners: []value.OwnerBinding{{InstallationID: pool.InstallationID, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}}}
	owners, err := r.ReadOwnerObservationCandidates(context.Background())
	if err != nil || len(owners.Owners) != 1 || owners.Pool != pool {
		t.Fatal("owner observation candidates", owners, err)
	}
	now := time.Now().UTC()
	certificate := value.OwnerCertificate{Binding: value.OwnerBinding{InstallationID: request.Process.Binding.InstallationID, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}, Usage: "server", Digest: artifact.Digest{3}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute)}
	services.registration = value.OwnerRegistrationObservation{Certificate: certificate}
	if got, err := r.ReadOwnerRegistration(context.Background(), certificate); err != nil || got.Certificate != certificate {
		t.Fatal("owner registration", got, err)
	}
	other := certificate
	other.Digest = artifact.Digest{4}
	if _, err = r.ReadOwnerRegistration(context.Background(), other); err == nil {
		t.Fatal("registration of another certificate answered")
	}
	client := certificate
	client.Usage = "client"
	if _, err = r.ReadOwnerRegistration(context.Background(), client); err == nil {
		t.Fatal("registration read of a client certificate accepted")
	}
}
