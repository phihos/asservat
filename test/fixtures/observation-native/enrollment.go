//go:build ignore

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	"k8s.io/client-go/rest"
)

// Initial CA/acceptance and wrapping keys are explicit fixture roots. A/R own
// their generated process keys. Real SQL permit consumption, encrypted S3 audit,
// activated registry reads and the exact leaf verifiers remain unchanged.
type fixtureWrap struct{ a cipher.AEAD }

func (k fixtureWrap) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	if ctx.Err() != nil {
		return artifact.SealedKey{}, ctx.Err()
	}
	nonce := make([]byte, k.a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return artifact.SealedKey{}, e
	}
	sealed := k.a.Seal(nonce, nonce, b, ad)
	if ctx.Err() != nil {
		clear(sealed)
		return artifact.SealedKey{}, ctx.Err()
	}
	return artifact.SealedKey{Reference: "synthetic-observation-native", Ciphertext: base64.StdEncoding.EncodeToString(sealed)}, nil
}
func (k fixtureWrap) Open(ctx context.Context, key artifact.SealedKey, ad []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	b, e := base64.StdEncoding.DecodeString(key.Ciphertext)
	defer clear(b)
	if e != nil || key.Reference != "synthetic-observation-native" || len(b) < k.a.NonceSize() {
		return nil, errFixture
	}
	out, e := k.a.Open(nil, b[:k.a.NonceSize()], b[k.a.NonceSize():], ad)
	if ctx.Err() != nil {
		clear(out)
		return nil, ctx.Err()
	}
	return out, e
}
func (r *fixtureRuntime) auditStore() (*objectstore.Store, fixtureWrap, error) {
	in := r.input.Audit
	if len(in.WrapKey) != 32 {
		return nil, fixtureWrap{}, errFixture
	}
	block, e := aes.NewCipher(in.WrapKey)
	if e != nil {
		return nil, fixtureWrap{}, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, fixtureWrap{}, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(in.Roots) {
		return nil, fixtureWrap{}, errFixture
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, Proxy: nil, DisableCompression: true, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2}
	r.cleanups = append(r.cleanups, transport.CloseIdleConnections)
	store, e := objectstore.NewVersionedAudit(in.Endpoint, in.Region, in.Bucket, credentials.NewStaticCredentialsProvider(in.AccessKey, in.SecretKey, ""), &http.Client{Transport: transport, Timeout: 30 * time.Second})
	return store, fixtureWrap{aead}, e
}

type fixtureIssuer struct{ owner, client, server fixtureCA }

func parseFixtureCA(in fixtureCA) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	ca, e := x509.ParseCertificate(in.DER)
	if e != nil || !ca.IsCA {
		return nil, nil, errFixture
	}
	parsed, e := x509.ParsePKCS8PrivateKey(in.PKCS8)
	if e != nil {
		return nil, nil, errFixture
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(ca.PublicKey) {
		return nil, nil, errFixture
	}
	return ca, key, nil
}
func fixtureSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
func (s fixtureIssuer) SignOwnerCertificate(ctx context.Context, p value.OwnerCertificatePermit, csr []byte) (value.IssuedOwnerCertificate, error) {
	var zero value.IssuedOwnerCertificate
	if ctx.Err() != nil || !p.Valid(time.Now()) {
		return zero, errFixture
	}
	request, e := x509.ParseCertificateRequest(csr)
	if e != nil || request.CheckSignature() != nil {
		return zero, errFixture
	}
	digest, e := mtls.EnrollmentKey(csr)
	if e != nil || digest != p.PublicKeyDigest {
		return zero, errFixture
	}
	ca, key, e := parseFixtureCA(s.owner)
	if e != nil {
		return zero, e
	}
	uri, e := mtls.OwnerURI(p.Binding)
	if e != nil {
		return zero, e
	}
	serial, e := fixtureSerial()
	if e != nil {
		return zero, e
	}
	template := &x509.Certificate{SerialNumber: serial, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri}, NotBefore: p.CheckedAt.UTC().Truncate(time.Second).Add(-time.Second), NotAfter: p.CertificateNotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if p.Usage == "server" {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		exact, e := mtls.OwnerServerName(p.Binding)
		if e != nil {
			return zero, e
		}
		template.DNSNames = []string{exact}
		if p.Configuration.Configuration.Pool.NativeBootstrap != "" {
			common, e := mtls.OwnerBootstrapServerName(p.Configuration.Configuration.Pool)
			if e != nil {
				return zero, e
			}
			template.DNSNames = append(template.DNSNames, common)
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, ca, request.PublicKey, key)
	if e != nil || ctx.Err() != nil || !p.Valid(time.Now()) {
		return zero, errFixture
	}
	return value.IssuedOwnerCertificate{Certificate: value.OwnerCertificate{Binding: p.Binding, Usage: p.Usage, Digest: sha256.Sum256(der), NotBefore: template.NotBefore, NotAfter: template.NotAfter}, DER: der, ChainDER: [][]byte{ca.Raw}}, nil
}
func (s fixtureIssuer) SignConnectorCredential(ctx context.Context, p value.ConnectorCredentialPermit, csr []byte) (value.IssuedConnectorCredential, error) {
	var zero value.IssuedConnectorCredential
	if ctx.Err() != nil || !p.Valid(time.Now()) {
		return zero, errFixture
	}
	request, e := x509.ParseCertificateRequest(csr)
	if e != nil || request.CheckSignature() != nil {
		return zero, errFixture
	}
	digest, e := mtls.EnrollmentKey(csr)
	if e != nil || digest != p.PublicKeyDigest() {
		return zero, errFixture
	}
	selected, usage, name := s.client, x509.ExtKeyUsageClientAuth, ""
	if p.Usage == "server" {
		selected, usage, name = s.server, x509.ExtKeyUsageServerAuth, p.Configuration.Profile.ServerName
	}
	ca, key, e := parseFixtureCA(selected)
	if e != nil {
		return zero, e
	}
	uri, e := mtls.PeerURI(p.Process.Binding)
	if e != nil {
		return zero, e
	}
	serial, e := fixtureSerial()
	if e != nil {
		return zero, e
	}
	template := &x509.Certificate{SerialNumber: serial, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri}, NotBefore: p.CheckedAt.UTC().Truncate(time.Second).Add(-time.Second), NotAfter: p.CertificateNotAfter, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if name != "" {
		template.DNSNames = []string{name}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, ca, request.PublicKey, key)
	if e != nil || ctx.Err() != nil || !p.Valid(time.Now()) {
		return zero, errFixture
	}
	return value.IssuedConnectorCredential{Certificate: value.ConnectorCredentialCertificate{Binding: p.Process.Binding, Usage: p.Usage, ServerName: name, Digest: sha256.Sum256(der), PublicKeyDigest: p.PublicKeyDigest(), NotBefore: template.NotBefore, NotAfter: template.NotAfter}, DER: der, ChainDER: [][]byte{ca.Raw}}, nil
}

func (r *fixtureRuntime) enrollOwner(roots *x509.CertPool) (*mtls.OwnerCredentials, error) {
	if r.input.OwnerTokenFile != "/fixture/owner.token" {
		return nil, errFixture
	}
	p := r.input.Owner.Pool
	configuration, e := postgres.NewOwnerConfigurations(r.root, r.pools["owner-read"], p.InstallationID, p.ClusterID, p.NamespaceUID, r.input.Owner.SourceUID)
	if e != nil {
		return nil, e
	}
	proof, e := kube.NewOwnerEnrollmentAttester(r.observer, configuration, r.guard, fileToken(r.input.OwnerTokenFile))
	if e != nil {
		return nil, e
	}
	ledger := func(purpose string) (*postgres.OwnerEnrollments, error) {
		return postgres.NewOwnerEnrollments(r.root, r.pools[purpose], p.InstallationID, p.ClusterID, p.NamespaceUID, r.input.Owner.SourceUID, uuid.NewString)
	}
	writer, e := ledger("owner-write")
	if e != nil {
		return nil, e
	}
	ack, e := ledger("owner-ack")
	if e != nil {
		return nil, e
	}
	activation, e := ledger("owner-activate")
	if e != nil {
		return nil, e
	}
	store, keys, e := r.auditStore()
	if e != nil {
		return nil, e
	}
	verify, e := mtls.NewOwnerPeerVerifierForPool(roots, p, time.Now)
	if e != nil {
		return nil, e
	}
	coordinator := &app.OwnerEnrollmentCoordinator{Verifier: verify, Proofs: proof, Ledger: writer, Activation: activation, Audit: &objectstore.OwnerEnrollmentAuditObjects{Store: store, Seal: keys, Open: keys}, Acknowledgements: ack, Issuer: fixtureIssuer{owner: r.input.OwnerCA}, Now: time.Now}
	binding := value.OwnerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: r.input.PodUID, ProcessEpoch: uuid.NewString()}
	server, e := mtls.NewOwnerCredentialsForPool(binding, "server", p, roots, coordinator, r.owners, time.Now)
	if e != nil {
		return nil, e
	}
	if e = server.Enroll(r.root); e != nil {
		server.Close()
		return nil, phaseError{"owner-enrollment", e}
	}
	// No issuance retries or background reenrollment in this short qualification.
	// The exact process/leaf stays bound; closed effect pools cannot sign again.
	for _, purpose := range []string{"owner-write", "owner-ack", "owner-activate"} {
		r.pools[purpose].Close()
	}
	return server, nil
}

// connectorDuties are the hub's unchanged ADR-153 duties for the one regional
// peer (ADR-169). They run in the owner Pod; the regional Pod holds none of
// these credentials. fixtureIssuer remains synthetic provider authority.
func (r *fixtureRuntime) connectorDuties() (connectorlifecycle.Runners, error) {
	profile := r.input.Regional.Profile
	backing := r.input.ConnectorConfiguration.Backing
	if !backing.Valid() || !r.input.ConnectorConfiguration.Source.Observation.Profile.Equal(profile) {
		return nil, errFixture
	}
	mac, e := auditapp.NewOperationMAC("connector-mac-v1", r.input.OperationMACKey, backing.AccountVersion, r.input.AccountMACKey)
	if e != nil {
		return nil, e
	}
	r.cleanups = append(r.cleanups, mac.Close)
	process, e := postgres.NewConnectorProcesses(r.root, r.pools["connector-journal"], profile.RootID, profile.Binding, backing, mac)
	if e != nil {
		return nil, e
	}
	credential, e := postgres.NewConnectorCredentials(r.root, r.pools["connector-journal"], profile.RootID, profile.Binding, backing, mac)
	if e != nil {
		return nil, e
	}
	journal, e := postgres.NewConnectorAuditJournal(r.root, r.pools["connector-journal"], backing.Policy)
	if e != nil {
		return nil, e
	}
	ack, e := postgres.NewConnectorAuditAcknowledgements(r.root, r.pools["connector-ack"], backing.Policy)
	if e != nil {
		return nil, e
	}
	store, keys, e := r.auditStore()
	if e != nil {
		return nil, e
	}
	closed, e := objectstore.NewClosedOperationAuditObjects(store, backing.Policy.StoreID, keys, keys)
	if e != nil {
		return nil, e
	}
	auditor, e := app.NewConnectorOperationAuditor(backing.Policy, journal, ack, &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}, closed, ack, time.Now)
	if e != nil {
		return nil, e
	}
	recovery, e := postgres.NewRecoveryReader(r.root, r.pools["recovery-read"], profile.Binding.InstallationID)
	if e != nil {
		return nil, e
	}
	verifier, e := mtls.NewConnectorCredentialVerifier(profile, time.Now)
	if e != nil {
		return nil, e
	}
	q := backing.Policy
	pin := app.ConnectorQualificationPin{InstallationID: q.InstallationID, StoreID: q.StoreID, BackupProfileID: q.BackupProfileID, Qualification: *q.History}
	sources, e := postgres.NewConnectorIdentitySources(r.root, r.pools["connector-source"], profile.RootID, profile.Binding, pin)
	if e != nil {
		return nil, e
	}
	duties := connectorlifecycle.PeerDuties{
		Enrollment: app.ConnectorLifecycleEnrollment{Keys: mtls.EnrollmentProof{}, Recovery: recovery, Journal: process, Audit: auditor, MAC: mac, Now: time.Now},
		Renewal:    app.ConnectorLifecycleRenewal{Keys: mtls.EnrollmentProof{}, Recovery: recovery, Journal: credential, Audit: auditor, MAC: mac, Issuer: fixtureIssuer{client: r.input.ConnectorClientCA, server: r.input.ConnectorServerCA}, Verifier: verifier, Now: time.Now},
		Source:     app.ConnectorIdentityObserver{Journal: tracedSources{sources}, Qualification: pin, Binding: profile.Binding, Now: time.Now},
		Registry: func(ctx context.Context, source app.ConnectorIdentitySourceReader) (app.ConnectorLeafRegistry, error) {
			return postgres.NewConnectorRegistry(ctx, r.pools["connector-read"], source, profile)
		},
	}
	want := r.input.ClusterCredential
	return func(_ context.Context, p value.ClusterCredentialProfile) (connectorlifecycle.PeerDuties, error) {
		if p != want {
			return connectorlifecycle.PeerDuties{}, errFixture // exactly the one enrolled peer
		}
		return duties, nil
	}, nil
}

// serveLifecycle exposes the ADR-169 channel with the owner's bootstrap
// serving identity. The presenter is the real SQL ADR-168 store.
func (r *fixtureRuntime) serveLifecycle(serving *mtls.OwnerBootstrapServing) error {
	runners, err := r.connectorDuties()
	if err != nil {
		return err
	}
	store, err := postgres.NewClusterCredentials(r.root, r.pools["cluster-credential"], r.input.ClusterCredential.RootID)
	if err != nil {
		return err
	}
	handler, err := connectorlifecycle.NewHandler(tracedPresenter{app.ClusterCredentialVerifier{Store: store}}, mtls.EnrollmentProof{}, tracedServices{runners}, 2)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", ":9446")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: serving.GetCertificate, NextProtos: []string{"h2"}}, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 1)
	go func() {
		err := server.ServeTLS(listener, "", "")
		if !errors.Is(err, http.ErrServerClosed) && r.root.Err() == nil {
			emitFailure("lifecycle-listener", err)
			r.cancel()
		}
		done <- nil
	}()
	r.cleanups = append(r.cleanups, func() { _ = server.Close(); <-done })
	return nil
}

// enrollConnector enrolls the regional process over the delegated channel:
// its cluster credential Secret and in-cluster readers only (ADR-168/169).
func (r *fixtureRuntime) enrollConnector(source *kube.ConnectorIdentitySource, ownerRoots *x509.CertPool) (*mtls.ConnectorProcessCredentials, error) {
	profile := r.input.Regional.Profile
	native, e := kube.NewConnectorLifecycleReader(r.observer, source, r.guard, fileToken(r.input.ConnectorTokenFile))
	if e != nil {
		return nil, e
	}
	config := &rest.Config{Host: r.input.API.Host, BearerTokenFile: r.input.API.ObserverTokenFile, TLSClientConfig: rest.TLSClientConfig{CAData: r.input.API.CA}, WrapTransport: r.metrics.wrap(false)}
	secret, e := kube.NewClusterCredentialSecretForConfig(config, r.input.ClusterCredentialNamespace, r.input.ClusterCredentialSecret, r.input.ClusterCredentialSecretUID)
	if e != nil {
		return nil, e
	}
	serverName, e := mtls.OwnerBootstrapServerName(r.input.Owner.Pool)
	if e != nil {
		return nil, e
	}
	// Diagnostic-only boundaries: the Secret read and one TLS 1.3/h2 handshake
	// with the pinned name/roots. Neither is retried or grants anything.
	probe := beginPhase("regional-credential")
	_, _, e = secret.ReadClusterCredential(r.root)
	probe(e)
	if e != nil {
		return nil, phaseError{"regional-credential", e}
	}
	probe = beginPhase("regional-lifecycle-tls")
	dial, stop := context.WithTimeout(r.root, 5*time.Second)
	conn, e := (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ownerRoots, ServerName: serverName, NextProtos: []string{"h2"}}}).DialContext(dial, "tcp", r.input.LifecycleDial)
	stop()
	if e == nil {
		if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != "h2" {
			e = errFixture
		}
		_ = conn.Close()
	}
	probe(e)
	if e != nil {
		return nil, phaseError{"regional-lifecycle-tls", e}
	}
	client, e := connectorlifecycle.NewClient("https://"+r.input.LifecycleDial, serverName, ownerRoots)
	if e != nil {
		return nil, e
	}
	lifecycle := &bootstrap.RegionalLifecycle{Client: client, Local: regionalLocal{native, source}, Credential: app.ClusterCredentialRotator{Profile: r.input.ClusterCredential, Policy: value.DefaultClusterCredentialPolicy(), Store: secret, Exchange: unusedExchange{}, Now: time.Now}, Now: time.Now}
	credentials, e := mtls.NewConnectorProcessCredentials(r.root, profile, r.input.PodUID, lifecycle, lifecycle, source, lifecycle, time.Now)
	if e != nil {
		return nil, e
	}
	if e = credentials.Reconcile(r.root); e != nil {
		credentials.Close()
		return nil, phaseError{"regional-enrollment", e}
	}
	return credentials, nil
}

// Closed-label hub-side boundaries for each delegated conversation step.
type tracedPresenter struct{ app.ClusterCredentialVerifier }

func (p tracedPresenter) Present(ctx context.Context, r value.ClusterCredentialRequest, signature, exporter []byte) (value.ClusterCredentialPresentation, error) {
	done := beginPhase("lifecycle-present")
	out, err := p.ClusterCredentialVerifier.Present(ctx, r, signature, exporter)
	done(err)
	return out, err
}

type tracedServices struct{ connectorlifecycle.Runners }

func (s tracedServices) Enroll(ctx context.Context, region *connectorlifecycle.Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	done := beginPhase("lifecycle-enroll")
	out, err := s.Runners.Enroll(ctx, region, id, r)
	done(err)
	return out, err
}

func (s tracedServices) Issue(ctx context.Context, region *connectorlifecycle.Region, id, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	done := beginPhase("lifecycle-issue")
	out, err := s.Runners.Issue(ctx, region, id, usage, r)
	done(err)
	return out, err
}

func (s tracedServices) Registration(ctx context.Context, region *connectorlifecycle.Region, c value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	done := beginPhase("lifecycle-registration")
	out, err := s.Runners.Registration(ctx, region, c)
	done(err)
	return out, err
}

type tracedSources struct {
	app.ConnectorIdentitySourceJournal
}

func (j tracedSources) StageConnectorIdentity(ctx context.Context, c app.ConnectorIdentityConfiguration) error {
	done := beginPhase("lifecycle-stage")
	err := j.ConnectorIdentitySourceJournal.StageConnectorIdentity(ctx, c)
	done(err)
	return err
}

func (j tracedSources) FenceConnectorIdentity(ctx context.Context, b value.PeerBinding, at time.Time) error {
	done := beginPhase("lifecycle-fence")
	err := j.ConnectorIdentitySourceJournal.FenceConnectorIdentity(ctx, b, at)
	done(err)
	return err
}

// regionalLocal answers the hub's delegated reads; each answer is a closed
// diagnostic boundary in the regional log.
type regionalLocal struct {
	native *kube.ConnectorLifecycleReader
	source *kube.ConnectorIdentitySource
}

func (l regionalLocal) BeginConnectorLifecycle(ctx context.Context, r app.ConnectorLifecycleRequest) (app.ConnectorLifecycleOperation, error) {
	done := beginPhase("regional-local-begin")
	op, err := l.native.BeginConnectorLifecycle(ctx, r)
	done(err)
	if err != nil {
		return nil, err
	}
	return tracedOperation{op}, nil
}

type tracedOperation struct {
	app.ConnectorLifecycleOperation
}

func (o tracedOperation) Read(ctx context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	done := beginPhase("regional-local-read")
	out, err := o.ConnectorLifecycleOperation.Read(ctx, phase)
	done(err)
	return out, err
}

func (l regionalLocal) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	done := beginPhase("regional-local-source")
	out, err := l.source.ReadConnectorIdentitySource(ctx)
	done(err)
	return out, err
}

func (l regionalLocal) ReadConnectorIdentityConfiguration(ctx context.Context) (app.ConnectorIdentityConfiguration, error) {
	done := beginPhase("regional-local-configuration")
	out, err := l.source.ReadConnectorIdentityConfiguration(ctx)
	done(err)
	return out, err
}

// ponytail: rotation is qualified by the SQL/TLS component tests; this fixture
// presents generation 1 only and never exchanges.
type unusedExchange struct{}

func (unusedExchange) ExchangeClusterCredential(context.Context, value.ClusterCredentialRequest, func([]byte) ([]byte, error)) (int64, error) {
	return 0, errFixture
}
