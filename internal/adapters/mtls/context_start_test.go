package mtls

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	execution "asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/contextstart"
)

type contextStartAPIProcess func(context.Context) (execution.APIProcessObservation, error)

func (f contextStartAPIProcess) ReadAPIProcess(ctx context.Context) (execution.APIProcessObservation, error) {
	return f(ctx)
}

type contextStartTrust func(context.Context) (value.APIContextWorkTrust, error)

func (f contextStartTrust) APIContextWorkTrust(ctx context.Context) (value.APIContextWorkTrust, error) {
	return f(ctx)
}

type contextStartTLSFixture struct {
	connector       *connectorPairFixture
	client          *ContextStartClient
	router          *contextstart.Router
	owner           value.OwnerBinding
	requests, dials atomic.Int32
	intercept       func(http.ResponseWriter, *http.Request) bool
	rootID          string
	api             contextStartAPIProcess
	// Retained for the fixed-endpoint regional client (ADR-172).
	pool       value.OwnerPool
	roots      *x509.CertPool
	owners     *app.OwnerAuthenticator
	credential *ConnectorProcessCredentials
	listener   string
	// targets answers ADR-179 queries on regional streams opened by open.
	targets contextstart.QueryTargets
}

// Actual TLS1.3/H2 and process-owned keys, with explicitly synthetic current
// source/registry/route/process readers. No Kubernetes, SQL or capture proof.
func newContextStartTLSFixture(t *testing.T) *contextStartTLSFixture {
	t.Helper()
	cf := newConnectorPairFixture(t)
	connector := cf.owner()
	if e := connector.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	n := time.Now().UTC().Truncate(time.Second)
	ca := newOwnerTestCA(t, n)
	permit := ownerPermit(n, [][]byte{ca.cert.Raw}, artifact.Digest{1}, "server")
	pool := permit.Configuration.Configuration.Pool
	fixture := &contextStartTLSFixture{connector: cf, owner: permit.Binding, rootID: cf.profile.RootID}
	var handler *contextstart.Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		if fixture.intercept != nil && fixture.intercept(w, r) {
			return
		}
		if r.ProtoMajor != 2 {
			t.Error("not actual H2")
		}
		handler.ServeHTTP(w, r)
	}))
	port := server.Listener.Addr().(*net.TCPAddr).Port
	pool.NativePort = port
	source := newForwardCredentialFixture(t, ca, time.Now)
	source.mutateRegistration = func(o *value.OwnerRegistrationObservation) {
		o.Enrollment.Pool = pool
		o.Configuration.Configuration.Pool = pool
	}
	owner, e := NewOwnerCredentials(permit.Binding, "server", ca.roots, source, source, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(owner.Close)
	if e = owner.Enroll(context.Background()); e != nil {
		t.Fatal(e)
	}
	configuration := permit.Configuration.Configuration
	configuration.Pool = pool
	routes := forwardRoutes(func(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
		now := time.Now().UTC()
		if ctx.Err() != nil || b != fixture.owner {
			return value.OwnerRoute{}, value.ErrDenied
		}
		o := value.OwnerConfigurationObservation{Configuration: configuration, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		return value.OwnerRoute{Configuration: o, Endpoint: value.OwnerEndpoint{Binding: b, Pool: pool, Pod: source.enrollment.Pod, ReplicaSetUID: source.enrollment.ReplicaSetUID, Addresses: []string{"192.0.2.1"}, ObservedAt: now, FreshUntil: o.FreshUntil}, ObservedAt: now, FreshUntil: o.FreshUntil}, nil
	})
	guard := forwardGuard(func(ctx context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
		now := time.Now().UTC()
		if ctx.Err() != nil || p != pool {
			return value.OwnerProtection{}, value.ErrDenied
		}
		return value.OwnerProtection{Pool: pool, Digest: artifact.Digest{3}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
	})
	owners := &app.OwnerAuthenticator{Registry: source, Routes: routes, Protection: guard, Now: time.Now}
	api := execution.APIProcessBinding{InstallationID: cf.profile.Binding.InstallationID, ClusterID: cf.profile.Binding.ClusterID, IssuerEpoch: cf.profile.Binding.IssuerEpoch, NamespaceUID: cf.profile.Deployment.NamespaceUID, AccountUID: cf.profile.Deployment.AccountUID, PodUID: ownerTestID, ProcessEpoch: "55000000-0000-4000-8000-000000000099", StartupDigest: artifact.Digest{8}, ImageDigest: artifact.Digest{9}}
	process := contextStartAPIProcess(func(ctx context.Context) (execution.APIProcessObservation, error) {
		now := time.Now().UTC()
		if ctx.Err() != nil {
			return execution.APIProcessObservation{}, value.ErrUnavailable
		}
		return execution.APIProcessObservation{Binding: api, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
	})
	fixture.api = process
	pin := ContextStartExecutorPin{NamespaceUID: api.NamespaceUID, AccountUID: api.AccountUID, StartupDigest: api.StartupDigest, ImageDigest: api.ImageDigest}
	ingress, e := NewContextStartIngress(fixture.rootID, owner, owners, []ContextStartConnectorAdmission{{Profile: cf.profile, Executor: pin, Registry: contextStartObservationRegistry{cf}}}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	fixture.router, e = contextstart.NewRouter(contextstart.RouterLimits{Standby: 1, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: api.ClusterID, Standby: 1, Captures: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	name, _ := OwnerServerName(fixture.owner)
	handler, e = contextstart.NewHandler(net.JoinHostPort(name, strconv.Itoa(port)), fixture.router, ingress, 1)
	if e != nil {
		t.Fatal(e)
	}
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: cf.clientCA.roots, GetCertificate: owner.GetCertificate, NextProtos: []string{"h2"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	fixture.pool, fixture.roots, fixture.owners, fixture.credential, fixture.listener = pool, ca.roots, owners, connector, server.Listener.Addr().String()
	fixture.client, e = NewContextStartClient(context.Background(), fixture.rootID, pool, ca.roots, routes, owners, connector, process, 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	fixture.client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		fixture.dials.Add(1)
		if address != net.JoinHostPort("192.0.2.1", strconv.Itoa(port)) {
			t.Error("unaccepted dial destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(fixture.router.Close)
	t.Cleanup(fixture.client.Close)
	return fixture
}
func (f *contextStartTLSFixture) open(t *testing.T) (*ContextStartExchange, contextstart.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	e, err := f.client.Open(ctx, f.owner)
	if err != nil {
		t.Fatal("actual Open", err)
	}
	t.Cleanup(e.Close)
	response, writer, socket, err := e.IO()
	if err != nil {
		t.Fatal(err)
	}
	stream, err := contextstart.NewOutboundStream(e.Context(), e.Receiver().Channel, e.Check, f.connector, f.targets, response, writer, socket, e.Close)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	return e, stream
}
func (f *contextStartTLSFixture) work(t *testing.T, receiver value.APIContextReceiver, mutate ...func(*value.APIContextWork)) (value.APIContextWork, *jose.APIContextWorkSignatures, []byte, identity.Identity) {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(2 * time.Second)
	if receiver.ValidUntil.Before(until) {
		until = receiver.ValidUntil.UTC().Truncate(time.Microsecond)
	}
	actor := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "human", ClientID: "console", Kind: identity.Human}
	rev := identity.Revision{UID: ownerTestID, Generation: 1, Digest: artifact.Digest{1}}
	w := value.APIContextWork{Channel: receiver.Channel, CaptureID: ownerTestID, AttemptID: ownerTestID, Actor: actor, Target: authorization.Target{ClusterID: receiver.Channel.Connector.Binding.ClusterID, NamespaceUID: ownerTestID, WorkloadUID: ownerTestID, PodUID: ownerTestID}, ScopeDigest: artifact.Digest{1}, ExpectationDigest: artifact.Digest{2}, IntentDigest: artifact.Digest{3}, BudgetDigest: artifact.Digest{4}, Capability: rev, ProjectionDigest: artifact.Digest{5}, IssuedAt: n, NotAfter: until}
	for _, m := range mutate {
		m(&w)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := value.APIContextWorkTrust{RootID: f.rootID, InstallationID: f.owner.InstallationID, ClusterID: receiver.Channel.Connector.Binding.ClusterID, IssuerEpoch: f.owner.IssuerEpoch, Trust: value.WorkTrust{Revision: rev, ObservedAt: n, FreshUntil: until, Keys: []value.WorkKey{{ID: "purpose-only-test-key", ClusterID: receiver.Channel.Connector.Binding.ClusterID, IssuerEpoch: f.owner.IssuerEpoch, PublicKey: pub, NotBefore: n.Add(-time.Minute), NotAfter: n.Add(time.Minute)}}}}
	signer, err := jose.NewAPIContextWorkSignatures(contextStartTrust(func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }), "purpose-only-test-key", func(context.Context) crypto.Signer { return key }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignAPIContextWork(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	return w, signer, signed, identity.Identity{Principal: actor, Policy: rev, Scopes: []string{"evidence:capture"}, Groups: []string{"group-a"}, VerifiedAt: n, ValidUntil: until}
}

// contextStartObservationRegistry binds the fixture registry to each
// exchange's ADR-178 source feed: the feed must answer before registration.
type contextStartObservationRegistry struct{ registry app.ConnectorLeafRegistry }

func (r contextStartObservationRegistry) ReadConnectorObservationRegistration(ctx context.Context, _ value.ConnectorCredentialProfile, source app.ConnectorIdentitySourceReader, leaf value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	if _, e := source.ReadConnectorIdentitySource(ctx); e != nil {
		return app.ConnectorLeafRegistration{}, e
	}
	return r.registry.ConnectorLeafRegistration(ctx, leaf)
}
