package integration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
	native "asservat.local/asservat/internal/transport/native"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixture route/protection source is deliberately synthetic. The address
// belongs to the owned fixture bridge; actual owner registration/configuration,
// certificate verification and the fixed production dial path remain real.
type contextStartTestRoutes struct {
	sql     *contextStartOwnerSQL
	owner   fleet.OwnerBinding
	address string
}

func (s contextStartTestRoutes) CurrentOwnerRoute(ctx context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
	n := time.Now().UTC()
	if b != s.owner {
		return fleet.OwnerRoute{}, fleet.ErrDenied
	}
	o, e := s.sql.lab.reader.ReadOwnerConfiguration(ctx)
	if e != nil {
		return fleet.OwnerRoute{}, e
	}
	until := identity.Earlier(n.Add(5*time.Second), o.FreshUntil)
	endpoint := fleet.OwnerEndpoint{Binding: b, Pool: o.Configuration.Pool, Pod: "synthetic-owner", ReplicaSetUID: o.Configuration.Pool.DeploymentUID, Addresses: []string{s.address}, ObservedAt: n, FreshUntil: until}
	return fleet.OwnerRoute{Configuration: o, Endpoint: endpoint, ObservedAt: n, FreshUntil: until}, nil
}
func (s contextStartTestRoutes) ReadOwnerProtection(ctx context.Context, p fleet.OwnerPool) (fleet.OwnerProtection, error) {
	n := time.Now().UTC()
	if ctx.Err() != nil || p != s.sql.config.Pool {
		return fleet.OwnerProtection{}, fleet.ErrDenied
	}
	return fleet.OwnerProtection{Pool: p, Digest: artifact.Digest{31}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}

type contextStartTestProof func(context.Context, fleet.ConnectorProcessRequest) (fleet.ConnectorProcessProof, error)

func (f contextStartTestProof) ReadConnectorProcessProof(c context.Context, r fleet.ConnectorProcessRequest) (fleet.ConnectorProcessProof, error) {
	return f(c, r)
}

type contextStartTestTrust func(context.Context) (fleet.APIContextWorkTrust, error)

func (f contextStartTestTrust) APIContextWorkTrust(c context.Context) (fleet.APIContextWorkTrust, error) {
	return f(c)
}

type contextStartUnusedNative struct{}

func (contextStartUnusedNative) OpenNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (native.Conversation, error) {
	return nil, artifact.ErrDownloadUnavailable
}

// Start is the real synchronous application bridge. This tap counts invocations
// and duration only; it cannot start a runner, supply a result or replace peers.
type regionalAPIStartFixture struct {
	bridge       bootstrap.RegionalAPIContextStart
	client       *mtls.ContextStartClient
	candidates   *postgres.OwnerEnrollments
	owner        fleet.OwnerBinding
	verifier     fleetapp.APIContextWorkVerifier
	local        contextstart.RegionalLocal
	calls        int
	lastDuration time.Duration
	regional     chan error
	diagnostic   *publicJourneyDiagnostics
}

func (s *regionalAPIStartFixture) StartContext(c context.Context, i identities.CurrentIdentity, id string) error {
	s.calls++
	n := time.Now()
	defer func() { s.lastDuration = time.Since(n) }()
	return s.bridge.StartContext(c, i, id)
}
func (s *regionalAPIStartFixture) standby(t *testing.T, ctx context.Context) {
	t.Helper()
	if s.regional != nil {
		t.Fatal("fixture attempted to replace an unjoined conversation")
	}
	n := time.Now()
	candidates, e := s.candidates.ReadContextStartOwners(ctx)
	if e != nil || len(candidates.Owners) != 1 || candidates.Owners[0] != s.owner {
		t.Fatal("actual SQL exact owner discovery", e)
	}
	var streamDiagnostic *contextstart.StreamDiagnostics
	if s.diagnostic != nil {
		ctx, streamDiagnostic = contextstart.NewStreamDiagnosticContext(ctx)
	}
	standby, stop := context.WithTimeout(ctx, 30*time.Second)
	exchange, e := s.client.OpenDiscovered(standby, s.owner, candidates)
	if e != nil {
		stop()
		t.Fatalf("actual shared NativePort standby elapsed=%s error=%v", time.Since(n), e)
	}
	s.regional = make(chan error, 1)
	go func() {
		defer stop()
		err := bootstrap.ServeRegionalAPIContextExchange(exchange, s.verifier, s.local)
		if s.diagnostic != nil {
			// Log this original joined completion separately: the public result may
			// already have stopped its recorder. Never render the private error.
			interruption := streamDiagnostic.Interruption()
			t.Logf("journey original regional exchange completed reason=%s stream-stage=%s stream-reason=%s", journeyRegionalReason(err), interruption.Stage(), interruption.Reason())
		}
		s.regional <- err
	}()
	t.Logf("actual SQL discovery and original H2 standby setup elapsed=%s", time.Since(n))
}
func (s *regionalAPIStartFixture) joined(t *testing.T, ctx context.Context) {
	t.Helper()
	if s.regional == nil {
		return
	}
	select {
	case e := <-s.regional:
		s.regional = nil
		if e != nil {
			t.Fatal("regional signed exchange did not positively finish", e)
		}
	case <-ctx.Done():
		t.Fatal("regional child did not join", ctx.Err())
	}
}

// It intentionally runs in the fixture process. API target/process/local
// admission use the actual Pod-bound reader; connector enrollment proof and
// owner route/protection are synthetic roots, never described as deployed proof.
func newRegionalAPIStartFixture(t *testing.T, ctx context.Context, f fixture, n *nativeAPIEnvironment, s captureAdmissionScenario, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, runner executionapp.APIContextRunner) *regionalAPIStartFixture {
	t.Helper()
	// Determine the owned bridge's local address without sending a datagram or
	// permitting a production route override. Bind only that one actual address.
	provider, e := url.Parse(f.S3)
	if e != nil {
		t.Fatal(e)
	}
	probe, e := net.Dial("udp", net.JoinHostPort(provider.Hostname(), "8333"))
	if e != nil {
		t.Fatal(e)
	}
	localIP := probe.LocalAddr().(*net.UDPAddr).IP.String()
	probe.Close()
	if !fleet.OwnerAddress(localIP) {
		t.Fatal("owned bridge lacks a routable local address")
	}
	listener, e := net.Listen("tcp", net.JoinHostPort(localIP, "0"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	ca, key := connectorSQLCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	pool := fleet.OwnerPool{InstallationID: s.recovery.installation, ClusterID: custodyID(), IssuerEpoch: s.a.Recovery.IssuerEpoch, Namespace: "synthetic-hub", NamespaceUID: custodyID(), Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443, NativePort: port}
	if port == pool.Port {
		pool.Port = 8445
	}
	config := fleet.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{21}}, ProtectionDigest: artifact.Digest{22}, IssuerRoots: [][]byte{ca.Raw}}
	lab := &ownerConfigLab{observation: s.recovery.observation, admin: admin, audit: &objectstore.OwnerConfigurationAuditObjects{Store: store, Seal: keys, Open: keys}}
	configured := func(role, password string) (*pgxpool.Pool, *postgres.OwnerConfigurations) {
		p := poolFor(role, password)
		t.Cleanup(p.Close)
		v, e := postgres.NewOwnerConfigurations(ctx, p, pool.InstallationID, pool.ClusterID, pool.NamespaceUID, config.Revision.UID)
		if e != nil {
			t.Fatal(e)
		}
		return p, v
	}
	lab.writerPool, lab.writer = configured("owner_configuration_runtime", "synthetic-owner-configuration")
	lab.ackPool, lab.ack = configured("owner_configuration_audit_runtime", "synthetic-owner-configuration-audit")
	lab.readerPool, lab.reader = configured("owner_configuration_read_runtime", "synthetic-owner-configuration-read")
	sql := newContextStartOwnerSQL(t, ctx, lab, config, contextStartOwnerIssuer{ca, key})
	owner := fleet.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: custodyID(), ProcessEpoch: custodyID()}
	serving, e := mtls.NewOwnerCredentials(owner, "server", roots, sql.coordinator(), sql.reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(serving.Close)
	if e = serving.Enroll(ctx); e != nil {
		t.Fatal("actual scoped SQL/S3 owner enrollment", e)
	}
	sql.closeEffects() // No fixture renewal or effect-role pooling during the request.
	// Fixture source observation is renewed independently, not by a peer read.
	// Each SQL/transport check still retains the original observation deadline.
	loop, stopLoop := context.WithCancel(ctx)
	loopDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-loop.Done():
				loopDone <- nil
				return
			case <-ticker.C:
				if _, e := sql.refresh(loop, 5*time.Second); e != nil {
					if loop.Err() != nil {
						e = nil
					}
					loopDone <- e
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		stopLoop()
		if e := <-loopDone; e != nil && ctx.Err() == nil {
			t.Error("synthetic source observation failed", e)
		}
	})
	routes := contextStartTestRoutes{sql, owner, localIP}
	owners := &fleetapp.OwnerAuthenticator{Registry: sql.reader, Routes: routes, Protection: routes, Now: time.Now}
	clientCA, clientKey := connectorSQLCA(t)
	serverCA, serverKey := connectorSQLCA(t)
	observed, e := runner.Process.ReadAPIProcess(ctx)
	if e != nil {
		t.Fatal("real local process before standby", e)
	}
	b := observed.Binding
	profile := fleet.ConnectorCredentialProfile{RootID: s.a.RootID, Binding: fleet.PeerBinding{InstallationID: pool.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: pool.IssuerEpoch, PeerID: custodyID(), Role: fleet.ConnectorPeer}, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{23}}, ProtectionDigest: artifact.Digest{24}, ServerName: "regional.fixture.invalid", Deployment: fleet.ConnectorDeployment{Namespace: n.control.Name, NamespaceUID: b.NamespaceUID, ServiceAccount: n.plan.Account, AccountUID: b.AccountUID, Deployment: "synthetic-connector", DeploymentUID: custodyID(), ServingSlots: 1, RetainedProcesses: 2}, ClientIssuerRoots: [][]byte{clientCA.Raw}, ServerIssuerRoots: [][]byte{serverCA.Raw}}
	source := &contextStartConnectorFixture{profile: profile, clientCA: clientCA, serverCA: serverCA, clientKey: clientKey, serverKey: serverKey, issued: map[string]fleet.IssuedConnectorCredential{}, origins: map[artifact.Digest]fleet.ConnectorProcessIdentity{}}
	source.proof = contextStartTestProof(func(c context.Context, r fleet.ConnectorProcessRequest) (fleet.ConnectorProcessProof, error) {
		started := time.Now().UTC()
		p, e := runner.Process.ReadAPIProcess(c)
		if e != nil || p.Binding.PodUID != r.Process.PodUID || p.Binding != b {
			return fleet.ConnectorProcessProof{}, fleet.ErrDenied
		}
		config, e := source.ReadConnectorIdentitySource(c)
		if e != nil {
			return fleet.ConnectorProcessProof{}, e
		}
		client, e := mtls.EnrollmentKey(r.ClientCSRDER)
		if e != nil {
			return fleet.ConnectorProcessProof{}, e
		}
		server, e := mtls.EnrollmentKey(r.ServerCSRDER)
		if e != nil {
			return fleet.ConnectorProcessProof{}, e
		}
		until := identity.Earlier(started.Add(5*time.Second), identity.Earlier(p.ValidUntil, config.Observation.FreshUntil))
		return fleet.ConnectorProcessProof{Process: r.Process, Configuration: config.Observation, Pod: n.pod.Name, ReplicaSet: "synthetic-connector-rs", ReplicaSetUID: profile.Deployment.DeploymentUID, ClientKeyDigest: client, ServerKeyDigest: server, TokenDigest: artifact.Digest{25}, WorkloadDigest: artifact.Digest{26}, ProtectionDigest: artifact.Digest{27}, ObservedAt: started, FreshUntil: until}, nil
	})
	connector, e := mtls.NewConnectorProcessCredentials(ctx, profile, b.PodUID, source, source, source, source, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(connector.Close)
	if e = connector.Reconcile(ctx); e != nil {
		t.Fatal("synthetic connector registration with actual process-owned keys", e)
	}
	router, e := contextstart.NewRouter(contextstart.RouterLimits{Standby: 1, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: b.ClusterID, Standby: 1, Captures: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(router.Close)
	ingress, e := mtls.NewContextStartIngress(s.a.RootID, serving, owners, []mtls.ContextStartConnectorAdmission{{Profile: profile, Executor: mtls.ContextStartExecutorPin{NamespaceUID: b.NamespaceUID, AccountUID: b.AccountUID, StartupDigest: b.StartupDigest, ImageDigest: b.ImageDigest}, Registry: contextStartObservationRegistryFixture{source}}}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	name, e := mtls.OwnerServerName(owner)
	if e != nil {
		t.Fatal(e)
	}
	host := net.JoinHostPort(name, strconv.Itoa(port))
	handler, e := contextstart.NewHandler(host, router, ingress, 1)
	if e != nil {
		t.Fatal(e)
	}
	nativeHandler, e := native.NewHandler(contracts.NativeOwnerPath, host, contextStartUnusedNative{}, 1)
	if e != nil {
		t.Fatal(e)
	}
	connectorRoots := x509.NewCertPool()
	connectorRoots.AddCert(clientCA)
	live, cancel := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- native.ServeWithContextStart(live, listener, connectorRoots, serving, nativeHandler, handler, 1, 1)
	}()
	t.Cleanup(func() {
		cancel()
		router.Close()
		if e := <-serverDone; e != context.Canceled && e != context.DeadlineExceeded {
			t.Error("shared listener shutdown", e)
		}
	})
	client, e := mtls.NewContextStartClient(ctx, s.a.RootID, pool, roots, routes, owners, connector, runner.Process, 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(private) })
	issued := time.Now().UTC()
	trust := contextStartTestTrust(func(c context.Context) (fleet.APIContextWorkTrust, error) {
		if c.Err() != nil {
			return fleet.APIContextWorkTrust{}, c.Err()
		}
		now := time.Now().UTC()
		return fleet.APIContextWorkTrust{RootID: s.a.RootID, InstallationID: pool.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: pool.IssuerEpoch, Trust: fleet.WorkTrust{Revision: identity.Revision{UID: "synthetic-work-trust", Generation: 1, Digest: artifact.Digest{28}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Keys: []fleet.WorkKey{{ID: "synthetic-work", ClusterID: b.ClusterID, IssuerEpoch: pool.IssuerEpoch, PublicKey: public, NotBefore: issued.Add(-time.Second), NotAfter: issued.Add(time.Hour)}}}}, nil
	})
	signer, e := jose.NewAPIContextWorkSignatures(trust, "synthetic-work", func(context.Context) crypto.Signer { return private }, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := jose.NewAPIContextWorkSignatures(trust, "", nil, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	// ADR-171: the hub runs the runner with its SQL/authority ports; the region
	// answers only its cluster-local ports over the exchange.
	hub := executionapp.APIContextRunner{Read: runner.Read, Prepare: runner.Prepare, Record: runner.Record, Eligibility: runner.Eligibility, Capabilities: runner.Capabilities, Retention: runner.Retention, Recovery: runner.Recovery, Now: runner.Now}
	local := contextstart.RegionalLocal{Process: runner.Process, Targets: regionalQueryTargets(runner.Targets), Local: runner.Local, Starts: runner.Starts, Output: runner.Output, Collector: runner.Collector, Source: source, Now: runner.Now}
	out := &regionalAPIStartFixture{bridge: bootstrap.RegionalAPIContextStart{Runner: hub, Signer: signer, Router: router, Now: time.Now}, client: client, candidates: sql.reader, owner: owner, verifier: verifier, local: local}
	t.Cleanup(func() {
		client.Close()
		if out.regional != nil {
			<-out.regional
			out.regional = nil
		}
	})
	return out
}

// contextStartObservationRegistryFixture binds the synthetic registry to each
// exchange's ADR-178 source feed: the region's own source must answer first.
type contextStartObservationRegistryFixture struct {
	registry fleetapp.ConnectorLeafRegistry
}

func (r contextStartObservationRegistryFixture) ReadConnectorObservationRegistration(ctx context.Context, _ fleet.ConnectorCredentialProfile, source fleetapp.ConnectorIdentitySourceReader, leaf fleet.ConnectorCredentialCertificate) (fleetapp.ConnectorLeafRegistration, error) {
	if _, e := source.ReadConnectorIdentitySource(ctx); e != nil {
		return fleetapp.ConnectorLeafRegistration{}, e
	}
	return r.registry.ConnectorLeafRegistration(ctx, leaf)
}

// regionalQueryTargets keeps a full regional resolver for ADR-179 queries; a
// ResolvePod-only test port answers workload queries as unavailable.
func regionalQueryTargets(p interface {
	ResolvePod(context.Context, targets.Request) (targets.PodResolution, error)
}) contextstart.QueryTargets {
	if q, ok := p.(contextstart.QueryTargets); ok {
		return q
	}
	return podOnlyTargets{p}
}

type podOnlyTargets struct {
	pod interface {
		ResolvePod(context.Context, targets.Request) (targets.PodResolution, error)
	}
}

func (p podOnlyTargets) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return p.pod.ResolvePod(ctx, r)
}
func (podOnlyTargets) ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error) {
	return targets.PodResolution{}, targets.ErrUnavailable
}
