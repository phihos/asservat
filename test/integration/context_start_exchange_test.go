package integration

import (
	"context"
	"crypto/x509"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/bootstrap"
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

type regionalAPIStartFixture struct {
	bridge       bootstrap.RegionalAPIContextStart
	client       *mtls.ContextStartClient
	candidates   *postgres.OwnerEnrollments
	owner        fleet.OwnerBinding
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
	exchange, e := s.client.OpenRequested(standby, s.owner, candidates.ValidUntil)
	if e != nil {
		stop()
		t.Fatalf("actual shared NativePort standby elapsed=%s error=%v", time.Since(n), e)
	}
	s.regional = make(chan error, 1)
	go func() {
		defer stop()
		err := bootstrap.ServeRegionalAPIContextExchange(exchange, s.local)
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
			t.Fatal("regional exchange did not positively finish", e)
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
	pool := fleet.OwnerPool{InstallationID: s.recovery.installation, ClusterID: custodyID(), IssuerEpoch: s.recovery.observation.issuer, Namespace: "synthetic-hub", NamespaceUID: custodyID(), Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443, NativePort: port}
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
	observed, e := runner.Process.ReadAPIProcess(ctx)
	if e != nil {
		t.Fatal("real local process before standby", e)
	}
	b := observed.Binding
	// ADR-334: the connector is this cluster's token-attributed peer.
	connector := fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: pool.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: pool.IssuerEpoch, PeerID: custodyID(), Role: fleet.ConnectorPeer}, PodUID: b.PodUID, ProcessEpoch: custodyID()}
	tokens := contextStartTestTokens{fleet.ConnectorCluster{RootID: s.a.RootID, PeerID: connector.Binding.PeerID, InstallationID: pool.InstallationID, ClusterID: b.ClusterID}}
	router, e := contextstart.NewRouter([]contextstart.ClusterLimit{{ClusterID: b.ClusterID, Standby: 1, Captures: 1}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(router.Close)
	ingress, e := mtls.NewContextStartIngress(s.a.RootID, serving, owners, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	name, e := mtls.OwnerServerName(owner)
	if e != nil {
		t.Fatal(e)
	}
	host := net.JoinHostPort(name, strconv.Itoa(port))
	handler, e := contextstart.NewHandler(host, router, ingress, tokens, 1)
	if e != nil {
		t.Fatal(e)
	}
	live, cancel := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- native.ServeOwner(live, listener, roots, serving, host, handler, nil, 1, 1)
	}()
	t.Cleanup(func() {
		cancel()
		router.Close()
		if e := <-serverDone; e != context.Canceled && e != context.DeadlineExceeded {
			t.Error("shared listener shutdown", e)
		}
	})
	token := func() ([]byte, error) { return []byte(contextStartTestToken), nil }
	client, e := mtls.NewContextStartClient(ctx, s.a.RootID, pool, roots, net.JoinHostPort(localIP, strconv.Itoa(port)), (&net.Dialer{}).DialContext, owners, connector, token, runner.Process, 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	// ADR-171: the hub runs the runner with its SQL/authority ports; the region
	// answers only its cluster-local ports over the exchange.
	hub := executionapp.APIContextRunner{Read: runner.Read, Prepare: runner.Prepare, Record: runner.Record, Eligibility: runner.Eligibility, Capabilities: runner.Capabilities, Retention: runner.Retention, Now: runner.Now}
	local := contextstart.RegionalLocal{Process: runner.Process, Targets: regionalQueryTargets(runner.Targets), Output: runner.Output, Collector: runner.Collector, Now: runner.Now}
	out := &regionalAPIStartFixture{bridge: bootstrap.RegionalAPIContextStart{Runner: hub, Router: router, Now: time.Now}, client: client, candidates: sql.reader, owner: owner, local: local}
	t.Cleanup(func() {
		client.Close()
		if out.regional != nil {
			<-out.regional
			out.regional = nil
		}
	})
	return out
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

const contextStartTestToken = "synthetic-connector-token"

// contextStartTestTokens attributes the synthetic token to the fixture
// cluster; the hub verifies real tokens with the ServiceAccount verifier.
type contextStartTestTokens struct{ cluster fleet.ConnectorCluster }

func (t contextStartTestTokens) VerifyConnectorUntil(_ context.Context, token string) (fleet.ConnectorCluster, time.Time, error) {
	if token != contextStartTestToken {
		return fleet.ConnectorCluster{}, time.Time{}, fleet.ErrDenied
	}
	return t.cluster, time.Now().Add(time.Hour), nil
}
