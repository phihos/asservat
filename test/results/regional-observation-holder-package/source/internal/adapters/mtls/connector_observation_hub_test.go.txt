package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
)

type hubObservationWorkloadFunc func(context.Context, value.OwnerBinding, string) (value.OwnerObservationWorkload, error)

func (f hubObservationWorkloadFunc) ObserveOwnerWorkload(c context.Context, b value.OwnerBinding, p string) (value.OwnerObservationWorkload, error) {
	return f(c, b, p)
}

// This fixture has real process keys and a mutually authenticated TLS exporter.
// Its native workload/source and SQL49 registrations are synthetic, including
// the two independent source invocations performed by each registry read.
type hubObservationFixture struct {
	f                                    *connectorPairFixture
	pin                                  value.ConnectorObservationPin
	owner                                value.OwnerObservationPin
	ingress                              *OwnerObservationIngress
	state                                tls.ConnectionState
	local                                ConnectorProcessObservation
	request                              value.ClusterObservationRequest
	hub                                  *HubConnectorObservation
	mode                                 string
	registry, proofs, metadata, receipts int
	firstEnd                             time.Time
	block, release                       chan struct{}
}

func newHubObservationFixture(t *testing.T, mode string) *hubObservationFixture {
	t.Helper()
	f := newConnectorPairFixture(t)
	regional := f.owner()
	if err := regional.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	local, err := regional.ObserveConnectorProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pool := ownerBootstrapPool()
	owner := value.OwnerObservationPin{RootID: f.profile.RootID, SourceUID: ownerTestID, Pool: pool, TemplateDigest: artifact.Digest{13}, ImageDigest: artifact.Digest{14}, ProtectionDigest: artifact.Digest{15}}
	pin := value.ConnectorObservationPin{Profile: f.profile.Clone(), Roles: f.roles, TemplateDigest: artifact.Digest{11}, ImageDigest: artifact.Digest{12}, ProtectionDigest: artifact.Digest{17}}
	base := &ownerCredentialFixture{t: t, ca: newOwnerTestCA(t, f.clock())}
	base.clock.Store(f.clock().UnixNano())
	common, _ := OwnerBootstrapServerName(pool)
	base.mutateLeaf = func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, common) }
	issuer := &ownerBootstrapCredentialFixture{base: base, pool: pool}
	server, err := NewOwnerCredentialsForPool(ownerBootstrapBinding(ownerTestID), "server", pool, base.ca.roots, issuer, issuer, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	if err = server.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	serving, err := NewOwnerBootstrapServing(server, pool)
	if err != nil {
		t.Fatal(err)
	}
	configuration := ownerBootstrapConfiguration(pool, base.ca, f.clock())
	base.mutateRegistration = func(r *value.OwnerRegistrationObservation) { r.Configuration = configuration; r.Enrollment.Pool = pool }
	registry := forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
		return issuer.ReadOwnerRegistration(ctx, c)
	})
	routes := forwardRoutes(func(_ context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
		return value.OwnerRoute{Configuration: configuration, Endpoint: value.OwnerEndpoint{Binding: b, Pool: pool, Pod: "owner-1", ReplicaSetUID: ownerTestID, Addresses: []string{"10.0.0.8"}, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}, nil
	})
	guard := forwardGuard(func(context.Context, value.OwnerPool) (value.OwnerProtection, error) {
		return value.OwnerProtection{Pool: pool, Digest: owner.ProtectionDigest, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}, nil
	})
	work := hubObservationWorkloadFunc(func(_ context.Context, b value.OwnerBinding, p string) (value.OwnerObservationWorkload, error) {
		return value.OwnerObservationWorkload{Pin: owner, Binding: b, Pod: p, ReplicaSetUID: ownerTestID, WorkloadDigest: artifact.Digest{18}, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}, nil
	})
	ingress, err := NewOwnerObservationIngress(owner, server, &app.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: guard, Now: f.clock}, work, []OwnerObservationPeer{{Binding: f.profile.Binding, Roots: f.profile.ClientIssuerRoots}}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	ts := tls.Server(a, &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.clientCA.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}})
	tc := tls.Client(b, &tls.Config{GetClientCertificate: regional.GetClientCertificate, RootCAs: base.ca.roots, ServerName: common, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	serverDone := make(chan error, 1)
	go func() { serverDone <- ts.HandshakeContext(ctx) }()
	clientErr := tc.HandshakeContext(ctx)
	if clientErr != nil {
		a.Close()
		b.Close()
	}
	serverErr := <-serverDone
	if clientErr != nil || serverErr != nil {
		t.Fatal("actual TLS", clientErr, serverErr)
	}
	x := &hubObservationFixture{f: f, pin: pin, owner: owner, ingress: ingress, state: ts.ConnectionState(), local: local, mode: mode}
	x.request = value.ClusterObservationRequest{RootID: pin.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, ClusterID: pin.Profile.Binding.ClusterID, Purpose: value.ObserveCapacityNamespaces, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	x.hub, err = NewHubConnectorObservation(ctx, pin, ingress, x, x, &x.state, contracts.ClusterObservationHello{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: ownerOtherID, RootID: pin.Profile.RootID, ClusterID: pin.Profile.Binding.ClusterID}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.hub.Close)
	return x
}

func (x *hubObservationFixture) ReadConnectorObservationRegistration(ctx context.Context, p value.ConnectorCredentialProfile, source app.ConnectorIdentitySourceReader, leaf value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	x.registry++
	if x.mode == "blocked-registry" {
		close(x.block)
		<-ctx.Done()
		<-x.release
		return app.ConnectorLeafRegistration{}, value.ErrUnavailable
	}
	if !p.Equal(x.pin.Profile) || leaf != x.local.Registration.Certificate {
		return app.ConnectorLeafRegistration{}, value.ErrDenied
	}
	for i := 0; i < 2; i++ {
		if _, err := source.ReadConnectorIdentitySource(ctx); err != nil {
			return app.ConnectorLeafRegistration{}, err
		}
	}
	if x.mode == "revoked-before-metadata" || (x.mode == "revoked-after-result" && x.registry == 2) {
		return app.ConnectorLeafRegistration{}, value.ErrUnavailable
	}
	return x.local.Registration, nil
}

func (x *hubObservationFixture) ExchangeConnectorObservation(ctx context.Context, p contracts.ClusterObservationProbe) (contracts.ConnectorObservationReply, error) {
	x.proofs++
	if p.Ordinal != x.proofs {
		return contracts.ConnectorObservationReply{}, value.ErrDenied
	}
	r, err := ownerObservationRequest(p.Owner.Request, x.f.clock())
	if err != nil {
		return contracts.ConnectorObservationReply{}, err
	}
	channel, err := ownerObservationConnection(&x.state, r)
	if err != nil {
		return contracts.ConnectorObservationReply{}, err
	}
	source, err := x.f.ReadConnectorIdentitySource(ctx)
	if err != nil {
		return contracts.ConnectorObservationReply{}, err
	}
	end := r.NotAfter
	if x.mode == "first-bound" {
		end = r.RequestedAt.Add(4 * time.Second)
		if p.Ordinal == 1 {
			end = r.RequestedAt.Add(2 * time.Second)
			x.firstEnd = end
		}
	}
	if x.mode == "source-changed-after-result" && p.Ordinal == 3 {
		source.Observation.Profile.Revision.Generation++
		source.Observation.Profile.Revision.Digest[0]++
	}
	w := value.ConnectorObservationWorkload{Process: x.local.Request.Process, Pod: "connector-1", ReplicaSetUID: ownerTestID, TemplateDigest: x.pin.TemplateDigest, ImageDigest: x.pin.ImageDigest, ProtectionDigest: x.pin.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: x.f.clock(), FreshUntil: end}
	return connectorObservationReplyWire(value.ConnectorObservation{Request: r, Ordinal: p.Ordinal, ConnectionBinding: channel, Certificate: x.local.Registration.Certificate, Source: source, Workload: w, ObservedAt: x.f.clock(), FreshUntil: end}, x.pin)
}

func (x *hubObservationFixture) ExchangeClusterObservation(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	x.metadata++
	if x.registry != 1 || x.proofs != 2 {
		return value.ClusterObservationResult{}, value.ErrDenied
	}
	digest, err := app.ClusterObservationRequestDigest(r)
	if err != nil {
		return value.ClusterObservationResult{}, err
	}
	end, _ := ctx.Deadline()
	if x.mode == "first-bound" && end.After(x.firstEnd) {
		return value.ClusterObservationResult{}, value.ErrDenied
	}
	return value.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: digest, Interval: value.ClusterObservationInterval{ObservedAt: x.f.clock(), FreshUntil: end}, Namespaces: &value.ClusterNamespaceCandidatePage{ResourceVersion: "1", Items: []cfg.NamespaceRef{}}}, nil
}

func (x *hubObservationFixture) CompleteClusterObservation(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	x.receipts++
	digest, _ := app.ClusterObservationRequestDigest(x.request)
	if x.registry != 2 || x.proofs != 4 || x.metadata != 1 || r.ExchangeID != ownerOtherID || r.RequestID != x.request.ID || r.RequestDigest != ownerObservationHex(digest) || ctx.Err() != nil || x.mode == "lost-final-delivery" {
		return value.ErrUnavailable
	}
	return nil
}

func TestHubConnectorObservationBracketsMetadataAndPreservesBounds(t *testing.T) {
	for _, mode := range []string{"current", "first-bound", "revoked-after-result", "source-changed-after-result", "lost-final-delivery"} {
		t.Run(mode, func(t *testing.T) {
			x := newHubObservationFixture(t, mode)
			result, err := x.hub.ObserveCluster(context.Background(), x.request)
			good := mode == "current" || mode == "first-bound"
			if good != (err == nil) {
				t.Fatal("coordinator result", mode, err, x.registry, x.proofs, x.metadata, x.receipts)
			}
			if x.registry != 2 || x.metadata != 1 || x.proofs > 4 {
				t.Fatal("missing/repeated current boundaries", x.registry, x.proofs, x.metadata)
			}
			if good && (x.proofs != 4 || x.receipts != 1) {
				t.Fatal("missing terminal phases")
			}
			if (mode == "revoked-after-result" || mode == "source-changed-after-result") && x.receipts != 0 {
				t.Fatal("failed final current check sent success receipt")
			}
			if mode == "first-bound" && result.Interval.FreshUntil.After(x.firstEnd) {
				t.Fatal("first authority interval renewed")
			}
			counts := [4]int{x.registry, x.proofs, x.metadata, x.receipts}
			if _, err = x.hub.ObserveCluster(context.Background(), x.request); err == nil {
				t.Fatal("spent conversation retried")
			}
			if counts != ([4]int{x.registry, x.proofs, x.metadata, x.receipts}) {
				t.Fatal("replay performed I/O")
			}
		})
	}
}

func TestHubConnectorObservationCloseJoinsAdmittedRegistry(t *testing.T) {
	x := newHubObservationFixture(t, "blocked-registry")
	x.block = make(chan struct{})
	x.release = make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(x.release) }); x.hub.Close() })
	result := make(chan error, 1)
	go func() { _, err := x.hub.ObserveCluster(context.Background(), x.request); result <- err }()
	select {
	case <-x.block:
	case <-time.After(time.Second):
		t.Fatal("registry read not admitted")
	}
	closed := make(chan struct{})
	go func() { x.hub.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close certified joined while registry still running")
	case <-time.After(10 * time.Millisecond):
	}
	once.Do(func() { close(x.release) })
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join actual registry completion")
	}
	if err := <-result; err == nil || x.registry != 1 || x.proofs != 0 || x.metadata != 0 || x.receipts != 0 {
		t.Fatal("cancelled registry acquired later effects", err)
	}
}

func TestHubConnectorObservationRejectsWrongHelloBeforeRegistry(t *testing.T) {
	x := newHubObservationFixture(t, "current")
	for _, mode := range []string{"exchange", "root", "cluster"} {
		hello := contracts.ClusterObservationHello{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: ownerOtherID, RootID: x.pin.Profile.RootID, ClusterID: x.pin.Profile.Binding.ClusterID}
		switch mode {
		case "exchange":
			hello.ExchangeID = "not-an-id"
		case "root":
			hello.RootID = ownerOtherID
		case "cluster":
			hello.ClusterID = ownerOtherID
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		value, err := NewHubConnectorObservation(ctx, x.pin, x.ingress, x, x, &x.state, hello, x.f.clock)
		cancel()
		if err == nil {
			value.Close()
			t.Fatal("changed hello accepted", mode)
		}
	}
	if x.registry != 0 || x.proofs != 0 || x.metadata != 0 {
		t.Fatal("wrong hello performed source/metadata I/O")
	}
}

func TestHubConnectorObservationRequiresOriginalSocketDeadline(t *testing.T) {
	x := newHubObservationFixture(t, "current")
	hello := contracts.ClusterObservationHello{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: ownerOtherID, RootID: x.pin.Profile.RootID, ClusterID: x.pin.Profile.Binding.ClusterID}
	for _, mode := range []string{"missing", "overlong", "expired", "original"} {
		ctx := context.Background()
		cancel := func() {}
		switch mode {
		case "overlong":
			ctx, cancel = context.WithDeadline(ctx, x.f.clock().Add(31*time.Second))
		case "expired":
			ctx, cancel = context.WithDeadline(ctx, x.f.clock().Add(-time.Second))
		case "original":
			ctx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Second))
		}
		coordinator, err := NewHubConnectorObservation(ctx, x.pin, x.ingress, x, x, &x.state, hello, x.f.clock)
		if mode == "original" {
			if err != nil {
				cancel()
				t.Fatal("original socket rejected", err)
			}
			want, _ := ctx.Deadline()
			got, _ := coordinator.ctx.Deadline()
			if !got.Equal(want) {
				coordinator.Close()
				cancel()
				t.Fatal("socket deadline reset")
			}
		} else if err == nil {
			coordinator.Close()
			cancel()
			t.Fatal("missing/overlong/expired socket manufactured residency", mode)
		}
		if coordinator != nil {
			coordinator.Close()
		}
		cancel()
	}
	if x.registry != 0 || x.proofs != 0 || x.metadata != 0 {
		t.Fatal("routing constructor performed authority I/O")
	}
}

func TestHubConnectorObservationRevokedBeforeMetadataDeniesWithoutDelivery(t *testing.T) {
	x := newHubObservationFixture(t, "revoked-before-metadata")
	if _, err := x.hub.ObserveCluster(context.Background(), x.request); err == nil {
		t.Fatal("revoked original registration admitted metadata")
	}
	if x.registry != 1 || x.proofs != 2 || x.metadata != 0 || x.receipts != 0 {
		t.Fatal("failed current registration reached later phases", x.registry, x.proofs, x.metadata, x.receipts)
	}
}
