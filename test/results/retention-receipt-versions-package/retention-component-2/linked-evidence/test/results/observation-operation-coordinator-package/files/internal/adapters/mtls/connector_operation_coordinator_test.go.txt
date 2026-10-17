package mtls

import (
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Actual process keys and mutual TLS; native/SQL and terminal stream are fixed
// synthetic component ports. This is not a framed/native route qualification.
type ownerOperationNativeFixture struct {
	facts                   value.OwnerObservationNativeFacts
	original, final, closed atomic.Int32
	finalHook               func(context.Context, *value.OwnerObservationNativeFacts) error
	originalHook            func(context.Context)
}

func (f *ownerOperationNativeFixture) Original(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	f.original.Add(1)
	if f.originalHook != nil {
		f.originalHook(ctx)
	}
	if ctx.Err() != nil || f.final.Load() != 0 || f.closed.Load() != 0 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return f.facts.Clone(), nil
}
func (f *ownerOperationNativeFixture) Final(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	if f.final.Add(1) != 1 || f.closed.Load() != 0 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	v := f.facts.Clone()
	v.Final = true
	if f.finalHook != nil {
		if err := f.finalHook(ctx, &v); err != nil {
			return value.OwnerObservationNativeFacts{}, err
		}
	}
	return v, nil
}
func (f *ownerOperationNativeFixture) Close() { f.closed.Add(1) }

type operationCoordinatorFixture struct {
	f                                 *connectorPairFixture
	pin                               value.ConnectorObservationPin
	owner                             value.OwnerObservationPin
	server                            *OwnerCredentials
	registry                          app.OwnerCertificateRegistry
	regional                          *ConnectorProcessCredentials
	state                             tls.ConnectionState
	local                             ConnectorProcessObservation
	request                           value.ClusterObservationRequest
	mode                              string
	ctx                               context.Context
	native                            *ownerOperationNativeFixture
	regionalNative                    *connectorOperationNativeFixture
	operation                         *OwnerObservationOperation
	channel                           *ConnectorObservationOperationChannel
	hub                               *HubConnectorObservationOperation
	pairs, proofs, metadata, receipts int
	probeHook                         func(*contracts.ClusterObservationOperationProbe)
	pairHook                          func(int, *app.ConnectorObservationOperationRegistration)
	pairDeadlineHook                  func(context.Context, int)
}

func newOperationCoordinatorFixture(t *testing.T, mode string) *operationCoordinatorFixture {
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
	if configuration.Configuration.ProtectionDigest == owner.ProtectionDigest {
		t.Fatal("fixture must distinguish source-policy and workload guard digests")
	}
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
	x := &operationCoordinatorFixture{f: f, pin: pin, owner: owner, server: server, registry: registry, regional: regional, state: ts.ConnectionState(), local: local, mode: mode, ctx: ctx}
	x.request = value.ClusterObservationRequest{RootID: pin.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, ClusterID: pin.Profile.Binding.ClusterID, Purpose: value.ObserveCapacityNamespaces, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	request := value.OwnerObservationRequest{RootID: x.request.RootID, ID: x.request.ID, Challenge: x.request.Challenge, RequestedAt: x.request.RequestedAt, NotAfter: x.request.NotAfter}
	leaf, _ := server.ServingCertificate()
	x.native = &ownerOperationNativeFixture{facts: value.OwnerObservationNativeFacts{Request: request, Pin: owner, ObservedAt: f.clock(), FreshUntil: x.request.NotAfter, Peers: []value.OwnerObservationNativePeer{{Binding: leaf.Binding, Pod: "owner-1", ReplicaSetUID: ownerTestID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{18}}}}}
	cs := tc.ConnectionState()
	candidates := observationCandidatesFunc(func(context.Context) (value.APIContextOwnerCandidates, error) {
		if x.mode == "owner-revoked" && x.metadata > 0 {
			return value.APIContextOwnerCandidates{}, value.ErrUnavailable
		}
		return value.APIContextOwnerCandidates{Pool: pool, Owners: []value.OwnerBinding{leaf.Binding}, ObservedAt: f.clock(), ValidUntil: f.clock().Add(5 * time.Second)}, nil
	})
	selected, err := app.NewOwnerObservationCandidateSelection(pool, candidates)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := candidates.ReadOwnerObservationCandidates(ctx)
	x.regionalNative = &connectorOperationNativeFixture{f: f, pin: pin}
	producer, err := NewConnectorObservationOperationProducer(pin, regional, x.regionalNative, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	x.channel, err = NewConnectorObservationOperationChannel(ctx, ownerOtherID, owner, base.ca.roots, before, &cs, local.Registration.Certificate, producer, selected, registry, x, f.clock)
	if err != nil {
		t.Fatal("regional channel", err)
	}
	t.Cleanup(x.channel.Close)
	v2, err := NewOwnerObservationOperationIngress(owner, server, []OwnerObservationPeer{{Binding: pin.Profile.Binding, Roots: pin.Profile.ClientIssuerRoots}}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	_ = ingress // existing full authenticator is deliberately not a v2 dependency.
	x.hub, err = NewHubConnectorObservationOperation(ctx, pin, v2, x, x, &x.state, contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: ownerOtherID, RootID: request.RootID, ClusterID: x.request.ClusterID}, f.clock)
	if err != nil {
		t.Fatal("empty standby", err)
	}
	t.Cleanup(x.hub.Close)
	if x.native.original.Load() != 0 || x.native.final.Load() != 0 || x.regionalNative.opens.Load() != 0 {
		t.Fatal("empty standby opened query authority")
	}
	x.operation, err = NewOwnerObservationOperation(ctx, owner, request, server, registry, x.native, f.clock)
	if err != nil {
		t.Fatal("original native owner", err)
	}
	t.Cleanup(x.operation.Close)

	return x
}

func (x *operationCoordinatorFixture) ReadConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, source app.ConnectorObservationOperationSource, leaf value.ConnectorCredentialCertificate, n int) (app.ConnectorObservationOperationRegistration, error) {
	x.pairs++
	if x.pairDeadlineHook != nil {
		x.pairDeadlineHook(ctx, n)
	}
	if leaf != x.local.Registration.Certificate {
		return app.ConnectorObservationOperationRegistration{}, value.ErrDenied
	}
	var last value.ConnectorObservationOperationValue
	for i := n; i < n+2; i++ {
		v, err := source.ReadConnectorObservationValue(ctx, i)
		if err != nil {
			return app.ConnectorObservationOperationRegistration{}, err
		}
		last = v
	}
	out := app.ConnectorObservationOperationRegistration{Registration: x.local.Registration, Last: last}
	out.Registration.FreshUntil = identity.Earlier(out.Registration.FreshUntil, last.Until())
	if x.pairHook != nil {
		x.pairHook(n, &out)
	}
	if x.mode == "sql-revoked-final" && n == 3 {
		return out, value.ErrUnavailable
	}
	return out, nil
}
func (x *operationCoordinatorFixture) ExchangeConnectorObservationOperation(ctx context.Context, p contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error) {
	x.proofs++
	if x.probeHook != nil {
		x.probeHook(&p)
	}
	b, err := contracts.EncodeClusterObservationOperationProbe(p)
	if err != nil {
		return contracts.ConnectorObservationOperationReply{}, err
	}
	parsed, err := contracts.DecodeClusterObservationOperationProbe(b)
	if err != nil {
		return contracts.ConnectorObservationOperationReply{}, err
	}
	w, err := x.channel.AnswerConnectorObservation(ctx, parsed)
	if err != nil {
		return w, err
	}
	raw, err := contracts.EncodeConnectorObservationOperationReply(w)
	if err != nil {
		return w, err
	}
	return contracts.DecodeConnectorObservationOperationReply(raw)
}
func (x *operationCoordinatorFixture) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	x.metadata++
	if x.proofs != 2 || x.native.final.Load() != 0 || x.regionalNative.reads.Load() != 2 {
		return value.ClusterObservationResult{}, value.ErrDenied
	}
	digest, err := app.ClusterObservationRequestDigest(r)
	if err != nil {
		return value.ClusterObservationResult{}, err
	}
	end, _ := ctx.Deadline()
	return value.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: digest, Interval: value.ClusterObservationInterval{ObservedAt: x.f.clock(), FreshUntil: end}, Namespaces: &value.ClusterNamespaceCandidatePage{ResourceVersion: "1", Items: []cfg.NamespaceRef{}}}, nil
}
func (x *operationCoordinatorFixture) ExchangeClusterObservation(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	return x.channel.ObserveCluster(ctx, r)
}
func (x *operationCoordinatorFixture) CompleteClusterObservation(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	x.receipts++
	if x.native.final.Load() != 1 || x.regionalNative.finals.Load() != 1 || x.proofs != 4 {
		return value.ErrDenied
	}
	if err := x.channel.AcceptObservationReceipt(ctx, r); err != nil {
		return err
	}
	if x.mode == "lost-eof" {
		return value.ErrUnavailable
	}
	if x.mode == "closed-before-output" {
		x.server.Close()
	}
	return nil
}
func TestOperationCoordinatorRetainsOneOriginalAndFinal(t *testing.T) {
	x := newOperationCoordinatorFixture(t, "current")
	out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
	if err != nil {
		t.Fatal("coordinator", err, x.pairs, x.proofs, x.metadata, x.receipts)
	}
	if x.native.original.Load() != 1 || x.native.final.Load() != 1 || x.native.closed.Load() != 0 || x.regionalNative.opens.Load() != 1 || x.regionalNative.reads.Load() != 4 || x.regionalNative.finals.Load() != 1 || x.pairs != 2 || x.receipts != 1 {
		t.Fatal("wrong native/SQL/terminal composition")
	}
	before := out.Interval.FreshUntil
	x.hub.Close() // borrower cleanup must not close the locator's native handle.
	end, err := x.operation.CheckFinal(x.ctx)
	if err != nil || end.After(before) || x.native.original.Load() != 1 || x.native.final.Load() != 1 || x.native.closed.Load() != 0 {
		t.Fatal("reopened Original, renewed or closed borrowed final", err)
	}
	x.operation.Close()
	if x.native.closed.Load() != 1 {
		t.Fatal("owner did not close native handle")
	}
	if _, err = x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); err == nil {
		t.Fatal("replayed claimed standby")
	}
}
func TestOperationCoordinatorFinalFailuresSuppressResult(t *testing.T) {
	for _, mode := range []string{"native-mutation", "native-expiry", "sql-revoked-final", "owner-revoked", "source-mutation", "pair-substitution", "lost-eof", "closed-before-output"} {
		t.Run(mode, func(t *testing.T) {
			x := newOperationCoordinatorFixture(t, mode)
			if mode == "native-mutation" {
				x.native.finalHook = func(_ context.Context, v *value.OwnerObservationNativeFacts) error {
					v.Peers[0].WorkloadDigest[0]++
					return nil
				}
			}
			if mode == "native-expiry" {
				x.native.finalHook = func(_ context.Context, _ *value.OwnerObservationNativeFacts) error {
					x.f.advance.Store(int64(6 * time.Second))
					return nil
				}
			}
			if mode == "source-mutation" {
				x.regionalNative.readHook = func(_ context.Context, n int, v *value.ConnectorObservationNativeValue) error {
					if n == 4 {
						v.Source.Roles.Source = "changed"
					}
					return nil
				}
			}
			if mode == "pair-substitution" {
				x.pairHook = func(n int, v *app.ConnectorObservationOperationRegistration) {
					if n == 3 {
						v.Last.BracketID = ownerOtherID
					}
				}
			}
			out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
			if err == nil || out.RequestID != "" || x.metadata != 1 {
				t.Fatal("failed final boundary released output", err, x.metadata, x.proofs, x.receipts)
			}
			if mode != "lost-eof" && mode != "closed-before-output" && x.receipts != 0 {
				t.Fatal("failed proof sent terminal success")
			}
			counts := [4]int{x.pairs, x.proofs, x.metadata, x.receipts}
			if _, err = x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); err == nil || counts != [4]int{x.pairs, x.proofs, x.metadata, x.receipts} {
				t.Fatal("failed operation replay")
			}
		})
	}
}
func TestOperationCoordinatorOwnerWireMutationIsTerminal(t *testing.T) {
	for _, mode := range []string{"v1", "bracket", "channel", "leaf", "request", "native-start", "native-end", "configuration", "missing-final", "early-final"} {
		t.Run(mode, func(t *testing.T) {
			x := newOperationCoordinatorFixture(t, "current")
			x.probeHook = func(p *contracts.ClusterObservationOperationProbe) {
				n := 2
				if mode == "missing-final" {
					n = 4
				}
				if p.Ordinal != n {
					return
				}
				switch mode {
				case "v1":
					p.Owner.Format = contracts.OwnerObservationFormat
				case "bracket":
					p.Owner.BracketID = ownerOtherID
				case "channel":
					p.Owner.ConnectionBinding = ownerObservationHex(artifact.Digest{90})
				case "leaf":
					p.Owner.OwnerLeaf = ownerObservationHex(artifact.Digest{90})
				case "request":
					p.Owner.Request.ID = ownerOtherID
				case "native-start":
					p.Owner.NativeStartedAt = x.f.clock().Add(time.Millisecond).Format(time.RFC3339Nano)
				case "native-end":
					p.Owner.NativeUntil = x.request.NotAfter.Add(time.Second).Format(time.RFC3339Nano)
				case "configuration":
					p.Owner.Configuration.Generation++
				case "missing-final":
					p.Owner.Final = false
				case "early-final":
					p.Owner.Final = true
				}
			}
			out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
			if err == nil || out.RequestID != "" || (mode != "missing-final" && x.metadata != 0) {
				t.Fatal("changed owner proof admitted metadata/output", err, x.metadata)
			}
		})
	}
}
func TestOperationCoordinatorCloseJoinsNativeFinal(t *testing.T) {
	x := newOperationCoordinatorFixture(t, "current")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); x.hub.Close(); x.operation.Close() })
	x.native.finalHook = func(ctx context.Context, _ *value.OwnerObservationNativeFacts) error {
		close(entered)
		<-ctx.Done()
		<-release
		return value.ErrUnavailable
	}
	result := make(chan error, 1)
	go func() { _, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no final read")
	}
	done := make(chan struct{})
	go func() { x.hub.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("Close did not join admitted native read")
	case <-time.After(20 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not complete")
	}
	if err := <-result; err == nil || x.receipts != 0 {
		t.Fatal("cancelled final released success", err)
	}
}

func TestOperationCoordinatorOriginalDeadlineAndCancellation(t *testing.T) {
	for _, mode := range []string{"expired-before-claim", "cancelled-original", "early-final", "second-attach", "different-request", "different-leaf"} {
		t.Run(mode, func(t *testing.T) {
			x := newOperationCoordinatorFixture(t, "current")
			switch mode {
			case "expired-before-claim":
				x.f.advance.Store(int64(6 * time.Second))
			case "cancelled-original":
				x.operation.cancel()
			case "early-final":
				if _, err := x.operation.CheckFinal(x.ctx); err == nil {
					t.Fatal("initial facts became final")
				}
			case "second-attach":
				if err := x.operation.attach(x.ctx, &x.state, ownerOtherID, x.hub.leaf, x.hub.peer, x.operation.request); err != nil {
					t.Fatal(err)
				}
			case "different-request":
				x.request.Challenge = ownerTestID
			case "different-leaf":
				x.operation.leaf.Digest[0]++
			}
			if out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); err == nil || out.RequestID != "" || x.proofs != 0 || x.metadata != 0 {
				t.Fatal("invalid borrow reached regional request", mode, err, x.proofs, x.metadata)
			}
		})
	}
}
func TestOperationCoordinatorOwnerCloseJoinsActualFinal(t *testing.T) {
	x := newOperationCoordinatorFixture(t, "current")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); x.operation.Close(); x.hub.Close() })
	x.native.finalHook = func(ctx context.Context, _ *value.OwnerObservationNativeFacts) error {
		close(entered)
		<-ctx.Done()
		<-release
		return value.ErrUnavailable
	}
	result := make(chan error, 1)
	go func() { _, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no final read")
	}
	done := make(chan struct{})
	go func() { x.operation.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("native owner Close returned before admitted work joined")
	case <-time.After(20 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("native owner Close did not complete")
	}
	if err := <-result; err == nil || x.receipts != 0 {
		t.Fatal("closed original released result", err)
	}
}
func TestOperationCoordinatorFinalFactsCannotRefreshNativeInterval(t *testing.T) {
	x := newOperationCoordinatorFixture(t, "current")
	until := x.f.clock().Add(2 * time.Second)
	x.operation.mu.Lock()
	x.operation.until = until
	x.operation.mu.Unlock()
	if _, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); err != nil {
		t.Fatal(err)
	}
	x.f.advance.Store(int64(2100 * time.Millisecond))
	if _, err := x.operation.CheckFinal(x.ctx); err == nil {
		t.Fatal("retained final facts renewed the original bound")
	}
	if x.native.original.Load() != 1 || x.native.final.Load() != 1 {
		t.Fatal("reopened a native phase")
	}
}

func TestOperationOwnerCarriesShorterCutoffs(t *testing.T) {
	t.Run("constructor", func(t *testing.T) {
		x := newOperationCoordinatorFixture(t, "current")
		registryEnd := x.f.clock().Add(2 * time.Second)
		nativeEnd := registryEnd.Add(-200 * time.Millisecond)
		calls := 0
		registry := forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
			calls++
			if calls == 2 {
				d, _ := ctx.Deadline()
				if d.After(nativeEnd) {
					t.Error("following registry lost earlier native cutoff")
				}
			}
			r, err := x.registry.ReadOwnerRegistration(ctx, c)
			r.FreshUntil = identity.Earlier(r.FreshUntil, registryEnd)
			return r, err
		})
		native := &ownerOperationNativeFixture{facts: x.native.facts.Clone()}
		native.facts.FreshUntil = nativeEnd
		native.originalHook = func(ctx context.Context) {
			d, _ := ctx.Deadline()
			if d.After(registryEnd) {
				t.Error("native original lost earlier registry cutoff")
			}
		}
		o, err := NewOwnerObservationOperation(x.ctx, x.owner, x.operation.request, x.server, registry, native, x.f.clock)
		if err != nil {
			native.Close()
			t.Fatal(err)
		}
		defer o.Close()
		if calls != 2 || o.until.After(nativeEnd) {
			t.Fatal("constructor cutoff not retained")
		}
	})
	t.Run("final", func(t *testing.T) {
		x := newOperationCoordinatorFixture(t, "current")
		registryEnd := x.f.clock().Add(2 * time.Second)
		nativeEnd := registryEnd.Add(-200 * time.Millisecond)
		after := 0
		x.operation.registry = forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
			r, err := x.registry.ReadOwnerRegistration(ctx, c)
			if x.operation.ordinal == 4 {
				r.FreshUntil = identity.Earlier(r.FreshUntil, registryEnd)
				if x.native.final.Load() != 0 {
					after++
					d, _ := ctx.Deadline()
					if d.After(nativeEnd) {
						t.Error("final registry lost earlier native cutoff")
					}
				}
			}
			return r, err
		})
		x.native.finalHook = func(ctx context.Context, v *value.OwnerObservationNativeFacts) error {
			d, _ := ctx.Deadline()
			if d.After(registryEnd) {
				t.Error("final native lost earlier registry cutoff")
			}
			v.FreshUntil = nativeEnd
			return nil
		}
		out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
		if err != nil || after < 1 || out.Interval.FreshUntil.After(nativeEnd) {
			t.Fatal("final cutoff not retained", err, after)
		}
	})
	t.Run("post-metadata", func(t *testing.T) {
		x := newOperationCoordinatorFixture(t, "current")
		end := x.f.clock().Add(2 * time.Second)
		x.operation.registry = forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
			r, err := x.registry.ReadOwnerRegistration(ctx, c)
			if x.metadata > 0 {
				r.FreshUntil = identity.Earlier(r.FreshUntil, end)
			}
			return r, err
		})
		x.pairDeadlineHook = func(ctx context.Context, n int) {
			if n == 3 {
				d, _ := ctx.Deadline()
				if d.After(end) {
					t.Error("following SQL pair lost post-metadata owner cutoff")
				}
			}
		}
		out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
		if err != nil || out.Interval.FreshUntil.After(end) {
			t.Fatal("post-metadata cutoff not retained", err)
		}
	})
	t.Run("wait-expiry", func(t *testing.T) {
		x := newOperationCoordinatorFixture(t, "current")
		until := time.Now().Add(40 * time.Millisecond)
		calls := 0
		registry := forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
			calls++
			r, err := x.registry.ReadOwnerRegistration(ctx, c)
			r.FreshUntil = until
			return r, err
		})
		native := &ownerOperationNativeFixture{facts: x.native.facts.Clone()}
		native.originalHook = func(ctx context.Context) { <-ctx.Done() }
		o, err := NewOwnerObservationOperation(x.ctx, x.owner, x.operation.request, x.server, registry, native, x.f.clock)
		if o != nil {
			o.Close()
		} else {
			native.Close()
		}
		if err == nil || calls != 1 {
			t.Fatal("expired original interval continued SQL", err, calls)
		}
	})
}
