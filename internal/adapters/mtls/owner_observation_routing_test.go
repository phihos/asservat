package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Real process-owned keys, strict leaf profiles and actual mutual TLS state;
// independently invoked registry/route/native readers are synthetic here.
// Installed SQL/Kubernetes traversal timing remains a separate native gate.
type routingPeerFixture struct {
	checker                      *OwnerObservationRoutingPeers
	server, client               *OwnerCredentials
	state                        tls.ConnectionState
	pin                          value.OwnerObservationPin
	query                        value.ClusterObservationLocatorQuery
	configuration                value.OwnerConfigurationObservation
	serverFixture, clientFixture *ownerCredentialFixture
	mode                         string
	registry, route, guard, work int
	cancel                       context.CancelFunc
	callerEnd                    time.Time
}

func newRoutingPeerFixture(t *testing.T, exact bool) *routingPeerFixture {
	t.Helper()
	now := time.Now().UTC()
	ca := newOwnerTestCA(t, now)
	pool := ownerBootstrapPool()
	pool.NativeCandidateLimit = value.OwnerRegistrationsPerPool
	x := &routingPeerFixture{}
	x.pin = value.OwnerObservationPin{RootID: ownerOtherID, SourceUID: ownerTestID, Pool: pool, TemplateDigest: artifact.Digest{11}, ImageDigest: artifact.Digest{12}, ProtectionDigest: artifact.Digest{13}}
	x.configuration = ownerBootstrapConfiguration(pool, ca, now)
	common, _ := OwnerBootstrapServerName(pool)
	build := func(usage string, b value.OwnerBinding) (*OwnerCredentials, *ownerCredentialFixture) {
		f := newForwardCredentialFixture(t, ca, time.Now)
		if usage == "server" {
			f.mutateLeaf = func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, common) }
		}
		f.mutateRegistration = func(r *value.OwnerRegistrationObservation) {
			r.Enrollment.Pool = pool
			r.Configuration = x.configuration
			r.ObservedAt = time.Now().UTC()
			r.FreshUntil = r.ObservedAt.Add(5 * time.Second)
			r.Configuration.ObservedAt = r.ObservedAt
			r.Configuration.FreshUntil = r.FreshUntil
		}
		c, e := NewOwnerCredentialsForPool(b, usage, pool, ca.roots, f, f, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(c.Close)
		if e = c.Enroll(context.Background()); e != nil {
			t.Fatal("original certificate", e)
		}
		return c, f
	}
	x.server, x.serverFixture = build("server", ownerBootstrapBinding(ownerTestID))
	x.client, x.clientFixture = build("client", ownerBootstrapBinding(ownerOtherID))
	checkBound := func(ctx context.Context) {
		if !x.callerEnd.IsZero() {
			d, ok := ctx.Deadline()
			if !ok || d.After(x.callerEnd) {
				t.Error("original caller deadline widened")
			}
		}
	}
	registry := forwardRegistry(func(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
		checkBound(ctx)
		x.registry++
		if x.mode == "revoked" {
			return value.OwnerRegistrationObservation{}, value.ErrUnavailable
		}
		f := x.serverFixture
		if c.Usage == "client" {
			f = x.clientFixture
		}
		r, e := f.ReadOwnerRegistration(ctx, c)
		switch x.mode {
		case "changed-pool":
			r.Enrollment.Pool.ServiceUID = ownerOtherID
			r.Configuration.Configuration.Pool = r.Enrollment.Pool
		case "removed-root":
			r.Configuration.Configuration.IssuerRoots = nil
		case "suspended":
			r.Configuration.Configuration.Suspended = true
		case "source-replaced":
			r.Configuration.Configuration.Revision.UID = ownerOtherID
		case "revision-changed":
			if c.Usage == "server" {
				r.Configuration.Configuration.Revision.Generation++
			}
		}
		return r, e
	})
	routes := forwardRoutes(func(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
		checkBound(ctx)
		x.route++
		n := time.Now().UTC()
		c := x.configuration
		c.ObservedAt = n
		c.FreshUntil = n.Add(5 * time.Second)
		r := value.OwnerRoute{Configuration: c, Endpoint: value.OwnerEndpoint{Binding: b, Pool: pool, Pod: "owner-1", ReplicaSetUID: ownerTestID, Addresses: []string{"10.0.0.8"}, ObservedAt: n, FreshUntil: c.FreshUntil}, ObservedAt: n, FreshUntil: c.FreshUntil}
		if x.mode == "route-replaced" {
			r.Endpoint.Binding.ProcessEpoch = ownerTestID
		}
		return r, nil
	})
	guard := forwardGuard(func(ctx context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
		checkBound(ctx)
		x.guard++
		n := time.Now().UTC()
		r := value.OwnerProtection{Pool: p, Digest: x.pin.ProtectionDigest, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
		if x.mode == "guard-replaced" {
			r.Digest[0]++
		}
		return r, nil
	})
	work := hubObservationWorkloadFunc(func(ctx context.Context, b value.OwnerBinding, p string) (value.OwnerObservationWorkload, error) {
		checkBound(ctx)
		x.work++
		n := time.Now().UTC()
		r := value.OwnerObservationWorkload{Pin: x.pin, Binding: b, Pod: p, ReplicaSetUID: ownerTestID, WorkloadDigest: artifact.Digest{14}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
		switch x.mode {
		case "template-replaced":
			r.Pin.TemplateDigest[0]++
		case "namespace-replaced":
			r.Pin.Pool.NamespaceUID = ownerOtherID
		case "pod-replaced":
			r.Binding.PodUID = ownerTestID
		case "replicaset-replaced":
			r.ReplicaSetUID = ownerOtherID
		case "expired-workload":
			r.FreshUntil = n
		case "close-serving-key":
			if b == x.server.binding {
				x.server.Close()
			}
		case "cancel-during-last-native":
			if b == x.server.binding {
				x.cancel()
			}
		case "blocked-until-original-end":
			<-ctx.Done()
			return value.OwnerObservationWorkload{}, ctx.Err()
		}
		return r, nil
	})
	var err error
	x.checker, err = NewOwnerObservationRoutingPeers(x.pin, x.server, &app.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: guard, Now: time.Now}, work, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	serving, err := NewOwnerBootstrapServing(x.server, pool)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	server := tls.Server(a, &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}})
	name := common
	if exact {
		name, _ = OwnerServerName(x.server.binding)
	}
	client := tls.Client(b, &tls.Config{GetClientCertificate: x.client.GetClientCertificate, RootCAs: ca.roots, ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	joined := make(chan error, 1)
	go func() { joined <- server.HandshakeContext(ctx) }()
	ce := client.HandshakeContext(ctx)
	if ce != nil {
		a.Close()
		b.Close()
	}
	se := <-joined
	if ce != nil || se != nil {
		t.Fatal("actual TLS", ce, se)
	}
	x.state = server.ConnectionState()
	now = time.Now().UTC()
	x.query = value.ClusterObservationLocatorQuery{RequestID: ownerTestID, Challenge: ownerOtherID, RootID: x.pin.RootID, ClusterID: ownerOtherID, RequestedAt: now, NotAfter: now.Add(4 * time.Second)}
	return x
}

func TestOwnerObservationRoutingPeersActualTLSBothNamesAndFreshReads(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(map[bool]string{false: "common-locator", true: "exact-claim"}[exact], func(t *testing.T) {
			x := newRoutingPeerFixture(t, exact)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			x.callerEnd, _ = ctx.Deadline()
			first, err := x.checker.CheckObservationRouting(ctx, &x.state, x.query)
			if err != nil || !first.Valid(time.Now()) || first.Interval.FreshUntil.After(x.callerEnd) {
				t.Fatal("original peer check", err)
			}
			if x.registry != 4 || x.route != 2 || x.guard != 4 || x.work != 2 {
				t.Fatal("current independent traversals", x.registry, x.route, x.guard, x.work)
			}
			last, err := x.checker.CheckObservationRouting(ctx, &x.state, x.query)
			if err != nil || !first.SamePeers(last) || x.registry != 8 || x.route != 4 || x.guard != 8 || x.work != 4 {
				t.Fatal("second check reused old proofs", err)
			}
			x.mode = "revoked"
			if _, err = x.checker.CheckObservationRouting(ctx, &x.state, x.query); err == nil {
				t.Fatal("reused actual connection bypassed current revocation")
			}
		})
	}
}

func TestOwnerObservationRoutingPeersRejectCurrentChanges(t *testing.T) {
	for _, mode := range []string{"revoked", "changed-pool", "removed-root", "suspended", "source-replaced", "revision-changed", "route-replaced", "guard-replaced", "template-replaced", "namespace-replaced", "pod-replaced", "replicaset-replaced", "expired-workload", "close-serving-key", "cancel-during-last-native", "blocked-until-original-end", "wrong-sni", "wrong-root", "expired-query", "cancelled-caller"} {
		t.Run(mode, func(t *testing.T) {
			x := newRoutingPeerFixture(t, false)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			x.cancel = cancel
			x.callerEnd, _ = ctx.Deadline()
			x.mode = mode
			switch mode {
			case "wrong-sni":
				x.state.ServerName = "unrelated.test"
			case "wrong-root":
				x.query.RootID = ownerTestID
			case "expired-query":
				x.query.NotAfter = time.Now().Add(-time.Nanosecond)
			case "cancelled-caller":
				cancel()
			}
			if _, err := x.checker.CheckObservationRouting(ctx, &x.state, x.query); err == nil {
				t.Fatal("changed/current unavailable peer admitted", mode)
			}
			if (mode == "wrong-sni" || mode == "wrong-root" || mode == "expired-query" || mode == "cancelled-caller") && x.registry != 0 {
				t.Fatal("invalid original tuple reached registry")
			}
		})
	}
}
