package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type connectorObservationTestExchange func(context.Context, int) (contracts.ConnectorObservationReply, error)

func (f connectorObservationTestExchange) ReadConnectorObservation(ctx context.Context, n int) (contracts.ConnectorObservationReply, error) {
	return f(ctx, n)
}

// Real retained mutual TLS/h2 and real process keys; only source/SQL/native
// observation contents below are synthetic. This is not native qualification.
func connectorObservationTestTLS(t *testing.T) (*connectorPairFixture, *ConnectorProcessCredentials, value.ConnectorObservationPin, value.OwnerObservationPin, ConnectorProcessObservation, context.Context, *tls.ConnectionState) {
	t.Helper()
	f := newConnectorPairFixture(t)
	c := f.owner()
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	local, e := c.ObserveConnectorProcess(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	pin := value.ConnectorObservationPin{Profile: f.profile.Clone(), Roles: f.roles, TemplateDigest: artifact.Digest{11}, ImageDigest: artifact.Digest{12}, ProtectionDigest: artifact.Digest{17}}
	owner := value.OwnerObservationPin{RootID: f.profile.RootID, SourceUID: ownerTestID, Pool: ownerBootstrapPool(), TemplateDigest: artifact.Digest{13}, ImageDigest: artifact.Digest{14}, ProtectionDigest: artifact.Digest{15}}
	common, _ := OwnerBootstrapServerName(owner.Pool)
	ca := newOwnerTestCA(t, f.clock())
	leaf := ca.leaf(t, f.clock(), ownerBootstrapBinding(ownerTestID), true, func(v *x509.Certificate) { v.DNSNames = append(v.DNSNames, common) })
	type admitted struct {
		ctx   context.Context
		state *tls.ConnectionState
	}
	ready := make(chan admitted, 1)
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready <- admitted{r.Context(), r.TLS}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.clientCA.roots, SessionTicketsDisabled: true}
	server.StartTLS()
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: common, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetClientCertificate: c.GetClientCertificate}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ended := make(chan error, 1)
	go func() {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+common+"/", nil)
		resp, e := (&http.Client{Transport: tr}).Do(r)
		if e == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			e = resp.Body.Close()
		}
		ended <- e
	}()
	t.Cleanup(func() { close(release); cancel(); <-ended; tr.CloseIdleConnections(); server.Close() })
	select {
	case v := <-ready:
		return f, c, pin, owner, local, v.ctx, v.state
	case e := <-ended:
		ended <- e
		t.Fatal("actual h2 admission", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil, nil, value.ConnectorObservationPin{}, value.OwnerObservationPin{}, ConnectorProcessObservation{}, nil, nil
}

func TestRemoteConnectorSourceReadsFreshEveryTimeAndPreservesFirstDeadline(t *testing.T) {
	f, _, p, owner, local, ctx, state := connectorObservationTestTLS(t)
	request := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	channel, e := ownerObservationConnection(state, request)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	exchange := connectorObservationTestExchange(func(call context.Context, n int) (contracts.ConnectorObservationReply, error) {
		calls++
		if calls != n {
			t.Errorf("source read ordinal=%d calls=%d", n, calls)
		}
		source, _ := f.ReadConnectorIdentitySource(call)
		until := request.RequestedAt.Add(2 * time.Second)
		if n > 1 {
			until = request.RequestedAt.Add(4 * time.Second)
		}
		w := value.ConnectorObservationWorkload{Process: local.Request.Process, Pod: "connector-1", ReplicaSetUID: ownerTestID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: f.clock(), FreshUntil: until}
		return connectorObservationReplyWire(value.ConnectorObservation{Request: request, Ordinal: n, ConnectionBinding: channel, Certificate: local.Registration.Certificate, Source: source, Workload: w, ObservedAt: f.clock(), FreshUntil: until}, p)
	})
	s, e := NewRemoteConnectorObservationSource(ctx, p, owner, request, state, exchange, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for i := 1; i <= 4; i++ {
		if i > 1 {
			f.advance.Store(int64(time.Second))
		}
		x, e := s.ReadConnectorIdentitySource(ctx)
		if e != nil || calls != i || !x.Observation.FreshUntil.Equal(request.RequestedAt.Add(2*time.Second)) {
			t.Fatal("fresh reads or original interval lost", i, calls, e, x.Observation.FreshUntil)
		}
		if i == 1 {
			if _, e = s.MatchRegistration(local.Registration); e == nil {
				t.Fatal("one proof substituted for bracketed registry read")
			}
		}
		if i == 2 || i == 4 {
			if _, e = s.MatchRegistration(local.Registration); e != nil {
				t.Fatal("exact registration rejected", e)
			}
		}
	}
	if _, e = s.ReadConnectorIdentitySource(ctx); e == nil || calls != 4 {
		t.Fatal("source allowance refilled", calls, e)
	}
	f.advance.Store(int64(2 * time.Second))
	if _, e = s.MatchRegistration(local.Registration); e == nil {
		t.Fatal("first source deadline renewed by later source reads")
	}
}

func TestRemoteConnectorSourceUnknownAndChangedProofRemainUnavailable(t *testing.T) {
	for _, mode := range []string{"unknown", "ordinal", "challenge", "channel", "process", "backing", "workload", "revision"} {
		t.Run(mode, func(t *testing.T) {
			f, _, p, owner, local, ctx, state := connectorObservationTestTLS(t)
			r := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
			channel, e := ownerObservationConnection(state, r)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			exchange := connectorObservationTestExchange(func(call context.Context, n int) (contracts.ConnectorObservationReply, error) {
				calls++
				if n == 2 && mode == "unknown" {
					return contracts.ConnectorObservationReply{}, value.ErrUnavailable
				}
				source, _ := f.ReadConnectorIdentitySource(call)
				w := value.ConnectorObservationWorkload{Process: local.Request.Process, Pod: "connector-1", ReplicaSetUID: ownerTestID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: f.clock(), FreshUntil: r.NotAfter}
				out, e := connectorObservationReplyWire(value.ConnectorObservation{Request: r, Ordinal: n, ConnectionBinding: channel, Certificate: local.Registration.Certificate, Source: source, Workload: w, ObservedAt: f.clock(), FreshUntil: r.NotAfter}, p)
				if n == 2 {
					switch mode {
					case "ordinal":
						out.Ordinal = 1
					case "challenge":
						out.Request.Challenge = ownerTestID
					case "channel":
						out.ConnectionBinding = ownerObservationHex(artifact.Digest{99})
					case "process":
						out.ProcessEpoch = ownerOtherID
					case "backing":
						out.BackingRevision++
					case "workload":
						out.WorkloadDigest = ownerObservationHex(artifact.Digest{99})
					case "revision":
						out.Configuration.Generation++
						out.Configuration.Digest = ownerObservationHex(artifact.Digest{99})
					}
				}
				return out, e
			})
			s, e := NewRemoteConnectorObservationSource(ctx, p, owner, r, state, exchange, f.clock)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = s.ReadConnectorIdentitySource(ctx); e != nil {
				t.Fatal(e)
			}
			if _, e = s.ReadConnectorIdentitySource(ctx); e == nil {
				t.Fatal("changed or unknown proof accepted")
			}
			if _, e = s.ReadConnectorIdentitySource(ctx); e == nil || calls != 2 {
				t.Fatal("failed source query replayed", calls, e)
			}
			if _, e = s.MatchRegistration(app.ConnectorLeafRegistration{}); e == nil {
				t.Fatal("failed source became registry authority")
			}
		})
	}
}

func TestRemoteConnectorSourceCloseJoinsAdmittedProofAndDeniesConcurrentRead(t *testing.T) {
	f, _, p, owner, _, ctx, state := connectorObservationTestTLS(t)
	r := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	exchange := connectorObservationTestExchange(func(call context.Context, n int) (contracts.ConnectorObservationReply, error) {
		if n != 1 {
			t.Errorf("unexpected ordinal %d", n)
		}
		close(entered)
		<-call.Done()
		close(cancelled)
		// Cancellation is observed but the real socket owner has not yet joined.
		<-release
		return contracts.ConnectorObservationReply{}, call.Err()
	})
	s, e := NewRemoteConnectorObservationSource(ctx, p, owner, r, state, exchange, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { once.Do(func() { close(release) }); s.Close() })
	read := make(chan error, 1)
	go func() { _, e := s.ReadConnectorIdentitySource(ctx); read <- e }()
	<-entered
	if _, e := s.ReadConnectorIdentitySource(ctx); e == nil {
		t.Fatal("concurrent source read admitted")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	<-cancelled
	select {
	case <-closed:
		t.Fatal("Close returned before admitted exchange joined")
	default:
	}
	once.Do(func() { close(release) })
	if e := <-read; e == nil {
		t.Fatal("cancelled original read returned authority")
	}
	<-closed
	if _, e := s.ReadConnectorIdentitySource(ctx); e == nil {
		t.Fatal("closed source reopened")
	}
}
