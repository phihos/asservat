package clusterobservation

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type routingPeerCheckFunc func(context.Context, *tls.ConnectionState, fleet.ClusterObservationLocatorQuery) (fleet.ClusterObservationRoutingPeers, error)

func (f routingPeerCheckFunc) CheckObservationRouting(c context.Context, s *tls.ConnectionState, q fleet.ClusterObservationLocatorQuery) (fleet.ClusterObservationRoutingPeers, error) {
	return f(c, s, q)
}

// Real mutual TLS/h2 and the real holder/stream, with synthetic native/registry
// proofs. These tests do not qualify installed peer authority or regional RTTs.
type routingTestServer struct {
	handler       *OwnerRoutingHandler
	server        *httptest.Server
	common, exact *http.Transport
	pin           fleet.OwnerObservationPin
	binding       fleet.OwnerBinding
	born          time.Time
	calls         atomic.Int32
}

func (x *routingTestServer) proof(q fleet.ClusterObservationLocatorQuery, end time.Time) fleet.ClusterObservationRoutingPeers {
	now := time.Now().UTC()
	owner := func(b fleet.OwnerBinding, usage, pod string) (fleet.AuthenticatedOwner, fleet.OwnerObservationWorkload) {
		o := fleet.AuthenticatedOwner{Certificate: fleet.OwnerCertificate{Binding: b, Usage: usage, Digest: artifact.Digest{4}, NotBefore: x.born.Add(-time.Minute), NotAfter: x.born.Add(20 * time.Minute)}, EnrollmentID: localID(40), Pool: x.pin.Pool, Pod: pod, ReplicaSetUID: localID(41), ConfigurationRevision: identity.Revision{UID: x.pin.SourceUID, Generation: 1, Digest: artifact.Digest{5}}, ProtectionDigest: x.pin.ProtectionDigest, VerifiedAt: now, ValidUntil: end}
		w := fleet.OwnerObservationWorkload{Pin: x.pin, Binding: b, Pod: pod, ReplicaSetUID: o.ReplicaSetUID, WorkloadDigest: artifact.Digest{6}, ObservedAt: now, FreshUntil: end}
		return o, w
	}
	h, hw := owner(x.binding, "server", "holder-pod")
	sender := x.binding
	sender.PodUID, sender.ProcessEpoch = localID(42), localID(43)
	s, sw := owner(sender, "client", "sender-pod")
	return fleet.ClusterObservationRoutingPeers{Query: q, Pin: x.pin, Sender: s, Holder: h, SenderWorkload: sw, HolderWorkload: hw, Interval: fleet.ClusterObservationInterval{ObservedAt: now, FreshUntil: end}}
}

func newRoutingTestServer(t *testing.T, holder *HubObservationHolder, check func(context.Context, int32, *fleet.ClusterObservationRoutingPeers) error) *routingTestServer {
	t.Helper()
	x := &routingTestServer{born: time.Now().UTC()}
	roots, serverCert, clientCert := hubStreamCertificates(t)
	x.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test-only accept-bound stand-in; the installed native listener retains
		// its own original socket bound and connection accounting separately.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		x.handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	x.server.EnableHTTP2 = true
	x.server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
	x.server.StartTLS()
	_, port, _ := net.SplitHostPort(x.server.Listener.Addr().String())
	nativePort, _ := strconv.Atoi(port)
	pool := fleet.OwnerPool{InstallationID: localID(2), ClusterID: localID(3), IssuerEpoch: localID(4), Namespace: "hub", NamespaceUID: localID(5), Service: "hub", ServiceUID: localID(6), Deployment: "hub", DeploymentUID: localID(7), ServiceAccount: "hub", AccountUID: localID(8), Port: 9443, NativePort: nativePort, NativeBootstrap: fleet.OwnerBootstrapProfile, NativeCandidateLimit: fleet.OwnerRegistrationsPerPool}
	// Avoid an incidental ephemeral test-port collision with the control port.
	if pool.NativePort == pool.Port {
		pool.Port++
	}
	x.pin = fleet.OwnerObservationPin{RootID: localID(1), SourceUID: localID(9), Pool: pool, TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}}
	x.binding = fleet.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: localID(30), ProcessEpoch: localID(31)}
	peers := routingPeerCheckFunc(func(ctx context.Context, state *tls.ConnectionState, q fleet.ClusterObservationLocatorQuery) (fleet.ClusterObservationRoutingPeers, error) {
		if state == nil || len(state.VerifiedChains) == 0 || !state.HandshakeComplete {
			return fleet.ClusterObservationRoutingPeers{}, fleet.ErrDenied
		}
		end, _ := ctx.Deadline()
		v := x.proof(q, end)
		n := x.calls.Add(1)
		if check != nil {
			if err := check(ctx, n, &v); err != nil {
				return fleet.ClusterObservationRoutingPeers{}, err
			}
		}
		return v, nil
	})
	var err error
	x.handler, err = NewOwnerRoutingHandler(context.Background(), net.JoinHostPort("holder.test", port), net.JoinHostPort("other.test", port), x.pin, x.binding, peers, holder, 1, time.Now)
	if err != nil {
		x.server.Close()
		t.Fatal(err)
	}
	transport := func(name string) *http.Transport {
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, ServerName: name, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxConnsPerHost: 1, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, x.server.Listener.Addr().String())
		}}
	}
	x.common, x.exact = transport("holder.test"), transport("other.test")
	t.Cleanup(func() {
		x.handler.Close()
		x.common.CloseIdleConnections()
		x.exact.CloseIdleConnections()
		x.server.Close()
	})
	return x
}

func routingQueryTarget(t *testing.T, q fleet.ClusterObservationLocatorQuery) string {
	t.Helper()
	target, err := contracts.EncodeClusterObservationLocatorTarget(contracts.ClusterObservationLocatorQuery{Format: contracts.ClusterObservationLocatorFormat, RootID: q.RootID, ClusterID: q.ClusterID, RequestID: q.RequestID, Challenge: q.Challenge, RequestedAt: writeTime(q.RequestedAt), NotAfter: writeTime(q.NotAfter)})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func routingHTTP(ctx context.Context, tr *http.Transport, host, target, method, media string, body []byte) (*http.Response, []byte, error) {
	r, err := http.NewRequestWithContext(ctx, method, "https://"+host+target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	r.Header.Set("Accept", media)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", media)
	}
	response, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(r)
	if err != nil {
		return response, nil, err
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, contracts.ClusterObservationClaimBytes+1))
	return response, b, err
}

func routingLookup(t *testing.T, x *routingTestServer, ctx context.Context, q fleet.ClusterObservationLocatorQuery) contracts.ClusterObservationLocator {
	t.Helper()
	r, b, err := routingHTTP(ctx, x.common, x.handler.CommonAuthority(), routingQueryTarget(t, q), http.MethodGet, contracts.ClusterObservationLocatorMediaType, nil)
	if err != nil || r.StatusCode != 200 || r.ProtoMajor != 2 {
		t.Fatal("lookup", r, err)
	}
	v, err := contracts.DecodeClusterObservationLocator(b)
	if err != nil || !parseLocator(v).Matches(q, x.binding, time.Now()) {
		t.Fatal("locator", err)
	}
	return v
}

func routingAnswerStream(response *http.Response, writer *io.PipeWriter, request fleet.ClusterObservationRequest, receipt chan<- struct{}, release <-chan struct{}) error {
	for step := 0; step < 6; step++ {
		frame, err := contracts.ReadClusterObservationFrame(response.Body)
		if err != nil {
			return err
		}
		var b []byte
		switch frame.Kind {
		case contracts.ClusterObservationProbeFrame:
			probe, e := contracts.DecodeClusterObservationProbe(frame.Payload)
			if e != nil {
				return e
			}
			b, err = contracts.EncodeConnectorObservationReply(contracts.ConnectorObservationReply{Format: contracts.ConnectorObservationFormat, Ordinal: probe.Ordinal, Request: probe.Owner.Request, ObservedAt: writeTime(time.Now()), FreshUntil: writeTime(request.NotAfter)})
			if err == nil {
				err = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationSourceFrame, Payload: b})
			}
		case contracts.ClusterObservationReadFrame:
			b, err = contracts.EncodeClusterObservationResult(ResultWire(localResult(request)))
			if err == nil {
				err = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationResultFrame, Payload: b})
			}
		case contracts.ClusterObservationReceiptFrame:
			if step != 5 {
				return fmt.Errorf("early terminal frame")
			}
			close(receipt)
			<-release
			err = writer.Close()
		default:
			err = fmt.Errorf("unexpected frame kind")
		}
		clear(frame.Payload)
		clear(b)
		if err != nil {
			return err
		}
	}
	var extra [1]byte
	n, err := response.Body.Read(extra[:])
	if n != 0 || err != io.EOF {
		return fmt.Errorf("missing response EOF")
	}
	return nil
}

func TestObservationRoutingActualTLSRejectsWrongPurposeBeforeProof(t *testing.T) {
	for _, mode := range []string{"lookup-exact-sni", "claim-common-sni", "no-client-cert", "wrong-authority", "authorization", "cookie", "origin", "idempotency", "extra-query", "wrong-media", "lookup-body"} {
		t.Run(mode, func(t *testing.T) {
			holder, _ := NewHubObservationHolder(context.Background(), 1, time.Now)
			defer holder.Close()
			x := newRoutingTestServer(t, holder, nil)
			request := localRequest()
			request.NotAfter = time.Now().Add(time.Second)
			target := routingQueryTarget(t, request.LocatorQuery())
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			method, host, tr := http.MethodGet, x.handler.CommonAuthority(), x.common
			var body []byte
			if mode == "claim-common-sni" {
				method, target = http.MethodPost, contracts.ClusterObservationClaimPath
				body = []byte("{}")
				host = x.handler.ExactAuthority()
			}
			if mode == "lookup-exact-sni" {
				tr = x.exact
			}
			if mode == "no-client-cert" {
				tr.TLSClientConfig.Certificates = nil
			}
			if mode == "extra-query" {
				target += "&other=1"
			}
			if mode == "lookup-body" {
				body = []byte("x")
			}
			r, err := http.NewRequestWithContext(ctx, method, "https://"+host+target, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Accept", contracts.ClusterObservationLocatorMediaType)
			if method == http.MethodPost {
				r.Header.Set("Content-Type", contracts.ClusterObservationClaimMediaType)
				r.Header.Set("Accept", contracts.ClusterObservationClaimMediaType)
			}
			switch mode {
			case "wrong-authority":
				r.Host = x.handler.ExactAuthority()
			case "authorization":
				r.Header.Set("Authorization", "synthetic-forbidden")
			case "cookie":
				r.Header.Set("Cookie", "synthetic-forbidden")
			case "origin":
				r.Header.Set("Origin", "https://holder.test")
			case "idempotency":
				r.Header.Set("Idempotency-Key", localID(90))
			case "wrong-media":
				r.Header.Set("Accept", "application/json")
			}
			out, e := (&http.Client{Transport: tr}).Do(r)
			if out != nil {
				io.Copy(io.Discard, out.Body)
				out.Body.Close()
			}
			if e == nil && out.StatusCode == 200 || x.calls.Load() != 0 {
				t.Fatal("unqualified HTTP purpose reached peer proof", mode, e, x.calls.Load())
			}
		})
	}
}

func TestObservationRoutingCloseJoinsBlockedAuthorityAndRetainsSlot(t *testing.T) {
	holder, _ := NewHubObservationHolder(context.Background(), 1, time.Now)
	defer holder.Close()
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	x := newRoutingTestServer(t, holder, func(ctx context.Context, _ int32, _ *fleet.ClusterObservationRoutingPeers) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q := localRequest().LocatorQuery()
	q.NotAfter = time.Now().Add(time.Second)
	target := routingQueryTarget(t, q)
	finished := make(chan struct{})
	go func() {
		routingHTTP(ctx, x.common, x.handler.CommonAuthority(), target, http.MethodGet, contracts.ClusterObservationLocatorMediaType, nil)
		close(finished)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("authority not entered")
	}
	closed := make(chan struct{})
	go func() { x.handler.Close(); close(closed) }()
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("Close did not cancel authority")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before authority joined")
	default:
	}
	x.handler.mu.Lock()
	active := x.handler.active
	x.handler.mu.Unlock()
	if active != 1 {
		t.Fatal("unjoined work released slot")
	}
	once.Do(func() { close(release) })
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("Close did not join")
	}
	<-finished
	if x.handler.enter() {
		x.handler.leave()
		t.Fatal("closed handler accepted replacement")
	}
}
