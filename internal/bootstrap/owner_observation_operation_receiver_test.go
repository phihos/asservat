package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// Actual two owner connections plus the complete regional framed exchange.
// Native/SQL/installer/CA facts are synthetic. The assertions establish joined
// HTTP delivery ownership, not sustained real API availability or installation.
type receiverNativeFixture struct {
	pin                                        value.OwnerObservationPin
	mode                                       string
	opens                                      atomic.Int32
	mu                                         sync.Mutex
	last                                       *framedOwnerNative
	beginEntered, beginCancelled, beginRelease chan struct{}
}

func (f *receiverNativeFixture) OpenOwnerObservationOperation(ctx context.Context, r value.OwnerObservationRequest, peers []value.OwnerBinding) (app.OwnerNativeObservationOperation, error) {
	f.opens.Add(1)
	if f.mode == "cancel-native-begin" {
		close(f.beginEntered)
		<-ctx.Done()
		close(f.beginCancelled)
		<-f.beginRelease
		return nil, ctx.Err()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	end, _ := ctx.Deadline()
	facts := value.OwnerObservationNativeFacts{Pin: f.pin, Request: r, ObservedAt: time.Now(), FreshUntil: identity.Earlier(end, r.NotAfter)}
	for _, b := range peers {
		facts.Peers = append(facts.Peers, value.OwnerObservationNativePeer{Binding: b, Pod: "owner-" + b.PodUID, ReplicaSetUID: runtimeID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{41}})
	}
	n := &framedOwnerNative{facts: facts, mode: f.mode, entered: make(chan struct{}), release: make(chan struct{})}
	f.mu.Lock()
	f.last = n
	f.mu.Unlock()
	return n, nil
}

// Count only A's routing/borrowed-operation registry port. The regional
// channel uses its separate original dependency and is not hidden in this count.
type receiverOwnerRegistry struct {
	app.OwnerCertificateRegistry
	reads atomic.Int32
}

func (r *receiverOwnerRegistry) ReadOwnerRegistration(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	r.reads.Add(1)
	return r.OwnerCertificateRegistry.ReadOwnerRegistration(ctx, leaf)
}

type receiverAbortWriter struct{ http.ResponseWriter }

func (w receiverAbortWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w receiverAbortWriter) Write(body []byte) (int, error) {
	if len(body) > 0 {
		_, _ = w.ResponseWriter.Write(body[:1])
		_ = http.NewResponseController(w.ResponseWriter).Flush()
	}
	// The exact full Content-Length was already set. A bounded real prefix
	// makes unknown completion visible to HTTP/2 rather than a pre-write retry.
	panic(http.ErrAbortHandler)
}

type operationReceiverFixture struct {
	root         context.Context
	cancel       context.CancelFunc
	server       *httptest.Server
	base         *runtimeFixture
	owner        *observationForwardFixture
	keys, sender *mtls.OwnerCredentials
	regional     *framedRegionalFixture
	native       *receiverNativeFixture
	registry     *receiverOwnerRegistry
	holder       *wire.HubObservationOperationHolder
	receiver     *OwnerObservationOperationReceiver
	stream       *mtls.ConnectorObservationOperationConnection
	regionalDone chan error
	get, post    atomic.Int32
	mode         string
}

func (f *operationReceiverFixture) request() value.ClusterObservationRequest {
	now := time.Now().UTC()
	end, _ := f.root.Deadline()
	return value.ClusterObservationRequest{RootID: f.owner.pin.RootID, ClusterID: f.regional.pin.Profile.Binding.ClusterID, ID: observationForwardID(510), Challenge: observationForwardID(511), Purpose: value.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: end}
}
func (f *operationReceiverFixture) http(t *testing.T, method, target, media string, body []byte, exact bool) (int, []byte, error) {
	t.Helper()
	return f.httpContext(t, f.root, method, target, media, body, exact)
}
func (f *operationReceiverFixture) httpContext(t *testing.T, ctx context.Context, method, target, media string, body []byte, exact bool) (int, []byte, error) {
	t.Helper()
	authority := f.receiver.CommonAuthority()
	if exact {
		authority = f.receiver.ExactAuthority()
	}
	name, _, _ := net.SplitHostPort(authority)
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxConnsPerHost: 1, TLSClientConfig: &tls.Config{ServerName: name, RootCAs: f.base.roots, GetClientCertificate: f.sender.GetClientCertificate, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}}
	defer tr.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, method, "https://"+authority+target, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Accept", media)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", media)
	}
	resp, e := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, contracts.ClusterObservationClaimBytes+1))
	return resp.StatusCode, b, e
}
func operationReceiverTarget(t *testing.T, r value.ClusterObservationRequest) string {
	t.Helper()
	q := contracts.ClusterObservationOperationLocatorQuery(wire.LocatorQueryWire(r.LocatorQuery()))
	q.Format = contracts.ClusterObservationOperationLocatorFormat
	v, e := contracts.EncodeClusterObservationOperationLocatorTarget(q)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
