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

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Actual independent HWORK HTTPS connections plus existing actual framed R
// stream. Native/SQL/installer/CA authority remains explicitly synthetic.
const localObservationFixtureToken = "synthetic-projected-observation-token"

type localReceiverNativeFixture struct {
	base   receiverNativeFixture
	mode   string
	mu     sync.Mutex
	last   *localReceiverNative
	claims atomic.Int32
}
type localReceiverNative struct {
	*framedOwnerNative
	fixture *localReceiverNativeFixture
	token   []byte
	pod     string
	claimed atomic.Bool
	mu      sync.Mutex
	once    sync.Once
}

func (f *localReceiverNativeFixture) begin(ctx context.Context, r value.OwnerObservationRequest, b value.OwnerBinding, token []byte, pod string) (ownerLocalNativeOperation, error) {
	if string(token) != localObservationFixtureToken || pod != observationForwardID(701) {
		return nil, value.ErrDenied
	}
	n, err := f.base.OpenOwnerObservationOperation(ctx, r, []value.OwnerBinding{b})
	if err != nil {
		return nil, err
	}
	v := &localReceiverNative{framedOwnerNative: n.(*framedOwnerNative), fixture: f, token: bytes.Clone(token), pod: pod}
	f.mu.Lock()
	f.last = v
	f.mu.Unlock()
	return v, nil
}
func (n *localReceiverNative) Claim(ctx context.Context, token []byte, pod string) (time.Time, error) {
	n.fixture.claims.Add(1)
	n.mu.Lock()
	defer n.mu.Unlock()
	if ctx.Err() != nil || n.fixture.mode == "revoked-claim" || !bytes.Equal(token, n.token) || pod != n.pod || !n.claimed.CompareAndSwap(false, true) {
		return time.Time{}, value.ErrUnavailable
	}
	return n.facts.FreshUntil, nil
}
func (n *localReceiverNative) Final(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	if !n.claimed.Load() || n.fixture.mode == "revoked-final" {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return n.framedOwnerNative.Final(ctx)
}
func (n *localReceiverNative) Close() {
	n.once.Do(func() { n.framedOwnerNative.Close(); n.mu.Lock(); clear(n.token); n.mu.Unlock() })
}

type localReceiverFixture struct {
	base      *operationReceiverFixture
	native    *localReceiverNativeFixture
	receiver  *OwnerLocalObservationReceiver
	server    *httptest.Server
	get, post atomic.Int32
	mode      string
}

func (f *localReceiverFixture) http(t *testing.T, ctx context.Context, method, target, media string, body []byte, exact bool, token string) (int, []byte, error) {
	t.Helper()
	authority := f.receiver.CommonAuthority()
	if exact {
		authority = f.receiver.ExactAuthority()
	}
	name, _, _ := net.SplitHostPort(authority)
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxConnsPerHost: 1, TLSClientConfig: &tls.Config{ServerName: name, RootCAs: f.base.base.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}}
	defer tr.CloseIdleConnections()
	var input io.Reader
	if method == http.MethodPost {
		input = io.NopCloser(bytes.NewReader(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+authority+target, input)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Accept", media)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", media)
	}
	response, err := tr.RoundTrip(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, contracts.ClusterObservationBytes+1))
	return response.StatusCode, data, err
}
func localReceiverTarget(t *testing.T, r value.ClusterObservationRequest) string {
	t.Helper()
	target, err := contracts.EncodeClusterObservationLocalLocatorTarget(contracts.ClusterObservationLocalLocatorQuery{PodUID: observationForwardID(701), Query: ownerLocalQueryWire(r.LocatorQuery())})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// The reservation retains the original native/request bound after GET while
// independent current SQL still restricts claim and final output.
type localReceiverCutoffRegistry struct {
	app.OwnerCertificateRegistry
	until time.Time
}

func (r localReceiverCutoffRegistry) ReadOwnerRegistration(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	v, err := r.OwnerCertificateRegistry.ReadOwnerRegistration(ctx, leaf)
	if err == nil && v.FreshUntil.After(r.until) {
		v.FreshUntil = r.until
	}
	return v, err
}
