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
	value "asservat.local/asservat/internal/domain/fleet"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
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

func newLocalReceiverFixture(t *testing.T, mode string) *localReceiverFixture {
	t.Helper()
	base := newOperationReceiverFixture(t, "joined")
	f := &localReceiverFixture{base: base, mode: mode}
	f.native = &localReceiverNativeFixture{base: receiverNativeFixture{pin: base.owner.pin, mode: mode}, mode: mode}
	receiver, err := newOwnerLocalObservationReceiver(base.root, base.owner.pin, base.keys, base.registry, f.native, base.holder, 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.receiver = receiver
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			f.get.Add(1)
		} else {
			f.post.Add(1)
		}
		if mode == "lost-get" && r.Method == http.MethodGet || mode == "lost-post" && r.Method == http.MethodPost {
			receiver.ServeHTTP(receiverAbortWriter{w}, r)
			return
		}
		receiver.ServeHTTP(w, r)
	}))
	f.server = server
	serving, err := mtls.NewOwnerBootstrapServing(base.keys, base.owner.pin.Pool)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.ConnContext = func(context.Context, net.Conn) context.Context { return base.root }
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: base.base.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}
	server.StartTLS()
	t.Cleanup(func() { receiver.Close(); server.Close() })
	return f
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
func TestLocalReceiverActualFramedClaimAndUncertainDelivery(t *testing.T) {
	for _, mode := range []string{"joined", "lost-get", "lost-post", "revoked-claim", "revoked-final", "owner-final"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalReceiverFixture(t, mode)
			r := f.base.request()
			target := localReceiverTarget(t, r)
			status, body, err := f.http(t, f.base.root, http.MethodGet, target, contracts.ClusterObservationLocalLocatorMedia, nil, false, localObservationFixtureToken)
			if mode == "lost-get" {
				if err == nil {
					t.Fatal("prefix-aborted locator looked complete")
				}
				status, _, _ = f.http(t, f.base.root, http.MethodGet, target, contracts.ClusterObservationLocalLocatorMedia, nil, false, localObservationFixtureToken)
				if status != 503 || f.native.base.opens.Load() != 1 || f.post.Load() != 0 {
					t.Fatal("unknown locator was reissued", status, f.native.base.opens.Load(), f.post.Load())
				}
				return
			}
			if err != nil || status != 200 {
				t.Fatal("locator", status, err)
			}
			locator, err := contracts.DecodeClusterObservationLocalLocator(body)
			if err != nil || locator.Locator == nil {
				t.Fatal("positive exact locator", err)
			}
			claim, err := contracts.EncodeClusterObservationLocalClaim(contracts.ClusterObservationLocalClaim{Format: contracts.ClusterObservationLocalClaimFormat, PodUID: observationForwardID(701), Request: wire.RequestWire(r), Locator: *locator.Locator})
			if err != nil {
				t.Fatal(err)
			}
			status, body, err = f.http(t, f.base.root, http.MethodPost, contracts.ClusterObservationLocalClaimPath, contracts.ClusterObservationLocalClaimMedia, claim, true, localObservationFixtureToken)
			if mode == "joined" {
				digest, _ := wire.RequestDigest(r)
				decoded, de := contracts.DecodeClusterObservationResult(body)
				result, pe := wire.ParseResult(decoded, r, digest, time.Now())
				if err != nil || de != nil || pe != nil || status != 200 || !result.Matches(r, digest, time.Now()) {
					t.Fatal("actual regional completion", status, err, de, pe)
				}
				f.native.mu.Lock()
				last := f.native.last
				f.native.mu.Unlock()
				if last == nil || f.native.claims.Load() != 1 || last.final.Load() != 1 {
					t.Fatal("missing one-use claim/final native")
				}
			} else if mode == "lost-post" {
				if err == nil {
					t.Fatal("prefix-aborted result looked complete")
				}
			} else if status != 503 {
				t.Fatal("revoked or changed source returned result", status, err)
			}
			status, _, _ = f.http(t, f.base.root, http.MethodPost, contracts.ClusterObservationLocalClaimPath, contracts.ClusterObservationLocalClaimMedia, claim, true, localObservationFixtureToken)
			if status != 503 || f.native.claims.Load() != 1 || f.native.base.opens.Load() != 1 {
				t.Fatal("spent claim replayed native work", status, f.native.claims.Load(), f.native.base.opens.Load())
			}
		})
	}
}
func TestLocalReceiverNoTokenAuthorityFromWrongRoute(t *testing.T) {
	for _, mode := range []string{"missing-token", "wrong-token", "lookup-exact-sni", "claim-common-sni"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalReceiverFixture(t, "joined")
			r := f.base.request()
			token := localObservationFixtureToken
			exact := false
			method := http.MethodGet
			target := localReceiverTarget(t, r)
			media := contracts.ClusterObservationLocalLocatorMedia
			var body []byte
			switch mode {
			case "missing-token":
				token = ""
			case "wrong-token":
				token = "wrong"
			case "lookup-exact-sni":
				exact = true
			case "claim-common-sni":
				method = http.MethodPost
				target = contracts.ClusterObservationLocalClaimPath
				media = contracts.ClusterObservationLocalClaimMedia
				body = []byte(`{}`)
			}
			status, _, err := f.http(t, f.base.root, method, target, media, body, exact, token)
			if err != nil || status != 503 || f.native.claims.Load() != 0 {
				t.Fatal("invalid route/token", status, err)
			}
		})
	}
}
func TestLocalReceiverExplicitAbsenceDiffersFromClosedHolder(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "observed-absence", true: "unavailable"}[closed], func(t *testing.T) {
			f := newLocalReceiverFixture(t, "joined")
			r := f.base.request()
			r.ClusterID = observationForwardID(990)
			if closed {
				f.base.holder.Close()
			}
			status, body, err := f.http(t, f.base.root, http.MethodGet, localReceiverTarget(t, r), contracts.ClusterObservationLocalLocatorMedia, nil, false, localObservationFixtureToken)
			if closed {
				if status != 503 {
					t.Fatal("closed holder fabricated absence", status, err)
				}
				return
			}
			v, de := contracts.DecodeClusterObservationLocalLocator(body)
			if err != nil || de != nil || status != 200 || v.Locator != nil {
				t.Fatal("explicit authenticated absence", status, err, de)
			}
			status, _, _ = f.http(t, f.base.root, http.MethodGet, localReceiverTarget(t, r), contracts.ClusterObservationLocalLocatorMedia, nil, false, localObservationFixtureToken)
			if status != 503 || f.native.base.opens.Load() != 1 {
				t.Fatal("absence attempt refilled", status)
			}
		})
	}
}

// The original reservation must retain the earliest proof cutoff after GET
// completes, without inheriting GET handler cancellation or the broader slot.
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
func TestLocalReceiverReservationRetainsShorterOriginalProofBound(t *testing.T) {
	f := newLocalReceiverFixture(t, "joined")
	request := f.base.request()
	until := request.RequestedAt.Add(3 * time.Second)
	f.receiver.registry = localReceiverCutoffRegistry{f.base.registry, until}
	status, body, err := f.http(t, f.base.root, http.MethodGet, localReceiverTarget(t, request), contracts.ClusterObservationLocalLocatorMedia, nil, false, localObservationFixtureToken)
	if err != nil || status != 200 {
		t.Fatal("short original locator", status, err)
	}
	v, err := contracts.DecodeClusterObservationLocalLocator(body)
	if err != nil || v.Locator == nil || !ownerOperationTime(v.Locator.FreshUntil).Equal(until) {
		t.Fatal("locator lost original shorter proof", err)
	}
	f.receiver.pending.mu.Lock()
	e := f.receiver.pending.entries[ownerLocalObservationPendingKey{request.RootID, request.ID}]
	f.receiver.pending.mu.Unlock()
	if e == nil {
		t.Fatal("original pending entry missing")
	}
	e.mu.Lock()
	reservation := e.reservation
	e.mu.Unlock()
	if reservation == nil || !reservation.Until().Equal(until) {
		t.Fatal("reserved regional stream kept broader slot deadline")
	}
	claim, err := contracts.EncodeClusterObservationLocalClaim(contracts.ClusterObservationLocalClaim{Format: contracts.ClusterObservationLocalClaimFormat, PodUID: observationForwardID(701), Request: wire.RequestWire(request), Locator: *v.Locator})
	if err != nil {
		t.Fatal(err)
	}
	status, _, err = f.http(t, f.base.root, http.MethodPost, contracts.ClusterObservationLocalClaimPath, contracts.ClusterObservationLocalClaimMedia, claim, true, localObservationFixtureToken)
	if err != nil || status != 200 {
		t.Fatal("GET exit cancelled retained reservation", status, err)
	}
}
