package native_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

// Actual socket/TLS/h2/holder admission and joined cancellation. The receiver
// and regional factory deliberately supply synthetic authority; no native API,
// SQL, installed selection or complete-path availability is inferred here.
type operationSocketLocal struct {
	common, exact    string
	calls            atomic.Int32
	end              chan time.Time
	entered, release chan struct{}
	once             sync.Once
}

func (h *operationSocketLocal) CommonAuthority() string {
	if h == nil {
		return ""
	}
	return h.common
}
func (h *operationSocketLocal) ExactAuthority() string {
	if h == nil {
		return ""
	}
	return h.exact
}
func (h *operationSocketLocal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls.Add(1)
	end, _ := r.Context().Deadline()
	h.end <- end
	if h.entered != nil {
		h.once.Do(func() { close(h.entered) })
		<-r.Context().Done()
		<-h.release
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type operationSocketConversation struct{ closed atomic.Int32 }

func (c *operationSocketConversation) Close() { c.closed.Add(1) }
func (c *operationSocketConversation) ObserveCluster(ctx context.Context, _ value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	return value.ClusterObservationResult{}, value.ErrUnavailable
}

type operationSocketFixture struct {
	listener       net.Listener
	roots          *x509.CertPool
	server, client tls.Certificate
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan error
	joined         sync.Once
	releaseOnce    sync.Once
	local          *operationSocketLocal
	regional       *wire.HubObservationOperationHandler
	holder         *wire.HubObservationOperationHolder
	factoryCalls   atomic.Int32
	originalEnd    chan time.Time
}

func newOperationSocketFixture(t *testing.T, blocked bool) *operationSocketFixture {
	t.Helper()
	roots, server, client := observationTLSFixture(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	x := &operationSocketFixture{listener: listener, roots: roots, server: server, client: client, ctx: ctx, cancel: cancel, done: make(chan error, 1), originalEnd: make(chan time.Time, 4)}
	x.local = &operationSocketLocal{common: net.JoinHostPort("owner-proof.test", port), exact: net.JoinHostPort("exact-owner.test", port), end: make(chan time.Time, 16)}
	if blocked {
		x.local.entered = make(chan struct{})
		x.local.release = make(chan struct{})
	}
	x.holder, e = wire.NewHubObservationOperationHolder(ctx, 2, time.Now)
	if e != nil {
		cancel()
		listener.Close()
		t.Fatal(e)
	}
	x.regional, e = wire.NewHubObservationOperationHandler(x.local.common, x.holder, func(root, setup context.Context, s *tls.ConnectionState, h contracts.ClusterObservationHello, stream *wire.HubObservationOperationStream) (wire.HubObservationOperationConversation, error) {
		if root.Err() != nil || setup.Err() != nil || s == nil || len(s.VerifiedChains) == 0 {
			return nil, value.ErrDenied
		}
		x.factoryCalls.Add(1)
		end, _ := root.Deadline()
		x.originalEnd <- end
		return &operationSocketConversation{}, nil
	}, time.Now)
	if e != nil {
		cancel()
		listener.Close()
		x.holder.Close()
		t.Fatal(e)
	}
	go func() {
		x.done <- native.ServeOwnerObservationOperation(ctx, listener, roots, syntheticServingCertificate{server}, x.local, x.regional, 1, 1)
	}()
	t.Cleanup(func() { x.release(); cancel(); listener.Close(); x.regional.Close(); x.join(t) })
	return x
}
func (x *operationSocketFixture) release() {
	if x.local.release != nil {
		x.releaseOnce.Do(func() { close(x.local.release) })
	}
}
func (x *operationSocketFixture) join(t *testing.T) {
	t.Helper()
	x.joined.Do(func() {
		select {
		case e := <-x.done:
			if e != nil && !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("v2 listener did not join")
		}
	})
}
func (x *operationSocketFixture) transport(t *testing.T, sni string, cert bool) *http.Transport {
	t.Helper()
	c := &tls.Config{RootCAs: x.roots, ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if cert {
		c.Certificates = []tls.Certificate{x.client}
	}
	tr := &http.Transport{TLSClientConfig: c, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, x.listener.Addr().String())
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}
func (x *operationSocketFixture) request(t *testing.T, sni, host, path, method string, cert bool) (*http.Response, error) {
	t.Helper()
	q, e := http.NewRequestWithContext(x.ctx, method, "https://"+host+path, nil)
	if e != nil {
		t.Fatal(e)
	}
	return (&http.Client{Transport: x.transport(t, sni, cert)}).Do(q)
}
func (x *operationSocketFixture) open(t *testing.T, cert bool, id string) (*http.Response, *io.PipeWriter) {
	t.Helper()
	reader, writer := io.Pipe()
	q, e := http.NewRequestWithContext(x.ctx, http.MethodPost, "https://"+x.local.common+contracts.ClusterObservationOperationExchangePath, reader)
	if e != nil {
		t.Fatal(e)
	}
	q.ContentLength = -1
	q.Header.Set("Content-Type", contracts.ClusterObservationOperationExchangeMedia)
	q.Header.Set("Accept", contracts.ClusterObservationOperationExchangeMedia)
	written := make(chan error, 1)
	go func() {
		b, e := contracts.EncodeClusterObservationHello(contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: id, RootID: nativeID, ClusterID: nativeID})
		if e == nil {
			e = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationHelloFrame, Payload: b})
		}
		clear(b)
		written <- e
	}()
	response, e := (&http.Client{Transport: x.transport(t, "owner-proof.test", cert)}).Do(q)
	if e != nil {
		writer.CloseWithError(e)
		reader.Close()
		<-written
		t.Fatal(e)
	}
	if response.StatusCode != http.StatusOK {
		writer.Close()
		reader.Close()
	}
	if e := <-written; e != nil && response.StatusCode == http.StatusOK {
		writer.Close()
		reader.Close()
		response.Body.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { writer.Close(); reader.Close(); response.Body.Close() })
	return response, writer
}

func TestOwnerObservationOperationListenerExactPurposes(t *testing.T) {
	x := newOperationSocketFixture(t, false)
	for _, v := range []struct {
		name, sni, host, path, method string
		cert, allow                   bool
	}{
		{"local-locator", "owner-proof.test", x.local.common, contracts.ClusterObservationLocalLocatorPath + "?closed=query", http.MethodGet, false, true},
		{"local-claim", "exact-owner.test", x.local.exact, contracts.ClusterObservationLocalClaimPath, http.MethodPost, false, true},
		{"common-cannot-claim", "owner-proof.test", x.local.common, contracts.ClusterObservationLocalClaimPath, http.MethodPost, false, false},
		{"exact-cannot-locate", "exact-owner.test", x.local.exact, contracts.ClusterObservationLocalLocatorPath, http.MethodGet, false, false},
		{"host-cannot-change-sni", "owner-proof.test", x.local.exact, contracts.ClusterObservationLocalClaimPath, http.MethodPost, false, false},
		{"client-certificate-cannot-be-hwork", "owner-proof.test", x.local.common, contracts.ClusterObservationLocalLocatorPath, http.MethodGet, true, false},
		{"claim-query", "exact-owner.test", x.local.exact, contracts.ClusterObservationLocalClaimPath + "?x=y", http.MethodPost, false, false},
		{"wrong-method", "owner-proof.test", x.local.common, contracts.ClusterObservationLocalLocatorPath, http.MethodPost, false, false},
		{"legacy-local-disabled", "owner-proof.test", x.local.common, contracts.ClusterObservationLocalPath, http.MethodPost, false, false},
		{"legacy-regional-disabled", "owner-proof.test", x.local.common, contracts.ClusterObservationExchangePath, http.MethodPost, true, false},
		{"owner-proof-disabled", "owner-proof.test", x.local.common, contracts.OwnerObservationPath, http.MethodPost, true, false},
		{"public-disabled", "owner-proof.test", x.local.common, "/", http.MethodGet, false, false},
	} {
		t.Run(v.name, func(t *testing.T) {
			before := x.local.calls.Load()
			r, e := x.request(t, v.sni, v.host, v.path, v.method, v.cert)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Body.Close()
			if r.ProtoMajor != 2 {
				t.Fatal("actual h2 missing")
			}
			if (r.StatusCode == http.StatusNoContent) != v.allow || x.local.calls.Load() != before+map[bool]int32{true: 1, false: 0}[v.allow] {
				t.Fatal("closed purpose dispatch", r.StatusCode, x.local.calls.Load()-before)
			}
		})
	}
	r, _ := x.open(t, false, nativeID)
	defer r.Body.Close()
	if r.StatusCode == http.StatusOK || x.factoryCalls.Load() != 0 {
		t.Fatal("anonymous regional dispatch")
	}
}
func TestOwnerObservationOperationListenerStandbyPreservesProofCapacity(t *testing.T) {
	x := newOperationSocketFixture(t, false)
	r, _ := x.open(t, true, nativeID)
	if r.StatusCode != http.StatusOK || r.ProtoMajor != 2 || r.ContentLength != -1 {
		t.Fatal("actual regional h2 stream", r.StatusCode)
	}
	original := <-x.originalEnd
	parent, _ := x.ctx.Deadline()
	if original.After(parent) || original.After(time.Now().Add(30*time.Second)) {
		t.Fatal("renewed socket residency")
	}
	closed := make(chan error, 1)
	go func() { var b [1]byte; _, e := r.Body.Read(b[:]); closed <- e }()
	select {
	case <-time.After(5200 * time.Millisecond):
	case e := <-closed:
		t.Fatal("standby inherited proof expiry", e)
	case <-x.ctx.Done():
		t.Fatal(x.ctx.Err())
	}
	other, _ := x.open(t, true, "22222222-2222-4222-8222-222222222222")
	other.Body.Close()
	if other.StatusCode == http.StatusOK || x.factoryCalls.Load() != 1 {
		t.Fatal("standby consumed proof slot")
	}
	proof, e := x.request(t, "owner-proof.test", x.local.common, contracts.ClusterObservationLocalLocatorPath, http.MethodGet, false)
	if e != nil {
		t.Fatal(e)
	}
	proof.Body.Close()
	if proof.StatusCode != http.StatusNoContent {
		t.Fatal("standby blocked proof")
	}
	x.cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled regional body did not join")
	}
}
func TestOwnerObservationOperationListenerCloseJoinsHandler(t *testing.T) {
	x := newOperationSocketFixture(t, true)
	q, err := http.NewRequestWithContext(x.ctx, http.MethodGet, "https://"+x.local.common+contracts.ClusterObservationLocalLocatorPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: x.transport(t, "owner-proof.test", false)}
	done := make(chan struct{})
	go func() {
		r, _ := client.Do(q)
		if r != nil {
			r.Body.Close()
		}
		close(done)
	}()
	select {
	case <-x.local.entered:
	case <-time.After(time.Second):
		t.Fatal("local handler not entered")
	}
	x.cancel()
	select {
	case <-x.done:
		t.Fatal("listener released live handler")
	case <-time.After(50 * time.Millisecond):
	}
	x.release()
	x.join(t)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not join")
	}
}
func TestOwnerObservationOperationListenerAcceptPreludeAndProofDeadline(t *testing.T) {
	x := newOperationSocketFixture(t, false)
	raw, e := net.Dial("tcp", x.listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	started := time.Now()
	var b [1]byte
	_, e = raw.Read(b[:])
	if e == nil || time.Since(started) > 2800*time.Millisecond {
		t.Fatal("unclassified accept exceeded original prelude", e)
	}
	tr := x.transport(t, "owner-proof.test", false)
	dial := tr.DialContext
	var accepted atomic.Int64
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, e := dial(ctx, network, address)
		if e != nil {
			return nil, e
		}
		accepted.Store(time.Now().UnixNano())
		time.Sleep(200 * time.Millisecond)
		return c, nil
	}
	q, e := http.NewRequestWithContext(x.ctx, http.MethodGet, "https://"+x.local.common+contracts.ClusterObservationLocalLocatorPath, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := (&http.Client{Transport: tr}).Do(q)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	end := <-x.local.end
	if r.StatusCode != http.StatusNoContent || end.After(time.Unix(0, accepted.Load()).Add(5050*time.Millisecond)) || !end.Before(time.Now().Add(4900*time.Millisecond)) {
		t.Fatal("proof deadline restarted after handshake", time.Until(end))
	}
}
func TestOwnerObservationOperationListenerRejectsInvalidTuple(t *testing.T) {
	roots, server, _ := observationTLSFixture(t)
	for _, v := range []struct {
		name, common, exact, regional string
		p, r                          int
	}{
		{"same-name", "owner-proof.test:9444", "owner-proof.test:9444", "owner-proof.test:9444", 1, 1},
		{"different-port", "owner-proof.test:9444", "exact-owner.test:9445", "owner-proof.test:9444", 1, 1},
		{"wrong-regional", "owner-proof.test:9444", "exact-owner.test:9444", "different.test:9444", 1, 1},
		{"ip", "127.0.0.1:9444", "exact-owner.test:9444", "owner-proof.test:9444", 1, 1},
		{"noncanonical-port", "owner-proof.test:09444", "exact-owner.test:9444", "owner-proof.test:9444", 1, 1},
		{"no-proof-reservation", "owner-proof.test:9444", "exact-owner.test:9444", "owner-proof.test:9444", 0, 1},
		{"over-total", "owner-proof.test:9444", "exact-owner.test:9444", "owner-proof.test:9444", 64, 1},
	} {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ln, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			holder, e := wire.NewHubObservationOperationHolder(ctx, 1, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			defer holder.Close()
			regional, e := wire.NewHubObservationOperationHandler(v.regional, holder, func(context.Context, context.Context, *tls.ConnectionState, contracts.ClusterObservationHello, *wire.HubObservationOperationStream) (wire.HubObservationOperationConversation, error) {
				t.Error("invalid tuple invoked authority")
				return nil, value.ErrUnavailable
			}, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			defer regional.Close()
			local := &operationSocketLocal{common: v.common, exact: v.exact}
			if e := native.ServeOwnerObservationOperation(ctx, ln, roots, syntheticServingCertificate{server}, local, regional, v.p, v.r); !errors.Is(e, contracts.ErrNativeProtocol) {
				t.Fatal("invalid tuple admitted", e)
			}
		})
	}
}
