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
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

// The socket, TLS, h2, handler/holder and all closure paths are concrete. Current
// owner/connector registries and native workload proofs are synthetic here;
// this is not installed delegation or two-cluster availability qualification.
type regionalSocketConversation struct {
	stream           *wire.HubObservationStream
	hello            contracts.ClusterObservationHello
	entered, release chan struct{}
	closes           atomic.Int32
}

func (c *regionalSocketConversation) Close() { c.closes.Add(1) }
func (c *regionalSocketConversation) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	if c.entered != nil {
		close(c.entered)
		<-ctx.Done()
		<-c.release
		return value.ClusterObservationResult{}, ctx.Err()
	}
	var result value.ClusterObservationResult
	formatTime := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	owner := contracts.OwnerObservationRequest{Format: contracts.OwnerObservationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: formatTime(r.RequestedAt), NotAfter: formatTime(r.NotAfter)}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		end, _ := ctx.Deadline()
		p := contracts.ClusterObservationProbe{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: c.hello.ExchangeID, Ordinal: ordinal, Owner: contracts.OwnerObservationReply{Format: contracts.OwnerObservationFormat, Request: owner, ObservedAt: formatTime(time.Now()), FreshUntil: formatTime(end)}}
		if _, err := c.stream.ExchangeConnectorObservation(ctx, p); err != nil {
			return value.ClusterObservationResult{}, err
		}
		if ordinal == 2 {
			var err error
			result, err = c.stream.ExchangeClusterObservation(ctx, r)
			if err != nil {
				return value.ClusterObservationResult{}, err
			}
		}
	}
	encoded := wire.ResultWire(result)
	err := c.stream.CompleteClusterObservation(ctx, contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: c.hello.ExchangeID, RequestID: r.ID, Challenge: r.Challenge, RequestDigest: encoded.RequestDigest})
	return result, err
}

type regionalSocketFixture struct {
	listener                           net.Listener
	authority                          string
	roots                              *x509.CertPool
	client                             tls.Certificate
	ctx                                context.Context
	cancel                             context.CancelFunc
	done                               chan error
	holder                             *wire.HubObservationHolder
	own                                *wire.OwnerHandler
	local                              *wire.LocalHandler
	regional                           *wire.HubObservationHandler
	created                            chan *regionalSocketConversation
	factoryCalls, ownCalls, localCalls atomic.Int32
	originalEnd                        chan time.Time
	ownEnd                             chan time.Time
	entered, release                   chan struct{}
	closeOnce                          sync.Once
}

func newRegionalSocketFixture(t *testing.T, lifetime time.Duration, blocked bool) *regionalSocketFixture {
	t.Helper()
	roots, server, client := observationTLSFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	x := &regionalSocketFixture{listener: listener, authority: net.JoinHostPort("owner-proof.test", port), roots: roots, client: client, ctx: ctx, cancel: cancel, done: make(chan error, 1), created: make(chan *regionalSocketConversation, 2), originalEnd: make(chan time.Time, 2), ownEnd: make(chan time.Time, 2)}
	if blocked {
		x.entered, x.release = make(chan struct{}), make(chan struct{})
	}
	x.own, err = wire.NewOwnerHandler(ctx, x.authority, ownerObservationCall(func(c context.Context, _ *tls.ConnectionState, r contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error) {
		x.ownCalls.Add(1)
		d, _ := c.Deadline()
		x.ownEnd <- d
		return contracts.OwnerObservationReply{Format: contracts.OwnerObservationFormat, Request: r, ObservedAt: r.RequestedAt, FreshUntil: d.UTC().Format(time.RFC3339Nano)}, nil
	}), 1, time.Now)
	if err != nil {
		cancel()
		listener.Close()
		t.Fatal(err)
	}
	pin := value.ClusterObservationCallerPin{RootID: nativeID, InstallationID: nativeID, ClusterID: nativeID, Namespace: cfg.NamespaceRef{Name: "hub", UID: nativeID}, Account: "hwork", AccountUID: nativeID, Deployment: "hwork", DeploymentUID: nativeID, TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}}
	x.local, err = wire.NewLocalHandler(ctx, x.authority, pin, observationLocalCaller(func(context.Context, []byte, string, value.ClusterObservationRequest) (value.ClusterObservationCaller, error) {
		x.localCalls.Add(1)
		return value.ClusterObservationCaller{}, value.ErrDenied
	}), observationLocalExchange{}, 1, time.Now)
	if err != nil {
		cancel()
		listener.Close()
		x.own.Close()
		t.Fatal(err)
	}
	x.holder, err = wire.NewHubObservationHolder(ctx, 2, time.Now)
	if err != nil {
		cancel()
		listener.Close()
		x.own.Close()
		x.local.Close()
		t.Fatal(err)
	}
	x.regional, err = wire.NewHubObservationHandler(x.authority, x.holder, func(root, setup context.Context, s *tls.ConnectionState, h contracts.ClusterObservationHello, stream *wire.HubObservationStream) (wire.HubObservationConversation, error) {
		if root.Err() != nil || setup.Err() != nil || s == nil || len(s.VerifiedChains) == 0 {
			return nil, value.ErrDenied
		}
		x.factoryCalls.Add(1)
		end, _ := root.Deadline()
		x.originalEnd <- end
		c := &regionalSocketConversation{stream: stream, hello: h, entered: x.entered, release: x.release}
		x.created <- c
		return c, nil
	}, time.Now)
	if err != nil {
		cancel()
		listener.Close()
		x.own.Close()
		x.local.Close()
		t.Fatal(err)
	}
	go func() {
		x.done <- native.ServeOwnerRegionalObservation(ctx, listener, roots, syntheticServingCertificate{server}, x.own, x.local, x.regional, 1, 1)
	}()
	t.Cleanup(func() {
		if x.release != nil {
			x.closeOnce.Do(func() { close(x.release) })
		}
		cancel()
		listener.Close()
		x.regional.Close()
		x.local.Close()
		x.own.Close()
		select {
		case err := <-x.done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("listener cleanup did not join")
		}
	})
	return x
}
func (x *regionalSocketFixture) transport(t *testing.T, certificate bool) *http.Transport {
	t.Helper()
	config := &tls.Config{RootCAs: x.roots, ServerName: "owner-proof.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if certificate {
		config.Certificates = []tls.Certificate{x.client}
	}
	tr := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, network, x.listener.Addr().String())
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}
func (x *regionalSocketFixture) open(t *testing.T, ctx context.Context, certificate bool, id string) (*http.Response, *io.PipeWriter) {
	t.Helper()
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+x.authority+contracts.ClusterObservationExchangePath, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Content-Type", contracts.ClusterObservationExchangeMedia)
	request.Header.Set("Accept", contracts.ClusterObservationExchangeMedia)
	written := make(chan error, 1)
	go func() {
		b, e := contracts.EncodeClusterObservationHello(contracts.ClusterObservationHello{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: id, RootID: nativeID, ClusterID: nativeID})
		if e == nil {
			e = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationHelloFrame, Payload: b})
		}
		clear(b)
		written <- e
	}()
	response, err := (&http.Client{Transport: x.transport(t, certificate)}).Do(request)
	if err != nil {
		writer.CloseWithError(err)
		reader.Close()
		<-written
		t.Fatal(err)
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
func (x *regionalSocketFixture) locate(t *testing.T) wire.HubObservationLocator {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		l, e := x.holder.Lookup(x.ctx, nativeID, nativeID)
		if e == nil {
			return l
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("actual header-flushed standby was not located")
	return wire.HubObservationLocator{}
}
func regionalSocketRequest() value.ClusterObservationRequest {
	n := time.Now().UTC()
	return value.ClusterObservationRequest{RootID: nativeID, ClusterID: nativeID, ID: nativeID, Challenge: nativeID, Purpose: value.ObserveCapacityNamespaces, RequestedAt: n, NotAfter: n.Add(2 * time.Second)}
}

func TestOwnerRegionalObservationListenerSeparatePurposeCapacity(t *testing.T) {
	x := newRegionalSocketFixture(t, 12*time.Second, false)
	r, w := x.open(t, x.ctx, true, nativeID)
	if r.StatusCode != http.StatusOK || r.ProtoMajor != 2 || r.ContentLength != -1 {
		t.Fatal("standby did not use actual streaming h2", r.StatusCode, r.Proto)
	}
	x.locate(t)
	original := <-x.originalEnd
	rootEnd, _ := x.ctx.Deadline()
	if original.After(rootEnd) || original.After(time.Now().Add(30*time.Second)) {
		t.Fatal("socket residency exceeded original parent/accept interval")
	}
	// Wait beyond the proof purpose's five-second accept bound. This is only
	// passive socket residency: no authority or source operation is repeated.
	terminal := make(chan error, 1)
	go func() { var b [1]byte; _, e := r.Body.Read(b[:]); terminal <- e }()
	timer := time.NewTimer(5200 * time.Millisecond)
	defer timer.Stop()
	select {
	case e := <-terminal:
		t.Fatal("standby inherited proof bound", e)
	case <-timer.C:
	case <-x.ctx.Done():
		t.Fatal(x.ctx.Err())
	}
	rejected, _ := x.open(t, x.ctx, true, "22222222-2222-4222-8222-222222222222")
	if rejected.StatusCode == http.StatusOK || x.factoryCalls.Load() != 1 {
		t.Fatal("regional purpose consumed proof reservation", rejected.StatusCode, x.factoryCalls.Load())
	}
	rejected.Body.Close()
	response, err := observationPost(x.ctx, &http.Client{Transport: x.transport(t, true)}, x.authority, contracts.OwnerObservationPath, observationWireRequest(), false)
	if err != nil {
		t.Fatal("idle standby blocked independently reserved proof", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || x.ownCalls.Load() != 1 {
		t.Fatal("proof did not retain independent capacity", response.StatusCode, x.ownCalls.Load())
	}
	w.Close()
	r.Body.Close()
	select {
	case <-terminal:
	case <-time.After(time.Second):
		t.Fatal("actual standby reader did not join")
	}
}

func TestOwnerRegionalObservationListenerCleanTerminalEOF(t *testing.T) {
	x := newRegionalSocketFixture(t, 5*time.Second, false)
	response, writer := x.open(t, x.ctx, true, nativeID)
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	locator := x.locate(t)
	request := regionalSocketRequest()
	done := make(chan error, 1)
	go func() { _, err := x.holder.Observe(x.ctx, locator, request); done <- err }()
	for i := 0; i < 6; i++ {
		frame, err := contracts.ReadClusterObservationFrame(response.Body)
		if err != nil {
			t.Fatal("actual response frame", i, err)
		}
		var payload []byte
		switch frame.Kind {
		case contracts.ClusterObservationProbeFrame:
			p, e := contracts.DecodeClusterObservationProbe(frame.Payload)
			if e != nil {
				t.Fatal(e)
			}
			payload, err = contracts.EncodeConnectorObservationReply(contracts.ConnectorObservationReply{Format: contracts.ConnectorObservationFormat, Request: p.Owner.Request, Ordinal: p.Ordinal, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), FreshUntil: request.NotAfter.UTC().Format(time.RFC3339Nano)})
			if err == nil {
				err = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationSourceFrame, Payload: payload})
			}
		case contracts.ClusterObservationReadFrame:
			digest, e := wire.RequestDigest(request)
			if e != nil {
				t.Fatal(e)
			}
			result := value.ClusterObservationResult{RootID: request.RootID, ClusterID: request.ClusterID, RequestID: request.ID, Challenge: request.Challenge, Purpose: request.Purpose, RequestDigest: digest, Interval: value.ClusterObservationInterval{ObservedAt: time.Now(), FreshUntil: request.NotAfter}, Namespaces: &value.ClusterNamespaceCandidatePage{ResourceVersion: "1", Items: []cfg.NamespaceRef{}}}
			payload, err = contracts.EncodeClusterObservationResult(wire.ResultWire(result))
			if err == nil {
				err = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationResultFrame, Payload: payload})
			}
		case contracts.ClusterObservationReceiptFrame:
			if i != 5 {
				t.Fatal("early Receipt")
			}
			if _, e := x.holder.Lookup(x.ctx, nativeID, nativeID); e == nil {
				t.Fatal("Receipt preceded exact routing closure")
			}
			err = writer.Close()
		default:
			t.Fatal("unexpected purpose frame", frame.Kind)
		}
		clear(payload)
		clear(frame.Payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("joined result", err)
		}
	case <-x.ctx.Done():
		t.Fatal(x.ctx.Err())
	}
	var extra [1]byte
	if n, e := response.Body.Read(extra[:]); n != 0 || e != io.EOF {
		t.Fatal("listener lost clean final response EOF", n, e)
	}
}

func TestOwnerRegionalObservationListenerCloseJoinsActualClaim(t *testing.T) {
	x := newRegionalSocketFixture(t, 5*time.Second, true)
	response, _ := x.open(t, x.ctx, true, nativeID)
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	l := x.locate(t)
	result := make(chan error, 1)
	go func() { _, e := x.holder.Observe(x.ctx, l, regionalSocketRequest()); result <- e }()
	select {
	case <-x.entered:
	case <-time.After(time.Second):
		t.Fatal("claim not admitted")
	}
	x.cancel()
	select {
	case e := <-x.done:
		x.done <- e
		t.Fatal("listener returned before admitted coordinator joined")
	case <-time.After(20 * time.Millisecond):
	}
	x.closeOnce.Do(func() { close(x.release) })
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("cancelled call succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("claim failed to join")
	}
	// Fixture cleanup consumes the actual listener terminal after the same join.
}

func TestOwnerRegionalObservationListenerRetainsOriginalParentEnd(t *testing.T) {
	x := newRegionalSocketFixture(t, 450*time.Millisecond, false)
	response, _ := x.open(t, x.ctx, true, nativeID)
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	got := <-x.originalEnd
	want, _ := x.ctx.Deadline()
	if !got.Equal(want) {
		t.Fatal("handler reset original shorter stream bound")
	}
	var b [1]byte
	if _, e := response.Body.Read(b[:]); e == nil {
		t.Fatal("expired original socket remained usable")
	}
	if _, e := x.holder.Lookup(context.Background(), nativeID, nativeID); e == nil {
		t.Fatal("expired socket remained claimable")
	}
}

func TestOwnerRegionalObservationListenerRequiresCertificateForStandby(t *testing.T) {
	x := newRegionalSocketFixture(t, 3*time.Second, false)
	response, _ := x.open(t, x.ctx, false, nativeID)
	if response.StatusCode == http.StatusOK || x.factoryCalls.Load() != 0 {
		t.Fatal("certificate-free local TLS entered regional purpose")
	}
	response.Body.Close()
}

func TestOwnerRegionalObservationListenerProofUsesAcceptTimeNotPathTime(t *testing.T) {
	x := newRegionalSocketFixture(t, 8*time.Second, false)
	raw, err := (&net.Dialer{}).DialContext(x.ctx, "tcp", x.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	connection := tls.Client(raw, &tls.Config{RootCAs: x.roots, Certificates: []tls.Certificate{x.client}, ServerName: "owner-proof.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true})
	if err = connection.HandshakeContext(x.ctx); err != nil {
		t.Fatal(err)
	}
	handshaken := time.Now()
	timer := time.NewTimer(600 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-x.ctx.Done():
		t.Fatal(x.ctx.Err())
	}
	var dialed atomic.Bool
	transport := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		if !dialed.CompareAndSwap(false, true) {
			return nil, errors.New("unexpected additional fixture dial")
		}
		return connection, nil
	}}
	defer transport.CloseIdleConnections()
	request := observationWireRequest()
	now := time.Now().UTC()
	request.RequestedAt, request.NotAfter = now.Format(time.RFC3339Nano), now.Add(5*time.Second).Format(time.RFC3339Nano)
	response, err := observationPost(x.ctx, &http.Client{Transport: transport}, x.authority, contracts.OwnerObservationPath, request, false)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || x.ownCalls.Load() != 1 {
		t.Fatal("delayed exact proof rejected", response.StatusCode)
	}
	got := <-x.ownEnd
	if got.After(handshaken.Add(5 * time.Second)) {
		t.Fatal("path selection manufactured a new five-second interval")
	}
	if !got.Before(now.Add(4700 * time.Millisecond)) {
		t.Fatal("delayed request did not spend original accept interval")
	}
}

func TestOwnerRegionalObservationListenerUnclassifiedSocketExpires(t *testing.T) {
	x := newRegionalSocketFixture(t, 5*time.Second, false)
	socket, err := net.Dial("tcp", x.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	var b [1]byte
	_, err = socket.Read(b[:])
	if err == nil || time.Since(start) > 2800*time.Millisecond {
		t.Fatal("unclassified socket exceeded original two-second prelude", err)
	}
	if x.factoryCalls.Load() != 0 || x.ownCalls.Load() != 0 || x.localCalls.Load() != 0 {
		t.Fatal("unclassified socket reached a purpose")
	}
}
