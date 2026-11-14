package clusterobservation

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// Actual receiving HTTP/2 and mutual TLS, with a purpose-fixed synthetic
// coordinator. This fixture proves stream/holder lifetimes, not SQL activation,
// native source/workload authority or installed/load-balanced reachability.
type hubOperationStreamConversation struct {
	stream                   *HubObservationOperationStream
	hello                    contracts.ClusterObservationHello
	proofs, metadata, closes atomic.Int32
}

func (c *hubOperationStreamConversation) Close() { c.closes.Add(1) }
func (c *hubOperationStreamConversation) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var result fleet.ClusterObservationResult
	owner := contracts.ObservationOperationRequest{Format: contracts.OwnerObservationOperationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: writeTime(r.RequestedAt), NotAfter: writeTime(r.NotAfter)}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		end, _ := ctx.Deadline()
		probe := contracts.ClusterObservationOperationProbe{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: c.hello.ExchangeID, Ordinal: ordinal, Owner: contracts.OwnerObservationOperationReply{Format: contracts.OwnerObservationOperationFormat, Request: owner, NativeStartedAt: writeTime(r.RequestedAt), NativeUntil: writeTime(end), RegistrationUntil: writeTime(end)}}
		c.proofs.Add(1)
		if _, err := c.stream.ExchangeConnectorObservationOperation(ctx, probe); err != nil {
			return fleet.ClusterObservationResult{}, err
		}
		if ordinal == 2 {
			c.metadata.Add(1)
			var err error
			result, err = c.stream.ExchangeClusterObservation(ctx, r)
			if err != nil {
				return fleet.ClusterObservationResult{}, err
			}
		}
	}
	digest, _ := RequestDigest(r)
	err := c.stream.CompleteClusterObservation(ctx, contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: c.hello.ExchangeID, RequestID: r.ID, Challenge: r.Challenge, RequestDigest: writeDigest(digest)})
	return result, err
}

type hubOperationStreamTestServer struct {
	holder    *HubObservationOperationHolder
	handler   *HubObservationOperationHandler
	server    *httptest.Server
	transport *http.Transport
	authority string
	created   chan *hubOperationStreamConversation
	requests  atomic.Int32
	root      context.Context
	cancel    context.CancelFunc
}

func newHubOperationStreamTestServer(t *testing.T) *hubOperationStreamTestServer {
	t.Helper()
	root, cancel := context.WithCancel(context.Background())
	x := &hubOperationStreamTestServer{root: root, cancel: cancel, created: make(chan *hubOperationStreamConversation, 1)}
	roots, serverCert, clientCert := hubStreamCertificates(t)
	x.holder, _ = NewHubObservationOperationHolder(root, 1, time.Now)
	x.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.requests.Add(1)
		// Test-only listener authority: the real installed listener must start
		// this bound at accept and retain its independent socket slot to close.
		ctx, stop := context.WithTimeout(r.Context(), 3*time.Second)
		defer stop()
		x.handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	x.server.EnableHTTP2 = true
	x.server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
	x.server.StartTLS()
	_, port, _ := net.SplitHostPort(x.server.Listener.Addr().String())
	x.authority = net.JoinHostPort("holder.test", port)
	var err error
	x.handler, err = NewHubObservationOperationHandler(x.authority, x.holder, func(root, setup context.Context, state *tls.ConnectionState, hello contracts.ClusterObservationHello, stream *HubObservationOperationStream) (HubObservationOperationConversation, error) {
		if root.Err() != nil || setup.Err() != nil || state == nil || len(state.VerifiedChains) == 0 {
			return nil, fleet.ErrUnavailable
		}
		c := &hubOperationStreamConversation{stream: stream, hello: hello}
		x.created <- c
		return c, nil
	}, time.Now)
	if err != nil {
		cancel()
		x.server.Close()
		t.Fatal(err)
	}
	x.transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, ServerName: "holder.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}, ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxConnsPerHost: 1, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, x.server.Listener.Addr().String())
	}}
	t.Cleanup(func() { cancel(); x.handler.Close(); x.transport.CloseIdleConnections(); x.server.Close() })
	return x
}

func hubOperationStreamLocator(t *testing.T, x *hubOperationStreamTestServer, ctx context.Context) HubObservationLocator {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		l, err := x.holder.Lookup(ctx, localID(1), localID(12))
		if err == nil {
			return l
		}
		time.Sleep(time.Millisecond) // Test-only wait for response-header publication.
	}
	t.Fatal("header-flushed standby was not published")
	return HubObservationLocator{}
}

func TestHubObservationOperationHandlerCancellationDuringHelloJoinsSlot(t *testing.T) {
	x := newHubOperationStreamTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+x.authority+contracts.ClusterObservationOperationExchangePath, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Content-Type", contracts.ClusterObservationOperationExchangeMedia)
	request.Header.Set("Accept", contracts.ClusterObservationOperationExchangeMedia)
	returned := make(chan error, 1)
	go func() {
		response, err := (&http.Client{Transport: x.transport}).Do(request)
		if response != nil {
			response.Body.Close()
		}
		returned <- err
	}()
	end := time.Now().Add(time.Second)
	admitted := false
	for time.Now().Before(end) {
		x.holder.mu.Lock()
		admitted = len(x.holder.entries) == 1
		x.holder.mu.Unlock()
		if admitted {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !admitted {
		cancel()
		reader.Close()
		writer.Close()
		<-returned
		t.Fatal("Hello read never admitted")
	}
	cancel()
	reader.Close()
	writer.Close()
	if err = <-returned; err == nil {
		t.Fatal("cancelled unread Hello succeeded")
	}
	x.handler.Close()
	select {
	case <-x.created:
		t.Fatal("cancelled Hello reached coordinator")
	default:
	}
	x.holder.mu.Lock()
	count := len(x.holder.entries)
	x.holder.mu.Unlock()
	if count != 0 {
		t.Fatal("setup cancellation failed to join slot", count)
	}
}
