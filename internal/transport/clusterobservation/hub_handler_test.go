package clusterobservation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
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
type hubStreamConversation struct {
	stream                   *HubObservationStream
	hello                    contracts.ClusterObservationHello
	proofs, metadata, closes atomic.Int32
}

func (c *hubStreamConversation) Close() { c.closes.Add(1) }
func (c *hubStreamConversation) ObserveCluster(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var result fleet.ClusterObservationResult
	owner := contracts.OwnerObservationRequest{Format: contracts.OwnerObservationFormat, RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: writeTime(r.RequestedAt), NotAfter: writeTime(r.NotAfter)}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		end, _ := ctx.Deadline()
		probe := contracts.ClusterObservationProbe{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: c.hello.ExchangeID, Ordinal: ordinal, Owner: contracts.OwnerObservationReply{Format: contracts.OwnerObservationFormat, Request: owner, ObservedAt: writeTime(time.Now()), FreshUntil: writeTime(end)}}
		c.proofs.Add(1)
		if _, err := c.stream.ExchangeConnectorObservation(ctx, probe); err != nil {
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
	err := c.stream.CompleteClusterObservation(ctx, contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: c.hello.ExchangeID, RequestID: r.ID, Challenge: r.Challenge, RequestDigest: writeDigest(digest)})
	return result, err
}

func hubStreamCertificates(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaves := make([]tls.Certificate, 2)
	for i, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if i == 0 {
			leaf.DNSNames = []string{"holder.test", "other.test"}
		}
		der, e = x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), key)
		if e != nil {
			t.Fatal(e)
		}
		leaves[i] = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
	}
	return roots, leaves[0], leaves[1]
}

type hubStreamTestServer struct {
	holder    *HubObservationHolder
	handler   *HubObservationHandler
	server    *httptest.Server
	transport *http.Transport
	authority string
	created   chan *hubStreamConversation
	requests  atomic.Int32
	root      context.Context
	cancel    context.CancelFunc
}

func newHubStreamTestServer(t *testing.T) *hubStreamTestServer {
	t.Helper()
	root, cancel := context.WithCancel(context.Background())
	x := &hubStreamTestServer{root: root, cancel: cancel, created: make(chan *hubStreamConversation, 1)}
	roots, serverCert, clientCert := hubStreamCertificates(t)
	x.holder, _ = NewHubObservationHolder(root, 1, time.Now)
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
	x.handler, err = NewHubObservationHandler(x.authority, x.holder, func(root, setup context.Context, state *tls.ConnectionState, hello contracts.ClusterObservationHello, stream *HubObservationStream) (HubObservationConversation, error) {
		if root.Err() != nil || setup.Err() != nil || state == nil || len(state.VerifiedChains) == 0 {
			return nil, fleet.ErrUnavailable
		}
		c := &hubStreamConversation{stream: stream, hello: hello}
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

func hubStreamLocator(t *testing.T, x *hubStreamTestServer, ctx context.Context) HubObservationLocator {
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

func TestHubObservationHandlerCancellationDuringHelloJoinsSlot(t *testing.T) {
	x := newHubStreamTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+x.authority+contracts.ClusterObservationExchangePath, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Content-Type", contracts.ClusterObservationExchangeMedia)
	request.Header.Set("Accept", contracts.ClusterObservationExchangeMedia)
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
