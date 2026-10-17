package clusterobservation

import (
	"bytes"
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

func (x *hubOperationStreamTestServer) open(t *testing.T, ctx context.Context) (*http.Response, *io.PipeWriter, contracts.ClusterObservationHello) {
	t.Helper()
	hello := contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, RootID: localID(1), ClusterID: localID(12), ExchangeID: localID(99)}
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+x.authority+contracts.ClusterObservationOperationExchangePath, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Content-Type", contracts.ClusterObservationOperationExchangeMedia)
	request.Header.Set("Accept", contracts.ClusterObservationOperationExchangeMedia)
	written := make(chan error, 1)
	go func() {
		b, e := contracts.EncodeClusterObservationHello(hello)
		if e == nil {
			e = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationHelloFrame, Payload: b})
		}
		clear(b)
		written <- e
	}()
	response, err := (&http.Client{Transport: x.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		_ = writer.CloseWithError(err)
		_ = reader.Close()
		<-written
		t.Fatal(err)
	}
	if e := <-written; e != nil {
		response.Body.Close()
		writer.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { writer.Close(); reader.Close(); response.Body.Close() })
	return response, writer, hello
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

func TestHubObservationOperationStreamActualHTTP2TerminalAndClaim(t *testing.T) {
	for _, mode := range []string{"joined", "extra-request-byte", "missing-request-eof", "cancel-after-claim"} {
		t.Run(mode, func(t *testing.T) {
			x := newHubOperationStreamTestServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			response, writer, hello := x.open(t, ctx)
			if response.ProtoMajor != 2 || response.StatusCode != 200 || response.ContentLength != -1 {
				t.Fatal("not streaming h2", response.StatusCode, response.Proto, response.ContentLength)
			}
			conversation := <-x.created
			request := localRequest()
			request.NotAfter = time.Now().Add(600 * time.Millisecond)
			locator := hubOperationStreamLocator(t, x, ctx)
			claim := make(chan error, 1)
			go func() { _, err := x.holder.Observe(ctx, locator, request); claim <- err }()
			if mode == "cancel-after-claim" {
				// Reading the first probe proves an admitted actual write before
				// cancellation; local cancellation alone is never success.
				if _, err := contracts.ReadClusterObservationFrame(response.Body); err != nil {
					t.Fatal(err)
				}
				cancel()
			} else {
				for step := 0; step < 6; step++ {
					frame, err := contracts.ReadClusterObservationFrame(response.Body)
					if err != nil {
						t.Fatal("frame", step, err)
					}
					var body []byte
					switch frame.Kind {
					case contracts.ClusterObservationProbeFrame:
						probe, e := contracts.DecodeClusterObservationOperationProbe(frame.Payload)
						if e != nil {
							t.Fatal(e)
						}
						body, err = contracts.EncodeConnectorObservationOperationReply(contracts.ConnectorObservationOperationReply{Format: contracts.ConnectorObservationOperationFormat, Ordinal: probe.Ordinal, Request: probe.Owner.Request, NativeStartedAt: writeTime(request.RequestedAt), NativeUntil: writeTime(request.NotAfter), SourceFreshUntil: writeTime(request.NotAfter), WorkloadFreshUntil: writeTime(request.NotAfter)})
						if err == nil {
							err = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationSourceFrame, Payload: body})
						}
					case contracts.ClusterObservationReadFrame:
						body, err = contracts.EncodeClusterObservationResult(ResultWire(localResult(request)))
						if err == nil {
							err = contracts.WriteClusterObservationFrame(writer, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationResultFrame, Payload: body})
						}
					case contracts.ClusterObservationReceiptFrame:
						if step != 5 {
							t.Fatal("early receipt")
						}
						if _, e := x.holder.Lookup(ctx, hello.RootID, hello.ClusterID); e == nil {
							t.Fatal("receipt sent before routing removal")
						}
						if _, e := x.holder.Observe(ctx, locator, request); e == nil {
							t.Fatal("old locator claimed after receipt")
						}
						short, stop := context.WithTimeout(ctx, time.Second)
						if e, eerr := x.holder.reserve(short); eerr == nil {
							e.close()
							t.Fatal("unjoined receipt released slot")
						}
						stop()
						switch mode {
						case "joined":
							err = writer.Close()
						case "extra-request-byte":
							_, err = writer.Write([]byte{1})
							_ = writer.Close()
						case "missing-request-eof":
						}
					default:
						t.Fatal("unexpected frame", frame.Kind)
					}
					clear(frame.Payload)
					clear(body)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			select {
			case err := <-claim:
				if (mode == "joined") != (err == nil) {
					t.Fatal("terminal result", mode, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("claim did not join original bound")
			}
			if mode == "joined" {
				var extra [1]byte
				n, err := response.Body.Read(extra[:])
				if n != 0 || err != io.EOF {
					t.Fatal("response did not end cleanly", n, err)
				}
			}
			x.holder.mu.Lock()
			remaining := len(x.holder.entries)
			x.holder.mu.Unlock()
			if remaining != 0 || conversation.closes.Load() != 1 || x.requests.Load() != 1 {
				t.Fatal("unfinished/replayed stream", remaining, conversation.closes.Load(), x.requests.Load())
			}
			if mode != "cancel-after-claim" && (conversation.proofs.Load() != 4 || conversation.metadata.Load() != 1) {
				t.Fatal("phase replay or missing call")
			}
		})
	}
}

func TestHubObservationOperationHandlerActualTLSAndClosedRequest(t *testing.T) {
	for _, mode := range []string{"wrong-sni", "no-client-cert", "fixed-body", "wrong-authority", "credential-header", "query", "wrong-media", "v1-hello"} {
		t.Run(mode, func(t *testing.T) {
			x := newHubOperationStreamTestServer(t)
			if mode == "wrong-sni" {
				x.transport.TLSClientConfig.ServerName = "other.test"
			}
			if mode == "no-client-cert" {
				x.transport.TLSClientConfig.Certificates = nil
			}
			hello := contracts.ClusterObservationHello{Format: contracts.ClusterObservationOperationExchangeFormat, ExchangeID: localID(99), RootID: localID(1), ClusterID: localID(12)}
			if mode == "v1-hello" {
				hello.Format = contracts.ClusterObservationExchangeFormat
			}
			payload, _ := contracts.EncodeClusterObservationHello(hello)
			var body bytes.Buffer
			if err := contracts.WriteClusterObservationFrame(&body, contracts.ClusterObservationFrame{Kind: contracts.ClusterObservationHelloFrame, Payload: payload}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+x.authority+contracts.ClusterObservationOperationExchangePath, io.NopCloser(bytes.NewReader(body.Bytes())))
			if err != nil {
				t.Fatal(err)
			}
			request.ContentLength = -1
			request.Header.Set("Content-Type", contracts.ClusterObservationOperationExchangeMedia)
			request.Header.Set("Accept", contracts.ClusterObservationOperationExchangeMedia)
			switch mode {
			case "fixed-body":
				request.ContentLength = int64(body.Len())
			case "wrong-authority":
				request.Host = "other.test:9444"
			case "credential-header":
				request.Header.Set("Authorization", "synthetic-forbidden")
			case "query":
				request.URL.RawQuery = "method=other"
			case "wrong-media":
				request.Header.Set("Content-Type", "application/json")
			}
			response, err := (&http.Client{Transport: x.transport}).Do(request)
			if err == nil {
				defer response.Body.Close()
				if response.StatusCode == http.StatusOK {
					t.Fatal("invalid receiving boundary succeeded")
				}
			}
			select {
			case <-x.created:
				t.Fatal("invalid request reached bootstrap factory")
			default:
			}
			x.handler.Close()
			x.holder.mu.Lock()
			count := len(x.holder.entries)
			x.holder.mu.Unlock()
			if count != 0 {
				t.Fatal("rejected request retained slot", count)
			}
		})
	}
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
