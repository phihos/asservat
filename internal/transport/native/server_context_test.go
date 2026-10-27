package native_test

import (
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/contextstart"
	native "asservat.local/asservat/internal/transport/native"
)

// Only the current authority is synthetic. The shared production listener,
// actual TLS/h2, both exact handlers and original socket clocks are exercised.
type sharedStartIngress struct{ calls atomic.Int64 }

func (s *sharedStartIngress) AuthenticateContextStart(ctx context.Context, peer *tls.ConnectionState, hello contracts.APIContextHello, _ fleetapp.ConnectorIdentitySourceReader) (fleet.APIContextReceiver, contextstart.ReceiverCheck, error) {
	s.calls.Add(1)
	if ctx.Err() != nil || peer == nil || peer.NegotiatedProtocol != "h2" || len(peer.VerifiedChains) == 0 {
		return fleet.APIContextReceiver{}, nil, fleet.ErrDenied
	}
	c := fleet.APIContextChannel{RootID: nativeID, ExchangeID: hello.Channel.ExchangeID, Challenge: nativeID, Hub: fleet.OwnerBinding{InstallationID: nativeID, ClusterID: nativeID, IssuerEpoch: nativeID, PodUID: nativeID, ProcessEpoch: nativeID}, Connector: fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: nativeID, ClusterID: nativeID, IssuerEpoch: nativeID, PeerID: nativeID, Role: fleet.ConnectorPeer}, PodUID: nativeID, ProcessEpoch: nativeID}, ConnectorLeaf: artifact.Digest{1}, Executor: fleet.APIContextExecutor{NamespaceUID: nativeID, AccountUID: nativeID, PodUID: nativeID, ProcessEpoch: "22222222-2222-4222-8222-222222222222", StartupDigest: artifact.Digest{2}, ImageDigest: artifact.Digest{3}}}
	check := func(call context.Context) (fleet.APIContextReceiver, error) {
		n := time.Now()
		return fleet.APIContextReceiver{Channel: c, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}, call.Err()
	}
	r, e := check(ctx)
	return r, check, e
}
func TestNativeSharedPortActualH2StandbyAndIndependentPurpose(t *testing.T) {
	certificate, clientCertificate, roots := testCertificates(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	router, e := contextstart.NewRouter(contextstart.RouterLimits{Standby: 2, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: nativeID, Standby: 2, Captures: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	ingress := &sharedStartIngress{}
	starts, e := contextstart.NewHandler(listener.Addr().String(), router, ingress, 2)
	if e != nil {
		t.Fatal(e)
	}
	admission := &syntheticAdmission{closed: make(chan struct{}), serve: func(c context.Context, s native.Stream) error {
		if e := s.Send(c, contracts.NativeFrame{Kind: contracts.NativeCommandFrame, Payload: []byte(`{}`)}); e != nil {
			return e
		}
		<-s.Context().Done()
		return s.Context().Err()
	}}
	handler, e := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), admission, 1)
	if e != nil {
		t.Fatal(e)
	}
	// Longer than the ten-second check plus the router's idle retirement
	// margin (an idle standby ends when it can no longer cover any work).
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- native.ServeWithContextStart(ctx, listener, roots, syntheticServingCertificate{certificate}, handler, starts, 1, 1)
	}()
	t.Cleanup(func() {
		cancel()
		router.Close()
		if e := <-done; !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
			t.Error(e)
		}
	})
	open := func(id string) (*http.Response, func()) {
		t.Helper()
		read, write := io.Pipe()
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true, DisableKeepAlives: true}
		call, stop := context.WithCancel(ctx)
		req, e := http.NewRequestWithContext(call, http.MethodPost, "https://"+listener.Addr().String()+contracts.APIContextStartPath, read)
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", contracts.APIContextStartMedia)
		req.Header.Set("Accept", contracts.APIContextStartMedia)
		hello, e := contracts.EncodeAPIContextHello(contracts.APIContextHello{Format: contracts.APIContextExchangeFormat, Channel: contracts.APIContextChannel{ExchangeID: id}})
		if e != nil {
			t.Fatal(e)
		}
		wrote := make(chan error, 1)
		go func() {
			e := contracts.WriteAPIContextFrame(write, contracts.APIContextFrame{Kind: contracts.APIContextHelloFrame, Payload: hello})
			if e == nil {
				e = writeTestSource(write, id)
			}
			wrote <- e
		}()
		response, e := tr.RoundTrip(req)
		closeAll := func() {
			stop()
			read.Close()
			write.Close()
			if response != nil {
				response.Body.Close()
			}
			tr.CloseIdleConnections()
		}
		if e != nil {
			closeAll()
			<-wrote
			t.Fatal("actual shared h2 POST", e)
		}
		if e = <-wrote; e != nil && response.StatusCode == http.StatusOK {
			closeAll()
			t.Fatal("hello write", e)
		}
		return response, closeAll
	}
	response, stop := open(nativeID)
	defer stop()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
		t.Fatal("context-start exact handler unavailable", response.StatusCode)
	}
	ended := make(chan error, 1)
	go func() { var b [1]byte; _, e := response.Body.Read(b[:]); ended <- e }()
	// Actual standby must outlive the native purpose's original ten-second cap.
	// This is passive residency; no work, human identity or grant is refreshed.
	timer := time.NewTimer(10500 * time.Millisecond)
	defer timer.Stop()
	select {
	case e := <-ended:
		t.Fatal("context standby inherited native lifetime", e)
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	rejected, closeRejected := open("33333333-3333-4333-8333-333333333333")
	if rejected.StatusCode == http.StatusOK || ingress.calls.Load() != 1 {
		closeRejected()
		t.Fatal("context purpose exceeded its separately reserved slot", rejected.StatusCode, ingress.calls.Load())
	}
	closeRejected()
	client, e := mtls.NewNativeClient("https://"+listener.Addr().String()+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}})
	if e != nil {
		t.Fatal(e)
	}
	stream, e := client.Open(ctx, workerHello())
	if e != nil {
		t.Fatal("standby exhausted independent native purpose", e)
	}
	// The socket/test lifetime is not a native frame lease. NativeClientStream
	// requires the same at-most-five-second frame bound as the exact handler.
	read, endRead := context.WithTimeout(ctx, 4*time.Second)
	frame, e := stream.Receive(read)
	endRead()
	clear(frame.Payload)
	stream.Close()
	if e != nil || frame.Kind != contracts.NativeCommandFrame || admission.calls.Load() != 1 {
		t.Fatal("native purpose did not use exact unchanged handler", e)
	}
	stop()
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("standby reader failed to join")
	}
}
func TestNativeSharedPortUnclassifiedSocketExpires(t *testing.T) {
	server, _, roots := testCertificates(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	router, e := contextstart.NewRouter(contextstart.RouterLimits{Standby: 1, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: nativeID, Standby: 1, Captures: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	starts, e := contextstart.NewHandler(listener.Addr().String(), router, &sharedStartIngress{}, 1)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), &syntheticAdmission{closed: make(chan struct{})}, 1)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- native.ServeWithContextStart(ctx, listener, roots, syntheticServingCertificate{server}, handler, starts, 1, 1)
	}()
	defer func() { cancel(); router.Close(); <-done }()
	socket, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	n := time.Now()
	var b [1]byte
	_, e = socket.Read(b[:])
	elapsed := time.Since(n)
	if e == nil || elapsed > 2800*time.Millisecond {
		t.Fatal("unclassified raw socket outlived original two-second admission", elapsed, e)
	}
}

// writeTestSource sends the ADR-178 source frame that follows Hello. The
// synthetic ingress ignores its content; production ingress validates it.
func writeTestSource(w io.Writer, exchange string) error {
	source, e := contracts.EncodeAPIContextSource(contracts.APIContextSource{Format: contracts.APIContextExchangeFormat, ExchangeID: exchange, Sequence: 0, Source: []byte(`{}`)})
	if e != nil {
		return e
	}
	return contracts.WriteAPIContextFrame(w, contracts.APIContextFrame{Kind: contracts.APIContextSourceFrame, Payload: source})
}
