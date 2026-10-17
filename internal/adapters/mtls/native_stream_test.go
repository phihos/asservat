package mtls

import (
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual HTTP/2 and mutual TLS; certificates are explicitly synthetic. These
// tests establish neither current peer registry nor native operation authority.
func nativeStreamServer(t *testing.T, h http.Handler, h2 bool) (*httptest.Server, *NativeClient) {
	t.Helper()
	now := time.Now()
	ca := newOwnerTestCA(t, now)
	b := value.OwnerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PodUID: ownerTestID, ProcessEpoch: ownerTestID}
	server := ca.leaf(t, now, b, true, func(c *x509.Certificate) { c.DNSNames = nil; c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} })
	client := ca.leaf(t, now, b, false, nil)
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = h2
	s.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	c, err := NewNativeClient(s.URL+contracts.NativeWorkerPath, &tls.Config{RootCAs: ca.roots, Certificates: []tls.Certificate{client}})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}
func nativeHello() contracts.NativeHello {
	return contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: ownerTestID, SessionID: ownerTestID, WorkerID: ownerTestID, OperationID: ownerTestID, Fence: 1}, Nonce: strings.Repeat("A", 43)}
}
func TestNativeClientActualH2DuplexAndJoinedClose(t *testing.T) {
	done := make(chan struct{})
	failure := make(chan string, 1)
	_, c := nativeStreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		if r.ProtoMajor != 2 || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Idempotency-Key") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			failure <- "request boundary"
			return
		}
		f, err := contracts.ReadNativeFrame(r.Body)
		if err != nil || f.Kind != contracts.NativeHelloFrame {
			failure <- "hello"
			return
		}
		clear(f.Payload)
		w.Header().Set("Content-Type", contracts.NativeExchangeMedia)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		// Response arrives while the live POST request is still open.
		if contracts.WriteNativeFrame(w, contracts.NativeFrame{Kind: contracts.NativeCommandFrame, Payload: []byte(`{"read":true}`)}) != nil {
			failure <- "command"
			return
		}
		http.NewResponseController(w).Flush()
		f, err = contracts.ReadNativeFrame(r.Body)
		if err != nil || f.Kind != contracts.NativeDataFrame || !bytes.Equal(f.Payload, []byte("verified-native")) {
			failure <- "native data"
			return
		}
		clear(f.Payload)
		contracts.WriteNativeFrame(w, contracts.NativeFrame{Kind: contracts.NativeAcknowledgeFrame, Payload: []byte(`{"bytes":15}`)})
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}), true)
	ctx, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	s, err := c.Open(ctx, nativeHello())
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Receive(ctx)
	if err != nil || f.Kind != contracts.NativeCommandFrame {
		t.Fatal("duplex command", err)
	}
	clear(f.Payload)
	if err = s.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeDataFrame, Payload: []byte("verified-native")}); err != nil {
		t.Fatal(err)
	}
	f, err = s.Receive(ctx)
	if err != nil || f.Kind != contracts.NativeAcknowledgeFrame {
		t.Fatal("ack", err)
	}
	clear(f.Payload)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server not joined after stream close")
	}
	select {
	case s := <-failure:
		t.Fatal(s)
	default:
	}
}
func TestNativeClientRefusesH1BeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	_, c := nativeStreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }), false)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if s, err := c.Open(ctx, nativeHello()); err == nil {
		s.Close()
		t.Fatal("h1 accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP reached server without negotiated h2")
	}
}
func TestNativeClientNeverFollowsRedirect(t *testing.T) {
	var calls atomic.Int32
	_, c := nativeStreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, io.LimitReader(r.Body, 5))
		w.Header().Set("Location", contracts.NativeWorkerPath)
		w.WriteHeader(307)
	}), true)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if s, err := c.Open(ctx, nativeHello()); err == nil {
		s.Close()
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("uncertain native POST replayed", calls.Load())
	}
}
func TestNativeClientFrameCancellationJoinsActualRead(t *testing.T) {
	done := make(chan struct{})
	_, c := nativeStreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		f, e := contracts.ReadNativeFrame(r.Body)
		clear(f.Payload)
		if e != nil {
			return
		}
		w.Header().Set("Content-Type", contracts.NativeExchangeMedia)
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}), true)
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	s, err := c.Open(ctx, nativeHello())
	if err != nil {
		t.Fatal(err)
	}
	frame, end := context.WithTimeout(ctx, 30*time.Millisecond)
	defer end()
	if _, err = s.Receive(frame); err == nil {
		t.Fatal("expired read succeeded")
	}
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled server still active")
	}
	if err = s.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeDoneFrame, Payload: []byte(`{}`)}); err == nil {
		t.Fatal("cancelled stream reused")
	}
}
