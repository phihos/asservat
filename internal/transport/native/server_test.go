package native_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	native "asservat.local/asservat/internal/transport/native"
)

type syntheticServingCertificate struct{ certificate tls.Certificate }

func (s syntheticServingCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &s.certificate, nil
}

// Actual bounded listener, Go h2/TLS client and joined shutdown. Only issuer and
// operation authority are synthetic; this does not qualify installed identity.
func TestNativeServeActualH2AndJoinedCancellation(t *testing.T) {
	certificate, clientCertificate, roots := testCertificates(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, cancelled := make(chan struct{}), make(chan struct{})
	a := &syntheticAdmission{closed: make(chan struct{}), serve: func(ctx context.Context, s native.Stream) error {
		if e := s.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeCommandFrame, Payload: []byte(`{}`)}); e != nil {
			return e
		}
		close(entered)
		<-s.Context().Done()
		close(cancelled)
		return s.Context().Err()
	}}
	h, err := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), a, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- native.Serve(ctx, listener, roots, syntheticServingCertificate{certificate}, h, 1) }()
	client, err := mtls.NewNativeClient("https://"+listener.Addr().String()+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Open(ctx, workerHello())
	if err != nil {
		t.Fatal("actual native listener", err)
	}
	frame, err := stream.Receive(ctx)
	clear(frame.Payload)
	if err != nil || frame.Kind != contracts.NativeCommandFrame {
		t.Fatal("h2 duplex", err)
	}
	<-entered
	cancel()
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("operation did not cancel")
	}
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener returned before joined cleanup")
	}
	select {
	case <-a.closed:
	default:
		t.Fatal("admission cleanup was not joined")
	}
}

func TestNativeServeRejectsHTTP1AndClientOnlyServer(t *testing.T) {
	for _, test := range []string{"http1", "client-purpose"} {
		t.Run(test, func(t *testing.T) {
			server, client, roots := testCertificates(t)
			if test == "client-purpose" {
				server = client
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			a := &syntheticAdmission{closed: make(chan struct{})}
			h, err := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), a, 1)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			done := make(chan error, 1)
			go func() { done <- native.Serve(ctx, listener, roots, syntheticServingCertificate{server}, h, 1) }()
			next := []string{"h2"}
			if test == "http1" {
				next = []string{"http/1.1"}
			}
			dialer := tls.Dialer{Config: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{client}, MinVersion: tls.VersionTLS13, NextProtos: next}}
			connection, e := dialer.DialContext(ctx, "tcp", listener.Addr().String())
			if connection != nil {
				connection.Close()
			}
			cancel()
			<-done
			if e == nil || a.calls.Load() != 0 {
				t.Fatal("unsupported handshake admitted", e, a.calls.Load())
			}
		})
	}
}
