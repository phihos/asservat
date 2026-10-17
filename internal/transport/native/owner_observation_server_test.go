package native_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

type ownerObservationCall func(context.Context, *tls.ConnectionState, contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error)

func (f ownerObservationCall) ObserveOwnerPeer(ctx context.Context, s *tls.ConnectionState, r contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error) {
	return f(ctx, s, r)
}

// This is real TLS13/h2/socket lifetime coverage. Admission is explicitly
// synthetic; these results cannot qualify current SQL/Kubernetes identity.
func observationTLSFixture(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(server bool) tls.Certificate {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
		if server {
			tmpl.SerialNumber = big.NewInt(3)
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"owner-proof.test", "exact-owner.test"}
		}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return roots, leaf(true), leaf(false)
}
func observationWireRequest() contracts.OwnerObservationRequest {
	now := time.Now().UTC()
	return contracts.OwnerObservationRequest{Format: contracts.OwnerObservationFormat, RootID: nativeID, ID: nativeID, Challenge: nativeID, RequestedAt: now.Format(time.RFC3339Nano), NotAfter: now.Add(3 * time.Second).Format(time.RFC3339Nano)}
}
func observationPost(ctx context.Context, client *http.Client, authority, path string, r contracts.OwnerObservationRequest, extra bool) (*http.Response, error) {
	b, e := contracts.EncodeOwnerObservationRequest(r)
	if e != nil {
		return nil, e
	}
	if extra {
		b = append(b, []byte(" {}")...)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority+path, io.NopCloser(bytes.NewReader(b)))
	if e != nil {
		return nil, e
	}
	req.ContentLength = int64(len(b))
	req.Header.Set("Content-Type", contracts.OwnerObservationMedia)
	req.Header.Set("Accept", contracts.OwnerObservationMedia)
	return client.Do(req)
}
func observationTestServer(t *testing.T, roots *x509.CertPool, serverCert, clientCert tls.Certificate, sni string, call ownerObservationCall) (*clusterobservation.OwnerHandler, *http.Client, string, func()) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	authority := net.JoinHostPort("owner-proof.test", port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	handler, e := clusterobservation.NewOwnerHandler(ctx, authority, call, 1, time.Now)
	if e != nil {
		cancel()
		listener.Close()
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		done <- native.ServeOwnerObservation(ctx, listener, roots, syntheticServingCertificate{serverCert}, handler, 2)
	}()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, network, listener.Addr().String())
	}}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	close := func() {
		cancel()
		handler.Close()
		tr.CloseIdleConnections()
		if e := <-done; !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
			t.Error(e)
		}
	}
	return handler, client, authority, close
}
func TestOwnerObservationOnlyListenerActualTLS(t *testing.T) {
	roots, serverCert, clientCert := observationTLSFixture(t)
	for _, mode := range []string{"exact", "exact-owner-sni", "wrong-host", "native-path", "worker-path", "public-path", "extra-body", "expired-wire"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			ingress := ownerObservationCall(func(ctx context.Context, s *tls.ConnectionState, r contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error) {
				calls.Add(1)
				if ctx.Err() != nil || s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || s.ServerName != "owner-proof.test" {
					return contracts.OwnerObservationReply{}, errors.New("synthetic TLS check")
				}
				return contracts.OwnerObservationReply{Format: contracts.OwnerObservationFormat, Request: r, ObservedAt: r.RequestedAt, FreshUntil: r.NotAfter}, nil
			})
			sni := "owner-proof.test"
			if mode == "exact-owner-sni" {
				sni = "exact-owner.test"
			}
			_, client, authority, close := observationTestServer(t, roots, serverCert, clientCert, sni, ingress)
			defer close()
			path := contracts.OwnerObservationPath
			switch mode {
			case "wrong-host":
				_, port, _ := net.SplitHostPort(authority)
				authority = net.JoinHostPort("exact-owner.test", port)
			case "native-path":
				path = contracts.NativeOwnerPath
			case "worker-path":
				path = contracts.NativeWorkerPath
			case "public-path":
				path = "/api/context"
			}
			r := observationWireRequest()
			if mode == "expired-wire" {
				r.RequestedAt = time.Now().Add(-3 * time.Second).UTC().Format(time.RFC3339Nano)
				r.NotAfter = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			}
			response, e := observationPost(context.Background(), client, authority, path, r, mode == "extra-body")
			if response != nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			if mode == "exact" {
				if e != nil || response == nil || response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || calls.Load() != 1 {
					t.Fatalf("exact own proof failed: calls=%d err=%v", calls.Load(), e)
				}
			} else if calls.Load() != 0 || e == nil && response != nil && response.StatusCode == http.StatusOK {
				t.Fatalf("unrelated route/input reached own proof: calls=%d err=%v", calls.Load(), e)
			}
		})
	}
}
func TestOwnerObservationListenerCloseJoinsOriginalCall(t *testing.T) {
	roots, serverCert, clientCert := observationTLSFixture(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	ingress := ownerObservationCall(func(ctx context.Context, _ *tls.ConnectionState, _ contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return contracts.OwnerObservationReply{}, ctx.Err()
	})
	handler, client, authority, shutdown := observationTestServer(t, roots, serverCert, clientCert, "owner-proof.test", ingress)
	done := make(chan error, 1)
	go func() {
		r, e := observationPost(context.Background(), client, authority, contracts.OwnerObservationPath, observationWireRequest(), false)
		if r != nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		shutdown()
		t.Fatal("request not admitted")
	}
	joined := make(chan struct{})
	go func() { handler.Close(); close(joined) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		close(release)
		shutdown()
		t.Fatal("Close did not cancel original call")
	}
	select {
	case <-joined:
		close(release)
		shutdown()
		t.Fatal("Close returned while admitted operation remained active")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("Close did not join")
	}
	<-done
	shutdown()
}
