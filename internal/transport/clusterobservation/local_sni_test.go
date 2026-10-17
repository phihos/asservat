package clusterobservation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

func TestClusterObservationLocalActualSNIAndAuthority(t *testing.T) {
	const exact = "observer.test"
	const other = "other.test"
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{exact, other}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	for _, mode := range []string{"exact-dns", "wrong-sni-dns", "ip-empty-sni", "ip-wrong-dns-sni"} {
		t.Run(mode, func(t *testing.T) {
			var handler *LocalHandler
			var callers, reads atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}}
			server.StartTLS()
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			host := exact
			if mode == "ip-empty-sni" || mode == "ip-wrong-dns-sni" {
				host = "127.0.0.1"
			}
			authority := net.JoinHostPort(host, port)
			handler, e = NewLocalHandler(context.Background(), authority, localPin(), localCallerFunc(func(_ context.Context, _ []byte, _ string, r fleet.ClusterObservationRequest) (fleet.ClusterObservationCaller, error) {
				callers.Add(1)
				return localProof(r), nil
			}), localExchangeFunc(func(_ context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
				reads.Add(1)
				return localResult(r), nil
			}), 1, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			client, e := NewLocalClient(context.Background(), "https://"+authority, localPin().RootID, localID(7), roots, localTokenFunc(func(context.Context) ([]byte, error) { return []byte("synthetic-projected-token"), nil }), 1, time.Now)
			if e != nil {
				handler.Close()
				server.Close()
				t.Fatal(e)
			}
			defer func() { client.Close(); handler.Close(); server.Close() }()
			// Test-only local address routing and wrong SNI. Standard root/hostname
			// verification stays enabled and succeeds for each chosen certificate name.
			client.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			wrong := mode == "wrong-sni-dns" || mode == "ip-wrong-dns-sni"
			if wrong {
				client.transport.TLSClientConfig.ServerName = other
			}
			_, callErr := client.ObserveCluster(context.Background(), localRequest())
			if wrong {
				if callErr == nil || callers.Load() != 0 || reads.Load() != 0 {
					t.Fatalf("mismatched actual SNI reached local authority: callers=%d reads=%d err=%v", callers.Load(), reads.Load(), callErr)
				}
			} else if callErr != nil || callers.Load() != 2 || reads.Load() != 1 {
				t.Fatalf("exact authority denied: callers=%d reads=%d err=%v", callers.Load(), reads.Load(), callErr)
			}
		})
	}
}
