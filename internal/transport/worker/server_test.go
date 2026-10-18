package worker_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	worker "asservat.local/asservat/internal/transport/worker"
)

const (
	serveID   = "11111111-1111-4111-8111-111111111111"
	serveName = "worker-facing.synthetic.invalid"
)

// The exchange is a synthetic port: it never issues a certificate. It counts
// requests that reach it and, when hold is set, blocks until cancellation.
type serveExchange struct {
	calls    atomic.Int32
	hold     bool
	entered  chan struct{}
	returned atomic.Bool
}

func (e *serveExchange) BeginWorkerEnrollment(ctx context.Context, installation, session, w string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	e.calls.Add(1)
	if e.hold {
		close(e.entered)
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		e.returned.Store(true)
	}
	return nil, artifact.ErrDownloadUnavailable
}

type serveCredentials struct{ cert tls.Certificate }

func (c serveCredentials) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &c.cert, nil
}

func serveCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{serveName}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}, roots
}

func serveRequestBody(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: serveID, SessionID: serveID, WorkerID: serveID, Nonce: strings.Repeat("A", 42) + "E", CSR: bytes.Repeat([]byte{1}, 64)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func startServe(t *testing.T, exchange *serveExchange) (context.CancelFunc, chan error, string, *x509.CertPool) {
	t.Helper()
	cert, roots := serveCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := worker.NewHandler(serveID, exchange, time.Now, 2)
	if err != nil {
		t.Fatal(err)
	}
	authority := net.JoinHostPort(serveName, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Serve(ctx, listener, authority, serveCredentials{cert}, handler, 2) }()
	return cancel, done, listener.Addr().String(), roots
}

func serveClient(roots *x509.CertPool, address string, configure func(*tls.Config, *http.Transport)) *http.Client {
	t := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	if configure != nil {
		configure(t.TLSClientConfig, t)
	}
	return &http.Client{Transport: t, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func serveRequest(t *testing.T, port, host string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://"+net.JoinHostPort(serveName, port)+contracts.WorkerEnrollmentPath, bytes.NewReader(serveRequestBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer synthetic.projected.token")
	if host != "" {
		r.Host = host
	}
	return r
}

func TestServeReachesEnrollmentOnlyUnderItsProfile(t *testing.T) {
	exchange := &serveExchange{}
	cancel, done, address, roots := startServe(t, exchange)
	_, port, _ := net.SplitHostPort(address)
	// A ClientHello offering only h2 belongs to the native path, never here.
	if c, err := tls.Dial("tcp", address, &tls.Config{ServerName: serveName, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}); err == nil {
		c.Close()
		t.Fatal("h2-only handshake accepted")
	}
	for _, mode := range []string{"enrollment", "other-name", "wrong-authority"} {
		t.Run(mode, func(t *testing.T) {
			before := exchange.calls.Load()
			client := serveClient(roots, address, func(c *tls.Config, _ *http.Transport) {
				if mode == "other-name" {
					c.ServerName, c.InsecureSkipVerify = "other.synthetic.invalid", true
				}
			})
			host := ""
			if mode == "wrong-authority" {
				host = net.JoinHostPort("other.synthetic.invalid", port)
			}
			resp, err := client.Do(serveRequest(t, port, host))
			switch mode {
			case "enrollment":
				// The synthetic exchange refuses: 503 proves the handler ran.
				if err != nil || resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Cache-Control") != "no-store, private" || exchange.calls.Load() != before+1 {
					t.Fatal("enrollment did not reach the handler", err)
				}
				resp.Body.Close()
			case "wrong-authority":
				if err != nil || resp.StatusCode != http.StatusMisdirectedRequest || exchange.calls.Load() != before {
					t.Fatal("foreign authority reached enrollment", err)
				}
				resp.Body.Close()
			default:
				if err == nil {
					resp.Body.Close()
					t.Fatal("handshake outside the fixed TLS profile", mode)
				}
				if exchange.calls.Load() != before {
					t.Fatal("refused handshake reached enrollment", mode)
				}
			}
		})
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal("serve ended without its cause", e)
	}
}

func TestServeJoinsBlockedEnrollmentOnShutdown(t *testing.T) {
	exchange := &serveExchange{hold: true, entered: make(chan struct{})}
	cancel, done, address, roots := startServe(t, exchange)
	_, port, _ := net.SplitHostPort(address)
	go func() {
		resp, err := serveClient(roots, address, nil).Do(serveRequest(t, port, ""))
		if err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-exchange.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("enrollment never started")
	}
	cancel()
	select {
	case <-done:
		if !exchange.returned.Load() {
			t.Fatal("serve returned before the blocked handler")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not join after cancellation")
	}
}

func TestServeRejectsUnboundedConfiguration(t *testing.T) {
	cert, _ := serveCertificate(t)
	handler, _ := worker.NewHandler(serveID, &serveExchange{}, time.Now, 1)
	for _, authority := range []string{"127.0.0.1:9443", serveName, serveName + ":0", ":9443"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if worker.Serve(context.Background(), listener, authority, serveCredentials{cert}, handler, 1) == nil {
			t.Fatal("accepted authority", authority)
		}
		listener.Close()
	}
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	if worker.Serve(context.Background(), listener, serveName+":9443", serveCredentials{cert}, handler, 65) == nil {
		t.Fatal("unbounded connections accepted")
	}
}
