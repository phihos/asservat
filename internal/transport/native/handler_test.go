package native_test

import (
	mtls "asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const nativeID = "11111111-1111-4111-8111-111111111111"

type syntheticAdmission struct {
	calls  atomic.Int32
	serve  func(context.Context, native.Stream) error
	deny   atomic.Bool
	closed chan struct{}
}
type syntheticConversation struct {
	gate *evidence.NativeFrameGate
	a    *syntheticAdmission
}

func (c *syntheticConversation) Gate() *evidence.NativeFrameGate { return c.gate }
func (c *syntheticConversation) Serve(ctx context.Context, s native.Stream) error {
	return c.a.serve(ctx, s)
}
func (c *syntheticConversation) Close() error {
	c.gate.Close()
	_ = c.gate.Wait(context.Background())
	select {
	case <-c.a.closed:
	default:
		close(c.a.closed)
	}
	return nil
}
func (a *syntheticAdmission) OpenNative(ctx context.Context, peer *tls.ConnectionState, h contracts.NativeHello) (native.Conversation, error) {
	a.calls.Add(1)
	if peer == nil || len(peer.VerifiedChains) == 0 || len(peer.PeerCertificates) == 0 || peer.NegotiatedProtocol != "h2" {
		return nil, contracts.ErrNativeProtocol
	}
	now := time.Now()
	o := value.NativeOperation{Reference: value.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: 1}, Kind: value.NativePrepare, HubPodUID: nativeID, HubProcessEpoch: nativeID, WorkerPodUID: nativeID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: artifact.Digest{2}, ParentID: nativeID, Generation: 1, StartedAt: now, Until: now.Add(4 * time.Second)}
	o = syntheticProcessingPath(o)
	l := value.NativeLease{Operation: o, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: now, Until: o.Until}
	// Synthetic current SQL/identity authority is explicit. Actual handler/client
	// HTTP/2, TLS, deadlines and joined body delivery are under test.
	gate, e := evidence.NewNativeFrameGate(context.WithoutCancel(ctx), func(context.Context) (value.NativeLease, error) {
		if a.deny.Load() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		return l, nil
	}, time.Now)
	if e != nil {
		return nil, e
	}
	return &syntheticConversation{gate, a}, nil
}
func testCertificates(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic native fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	makeLeaf := func(serial int64, server bool) tls.Certificate {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		b, e := x509.CreateCertificate(rand.Reader, c, root, k.Public(), key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: k}
	}
	return makeLeaf(2, true), makeLeaf(3, false), roots
}
func nativeServer(t *testing.T, a *syntheticAdmission) (*mtls.NativeClient, *httptest.Server) {
	t.Helper()
	server, client, roots := testCertificates(t)
	var handler http.Handler
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	var e error
	handler, e = native.NewHandler(contracts.NativeWorkerPath, u.Host, a, 1)
	if e != nil {
		t.Fatal(e)
	}
	c, e := mtls.NewNativeClient(s.URL+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{client}})
	if e != nil {
		t.Fatal(e)
	}
	return c, s
}
func workerHello() contracts.NativeHello {
	return contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID}, Nonce: strings.Repeat("A", 43), WorkerToken: []byte("synthetic.projected.token")}
}
func TestNativeHandlerActualDuplexAndCurrentRevocation(t *testing.T) {
	for _, mode := range []string{"success", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			a := &syntheticAdmission{closed: make(chan struct{})}
			emitted := make(chan []byte, 1)
			a.serve = func(ctx context.Context, s native.Stream) error {
				b, _ := json.Marshal(contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Kind: "read-context-response"})
				if e := s.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeCommandFrame, Payload: b}); e != nil {
					return e
				}
				f, e := s.Receive(ctx)
				if e != nil {
					return e
				}
				defer clear(f.Payload)
				if f.Kind != contracts.NativeDataFrame {
					return contracts.ErrNativeProtocol
				}
				if mode == "revoked" {
					a.deny.Store(true)
				}
				e = s.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeAcknowledgeFrame, Payload: []byte(`{"bytes":4}`)})
				if e == nil {
					emitted <- append([]byte(nil), f.Payload...)
				}
				return e
			}
			c, _ := nativeServer(t, a)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s, e := c.Open(ctx, workerHello())
			if e != nil {
				t.Fatal("open", e)
			}
			defer s.Close()
			f, e := s.Receive(ctx)
			clear(f.Payload)
			if e != nil || f.Kind != contracts.NativeCommandFrame {
				t.Fatal("command", e)
			}
			if e = s.Send(ctx, contracts.NativeFrame{Kind: contracts.NativeDataFrame, Payload: []byte("body")}); e != nil {
				t.Fatal(e)
			}
			f, e = s.Receive(ctx)
			clear(f.Payload)
			if mode == "success" && e != nil {
				t.Fatal("ack", e)
			}
			if mode == "revoked" && e == nil {
				t.Fatal("known revocation acknowledged")
			}
			s.Close()
			select {
			case <-a.closed:
			case <-time.After(time.Second):
				t.Fatal("conversation not joined")
			}
			if a.calls.Load() != 1 {
				t.Fatal("replayed admission")
			}
			select {
			case b := <-emitted:
				if mode != "success" || string(b) != "body" {
					t.Fatal("unexpected data")
				}
			default:
				if mode == "success" {
					t.Fatal("actual data missing")
				}
			}
		})
	}
}
