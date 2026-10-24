package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Synthetic SQL/native reads: every lookup is unavailable. They only satisfy
// the native runtime's constructor; the worker path's peers are replaced below.
type workerServingReads struct{}

func (workerServingReads) LocateNativeOperation(context.Context, string, string, string, authorization.KeyPeer) (authorization.NativeLease, error) {
	return authorization.NativeLease{}, artifact.ErrDownloadUnavailable
}
func (workerServingReads) ObserveNativeOperation(context.Context, authorization.NativeReference, authorization.KeyPeer) (authorization.NativeLease, error) {
	return authorization.NativeLease{}, artifact.ErrDownloadUnavailable
}
func (workerServingReads) ReadNativeWorkerCertificate(context.Context, string, string, []byte) (authorization.WorkerCertificate, error) {
	return authorization.WorkerCertificate{}, artifact.ErrDownloadUnavailable
}

// workerServingPeers counts worker native checks that reach the admission and
// refuses them; it proves routing, never a worker's authority.
type workerServingPeers struct{ worker atomic.Int32 }

func (p *workerServingPeers) CheckWorkerNative(_ context.Context, state *tls.ConnectionState, h contracts.NativeHello) (evidence.NativeOrigin, error) {
	if state != nil && len(state.VerifiedChains) > 0 && h.Reference.InstallationID == runtimeID {
		p.worker.Add(1)
	}
	return evidence.NativeOrigin{}, artifact.ErrDownloadUnavailable
}
func (p *workerServingPeers) CheckForwardedNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error) {
	return evidence.NativeOrigin{}, artifact.ErrDownloadUnavailable
}
func (p *workerServingPeers) RecheckWorkerNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (authorization.NativeLease, error) {
	return authorization.NativeLease{}, artifact.ErrDownloadUnavailable
}
func (p *workerServingPeers) RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (authorization.NativeLease, error) {
	return authorization.NativeLease{}, artifact.ErrDownloadUnavailable
}

type workerServingHub struct{}

func (workerServingHub) CheckOwnerServing(context.Context) (time.Time, error) {
	return time.Now().Add(5 * time.Second), nil
}
func (workerServingHub) CheckNativeHub(context.Context, authorization.NativeOperation) (time.Time, error) {
	return time.Time{}, artifact.ErrDownloadUnavailable
}

type workerServingToken struct{}

func (workerServingToken) ReadDownloadPeerToken(context.Context) ([]byte, error) {
	return []byte("synthetic.projected.token"), nil
}

// workerServingIssuer is a synthetic acquisition issuer: its CA is the
// worker-path client root and it signs one client leaf.
func workerServingIssuer(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(70), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(71), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func workerServingRuntime(t *testing.T, ctx context.Context) (*runtimeFixture, *OwnerRuntime, net.Listener, net.Listener) {
	t.Helper()
	f, c, listener := newRuntimeFixture(t)
	nativeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nativeListener.Close() })
	c.Pool.NativePort = nativeListener.Addr().(*net.TCPAddr).Port
	c.Pool.NativeBootstrap = value.OwnerBootstrapProfile
	f.configuration.Pool = c.Pool
	f.bootstrapSAN = true
	verifier, err := mtls.NewPeerVerifier(f.roots, runtimeID, value.ConnectorPeer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reads := workerServingReads{}
	origins := evidence.NativeOrigins{Locators: reads, Operations: reads, Now: time.Now, Proofs: func(evidence.DownloadPeerToken) (evidence.DownloadPeerProofReader, error) {
		return nil, artifact.ErrDownloadUnavailable
	}}
	trust, err := mtls.NewWorkerTrustCatalog(runtimeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Native = &OwnerNativeRuntimeConfig{Peers: &mtls.NativePeerChecks{Workers: f, WorkerTrust: trust, Certificates: reads, Origins: origins, ConnectorVerifier: verifier, Connectors: &fleetapp.PeerAuthenticator{}, Now: time.Now}, ConnectorRoots: f.roots, Connections: 2, Concurrency: 1}
	r, err := NewOwnerRuntime(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return f, r, listener, nativeListener
}

// ADR-221: the owner port serves local admitted-worker enrollment and native
// traffic under the fixed name. The certificate-owner relay is retired; the
// separate connector native port keeps its existing exact-process profile.
func TestOwnerRuntimeServesAcquisitionWorkersOnlyWhenComposed(t *testing.T) {
	for _, composed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfigured", true: "configured"}[composed], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f, r, listener, nativeListener := workerServingRuntime(t, ctx)
			peers := &workerServingPeers{}
			r.native.peers, r.native.hub = peers, workerServingHub{}
			issuerRoots, workerLeaf := workerServingIssuer(t)
			var rootReads atomic.Int32
			if composed {
				if err := r.ServeAcquisitionWorkers(func(time.Time) (*x509.CertPool, error) { rootReads.Add(1); return issuerRoots, nil }, f); err != nil {
					t.Fatal(err)
				}
				if r.ServeAcquisitionWorkers(func(time.Time) (*x509.CertPool, error) { return issuerRoots, nil }, f) == nil {
					t.Fatal("worker serving composed twice")
				}
			}
			done := make(chan error, 1)
			go func() { done <- r.Run(listener, nativeListener) }()
			waitOwnerState(t, r.Ready)
			address := listener.Addr().String()
			endpoints, err := ownerWorkerEndpointsFor(r.pool)
			if err != nil {
				t.Fatal(err)
			}
			if endpoints.Address != net.JoinHostPort("owner.hub.svc", strconv.Itoa(r.pool.Port)) || endpoints.Endpoint != "https://"+endpoints.Authority || endpoints.ExchangeEndpoint != "https://"+endpoints.Authority+contracts.NativeWorkerPath || !strings.HasPrefix(endpoints.Name, "s-"+runtimeID+".e-"+runtimeID+".hub-bootstrap.") {
				t.Fatal("worker endpoints are not the pool's fixed name on the owner port", endpoints)
			}

			// No certificate-owner relay is served in either composition.
			exact, _ := mtls.OwnerServerName(r.Binding())
			tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.roots, ServerName: exact, GetClientCertificate: r.client.GetClientCertificate}, DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			req, _ := http.NewRequest("POST", "https://"+address+contracts.OwnerRelayPath, bytes.NewReader([]byte(`{}`)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer synthetic.token")
			resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Do(req)
			if err == nil {
				resp.Body.Close()
				t.Fatal("retired certificate relay remained reachable")
			}

			// Enrollment: the actual worker client, dialing the owner port by
			// address while verifying the fixed name against the owner roots.
			now := time.Now()
			target := authorization.WorkerCredentialTarget{InstallationID: runtimeID, SessionID: runtimeID, WorkerID: runtimeID, PodUID: runtimeID, CreatedAt: now.Add(-time.Second), RunUntil: now.Add(10 * time.Minute)}
			credentials, err := mtls.NewWorkerCredentialsVia(endpoints.Endpoint, address, target, f.roots, issuerRoots, workerServingToken{}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer credentials.Close()
			call, end := context.WithTimeout(ctx, 5*time.Second)
			err = credentials.Enroll(call)
			end()
			if err == nil {
				t.Fatal("synthetic refusal produced a certificate")
			}
			if reached := f.ownerReads.Load() > 0; reached != composed {
				t.Fatal("enrollment reached the local admitted-worker handler", reached, "composed", composed)
			}

			// The worker native path: h2 under the fixed name, worker client
			// leaf verified by the profile's issuer roots.
			client, err := mtls.NewNativeClientVia(endpoints.ExchangeEndpoint, address, &tls.Config{RootCAs: f.roots, Certificates: []tls.Certificate{workerLeaf}})
			if err != nil {
				t.Fatal(err)
			}
			hello := contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: runtimeID, SessionID: runtimeID, WorkerID: runtimeID}, Nonce: strings.Repeat("A", 43), WorkerToken: []byte("synthetic.projected.token")}
			call, end = context.WithTimeout(ctx, 5*time.Second)
			stream, err := client.Open(call, hello)
			end()
			if stream != nil {
				stream.Close()
			}
			if err == nil {
				t.Fatal("refused worker check opened a conversation")
			}
			if reached := peers.worker.Load() > 0; reached != composed || (rootReads.Load() > 0) != composed {
				t.Fatal("worker native path reached its admission", reached, "composed", composed)
			}

			// The native port keeps its exact-name connector profile: the
			// fixed worker-facing name is not served there.
			if c, e := tls.Dial("tcp", nativeListener.Addr().String(), &tls.Config{ServerName: endpoints.Name, RootCAs: f.roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{workerLeaf}}); e == nil {
				c.Close()
				t.Fatal("native port accepted the worker-facing name")
			}
			if r.ServeAcquisitionWorkers(func(time.Time) (*x509.CertPool, error) { return issuerRoots, nil }, f) == nil {
				t.Fatal("worker serving composed after Run started")
			}
			cancel()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runtime failed to join")
			}
		})
	}
}

// The fixed worker-facing name needs an owner-bootstrap/v1 pool.
func TestServeAcquisitionWorkersRequiresBootstrapPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f, r, _, _ := workerServingRuntime(t, ctx)
	r.pool.NativeBootstrap = ""
	if r.ServeAcquisitionWorkers(func(time.Time) (*x509.CertPool, error) { return x509.NewCertPool(), nil }, f) == nil {
		t.Fatal("worker serving without the pool's fixed serving name")
	}
	_, c, _ := newRuntimeFixture(t)
	plain, err := NewOwnerRuntime(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if plain.ServeAcquisitionWorkers(func(time.Time) (*x509.CertPool, error) { return x509.NewCertPool(), nil }, f) == nil {
		t.Fatal("worker serving without a native runtime")
	}
}
