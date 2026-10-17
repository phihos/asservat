package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	workertransport "asservat.local/asservat/internal/transport/worker"
)

const channelInstallation = "01000000-0000-4000-8000-000000000001"
const channelSession = "01000000-0000-4000-8000-000000000002"
const channelWorker = "01000000-0000-4000-8000-000000000003"
const channelPod = "01000000-0000-4000-8000-000000000004"

// These TLS tests use a test-only issuer and token verifier. The separate SQL
// and Kubernetes/provider suites establish those independent authority edges.
type workerChannelFixture struct {
	target value.WorkerCredentialTarget
	clock  atomic.Int64
	calls  atomic.Int64
	tokens atomic.Int64
	root   *x509.Certificate
	key    *ecdsa.PrivateKey
	roots  *x509.CertPool
	mutate func(*x509.Certificate)
	block  func(context.Context)
}

func (f *workerChannelFixture) now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
func (f *workerChannelFixture) ReadDownloadPeerToken(context.Context) ([]byte, error) {
	n := f.tokens.Add(1)
	if n == 1 {
		return []byte("synthetic.first.token"), nil
	}
	return []byte("synthetic.rotated.token"), nil
}
func (f *workerChannelFixture) EnrollWorker(ctx context.Context, installation, session, worker string, token, csr []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if installation != f.target.InstallationID || session != f.target.SessionID || worker != f.target.WorkerID || !(bytes.Equal(token, []byte("synthetic.first.token")) || bytes.Equal(token, []byte("synthetic.rotated.token"))) {
		return zero, artifact.ErrInvalid
	}
	if _, err := mtls.EnrollmentKey(csr); err != nil {
		return zero, err
	}
	f.calls.Add(1)
	if f.block != nil {
		f.block(ctx)
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
	}
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return zero, err
	}
	_, until, err := f.target.CertificateEpoch(f.now())
	if err != nil {
		return zero, err
	}
	uri := &url.URL{Scheme: "spiffe", Host: "asservat." + f.target.InstallationID, Path: "/key-client/acquisition/" + f.target.PodUID}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(f.calls.Load() + 1), NotBefore: f.now().Add(-time.Second), NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	if f.mutate != nil {
		f.mutate(leaf)
	}
	public := req.PublicKey
	if leaf.Subject.CommonName == "wrong-key" {
		public = f.key.Public()
		leaf.Subject = pkix.Name{}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.root, public, f.key)
	if err != nil {
		return zero, err
	}
	return value.WorkerCertificate{Peer: value.KeyPeer{InstallationID: installation, Role: "acquisition", PeerID: f.target.PodUID, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Certificate: sha256.Sum256(der)}, DER: der, ChainDER: [][]byte{f.root.Raw}}, nil
}
func newWorkerChannelFixture(t *testing.T) *workerChannelFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	f := &workerChannelFixture{target: value.WorkerCredentialTarget{InstallationID: channelInstallation, SessionID: channelSession, WorkerID: channelWorker, PodUID: channelPod, CreatedAt: now.Add(-time.Second), RunUntil: now.Add(time.Hour)}}
	f.clock.Store(now.UnixNano())
	var err error
	f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-channel-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, f.key.Public(), f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.root)
	return f
}
func channelServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	s.Config.ReadHeaderTimeout = 2 * time.Second
	s.Config.IdleTimeout = 2 * time.Second
	s.Config.MaxHeaderBytes = 20 << 10
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return s, roots
}
func channelCredentials(t *testing.T, f *workerChannelFixture, handler http.Handler) (*mtls.WorkerCredentials, *httptest.Server) {
	t.Helper()
	if handler == nil {
		var err error
		handler, err = workertransport.NewHandler(f.target.InstallationID, f, f.now, 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	s, roots := channelServer(t, handler)
	c, err := mtls.NewWorkerCredentials(s.URL, f.target, roots, f.roots, f, f.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, s
}
func channelCert(t *testing.T, c *mtls.WorkerCredentials) *tls.Certificate {
	t.Helper()
	cert, err := c.GetClientCertificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS13, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestWorkerChannelRenewalAndProcessKey(t *testing.T) {
	f := newWorkerChannelFixture(t)
	c, _ := channelCredentials(t, f, nil)
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial := channelCert(t, c)
	if err := c.Enroll(context.Background()); err != nil || f.calls.Load() != 1 || f.tokens.Load() != 1 {
		t.Fatal("cached credential performed enrollment", err)
	}
	f.clock.Store(f.target.CreatedAt.Add(19 * time.Minute).UnixNano())
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	renewed := channelCert(t, c)
	if bytes.Equal(initial.Certificate[0], renewed.Certificate[0]) || !bytes.Equal(initial.Leaf.RawSubjectPublicKeyInfo, renewed.Leaf.RawSubjectPublicKeyInfo) || f.calls.Load() != 2 || f.tokens.Load() != 2 {
		t.Fatal("renewal replaced process key or failed to reread projected token")
	}
	hash := sha256.Sum256([]byte("synthetic TLS signature"))
	if _, err := initial.PrivateKey.(crypto.Signer).Sign(rand.Reader, hash[:], crypto.SHA256); err != nil {
		t.Fatal("renewal broke original finite overlap", err)
	}
	f.clock.Store(initial.Leaf.NotAfter.UnixNano())
	if _, err := initial.PrivateKey.(crypto.Signer).Sign(rand.Reader, hash[:], crypto.SHA256); err == nil {
		t.Fatal("expired signer remained usable")
	}
	if _, err := renewed.PrivateKey.(crypto.Signer).Sign(rand.Reader, hash[:], crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := renewed.PrivateKey.(crypto.Signer).Sign(rand.Reader, hash[:], crypto.SHA256); err == nil {
		t.Fatal("close left retained signer usable")
	}
	if _, err := c.Peer(); err == nil {
		t.Fatal("close left identity usable")
	}
	if err := c.Enroll(context.Background()); err == nil {
		t.Fatal("closed key enrolled again")
	}
}

func TestWorkerChannelActualMutualTLS(t *testing.T) {
	f := newWorkerChannelFixture(t)
	c, _ := channelCredentials(t, f, nil)
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	verifier, err := mtls.NewKeyPeerVerifier(f.roots, f.target.InstallationID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	accepted := atomic.Int64{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, e := verifier.Verify(r.TLS)
		expected, other := c.Peer()
		if e != nil || other != nil || peer != expected {
			w.WriteHeader(403)
			return
		}
		accepted.Add(1)
		w.WriteHeader(204)
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.roots, Time: f.now}
	s.StartTLS()
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, GetClientCertificate: c.GetClientCertificate, Time: f.now}}
	defer transport.CloseIdleConnections()
	h := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := h.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 || accepted.Load() != 1 {
		t.Fatal("process-owned credential failed actual TLS")
	}
}

func TestWorkerChannelRejectsCertificateSubstitution(t *testing.T) {
	cases := map[string]func(*x509.Certificate){
		"key":          func(c *x509.Certificate) { c.Subject.CommonName = "wrong-key" },
		"pod":          func(c *x509.Certificate) { c.URIs[0].Path = "/key-client/acquisition/" + channelSession },
		"installation": func(c *x509.Certificate) { c.URIs[0].Host = "asservat." + channelSession },
		"role":         func(c *x509.Certificate) { c.URIs[0].Path = "/key-client/collector/" + channelPod },
		"dns":          func(c *x509.Certificate) { c.DNSNames = []string{"untrusted.invalid"} },
		"server-usage": func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"expiry":       func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Second) },
		"expired":      func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(-time.Second) },
		"old-start":    func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(-time.Hour) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newWorkerChannelFixture(t)
			f.mutate = mutate
			c, _ := channelCredentials(t, f, nil)
			if err := c.Enroll(context.Background()); err == nil {
				t.Fatal("substituted certificate installed")
			}
			if _, err := c.Peer(); err == nil {
				t.Fatal("rejected leaf yielded peer")
			}
		})
	}
}

func TestWorkerChannelResponseFramingAndNoRedirect(t *testing.T) {
	for _, mode := range []string{"nonce", "worker", "unknown", "null-chain", "duplicate", "oversize", "redirect", "encoding", "media", "trailer", "lost-reply"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkerChannelFixture(t)
			requests := atomic.Int64{}
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				in, err := contracts.DecodeWorkerEnrollmentRequest(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", "/credential-leak")
					w.WriteHeader(307)
					return
				}
				if mode == "lost-reply" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				c, err := f.EnrollWorker(r.Context(), in.InstallationID, in.SessionID, in.WorkerID, []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), in.CSR)
				if err != nil {
					t.Error(err)
					return
				}
				out := contracts.WorkerEnrollmentResponse{Format: in.Format, InstallationID: in.InstallationID, SessionID: in.SessionID, WorkerID: in.WorkerID, Nonce: in.Nonce, Certificate: c.DER, Chain: c.ChainDER}
				switch mode {
				case "nonce":
					out.Nonce = strings.Repeat("A", 43)
				case "worker":
					out.WorkerID = channelSession
				case "null-chain":
					out.Chain = nil
				}
				body, _ := json.Marshal(out)
				switch mode {
				case "unknown":
					body = append(body[:len(body)-1], []byte(",\"extra\":true}")...)
				case "duplicate":
					body = append(body[:len(body)-1], []byte(",\"format\":\"asservat-worker-enrollment/v1\"}")...)
				case "oversize":
					body = bytes.Repeat([]byte("x"), contracts.WorkerEnrollmentMaxResponse+1)
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "media" {
					w.Header().Set("Content-Type", "text/html")
				}
				if mode == "encoding" {
					w.Header().Set("Content-Encoding", "gzip")
				}
				if mode == "trailer" {
					w.Header().Set("Trailer", "Unexpected")
				}
				w.Write(body)
			})
			c, _ := channelCredentials(t, f, h)
			if err := c.Enroll(context.Background()); err == nil {
				t.Fatal("invalid response accepted")
			}
			if requests.Load() != 1 {
				t.Fatal("enrollment automatically replayed or followed redirect")
			}
		})
	}
}

func TestWorkerChannelCancellationAndSingleFlight(t *testing.T) {
	f := newWorkerChannelFixture(t)
	entered := make(chan struct{})
	f.block = func(ctx context.Context) { close(entered); <-ctx.Done() }
	c, s := channelCredentials(t, f, nil)
	done := make(chan error, 1)
	go func() { done <- c.Enroll(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("did not reach enrollment")
	}
	if err := c.Enroll(context.Background()); err == nil {
		t.Fatal("parallel enrollment accepted")
	}
	req, _ := http.NewRequest(http.MethodPost, s.URL+contracts.WorkerEnrollmentPath, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer synthetic.first.token")
	response, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 429 {
		t.Fatal("server did not bound concurrent work", response.StatusCode)
	}
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed request succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel request")
	}
	if f.calls.Load() != 1 {
		t.Fatal("duplicate enrollment reached authority")
	}
}

func TestWorkerChannelIngressRejectsPublicAndMalformedInputs(t *testing.T) {
	for _, mode := range []string{"http", "cookie", "duplicate-auth", "unknown", "missing", "token-space", "install", "principal", "query"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkerChannelFixture(t)
			h, err := workertransport.NewHandler(f.target.InstallationID, f, f.now, 1)
			if err != nil {
				t.Fatal(err)
			}
			var s *httptest.Server
			if mode == "http" {
				s = httptest.NewServer(h)
				defer s.Close()
			} else {
				s, _ = channelServer(t, h)
			}
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			in := contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: channelInstallation, SessionID: channelSession, WorkerID: channelWorker, Nonce: strings.Repeat("A", 43), CSR: csr}
			if mode == "install" {
				in.InstallationID = channelSession
			}
			b, _ := json.Marshal(in)
			switch mode {
			case "unknown", "principal":
				b = append(b[:len(b)-1], []byte(",\"principal\":\"administrator\"}")...)
			case "missing":
				b = []byte("{}")
			}
			endpoint := s.URL + contracts.WorkerEnrollmentPath
			if mode == "query" {
				endpoint += "?token=synthetic"
			}
			r, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer synthetic.first.token")
			switch mode {
			case "cookie":
				r.Header.Set("Cookie", "session=synthetic")
			case "duplicate-auth":
				r.Header.Add("Authorization", "Bearer synthetic.other.token")
			case "token-space":
				r.Header.Set("Authorization", "Bearer synthetic first token")
			}
			response, err := s.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode < 400 || f.calls.Load() != 0 || len(body) != 0 {
				t.Fatal("invalid ingress reached authority or disclosed diagnostics", response.StatusCode)
			}
		})
	}
}

func TestWorkerChannelFailedRenewalKeepsOnlyOriginalCredential(t *testing.T) {
	f := newWorkerChannelFixture(t)
	fail := atomic.Bool{}
	handler, err := workertransport.NewHandler(f.target.InstallationID, f, f.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := channelCredentials(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := c.Peer()
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	f.clock.Store(f.target.CreatedAt.Add(19 * time.Minute).UnixNano())
	if err := c.Enroll(context.Background()); err == nil {
		t.Fatal("failed renewal succeeded")
	}
	after, err := c.Peer()
	if err != nil || after != before {
		t.Fatal("failed renewal altered original credential", err)
	}
	tokens := f.tokens.Load()
	if err := c.Enroll(context.Background()); err == nil || f.tokens.Load() != tokens {
		t.Fatal("failed retry bypassed spacing")
	}
	f.clock.Store(before.NotAfter.UnixNano())
	if _, err := c.Peer(); err == nil {
		t.Fatal("failed renewal extended original expiry")
	}
}

func TestWorkerChannelPinnedTrustAndEndpoint(t *testing.T) {
	f := newWorkerChannelFixture(t)
	h, err := workertransport.NewHandler(f.target.InstallationID, f, f.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	server, roots := channelServer(t, h)
	for _, endpoint := range []string{"http://localhost", server.URL + "?token=forbidden", server.URL + "/arbitrary", strings.Replace(server.URL, "https://", "https://credential@", 1), server.URL + "#fragment"} {
		if c, err := mtls.NewWorkerCredentials(endpoint, f.target, roots, f.roots, f, f.now); err == nil {
			c.Close()
			t.Fatal("unsafe endpoint accepted", endpoint)
		}
	}
	other := newWorkerChannelFixture(t)
	c, err := mtls.NewWorkerCredentials(server.URL, f.target, other.roots, f.roots, f, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Enroll(context.Background()); err == nil || f.calls.Load() != 0 {
		t.Fatal("unpinned server received enrollment", err)
	}
	c, err = mtls.NewWorkerCredentials(server.URL, f.target, roots, other.roots, f, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Enroll(context.Background()); err == nil {
		t.Fatal("unpinned issuer accepted")
	}
	var zero mtls.WorkerCredentials
	if err := zero.Enroll(context.Background()); err == nil {
		t.Fatal("uninitialized client accepted")
	}
	zero.Close()
}

func TestWorkerChannelRechecksExpiredServerAtRenewal(t *testing.T) {
	f := newWorkerChannelFixture(t)
	handler, err := workertransport.NewHandler(f.target.InstallationID, f, f.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(999), NotBefore: f.now().Add(-time.Minute), NotAfter: f.now().Add(10 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, f.root, key.Public(), f.key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der, f.root.Raw}, PrivateKey: key}}, Time: f.now}
	server.StartTLS()
	defer server.Close()
	c, err := mtls.NewWorkerCredentials(server.URL, f.target, f.roots, f.roots, f, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clock.Store(f.target.CreatedAt.Add(19 * time.Minute).UnixNano())
	if err := c.Enroll(context.Background()); err == nil || f.calls.Load() != 1 {
		t.Fatal("reused channel sent token to expired server", err)
	}
}
