package mtls

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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type connectorCredentialFixture struct {
	t              *testing.T
	ca             ownerTestCA
	now            time.Time
	advance        atomic.Int64
	bootstrap      app.ConnectorBootstrapReference
	original       audit.EnrollmentClaim
	issued         value.IssuedCertificate
	firstCSR       []byte
	calls          int
	mode           string
	block, release chan struct{}
	revoked        atomic.Bool
}

func newConnectorCredentialFixture(t *testing.T) *connectorCredentialFixture {
	now := time.Now().UTC().Truncate(time.Second)
	b := value.PeerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PeerID: ownerTestID, Role: value.ConnectorPeer}
	f := &connectorCredentialFixture{t: t, ca: newOwnerTestCA(t, now), now: now, bootstrap: app.ConnectorBootstrapReference{ID: ownerTestID, Binding: b, SecretDigest: artifact.Digest{1}, NotBefore: now, NotAfter: now.Add(5 * time.Minute)}}
	return f
}
func (f *connectorCredentialFixture) clock() time.Time {
	return f.now.Add(time.Duration(f.advance.Load()))
}
func (f *connectorCredentialFixture) Enroll(ctx context.Context, c value.EnrollmentClaim, csr []byte) (value.IssuedCertificate, error) {
	f.calls++
	if f.firstCSR == nil {
		f.firstCSR = bytes.Clone(csr)
	} else if !bytes.Equal(f.firstCSR, csr) {
		f.t.Error("retry replaced original CSR")
	}
	key, e := EnrollmentKey(csr)
	if e != nil || key != c.PublicKeyDigest || c.SecretDigest != f.bootstrap.SecretDigest || c.BootstrapID != f.bootstrap.ID {
		return value.IssuedCertificate{}, value.ErrDenied
	}
	if f.mode == "blocked" {
		close(f.block)
		<-ctx.Done()
		<-f.release
		return value.IssuedCertificate{}, ctx.Err()
	}
	if f.mode == "unknown" && f.calls == 1 {
		return value.IssuedCertificate{}, value.ErrUnavailable
	}
	request, e := x509.ParseCertificateRequest(csr)
	if e != nil {
		return value.IssuedCertificate{}, e
	}
	f.original = audit.EnrollmentClaim{BootstrapID: c.BootstrapID, Binding: f.bootstrap.Binding, PublicKeyDigest: key, IssueAuthorityDigest: artifact.Digest{2}, IssueAuditDigest: artifact.Digest{3}, IssueAuditID: ownerTestID, IssuedAt: f.bootstrap.NotBefore, ClaimedAt: f.now, NotAfter: f.bootstrap.NotAfter}
	u, _ := PeerURI(f.bootstrap.Binding)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: f.now.Add(-time.Second), NotAfter: f.now.Add(30 * time.Minute)}
	switch f.mode {
	case "server":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "extended":
		template.NotAfter = template.NotAfter.Add(time.Second)
	case "wrong-key":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		request.PublicKey = k.Public()
	case "dns":
		template.DNSNames = []string{"unexpected.invalid"}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, f.ca.cert, request.PublicKey, f.ca.key)
	if e != nil {
		return value.IssuedCertificate{}, e
	}
	f.issued = value.IssuedCertificate{Certificate: value.PeerCertificate{Binding: f.bootstrap.Binding, Digest: artifact.Digest(sha256.Sum256(der)), NotBefore: template.NotBefore, NotAfter: template.NotAfter}, DER: der, ChainDER: [][]byte{f.ca.cert.Raw}}
	return f.issued, nil
}
func (f *connectorCredentialFixture) ReadEnrollmentClaim(context.Context, string, string) (audit.EnrollmentClaim, error) {
	out := f.original
	if f.mode == "changed-claim" {
		out.NotAfter = out.NotAfter.Add(-time.Second)
	}
	return out, nil
}
func (f *connectorCredentialFixture) PeerRegistration(_ context.Context, b value.PeerBinding) (value.PeerRegistration, error) {
	if f.revoked.Load() {
		return value.PeerRegistration{}, value.ErrDenied
	}
	now := f.clock()
	out := value.PeerRegistration{Binding: b, Revision: identity.Revision{UID: ownerTestID, Generation: 1, Digest: artifact.Digest{4}}, Enabled: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Certificates: []value.PeerCertificate{f.issued.Certificate}}
	if f.mode == "late-registry" {
		f.advance.Add(int64(31 * time.Second))
	}
	return out, nil
}
func (f *connectorCredentialFixture) owner(ctx context.Context) *ConnectorCredentials {
	c, e := NewConnectorCredentials(ctx, f.bootstrap, f.ca.roots, f, f, f, f.clock)
	if e != nil {
		f.t.Fatal(e)
	}
	f.t.Cleanup(c.Close)
	return c
}
func connectorRequestInfo() *tls.CertificateRequestInfo {
	return &tls.CertificateRequestInfo{Version: tls.VersionTLS13, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}
}
func TestConnectorCredentialsOriginalClaimAndRetainedSigner(t *testing.T) {
	f := newConnectorCredentialFixture(t)
	f.mode = "unknown"
	c := f.owner(context.Background())
	if c.Enroll(context.Background()) == nil {
		t.Fatal("unknown outcome installed certificate")
	}
	f.advance.Store(int64(2 * time.Second))
	if e := c.Enroll(context.Background()); e != nil {
		t.Fatal(e)
	}
	cert, e := c.GetClientCertificate(connectorRequestInfo())
	if e != nil {
		t.Fatal(e)
	}
	if !cert.Leaf.NotAfter.Equal(f.now.Add(30 * time.Minute)) {
		t.Fatal("retry extended certificate expiry")
	}
	if e = c.Enroll(context.Background()); e != nil || f.calls != 2 {
		t.Fatal("installed leaf reissued", e, f.calls)
	}
	// A retained certificate is immutable public state and a bounded signer.
	cert.Certificate[0][0] ^= 1
	again, e := c.GetClientCertificate(connectorRequestInfo())
	if e != nil || bytes.Equal(cert.Certificate[0], again.Certificate[0]) {
		t.Fatal("snapshot alias", e)
	}
	signer := again.PrivateKey.(crypto.Signer)
	digest := sha256.Sum256([]byte("synthetic handshake"))
	if _, e = signer.Sign(rand.Reader, digest[:], crypto.SHA256); e != nil {
		t.Fatal(e)
	}
	f.revoked.Store(true)
	if c.Enroll(context.Background()) == nil {
		t.Fatal("cached identity bypassed current registration")
	}
	c.Close()
	if _, e = signer.Sign(rand.Reader, digest[:], crypto.SHA256); e == nil {
		t.Fatal("retained signer survived close")
	}
}
func TestConnectorCredentialsRejectMalformedAndLateResults(t *testing.T) {
	for _, mode := range []string{"server", "extended", "wrong-key", "dns", "changed-claim", "late-registry"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorCredentialFixture(t)
			f.mode = mode
			c := f.owner(context.Background())
			if c.Enroll(context.Background()) == nil {
				t.Fatal("unqualified result installed")
			}
			if _, e := c.GetClientCertificate(connectorRequestInfo()); e == nil {
				t.Fatal("rejected result exposed")
			}
		})
	}
}
func TestConnectorCredentialsCloseJoinsOriginalOwner(t *testing.T) {
	f := newConnectorCredentialFixture(t)
	f.mode = "blocked"
	f.block = make(chan struct{})
	f.release = make(chan struct{})
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := f.owner(owner)
	enrolled := make(chan error, 1)
	go func() { enrolled <- c.Enroll(context.Background()) }()
	<-f.block
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before blocked owned operation joined")
	case <-time.After(10 * time.Millisecond):
	}
	close(f.release)
	select {
	case e := <-enrolled:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("enrollment did not cancel")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join")
	}
}
func TestConnectorIdentityUsesProcessOwnedCertificate(t *testing.T) {
	f := newConnectorCredentialFixture(t)
	c := f.owner(context.Background())
	if e := c.Enroll(context.Background()); e != nil {
		t.Fatal(e)
	}
	n, e := NewNativeConnectorIdentity(f.bootstrap.Binding, f.ca.roots, &app.PeerAuthenticator{Registry: f, Now: f.clock}, c.GetClientCertificate, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = n.CheckNativeConnector(context.Background()); e != nil {
		t.Fatal("production process-owned callback rejected", e)
	}
}

func TestConnectorCredentialsActualTLSAndCurrentRevocation(t *testing.T) {
	f := newConnectorCredentialFixture(t)
	c := f.owner(context.Background())
	if e := c.Enroll(context.Background()); e != nil {
		t.Fatal(e)
	}
	verifier, e := NewPeerVerifier(f.ca.roots, f.bootstrap.Binding.InstallationID, value.ConnectorPeer, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	authenticator := app.PeerAuthenticator{Registry: f, Now: f.clock}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, e := verifier.Verify(r.TLS)
		if e == nil {
			_, e = authenticator.AuthenticatePeer(r.Context(), peer)
		}
		if e != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.ca.roots, Time: f.clock}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.GetClientCertificate = c.GetClientCertificate
	client.Transport = transport
	client.Timeout = 2 * time.Second
	for _, revoked := range []bool{false, true} {
		f.revoked.Store(revoked)
		response, e := client.Get(server.URL)
		if e != nil {
			t.Fatal("actual process-owned TLS client", e)
		}
		response.Body.Close()
		expected := http.StatusNoContent
		if revoked {
			expected = http.StatusForbidden
		}
		if response.StatusCode != expected {
			t.Fatal("current registration did not fence same client identity", response.StatusCode)
		}
	}
}
