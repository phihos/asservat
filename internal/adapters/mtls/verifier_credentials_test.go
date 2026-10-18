package mtls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
)

const verifierTestInstallation = "10000000-0000-4000-8000-000000002031"

type verifierTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newVerifierTestCA(t *testing.T, now time.Time) verifierTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2031), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return verifierTestCA{cert, key, pool}
}

// verifierTestSigner is a synthetic provider: it signs the CSR's key for the
// requested URI unless a mode substitutes something else.
type verifierTestSigner struct {
	mu    sync.Mutex
	ca    verifierTestCA
	now   func() time.Time
	mode  string
	calls int
	uris  []string
	keys  [][32]byte
}

func (s *verifierTestSigner) SignVerifierCertificate(_ context.Context, csr []byte, uri string) ([]byte, [][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.uris = append(s.uris, uri)
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, err
	}
	public := request.PublicKey
	s.keys = append(s.keys, sha256.Sum256(request.RawSubjectPublicKeyInfo))
	at := s.now()
	notAfter := at.Add(VerifierCertificatePeriod)
	u, _ := url.Parse(uri)
	issuer, issuerKey := s.ca.cert, crypto.Signer(s.ca.key)
	switch s.mode {
	case "other-peer":
		u, _ = url.Parse(VerifierCertificateURI(verifierTestInstallation, "10000000-0000-4000-8000-0000000020ff"))
	case "acquisition-role":
		u, _ = url.Parse(strings.Replace(uri, "/verifier/", "/acquisition/", 1))
	case "other-key":
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		public = other.Public()
	case "long-period":
		notAfter = at.Add(50 * time.Minute)
	case "untrusted-issuer":
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		issuerKey = other
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(s.calls) + 9000), NotBefore: at.Add(-30 * time.Second), NotAfter: notAfter, URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, issuerKey)
	if err != nil {
		return nil, nil, err
	}
	return der, [][]byte{s.ca.cert.Raw}, nil
}

type verifierTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *verifierTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *verifierTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ADR-203 decision 4: the in-process verifier key gets exactly its own
// key-client/verifier URI, renews at half the period with the same key and
// stops signing once closed.
func TestVerifierCredentialsRenewAtHalfPeriodAndCloseDisablesSigner(t *testing.T) {
	clock := &verifierTestClock{now: time.Now().UTC().Truncate(time.Second)}
	ca := newVerifierTestCA(t, clock.Now())
	signer := &verifierTestSigner{ca: ca, now: clock.Now}
	v, err := NewVerifierCredentials(verifierTestInstallation, signer, ca.pool, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	info := &tls.CertificateRequestInfo{Version: tls.VersionTLS13, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}
	if _, err = v.GetClientCertificate(info); err == nil {
		t.Fatal("certificate served before signing")
	}
	if err = v.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	peer, err := v.Peer()
	if err != nil || peer.Role != "verifier" || !value.UUID(peer.PeerID) || peer.InstallationID != verifierTestInstallation || signer.uris[0] != "spiffe://asservat."+verifierTestInstallation+"/key-client/verifier/"+peer.PeerID {
		t.Fatal("verifier identity", peer, signer.uris, err)
	}
	if !peer.CanRequest(value.KeyScope{InstallationID: verifierTestInstallation, Purpose: "artifact", KeyID: "artifact"}, "unwrap") || peer.CanRequest(value.KeyScope{InstallationID: verifierTestInstallation, Purpose: "artifact", KeyID: "artifact"}, "wrap") {
		t.Fatal("verifier role gained more than artifact unwrap eligibility")
	}
	snapshot, err := v.GetClientCertificate(info)
	if err != nil || len(snapshot.Certificate) != 2 {
		t.Fatal("client certificate", err)
	}
	digest := sha256.Sum256([]byte("synthetic-handshake"))
	if _, err = snapshot.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatal("installed signer refused", err)
	}
	if _, err = v.GetClientCertificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS 1.2 client certificate served")
	}
	clock.advance(9 * time.Minute)
	if err = v.Renew(context.Background()); err != nil || signer.calls != 1 {
		t.Fatal("renewed before half the period", err, signer.calls)
	}
	clock.advance(2 * time.Minute)
	if err = v.Renew(context.Background()); err != nil || signer.calls != 2 || signer.keys[0] != signer.keys[1] || signer.uris[0] != signer.uris[1] {
		t.Fatal("half-period renewal changed key or URI or did not run", err, signer.calls)
	}
	other, err := NewVerifierCredentials(verifierTestInstallation, signer, ca.pool, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = other.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if second, _ := other.Peer(); second.PeerID == peer.PeerID || signer.keys[2] == signer.keys[0] {
		t.Fatal("a second process reused the peer ID or key")
	}
	other.Close()
	v.Close()
	if _, err = snapshot.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("retained signer usable after close")
	}
	if _, err = v.GetClientCertificate(info); err == nil {
		t.Fatal("closed credential served a certificate")
	}
	if v.Renew(context.Background()) == nil || v.Run(context.Background()) == nil {
		t.Fatal("closed credential renewed")
	}
}

// A provider reply for another peer, role or key, a period beyond the role's
// or an untrusted issuer installs nothing.
func TestVerifierCredentialsRejectSubstitutedCertificates(t *testing.T) {
	for _, mode := range []string{"other-peer", "acquisition-role", "other-key", "long-period", "untrusted-issuer"} {
		t.Run(mode, func(t *testing.T) {
			clock := &verifierTestClock{now: time.Now().UTC().Truncate(time.Second)}
			ca := newVerifierTestCA(t, clock.Now())
			signer := &verifierTestSigner{ca: ca, now: clock.Now, mode: mode}
			v, err := NewVerifierCredentials(verifierTestInstallation, signer, ca.pool, clock.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if err = v.Renew(context.Background()); err == nil {
				t.Fatal("accepted", mode)
			}
			if _, err = v.Peer(); err == nil {
				t.Fatal("identity installed", mode)
			}
			if err = v.Renew(context.Background()); err == nil || signer.calls != 1 {
				t.Fatal("failed attempt retried without waiting", signer.calls)
			}
		})
	}
	if _, err := NewVerifierCredentials("not-an-installation", &verifierTestSigner{}, x509.NewCertPool(), time.Now); err == nil {
		t.Fatal("invalid installation accepted")
	}
}
