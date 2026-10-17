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
	"io"
	"slices"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerCredentials owns one purpose's key for one process. Bootstrap supplies
// a fresh process epoch and separate server/client instances. It never accepts
// or serializes a private key. Its certificate is identity, not request authority.
type OwnerCredentials struct {
	mu           sync.Mutex
	binding      value.OwnerBinding
	usage        string
	verifier     *OwnerPeerVerifier
	enrollment   app.OwnerCredentialEnrollment
	registry     app.OwnerCertificateRegistry
	now          func() time.Time
	key          *ecdsa.PrivateKey
	csr          []byte
	cert         *tls.Certificate
	identity     value.OwnerCertificate
	closed, busy bool
	lastAttempt  time.Time
	cancel       context.CancelFunc
}

var _ app.OwnerCredentialClient = (*OwnerCredentials)(nil)
var _ app.OwnerCredentialEnrollment = (*app.OwnerEnrollmentCoordinator)(nil)

func NewOwnerCredentials(binding value.OwnerBinding, usage string, roots *x509.CertPool, enrollment app.OwnerCredentialEnrollment, registry app.OwnerCertificateRegistry, now func() time.Time) (*OwnerCredentials, error) {
	if !binding.Valid() || (usage != "server" && usage != "client") || enrollment == nil || registry == nil || now == nil {
		return nil, value.ErrInvalid
	}
	v, err := NewOwnerPeerVerifier(roots, binding.InstallationID, binding.ClusterID, binding.IssuerEpoch, now)
	if err != nil {
		return nil, err
	}
	if _, _, err = value.OwnerCertificateWindow(now()); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	if _, err = EnrollmentKey(csr); err != nil {
		return nil, err
	}
	return &OwnerCredentials{binding: binding, usage: usage, verifier: v, enrollment: enrollment, registry: registry, now: now, key: key, csr: csr}, nil
}

// Enroll performs one bounded attempt, retaining the original CSR across
// retries and renewal. No hidden retry or new signing permit is introduced.
// Returning an already installed current-window leaf is only a local identity
// result; every protected peer use still requires OwnerAuthenticator.
func (c *OwnerCredentials) Enroll(ctx context.Context) error {
	if c == nil || c.now == nil || c.enrollment == nil || c.registry == nil || ctx == nil || ctx.Err() != nil {
		return value.ErrInvalid
	}
	c.mu.Lock()
	start := c.now()
	_, until, err := value.OwnerCertificateWindow(start)
	if err != nil || ctx.Err() != nil || c.closed || c.busy {
		c.mu.Unlock()
		return value.ErrUnavailable
	}
	if c.identity.Valid(start) && c.identity.NotAfter.Equal(until) {
		c.mu.Unlock()
		return nil
	}
	if !c.lastAttempt.IsZero() && start.Before(c.lastAttempt.Add(time.Second)) {
		c.mu.Unlock()
		return value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	c.busy, c.lastAttempt, c.cancel = true, start, cancel
	csr := bytes.Clone(c.csr)
	c.mu.Unlock()
	defer func() { cancel(); c.mu.Lock(); c.busy, c.cancel = false, nil; c.mu.Unlock() }()
	out, err := c.enrollment.Enroll(ctx, value.OwnerEnrollmentRequest{Binding: c.binding, Usage: c.usage, CSRDER: bytes.Clone(csr)})
	if err != nil {
		return err
	}
	if ctx.Err() != nil || c.now().Before(start) || !c.now().Before(start.Add(30*time.Second)) {
		return value.ErrUnavailable
	}
	cert, identity, err := c.checkCertificate(start, csr, out)
	if err != nil {
		return err
	}
	registration, err := c.registry.ReadOwnerRegistration(ctx, identity)
	if err != nil {
		return err
	}
	key, err := EnrollmentKey(csr)
	if err != nil || !registration.Valid(c.now()) || !sameOwnerCertificate(registration.Certificate, identity) || registration.Enrollment.PublicKeyDigest != key {
		return value.ErrDenied
	}
	// Registry is independently pool/source pinned. Both constructor and current
	// accepted roots must validate the actual certificate, never metadata alone.
	registration.Configuration.Configuration = registration.Configuration.Configuration.Clone()
	current, err := c.verifier.currentVerifier(registration.Configuration)
	if err != nil {
		return err
	}
	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	for _, der := range cert.Certificate {
		parsed, e := x509.ParseCertificate(der)
		if e != nil {
			return value.ErrDenied
		}
		chain = append(chain, parsed)
	}
	verified, err := current.verifyCertificates(chain, c.usage)
	if err != nil || !sameOwnerCertificate(verified, identity) {
		return value.ErrDenied
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	finish := c.now()
	if c.closed || ctx.Err() != nil || finish.Before(start) || !finish.Before(start.Add(30*time.Second)) || !identity.Valid(finish) || !registration.Valid(finish) {
		return value.ErrUnavailable
	}
	cert.PrivateKey = &ownerCredentialSigner{owner: c, identity: identity, publicDER: bytes.Clone(cert.Leaf.RawSubjectPublicKeyInfo)}
	c.cert, c.identity = cert, identity
	return nil
}

func sameOwnerCertificate(a, b value.OwnerCertificate) bool {
	return a.Binding == b.Binding && a.Usage == b.Usage && a.Digest == b.Digest && a.NotBefore.Equal(b.NotBefore) && a.NotAfter.Equal(b.NotAfter)
}

func (c *OwnerCredentials) checkCertificate(start time.Time, csr []byte, result value.IssuedOwnerCertificate) (*tls.Certificate, value.OwnerCertificate, error) {
	var zero value.OwnerCertificate
	if len(result.DER) < 1 || len(result.DER) > 16<<10 || len(result.ChainDER) > 3 {
		return nil, zero, value.ErrDenied
	}
	total := len(result.DER)
	for _, der := range result.ChainDER {
		total += len(der)
		if len(der) < 1 || len(der) > 16<<10 || total > 32<<10 {
			return nil, zero, value.ErrDenied
		}
	}
	result = result.Clone()
	raw := append([][]byte{result.DER}, result.ChainDER...)
	chain := make([]*x509.Certificate, 0, len(raw))
	for _, der := range raw {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, zero, value.ErrDenied
		}
		chain = append(chain, cert)
	}
	key, err := EnrollmentKey(csr)
	if err != nil || artifact.Digest(sha256.Sum256(chain[0].RawSubjectPublicKeyInfo)) != key {
		return nil, zero, value.ErrDenied
	}
	identity, err := c.verifier.verifyCertificates(chain, c.usage)
	if err != nil || identity.Binding != c.binding || !sameOwnerCertificate(identity, result.Certificate) || !identity.NotAfter.Equal(chain[0].NotAfter) || identity.NotAfter.Sub(identity.NotBefore) > value.OwnerCertificatePeriod+value.OwnerCertificateRenewBefore+time.Minute {
		return nil, zero, value.ErrDenied
	}
	// A bounded request may straddle the fixed UTC renewal boundary. Neither
	// caller retries nor provider response dates create a different period.
	finish := c.now()
	_, first, e1 := value.OwnerCertificateWindow(start)
	_, last, e2 := value.OwnerCertificateWindow(finish)
	if e1 != nil || e2 != nil || finish.Before(start) || !(identity.NotAfter.Equal(first) || identity.NotAfter.Equal(last)) {
		return nil, zero, value.ErrDenied
	}
	return &tls.Certificate{Certificate: raw, Leaf: chain[0]}, identity, nil
}

// Snapshot copies public bytes/parsed state. The signer exposes only a copied
// public key and retains the original leaf's expiry even after renewal.
func (c *OwnerCredentials) snapshot() (*tls.Certificate, error) {
	if c == nil || c.now == nil {
		return nil, value.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.cert == nil || !c.identity.Valid(c.now()) {
		return nil, value.ErrUnavailable
	}
	out := *c.cert
	out.Certificate = make([][]byte, len(c.cert.Certificate))
	for i, der := range c.cert.Certificate {
		out.Certificate[i] = bytes.Clone(der)
	}
	out.Leaf, _ = x509.ParseCertificate(out.Certificate[0])
	return &out, nil
}

func (c *OwnerCredentials) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c == nil || c.usage != "server" || info == nil || !slices.Contains(info.SupportedVersions, tls.VersionTLS13) {
		return nil, value.ErrDenied
	}
	name, _ := OwnerServerName(c.binding)
	if info.ServerName != name {
		return nil, value.ErrDenied
	}
	out, err := c.snapshot()
	if err != nil {
		return nil, err
	}
	if info.SupportsCertificate(out) != nil {
		return nil, value.ErrDenied
	}
	return out, nil
}
func (c *OwnerCredentials) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c == nil || c.usage != "client" || info == nil || info.Version != tls.VersionTLS13 {
		return nil, value.ErrDenied
	}
	out, err := c.snapshot()
	if err != nil {
		return nil, err
	}
	if info.SupportsCertificate(out) != nil {
		return nil, value.ErrDenied
	}
	return out, nil
}
func (c *OwnerCredentials) Certificate() (value.OwnerCertificate, error) {
	if c == nil || c.now == nil {
		return value.OwnerCertificate{}, value.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.identity.Valid(c.now()) {
		return value.OwnerCertificate{}, value.ErrUnavailable
	}
	return c.identity, nil
}

// Close cancels enrollment and disables retained signers. Socket closure belongs
// to the runtime; Go does not guarantee physical heap zeroization.
func (c *OwnerCredentials) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	c.key, c.cert = nil, nil
	c.identity = value.OwnerCertificate{}
}

type ownerCredentialSigner struct {
	owner     *OwnerCredentials
	identity  value.OwnerCertificate
	publicDER []byte
}

func (s *ownerCredentialSigner) Public() crypto.PublicKey {
	key, _ := x509.ParsePKIXPublicKey(bytes.Clone(s.publicDER))
	return key
}
func (s *ownerCredentialSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.key == nil || !s.identity.Valid(c.now()) || opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, value.ErrDenied
	}
	// Do not let a caller-supplied blocking/randomness reader hold shutdown.
	signed, err := c.key.Sign(rand.Reader, digest, opts)
	if err != nil || !s.identity.Valid(c.now()) {
		return nil, value.ErrDenied
	}
	return signed, nil
}
