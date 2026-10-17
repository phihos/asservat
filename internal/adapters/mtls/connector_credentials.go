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
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorCredentials owns one initial connector process key. The runtime
// must disable core dumps before construction. This type never exports the key,
// invents a bootstrap or renews the initial certificate. Its TLS snapshot is
// identity only: NativeConnectorIdentity still checks current registry authority.
type ConnectorCredentials struct {
	mu          sync.Mutex
	root        context.Context
	stop        context.CancelFunc
	bootstrap   app.ConnectorBootstrapReference
	enrollment  app.ConnectorCredentialEnrollment
	claims      app.ConnectorCredentialClaims
	registry    *app.PeerAuthenticator
	verifier    *PeerVerifier
	now         func() time.Time
	key         *ecdsa.PrivateKey
	csr         []byte
	cert        *tls.Certificate
	identity    value.PeerCertificate
	active      chan struct{}
	cancel      context.CancelFunc
	lastAttempt time.Time
	closed      bool
}

func NewConnectorCredentials(ctx context.Context, bootstrap app.ConnectorBootstrapReference, roots *x509.CertPool, enrollment app.ConnectorCredentialEnrollment, claims app.ConnectorCredentialClaims, registry app.PeerRegistry, now func() time.Time) (*ConnectorCredentials, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !bootstrap.Valid(now()) || enrollment == nil || claims == nil || registry == nil {
		return nil, value.ErrInvalid
	}
	verifier, err := NewPeerVerifier(roots, bootstrap.Binding.InstallationID, value.ConnectorPeer, now)
	if err != nil {
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
	if ctx.Err() != nil || !bootstrap.Valid(now()) {
		return nil, value.ErrUnavailable
	}
	root, stop := context.WithCancel(ctx)
	return &ConnectorCredentials{root: root, stop: stop, bootstrap: bootstrap, enrollment: enrollment, claims: claims, registry: &app.PeerAuthenticator{Registry: registry, Now: now}, verifier: verifier, now: now, key: key, csr: csr}, nil
}

// Enroll executes one attempt with the original CSR/bootstrap. Unknown replies
// permit only that same request; no new key/claim/expiry or hidden retry is used.
// Once installed, this performs a current registration check without reissuing.
func (c *ConnectorCredentials) Enroll(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return value.ErrInvalid
	}
	c.mu.Lock()
	start := c.now()
	if c.closed || c.root.Err() != nil || c.active != nil {
		c.mu.Unlock()
		return value.ErrUnavailable
	}
	cached := c.cert != nil
	if !cached && (!c.bootstrap.Valid(start) || !c.lastAttempt.IsZero() && start.Before(c.lastAttempt.Add(time.Second))) {
		c.mu.Unlock()
		return value.ErrUnavailable
	}
	deadline := start.Add(30 * time.Second)
	if cached {
		deadline = start.Add(5 * time.Second)
	} else if c.bootstrap.NotAfter.Before(deadline) {
		deadline = c.bootstrap.NotAfter
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	stopped := make(chan struct{})
	stopRoot := context.AfterFunc(c.root, func() { cancel(); close(stopped) })
	done := make(chan struct{})
	c.active, c.cancel = done, cancel
	if !cached {
		c.lastAttempt = start
	}
	csr := bytes.Clone(c.csr)
	identity := c.identity
	bootstrap := c.bootstrap
	c.mu.Unlock()
	defer func() {
		cancel()
		if !stopRoot() {
			<-stopped
		}
		c.mu.Lock()
		c.active, c.cancel = nil, nil
		close(done)
		c.mu.Unlock()
	}()
	if cached {
		observed, err := c.registry.AuthenticatePeer(call, identity)
		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil || c.closed || c.root.Err() != nil || call.Err() != nil || c.now().Before(start) || !c.now().Before(deadline) || !c.now().Before(observed.ValidUntil) {
			return value.ErrUnavailable
		}
		return nil
	}
	key, err := EnrollmentKey(csr)
	if err != nil {
		return err
	}
	claim := value.EnrollmentClaim{InstallationID: bootstrap.Binding.InstallationID, BootstrapID: bootstrap.ID, SecretDigest: bootstrap.SecretDigest, PublicKeyDigest: key}
	issued, err := c.enrollment.Enroll(call, claim, bytes.Clone(csr))
	if err != nil {
		return err
	}
	if call.Err() != nil || c.root.Err() != nil || c.now().Before(start) || !bootstrap.Valid(c.now()) {
		return value.ErrUnavailable
	}
	original, err := c.claims.ReadEnrollmentClaim(call, claim.InstallationID, claim.BootstrapID)
	if err != nil || !original.Valid() || original.BootstrapID != bootstrap.ID || original.Binding != bootstrap.Binding || original.PublicKeyDigest != key || !original.IssuedAt.Equal(bootstrap.NotBefore) || !original.NotAfter.Equal(bootstrap.NotAfter) || original.ClaimedAt.After(c.now()) {
		return value.ErrDenied
	}
	cert, identity, err := c.checkCertificate(issued, key, original.ClaimedAt)
	if err != nil {
		return err
	}
	observed, err := c.registry.AuthenticatePeer(call, identity)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	finish := c.now()
	if c.closed || c.root.Err() != nil || call.Err() != nil || finish.Before(start) || !finish.Before(deadline) || !bootstrap.Valid(finish) || !identity.Valid(finish) || !finish.Before(observed.ValidUntil) {
		return value.ErrUnavailable
	}
	cert.PrivateKey = &connectorCredentialSigner{owner: c, identity: identity, publicDER: bytes.Clone(cert.Leaf.RawSubjectPublicKeyInfo)}
	c.cert, c.identity = cert, identity
	// Positive installation no longer needs the bootstrap credential. Unknown
	// attempts retain it for the exact original retry, never another process.
	c.bootstrap.SecretDigest = artifact.Digest{}
	return nil
}
func (c *ConnectorCredentials) checkCertificate(issued value.IssuedCertificate, key artifact.Digest, claimed time.Time) (*tls.Certificate, value.PeerCertificate, error) {
	var zero value.PeerCertificate
	if len(issued.DER) < 1 || len(issued.DER) > 16<<10 || len(issued.ChainDER) > 3 {
		return nil, zero, value.ErrDenied
	}
	raw := make([][]byte, 1, len(issued.ChainDER)+1)
	raw[0] = bytes.Clone(issued.DER)
	total := len(issued.DER)
	for _, der := range issued.ChainDER {
		total += len(der)
		if len(der) < 1 || len(der) > 16<<10 || total > 32<<10 {
			return nil, zero, value.ErrDenied
		}
		raw = append(raw, bytes.Clone(der))
	}
	chain := make([]*x509.Certificate, len(raw))
	for i, der := range raw {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, zero, value.ErrDenied
		}
		chain[i] = parsed
	}
	checked, err := c.verifier.verifyCertificates(chain)
	if err != nil || checked.Binding != c.bootstrap.Binding || !sameConnectorCertificate(checked, issued.Certificate) || artifact.Digest(sha256.Sum256(chain[0].RawSubjectPublicKeyInfo)) != key || !checked.NotAfter.Equal(claimed.Add(30*time.Minute).UTC().Truncate(time.Second)) || checked.NotBefore.Before(claimed.Add(-time.Minute)) {
		return nil, zero, value.ErrDenied
	}
	return &tls.Certificate{Certificate: raw, Leaf: chain[0]}, checked, nil
}
func sameConnectorCertificate(a, b value.PeerCertificate) bool {
	return a.Binding == b.Binding && a.Digest == b.Digest && a.NotBefore.Equal(b.NotBefore) && a.NotAfter.Equal(b.NotAfter)
}

func (c *ConnectorCredentials) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c == nil || info == nil || info.Version != tls.VersionTLS13 {
		return nil, value.ErrDenied
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || c.cert == nil || !c.identity.Valid(c.now()) {
		return nil, value.ErrUnavailable
	}
	out := *c.cert
	out.Certificate = make([][]byte, len(c.cert.Certificate))
	for i, der := range c.cert.Certificate {
		out.Certificate[i] = bytes.Clone(der)
	}
	out.Leaf, _ = x509.ParseCertificate(out.Certificate[0])
	if info.SupportsCertificate(&out) != nil {
		return nil, value.ErrDenied
	}
	return &out, nil
}
func (c *ConnectorCredentials) Certificate() (value.PeerCertificate, error) {
	if c == nil {
		return value.PeerCertificate{}, value.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || !c.identity.Valid(c.now()) {
		return value.PeerCertificate{}, value.ErrUnavailable
	}
	return c.identity, nil
}

// Close joins the owned attempt, disables retained signers and discards owned
// references. Go does not promise physical heap erasure; sockets belong to the
// runtime and must be closed and joined there as well.
func (c *ConnectorCredentials) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.stop()
	if c.cancel != nil {
		c.cancel()
	}
	done := c.active
	c.key, c.cert = nil, nil
	c.identity = value.PeerCertificate{}
	c.bootstrap.SecretDigest = artifact.Digest{}
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

type connectorCredentialSigner struct {
	owner     *ConnectorCredentials
	identity  value.PeerCertificate
	publicDER []byte
}

func (s *connectorCredentialSigner) Public() crypto.PublicKey {
	key, _ := x509.ParsePKIXPublicKey(bytes.Clone(s.publicDER))
	return key
}
func (s *connectorCredentialSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || c.key == nil || !s.identity.Valid(c.now()) || opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, value.ErrDenied
	}
	signed, err := c.key.Sign(rand.Reader, digest, opts)
	if err != nil || c.closed || c.root.Err() != nil || !s.identity.Valid(c.now()) {
		return nil, value.ErrDenied
	}
	return signed, nil
}
