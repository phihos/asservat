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
	"net/url"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/google/uuid"
)

// VerifierCertificatePeriod is the verifier PKI role's fixed TTL (ADR-203).
// The credential renews at half of a leaf's actual validity.
const VerifierCertificatePeriod = 20 * time.Minute

// verifierRetry spaces failed signing attempts; a success is passive until
// its own renewal point.
const verifierRetry = 5 * time.Second

// VerifierSigner signs one identity-free CSR for exactly the given
// key-client/verifier URI and returns the provider's leaf and chain DER. It
// confers nothing: the credential verifies the chain against its own roots.
type VerifierSigner interface {
	SignVerifierCertificate(ctx context.Context, csr []byte, uri string) ([]byte, [][]byte, error)
}

// VerifierCredentials owns the publisher's in-process verifier key-client
// identity (ADR-203): one P-256 key and one fresh peer ID per process, never
// written out. A verifier leaf carries no authority of its own; every unwrap
// still needs the key service's per-attempt SQL grant (ADR-181).
type VerifierCredentials struct {
	mu          sync.Mutex
	uri, peerID string
	signer      VerifierSigner
	verifier    *KeyPeerVerifier
	now         func() time.Time
	key         *ecdsa.PrivateKey
	csr         []byte
	cert        *tls.Certificate
	peer        value.KeyPeer
	renewAt     time.Time
	lastAttempt time.Time
	busy        bool
	closed      bool
	cancel      context.CancelFunc
}

// NewVerifierCredentials creates the process key and its identity-free CSR.
// issuerRoots are the worker PKI issuer only; there is no system-CA,
// filesystem-key or provider fallback.
func NewVerifierCredentials(installation string, signer VerifierSigner, issuerRoots *x509.CertPool, now func() time.Time) (*VerifierCredentials, error) {
	if !value.UUID(installation) || signer == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	verifier, err := NewKeyPeerVerifier(issuerRoots, installation, now)
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	peerID := uuid.NewString()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	if _, err = EnrollmentKey(csr); err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &VerifierCredentials{uri: VerifierCertificateURI(installation, peerID), peerID: peerID, signer: signer, verifier: verifier, now: now, key: key, csr: csr}, nil
}

// VerifierCertificateURI is the only URI a verifier leaf may carry.
func VerifierCertificateURI(installation, peerID string) string {
	return (&url.URL{Scheme: "spiffe", Host: "asservat." + installation, Path: "/key-client/verifier/" + peerID}).String()
}

// Renew signs a leaf when none is installed or the installed one has passed
// half its validity. One attempt runs at a time and a failure waits before
// the next; a request ends within thirty seconds.
func (v *VerifierCredentials) Renew(ctx context.Context) error {
	if v == nil || v.now == nil || ctx == nil || ctx.Err() != nil {
		return artifact.ErrInvalid
	}
	v.mu.Lock()
	start := v.now()
	if v.closed || v.busy {
		v.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	if v.cert != nil && v.peer.Valid(start) && start.Before(v.renewAt) {
		v.mu.Unlock()
		return nil
	}
	if !v.lastAttempt.IsZero() && start.Before(v.lastAttempt.Add(verifierRetry)) {
		v.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	deadline := start.Add(30 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	v.busy, v.lastAttempt, v.cancel = true, start, cancel
	csr := bytes.Clone(v.csr)
	v.mu.Unlock()
	defer func() { cancel(); v.mu.Lock(); v.busy, v.cancel = false, nil; v.mu.Unlock() }()
	der, chain, err := v.signer.SignVerifierCertificate(ctx, csr, v.uri)
	if err != nil || ctx.Err() != nil {
		return artifact.ErrDownloadUnavailable
	}
	cert, peer, err := checkVerifierCertificate(v.verifier, v.peerID, v.now, start, csr, der, chain)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if v.closed || v.key == nil || ctx.Err() != nil || !now.Before(deadline) || !peer.Valid(now) {
		return artifact.ErrDownloadExpired
	}
	cert.PrivateKey = &verifierCredentialSigner{owner: v, peer: peer, public: cert.Leaf.PublicKey}
	v.cert, v.peer = cert, peer
	v.renewAt = cert.Leaf.NotBefore.Add(cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) / 2)
	return nil
}

// checkVerifierCertificate applies the strict CSR/X.509 key-client checks to
// an actual provider reply: same public key, exactly this process's verifier
// URI, a chain to the pinned issuer and at most the role's period from now.
func checkVerifierCertificate(verifier *KeyPeerVerifier, peerID string, now func() time.Time, start time.Time, csr, der []byte, chain [][]byte) (*tls.Certificate, value.KeyPeer, error) {
	var zero value.KeyPeer
	if len(der) < 1 || len(der) > 16<<10 || len(chain) > 3 {
		return nil, zero, artifact.ErrIntegrity
	}
	key, err := EnrollmentKey(csr)
	if err != nil {
		return nil, zero, artifact.ErrIntegrity
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != key {
		return nil, zero, artifact.ErrIntegrity
	}
	certs := []*x509.Certificate{leaf}
	raw := [][]byte{bytes.Clone(der)}
	total := len(der)
	for _, der := range chain {
		if len(der) < 1 || len(der) > 16<<10 {
			return nil, zero, artifact.ErrIntegrity
		}
		if total += len(der); total > 32<<10 {
			return nil, zero, artifact.ErrIntegrity
		}
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, zero, artifact.ErrIntegrity
		}
		certs = append(certs, c)
		raw = append(raw, bytes.Clone(der))
	}
	peer, err := verifier.verifyCertificates(certs)
	current := now()
	if err != nil || peer.Role != "verifier" || peer.PeerID != peerID || !peer.NotAfter.Equal(leaf.NotAfter) || current.Before(start) ||
		leaf.NotBefore.Before(start.Add(-2*time.Minute)) || leaf.NotAfter.Sub(leaf.NotBefore) > VerifierCertificatePeriod+time.Minute || leaf.NotAfter.After(current.Add(VerifierCertificatePeriod+time.Minute)) {
		return nil, zero, artifact.ErrIntegrity
	}
	return &tls.Certificate{Certificate: raw, Leaf: leaf}, peer, nil
}

// Run renews once a second until ctx ends or Close. A failed renewal keeps the
// installed leaf only until its own expiry; nothing extends it.
func (v *VerifierCredentials) Run(ctx context.Context) error {
	if v == nil || ctx == nil {
		return artifact.ErrInvalid
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if v.isClosed() {
			return artifact.ErrDownloadUnavailable
		}
		_ = v.Renew(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (v *VerifierCredentials) isClosed() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.closed
}

// GetClientCertificate implements tls.Config's callback for the key service
// only (TLS 1.3). A snapshot stays usable only through its own expiry.
func (v *VerifierCredentials) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if v == nil || v.now == nil || info == nil || info.Version != tls.VersionTLS13 {
		return nil, artifact.ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.cert == nil || !v.peer.Valid(v.now()) {
		return nil, artifact.ErrDownloadExpired
	}
	out := *v.cert
	out.Certificate = make([][]byte, len(v.cert.Certificate))
	for i, der := range v.cert.Certificate {
		out.Certificate[i] = bytes.Clone(der)
	}
	// Reparse so callers cannot mutate the installed leaf through a snapshot.
	out.Leaf, _ = x509.ParseCertificate(out.Certificate[0])
	if info.SupportsCertificate(&out) != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &out, nil
}

// Peer is the installed leaf's key-client identity; it is no permit.
func (v *VerifierCredentials) Peer() (value.KeyPeer, error) {
	if v == nil || v.now == nil {
		return value.KeyPeer{}, artifact.ErrInvalid
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || !v.peer.Valid(v.now()) {
		return value.KeyPeer{}, artifact.ErrDownloadExpired
	}
	return v.peer, nil
}

// Close cancels a signing request and disables every retained signer
// snapshot. Go does not guarantee heap zeroization; the key is never written.
func (v *VerifierCredentials) Close() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	if v.cancel != nil {
		v.cancel()
	}
	v.key, v.cert = nil, nil
	v.peer = value.KeyPeer{}
}

type verifierCredentialSigner struct {
	owner  *VerifierCredentials
	peer   value.KeyPeer
	public crypto.PublicKey
}

func (s *verifierCredentialSigner) Public() crypto.PublicKey { return s.public }
func (s *verifierCredentialSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	v := s.owner
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.key == nil || !s.peer.Valid(v.now()) || opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, artifact.ErrDownloadExpired
	}
	return v.key.Sign(random, digest, opts)
}
