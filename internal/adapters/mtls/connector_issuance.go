package mtls

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// Independent pinned roots and the accepted current profile must both validate
// every result. This component never signs, activates or fabricates a handshake.
type ConnectorCredentialVerifier struct {
	profile                  value.ConnectorCredentialProfile
	clientRoots, serverRoots *x509.CertPool
	now                      func() time.Time
}

func NewConnectorCredentialVerifier(p value.ConnectorCredentialProfile, now func() time.Time) (*ConnectorCredentialVerifier, error) {
	if !p.Valid() || p.Suspended || now == nil {
		return nil, value.ErrInvalid
	}
	client, _, e := OwnerTrustRoots(p.ClientIssuerRoots, now())
	if e != nil {
		return nil, e
	}
	server, _, e := OwnerTrustRoots(p.ServerIssuerRoots, now())
	if e != nil {
		return nil, e
	}
	return &ConnectorCredentialVerifier{p.Clone(), client, server, now}, nil
}

// CheckConnectorPermit is the pre-provider purpose/source pin check. It grants
// no spend or activation and is repeated by result verification after I/O.
func (v *ConnectorCredentialVerifier) CheckConnectorPermit(p value.ConnectorCredentialPermit) error {
	if v == nil || v.now == nil || !p.Valid(v.now()) || p.Configuration.Profile.RootID != v.profile.RootID || p.Configuration.Profile.Binding != v.profile.Binding || p.Configuration.Profile.Revision.UID != v.profile.Revision.UID || p.Configuration.Profile.ServerName != v.profile.ServerName {
		return value.ErrDenied
	}
	return nil
}
func (v *ConnectorCredentialVerifier) CheckConnectorCredential(p value.ConnectorCredentialPermit, csr, der []byte, chain [][]byte) (value.IssuedConnectorCredential, error) {
	if v.CheckConnectorPermit(p) != nil {
		return value.IssuedConnectorCredential{}, value.ErrDenied
	}
	return v.CheckConnectorCredentialCurrent(p, csr, der, chain, p.Configuration)
}

// This may verify a positively stored result after SignBefore, but never makes
// another provider call or renews that signing permit. Current admission/audit
// and activated registry checks remain mandatory before certificate delivery.
func (v *ConnectorCredentialVerifier) CheckConnectorCredentialCurrent(p value.ConnectorCredentialPermit, csr, der []byte, chain [][]byte, current value.ConnectorCredentialObservation) (value.IssuedConnectorCredential, error) {
	var zero value.IssuedConnectorCredential
	if v == nil || v.now == nil || !p.WellFormed() || !current.Valid(v.now()) || current.Profile.RootID != v.profile.RootID || current.Profile.Binding != v.profile.Binding || current.Profile.ServerName != v.profile.ServerName || current.Profile.Revision.UID != v.profile.Revision.UID || p.Configuration.Profile.RootID != current.Profile.RootID || p.Configuration.Profile.Binding != current.Profile.Binding || p.Configuration.Profile.Revision.UID != current.Profile.Revision.UID || p.Configuration.Profile.ServerName != current.Profile.ServerName || len(der) < 1 || len(der) > 16<<10 || len(chain) > 3 {
		return zero, value.ErrDenied
	}
	key, e := EnrollmentKey(csr)
	if e != nil || key != p.PublicKeyDigest() {
		return zero, value.ErrDenied
	}
	leaf, e := x509.ParseCertificate(bytes.Clone(der))
	if e != nil || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != key {
		return zero, value.ErrDenied
	}
	certs := []*x509.Certificate{leaf}
	total := len(der)
	for _, raw := range chain {
		total += len(raw)
		if len(raw) < 1 || len(raw) > 16<<10 || total > 32<<10 {
			return zero, value.ErrInvalid
		}
		c, e := x509.ParseCertificate(bytes.Clone(raw))
		if e != nil {
			return zero, value.ErrInvalid
		}
		certs = append(certs, c)
	}
	roots := current.Profile.ClientIssuerRoots
	if p.Usage == "server" {
		roots = current.Profile.ServerIssuerRoots
	}
	currentRoots, _, e := OwnerTrustRoots(roots, v.now())
	if e != nil {
		return zero, e
	}
	c, e := v.verify(certs, p.Usage, currentRoots)
	if e != nil {
		return zero, e
	}
	out := value.IssuedConnectorCredential{Certificate: c, DER: der, ChainDER: chain}
	if !p.Matches(out) || !current.Valid(v.now()) {
		return zero, value.ErrDenied
	}
	return out.Clone(), nil
}

// VerifyConnectorServer accepts an actual completed client-side TLS handshake.
// It never converts its serverAuth leaf into a client PeerCertificate.
func (v *ConnectorCredentialVerifier) VerifyConnectorServer(s *tls.ConnectionState, current value.ConnectorCredentialObservation) (value.ConnectorCredentialCertificate, error) {
	var zero value.ConnectorCredentialCertificate
	if v == nil || v.now == nil || s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) < 1 || len(s.PeerCertificates) > 4 || s.PeerCertificates[0] == nil || !current.Valid(v.now()) || current.Profile.RootID != v.profile.RootID || current.Profile.Binding != v.profile.Binding || current.Profile.ServerName != v.profile.ServerName || current.Profile.Revision.UID != v.profile.Revision.UID {
		return zero, value.ErrDenied
	}
	found := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, s.PeerCertificates[0].Raw) {
			found = true
		}
	}
	if !found {
		return zero, value.ErrDenied
	}
	roots, _, e := OwnerTrustRoots(current.Profile.ServerIssuerRoots, v.now())
	if e != nil {
		return zero, e
	}
	c, e := v.verify(s.PeerCertificates, "server", roots)
	if e != nil || !current.Valid(v.now()) {
		return zero, value.ErrDenied
	}
	return c, nil
}
func (v *ConnectorCredentialVerifier) verify(certs []*x509.Certificate, usage string, currentRoots *x509.CertPool) (value.ConnectorCredentialCertificate, error) {
	var zero value.ConnectorCredentialCertificate
	if len(certs) < 1 || len(certs) > 4 || currentRoots == nil {
		return zero, value.ErrDenied
	}
	leaf := certs[0]
	if leaf == nil || len(leaf.Raw) > 16<<10 || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.Subject.CommonName != "" || len(leaf.URIs) != 1 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || len(leaf.UnknownExtKeyUsage) != 0 {
		return zero, value.ErrDenied
	}
	eku := x509.ExtKeyUsageClientAuth
	roots := v.clientRoots
	name := ""
	if usage == "server" {
		eku = x509.ExtKeyUsageServerAuth
		roots = v.serverRoots
		name = v.profile.ServerName
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name {
			return zero, value.ErrDenied
		}
	} else if usage != "client" || len(leaf.DNSNames) != 0 {
		return zero, value.ErrDenied
	}
	if leaf.ExtKeyUsage[0] != eku {
		return zero, value.ErrDenied
	}
	b, e := parsePeerURI(leaf.URIs[0], v.profile.Binding.InstallationID, value.ConnectorPeer)
	if e != nil || b != v.profile.Binding {
		return zero, value.ErrDenied
	}
	ints := x509.NewCertPool()
	total := len(leaf.Raw)
	for _, c := range certs[1:] {
		if c == nil || len(c.Raw) < 1 || len(c.Raw) > 16<<10 {
			return zero, value.ErrDenied
		}
		total += len(c.Raw)
		if total > 32<<10 {
			return zero, value.ErrDenied
		}
		ints.AddCert(c)
	}
	n := v.now()
	opts := x509.VerifyOptions{Roots: roots, Intermediates: ints, CurrentTime: n, KeyUsages: []x509.ExtKeyUsage{eku}, DNSName: name}
	if _, e = leaf.Verify(opts); e != nil {
		return zero, value.ErrDenied
	}
	opts.Roots = currentRoots
	if _, e = leaf.Verify(opts); e != nil {
		return zero, value.ErrDenied
	}
	out := value.ConnectorCredentialCertificate{Binding: b, Usage: usage, ServerName: name, Digest: artifact.Digest(sha256.Sum256(leaf.Raw)), PublicKeyDigest: artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}
	if !out.Valid(v.now()) {
		return zero, value.ErrDenied
	}
	return out, nil
}
