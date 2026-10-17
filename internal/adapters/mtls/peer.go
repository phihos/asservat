// Package mtls implements the installation peer certificate profile with the
// Go TLS/x509 stack. It does not issue certificates or accept proxy headers.
package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// PeerURI is an installation-specific SPIFFE ID profile, not a requirement for
// SPIRE or a claim of Workload API conformance. No display names enter identity.
func PeerURI(p value.PeerBinding) (*url.URL, error) {
	if !p.Valid() {
		return nil, value.ErrInvalid
	}
	s := "spiffe://asservat." + p.InstallationID + "/cluster/" + p.ClusterID + "/epoch/" + p.IssuerEpoch + "/" + string(p.Role) + "/" + p.PeerID
	if p.Role == value.NodePeer {
		s += "/uid/" + p.NodeUID + "/boot/" + p.NodeBootID + "/collector/" + p.CollectorEpoch
	}
	return url.Parse(s)
}
func parsePeerURI(u *url.URL, installation string, role value.PeerRole) (value.PeerBinding, error) {
	var p value.PeerBinding
	if u == nil || u.Scheme != "spiffe" || u.Host != "asservat."+installation || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return p, value.ErrDenied
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 7 && len(parts) != 13 {
		return p, value.ErrDenied
	}
	if parts[0] != "" || parts[1] != "cluster" || parts[3] != "epoch" || parts[5] != string(role) {
		return p, value.ErrDenied
	}
	p = value.PeerBinding{InstallationID: installation, ClusterID: parts[2], IssuerEpoch: parts[4], PeerID: parts[6], Role: role}
	if role == value.NodePeer {
		if len(parts) != 13 || parts[7] != "uid" || parts[9] != "boot" || parts[11] != "collector" {
			return value.PeerBinding{}, value.ErrDenied
		}
		p.NodeUID, p.NodeBootID, p.CollectorEpoch = parts[8], parts[10], parts[12]
	} else if len(parts) != 7 {
		return value.PeerBinding{}, value.ErrDenied
	}
	if !p.Valid() {
		return value.PeerBinding{}, value.ErrDenied
	}
	canonical, _ := PeerURI(p)
	if canonical.String() != u.String() {
		return value.PeerBinding{}, value.ErrDenied
	}
	return p, nil
}

type PeerVerifier struct {
	roots        *x509.CertPool
	installation string
	role         value.PeerRole
	now          func() time.Time
}

func NewPeerVerifier(roots *x509.CertPool, installation string, role value.PeerRole, now func() time.Time) (*PeerVerifier, error) {
	if roots == nil || len(roots.Subjects()) == 0 || !authorization.UUID(installation) || (role != value.ConnectorPeer && role != value.NodePeer) || now == nil {
		return nil, value.ErrInvalid
	}
	return &PeerVerifier{roots: roots.Clone(), installation: installation, role: role, now: now}, nil
}

// Verify accepts only the actual server-side TLS state. TLS must have verified
// the client chain; a second current-time verification also bounds long-lived
// connections and prevents stale trust from being inferred from that handshake.
func (v *PeerVerifier) Verify(s *tls.ConnectionState) (value.PeerCertificate, error) {
	var out value.PeerCertificate
	if v == nil || v.roots == nil || v.now == nil {
		return out, value.ErrUnavailable
	}
	if s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || len(s.PeerCertificates) < 1 || len(s.PeerCertificates) > 4 || len(s.VerifiedChains) == 0 {
		return out, value.ErrDenied
	}
	leaf := s.PeerCertificates[0]
	if leaf == nil {
		return out, value.ErrDenied
	}
	verifiedLeaf := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) {
			verifiedLeaf = true
		}
	}
	if !verifiedLeaf {
		return out, value.ErrDenied
	}
	return v.verifyCertificates(s.PeerCertificates)
}

func (v *PeerVerifier) verifyCertificates(certificates []*x509.Certificate) (value.PeerCertificate, error) {
	var out value.PeerCertificate
	if v == nil || v.roots == nil || v.now == nil || len(certificates) < 1 || len(certificates) > 4 {
		return out, value.ErrInvalid
	}
	leaf := certificates[0]
	if leaf == nil || len(leaf.Raw) > 16<<10 || leaf.IsCA || !leaf.BasicConstraintsValid || len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || leaf.Subject.CommonName != "" || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return out, value.ErrDenied
	}
	intermediates := x509.NewCertPool()
	for _, c := range certificates[1:] {
		if c == nil || len(c.Raw) > 16<<10 {
			return out, value.ErrDenied
		}
		intermediates.AddCert(c)
	}
	now := v.now()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return out, value.ErrDenied
	}
	p, err := parsePeerURI(leaf.URIs[0], v.installation, v.role)
	if err != nil {
		return out, err
	}
	out = value.PeerCertificate{Binding: p, Digest: artifact.Digest(sha256.Sum256(leaf.Raw)), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}
	if !out.Valid(v.now()) {
		return value.PeerCertificate{}, value.ErrDenied
	}
	return out, nil
}

// CheckIssued verifies the signing result without pretending a TLS handshake
// occurred. It grants no peer authority; registration remains a separate gate.
func (v *PeerVerifier) CheckIssued(permit value.CertificateIssuePermit, der []byte, chainDER [][]byte) (value.IssuedCertificate, error) {
	var out value.IssuedCertificate
	if v == nil || v.now == nil || !permit.Valid(v.now()) || len(der) == 0 || len(der) > 16<<10 || len(chainDER) > 3 {
		return out, value.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return out, value.ErrDenied
	}
	certificates := []*x509.Certificate{leaf}
	total := len(der)
	for _, b := range chainDER {
		total += len(b)
		if len(b) == 0 || len(b) > 16<<10 || total > 32<<10 {
			return out, value.ErrInvalid
		}
		c, e := x509.ParseCertificate(b)
		if e != nil {
			return out, value.ErrDenied
		}
		certificates = append(certificates, c)
	}
	peer, err := v.verifyCertificates(certificates)
	if err != nil || peer.Binding != permit.Enrollment.Binding || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != permit.Enrollment.PublicKeyDigest || !peer.NotAfter.Equal(permit.CertificateNotAfter()) || peer.NotBefore.Before(permit.Enrollment.ClaimedAt.Add(-time.Minute)) {
		return out, value.ErrDenied
	}
	if !permit.Valid(v.now()) {
		return out, value.ErrDenied
	}
	out = value.IssuedCertificate{Certificate: peer, DER: bytes.Clone(der)}
	for _, b := range chainDER {
		out.ChainDER = append(out.ChainDER, bytes.Clone(b))
	}
	return out, nil
}
