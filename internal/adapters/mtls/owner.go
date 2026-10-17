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

func OwnerURI(b value.OwnerBinding) (*url.URL, error) {
	if !b.Valid() {
		return nil, value.ErrInvalid
	}
	return url.Parse("spiffe://asservat." + b.InstallationID + "/hub/" + b.ClusterID + "/issuer/" + b.IssuerEpoch + "/pod/" + b.PodUID + "/process/" + b.ProcessEpoch)
}

// The DNS SAN is a deterministic TLS verification name, not a lookup address.
// Dial only the independently observed Pod IP; never resolve this as a callback.
func OwnerServerName(b value.OwnerBinding) (string, error) {
	if !b.Valid() {
		return "", value.ErrInvalid
	}
	return "p-" + b.PodUID + ".e-" + b.ProcessEpoch + ".hub." + b.ClusterID + ".asservat." + b.InstallationID, nil
}

type OwnerPeerVerifier struct {
	roots                        *x509.CertPool
	installation, cluster, epoch string
	now                          func() time.Time
	bootstrapPool                value.OwnerPool
}

func NewOwnerPeerVerifier(roots *x509.CertPool, installation, cluster, epoch string, now func() time.Time) (*OwnerPeerVerifier, error) {
	if roots == nil || len(roots.Subjects()) == 0 || !authorization.UUID(installation) || !authorization.UUID(cluster) || !authorization.UUID(epoch) || now == nil {
		return nil, value.ErrInvalid
	}
	return &OwnerPeerVerifier{roots: roots.Clone(), installation: installation, cluster: cluster, epoch: epoch, now: now}, nil
}

func (v *OwnerPeerVerifier) VerifyServer(s *tls.ConnectionState, expected value.OwnerBinding) (value.OwnerCertificate, error) {
	name, err := OwnerServerName(expected)
	if err != nil || s == nil || s.ServerName != name {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	cert, err := v.verify(s, "server")
	if err != nil || cert.Binding != expected {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return cert, nil
}
func (v *OwnerPeerVerifier) VerifyClient(s *tls.ConnectionState) (value.OwnerCertificate, error) {
	return v.verify(s, "client")
}

// Actual TLS verification and current X.509 revalidation precede URI parsing
// results. A valid owner leaf still needs current Pod/pool, locator and human
// authority. Issuance/activation is not supplied by this verifier.
func (v *OwnerPeerVerifier) verify(s *tls.ConnectionState, usage string) (value.OwnerCertificate, error) {
	var out value.OwnerCertificate
	if v == nil || v.roots == nil || v.now == nil || s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || len(s.PeerCertificates) < 1 || len(s.PeerCertificates) > 4 || len(s.VerifiedChains) == 0 {
		return out, value.ErrDenied
	}
	leaf := s.PeerCertificates[0]
	if leaf == nil {
		return out, value.ErrDenied
	}
	verified := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) {
			verified = true
		}
	}
	if !verified {
		return out, value.ErrDenied
	}
	return v.verifyCertificates(s.PeerCertificates, usage)
}

// Shared strict leaf/chain verification for issuance and actual handshakes.
// Issuance never fabricates a successful TLS ConnectionState.
func (v *OwnerPeerVerifier) verifyCertificates(certs []*x509.Certificate, usage string) (value.OwnerCertificate, error) {
	var out value.OwnerCertificate
	if v == nil || v.roots == nil || v.now == nil || len(certs) < 1 || len(certs) > 4 {
		return out, value.ErrDenied
	}
	leaf := certs[0]
	if leaf == nil || leaf.IsCA || !leaf.BasicConstraintsValid || len(leaf.Subject.Names) != 0 || len(leaf.URIs) != 1 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || len(leaf.UnknownExtKeyUsage) != 0 {
		return out, value.ErrDenied
	}
	u := leaf.URIs[0]
	if u == nil || u.Scheme != "spiffe" || u.Host != "asservat."+v.installation || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return out, value.ErrDenied
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 9 || parts[0] != "" || parts[1] != "hub" || parts[3] != "issuer" || parts[5] != "pod" || parts[7] != "process" || parts[2] != v.cluster || parts[4] != v.epoch {
		return out, value.ErrDenied
	}
	b := value.OwnerBinding{InstallationID: v.installation, ClusterID: parts[2], IssuerEpoch: parts[4], PodUID: parts[6], ProcessEpoch: parts[8]}
	canonical, err := OwnerURI(b)
	if err != nil || canonical.String() != u.String() {
		return out, value.ErrDenied
	}
	ext := x509.ExtKeyUsageClientAuth
	dns := ""
	if usage == "server" {
		ext = x509.ExtKeyUsageServerAuth
		dns, _ = OwnerServerName(b)
		if !v.serverNames(leaf.DNSNames, dns) {
			return out, value.ErrDenied
		}
	} else if usage != "client" || len(leaf.DNSNames) != 0 {
		return out, value.ErrDenied
	}
	if leaf.ExtKeyUsage[0] != ext {
		return out, value.ErrDenied
	}
	intermediates := x509.NewCertPool()
	total := 0
	for i, cert := range certs {
		if cert == nil || len(cert.Raw) < 1 || len(cert.Raw) > 16<<10 {
			return out, value.ErrDenied
		}
		total += len(cert.Raw)
		if i > 0 {
			intermediates.AddCert(cert)
		}
	}
	if total > 32<<10 {
		return out, value.ErrDenied
	}
	out = value.OwnerCertificate{Binding: b, Usage: usage, Digest: artifact.Digest(sha256.Sum256(leaf.Raw)), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}
	if !out.Valid(v.now()) {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: intermediates, CurrentTime: v.now(), DNSName: dns, KeyUsages: []x509.ExtKeyUsage{ext}})
	if err != nil || len(chains) == 0 {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	for _, chain := range chains {
		for _, cert := range chain {
			if cert.NotAfter.Before(out.NotAfter) {
				out.NotAfter = cert.NotAfter.UTC()
			}
		}
	}
	if !out.Valid(v.now()) {
		return value.OwnerCertificate{}, value.ErrDenied
	}
	return out, nil
}
