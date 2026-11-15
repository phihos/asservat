package mtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type KeyPeerVerifier struct {
	roots        *x509.CertPool
	installation string
	now          func() time.Time
}

func NewKeyPeerVerifier(roots *x509.CertPool, installation string, now func() time.Time) (*KeyPeerVerifier, error) {
	if roots == nil || len(roots.Subjects()) == 0 || !value.UUID(installation) || now == nil {
		return nil, app.ErrKeyDenied
	}
	return &KeyPeerVerifier{roots.Clone(), installation, now}, nil
}

func (v *KeyPeerVerifier) Verify(s *tls.ConnectionState) (value.KeyPeer, error) {
	var out value.KeyPeer
	if v == nil || v.roots == nil || v.now == nil || s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || len(s.PeerCertificates) < 1 || len(s.PeerCertificates) > 4 || len(s.VerifiedChains) == 0 {
		return out, app.ErrKeyDenied
	}
	leaf := s.PeerCertificates[0]
	if leaf == nil {
		return out, app.ErrKeyDenied
	}
	matched := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) {
			matched = true
		}
	}
	if !matched {
		return out, app.ErrKeyDenied
	}
	return v.verifyCertificates(s.PeerCertificates)
}

func (v *KeyPeerVerifier) verifyCertificates(certs []*x509.Certificate) (value.KeyPeer, error) {
	var out value.KeyPeer
	if v == nil || v.roots == nil || v.now == nil || len(certs) < 1 || len(certs) > 4 {
		return out, app.ErrKeyDenied
	}
	leaf := certs[0]
	if leaf == nil || len(leaf.Raw) > 16<<10 || leaf.IsCA || !leaf.BasicConstraintsValid || len(leaf.Subject.Names) != 0 || len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return out, app.ErrKeyDenied
	}
	u := leaf.URIs[0]
	if u == nil || u.Scheme != "spiffe" || u.Host != "asservat."+v.installation || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return out, app.ErrKeyDenied
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "key-client" {
		return out, app.ErrKeyDenied
	}
	out = value.KeyPeer{InstallationID: v.installation, Role: parts[2], PeerID: parts[3], Certificate: artifact.Digest(sha256.Sum256(leaf.Raw)), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}
	want := (&url.URL{Scheme: "spiffe", Host: "asservat." + v.installation, Path: "/key-client/" + out.Role + "/" + out.PeerID}).String()
	if u.String() != want || !out.Valid(v.now()) {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		if c == nil || len(c.Raw) > 16<<10 {
			return value.KeyPeer{}, app.ErrKeyDenied
		}
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: intermediates, CurrentTime: v.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	// A cached connection must not keep using an operation lease beyond its
	// verified chain's lifetime. Conservatively intersect alternative chains.
	for _, chain := range chains {
		for _, cert := range chain {
			if cert.NotAfter.Before(out.NotAfter) {
				out.NotAfter = cert.NotAfter.UTC()
			}
		}
	}
	return out, nil
}

// ConnectorTokenVerifier attributes a connector's ServiceAccount token to its
// registered cluster (ADR-334) and returns the token's expiry.
type ConnectorTokenVerifier interface {
	VerifyConnectorUntil(context.Context, string) (fleetvalue.ConnectorCluster, time.Time, error)
}

// connectorKeyPeer maps a connector's verified token to the artifact key
// service's collector role (ADR-176). Certificate names the presenting
// cluster, so the wrap ledger binds an attempt's roles to one cluster;
// ContextKeyWraps checks that cluster against the prepared execution.
func connectorKeyPeer(cluster fleetvalue.ConnectorCluster, installation string, until, now time.Time) (value.KeyPeer, error) {
	if cluster.InstallationID != installation {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	out := value.KeyPeer{InstallationID: installation, PeerID: cluster.PeerID, ClusterID: cluster.ClusterID, Role: "collector", Certificate: artifact.Digest(sha256.Sum256([]byte("asservat-connector/" + cluster.ClusterID))), NotBefore: now.UTC(), NotAfter: identity.Earlier(until, now.Add(time.Hour)).UTC()}
	if !out.Valid(now) {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	return out, nil
}

// KeyPeerUnion accepts key-client leaves and, when configured, connector
// ServiceAccount tokens (ADR-334). A bearer token selects the connector
// verifier; there is no fallback from one to the other.
type KeyPeerUnion struct {
	KeyClients *KeyPeerVerifier
	Connectors ConnectorTokenVerifier
	Now        func() time.Time
}

// Verify serves callers without a request.
func (u KeyPeerUnion) Verify(s *tls.ConnectionState) (value.KeyPeer, error) {
	if u.KeyClients == nil {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	return u.KeyClients.Verify(s)
}

func (u KeyPeerUnion) VerifyRequest(ctx context.Context, r *http.Request) (value.KeyPeer, error) {
	if r == nil || u.KeyClients == nil {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return u.KeyClients.Verify(r.TLS)
	}
	token, ok := strings.CutPrefix(values[0], "Bearer ")
	if u.Connectors == nil || u.Now == nil || len(values) != 1 || !ok || token == "" || r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	cluster, until, err := u.Connectors.VerifyConnectorUntil(ctx, token)
	if err != nil {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	return connectorKeyPeer(cluster, u.KeyClients.installation, until, u.Now())
}
