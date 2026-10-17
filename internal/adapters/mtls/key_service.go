package mtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
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

// ConnectorKeyPeerVerifier maps a connector's client leaf to the artifact
// key service's collector role (ADR-176). The leaf names its peer, whose
// staged profile is read per request (ADR-198), so a joined region needs no
// key-service change. The verified chain only identifies the leaf;
// ContextKeyWraps checks its activation, process and attempt in SQL.
type ConnectorKeyPeerVerifier struct {
	installation, root string
	read               func(context.Context, fleetvalue.ClusterCredentialProfile) (fleetvalue.ConnectorCredentialProfile, error)
	now                func() time.Time
	mu                 sync.Mutex
	peers              map[fleetvalue.ClusterCredentialProfile]connectorKeyPeer
}

type connectorKeyPeer struct {
	staged   []byte
	verifier *ConnectorCredentialVerifier
	roots    *x509.CertPool
}

// connectorKeyPeerLimit bounds the cached profiles, as the former pin list did.
const connectorKeyPeerLimit = 16

func NewConnectorKeyPeerVerifier(installation, root string, read func(context.Context, fleetvalue.ClusterCredentialProfile) (fleetvalue.ConnectorCredentialProfile, error), now func() time.Time) (*ConnectorKeyPeerVerifier, error) {
	if !value.UUID(installation) || !value.UUID(root) || read == nil || now == nil {
		return nil, app.ErrKeyDenied
	}
	return &ConnectorKeyPeerVerifier{installation: installation, root: root, read: read, now: now, peers: map[fleetvalue.ClusterCredentialProfile]connectorKeyPeer{}}, nil
}

func (v *ConnectorKeyPeerVerifier) verify(ctx context.Context, certs []*x509.Certificate) (value.KeyPeer, error) {
	if v == nil || ctx == nil || len(certs) < 1 || certs[0] == nil || len(certs[0].URIs) != 1 {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	b, err := parsePeerURI(certs[0].URIs[0], v.installation, fleetvalue.ConnectorPeer)
	if err != nil {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	key := fleetvalue.ClusterCredentialProfile{RootID: v.root, PeerID: b.PeerID, InstallationID: v.installation, ClusterID: b.ClusterID}
	profile, err := v.read(ctx, key)
	if err != nil || ctx.Err() != nil || profile.RootID != v.root || profile.Binding != b || profile.Suspended {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	p, err := v.peer(key, profile)
	if err != nil {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	leaf, err := p.verifier.verify(certs, "client", p.roots)
	if err != nil || leaf.Binding != b {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	out := value.KeyPeer{InstallationID: v.installation, PeerID: leaf.Binding.PeerID, Role: "collector", Certificate: leaf.Digest, NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC()}
	if !out.Valid(v.now()) {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	return out, nil
}

// peer reuses the verifier of an unchanged staged profile; a restaged profile
// replaces it.
func (v *ConnectorKeyPeerVerifier) peer(key fleetvalue.ClusterCredentialProfile, profile fleetvalue.ConnectorCredentialProfile) (connectorKeyPeer, error) {
	staged, err := json.Marshal(profile)
	if err != nil {
		return connectorKeyPeer{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.peers[key]; ok && bytes.Equal(p.staged, staged) {
		return p, nil
	} else if !ok && len(v.peers) >= connectorKeyPeerLimit {
		return connectorKeyPeer{}, app.ErrKeyDenied
	}
	verifier, err := NewConnectorCredentialVerifier(profile, v.now)
	if err != nil {
		return connectorKeyPeer{}, err
	}
	roots, _, err := OwnerTrustRoots(profile.ClientIssuerRoots, v.now())
	if err != nil {
		return connectorKeyPeer{}, err
	}
	p := connectorKeyPeer{staged: staged, verifier: verifier, roots: roots}
	v.peers[key] = p
	return p, nil
}

// KeyPeerUnion accepts key-client leaves and, when configured, connector client
// leaves (ADR-176). The URI form selects exactly one verifier; there is no
// fallback from one to the other.
type KeyPeerUnion struct {
	KeyClients *KeyPeerVerifier
	Connectors *ConnectorKeyPeerVerifier
}

// Verify serves callers without a request; the key handler passes its
// request context through VerifyContext.
func (u KeyPeerUnion) Verify(s *tls.ConnectionState) (value.KeyPeer, error) {
	return u.VerifyContext(context.Background(), s)
}

func (u KeyPeerUnion) VerifyContext(ctx context.Context, s *tls.ConnectionState) (value.KeyPeer, error) {
	if u.KeyClients == nil || s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || len(s.PeerCertificates) < 1 || len(s.PeerCertificates) > 4 || s.PeerCertificates[0] == nil || len(s.VerifiedChains) == 0 {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	leaf := s.PeerCertificates[0]
	if len(leaf.URIs) == 1 && leaf.URIs[0] != nil && strings.HasPrefix(leaf.URIs[0].Path, "/key-client/") {
		return u.KeyClients.Verify(s)
	}
	matched := false
	for _, chain := range s.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && bytes.Equal(chain[0].Raw, leaf.Raw) {
			matched = true
		}
	}
	if u.Connectors == nil || !matched {
		return value.KeyPeer{}, app.ErrKeyDenied
	}
	return u.Connectors.verify(ctx, s.PeerCertificates)
}
