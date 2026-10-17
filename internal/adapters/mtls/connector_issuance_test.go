package mtls

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func connectorPermit(now time.Time, roots [][]byte, key artifact.Digest, usage string) value.ConnectorCredentialPermit {
	id := ownerTestID
	b := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	claim := now
	if usage == "client" {
		claim = now.Add(-29 * time.Minute)
	}
	process := value.ConnectorCredentialProcess{BootstrapID: id, Binding: b, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, ClaimedAt: claim, InitialCertificateNotAfter: claim.Add(30 * time.Minute)}
	if usage == "client" {
		process.ClientKeyDigest = key
	} else {
		process.ServerKeyDigest = key
	}
	cfg := value.ConnectorCredentialProfile{Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}, RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{3}}, ProtectionDigest: artifact.Digest{4}, ServerName: "connector.example.invalid", ClientIssuerRoots: roots, ServerIssuerRoots: roots}
	peer := value.AuthenticatedPeer{Certificate: value.PeerCertificate{Binding: b, Digest: artifact.Digest{9}, NotBefore: claim, NotAfter: process.InitialCertificateNotAfter}, RegistrationRevision: cfg.Revision, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
	epoch, end, _ := process.Window(now)
	return value.ConnectorCredentialPermit{ID: id, Process: process, Usage: usage, Configuration: value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: cfg, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, CurrentPeer: peer, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: cfg.Revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, IntentDigest: artifact.Digest{5}, Epoch: epoch, Ordinal: 1, CheckedAt: now, SignBefore: now.Add(5 * time.Second), CertificateNotAfter: end}
}
func TestConnectorIssuedCredentialPinsIndependentPurposeSourceAndKey(t *testing.T) {
	for _, usage := range []string{"client", "server"} {
		for _, mode := range []string{"valid", "staggered-valid", "wrong-key", "other-peer", "dual-purpose", "wrong-dns", "cn", "expiry", "foreign-source", "current-root-removed", "expired-permit", "expired-peer", "third-attempt", "missing-intent", "server-key-reuse"} {
			t.Run(usage+"/"+mode, func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				clock := now
				ca := newOwnerTestCA(t, now)
				private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
				if e != nil {
					t.Fatal(e)
				}
				key, _ := EnrollmentKey(csr)
				p := connectorPermit(now, [][]byte{ca.cert.Raw}, key, usage)
				verifier, e := NewConnectorCredentialVerifier(p.Configuration.Profile, func() time.Time { return clock })
				if e != nil {
					t.Fatal(e)
				}
				b := p.Process.Binding
				if mode == "other-peer" {
					b.PeerID = ownerOtherID
				}
				uri, _ := PeerURI(b)
				leaf := &x509.Certificate{SerialNumber: big.NewInt(8), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}, NotBefore: now.Add(-30 * time.Second), NotAfter: p.CertificateNotAfter}
				if usage == "server" {
					leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
					leaf.DNSNames = []string{p.Configuration.Profile.ServerName}
				}
				public := private.Public()
				switch mode {
				case "staggered-valid":
					p.CurrentPeer.VerifiedAt = now.Add(time.Millisecond)
					p.Configuration.ObservedAt = now.Add(2 * time.Millisecond)
					p.Recovery.ObservedAt = now.Add(3 * time.Millisecond)
					clock = now.Add(4 * time.Millisecond)
				case "wrong-key":
					other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					public = other.Public()
				case "dual-purpose":
					leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				case "wrong-dns":
					leaf.DNSNames = []string{"other.example.invalid"}
				case "cn":
					leaf.Subject = pkix.Name{CommonName: "connector"}
				case "expiry":
					leaf.NotAfter = leaf.NotAfter.Add(time.Second)
				case "foreign-source":
					p.Configuration.Profile.Revision.UID = ownerOtherID
				case "current-root-removed":
					p.Configuration.Profile.ClientIssuerRoots = [][]byte{newOwnerTestCA(t, now).cert.Raw}
					p.Configuration.Profile.ServerIssuerRoots = p.Configuration.Profile.ClientIssuerRoots
				case "expired-permit":
					clock = now.Add(5 * time.Second)
				case "expired-peer":
					p.CurrentPeer.ValidUntil = now
				case "third-attempt":
					p.Ordinal = 3
				case "missing-intent":
					p.IntentDigest = artifact.Digest{}
				case "server-key-reuse":
					p.Process.ServerKeyDigest = p.Process.ClientKeyDigest
				}
				der, e := x509.CreateCertificate(rand.Reader, leaf, ca.cert, public, ca.key)
				if e != nil {
					t.Fatal(e)
				}
				got, e := verifier.CheckConnectorCredential(p, csr, der, nil)
				if mode != "valid" && mode != "staggered-valid" {
					if e == nil {
						t.Fatal("invalid credential accepted")
					}
					return
				}
				if e != nil || !p.Matches(got) {
					t.Fatal("valid credential failed", e)
				}
				original := got.DER[0]
				der[0] ^= 1
				if got.DER[0] != original {
					t.Fatal("provider mutable buffer retained")
				}
				// Local verification produces certificate facts only; it never invents a
				// completed TLS handshake for the server identity path.
				if _, e = verifier.VerifyConnectorServer(nil, p.Configuration); e == nil {
					t.Fatal("missing actual TLS accepted")
				}
			})
		}
	}
}
func TestConnectorStoredResultDoesNotRenewOriginalSigningDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	ca := newOwnerTestCA(t, now)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	key, _ := EnrollmentKey(csr)
	p := connectorPermit(now, [][]byte{ca.cert.Raw}, key, "server")
	v, e := NewConnectorCredentialVerifier(p.Configuration.Profile, func() time.Time { return clock })
	if e != nil {
		t.Fatal(e)
	}
	uri, _ := PeerURI(p.Process.Binding)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(10), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}, DNSNames: []string{p.Configuration.Profile.ServerName}, NotBefore: now.Add(-time.Second), NotAfter: p.CertificateNotAfter}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, ca.cert, private.Public(), ca.key)
	clock = now.Add(8 * time.Second)
	current := p.Configuration
	current.ObservedAt = clock
	current.FreshUntil = clock.Add(5 * time.Second)
	if _, e = v.CheckConnectorCredential(p, csr, der, nil); e == nil {
		t.Fatal("signing permit revived")
	}
	if _, e = v.CheckConnectorCredentialCurrent(p, csr, der, nil, current); e != nil {
		t.Fatal("stored original result cannot be verified", e)
	}
	current.Profile.Suspended = true
	if _, e = v.CheckConnectorCredentialCurrent(p, csr, der, nil, current); e == nil {
		t.Fatal("stored result bypassed suspension")
	}
}
