package mtls

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func ownerPermit(now time.Time, roots [][]byte, key artifact.Digest, usage string) value.OwnerCertificatePermit {
	id := ownerTestID
	b := value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: roots}
	epoch, until, _ := value.OwnerCertificateWindow(now)
	return value.OwnerCertificatePermit{ID: id, Binding: b, Usage: usage, PublicKeyDigest: key, EnrollmentAudit: artifact.Digest{3}, Configuration: value.OwnerConfigurationObservation{Configuration: c, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{4}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 1, CheckedAt: now, SignBefore: now.Add(5 * time.Second), CertificateNotAfter: until}
}

func TestOwnerIssuedCertificateBindsProofPurposeAndCurrentRoots(t *testing.T) {
	for _, usage := range []string{"client", "server"} {
		for _, mode := range []string{"valid", "different-key", "wrong-process", "wrong-purpose", "extra-name", "different-expiry", "wrong-current-root", "suspended", "expired-proof", "expired-recovery", "missing-audit", "oversize-chain", "malformed"} {
			t.Run(usage+"/"+mode, func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				clock := now
				ca := newOwnerTestCA(t, now)
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
				if err != nil {
					t.Fatal(err)
				}
				key, err := EnrollmentKey(csr)
				if err != nil {
					t.Fatal(err)
				}
				p := ownerPermit(now, [][]byte{ca.cert.Raw}, key, usage)
				b := p.Binding
				if mode == "wrong-process" {
					b.ProcessEpoch = ownerOtherID
				}
				u, _ := OwnerURI(b)
				name, _ := OwnerServerName(b)
				leaf := &x509.Certificate{SerialNumber: big.NewInt(2), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: now.Add(-30 * time.Second), NotAfter: p.CertificateNotAfter}
				if usage == "server" {
					leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
					leaf.DNSNames = []string{name}
				}
				switch mode {
				case "different-key":
					pub, _, _ = ed25519.GenerateKey(rand.Reader)
				case "wrong-purpose":
					leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
				case "extra-name":
					leaf.Subject = pkix.Name{CommonName: "forbidden"}
				case "different-expiry":
					leaf.NotAfter = leaf.NotAfter.Add(time.Second)
				case "wrong-current-root":
					p.Configuration.Configuration.IssuerRoots = [][]byte{newOwnerTestCA(t, now).cert.Raw}
				case "suspended":
					p.Configuration.Configuration.Suspended = true
				case "expired-proof":
					clock = now.Add(5 * time.Second)
				case "expired-recovery":
					p.Recovery.FreshUntil = now
				case "missing-audit":
					p.EnrollmentAudit = artifact.Digest{}
				}
				der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, pub, ca.key)
				if err != nil {
					t.Fatal(err)
				}
				var chain [][]byte
				if mode == "oversize-chain" {
					chain = [][]byte{make([]byte, 16<<10+1)}
				}
				if mode == "malformed" {
					der = []byte("invalid")
				}
				v, err := NewOwnerPeerVerifier(ca.roots, ownerTestID, ownerTestID, ownerTestID, func() time.Time { return clock })
				if err != nil {
					t.Fatal(err)
				}
				got, err := v.CheckOwnerCertificate(p, csr, der, chain)
				if mode != "valid" {
					if err == nil {
						t.Fatal("invalid certificate accepted")
					}
					return
				}
				if err != nil || !p.Matches(got) {
					t.Fatal("valid issue rejected", err)
				}
				before := got.DER[0]
				der[0] ^= 1
				if got.DER[0] != before {
					t.Fatal("provider buffer retained")
				}
			})
		}
	}
}

func TestOwnerStoredCertificateUsesCurrentTrustWithoutRefreshingSigning(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	ca := newOwnerTestCA(t, now)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := EnrollmentKey(csr)
	p := ownerPermit(now, [][]byte{ca.cert.Raw}, key, "client")
	uri, _ := OwnerURI(p.Binding)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(45), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}, NotBefore: now.Add(-30 * time.Second), NotAfter: p.CertificateNotAfter}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewOwnerPeerVerifier(ca.roots, ownerTestID, ownerTestID, ownerTestID, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	clock = now.Add(8 * time.Second)
	current := p.Configuration
	current.ObservedAt = clock
	current.FreshUntil = clock.Add(5 * time.Second)
	current.Configuration = current.Configuration.Clone()
	current.Configuration.Revision.Generation++
	if _, err = v.CheckOwnerCertificate(p, csr, der, nil); err == nil {
		t.Fatal("expired signing permit revived")
	}
	if _, err = v.CheckOwnerCertificateCurrent(p, csr, der, nil, current); err != nil {
		t.Fatal("late audit could not resume valid stored leaf", err)
	}
	for _, mode := range []string{"removed-root", "foreign-source", "suspended", "stale", "pool-change", "expired-leaf"} {
		t.Run(mode, func(t *testing.T) {
			c := current
			c.Configuration = c.Configuration.Clone()
			clock = now.Add(8 * time.Second)
			switch mode {
			case "removed-root":
				c.Configuration.IssuerRoots = [][]byte{newOwnerTestCA(t, clock).cert.Raw}
			case "foreign-source":
				c.Configuration.Revision.UID = ownerOtherID
			case "suspended":
				c.Configuration.Suspended = true
			case "stale":
				c.FreshUntil = clock
			case "pool-change":
				c.Configuration.Pool.Port++
			case "expired-leaf":
				clock = p.CertificateNotAfter
				c.ObservedAt = clock
				c.FreshUntil = clock.Add(5 * time.Second)
			}
			if _, err = v.CheckOwnerCertificateCurrent(p, csr, der, nil, c); err == nil {
				t.Fatal("stored certificate bypassed current trust")
			}
		})
	}
}
