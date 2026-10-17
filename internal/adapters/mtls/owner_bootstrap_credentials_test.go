package mtls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// Extends the existing synthetic enrollment fixture with one explicitly
// accepted opted pool. The production credential key, CSR, result checking,
// current registry checking, renewal and retained signer closure remain real.
type ownerBootstrapCredentialFixture struct {
	base    *ownerCredentialFixture
	pool    value.OwnerPool
	changed bool
}

func (f *ownerBootstrapCredentialFixture) Enroll(ctx context.Context, r value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
	out, e := f.base.Enroll(ctx, r)
	f.base.enrollment.Pool = f.pool
	return out, e
}
func (f *ownerBootstrapCredentialFixture) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	out, e := f.base.ReadOwnerRegistration(ctx, c)
	out.Configuration.Configuration.Pool = f.pool
	if f.changed {
		out.Configuration.Configuration.Pool.NativeBootstrap = ""
	}
	return out, e
}
func TestOwnerBootstrapCredentialInstallationRenewalAndCurrentChecks(t *testing.T) {
	for _, usage := range []string{"server", "client"} {
		t.Run(usage, func(t *testing.T) {
			now := time.Now().Add(time.Hour).UTC().Truncate(value.OwnerCertificatePeriod).Add(2 * time.Minute)
			base := &ownerCredentialFixture{t: t, ca: newOwnerTestCA(t, now)}
			base.clock.Store(now.UnixNano())
			pool := ownerBootstrapPool()
			common, _ := OwnerBootstrapServerName(pool)
			base.mutateLeaf = func(c *x509.Certificate) {
				if usage == "server" {
					c.DNSNames = append(c.DNSNames, common)
				}
			}
			f := &ownerBootstrapCredentialFixture{base: base, pool: pool}
			c, e := NewOwnerCredentialsForPool(ownerBootstrapBinding(ownerTestID), usage, pool, base.ca.roots, f, f, base.now)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if e = c.Enroll(context.Background()); e != nil {
				t.Fatal("opted certificate installation", e)
			}
			firstRequest := bytes.Clone(base.request.CSRDER)
			firstEnrollment := base.enrollment
			firstKey := c.key
			original, e := c.Certificate()
			if e != nil {
				t.Fatal(e)
			}
			registered, e := f.ReadOwnerRegistration(context.Background(), original)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := c.VerifyReadinessCertificate(registered.Configuration); e != nil || got != original {
				t.Fatal("readiness dropped accepted profile", e)
			}
			verify := c.VerifyServingCertificate
			if usage == "client" {
				verify = c.VerifyClientCertificate
			}
			if got, e := verify(registered.Configuration); e != nil || got != original {
				t.Fatal("current local verifier dropped profile", e)
			}
			if e = c.Enroll(context.Background()); e != nil || base.calls != 1 {
				t.Fatal("same period repeated enrollment", e, base.calls)
			}
			changed := registered.Configuration
			changed.Configuration = changed.Configuration.Clone()
			changed.Configuration.Pool.NativeBootstrap = ""
			if _, e = verify(changed); e == nil {
				t.Fatal("removed accepted capability survived current local check")
			}
			base.clock.Add(int64(value.OwnerCertificatePeriod))
			if e = c.Enroll(context.Background()); e != nil || base.calls != 2 {
				t.Fatal("fixed-period renewal failed", e, base.calls)
			}
			if c.key != firstKey || !bytes.Equal(base.request.CSRDER, firstRequest) || base.enrollment != firstEnrollment {
				t.Fatal("profile renewal changed original process key, CSR or enrollment")
			}
			renewed, e := c.Certificate()
			if e != nil || !renewed.NotAfter.After(original.NotAfter) {
				t.Fatal("new original period missing", e)
			}
			base.clock.Add(int64(value.OwnerCertificatePeriod))
			f.changed = true
			if e = c.Enroll(context.Background()); e == nil {
				t.Fatal("changed current registry profile installed result")
			}
			c.Close()
			if _, e = c.Certificate(); e == nil {
				t.Fatal("closed credential survived")
			}
		})
	}
}

func TestOwnerBootstrapStoredResultRetainsOriginalPermitAndCurrentProfile(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	ca := newOwnerTestCA(t, now)
	pool := ownerBootstrapPool()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if e != nil {
		t.Fatal(e)
	}
	key, e := EnrollmentKey(csr)
	if e != nil {
		t.Fatal(e)
	}
	permit := ownerPermit(now, [][]byte{ca.cert.Raw}, key, "server")
	permit.Configuration.Configuration.Pool = pool
	uri, _ := OwnerURI(permit.Binding)
	exact, _ := OwnerServerName(permit.Binding)
	common, _ := OwnerBootstrapServerName(pool)
	template := &x509.Certificate{SerialNumber: big.NewInt(9), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}, DNSNames: []string{exact, common}, NotBefore: now.Add(-30 * time.Second), NotAfter: permit.CertificateNotAfter}
	der, e := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if e != nil {
		t.Fatal(e)
	}
	v, e := NewOwnerPeerVerifierForPool(ca.roots, pool, func() time.Time { return clock })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.CheckOwnerCertificate(permit, csr, der, nil); e != nil {
		t.Fatal("opted result denied", e)
	}
	clock = now.Add(8 * time.Second)
	current := permit.Configuration
	current.ObservedAt = clock
	current.FreshUntil = clock.Add(5 * time.Second)
	if _, e = v.CheckOwnerCertificate(permit, csr, der, nil); e == nil {
		t.Fatal("original signing interval renewed")
	}
	original := permit
	if _, e = v.CheckOwnerCertificateCurrent(permit, csr, der, nil, current); e != nil {
		t.Fatal("stored result cannot finish under current same profile", e)
	}
	if !permit.SignBefore.Equal(original.SignBefore) || !permit.CertificateNotAfter.Equal(original.CertificateNotAfter) || permit.Ordinal != original.Ordinal {
		t.Fatal("stored verification changed original signing allowance")
	}
	for _, mode := range []string{"removed", "different-service", "removed-root", "expired"} {
		t.Run(mode, func(t *testing.T) {
			changed := current
			changed.Configuration = changed.Configuration.Clone()
			switch mode {
			case "removed":
				changed.Configuration.Pool.NativeBootstrap = ""
			case "different-service":
				changed.Configuration.Pool.ServiceUID = ownerOtherID
			case "removed-root":
				changed.Configuration.IssuerRoots = [][]byte{newOwnerTestCA(t, clock).cert.Raw}
			case "expired":
				changed.FreshUntil = clock
			}
			if _, e = v.CheckOwnerCertificateCurrent(permit, csr, der, nil, changed); e == nil {
				t.Fatal("stored result bypassed changed current profile")
			}
		})
	}
}
