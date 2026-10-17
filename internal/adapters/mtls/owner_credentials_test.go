package mtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Synthetic audited registrar/registry for isolating credential custody. Real
// SQL/provider/native proof composition is exercised in test/integration.
type ownerCredentialFixture struct {
	t                  *testing.T
	ca                 ownerTestCA
	clock              atomic.Int64
	liveClock          func() time.Time
	request            value.OwnerEnrollmentRequest
	issued             value.IssuedOwnerCertificate
	enrollment         value.OwnerEnrollment
	calls              int
	fail               bool
	mutateLeaf         func(*x509.Certificate)
	mutateResult       func(*value.IssuedOwnerCertificate)
	mutateRegistration func(*value.OwnerRegistrationObservation)
	beforeIssue        func(context.Context) error
}

func (f *ownerCredentialFixture) now() time.Time {
	if f.liveClock != nil {
		// X.509 serializes validity to seconds; keep synthetic metadata identical.
		return f.liveClock().UTC().Truncate(time.Second)
	}
	return time.Unix(0, f.clock.Load()).UTC()
}
func (f *ownerCredentialFixture) Enroll(ctx context.Context, r value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
	f.calls++
	if f.beforeIssue != nil {
		if e := f.beforeIssue(ctx); e != nil {
			return value.IssuedOwnerCertificate{}, e
		}
	}
	if f.fail {
		return value.IssuedOwnerCertificate{}, value.ErrUnavailable
	}
	csr, err := x509.ParseCertificateRequest(r.CSRDER)
	if err != nil || csr.CheckSignature() != nil {
		f.t.Fatal("invalid generated CSR", err)
	}
	key, err := EnrollmentKey(r.CSRDER)
	if err != nil {
		f.t.Fatal("identity-bearing CSR", err)
	}
	f.request = r
	u, _ := OwnerURI(r.Binding)
	issuedAt := f.now()
	_, until, _ := value.OwnerCertificateWindow(issuedAt)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(f.calls + 1)), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: issuedAt.Add(-30 * time.Second), NotAfter: until}
	if r.Usage == "server" {
		name, _ := OwnerServerName(r.Binding)
		leaf.DNSNames = []string{name}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if f.mutateLeaf != nil {
		f.mutateLeaf(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca.cert, csr.PublicKey, f.ca.key)
	if err != nil {
		f.t.Fatal(err)
	}
	out := value.IssuedOwnerCertificate{Certificate: value.OwnerCertificate{Binding: r.Binding, Usage: r.Usage, Digest: artifact.Digest(sha256.Sum256(der)), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, DER: der}
	if f.mutateResult != nil {
		f.mutateResult(&out)
	}
	f.issued = out.Clone()
	if f.enrollment.ID == "" {
		p := ownerPermit(issuedAt, [][]byte{f.ca.cert.Raw}, key, r.Usage)
		f.enrollment = value.OwnerEnrollment{ID: ownerTestID, Binding: r.Binding, Usage: r.Usage, Pool: p.Configuration.Configuration.Pool, SourceUID: ownerTestID, Pod: "owner-1", ReplicaSet: "owner", ReplicaSetUID: ownerTestID, PublicKeyDigest: key, InitialTokenDigest: artifact.Digest{1}, InitialWorkloadDigest: artifact.Digest{2}, InitialProtectionDigest: artifact.Digest{3}, ClaimedAt: issuedAt, InitialHoldUntil: p.CertificateNotAfter.Add(time.Minute)}
	}
	return out, nil
}
func (f *ownerCredentialFixture) ReadOwnerRegistration(_ context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	key, _ := EnrollmentKey(f.request.CSRDER)
	now := f.now()
	p := ownerPermit(now, [][]byte{f.ca.cert.Raw}, key, f.request.Usage)
	// Refresh observations, never the persisted first enrollment. Advancing its
	// ClaimedAt between the authenticator's two reads fabricated a replacement.
	out := value.OwnerRegistrationObservation{Enrollment: f.enrollment, Certificate: c, Configuration: p.Configuration, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if f.mutateRegistration != nil {
		f.mutateRegistration(&out)
	}
	return out, nil
}
func newOwnerCredentialFixture(t *testing.T, usage string) (*OwnerCredentials, *ownerCredentialFixture) {
	t.Helper()
	// A future UTC-aligned clock keeps real context deadlines live while tests
	// advance through complete renewal windows without sleeping.
	now := time.Now().Add(time.Hour).UTC().Truncate(value.OwnerCertificatePeriod).Add(2 * time.Minute)
	f := &ownerCredentialFixture{t: t, ca: newOwnerTestCA(t, now)}
	f.clock.Store(now.UnixNano())
	b := value.OwnerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PodUID: ownerTestID, ProcessEpoch: ownerTestID}
	c, err := NewOwnerCredentials(b, usage, f.ca.roots, f, f, f.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, f
}
func ownerClientInfo() *tls.CertificateRequestInfo {
	return &tls.CertificateRequestInfo{Version: tls.VersionTLS13, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}
}

func TestOwnerCredentialFixtureRetainsOriginalEnrollment(t *testing.T) {
	c, f := newOwnerCredentialFixture(t, "server")
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	cert, err := c.ServingCertificate()
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.ReadOwnerRegistration(context.Background(), cert)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Add(int64(time.Second))
	last, err := f.ReadOwnerRegistration(context.Background(), cert)
	if err != nil {
		t.Fatal(err)
	}
	if first.Enrollment != last.Enrollment {
		t.Fatal("fixture changed immutable enrollment when observation clock crossed a second")
	}
	if !last.ObservedAt.After(first.ObservedAt) || !last.Valid(f.now()) {
		t.Fatal("fixture froze current observation instead of enrollment")
	}
	f.clock.Add(int64(value.OwnerCertificatePeriod))
	if err = c.Enroll(context.Background()); err != nil {
		t.Fatal("renewal", err)
	}
	cert, err = c.ServingCertificate()
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := f.ReadOwnerRegistration(context.Background(), cert)
	if err != nil || renewed.Enrollment != first.Enrollment || !renewed.Valid(f.now()) {
		t.Fatal("renewal changed first enrollment or returned stale observation", err)
	}
}

func TestOwnerReadinessSnapshotOwnsPublicBytes(t *testing.T) {
	for _, usage := range []string{"server", "client"} {
		t.Run(usage, func(t *testing.T) {
			c, f := newOwnerCredentialFixture(t, usage)
			defer c.Close()
			if _, _, err := c.ReadinessRequest(); err == nil {
				t.Fatal("unenrolled key became ready")
			}
			if err := c.Enroll(context.Background()); err != nil {
				t.Fatal(err)
			}
			certificate, first, err := c.ReadinessRequest()
			if err != nil || first.Usage != usage || certificate.Usage != usage {
				t.Fatal(err)
			}
			original := bytes.Clone(first.CSRDER)
			first.CSRDER[0] ^= 1
			_, again, err := c.ReadinessRequest()
			if err != nil || !bytes.Equal(again.CSRDER, original) {
				t.Fatal("caller mutated owned CSR")
			}
			registration, err := f.ReadOwnerRegistration(context.Background(), certificate)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := c.VerifyReadinessCertificate(registration.Configuration); err != nil || got != certificate {
				t.Fatal("current readiness identity", err)
			}
			c.Close()
			if _, _, err := c.ReadinessRequest(); err == nil {
				t.Fatal("closed key returned readiness")
			}
			if _, err := c.VerifyReadinessCertificate(registration.Configuration); err == nil {
				t.Fatal("closed key reverified")
			}
		})
	}
}

func TestOwnerServingIdentityRequiresCurrentRootsAndLiveKey(t *testing.T) {
	c, f := newOwnerCredentialFixture(t, "server")
	if _, err := c.ServingCertificate(); err == nil {
		t.Fatal("unenrolled server accepted")
	}
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	cert, err := c.ServingCertificate()
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := f.ReadOwnerRegistration(context.Background(), cert)
	if got, err := c.VerifyServingCertificate(registration.Configuration); err != nil || got != cert {
		t.Fatal("current serving identity", err)
	}
	registration.Configuration.Configuration.Suspended = true
	if _, err := c.VerifyServingCertificate(registration.Configuration); err == nil {
		t.Fatal("suspended serving identity")
	}
	registration.Configuration.Configuration.Suspended = false
	foreign := newOwnerTestCA(t, f.now())
	registration.Configuration.Configuration.IssuerRoots = [][]byte{foreign.cert.Raw}
	if _, err := c.VerifyServingCertificate(registration.Configuration); err == nil {
		t.Fatal("removed serving root")
	}
	c.Close()
	if _, err := c.ServingCertificate(); err == nil {
		t.Fatal("closed serving identity")
	}
	client, _ := newOwnerCredentialFixture(t, "client")
	if err := client.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ServingCertificate(); err == nil {
		t.Fatal("client is not server identity")
	}
}

func TestOwnerClientIdentityRequiresCurrentRootsAndLiveKey(t *testing.T) {
	c, f := newOwnerCredentialFixture(t, "client")
	if _, err := c.ClientCertificate(); err == nil {
		t.Fatal("unenrolled client")
	}
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	cert, err := c.ClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := f.ReadOwnerRegistration(context.Background(), cert)
	if got, err := c.VerifyClientCertificate(registration.Configuration); err != nil || got != cert {
		t.Fatal("current client", err)
	}
	registration.Configuration.Configuration.Suspended = true
	if _, err := c.VerifyClientCertificate(registration.Configuration); err == nil {
		t.Fatal("suspended client")
	}
	c.Close()
	if _, err := c.ClientCertificate(); err == nil {
		t.Fatal("closed client")
	}
}

func TestOwnerCredentialsRenewalRetainsKeyAndExpiresSnapshots(t *testing.T) {
	c, f := newOwnerCredentialFixture(t, "client")
	if _, err := c.Certificate(); err == nil {
		t.Fatal("identity before activation")
	}
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := c.Certificate()
	csr := bytes.Clone(f.request.CSRDER)
	snapshot, err := c.GetClientCertificate(ownerClientInfo())
	if err != nil {
		t.Fatal(err)
	}
	signer := snapshot.PrivateKey.(crypto.Signer)
	if _, ok := snapshot.PrivateKey.(*ecdsa.PrivateKey); ok {
		t.Fatal("exported private key")
	}
	if err = c.Enroll(context.Background()); err != nil || f.calls != 1 {
		t.Fatal("same window reissued", err)
	}
	f.clock.Store(first.NotAfter.Add(-time.Minute).UnixNano())
	f.fail = true
	if err = c.Enroll(context.Background()); err == nil {
		t.Fatal("ignored failed renewal")
	}
	if got, e := c.Certificate(); e != nil || got != first {
		t.Fatal("failed renewal lost original", e)
	}
	f.clock.Add(int64(time.Second))
	f.fail = false
	if err = c.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	next, _ := c.Certificate()
	if !bytes.Equal(csr, f.request.CSRDER) || !next.NotAfter.After(first.NotAfter) {
		t.Fatal("changed key or failed to renew")
	}
	f.clock.Store(first.NotAfter.UnixNano())
	digest := sha256.Sum256([]byte("synthetic TLS proof"))
	if _, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("old snapshot outlived original leaf")
	}
	if _, err = c.Certificate(); err != nil {
		t.Fatal("new leaf expired with old", err)
	}
	current, _ := c.GetClientCertificate(ownerClientInfo())
	c.Close()
	if _, err = current.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("retained signer survived close")
	}
	if err = c.Enroll(context.Background()); err == nil {
		t.Fatal("closed owner enrolled")
	}
}

func TestOwnerCredentialsRequireExactActivatedCertificate(t *testing.T) {
	for _, mode := range []string{"unactivated", "wrong-key", "wrong-process", "wrong-purpose", "metadata", "expiry", "extra-name", "current-root", "suspended", "stale-registry", "oversize-chain", "cancelled", "clock-backwards", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			c, f := newOwnerCredentialFixture(t, "client")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "unactivated":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) { *o = value.OwnerRegistrationObservation{} }
			case "wrong-key":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) { o.Enrollment.PublicKeyDigest = artifact.Digest{7} }
			case "wrong-process":
				f.mutateLeaf = func(l *x509.Certificate) {
					b := c.binding
					b.ProcessEpoch = ownerOtherID
					u, _ := OwnerURI(b)
					l.URIs = []*url.URL{u}
				}
			case "wrong-purpose":
				f.mutateLeaf = func(l *x509.Certificate) { l.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }
			case "metadata":
				f.mutateResult = func(o *value.IssuedOwnerCertificate) { o.Certificate.Digest = artifact.Digest{7} }
			case "expiry":
				f.mutateLeaf = func(l *x509.Certificate) { l.NotAfter = l.NotAfter.Add(time.Second) }
			case "extra-name":
				f.mutateLeaf = func(l *x509.Certificate) { l.Subject.CommonName = "extra" }
			case "current-root":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) {
					o.Configuration.Configuration.IssuerRoots = [][]byte{newOwnerTestCA(t, f.now()).cert.Raw}
				}
			case "suspended":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) { o.Configuration.Configuration.Suspended = true }
			case "stale-registry":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) { f.clock.Add(int64(5 * time.Second)) }
			case "oversize-chain":
				f.mutateResult = func(o *value.IssuedOwnerCertificate) { o.ChainDER = [][]byte{make([]byte, 16385)} }
			case "cancelled":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) { cancel() }
			case "clock-backwards":
				f.mutateRegistration = func(o *value.OwnerRegistrationObservation) { f.clock.Add(-int64(time.Second)) }
			case "deadline":
				f.beforeIssue = func(context.Context) error { f.clock.Add(int64(30 * time.Second)); return nil }
			}
			if err := c.Enroll(ctx); err == nil {
				t.Fatal("unsafe credential installed")
			}
			if _, err := c.Certificate(); err == nil {
				t.Fatal("failed enrollment retained identity")
			}
		})
	}
}

func TestOwnerCredentialsCloseCancelsSingleEnrollment(t *testing.T) {
	c, f := newOwnerCredentialFixture(t, "client")
	entered := make(chan struct{})
	f.beforeIssue = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- c.Enroll(context.Background()) }()
	<-entered
	if err := c.Enroll(context.Background()); err == nil {
		t.Fatal("concurrent enrollment admitted")
	}
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed enrollment returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("enrollment not cancelled")
	}
	if f.calls != 1 {
		t.Fatal("duplicate issuer call")
	}
}

func TestOwnerCredentialsRecheckCancellationAfterLock(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "cached"}[cached], func(t *testing.T) {
			c, f := newOwnerCredentialFixture(t, "client")
			if cached {
				if err := c.Enroll(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := f.calls
			// The first protected clock read occurs after taking the mutex. This
			// models cancellation while waiting for that lock, deterministically.
			c.now = func() time.Time { cancel(); return f.now() }
			if err := c.Enroll(ctx); err == nil || f.calls != calls {
				t.Fatal("cancelled caller received identity or started enrollment", err, f.calls, calls)
			}
		})
	}
}

func TestOwnerCredentialsActualTLSAndSnapshotOwnership(t *testing.T) {
	server, sf := newOwnerCredentialFixture(t, "server")
	client, cf := newOwnerCredentialFixture(t, "client")
	cf.ca = sf.ca // separate process keys, shared synthetic issuer
	client.verifier.roots = sf.ca.roots.Clone()
	for _, c := range []*OwnerCredentials{server, client} {
		if err := c.Enroll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	skey, _ := EnrollmentKey(sf.request.CSRDER)
	ckey, _ := EnrollmentKey(cf.request.CSRDER)
	if skey == ckey {
		t.Fatal("purposes share a process key")
	}
	snapshot, err := client.GetClientCertificate(ownerClientInfo())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Certificate[0][0] ^= 1
	snapshot.Leaf.Subject.CommonName = "mutated"
	signer := snapshot.PrivateKey.(crypto.Signer)
	signer.Public().(*ecdsa.PublicKey).X.SetInt64(1)
	serverCert, _ := server.Certificate()
	name, _ := OwnerServerName(serverCert.Binding)
	if _, err = server.GetClientCertificate(ownerClientInfo()); err == nil {
		t.Fatal("server used as client")
	}
	if _, err = client.GetClientCertificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS12 credential exposed")
	}
	if _, err = server.GetCertificate(&tls.ClientHelloInfo{ServerName: "foreign", SupportedVersions: []uint16{tls.VersionTLS13}}); err == nil {
		t.Fatal("wrong SNI accepted")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, e := server.verifier.VerifyClient(r.TLS)
		if e != nil || peer.Binding != serverCert.Binding {
			t.Error("actual client", e)
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: server.GetCertificate, ClientCAs: sf.ca.roots, ClientAuth: tls.RequireAndVerifyClientCert, Time: sf.now}
	srv.StartTLS()
	defer srv.Close()
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: sf.ca.roots, ServerName: name, GetClientCertificate: client.GetClientCertificate, Time: cf.now}}
	defer tr.CloseIdleConnections()
	h := &http.Client{Transport: tr, Timeout: time.Second}
	r, err := h.Get(srv.URL)
	if err != nil {
		t.Fatal("actual TLS callbacks", err)
	}
	r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatal("TLS status", r.StatusCode)
	}
	if _, err = client.verifier.VerifyServer(r.TLS, serverCert.Binding); err != nil {
		t.Fatal(err)
	}
}
