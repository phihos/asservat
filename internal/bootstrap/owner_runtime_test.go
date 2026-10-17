package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

const runtimeID = "11111111-1111-4111-8111-111111111111"

type runtimeIdentity struct {
	registration value.OwnerEnrollment
	issued       value.IssuedOwnerCertificate
}
type runtimeFixture struct {
	mu                 sync.Mutex
	ca                 *x509.Certificate
	key                *ecdsa.PrivateKey
	roots              *x509.CertPool
	configuration      value.OwnerConfiguration
	identities         map[string]runtimeIdentity
	denyProof          atomic.Bool
	signings, routes   atomic.Int32
	mutateProof        func(*value.OwnerEnrollmentProof)
	mutateRegistration func(*value.OwnerRegistrationObservation)
}

func (f *runtimeFixture) ReadOwnerConfiguration(context.Context) (value.OwnerConfigurationObservation, error) {
	now := time.Now()
	return value.OwnerConfigurationObservation{Configuration: f.configuration.Clone(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *runtimeFixture) Enroll(ctx context.Context, r value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
	key, err := mtls.EnrollmentKey(r.CSRDER)
	if err != nil {
		return value.IssuedOwnerCertificate{}, err
	}
	csr, err := x509.ParseCertificateRequest(r.CSRDER)
	if err != nil {
		return value.IssuedOwnerCertificate{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	_, until, _ := value.OwnerCertificateWindow(now)
	u, _ := mtls.OwnerURI(r.Binding)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(f.signings.Add(1))), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: now.Add(-30 * time.Second), NotAfter: until}
	if r.Usage == "server" {
		name, _ := mtls.OwnerServerName(r.Binding)
		leaf.DNSNames = []string{name}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, csr.PublicKey, f.key)
	if err != nil {
		return value.IssuedOwnerCertificate{}, err
	}
	out := value.IssuedOwnerCertificate{Certificate: value.OwnerCertificate{Binding: r.Binding, Usage: r.Usage, Digest: artifact.Digest(sha256.Sum256(der)), NotBefore: leaf.NotBefore, NotAfter: until}, DER: der}
	e := value.OwnerEnrollment{ID: runtimeID, Binding: r.Binding, Usage: r.Usage, Pool: f.configuration.Pool, SourceUID: runtimeID, Pod: "owner-pod", ReplicaSet: "owner-rs", ReplicaSetUID: runtimeID, PublicKeyDigest: key, InitialTokenDigest: artifact.Digest{2}, InitialWorkloadDigest: artifact.Digest{3}, InitialProtectionDigest: artifact.Digest{4}, ClaimedAt: now, InitialHoldUntil: until.Add(time.Minute)}
	f.mu.Lock()
	f.identities[r.Usage] = runtimeIdentity{e, out}
	f.mu.Unlock()
	return out, nil
}
func (f *runtimeFixture) ReadOwnerRegistration(ctx context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	f.mu.Lock()
	x, ok := f.identities[c.Usage]
	f.mu.Unlock()
	if !ok || x.issued.Certificate != c {
		return value.OwnerRegistrationObservation{}, value.ErrUnavailable
	}
	configuration, _ := f.ReadOwnerConfiguration(ctx)
	now := time.Now()
	o := value.OwnerRegistrationObservation{Enrollment: x.registration, Certificate: c, Configuration: configuration, ObservedAt: now, FreshUntil: configuration.FreshUntil}
	if f.mutateRegistration != nil {
		f.mutateRegistration(&o)
	}
	return o, nil
}
func (f *runtimeFixture) ReadOwnerEnrollmentProof(ctx context.Context, r value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
	if f.denyProof.Load() {
		return value.OwnerEnrollmentProof{}, value.ErrUnavailable
	}
	now := time.Now()
	c, _ := f.ReadOwnerConfiguration(ctx)
	key, err := mtls.EnrollmentKey(r.CSRDER)
	if err != nil {
		return value.OwnerEnrollmentProof{}, err
	}
	p := value.OwnerEnrollmentProof{Binding: r.Binding, Usage: r.Usage, Configuration: c, Pod: "owner-pod", ReplicaSet: "owner-rs", ReplicaSetUID: runtimeID, PublicKeyDigest: key, TokenDigest: artifact.Digest{2}, WorkloadDigest: artifact.Digest{3}, ProtectionDigest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if f.mutateProof != nil {
		f.mutateProof(&p)
	}
	return p, nil
}
func (f *runtimeFixture) CurrentOwnerRoute(context.Context, value.OwnerBinding) (value.OwnerRoute, error) {
	f.routes.Add(1)
	return value.OwnerRoute{}, value.ErrUnavailable
}
func (f *runtimeFixture) ReadOwnerProtection(context.Context, value.OwnerPool) (value.OwnerProtection, error) {
	return value.OwnerProtection{}, value.ErrUnavailable
}
func (f *runtimeFixture) ReadDownloadWorkerEnrollment(context.Context, string, string) (authorization.DownloadWorkerIdentity, error) {
	return authorization.DownloadWorkerIdentity{}, artifact.ErrDownloadUnavailable
}
func (f *runtimeFixture) ReadWorkerOwner(context.Context, string, string) (authorization.WorkerOwnerLease, error) {
	return authorization.WorkerOwnerLease{}, artifact.ErrDownloadUnavailable
}
func (f *runtimeFixture) BeginOwnedWorkerEnrollment(context.Context, authorization.WorkerOwnerLease, []byte, []byte) (evidence.WorkerEnrollmentDelivery, error) {
	return nil, artifact.ErrDownloadUnavailable
}

func newRuntimeFixture(t *testing.T) (*runtimeFixture, OwnerRuntimeConfig, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(90), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	p := value.OwnerPool{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, Namespace: "hub", NamespaceUID: runtimeID, Service: "owner", ServiceUID: runtimeID, Deployment: "owner", DeploymentUID: runtimeID, ServiceAccount: "owner", AccountUID: runtimeID, Port: l.Addr().(*net.TCPAddr).Port}
	f := &runtimeFixture{ca: ca, key: key, roots: roots, identities: map[string]runtimeIdentity{}, configuration: value.OwnerConfiguration{Pool: p, Revision: identity.Revision{UID: runtimeID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{5}, IssuerRoots: [][]byte{der}}}
	trust, err := mtls.NewWorkerTrustCatalog(runtimeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := OwnerRuntimeConfig{Pool: p, PodUID: runtimeID, SourceUID: runtimeID, Configuration: f, ServerEnrollment: f, ClientEnrollment: f, Registry: f, Proofs: f, Routes: f, Protection: f, Requests: func(value.OwnerBinding) (evidence.WorkerOwnerEnrollment, error) { return f, nil }, WorkerTrust: trust, Workers: f, Locators: f, Connections: 2, Concurrency: 1}
	return f, c, l
}

func waitOwnerState(t *testing.T, condition func() bool) {
	t.Helper()
	timeout := time.After(3 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-tick.C:
		case <-timeout:
			t.Fatal("owner state did not converge")
		}
	}
}
func TestOwnerRuntimeReadinessAndShutdown(t *testing.T) {
	f, c, listener := newRuntimeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := NewOwnerRuntime(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Ready() {
		t.Fatal("ready without activated credentials")
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(listener) }()
	waitOwnerState(t, r.Ready)
	if f.signings.Load() != 2 || f.routes.Load() != 0 {
		t.Fatal("readiness signed again or depended on Ready route")
	}
	name, _ := mtls.OwnerServerName(r.Binding())
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.roots, ServerName: name, GetClientCertificate: r.client.GetClientCertificate}}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("POST", "https://"+listener.Addr().String()+contracts.OwnerRelayPath, bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer synthetic.token")
	resp, err := (&http.Client{Transport: tr, Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("readiness substituted for current peer/route authority", resp.StatusCode)
	}
	f.denyProof.Store(true)
	waitOwnerState(t, func() bool { return !r.Ready() })
	if d, e := r.BeginWorkerEnrollment(ctx, runtimeID, runtimeID, runtimeID, []byte("synthetic.token"), nil); e == nil || d != nil {
		t.Fatal("unready runtime forwarded")
	}
	f.denyProof.Store(false)
	waitOwnerState(t, r.Ready)
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime failed to join")
	}
	if r.Ready() {
		t.Fatal("ready after shutdown")
	}
	if _, _, e := r.server.ReadinessRequest(); e == nil {
		t.Fatal("server key survived shutdown")
	}
	if _, _, e := r.client.ReadinessRequest(); e == nil {
		t.Fatal("client key survived shutdown")
	}
	conn, e := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
	if conn != nil {
		conn.Close()
	}
	if e == nil {
		t.Fatal("listener survived shutdown")
	}
}

func TestOwnerStartupRejectsChangedProofAndIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "foreign-source", "proof-key", "proof-workload", "proof-config", "registry-config", "closed-key", "parent-expired", "closed-during-client", "expired-proof", "short-parent"} {
		t.Run(mode, func(t *testing.T) {
			f, c, _ := newRuntimeFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "foreign-source" {
				c.SourceUID = "22222222-2222-4222-8222-222222222222"
			}
			r, err := NewOwnerRuntime(ctx, c)
			if mode == "foreign-source" {
				if err == nil {
					r.Close()
					t.Fatal("foreign source admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if r.server.Enroll(ctx) != nil || r.client.Enroll(ctx) != nil {
				t.Fatal("synthetic enrollment failed")
			}
			switch mode {
			case "proof-key":
				f.mutateProof = func(p *value.OwnerEnrollmentProof) { p.PublicKeyDigest = artifact.Digest{99} }
			case "proof-workload":
				f.mutateProof = func(p *value.OwnerEnrollmentProof) { p.ReplicaSetUID = "22222222-2222-4222-8222-222222222222" }
			case "proof-config":
				f.mutateProof = func(p *value.OwnerEnrollmentProof) { p.Configuration.Configuration.Revision.Generation++ }
			case "registry-config":
				f.mutateRegistration = func(p *value.OwnerRegistrationObservation) {
					if p.Certificate.Usage == "client" {
						p.Configuration.Configuration.Revision.Generation++
					}
				}
			case "closed-key":
				r.server.Close()
			case "parent-expired":
				cancel()
			case "closed-during-client":
				f.mutateProof = func(p *value.OwnerEnrollmentProof) {
					if p.Usage == "client" {
						r.server.Close()
					}
				}
			case "expired-proof":
				f.mutateProof = func(p *value.OwnerEnrollmentProof) { p.FreshUntil = p.ObservedAt }
			case "short-parent":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
				defer stop()
			}
			until, err := r.readiness.Check(ctx)
			if mode == "valid" || mode == "short-parent" {
				if mode == "short-parent" {
					deadline, _ := ctx.Deadline()
					if until.After(deadline) {
						t.Fatal("extended parent deadline")
					}
				}
				if err != nil || !time.Now().Before(until) {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("changed authority admitted")
			}
		})
	}
}

func TestOwnerRuntimeFreshEpochAndExpiredReadiness(t *testing.T) {
	_, c, _ := newRuntimeFixture(t)
	a, e := NewOwnerRuntime(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := NewOwnerRuntime(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if a.Binding().ProcessEpoch == b.Binding().ProcessEpoch {
		t.Fatal("reused process epoch")
	}
	now := time.Now()
	a.ready.Store(&ownerReadinessSnapshot{now.Add(-6 * time.Second), now.Add(-time.Second)})
	if a.Ready() {
		t.Fatal("stale readiness retained")
	}
	a.ready.Store(&ownerReadinessSnapshot{now.Add(time.Second), now.Add(2 * time.Second)})
	if a.Ready() {
		t.Fatal("clock rollback retained readiness")
	}
}

type runtimeEnrollmentFunc func(context.Context, value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error)

func (f runtimeEnrollmentFunc) Enroll(c context.Context, r value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
	return f(c, r)
}

func TestOwnerRuntimeStopsDuringEnrollmentAndListenerFailure(t *testing.T) {
	for _, mode := range []string{"cancel-enrollment", "closed-listener"} {
		t.Run(mode, func(t *testing.T) {
			_, c, listener := newRuntimeFixture(t)
			started := make(chan struct{})
			if mode == "cancel-enrollment" {
				c.ServerEnrollment = runtimeEnrollmentFunc(func(ctx context.Context, _ value.OwnerEnrollmentRequest) (value.IssuedOwnerCertificate, error) {
					close(started)
					<-ctx.Done()
					return value.IssuedOwnerCertificate{}, ctx.Err()
				})
			} else {
				listener.Close()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, err := NewOwnerRuntime(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			done := make(chan error, 1)
			go func() { done <- r.Run(listener) }()
			if mode == "cancel-enrollment" {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("enrollment not started")
				}
				cancel()
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("failed service reported success")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("startup failed to join")
			}
			if r.Ready() {
				t.Fatal("failed startup stayed ready")
			}
			if _, _, e := r.server.ReadinessRequest(); e == nil {
				t.Fatal("server retained after failed startup")
			}
			if _, _, e := r.client.ReadinessRequest(); e == nil {
				t.Fatal("client retained after failed startup")
			}
		})
	}
}
