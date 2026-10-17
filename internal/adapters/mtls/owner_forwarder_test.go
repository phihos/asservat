package mtls

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
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/ownerrelay"
)

type forwardRoutes func(context.Context, fleet.OwnerBinding) (fleet.OwnerRoute, error)

func (f forwardRoutes) CurrentOwnerRoute(c context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
	return f(c, b)
}

type forwardRegistry func(context.Context, fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error)

func (f forwardRegistry) ReadOwnerRegistration(c context.Context, b fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
	return f(c, b)
}

type forwardGuard func(context.Context, fleet.OwnerPool) (fleet.OwnerProtection, error)

func (f forwardGuard) ReadOwnerProtection(c context.Context, p fleet.OwnerPool) (fleet.OwnerProtection, error) {
	return f(c, p)
}

type forwardLookup func(context.Context, string, string) (value.WorkerOwnerLease, error)

func (f forwardLookup) ReadWorkerOwner(c context.Context, s, w string) (value.WorkerOwnerLease, error) {
	return f(c, s, w)
}

type forwardWorkers func(context.Context, string, string) (value.DownloadWorkerIdentity, error)

func (f forwardWorkers) ReadDownloadWorkerEnrollment(c context.Context, s, w string) (value.DownloadWorkerIdentity, error) {
	return f(c, s, w)
}

type forwardOperation func(context.Context, value.WorkerOwnerLease, []byte, []byte) (evidence.WorkerEnrollmentDelivery, error)

func (f forwardOperation) BeginOwnedWorkerEnrollment(c context.Context, l value.WorkerOwnerLease, t, k []byte) (evidence.WorkerEnrollmentDelivery, error) {
	return f(c, l, t, k)
}

type forwardDelivery struct {
	ctx     context.Context
	cert    value.WorkerCertificate
	release func()
}

func (d forwardDelivery) Context() context.Context             { return d.ctx }
func (d forwardDelivery) Certificate() value.WorkerCertificate { return d.cert }
func (d forwardDelivery) Close()                               { d.release() }

func forwardTestWorker(t *testing.T) value.DownloadWorker {
	t.Helper()
	id := ownerTestID
	now := time.Now().UTC().Truncate(time.Second)
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	profile := value.DownloadWorkerProfile{Configuration: rev, InstallationID: id, ClusterID: id, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "acquisition", ServiceAccountUID: "account", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", ControlDigest: artifact.Digest{1}, PriorityClass: "workers", PriorityClassUID: "priority", CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2}, Principal: identity.Principal{Issuer: "https://synthetic.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{3}, DecisionDigest: artifact.Digest{4}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	a.Environment = artifact.DownloadEnvironment{RootID: id, InstallationID: id, Region: "test", StoreID: id, RecoveryEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Principal: scope.Principal, Revision: rev, RecoveryRevision: rev, ObservedAt: now, ValidUntil: a.ValidUntil}
	intent := value.DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: profile, Authority: a, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	job := value.DownloadWorkerJob{IntentID: id, UID: "job", Spec: artifact.Digest{5}}
	w := value.DownloadWorker{Intent: intent, Job: job, Binding: value.KeyWorkerBinding{InstallationID: id, DownloadID: id, ClusterID: id, Namespace: profile.Namespace, NamespaceUID: profile.NamespaceUID, ServiceAccount: profile.ServiceAccount, ServiceAccountUID: profile.ServiceAccountUID, Job: intent.JobName(), JobUID: job.UID, JobSpec: job.Spec, Pod: "worker", PodUID: id, PodSpec: artifact.Digest{6}}}
	if !w.Valid() {
		t.Fatal("invalid synthetic worker")
	}
	return w
}

type forwardLab struct {
	t                            *testing.T
	mode                         string
	ca, workerCA                 ownerTestCA
	pool                         fleet.OwnerPool
	binding                      fleet.OwnerBinding
	configuration                fleet.OwnerConfiguration
	server, client               *OwnerCredentials
	serverFixture, clientFixture *ownerCredentialFixture
	forwarder                    *OwnerForwarder
	srv                          *httptest.Server
	worker                       value.DownloadWorker
	lease                        value.WorkerOwnerLease
	csr                          []byte
	requests, lookups, dials     atomic.Int32
	started                      chan struct{}
	owner                        context.Context
	cancelOwner                  context.CancelFunc
	released                     atomic.Int32
}

func newForwardCredentialFixture(t *testing.T, ca ownerTestCA, now func() time.Time) *ownerCredentialFixture {
	return &ownerCredentialFixture{t: t, ca: ca, liveClock: now}
}

func TestForwardCredentialFixtureFollowsRenewalBoundary(t *testing.T) {
	boundary := time.Now().Add(time.Hour).UTC().Truncate(fleet.OwnerCertificatePeriod).Add(-fleet.OwnerCertificateRenewBefore)
	now := boundary.Add(-time.Second)
	clock := func() time.Time { return now }
	ca := newOwnerTestCA(t, now)
	f := newForwardCredentialFixture(t, ca, clock)
	p := ownerPermit(now, [][]byte{ca.cert.Raw}, artifact.Digest{1}, "client")
	c, err := NewOwnerCredentials(p.Binding, "client", ca.roots, f, f, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Fixture setup and credential enrollment can cross the renewal boundary.
	now = boundary.Add(time.Second)
	if err = c.Enroll(context.Background()); err != nil {
		t.Fatal("fixture issued for its stale setup clock", err)
	}
	got, err := c.Certificate()
	_, expected, _ := fleet.OwnerCertificateWindow(now)
	if err != nil || !got.NotAfter.Equal(expected) {
		t.Fatal("fixture did not follow the current signing window", err)
	}
}

func newForwardLab(t *testing.T, mode string) *forwardLab {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	ca := newOwnerTestCA(t, now)
	p := ownerPermit(now, [][]byte{ca.cert.Raw}, artifact.Digest{1}, "server")
	f := &forwardLab{t: t, mode: mode, ca: ca, workerCA: newOwnerTestCA(t, now), pool: p.Configuration.Configuration.Pool, binding: p.Binding, configuration: p.Configuration.Configuration, worker: forwardTestWorker(t), started: make(chan struct{}, 1)}
	f.owner, f.cancelOwner = context.WithCancel(context.Background())
	t.Cleanup(f.cancelOwner)
	var h *ownerrelay.Handler
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if mode == "lost-reply" {
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				c.Close()
			}
			return
		}
		if mode == "redirect" {
			w.Header().Set("Location", "https://elsewhere.invalid")
			w.WriteHeader(307)
			return
		}
		if mode == "bad-json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"credential":"not-a-certificate"}`))
			return
		}
		if mode == "huge-header" {
			w.Header().Set("X-Oversized", strings.Repeat("x", 8192))
			w.WriteHeader(200)
			return
		}
		var response http.ResponseWriter = w
		if strings.HasPrefix(mode, "stream-") {
			response = &badOwnerStream{w, mode}
		}
		h.ServeHTTP(response, r)
	}))
	_, port, _ := net.SplitHostPort(f.srv.Listener.Addr().String())
	f.pool.Port, _ = strconv.Atoi(port)
	f.configuration.Pool = f.pool
	build := func(usage string) (*OwnerCredentials, *ownerCredentialFixture) {
		fixture := newForwardCredentialFixture(t, ca, time.Now)
		binding := f.binding
		if usage == "client" {
			binding.PodUID = ownerOtherID
			binding.ProcessEpoch = ownerOtherID
		}
		fixture.mutateRegistration = func(o *fleet.OwnerRegistrationObservation) {
			o.Enrollment.Pool = f.pool
			o.Configuration.Configuration = f.configuration.Clone()
		}
		c, e := NewOwnerCredentials(binding, usage, ca.roots, fixture, fixture, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		if e = c.Enroll(context.Background()); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(c.Close)
		return c, fixture
	}
	f.server, f.serverFixture = build("server")
	f.client, f.clientFixture = build("client")
	reg := forwardRegistry(func(ctx context.Context, c fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
		fixture := f.serverFixture
		if c.Usage == "client" {
			fixture = f.clientFixture
		}
		out, err := fixture.ReadOwnerRegistration(ctx, c)
		n := time.Now()
		out.ObservedAt, out.FreshUntil = n, n.Add(5*time.Second)
		out.Configuration.ObservedAt, out.Configuration.FreshUntil = n, out.FreshUntil
		return out, err
	})
	routes := forwardRoutes(func(_ context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
		n := time.Now()
		cfg := fleet.OwnerConfigurationObservation{Configuration: f.configuration.Clone(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
		return fleet.OwnerRoute{Configuration: cfg, Endpoint: fleet.OwnerEndpoint{Binding: b, Pool: f.pool, Pod: "owner-1", ReplicaSetUID: ownerTestID, Addresses: []string{"10.0.0.8", "10.0.0.9"}, ObservedAt: n, FreshUntil: cfg.FreshUntil}, ObservedAt: n, FreshUntil: cfg.FreshUntil}, nil
	})
	guard := forwardGuard(func(_ context.Context, p fleet.OwnerPool) (fleet.OwnerProtection, error) {
		n := time.Now()
		return fleet.OwnerProtection{Pool: p, Digest: artifact.Digest{3}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
	})
	gate := &app.OwnerAuthenticator{Registry: reg, Routes: routes, Protection: guard, Now: time.Now}
	verifier, _ := NewOwnerPeerVerifier(ca.roots, ownerTestID, ownerTestID, ownerTestID, time.Now)
	n := time.Now().UTC()
	f.lease = value.WorkerOwnerLease{Request: value.WorkerOwnerRequest{ID: ownerTestID, InstallationID: ownerTestID, SessionID: ownerTestID, WorkerID: ownerTestID, PodUID: ownerTestID, ProcessEpoch: ownerTestID, Until: n.Add(29 * time.Second)}, Fence: 1, Started: n}
	operation := forwardOperation(func(ctx context.Context, l value.WorkerOwnerLease, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
		if !l.Equal(f.lease) || string(token) != "synthetic.pod.token" || !bytes.Equal(csr, f.csr) {
			t.Error("relay changed input")
			return nil, errors.New("changed")
		}
		select {
		case f.started <- struct{}{}:
		default:
		}
		if mode == "hold" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		req, e := x509.ParseCertificateRequest(csr)
		if e != nil {
			t.Error(e)
			return nil, e
		}
		target := forwardTarget(f.worker)
		_, until, _ := target.CertificateEpoch(time.Now())
		uri, _ := url.Parse("spiffe://asservat." + ownerTestID + "/key-client/acquisition/" + target.PodUID)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(17), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}, NotBefore: target.CreatedAt.Add(-time.Second), NotAfter: until}
		key := req.PublicKey
		if mode == "wrong-worker-key" {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			key = &k.PublicKey
		}
		if mode == "wrong-worker-id" {
			leaf.URIs[0], _ = url.Parse("spiffe://asservat." + ownerTestID + "/key-client/acquisition/" + ownerOtherID)
		}
		if mode == "wrong-worker-expiry" {
			leaf.NotAfter = leaf.NotAfter.Add(time.Minute)
		}
		ca := f.workerCA
		if mode == "wrong-worker-root" {
			ca = newOwnerTestCA(t, time.Now())
		}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca.cert, key, ca.key)
		if e != nil {
			t.Error(e)
			return nil, e
		}
		cert := value.WorkerCertificate{DER: der, Peer: value.KeyPeer{InstallationID: ownerTestID, PeerID: target.PodUID, Role: "acquisition", Certificate: artifact.Digest(sha256.Sum256(der)), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}}
		owned, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(f.owner, cancel)
		return forwardDelivery{owned, cert, func() { stop(); cancel(); f.released.Add(1) }}, nil
	})
	h, e := ownerrelay.NewHandler(f.binding, &OwnerRequestPeers{Verifier: verifier, Authenticator: gate, Server: f.server}, operation, time.Now, 2)
	if e != nil {
		t.Fatal(e)
	}
	f.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: f.server.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	outboundReg := forwardRegistry(func(ctx context.Context, c fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
		if mode == "retired-before" && c.Usage == "server" || mode == "retired-after" && f.requests.Load() > 0 || mode == "client-retired" && c.Usage == "client" {
			return fleet.OwnerRegistrationObservation{}, errors.New("retired")
		}
		o, e := reg.ReadOwnerRegistration(ctx, c)
		if mode == "root-removed" && c.Usage == "server" {
			o.Configuration.Configuration.IssuerRoots = [][]byte{f.workerCA.cert.Raw}
		}
		return o, e
	})
	outboundGate := &app.OwnerAuthenticator{Registry: outboundReg, Routes: routes, Protection: guard, Now: time.Now}
	lookup := forwardLookup(func(_ context.Context, s, w string) (value.WorkerOwnerLease, error) {
		count := f.lookups.Add(1)
		l := f.lease
		if mode == "stale-before" && count > 1 || mode == "stale-after" && f.requests.Load() > 0 {
			l.Fence++
		}
		if mode == "foreign-process" {
			l.Request.ProcessEpoch = ownerOtherID
		}
		return l, nil
	})
	workers := forwardWorkers(func(_ context.Context, s, w string) (value.DownloadWorkerIdentity, error) {
		n := time.Now()
		out := value.DownloadWorkerIdentity{Worker: f.worker, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
		if mode == "worker-changed" && f.requests.Load() > 0 {
			out.Worker.Binding.PodUID = ownerOtherID
		}
		return out, nil
	})
	control := workerTrustDocument(t, f.worker.Intent.Profile.ClusterID, f.workerCA)
	f.worker.Intent.Profile.ControlDigest, _ = WorkerControlDigest(map[string]string{"worker.json": string(control)})
	trust, err := NewWorkerTrustCatalog(ownerTestID, [][]byte{control})
	if err != nil {
		t.Fatal(err)
	}
	cfg := OwnerForwarderConfig{Pool: f.pool, WorkerTrust: trust, Client: f.client, OwnerRoots: ca.roots, Routes: routes, Authentication: outboundGate, Owners: lookup, Workers: workers, Now: time.Now, Concurrency: 1}
	if mode == "wrong-owner-root" {
		cfg.OwnerRoots = f.workerCA.roots
	}
	if mode == "unsafe-address" {
		cfg.Routes = forwardRoutes(func(c context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
			r, e := routes.CurrentOwnerRoute(c, b)
			r.Endpoint.Addresses = []string{"127.0.0.1"}
			return r, e
		})
	}
	f.forwarder, e = NewOwnerForwarder(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.forwarder.Close)
	// Test-only remapping of synthetic discovered addresses to the owned loopback
	// listener. Production constructors expose no dial callback or address override.
	f.forwarder.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		count := f.dials.Add(1)
		if network != "tcp" || (address != net.JoinHostPort("10.0.0.8", port) && address != net.JoinHostPort("10.0.0.9", port)) {
			t.Error("dialed untrusted address", address)
			return nil, errors.New("invalid dial")
		}
		if mode == "first-address-down" && count == 1 {
			return nil, errors.New("synthetic unreachable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.csr, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return f
}
func (f *forwardLab) forward(ctx context.Context) (value.WorkerCertificate, error) {
	return f.forwarder.ForwardWorkerEnrollment(ctx, ownerTestID, ownerTestID, ownerTestID, []byte("synthetic.pod.token"), f.csr)
}
func TestOwnerForwarderActualReceiver(t *testing.T) {
	for _, mode := range []string{"valid", "first-address-down", "retired-before", "client-retired", "retired-after", "root-removed", "stale-before", "stale-after", "worker-changed", "foreign-process", "wrong-owner-root", "unsafe-address", "wrong-worker-key", "wrong-worker-id", "wrong-worker-expiry", "wrong-worker-root", "lost-reply", "redirect", "bad-json", "huge-header"} {
		t.Run(mode, func(t *testing.T) {
			f := newForwardLab(t, mode)
			out, e := f.forward(context.Background())
			if mode == "valid" || mode == "first-address-down" {
				if e != nil || !out.Peer.Valid(time.Now()) || len(out.DER) == 0 {
					t.Fatal("forward failed", e)
				}
				if f.requests.Load() != 1 {
					t.Fatal("not exactly one POST")
				}
				return
			}
			if e == nil || len(out.DER) != 0 {
				t.Fatal("invalid result accepted")
			}
			want := int32(1)
			switch mode {
			case "retired-before", "client-retired", "root-removed", "stale-before", "foreign-process", "wrong-owner-root", "unsafe-address":
				want = 0
			}
			if f.requests.Load() != want {
				t.Fatal("sent credentials before authentication or replayed POST", f.requests.Load(), want)
			}
			if mode == "unsafe-address" && f.dials.Load() != 0 {
				t.Fatal("unsafe route dialed")
			}
		})
	}
}
func TestOwnerForwarderCancellationAndCapacity(t *testing.T) {
	f := newForwardLab(t, "hold")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := f.forward(ctx); done <- e }()
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("no POST")
	}
	if _, e := f.forward(context.Background()); !errors.Is(e, artifact.ErrDownloadCapacity) {
		t.Fatal("concurrency not bounded", e)
	}
	f.forwarder.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("closed forwarder returned a certificate")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt TLS/HTTP")
	}
	if f.requests.Load() != 1 {
		t.Fatal("replayed POST")
	}
	if _, e := f.forward(context.Background()); e == nil {
		t.Fatal("closed forwarder accepted work")
	}
}
func TestOwnerForwarderMalformedInputNeverDials(t *testing.T) {
	f := newForwardLab(t, "valid")
	f.csr = []byte("not-a-csr")
	if _, e := f.forward(context.Background()); e == nil || f.dials.Load() != 0 {
		t.Fatal("invalid CSR reached network")
	}
}

func TestOwnerForwarderCancellationBeforeTransmission(t *testing.T) {
	for _, mode := range []string{"root-after-dial", "root-after-lookup", "client-after-lookup", "caller-after-lookup"} {
		t.Run(mode, func(t *testing.T) {
			f := newForwardLab(t, "valid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "root-after-dial" {
				dial := f.forwarder.dial
				f.forwarder.dial = func(c context.Context, n, a string) (net.Conn, error) {
					conn, e := dial(c, n, a)
					f.forwarder.Close()
					return conn, e
				}
			} else {
				original := f.forwarder.config.Owners
				f.forwarder.config.Owners = forwardLookup(func(c context.Context, s, w string) (value.WorkerOwnerLease, error) {
					l, e := original.ReadWorkerOwner(c, s, w)
					if f.lookups.Load() == 2 {
						switch mode {
						case "root-after-lookup":
							f.forwarder.Close()
						case "client-after-lookup":
							f.client.Close()
						case "caller-after-lookup":
							cancel()
						}
					}
					return l, e
				})
			}
			if _, e := f.forward(ctx); e == nil || f.requests.Load() != 0 {
				t.Fatal("cancelled caller sent credentials", e, f.requests.Load())
			}
		})
	}
}
