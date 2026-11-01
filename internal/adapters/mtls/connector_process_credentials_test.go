package mtls

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Actual process keys, certificate verification and TLS are exercised here.
// The fixture admission, provider and registry are explicitly synthetic; SQL
// role/activation and real Kubernetes proof remain separate qualification.
type connectorPairFixture struct {
	t                    *testing.T
	mu                   sync.Mutex
	now                  time.Time
	advance              atomic.Int64
	realClock            atomic.Bool
	revoked              atomic.Bool
	clientCA, serverCA   ownerTestCA
	profile              value.ConnectorCredentialProfile
	roles                value.ConnectorIdentityRoles
	processes            map[string]value.ConnectorCredentialProcess
	admitted             map[string]value.ConnectorCredentialProcess
	requests             map[string]value.ConnectorProcessRequest
	issued               map[string]value.IssuedConnectorCredential
	origins              map[artifact.Digest]value.ConnectorProcessIdentity
	active               value.ConnectorProcessIdentity
	calls                map[string]int
	loseAdmission        bool
	blockServer, release chan struct{}
	oldDuringPending     func()
}

func newConnectorPairFixture(t *testing.T) *connectorPairFixture {
	n := time.Now().UTC().Truncate(time.Second)
	f := &connectorPairFixture{t: t, now: n, clientCA: newOwnerTestCA(t, n), serverCA: newOwnerTestCA(t, n), processes: map[string]value.ConnectorCredentialProcess{}, admitted: map[string]value.ConnectorCredentialProcess{}, requests: map[string]value.ConnectorProcessRequest{}, issued: map[string]value.IssuedConnectorCredential{}, origins: map[artifact.Digest]value.ConnectorProcessIdentity{}, calls: map[string]int{}}
	f.profile = connectorPermit(n, [][]byte{f.clientCA.cert.Raw}, artifact.Digest{1}, "server").Configuration.Profile
	f.profile.ServerIssuerRoots = [][]byte{f.serverCA.cert.Raw}
	f.roles = value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}
	return f
}
func (f *connectorPairFixture) clock() time.Time {
	if f.realClock.Load() {
		return time.Now().UTC()
	}
	return f.now.Add(time.Duration(f.advance.Load()))
}
func (f *connectorPairFixture) owner() *ConnectorProcessCredentials {
	c, e := NewConnectorProcessCredentials(context.Background(), f.profile, ownerTestID, f, f, f, f, f.clock)
	if e != nil {
		f.t.Fatal(e)
	}
	f.t.Cleanup(c.Close)
	return c
}
func (f *connectorPairFixture) Enroll(ctx context.Context, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[id]++
	if old, ok := f.requests[id]; ok && (old.Process != r.Process || string(old.ClientCSRDER) != string(r.ClientCSRDER) || string(old.ServerCSRDER) != string(r.ServerCSRDER)) {
		return value.ConnectorCredentialProcess{}, value.ErrDenied
	}
	if p, ok := f.admitted[id]; ok {
		return p, nil
	}
	a, e := EnrollmentKey(r.ClientCSRDER)
	b, be := EnrollmentKey(r.ServerCSRDER)
	if e != nil || be != nil || a == b || ctx.Err() != nil {
		return value.ConnectorCredentialProcess{}, value.ErrDenied
	}
	n := f.clock()
	p := value.ConnectorCredentialProcess{Attested: &r.Process, Binding: r.Process.Binding, ClientKeyDigest: a, ServerKeyDigest: b, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute), RunUntil: n.Add(33 * time.Minute)}
	f.requests[id] = cloneConnectorRequest(r)
	f.admitted[id] = p
	f.processes[r.Process.ProcessEpoch] = p
	if f.loseAdmission {
		f.loseAdmission = false
		return value.ConnectorCredentialProcess{}, value.ErrUnavailable
	}
	return p, nil
}
func (f *connectorPairFixture) IssueProcess(ctx context.Context, id, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	f.mu.Lock()
	f.calls[id]++
	if out, ok := f.issued[id]; ok {
		f.mu.Unlock()
		return out.Clone(), nil
	}
	p := f.processes[r.Process.ProcessEpoch]
	f.mu.Unlock()
	if usage == "server" && f.oldDuringPending != nil {
		f.oldDuringPending()
	}
	if usage == "server" && f.blockServer != nil {
		close(f.blockServer)
		<-ctx.Done()
		<-f.release
		return value.IssuedConnectorCredential{}, ctx.Err()
	}
	csr, ca := r.ClientCSRDER, f.clientCA
	eku := x509.ExtKeyUsageClientAuth
	name := ""
	if usage == "server" {
		csr, ca, eku, name = r.ServerCSRDER, f.serverCA, x509.ExtKeyUsageServerAuth, f.profile.ServerName
	}
	q, e := x509.ParseCertificateRequest(csr)
	if e != nil {
		return value.IssuedConnectorCredential{}, e
	}
	key, e := EnrollmentKey(csr)
	if e != nil {
		return value.IssuedConnectorCredential{}, e
	}
	_, until, e := p.Window(f.clock())
	if e != nil {
		return value.IssuedConnectorCredential{}, e
	}
	uri, _ := PeerURI(r.Process.Binding)
	template := &x509.Certificate{SerialNumber: big.NewInt(int64(len(f.issued) + 10)), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{uri}, NotBefore: f.clock().Add(-time.Second), NotAfter: until}
	if name != "" {
		template.DNSNames = []string{name}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, ca.cert, q.PublicKey, ca.key)
	if e != nil {
		return value.IssuedConnectorCredential{}, e
	}
	out := value.IssuedConnectorCredential{Certificate: value.ConnectorCredentialCertificate{Binding: r.Process.Binding, Usage: usage, ServerName: name, Digest: artifact.Digest(sha256.Sum256(der)), PublicKeyDigest: key, NotBefore: template.NotBefore, NotAfter: template.NotAfter}, DER: der, ChainDER: [][]byte{ca.cert.Raw}}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued[id] = out
	f.origins[out.Certificate.Digest] = r.Process
	client, server := false, false
	for _, leaf := range f.issued {
		if f.origins[leaf.Certificate.Digest] == r.Process {
			client = client || leaf.Certificate.Usage == "client"
			server = server || leaf.Certificate.Usage == "server"
		}
	}
	if client && server {
		f.active = r.Process
	}
	return out.Clone(), nil
}
func (f *connectorPairFixture) ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error) {
	now := f.clock()
	return value.ConnectorIdentitySource{Observation: value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: f.profile.Clone(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Roles: f.roles}, nil
}
func (f *connectorPairFixture) ConnectorLeafRegistration(_ context.Context, c value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	now := f.clock()
	f.mu.Lock()
	defer f.mu.Unlock()
	origin, ok := f.origins[c.Digest]
	if f.revoked.Load() || !ok || origin != f.active || !c.Valid(f.clock()) {
		return app.ConnectorLeafRegistration{}, value.ErrDenied
	}
	return app.ConnectorLeafRegistration{Certificate: c, Process: origin, Revision: f.profile.Revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func TestConnectorPairedProcessKeysRenewAndAutomaticallyReplace(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	f.loseAdmission = true
	if c.Reconcile(context.Background()) == nil {
		t.Fatal("lost admission reply accepted")
	}
	f.advance.Store(int64(2 * time.Second))
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	first, _ := c.snapshot(0)
	server, _ := c.snapshot(1)
	if string(first.Leaf.RawSubjectPublicKeyInfo) == string(server.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("client/server key reused")
	}
	f.advance.Store(int64(29 * time.Minute))
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal("renew", e)
	}
	renewed, _ := c.snapshot(0)
	if string(first.Leaf.RawSubjectPublicKeyInfo) != string(renewed.Leaf.RawSubjectPublicKeyInfo) || !renewed.Leaf.NotAfter.Equal(f.now.Add(33*time.Minute)) {
		t.Fatal("renewal lost original process bounds")
	}
	oldProcess := f.active
	checkedOld := false
	f.oldDuringPending = func() {
		if _, e := c.snapshot(0); e != nil {
			t.Error("old serving credentials lost during replacement", e)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.active != oldProcess {
			t.Error("old serving process retired before complete pair")
		}
		checkedOld = true
	}
	f.advance.Store(int64(32 * time.Minute))
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal("automatic process replacement", e)
	}
	next, _ := c.snapshot(0)
	if !checkedOld || f.active == oldProcess || string(next.Leaf.RawSubjectPublicKeyInfo) == string(renewed.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("no distinct automatic epoch/key replacement")
	}
	sum := sha256.Sum256([]byte("synthetic signing challenge"))
	if _, e := renewed.PrivateKey.(crypto.Signer).Sign(rand.Reader, sum[:], crypto.SHA256); e == nil {
		t.Fatal("retired process retained signer")
	}
	if len(f.admitted) != 2 {
		t.Fatal("replacement changed more than bounded original admissions", len(f.admitted))
	}
}
func TestConnectorPairedCloseJoinsPendingProvider(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	f.blockServer = make(chan struct{})
	f.release = make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- c.Reconcile(context.Background()) }()
	<-f.blockServer
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close released before provider joined")
	case <-time.After(10 * time.Millisecond):
	}
	close(f.release)
	<-closed
	if <-result == nil {
		t.Fatal("cancelled issuance succeeded")
	}
	if _, e := c.snapshot(0); e == nil {
		t.Fatal("partial pair exposed after close")
	}
}
func TestConnectorPairedCredentialsActualDistinctTLS(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	peer, e := NewPeerVerifier(f.clientCA.roots, f.profile.Binding.InstallationID, value.ConnectorPeer, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual, e := peer.Verify(r.TLS)
		f.mu.Lock()
		allowed := e == nil && !f.revoked.Load() && actual.Binding == f.profile.Binding && f.origins[actual.Digest] == f.active
		f.mu.Unlock()
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: c.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.clientCA.roots, Time: f.clock}
	server.StartTLS()
	defer server.Close()
	verifier, e := NewConnectorCredentialVerifier(f.profile, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.serverCA.roots, ServerName: f.profile.ServerName, GetClientCertificate: c.GetClientCertificate, Time: f.clock}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	src, _ := f.ReadConnectorIdentitySource(context.Background())
	leaf, e := verifier.VerifyConnectorServer(response.TLS, src.Observation)
	if e != nil {
		response.Body.Close()
		t.Fatal("actual completed server handshake", e)
	}
	if _, e = f.ConnectorLeafRegistration(context.Background(), leaf); e != nil {
		response.Body.Close()
		t.Fatal("current server activation", e)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	f.revoked.Store(true)
	if r, e := client.Get(server.URL); e == nil {
		r.Body.Close()
		if r.StatusCode != http.StatusForbidden {
			t.Fatal("actual current revocation ignored", r.StatusCode)
		}
	}
}
