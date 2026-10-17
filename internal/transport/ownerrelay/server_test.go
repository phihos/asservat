package ownerrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

const testID = "11111111-1111-4111-8111-111111111111"
const otherID = "22222222-2222-4222-8222-222222222222"

func testBinding() fleet.OwnerBinding {
	return fleet.OwnerBinding{InstallationID: testID, ClusterID: testID, IssuerEpoch: testID, PodUID: testID, ProcessEpoch: testID}
}

type servingFixture struct {
	cert     tls.Certificate
	metadata fleet.OwnerCertificate
}

func (s *servingFixture) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &s.cert, nil
}
func (s *servingFixture) ServingCertificate() (fleet.OwnerCertificate, error) { return s.metadata, nil }

type peerFixture struct {
	serverDenied, peerDenied atomic.Bool
	clock                    atomic.Int64
	calls                    atomic.Int32
}

func (p *peerFixture) now() time.Time { return time.Now().Add(time.Duration(p.clock.Load())) }
func (p *peerFixture) CheckOwnerServing(context.Context) (time.Time, error) {
	if p.serverDenied.Load() {
		return time.Time{}, errors.New("retired")
	}
	return p.now().Add(5 * time.Second), nil
}
func (p *peerFixture) AuthenticateOwnerRequest(_ context.Context, s *tls.ConnectionState) (fleet.AuthenticatedOwner, error) {
	p.calls.Add(1)
	if p.peerDenied.Load() || s == nil || len(s.VerifiedChains) == 0 {
		return fleet.AuthenticatedOwner{}, errors.New("retired")
	}
	n := p.now()
	b := testBinding()
	b.ProcessEpoch = otherID
	pool := fleet.OwnerPool{InstallationID: testID, ClusterID: testID, IssuerEpoch: testID, Namespace: "hub", NamespaceUID: testID, Service: "hub", ServiceUID: testID, Deployment: "hub", DeploymentUID: testID, ServiceAccount: "hub", AccountUID: testID, Port: 8443}
	cert := s.PeerCertificates[0]
	return fleet.AuthenticatedOwner{Certificate: fleet.OwnerCertificate{Binding: b, Usage: "client", Digest: artifact.Digest(sha256.Sum256(cert.Raw)), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}, EnrollmentID: testID, Pool: pool, Pod: "hub-1", ReplicaSetUID: testID, ConfigurationRevision: identity.Revision{UID: testID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}, nil
}

type enrollmentFunction func(context.Context, value.WorkerOwnerLease, []byte, []byte) (evidence.WorkerEnrollmentDelivery, error)

func (f enrollmentFunction) BeginOwnedWorkerEnrollment(c context.Context, l value.WorkerOwnerLease, t, k []byte) (evidence.WorkerEnrollmentDelivery, error) {
	return f(c, l, t, k)
}

type delivered struct {
	ctx    context.Context
	cert   value.WorkerCertificate
	closed *atomic.Int32
}

func (d *delivered) Context() context.Context             { return d.ctx }
func (d *delivered) Certificate() value.WorkerCertificate { return d.cert }
func (d *delivered) Close()                               { d.closed.Add(1) }
func fakeDelivery(ctx context.Context, closed *atomic.Int32) *delivered {
	b := []byte("synthetic-certificate-payload-only")
	n := time.Now()
	return &delivered{ctx, value.WorkerCertificate{DER: b, Peer: value.KeyPeer{InstallationID: testID, PeerID: testID, Role: "acquisition", Certificate: artifact.Digest(sha256.Sum256(b)), NotBefore: n.Add(-time.Minute), NotAfter: n.Add(20 * time.Minute)}}, closed}
}
func wireRequest() contracts.OwnerRelayRequest {
	n := time.Now().UTC()
	return contracts.OwnerRelayRequest{Format: contracts.OwnerRelayFormat, Locator: contracts.OwnerRelayLocator{RequestID: testID, PodUID: testID, ProcessEpoch: testID, Fence: 1, Started: n, Until: n.Add(29 * time.Second)}, Enrollment: contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: testID, SessionID: testID, WorkerID: testID, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), CSR: bytes.Repeat([]byte{1}, 32)}}
}
func tlsFixtures(t *testing.T) (*servingFixture, tls.Certificate, *x509.CertPool) {
	t.Helper()
	n := time.Now()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: n.Add(-time.Minute), NotAfter: n.Add(time.Hour)}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(raw)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(server bool) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: n.Add(-time.Minute), NotAfter: n.Add(20 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			leaf.SerialNumber = big.NewInt(3)
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.DNSNames = []string{"owner.invalid"}
		}
		b, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, k)
		if e != nil {
			t.Fatal(e)
		}
		parsed, _ := x509.ParseCertificate(b)
		return tls.Certificate{Certificate: [][]byte{b}, PrivateKey: key, Leaf: parsed}
	}
	server := issue(true)
	return &servingFixture{server, fleet.OwnerCertificate{Binding: testBinding(), Usage: "server", Digest: artifact.Digest(sha256.Sum256(server.Certificate[0])), NotBefore: server.Leaf.NotBefore, NotAfter: server.Leaf.NotAfter}}, issue(false), roots
}

type relayLab struct {
	url    string
	client *http.Client
	cancel context.CancelFunc
	done   chan error
	config *tls.Config
	peers  *peerFixture
}

func startRelay(t *testing.T, peers *peerFixture, f enrollmentFunction, connections, concurrency int) *relayLab {
	t.Helper()
	server, client, roots := tlsFixtures(t)
	handler, e := NewHandler(testBinding(), peers, f, peers.now, concurrency)
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, roots, server, handler, connections) }()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "owner.invalid", Certificates: []tls.Certificate{client}, ClientSessionCache: tls.NewLRUClientSessionCache(2)}
	tr := &http.Transport{TLSClientConfig: config, MaxConnsPerHost: 8}
	lab := &relayLab{"https://" + l.Addr().String(), &http.Client{Transport: tr, Timeout: 3 * time.Second}, cancel, done, config, peers}
	t.Cleanup(func() {
		cancel()
		tr.CloseIdleConnections()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Errorf("server exit: %v", e)
			}
		case <-time.After(6 * time.Second):
			t.Error("server failed to join")
		}
	})
	return lab
}
func (l *relayLab) send(t *testing.T, b []byte) (*http.Response, []byte) {
	t.Helper()
	r, _ := http.NewRequest("POST", l.url+contracts.OwnerRelayPath, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer synthetic.pod.token")
	resp, e := l.client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	var out []byte
	if resp.StatusCode == 200 {
		var frame contracts.OwnerRelayResponse
		frame, e = contracts.DecodeOwnerRelayResponse(resp.Body)
		if e == nil {
			out, e = contracts.EncodeOwnerRelayResponse(frame)
		}
	} else {
		out, e = io.ReadAll(resp.Body)
	}
	resp.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	return resp, out
}
func TestRelayRequestBoundaries(t *testing.T) {
	for _, mode := range []string{"valid", "revoked-before", "local-revoked-before", "revoked-during", "local-revoked-during", "operation-outlives-first-proof", "cancelled-owner", "foreign-owner", "stale-lease", "duplicate", "unknown", "huge"} {
		t.Run(mode, func(t *testing.T) {
			peers := &peerFixture{}
			var calls, closed atomic.Int32
			if mode == "revoked-before" {
				peers.peerDenied.Store(true)
			}
			if mode == "local-revoked-before" {
				peers.serverDenied.Store(true)
			}
			lab := startRelay(t, peers, func(ctx context.Context, l value.WorkerOwnerLease, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
				calls.Add(1)
				if l.Request.ID != testID || string(token) != "synthetic.pod.token" || len(csr) != 32 {
					t.Error("request changed")
				}
				switch mode {
				case "revoked-during":
					peers.peerDenied.Store(true)
				case "local-revoked-during":
					peers.serverDenied.Store(true)
				case "operation-outlives-first-proof":
					peers.clock.Store(int64(6 * time.Second))
				case "cancelled-owner":
					c, end := context.WithCancel(ctx)
					end()
					return fakeDelivery(c, &closed), nil
				}
				return fakeDelivery(ctx, &closed), nil
			}, 4, 2)
			in := wireRequest()
			if mode == "foreign-owner" {
				in.Locator.ProcessEpoch = otherID
			}
			if mode == "stale-lease" {
				in.Locator.Until = in.Locator.Started.Add(-time.Second)
			}
			b, _ := json.Marshal(in)
			switch mode {
			case "duplicate":
				b = append([]byte(`{"format":"x",`), b[1:]...)
			case "unknown":
				b = append([]byte(`{"callback":"https://other.invalid",`), b[1:]...)
			case "huge":
				b = bytes.Repeat([]byte{'x'}, contracts.OwnerRelayMaxRequest+1)
			}
			resp, out := lab.send(t, b)
			if mode == "valid" || mode == "operation-outlives-first-proof" {
				if resp.StatusCode != 200 {
					t.Fatalf("status %d", resp.StatusCode)
				}
				r, e := contracts.DecodeOwnerRelayResponse(bytes.NewReader(out))
				if e != nil || r.Format != contracts.OwnerRelayFormat || !time.Now().Before(r.Until) || r.Enrollment.Nonce != in.Enrollment.Nonce || len(r.Enrollment.Certificate) == 0 || !bytes.Contains(out, []byte(`"chain":[]`)) {
					t.Fatal("response", e)
				}
			} else if resp.StatusCode == 200 || len(out) != 0 {
				t.Fatal("rejected request returned certificate", resp.StatusCode)
			}
			limit := time.After(time.Second)
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for calls.Load() != closed.Load() {
				select {
				case <-tick.C:
				case <-limit:
					t.Fatal("delivery not released", calls.Load(), closed.Load())
				}
			}
			if mode == "valid" { // Later requests must repeat authorization, never cache it.
				before := peers.calls.Load()
				peers.peerDenied.Store(true)
				resp, _ = lab.send(t, b)
				if resp.StatusCode != 403 || peers.calls.Load() <= before || calls.Load() != 1 {
					t.Fatal("reuse bypassed current peer check")
				}
			}
		})
	}
}
func TestRelayCancellationClosesActiveRequests(t *testing.T) {
	started := make(chan struct{})
	released := make(chan struct{})
	lab := startRelay(t, &peerFixture{}, func(ctx context.Context, _ value.WorkerOwnerLease, _, _ []byte) (evidence.WorkerEnrollmentDelivery, error) {
		close(started)
		<-ctx.Done()
		close(released)
		return nil, ctx.Err()
	}, 2, 1)
	b, _ := json.Marshal(wireRequest())
	result := make(chan error, 1)
	go func() {
		r, _ := http.NewRequest("POST", lab.url+contracts.OwnerRelayPath, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer synthetic.token")
		resp, e := lab.client.Do(r)
		if resp != nil {
			resp.Body.Close()
		}
		if e == nil && resp.StatusCode == 200 {
			e = errors.New("cancelled operation succeeded")
		}
		result <- e
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("operation did not start")
	}
	// A concurrent admitted TLS client cannot allocate another active operation.
	resp, _ := lab.send(t, b)
	if resp.StatusCode != 429 {
		t.Fatal("concurrency not bounded", resp.StatusCode)
	}
	lab.cancel()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("operation not cancelled")
	}
	select {
	case e := <-result:
		if e != nil && e.Error() == "cancelled operation succeeded" {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("active socket not closed")
	}
}
func TestRelayTLSProfileAndConnectionLimit(t *testing.T) {
	var closed atomic.Int32
	lab := startRelay(t, &peerFixture{}, func(c context.Context, _ value.WorkerOwnerLease, _, _ []byte) (evidence.WorkerEnrollmentDelivery, error) {
		return fakeDelivery(c, &closed), nil
	}, 1, 1)
	address := lab.url[len("https://"):]
	raw, e := net.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	// First handshake establishes that the single slot is actually occupied.
	held := tls.Client(raw, lab.config.Clone())
	if e = held.Handshake(); e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	second, e := net.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	blocked := tls.Client(second, lab.config.Clone())
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	e = blocked.HandshakeContext(c)
	cancel()
	blocked.Close()
	if e == nil {
		t.Fatal("connection limit bypassed")
	}
	held.Close()
	for _, mode := range []string{"no-client", "tls12", "http2"} {
		config := lab.config.Clone()
		switch mode {
		case "no-client":
			config.Certificates = nil
		case "tls12":
			config.MinVersion = tls.VersionTLS12
			config.MaxVersion = tls.VersionTLS12
		case "http2":
			config.NextProtos = []string{"h2"}
		}
		tr := &http.Transport{TLSClientConfig: config}
		client := &http.Client{Transport: tr, Timeout: time.Second}
		resp, e := client.Get(lab.url)
		if resp != nil {
			resp.Body.Close()
		}
		tr.CloseIdleConnections()
		if e == nil {
			t.Errorf("TLS profile accepted %s", mode)
		}
	}
	// Independent new handshakes must not resume a previous authenticated session.
	for i := 0; i < 2; i++ {
		b, _ := json.Marshal(wireRequest())
		resp, _ := lab.send(t, b)
		if resp.StatusCode != 200 || resp.TLS.DidResume {
			t.Fatal("resumed session or failed request")
		}
		lab.client.CloseIdleConnections()
	}
}
func TestConnectionDeadlineCannotBeExtended(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	until := time.Now().Add(40 * time.Millisecond)
	c := &lifetimeConn{Conn: a, ctx: ctx, cancel: cancel, until: until}
	defer c.Close()
	if e := c.SetReadDeadline(time.Time{}); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	_, e := c.Read(make([]byte, 1))
	if e == nil || time.Since(start) > time.Second {
		t.Fatal("cleared absolute deadline", e)
	}
}

// net.Pipe makes a response write block deterministically, without assuming
// kernel TCP buffer sizes or deliberately overflowing the certificate bounds.
type oneListener struct {
	conn     net.Conn
	accepted atomic.Bool
	done     chan struct{}
	once     sync.Once
}

func (l *oneListener) Accept() (net.Conn, error) {
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneListener) Addr() net.Addr { return l.conn.LocalAddr() }

type noticeConn struct {
	net.Conn
	observe atomic.Bool
	writing chan struct{}
}

func (c *noticeConn) Write(b []byte) (int, error) {
	if c.observe.Load() {
		select {
		case c.writing <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(b)
}
func TestRelayOwnerCancellationInterruptsBlockedTLSResponse(t *testing.T) {
	peers := &peerFixture{}
	server, client, roots := tlsFixtures(t)
	var released atomic.Int32
	ownerCancel := make(chan context.CancelFunc, 1)
	h, err := NewHandler(testBinding(), peers, enrollmentFunction(func(ctx context.Context, _ value.WorkerOwnerLease, _, _ []byte) (evidence.WorkerEnrollmentDelivery, error) {
		owner, cancel := context.WithCancel(ctx)
		ownerCancel <- cancel
		return fakeDelivery(owner, &released), nil
	}), time.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	observed := &noticeConn{Conn: a, writing: make(chan struct{}, 1)}
	l := &oneListener{conn: observed, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, roots, server, h, 1) }()
	tlsClient := tls.Client(b, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "owner.invalid", Certificates: []tls.Certificate{client}})
	t.Cleanup(func() {
		cancel()
		tlsClient.Close()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Error(e)
			}
		case <-time.After(6 * time.Second):
			t.Error("blocked receiver failed to join")
		}
	})
	handshake, end := context.WithTimeout(ctx, time.Second)
	defer end()
	if err = tlsClient.HandshakeContext(handshake); err != nil {
		t.Fatal(err)
	}
	observed.observe.Store(true)
	body, _ := json.Marshal(wireRequest())
	request, _ := http.NewRequest("POST", "https://owner.invalid"+contracts.OwnerRelayPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer synthetic.token")
	if err = request.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	select {
	case <-observed.writing:
	case <-time.After(time.Second):
		t.Fatal("response never blocked on TLS write")
	}
	var stop context.CancelFunc
	select {
	case stop = <-ownerCancel:
	case <-time.After(time.Second):
		t.Fatal("missing delivery owner")
	}
	stop()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for released.Load() == 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("owner cancellation did not release blocked response")
		}
	}
	if released.Load() != 1 {
		t.Fatal("delivery released more than once")
	}
}
