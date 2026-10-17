package mtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
)

type ConnectorProcessAdmitter interface {
	Enroll(context.Context, string, value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error)
}
type ConnectorProcessIssuer interface {
	IssueProcess(context.Context, string, string, value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error)
}
type connectorOwnedStep struct {
	id     string
	issued *value.IssuedConnectorCredential
}
type connectorOwnedProcess struct {
	request     value.ConnectorProcessRequest
	admissionID string
	process     value.ConnectorCredentialProcess
	keys        [2]*ecdsa.PrivateKey
	steps       [2]connectorOwnedStep
	certs       [2]*tls.Certificate
	installed   [2]value.ConnectorCredentialCertificate
	retired     bool
}

// ConnectorProcessCredentials owns a client/server key pair, one pending
// replacement and the original request IDs. It never exports private keys or
// creates SQL authority. The runtime must suppress core dumps before creation.
// Every use of a returned TLS identity still needs the actual peer/registry gate.
type ConnectorProcessCredentials struct {
	mu              sync.Mutex
	root            context.Context
	stop            context.CancelFunc
	profile         value.ConnectorCredentialProfile
	podUID          string
	admit           ConnectorProcessAdmitter
	issuer          ConnectorProcessIssuer
	source          app.ConnectorIdentitySourceReader
	registry        app.ConnectorLeafRegistry
	verifier        *ConnectorCredentialVerifier
	now             func() time.Time
	active, pending *connectorOwnedProcess
	inFlight        chan struct{}
	cancel          context.CancelFunc
	lastAttempt     time.Time
	closed          bool
}

func NewConnectorProcessCredentials(ctx context.Context, p value.ConnectorCredentialProfile, podUID string, admit ConnectorProcessAdmitter, issuer ConnectorProcessIssuer, source app.ConnectorIdentitySourceReader, registry app.ConnectorLeafRegistry, now func() time.Time) (*ConnectorProcessCredentials, error) {
	if ctx == nil || ctx.Err() != nil || !p.Valid() || p.Suspended || !authorization.UUID(podUID) || admit == nil || issuer == nil || source == nil || registry == nil || now == nil {
		return nil, value.ErrInvalid
	}
	verifier, e := NewConnectorCredentialVerifier(p, now)
	if e != nil {
		return nil, e
	}
	root, stop := context.WithCancel(ctx)
	return &ConnectorProcessCredentials{root: root, stop: stop, profile: p.Clone(), podUID: podUID, admit: admit, issuer: issuer, source: source, registry: registry, verifier: verifier, now: now}, nil
}
func newConnectorOwnedProcess(binding value.PeerBinding, podUID string) (*connectorOwnedProcess, error) {
	p := &connectorOwnedProcess{admissionID: uuid.NewString(), request: value.ConnectorProcessRequest{Process: value.ConnectorProcessIdentity{Binding: binding, PodUID: podUID, ProcessEpoch: uuid.NewString()}}}
	for i := range p.keys {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		p.keys[i] = key
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			return nil, e
		}
		if _, e = EnrollmentKey(csr); e != nil {
			return nil, e
		}
		if i == 0 {
			p.request.ClientCSRDER = csr
		} else {
			p.request.ServerCSRDER = csr
		}
	}
	return p, nil
}

// Reconcile does at most one original admission and one exact call per purpose.
// A lost reply retains its IDs; no uncertain signature is repeated under a new
// ID. A new process is a separate bounded admission, with prior spend retained.
func (c *ConnectorProcessCredentials) Reconcile(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return value.ErrInvalid
	}
	c.mu.Lock()
	start := c.now()
	if c.closed || c.root.Err() != nil || c.inFlight != nil || !c.lastAttempt.IsZero() && start.Before(c.lastAttempt.Add(time.Second)) {
		c.mu.Unlock()
		return value.ErrUnavailable
	}
	live, cancel := context.WithDeadline(ctx, start.Add(30*time.Second))
	stopped := make(chan struct{})
	stopRoot := context.AfterFunc(c.root, func() { cancel(); close(stopped) })
	done := make(chan struct{})
	c.inFlight, c.cancel, c.lastAttempt = done, cancel, start
	p := c.pending
	if p == nil && c.active != nil && start.Before(c.active.process.RunUntil.Add(-time.Minute)) {
		p = c.active
	}
	c.mu.Unlock()
	defer func() {
		cancel()
		if !stopRoot() {
			<-stopped
		}
		c.mu.Lock()
		c.inFlight, c.cancel = nil, nil
		close(done)
		c.mu.Unlock()
	}()
	if p == nil {
		var e error
		p, e = newConnectorOwnedProcess(c.profile.Binding, c.podUID)
		if e != nil {
			return e
		}
		c.mu.Lock()
		if c.closed || live.Err() != nil {
			c.mu.Unlock()
			return value.ErrUnavailable
		}
		c.pending = p
		c.mu.Unlock()
	}
	if !p.process.Valid() {
		admitted, e := c.admit.Enroll(live, p.admissionID, cloneConnectorRequest(p.request))
		if e != nil {
			return e
		}
		client, e1 := EnrollmentKey(p.request.ClientCSRDER)
		server, e2 := EnrollmentKey(p.request.ServerCSRDER)
		if e1 != nil || e2 != nil || !admitted.Valid() || admitted.Attested == nil || *admitted.Attested != p.request.Process || admitted.ClientKeyDigest != client || admitted.ServerKeyDigest != server || !c.now().Before(admitted.RunUntil) || live.Err() != nil {
			return value.ErrDenied
		}
		c.mu.Lock()
		origin := *admitted.Attested
		admitted.Attested = &origin
		p.process = admitted
		c.mu.Unlock()
	}
	_, window, e := p.process.Window(c.now())
	if e != nil {
		return e
	}
	source, e := c.source.ReadConnectorIdentitySource(live)
	if e != nil || !source.Valid(c.now()) || source.Observation.Profile.Binding != c.profile.Binding || source.Observation.Profile.RootID != c.profile.RootID || source.Observation.Profile.Revision.UID != c.profile.Revision.UID || source.Observation.Profile.ServerName != c.profile.ServerName {
		return value.ErrUnavailable
	}
	var checked [2]*tls.Certificate
	for i, usage := range []string{"client", "server"} {
		c.mu.Lock()
		step := p.steps[i]
		if step.id == "" || step.issued != nil && !step.issued.Certificate.NotAfter.Equal(window) {
			step = connectorOwnedStep{id: uuid.NewString()}
			p.steps[i] = step
		}
		c.mu.Unlock()
		if step.issued == nil {
			out, e := c.issuer.IssueProcess(live, step.id, usage, cloneConnectorRequest(p.request))
			if e != nil {
				return e
			}
			out = out.Clone()
			step.issued = &out
			c.mu.Lock()
			p.steps[i] = step
			c.mu.Unlock()
		}
		// Revalidate all public material against pinned and current roots. The SQL
		// registry below independently binds the exact activated process and leaf.
		current, e := c.source.ReadConnectorIdentitySource(live)
		if e != nil || !current.Valid(c.now()) || !current.Observation.SameSource(source.Observation) || current.Roles != source.Roles {
			return value.ErrUnavailable
		}
		checked[i], e = c.checkOwned(p, i, *step.issued, current.Observation)
		if e != nil {
			return e
		}
	}
	until := start.Add(30 * time.Second)
	for i := range checked {
		registration, e := c.registry.ConnectorLeafRegistration(live, p.steps[i].issued.Certificate)
		if e != nil || !registration.Valid(c.now()) || registration.Process != p.request.Process || registration.Certificate != p.steps[i].issued.Certificate || registration.Revision != source.Observation.Profile.Revision {
			return value.ErrUnavailable
		}
		until = identity.Earlier(until, registration.FreshUntil)
	}
	final, e := c.source.ReadConnectorIdentitySource(live)
	if e != nil || !final.Valid(c.now()) || !final.Observation.SameSource(source.Observation) || final.Roles != source.Roles {
		return value.ErrUnavailable
	}
	until = identity.Earlier(until, final.Observation.FreshUntil)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || live.Err() != nil || c.now().Before(start) || !c.now().Before(until) || !c.now().Before(p.process.RunUntil) {
		return value.ErrUnavailable
	}
	for i, cert := range checked {
		cert.PrivateKey = &connectorProcessSigner{owner: c, process: p, purpose: i, identity: p.steps[i].issued.Certificate, publicDER: bytes.Clone(cert.Leaf.RawSubjectPublicKeyInfo)}
		p.certs[i] = cert
		p.installed[i] = p.steps[i].issued.Certificate
	}
	if c.active != nil && c.active != p {
		c.active.retired = true
		c.active.keys = [2]*ecdsa.PrivateKey{}
		c.active.certs = [2]*tls.Certificate{}
	}
	c.active = p
	if c.pending == p {
		c.pending = nil
	}
	return nil
}
func cloneConnectorRequest(r value.ConnectorProcessRequest) value.ConnectorProcessRequest {
	r.ClientCSRDER = bytes.Clone(r.ClientCSRDER)
	r.ServerCSRDER = bytes.Clone(r.ServerCSRDER)
	return r
}
func (c *ConnectorProcessCredentials) checkOwned(p *connectorOwnedProcess, i int, out value.IssuedConnectorCredential, current value.ConnectorCredentialObservation) (*tls.Certificate, error) {
	if !current.Valid(c.now()) || len(out.DER) == 0 || len(out.DER) > 16<<10 || len(out.ChainDER) > 3 {
		return nil, value.ErrDenied
	}
	raw := append([][]byte{out.DER}, out.ChainDER...)
	chain := make([]*x509.Certificate, len(raw))
	total := 0
	for n, b := range raw {
		total += len(b)
		if len(b) == 0 || len(b) > 16<<10 || total > 32<<10 {
			return nil, value.ErrDenied
		}
		var e error
		chain[n], e = x509.ParseCertificate(bytes.Clone(b))
		if e != nil {
			return nil, e
		}
	}
	usage, csr, roots := "client", p.request.ClientCSRDER, current.Profile.ClientIssuerRoots
	if i == 1 {
		usage, csr, roots = "server", p.request.ServerCSRDER, current.Profile.ServerIssuerRoots
	}
	currentRoots, _, e := OwnerTrustRoots(roots, c.now())
	if e != nil {
		return nil, e
	}
	cert, e := c.verifier.verify(chain, usage, currentRoots)
	key, ke := EnrollmentKey(csr)
	if e != nil || ke != nil || cert != out.Certificate || cert.Binding != p.request.Process.Binding || cert.PublicKeyDigest != key || cert.NotAfter.After(p.process.RunUntil) {
		return nil, value.ErrDenied
	}
	copied := make([][]byte, len(raw))
	for n, b := range raw {
		copied[n] = bytes.Clone(b)
	}
	return &tls.Certificate{Certificate: copied, Leaf: chain[0]}, nil
}
func (c *ConnectorProcessCredentials) snapshot(i int) (*tls.Certificate, error) {
	if c == nil {
		return nil, value.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || c.active == nil || c.active.retired || c.active.certs[i] == nil || !c.now().Before(c.active.process.RunUntil) || !c.active.installed[i].Valid(c.now()) {
		return nil, value.ErrUnavailable
	}
	out := *c.active.certs[i]
	out.Certificate = make([][]byte, len(out.Certificate))
	for n, b := range c.active.certs[i].Certificate {
		out.Certificate[n] = bytes.Clone(b)
	}
	out.Leaf, _ = x509.ParseCertificate(out.Certificate[0])
	return &out, nil
}
func (c *ConnectorProcessCredentials) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if info == nil || info.Context().Err() != nil {
		return nil, value.ErrInvalid
	}
	cert, e := c.snapshot(0)
	if e != nil {
		return nil, e
	}
	if e = info.SupportsCertificate(cert); e != nil {
		return nil, e
	}
	return cert, nil
}
func (c *ConnectorProcessCredentials) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if info == nil || info.Context().Err() != nil {
		return nil, value.ErrInvalid
	}
	cert, e := c.snapshot(1)
	if e != nil {
		return nil, e
	}
	if e = info.SupportsCertificate(cert); e != nil {
		return nil, e
	}
	return cert, nil
}
func (c *ConnectorProcessCredentials) Certificate() (value.PeerCertificate, error) {
	cert, e := c.snapshot(0)
	if e != nil {
		return value.PeerCertificate{}, e
	}
	return value.PeerCertificate{Binding: c.profile.Binding, Digest: artifact.Digest(sha256.Sum256(cert.Certificate[0])), NotBefore: cert.Leaf.NotBefore, NotAfter: cert.Leaf.NotAfter}, nil
}

// Run performs rate-bounded reconciliation. Unavailability retains the active
// original leaf until its own expiry; it never renews that leaf's authority.
func (c *ConnectorProcessCredentials) Run(ctx context.Context) error {
	if c == nil || ctx == nil {
		return value.ErrInvalid
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_ = c.Reconcile(ctx)
		select {
		case <-ctx.Done():
			c.Close()
			return ctx.Err()
		case <-c.root.Done():
			c.Close()
			return c.root.Err()
		case <-ticker.C:
		}
	}
}
func (c *ConnectorProcessCredentials) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.stop()
	if c.cancel != nil {
		c.cancel()
	}
	done := c.inFlight
	for _, p := range []*connectorOwnedProcess{c.active, c.pending} {
		if p != nil {
			p.retired = true
			p.keys = [2]*ecdsa.PrivateKey{}
			p.certs = [2]*tls.Certificate{}
		}
	}
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

type connectorProcessSigner struct {
	owner     *ConnectorProcessCredentials
	process   *connectorOwnedProcess
	purpose   int
	identity  value.ConnectorCredentialCertificate
	publicDER []byte
}

func (s *connectorProcessSigner) Public() crypto.PublicKey {
	p, _ := x509.ParsePKIXPublicKey(bytes.Clone(s.publicDER))
	return p
}
func (s *connectorProcessSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || s.process.retired || s.process.keys[s.purpose] == nil || !s.identity.Valid(c.now()) || !c.now().Before(s.process.process.RunUntil) || opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, value.ErrDenied
	}
	out, e := s.process.keys[s.purpose].Sign(rand.Reader, digest, opts)
	if e != nil || !s.identity.Valid(c.now()) || c.root.Err() != nil {
		return nil, value.ErrDenied
	}
	return out, nil
}
