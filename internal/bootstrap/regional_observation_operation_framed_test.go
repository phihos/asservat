package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// This fixture composes the actual outbound client, h2 stream, holder, bootstrap
// binding, coordinator, private operation channel and regional executor. Native
// observations, SQL registration, source provisioning and CA issuance remain
// explicit synthetic facts. No native or installed availability is inferred.
type framedRegionalFixture struct {
	base                                          *runtimeFixture
	pin                                           value.ConnectorObservationPin
	now                                           time.Time
	mu                                            sync.Mutex
	process                                       value.ConnectorCredentialProcess
	issued                                        map[artifact.Digest]value.IssuedConnectorCredential
	identity                                      value.ConnectorProcessIdentity
	client, server                                bool
	pairs, opens, reads, finals, closes, metadata atomic.Int32
	mode                                          string
}

func (f *framedRegionalFixture) Enroll(ctx context.Context, _ string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	a, e := mtls.EnrollmentKey(r.ClientCSRDER)
	b, be := mtls.EnrollmentKey(r.ServerCSRDER)
	if e != nil || be != nil || a == b || ctx.Err() != nil {
		return value.ConnectorCredentialProcess{}, value.ErrDenied
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity = r.Process
	f.process = value.ConnectorCredentialProcess{Attested: &r.Process, Binding: r.Process.Binding, ClientKeyDigest: a, ServerKeyDigest: b, ClaimedAt: f.now, InitialCertificateNotAfter: f.now.Add(30 * time.Minute), RunUntil: f.now.Add(33 * time.Minute)}
	return f.process, nil
}
func (f *framedRegionalFixture) IssueProcess(ctx context.Context, _ string, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, eku, name := r.ClientCSRDER, x509.ExtKeyUsageClientAuth, ""
	if usage == "server" {
		raw, eku, name = r.ServerCSRDER, x509.ExtKeyUsageServerAuth, f.pin.Profile.ServerName
	}
	csr, e := x509.ParseCertificateRequest(raw)
	key, ke := mtls.EnrollmentKey(raw)
	if e != nil || ke != nil || ctx.Err() != nil || r.Process != f.identity {
		return value.IssuedConnectorCredential{}, value.ErrDenied
	}
	_, until, e := f.process.Window(f.now)
	if e != nil {
		return value.IssuedConnectorCredential{}, e
	}
	uri, _ := mtls.PeerURI(r.Process.Binding)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + len(f.issued))), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{uri}, NotBefore: f.now.Add(-time.Second), NotAfter: until}
	if name != "" {
		leaf.DNSNames = []string{name}
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, f.base.ca, csr.PublicKey, f.base.key)
	if e != nil {
		return value.IssuedConnectorCredential{}, e
	}
	out := value.IssuedConnectorCredential{Certificate: value.ConnectorCredentialCertificate{Binding: r.Process.Binding, Usage: usage, ServerName: name, Digest: artifact.Digest(sha256.Sum256(der)), PublicKeyDigest: key, NotBefore: leaf.NotBefore, NotAfter: until}, DER: der, ChainDER: [][]byte{f.base.ca.Raw}}
	f.issued[out.Certificate.Digest] = out
	if usage == "client" {
		f.client = true
	} else {
		f.server = true
	}
	return out, nil
}
func (f *framedRegionalFixture) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	if ctx.Err() != nil {
		return value.ConnectorIdentitySource{}, ctx.Err()
	}
	now := time.Now()
	return value.ConnectorIdentitySource{Observation: value.ConnectorCredentialObservation{Profile: f.pin.Profile.Clone(), Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Roles: f.pin.Roles}, nil
}
func (f *framedRegionalFixture) ConnectorLeafRegistration(ctx context.Context, c value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	issued, ok := f.issued[c.Digest]
	if !ok || issued.Certificate != c || !f.client || !f.server || ctx.Err() != nil {
		return app.ConnectorLeafRegistration{}, value.ErrUnavailable
	}
	now := time.Now()
	return app.ConnectorLeafRegistration{Certificate: c, Process: f.identity, Revision: f.pin.Profile.Revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *framedRegionalFixture) ReadConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, source app.ConnectorObservationOperationSource, leaf value.ConnectorCredentialCertificate, n int) (app.ConnectorObservationOperationRegistration, error) {
	f.pairs.Add(1)
	first, e := source.ReadConnectorObservationValue(ctx, n)
	if e != nil {
		return app.ConnectorObservationOperationRegistration{}, e
	}
	registration, e := f.ConnectorLeafRegistration(ctx, leaf)
	if e != nil {
		return app.ConnectorObservationOperationRegistration{}, e
	}
	last, e := source.ReadConnectorObservationValue(ctx, n+1)
	if e != nil || !first.Matches(f.pin, r, n, time.Now()) || !last.Matches(f.pin, r, n+1, time.Now()) || !last.Continues(first) {
		return app.ConnectorObservationOperationRegistration{}, value.ErrUnavailable
	}
	if f.mode == "sql-final" && n == 3 {
		return app.ConnectorObservationOperationRegistration{}, value.ErrUnavailable
	}
	registration.FreshUntil = identity.Earlier(registration.FreshUntil, last.Until())
	return app.ConnectorObservationOperationRegistration{Registration: registration, Last: last}, nil
}

type framedRegionalNative struct {
	f          *framedRegionalFixture
	root       context.Context
	cancel     context.CancelFunc
	request    value.OwnerObservationRequest
	process    value.ConnectorProcessIdentity
	start, end time.Time
	once       sync.Once
}

func (f *framedRegionalFixture) OpenConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, p value.ConnectorProcessIdentity) (app.ConnectorNativeObservationOperation, error) {
	f.opens.Add(1)
	root, cancel := context.WithCancel(ctx)
	end, _ := ctx.Deadline()
	return &framedRegionalNative{f: f, root: root, cancel: cancel, request: r, process: p, start: time.Now(), end: identity.Earlier(end, r.NotAfter)}, nil
}
func (o *framedRegionalNative) Read(ctx context.Context, n int) (value.ConnectorObservationNativeValue, error) {
	o.f.reads.Add(1)
	if n == 4 {
		o.f.finals.Add(1)
	}
	if ctx.Err() != nil || o.root.Err() != nil {
		return value.ConnectorObservationNativeValue{}, value.ErrUnavailable
	}
	source, e := o.f.ReadConnectorIdentitySource(ctx)
	if e != nil {
		return value.ConnectorObservationNativeValue{}, e
	}
	end, _ := ctx.Deadline()
	o.end = identity.Earlier(o.end, end)
	source.Observation.FreshUntil = o.end
	workload := value.ConnectorObservationWorkload{Process: o.process, Pod: "connector-1", ReplicaSetUID: runtimeID, TemplateDigest: o.f.pin.TemplateDigest, ProtectionDigest: o.f.pin.ProtectionDigest, WorkloadDigest: artifact.Digest{42}, ObservedAt: o.start, FreshUntil: o.end}
	if o.f.mode == "regional-final" && n == 4 {
		workload.WorkloadDigest = artifact.Digest{43}
	}
	return value.ConnectorObservationNativeValue{Request: o.request, Ordinal: n, Source: source, Workload: workload, NativeStartedAt: o.start, NativeUntil: o.end, ValueObservedAt: source.Observation.ObservedAt, Final: n == 4}, nil
}
func (o *framedRegionalNative) Close() { o.once.Do(func() { o.cancel(); o.f.closes.Add(1) }) }
func (f *framedRegionalFixture) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	f.metadata.Add(1)
	if f.reads.Load() != 2 || f.finals.Load() != 0 || ctx.Err() != nil {
		return value.ClusterObservationResult{}, value.ErrUnavailable
	}
	digest, e := app.ClusterObservationRequestDigest(r)
	if e != nil {
		return value.ClusterObservationResult{}, e
	}
	end, _ := ctx.Deadline()
	return value.ClusterObservationResult{RootID: r.RootID, ClusterID: r.ClusterID, RequestID: r.ID, Challenge: r.Challenge, Purpose: r.Purpose, RequestDigest: digest, Interval: value.ClusterObservationInterval{ObservedAt: time.Now(), FreshUntil: end}, Namespaces: &value.ClusterNamespaceCandidatePage{ResourceVersion: "1", Items: []cfg.NamespaceRef{}}}, nil
}

type framedOwnerNative struct {
	facts                   value.OwnerObservationNativeFacts
	mode                    string
	original, final, closed atomic.Int32
	entered, release        chan struct{}
}

func (o *framedOwnerNative) Original(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	o.original.Add(1)
	if ctx.Err() != nil || o.final.Load() != 0 || o.closed.Load() != 0 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return o.facts.Clone(), nil
}
func (o *framedOwnerNative) Final(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	if o.final.Add(1) != 1 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	v := o.facts.Clone()
	v.Final = true
	if o.mode == "owner-final" {
		v.Peers[0].WorkloadDigest = artifact.Digest{70}
	}
	if o.mode == "cancel-final" {
		close(o.entered)
		<-ctx.Done()
		<-o.release
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	if ctx.Err() != nil {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return v, nil
}
func (o *framedOwnerNative) Close() { o.closed.Add(1) }
