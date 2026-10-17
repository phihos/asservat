package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
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
	workload := value.ConnectorObservationWorkload{Process: o.process, Pod: "connector-1", ReplicaSetUID: runtimeID, TemplateDigest: o.f.pin.TemplateDigest, ImageDigest: o.f.pin.ImageDigest, ProtectionDigest: o.f.pin.ProtectionDigest, WorkloadDigest: artifact.Digest{42}, ObservedAt: o.start, FreshUntil: o.end}
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

// Closed numeric counters only; no payload, credential, identity or raw error logs.
type framedOperationPhaseTrace struct {
	*mtls.ConnectorObservationOperationConnection
	receives, answers, sends, failed atomic.Int32
}

func (d *framedOperationPhaseTrace) Receive(ctx context.Context) (contracts.ClusterObservationFrame, error) {
	d.receives.Add(1)
	f, e := d.ConnectorObservationOperationConnection.Receive(ctx)
	if e != nil {
		d.failed.CompareAndSwap(0, 1)
	}
	return f, e
}
func (d *framedOperationPhaseTrace) AnswerConnectorObservation(ctx context.Context, p contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error) {
	d.answers.Add(1)
	r, e := d.ConnectorObservationOperationConnection.AnswerConnectorObservation(ctx, p)
	if e != nil {
		d.failed.CompareAndSwap(0, 2)
	}
	return r, e
}
func (d *framedOperationPhaseTrace) Send(ctx context.Context, f contracts.ClusterObservationFrame) error {
	d.sends.Add(1)
	e := d.ConnectorObservationOperationConnection.Send(ctx, f)
	if e != nil {
		d.failed.CompareAndSwap(0, 3)
	}
	return e
}

func TestRegionalOperationActualFramedCoordinator(t *testing.T) {
	for _, mode := range []string{"joined", "owner-final", "regional-final", "sql-final", "cancel-final"} {
		t.Run(mode, func(t *testing.T) {
			base, _, unused := newRuntimeFixture(t)
			_ = unused.Close()
			root, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var handler *wire.HubObservationOperationHandler
			accepted := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { accepted <- struct{}{}; handler.ServeHTTP(w, r) }))
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			number, _ := strconv.Atoi(port)
			base.configuration.Pool.NativePort = number
			base.configuration.Pool.NativeBootstrap = value.OwnerBootstrapProfile
			base.configuration.Pool.NativeCandidateLimit = 1024
			pin := value.OwnerObservationPin{RootID: observationForwardID(900), SourceUID: runtimeID, Pool: base.configuration.Pool, TemplateDigest: artifact.Digest{3}, ImageDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{19}}
			owner := &observationForwardFixture{t: t, base: base, pin: pin, bound: time.Now().Add(5 * time.Second), identities: make(map[value.OwnerCertificate]value.OwnerEnrollment)}
			binding := value.OwnerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PodUID: observationForwardID(10), ProcessEpoch: observationForwardID(30)}
			owner.servers = []value.OwnerBinding{binding}
			keys, e := mtls.NewOwnerCredentialsForPool(binding, "server", pin.Pool, base.roots, owner, owner, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			defer keys.Close()
			if e = keys.Enroll(root); e != nil {
				server.Close()
				t.Fatal("owner keys", e)
			}
			regional := &framedRegionalFixture{base: base, now: time.Now().UTC().Truncate(time.Second), issued: make(map[artifact.Digest]value.IssuedConnectorCredential), mode: mode}
			regional.pin = value.ConnectorObservationPin{Profile: value.ConnectorCredentialProfile{RootID: pin.RootID, Binding: value.PeerBinding{InstallationID: runtimeID, ClusterID: observationForwardID(502), IssuerEpoch: runtimeID, PeerID: observationForwardID(503), Role: value.ConnectorPeer}, Revision: identity.Revision{UID: observationForwardID(504), Generation: 1, Digest: artifact.Digest{33}}, ProtectionDigest: artifact.Digest{34}, ServerName: "connector.example.invalid", Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: runtimeID, ServiceAccount: "connector", AccountUID: runtimeID, Deployment: "connector", DeploymentUID: runtimeID, ServingSlots: 2, RetainedProcesses: 8}, ClientIssuerRoots: [][]byte{base.ca.Raw}, ServerIssuerRoots: [][]byte{base.ca.Raw}}, Roles: value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}, TemplateDigest: artifact.Digest{35}, ImageDigest: artifact.Digest{36}, ProtectionDigest: artifact.Digest{37}}
			credentials, e := mtls.NewConnectorProcessCredentials(root, regional.pin.Profile, observationForwardID(505), regional, regional, regional, regional, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			defer credentials.Close()
			if e = credentials.Reconcile(root); e != nil {
				server.Close()
				t.Fatal("regional keys", e)
			}
			producer, e := mtls.NewConnectorObservationOperationProducer(regional.pin, credentials, regional, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			ingress, e := mtls.NewOwnerObservationOperationIngress(pin, keys, []mtls.OwnerObservationPeer{{Binding: regional.pin.Profile.Binding, Roots: regional.pin.Profile.ClientIssuerRoots}}, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			common, _ := mtls.OwnerBootstrapServerName(pin.Pool)
			holder, e := wire.NewHubObservationOperationHolder(root, 1, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			handler, e = regionalObservationOperationHandler(net.JoinHostPort(common, port), holder, regional.pin, ingress, regional, time.Now)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			serving, e := mtls.NewOwnerBootstrapServing(keys, pin.Pool)
			if e != nil {
				server.Close()
				t.Fatal(e)
			}
			// Test-only original accept root, supplied at connection acceptance rather
			// than renewed at HTTP path dispatch. Real listener qualification is separate.
			server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return root }
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: base.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}
			server.StartTLS()
			defer func() { cancel(); handler.Close(); server.Close() }()
			client, e := mtls.NewConnectorObservationOperationClient(root, pin, server.Listener.Addr().String(), base.roots, producer, owner, owner, regional, 1, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			stream, e := client.Open(root, observationForwardID(506))
			if e != nil {
				t.Fatal("real standby", e)
			}
			defer stream.Close()
			<-accepted
			if regional.opens.Load() != 0 || regional.reads.Load() != 0 || regional.metadata.Load() != 0 {
				t.Fatal("standby opened authority")
			}
			now := time.Now().In(time.FixedZone("framed-offset", 2*60*60))
			request := value.ClusterObservationRequest{RootID: pin.RootID, ClusterID: regional.pin.Profile.Binding.ClusterID, ID: observationForwardID(510), Challenge: observationForwardID(511), Purpose: value.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}
			original := value.OwnerObservationRequest{RootID: request.RootID, ID: request.ID, Challenge: request.Challenge, RequestedAt: request.RequestedAt, NotAfter: request.NotAfter}
			native := &framedOwnerNative{facts: value.OwnerObservationNativeFacts{Request: original, Pin: pin, ObservedAt: now, FreshUntil: owner.bound, Peers: []value.OwnerObservationNativePeer{{Binding: binding, Pod: "owner-" + binding.PodUID, ReplicaSetUID: runtimeID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{41}}}}, mode: mode, entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(native.release) })
			operation, e := mtls.NewOwnerObservationOperation(root, pin, original, keys, owner, native, time.Now)
			if e != nil {
				t.Fatal("owner operation", e)
			}
			defer operation.Close()
			var locator wire.HubObservationLocator
			for time.Now().Before(owner.bound) {
				locator, e = holder.Lookup(root, request.RootID, request.ClusterID)
				if e == nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if e != nil {
				t.Fatal("header publication", e)
			}
			regionalDone := make(chan error, 1)
			trace := &framedOperationPhaseTrace{ConnectorObservationOperationConnection: stream}
			go func() { regionalDone <- wire.ServeRegionalObservationOperation(root, trace, time.Now) }()
			caller, stop := context.WithCancel(root)
			defer stop()
			result := make(chan error, 1)
			go func() { _, e := ObserveRegionalOperation(caller, holder, locator, request, operation); result <- e }()
			hubJoined, regionalJoined := false, false
			defer func() {
				release.Do(func() { close(native.release) })
				stop()
				cancel()
				_ = stream.Close()
				if !hubJoined {
					<-result
				}
				if !regionalJoined {
					<-regionalDone
				}
			}()
			if mode == "cancel-final" {
				select {
				case <-native.entered:
				case <-time.After(time.Second):
					t.Fatal("final native not reached")
				}
				stop()
				select {
				case <-result:
					hubJoined = true
					t.Fatal("caller cancellation failed to join final work")
				case <-time.After(10 * time.Millisecond):
				}
				release.Do(func() { close(native.release) })
			}
			var resultErr error
			select {
			case resultErr = <-result:
				hubJoined = true
			case <-time.After(6 * time.Second):
				t.Fatal("hub did not join")
			}
			regionalErr := <-regionalDone
			regionalJoined = true
			t.Log("phase counters receives/answers/sends/first-failure/native-open/read/final/owner-registry", trace.receives.Load(), trace.answers.Load(), trace.sends.Load(), trace.failed.Load(), regional.opens.Load(), regional.reads.Load(), regional.finals.Load(), owner.registry.Load())
			if (mode == "joined") != (resultErr == nil) || (mode == "joined") != (regionalErr == nil) {
				t.Fatal("framed outcome", mode, resultErr, regionalErr)
			}
			if regional.metadata.Load() != 1 || regional.pairs.Load() != 2 || native.original.Load() != 1 || native.final.Load() != 1 {
				t.Fatal("proof/effect phase counts", regional.metadata.Load(), regional.pairs.Load(), native.original.Load(), native.final.Load())
			}
			if native.closed.Load() != 0 {
				t.Fatal("standby closed locator-owned native proof")
			}
			if mode == "joined" && (regional.reads.Load() != 4 || regional.finals.Load() != 1 || regional.closes.Load() != 1) {
				t.Fatal("regional phases not joined", regional.reads.Load(), regional.finals.Load(), regional.closes.Load())
			}
			if _, e = holder.Claim(root, locator, request); e == nil {
				t.Fatal("spent exact holder accepted second claim")
			}
		})
	}
}
