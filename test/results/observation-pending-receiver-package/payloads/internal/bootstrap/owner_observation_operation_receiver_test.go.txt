package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// Actual two owner connections plus the complete regional framed exchange.
// Native/SQL/installer/CA facts are synthetic. The assertions establish joined
// HTTP delivery ownership, not sustained real API availability or installation.
type receiverNativeFixture struct {
	pin                                        value.OwnerObservationPin
	mode                                       string
	opens                                      atomic.Int32
	mu                                         sync.Mutex
	last                                       *framedOwnerNative
	beginEntered, beginCancelled, beginRelease chan struct{}
}

func (f *receiverNativeFixture) OpenOwnerObservationOperation(ctx context.Context, r value.OwnerObservationRequest, peers []value.OwnerBinding) (app.OwnerNativeObservationOperation, error) {
	f.opens.Add(1)
	if f.mode == "cancel-native-begin" {
		close(f.beginEntered)
		<-ctx.Done()
		close(f.beginCancelled)
		<-f.beginRelease
		return nil, ctx.Err()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	end, _ := ctx.Deadline()
	facts := value.OwnerObservationNativeFacts{Pin: f.pin, Request: r, ObservedAt: time.Now(), FreshUntil: identity.Earlier(end, r.NotAfter)}
	for _, b := range peers {
		facts.Peers = append(facts.Peers, value.OwnerObservationNativePeer{Binding: b, Pod: "owner-" + b.PodUID, ReplicaSetUID: runtimeID, Addresses: []string{"10.0.0.8"}, WorkloadDigest: artifact.Digest{41}})
	}
	n := &framedOwnerNative{facts: facts, mode: f.mode, entered: make(chan struct{}), release: make(chan struct{})}
	f.mu.Lock()
	f.last = n
	f.mu.Unlock()
	return n, nil
}

// Count only A's routing/borrowed-operation registry port. The regional
// channel uses its separate original dependency and is not hidden in this count.
type receiverOwnerRegistry struct {
	app.OwnerCertificateRegistry
	reads atomic.Int32
}

func (r *receiverOwnerRegistry) ReadOwnerRegistration(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	r.reads.Add(1)
	return r.OwnerCertificateRegistry.ReadOwnerRegistration(ctx, leaf)
}

type receiverAbortWriter struct{ http.ResponseWriter }

func (w receiverAbortWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w receiverAbortWriter) Write(body []byte) (int, error) {
	if len(body) > 0 {
		_, _ = w.ResponseWriter.Write(body[:1])
		_ = http.NewResponseController(w.ResponseWriter).Flush()
	}
	// The exact full Content-Length was already set. A bounded real prefix
	// makes unknown completion visible to HTTP/2 rather than a pre-write retry.
	panic(http.ErrAbortHandler)
}

type operationReceiverFixture struct {
	root         context.Context
	cancel       context.CancelFunc
	server       *httptest.Server
	base         *runtimeFixture
	owner        *observationForwardFixture
	keys, sender *mtls.OwnerCredentials
	regional     *framedRegionalFixture
	native       *receiverNativeFixture
	registry     *receiverOwnerRegistry
	holder       *wire.HubObservationOperationHolder
	receiver     *OwnerObservationOperationReceiver
	stream       *mtls.ConnectorObservationOperationConnection
	regionalDone chan error
	get, post    atomic.Int32
	mode         string
}

func newOperationReceiverFixture(t *testing.T, mode string) *operationReceiverFixture {
	t.Helper()
	base, _, unused := newRuntimeFixture(t)
	_ = unused.Close()
	root, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	f := &operationReceiverFixture{root: root, cancel: cancel, base: base, mode: mode, regionalDone: make(chan error, 1)}
	var handler *wire.HubObservationOperationHandler
	accepted := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == contracts.ClusterObservationOperationExchangePath {
			accepted <- struct{}{}
			handler.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet {
			f.get.Add(1)
		} else {
			f.post.Add(1)
		}
		if mode == "lost-get" && r.Method == http.MethodGet || mode == "lost-post" && r.Method == http.MethodPost {
			f.receiver.ServeHTTP(receiverAbortWriter{w}, r)
			return
		}
		f.receiver.ServeHTTP(w, r)
	}))
	f.server = server
	t.Cleanup(func() { cancel(); server.Close() })
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	base.configuration.Pool.NativePort = number
	base.configuration.Pool.NativeBootstrap = value.OwnerBootstrapProfile
	base.configuration.Pool.NativeCandidateLimit = 1024
	pin := value.OwnerObservationPin{RootID: observationForwardID(900), SourceUID: runtimeID, Pool: base.configuration.Pool, TemplateDigest: artifact.Digest{3}, ImageDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{19}}
	end, _ := root.Deadline()
	owner := &observationForwardFixture{t: t, base: base, pin: pin, bound: end, identities: make(map[value.OwnerCertificate]value.OwnerEnrollment)}
	f.owner = owner
	binding := value.OwnerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PodUID: observationForwardID(10), ProcessEpoch: observationForwardID(30)}
	owner.servers = []value.OwnerBinding{binding}
	keys, e := mtls.NewOwnerCredentialsForPool(binding, "server", pin.Pool, base.roots, owner, owner, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	f.keys = keys
	t.Cleanup(keys.Close)
	if e = keys.Enroll(root); e != nil {
		t.Fatal(e)
	}
	senderBinding := binding
	senderBinding.PodUID = observationForwardID(11)
	senderBinding.ProcessEpoch = observationForwardID(31)
	sender, e := mtls.NewOwnerCredentialsForPool(senderBinding, "client", pin.Pool, base.roots, owner, owner, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	f.sender = sender
	t.Cleanup(sender.Close)
	if e = sender.Enroll(root); e != nil {
		t.Fatal(e)
	}
	regional := &framedRegionalFixture{base: base, now: time.Now().UTC().Truncate(time.Second), issued: make(map[artifact.Digest]value.IssuedConnectorCredential), mode: mode}
	f.regional = regional
	regional.pin = value.ConnectorObservationPin{Profile: value.ConnectorCredentialProfile{RootID: pin.RootID, Binding: value.PeerBinding{InstallationID: runtimeID, ClusterID: observationForwardID(502), IssuerEpoch: runtimeID, PeerID: observationForwardID(503), Role: value.ConnectorPeer}, Revision: identity.Revision{UID: observationForwardID(504), Generation: 1, Digest: artifact.Digest{33}}, ProtectionDigest: artifact.Digest{34}, ServerName: "connector.example.invalid", Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: runtimeID, ServiceAccount: "connector", AccountUID: runtimeID, Deployment: "connector", DeploymentUID: runtimeID, ServingSlots: 2, RetainedProcesses: 8}, ClientIssuerRoots: [][]byte{base.ca.Raw}, ServerIssuerRoots: [][]byte{base.ca.Raw}}, Roles: value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}, TemplateDigest: artifact.Digest{35}, ImageDigest: artifact.Digest{36}, ProtectionDigest: artifact.Digest{37}}
	credentials, e := mtls.NewConnectorProcessCredentials(root, regional.pin.Profile, observationForwardID(505), regional, regional, regional, regional, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(credentials.Close)
	if e = credentials.Reconcile(root); e != nil {
		t.Fatal(e)
	}
	producer, e := mtls.NewConnectorObservationOperationProducer(regional.pin, credentials, regional, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	ingress, e := mtls.NewOwnerObservationOperationIngress(pin, keys, []mtls.OwnerObservationPeer{{Binding: regional.pin.Profile.Binding, Roots: regional.pin.Profile.ClientIssuerRoots}}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	common, _ := mtls.OwnerBootstrapServerName(pin.Pool)
	holder, e := wire.NewHubObservationOperationHolder(root, 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	f.holder = holder
	handler, e = regionalObservationOperationHandler(net.JoinHostPort(common, port), holder, regional.pin, ingress, regional, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	f.native = &receiverNativeFixture{pin: pin, mode: mode, beginEntered: make(chan struct{}), beginCancelled: make(chan struct{}), beginRelease: make(chan struct{})}
	f.registry = &receiverOwnerRegistry{OwnerCertificateRegistry: owner}
	f.receiver, e = newOwnerObservationOperationReceiver(root, pin, keys, base.roots, f.registry, f.native, holder, 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	serving, e := mtls.NewOwnerBootstrapServing(keys, pin.Pool)
	if e != nil {
		t.Fatal(e)
	}
	server.Config.ConnContext = func(context.Context, net.Conn) context.Context { return root }
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{GetCertificate: serving.GetCertificate, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: base.roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}
	server.StartTLS()
	client, e := mtls.NewConnectorObservationOperationClient(root, pin, server.Listener.Addr().String(), base.roots, producer, owner, owner, regional, 1, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	stream, e := client.Open(root, observationForwardID(506))
	if e != nil {
		t.Fatal("standby", e)
	}
	f.stream = stream
	<-accepted
	for time.Now().Before(end) {
		if _, e = holder.Lookup(root, pin.RootID, regional.pin.Profile.Binding.ClusterID); e == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e != nil {
		t.Fatal("published standby", e)
	}
	go func() { f.regionalDone <- wire.ServeRegionalObservationOperation(root, stream, time.Now) }()
	t.Cleanup(func() {
		cancel()
		_ = stream.Close()
		f.receiver.Close()
		handler.Close()
		holder.Close()
		<-f.regionalDone
	})
	return f
}
func (f *operationReceiverFixture) request() value.ClusterObservationRequest {
	now := time.Now().UTC()
	end, _ := f.root.Deadline()
	return value.ClusterObservationRequest{RootID: f.owner.pin.RootID, ClusterID: f.regional.pin.Profile.Binding.ClusterID, ID: observationForwardID(510), Challenge: observationForwardID(511), Purpose: value.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: end}
}
func (f *operationReceiverFixture) http(t *testing.T, method, target, media string, body []byte, exact bool) (int, []byte, error) {
	t.Helper()
	return f.httpContext(t, f.root, method, target, media, body, exact)
}
func (f *operationReceiverFixture) httpContext(t *testing.T, ctx context.Context, method, target, media string, body []byte, exact bool) (int, []byte, error) {
	t.Helper()
	authority := f.receiver.CommonAuthority()
	if exact {
		authority = f.receiver.ExactAuthority()
	}
	name, _, _ := net.SplitHostPort(authority)
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, MaxConnsPerHost: 1, TLSClientConfig: &tls.Config{ServerName: name, RootCAs: f.base.roots, GetClientCertificate: f.sender.GetClientCertificate, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}}
	defer tr.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, method, "https://"+authority+target, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Accept", media)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", media)
	}
	resp, e := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, contracts.ClusterObservationClaimBytes+1))
	return resp.StatusCode, b, e
}
func operationReceiverTarget(t *testing.T, r value.ClusterObservationRequest) string {
	t.Helper()
	q := contracts.ClusterObservationOperationLocatorQuery(wire.LocatorQueryWire(r.LocatorQuery()))
	q.Format = contracts.ClusterObservationOperationLocatorFormat
	v, e := contracts.EncodeClusterObservationOperationLocatorTarget(q)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestOwnerOperationReceiverActualH2AndFramedCompletion(t *testing.T) {
	for _, mode := range []string{"joined", "lost-get", "lost-post", "owner-final", "regional-final", "sender-revoked", "common-claim"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperationReceiverFixture(t, mode)
			r := f.request()
			target := operationReceiverTarget(t, r)
			status, body, err := f.http(t, http.MethodGet, target, contracts.ClusterObservationOperationLocatorMediaType, nil, false)
			if mode == "lost-get" {
				if err == nil {
					t.Fatal("lost GET completed")
				}
				if f.native.opens.Load() != 1 || f.regional.opens.Load() != 0 {
					t.Fatal("lost locator changed admission", f.native.opens.Load(), f.regional.opens.Load())
				}
				if _, e := f.holder.Lookup(f.root, r.RootID, r.ClusterID); e == nil {
					t.Fatal("lost locator returned original standby to routing")
				}
				_, _, _ = f.http(t, http.MethodGet, target, contracts.ClusterObservationOperationLocatorMediaType, nil, false)
				if f.native.opens.Load() != 1 {
					t.Fatal("lost GET replay reopened native proof")
				}
				return
			}
			if err != nil || status != http.StatusOK {
				t.Fatal("locator", status, err)
			}
			locator, err := contracts.DecodeClusterObservationOperationLocator(body)
			clear(body)
			if err != nil {
				t.Fatal(err)
			}
			// A positive locator response also owns the original standby; another
			// request cannot race this retained query before its selected POST.
			if _, e := f.holder.Lookup(f.root, r.RootID, r.ClusterID); e == nil {
				t.Fatal("published locator did not spend standby")
			}
			if mode == "sender-revoked" {
				f.owner.mode = "revoked-after-get"
				f.owner.get.Store(1)
			}
			payload, err := contracts.EncodeClusterObservationOperationClaim(contracts.ClusterObservationOperationClaim{Format: contracts.ClusterObservationOperationClaimFormat, Request: wire.RequestWire(r), Locator: locator})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(payload)
			status, body, err = f.http(t, http.MethodPost, contracts.ClusterObservationOperationClaimPath, contracts.ClusterObservationOperationClaimMediaType, payload, mode != "common-claim")
			if mode == "joined" {
				if err != nil || status != http.StatusOK {
					t.Fatal("claim", status, err)
				}
				v, e := contracts.DecodeClusterObservationResult(body)
				if e != nil || v.RequestID != r.ID {
					t.Fatal("result", e)
				}
				if f.regional.reads.Load() != 4 || f.regional.metadata.Load() != 1 || f.regional.pairs.Load() != 2 {
					t.Fatal("complete regional conversation", f.regional.reads.Load(), f.regional.metadata.Load(), f.regional.pairs.Load())
				}
				if f.registry.reads.Load() != 22 || f.native.opens.Load() != 1 {
					t.Fatal("A registry/native port calls differ from reviewed source graph", f.registry.reads.Load(), f.native.opens.Load())
				}
				f.native.mu.Lock()
				native := f.native.last
				f.native.mu.Unlock()
				if native == nil || native.original.Load() != 1 || native.final.Load() != 1 {
					t.Fatal("borrowed owner native handle was replaced or reopened")
				}
			} else if mode == "lost-post" {
				if err == nil {
					t.Fatal("lost POST completed")
				}
			} else if err == nil && status == http.StatusOK {
				t.Fatal("denied final state returned result")
			}
			clear(body)
			if mode == "sender-revoked" || mode == "common-claim" {
				if f.regional.metadata.Load() != 0 {
					t.Fatal("preflight denial reached metadata")
				}
			} else if f.regional.metadata.Load() != 1 {
				t.Fatal("expected one metadata phase")
			}
			if mode == "common-claim" {
				return
			} // malformed authority was rejected before claim admission
			before := f.regional.metadata.Load()
			_, _, _ = f.http(t, http.MethodPost, contracts.ClusterObservationOperationClaimPath, contracts.ClusterObservationOperationClaimMediaType, payload, true)
			if f.regional.metadata.Load() != before || f.native.opens.Load() != 1 {
				t.Fatal("claim replay performed work")
			}
		})
	}
}

// The real HTTP/2 GET cancellation must reach an admitted native Begin, and
// receiver Close must join that actual read before its process slot is released.
func TestOwnerOperationReceiverCancellationDuringNativeBeginJoins(t *testing.T) {
	f := newOperationReceiverFixture(t, "cancel-native-begin")
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(f.native.beginRelease) }) }
	// Registered last so a failed assertion cannot strand fixture cleanup.
	t.Cleanup(release)
	r := f.request()
	target := operationReceiverTarget(t, r)
	ctx, cancel := context.WithCancel(f.root)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() {
		_, body, err := f.httpContext(t, ctx, http.MethodGet, target, contracts.ClusterObservationOperationLocatorMediaType, nil, false)
		clear(body)
		clientDone <- err
	}()
	select {
	case <-f.native.beginEntered:
	case <-f.root.Done():
		t.Fatal("native Begin was not admitted")
	}
	cancel()
	select {
	case <-f.native.beginCancelled:
	case <-f.root.Done():
		t.Fatal("actual GET cancellation did not reach native Begin")
	}
	closed := make(chan struct{})
	go func() { f.receiver.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("receiver Close returned with native read still admitted")
	case <-time.After(20 * time.Millisecond):
	}
	f.receiver.pending.mu.Lock()
	retained := len(f.receiver.pending.entries)
	f.receiver.pending.mu.Unlock()
	if retained != 1 || f.native.opens.Load() != 1 || f.regional.metadata.Load() != 0 {
		t.Fatal("cancelled native read released slot or reached metadata", retained, f.native.opens.Load(), f.regional.metadata.Load())
	}
	release()
	select {
	case <-closed:
	case <-f.root.Done():
		t.Fatal("receiver Close did not join released native read")
	}
	select {
	case err := <-clientDone:
		if err == nil {
			t.Fatal("cancelled GET returned success")
		}
	case <-f.root.Done():
		t.Fatal("cancelled HTTP transport did not join")
	}
}
