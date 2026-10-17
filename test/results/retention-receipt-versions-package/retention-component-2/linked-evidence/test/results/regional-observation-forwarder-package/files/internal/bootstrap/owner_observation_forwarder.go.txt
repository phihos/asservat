package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// OwnerObservationForwarder performs only the closed regional observation
// purpose. It never forwards the local HWORK token or accepts a caller-selected
// locator, peer, URL, pool or candidate limit. The installed backend owns this
// object and its purpose-fixed concrete SQL/native dependencies.
type OwnerObservationForwarder struct {
	root       context.Context
	cancel     context.CancelFunc
	pin        value.OwnerObservationPin
	client     *mtls.OwnerCredentials
	roots      *x509.CertPool
	verifier   *mtls.OwnerPeerVerifier
	candidates *app.OwnerObservationCandidateSelection
	ready      app.OwnerObservationCandidateGroupsReader
	routes     app.OwnerRouteReader
	owners     *app.OwnerAuthenticator
	workloads  app.OwnerObservationWorkloadReader
	now        func() time.Time
	dial       func(context.Context, string, string) (net.Conn, error)
	mu         sync.Mutex
	closed     bool
	active     int
	joined     sync.WaitGroup
}

var _ app.ClusterObservationExchange = (*OwnerObservationForwarder)(nil)

func NewOwnerObservationForwarder(ctx context.Context, pin value.OwnerObservationPin, client *mtls.OwnerCredentials, roots *x509.CertPool, registry *postgres.OwnerEnrollments, configuration *postgres.OwnerConfigurations, endpoints *kube.OwnerEndpoints, protection *kube.OwnerWorkloadProtection, workloads *kube.OwnerObservationWorkload, now func() time.Time) (*OwnerObservationForwarder, error) {
	if registry == nil || configuration == nil || endpoints == nil || protection == nil || workloads == nil {
		return nil, value.ErrInvalid
	}
	routes := &app.OwnerRoutes{Configurations: configuration, Endpoints: endpoints, Now: now}
	owners := &app.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: protection, Now: now}
	return newOwnerObservationForwarder(ctx, pin, client, roots, registry, endpoints, routes, owners, workloads, now)
}

// This unexported port seam permits component tests. The public constructor
// accepts only the existing installation-owned concrete adapters; it never
// exposes the dial function or an authentication callback to deployment input.
func newOwnerObservationForwarder(ctx context.Context, pin value.OwnerObservationPin, client *mtls.OwnerCredentials, roots *x509.CertPool, candidates app.OwnerObservationCandidateSource, ready app.OwnerObservationCandidateGroupsReader, routes app.OwnerRouteReader, owners *app.OwnerAuthenticator, workloads app.OwnerObservationWorkloadReader, now func() time.Time) (*OwnerObservationForwarder, error) {
	if ctx == nil || ctx.Err() != nil || !pin.Valid() || pin.Pool.NativeCandidateLimit == 0 || client == nil || roots == nil || len(roots.Subjects()) == 0 || ready == nil || routes == nil || owners == nil || owners.Registry == nil || owners.Routes == nil || owners.Protection == nil || owners.Now == nil || workloads == nil || now == nil {
		return nil, value.ErrInvalid
	}
	selected, err := app.NewOwnerObservationCandidateSelection(pin.Pool, candidates)
	if err != nil {
		return nil, err
	}
	verifier, err := mtls.NewOwnerPeerVerifierForPool(roots, pin.Pool, now)
	if err != nil {
		return nil, err
	}
	root, cancel := context.WithCancel(ctx)
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	return &OwnerObservationForwarder{root: root, cancel: cancel, pin: pin, client: client, roots: roots.Clone(), verifier: verifier, candidates: selected, ready: ready, routes: routes, owners: owners, workloads: workloads, now: now, dial: dialer.DialContext}, nil
}

func (f *OwnerObservationForwarder) enter() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.root.Err() != nil || f.active >= 2 {
		return false
	}
	f.active++
	f.joined.Add(1)
	return true
}
func (f *OwnerObservationForwarder) leave() {
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
	f.joined.Done()
}
func (f *OwnerObservationForwarder) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	f.cancel()
	f.mu.Unlock()
	f.joined.Wait()
}

// ObserveCluster retains one original <=5s interval across complete discovery,
// all read-only locator requests, their joined cancellation, and the sole claim.
func (f *OwnerObservationForwarder) ObserveCluster(ctx context.Context, request value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	if f == nil || ctx == nil || ctx.Err() != nil || !request.Valid(f.now()) || request.RootID != f.pin.RootID || !f.enter() {
		return zero, value.ErrUnavailable
	}
	defer f.leave()
	request = request.Clone()
	until := identity.Earlier(request.NotAfter, f.now().Add(5*time.Second))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	rootDone := make(chan struct{})
	stopRoot := context.AfterFunc(f.root, func() { cancel(); close(rootDone) })
	defer func() {
		if !stopRoot() {
			<-rootDone
		}
	}()
	candidates, err := f.candidates.ReadOwnerObservationCandidates(call)
	if err != nil || !candidates.Valid(f.now()) || candidates.Pool != f.pin.Pool || len(candidates.Owners) == 0 {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, candidates.ValidUntil)
	sqlCall, endSQL := context.WithDeadline(call, until)
	defer endSQL()
	nativeCandidates := candidates
	nativeCandidates.Owners = append([]value.OwnerBinding(nil), candidates.Owners...)
	groups, err := f.ready.ReadyOwnerObservationCandidates(sqlCall, nativeCandidates)
	if err != nil || !groups.Valid(f.now()) || !sameForwardCandidates(candidates, groups.Candidates) {
		return zero, value.ErrUnavailable
	}
	groups = groups.Clone()
	until = identity.Earlier(until, groups.ValidUntil)
	bounded, endBounded := context.WithDeadline(sqlCall, until)
	defer endBounded()
	selected, err := f.locate(bounded, request.LocatorQuery(), groups)
	if err != nil || bounded.Err() != nil || f.root.Err() != nil || !groups.Valid(f.now()) || !selected.peers.Valid(f.now()) || !selected.locator.Matches(request.LocatorQuery(), selected.peers.Holder.Certificate.Binding, f.now()) {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, identity.Earlier(selected.locator.Interval.FreshUntil, selected.peers.Interval.FreshUntil))
	claimCall, endClaim := context.WithDeadline(bounded, until)
	defer endClaim()
	return f.claim(claimCall, request, selected)
}

func sameForwardCandidates(a, b value.APIContextOwnerCandidates) bool {
	if a.Pool != b.Pool || !a.ObservedAt.Equal(b.ObservedAt) || !a.ValidUntil.Equal(b.ValidUntil) || len(a.Owners) != len(b.Owners) {
		return false
	}
	for i := range a.Owners {
		if a.Owners[i] != b.Owners[i] {
			return false
		}
	}
	return true
}

type ownerObservationLocated struct {
	locator value.ClusterObservationLocator
	peers   value.ClusterObservationRoutingPeers
}

// At most two workers traverse the bounded complete Pod groups. There is no
// goroutine per retained registration. Unknown GET outcomes are not absence;
// only one independently authenticated positive locator can select a claim.
func (f *OwnerObservationForwarder) locate(ctx context.Context, q value.ClusterObservationLocatorQuery, groups value.OwnerObservationCandidateGroups) (ownerObservationLocated, error) {
	lookup, cancel := context.WithCancel(ctx)
	defer cancel()
	var index atomic.Int32
	var joined sync.WaitGroup
	results := make(chan ownerObservationLocated, 2)
	workers := min(2, len(groups.Groups))
	for range workers {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for lookup.Err() == nil {
				i := int(index.Add(1)) - 1
				if i >= len(groups.Groups) {
					return
				}
				out, err := f.lookup(lookup, q, groups.Candidates, groups.Groups[i])
				if err != nil {
					continue
				}
				select {
				case results <- out:
				case <-lookup.Done():
				}
				return
			}
		}()
	}
	done := make(chan struct{})
	go func() { joined.Wait(); close(done) }()
	var selected ownerObservationLocated
	select {
	case selected = <-results:
	case <-done:
		// A last successful worker may have queued its value before closing.
		select {
		case selected = <-results:
		default:
		}
	case <-ctx.Done():
	}
	cancel()
	<-done
	if ctx.Err() != nil || !selected.peers.Valid(f.now()) || !selected.locator.Matches(q, selected.peers.Holder.Certificate.Binding, f.now()) {
		return ownerObservationLocated{}, value.ErrUnavailable
	}
	return selected, nil
}

func (f *OwnerObservationForwarder) peers(ctx context.Context, q value.ClusterObservationLocatorQuery, connection app.OwnerPeerConnection, expected value.OwnerCertificate) (value.ClusterObservationRoutingPeers, error) {
	var zero value.ClusterObservationRoutingPeers
	if ctx.Err() != nil || f.root.Err() != nil {
		return zero, value.ErrUnavailable
	}
	sender, err := f.owners.ObserveOwnerClient(ctx, f.client)
	if err != nil || sender.Certificate != expected || !sender.Valid(f.now()) || sender.Pool != f.pin.Pool || sender.ConfigurationRevision.UID != f.pin.SourceUID || sender.ProtectionDigest != f.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(q.NotAfter, sender.ValidUntil)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	sw, err := f.workloads.ObserveOwnerWorkload(call, sender.Certificate.Binding, sender.Pod)
	if err != nil || !sw.Valid(f.now()) || sw.Pin != f.pin || sw.Binding != expected.Binding || sw.Pod != sender.Pod || sw.ReplicaSetUID != sender.ReplicaSetUID {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, sw.FreshUntil)
	remoteCall, stopRemote := context.WithDeadline(call, until)
	defer stopRemote()
	holder, err := f.owners.AuthenticateOwner(remoteCall, connection)
	if err != nil || !holder.Valid(f.now()) || holder.Pool != f.pin.Pool || holder.ConfigurationRevision != sender.ConfigurationRevision || holder.ProtectionDigest != f.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, holder.ValidUntil)
	workCall, stopWork := context.WithDeadline(remoteCall, until)
	defer stopWork()
	hw, err := f.workloads.ObserveOwnerWorkload(workCall, holder.Certificate.Binding, holder.Pod)
	if err != nil || !hw.Valid(f.now()) {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, hw.FreshUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	client, ce := f.client.ClientCertificate()
	server, se := connection.OwnerCertificate()
	if ce != nil || se != nil || client != expected || server != holder.Certificate || workCall.Err() != nil || f.root.Err() != nil {
		return zero, value.ErrUnavailable
	}
	start := q.RequestedAt
	for _, d := range []time.Time{sender.VerifiedAt, sw.ObservedAt, holder.VerifiedAt, hw.ObservedAt} {
		if start.Before(d) {
			start = d
		}
	}
	out := value.ClusterObservationRoutingPeers{Query: q, Pin: f.pin, Sender: sender, Holder: holder, SenderWorkload: sw, HolderWorkload: hw, Interval: value.ClusterObservationInterval{ObservedAt: start, FreshUntil: until}}
	if !out.Valid(f.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

func (f *OwnerObservationForwarder) lookup(ctx context.Context, q value.ClusterObservationLocatorQuery, candidates value.APIContextOwnerCandidates, group value.OwnerObservationCandidateGroup) (ownerObservationLocated, error) {
	var zero ownerObservationLocated
	if len(group.Owners) == 0 || !candidates.Valid(f.now()) {
		return zero, value.ErrUnavailable
	}
	target, err := contracts.EncodeClusterObservationLocatorTarget(wire.LocatorQueryWire(q))
	if err != nil {
		return zero, err
	}
	name, err := mtls.OwnerBootstrapServerName(f.pin.Pool)
	if err != nil {
		return zero, err
	}
	// CurrentOwnerRoute resolves this Pod, not its process. The actual TLS leaf
	// must be independently present in the complete original SQL candidate set.
	data, peers, err := f.exchange(ctx, q, group.Owners[0], name, http.MethodGet, target, contracts.ClusterObservationLocatorMediaType, nil, candidates, nil)
	if err != nil {
		return zero, err
	}
	defer clear(data)
	decoded, err := contracts.DecodeClusterObservationLocator(data)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	locator, err := wire.ParseLocator(decoded, q, peers.Holder.Certificate.Binding, f.now())
	if err != nil || locator.Holder.PodUID != group.PodUID {
		return zero, value.ErrUnavailable
	}
	locator.Interval.FreshUntil = identity.Earlier(locator.Interval.FreshUntil, peers.Interval.FreshUntil)
	if !locator.Matches(q, peers.Holder.Certificate.Binding, f.now()) {
		return zero, value.ErrUnavailable
	}
	return ownerObservationLocated{locator: locator, peers: peers}, nil
}

func (f *OwnerObservationForwarder) claim(ctx context.Context, r value.ClusterObservationRequest, selected ownerObservationLocated) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	name, err := mtls.OwnerServerName(selected.locator.Holder)
	if err != nil {
		return zero, err
	}
	body, err := contracts.EncodeClusterObservationClaim(contracts.ClusterObservationClaim{Format: contracts.ClusterObservationClaimFormat, Request: wire.RequestWire(r), Locator: wire.LocatorWire(selected.locator)})
	if err != nil {
		return zero, err
	}
	defer clear(body)
	data, peers, err := f.exchange(ctx, r.LocatorQuery(), selected.locator.Holder, name, http.MethodPost, contracts.ClusterObservationClaimPath, contracts.ClusterObservationClaimMediaType, body, value.APIContextOwnerCandidates{}, &selected.peers)
	if err != nil {
		return zero, err
	}
	defer clear(data)
	digest, err := wire.RequestDigest(r)
	if err != nil {
		return zero, err
	}
	decoded, err := contracts.DecodeClusterObservationResult(data)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	result, err := wire.ParseResult(decoded, r, digest, f.now())
	if err != nil {
		return zero, err
	}
	result = result.Restrict(r.RequestedAt, peers.Interval.FreshUntil)
	if !result.Matches(r, digest, f.now()) || ctx.Err() != nil || f.root.Err() != nil {
		return zero, value.ErrUnavailable
	}
	return result, nil
}

// exchange owns one actual socket and one request. The dial target comes only
// from the current same-cluster exact Pod route. A failed address, GET or POST
// is never replayed against another address/process, including after unknown
// delivery. The caller can select a different Pod only for a read-only lookup.
func (f *OwnerObservationForwarder) exchange(ctx context.Context, q value.ClusterObservationLocatorQuery, routeBinding value.OwnerBinding, name, method, target, media string, body []byte, candidates value.APIContextOwnerCandidates, selected *value.ClusterObservationRoutingPeers) ([]byte, value.ClusterObservationRoutingPeers, error) {
	var zero value.ClusterObservationRoutingPeers
	route, err := f.routes.CurrentOwnerRoute(ctx, routeBinding)
	if err != nil || !route.Valid(f.now()) || route.Endpoint.Binding != routeBinding || route.Endpoint.Pool != f.pin.Pool || route.Configuration.Configuration.Revision.UID != f.pin.SourceUID {
		return nil, zero, value.ErrUnavailable
	}
	until := identity.Earlier(q.NotAfter, route.FreshUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	expected, err := f.client.ClientCertificate()
	if err != nil || expected.Binding.InstallationID != f.pin.Pool.InstallationID || expected.Binding.ClusterID != f.pin.Pool.ClusterID || expected.Binding.IssuerEpoch != f.pin.Pool.IssuerEpoch {
		return nil, zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, expected.NotAfter)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	raw, err := f.dial(call, "tcp", net.JoinHostPort(route.Endpoint.Addresses[0], strconv.Itoa(f.pin.Pool.NativePort)))
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, zero, value.ErrUnavailable
	}
	defer raw.Close()
	closed := make(chan struct{})
	stopIO := context.AfterFunc(call, func() { _ = raw.Close(); close(closed) })
	defer func() {
		if !stopIO() {
			<-closed
		}
	}()
	if raw.SetDeadline(until) != nil {
		return nil, zero, value.ErrUnavailable
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.roots.Clone(), ServerName: name, NextProtos: []string{"h2"}, SessionTicketsDisabled: true, Time: f.now}
	config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if call.Err() != nil || f.root.Err() != nil {
			return nil, value.ErrUnavailable
		}
		certificate, e := f.client.GetClientCertificate(info)
		if e != nil || certificate == nil || len(certificate.Certificate) == 0 || artifact.Digest(sha256.Sum256(certificate.Certificate[0])) != expected.Digest {
			return nil, value.ErrDenied
		}
		return certificate, nil
	}
	socket := tls.Client(raw, config)
	if socket.HandshakeContext(call) != nil {
		return nil, zero, value.ErrDenied
	}
	state := socket.ConnectionState()
	var connection app.OwnerPeerConnection
	if method == http.MethodGet {
		connection, err = mtls.NewOwnerBootstrapConnection(f.verifier, &state, candidates)
	} else {
		connection, err = mtls.NewOwnerServerConnection(f.verifier, &state, routeBinding)
	}
	if err != nil {
		return nil, zero, value.ErrDenied
	}
	first, err := f.peers(call, q, connection, expected)
	if err != nil || first.Holder.Certificate.Binding.PodUID != routeBinding.PodUID || first.Holder.ConfigurationRevision != route.Configuration.Configuration.Revision || first.Holder.Pod != route.Endpoint.Pod || first.Holder.ReplicaSetUID != route.Endpoint.ReplicaSetUID || !route.Valid(f.now()) || selected != nil && (!selected.Valid(f.now()) || !selected.SamePeers(first)) {
		return nil, zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, first.Interval.FreshUntil)
	requestCall, stopRequest := context.WithDeadline(call, until)
	defer stopRequest()
	if raw.SetDeadline(until) != nil {
		return nil, zero, value.ErrUnavailable
	}
	requestDone := make(chan struct{})
	stopRequestIO := context.AfterFunc(requestCall, func() { _ = raw.Close(); close(requestDone) })
	defer func() {
		if !stopRequestIO() {
			<-requestDone
		}
	}()
	authority := net.JoinHostPort(name, strconv.Itoa(f.pin.Pool.NativePort))
	var supplied atomic.Bool
	transport := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 4096, TLSClientConfig: config,
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, value.ErrUnavailable },
		DialTLSContext: func(c context.Context, network, address string) (net.Conn, error) {
			current, e := f.client.ClientCertificate()
			if e != nil || current != expected || c.Err() != nil || requestCall.Err() != nil || f.root.Err() != nil || network != "tcp" || address != authority || !supplied.CompareAndSwap(false, true) {
				return nil, value.ErrUnavailable
			}
			return socket, nil
		},
	}
	defer transport.CloseIdleConnections()
	var input io.Reader
	if method == http.MethodPost {
		input = io.NopCloser(bytes.NewReader(body)) // No GetBody replay path.
	}
	request, err := http.NewRequestWithContext(requestCall, method, "https://"+authority+target, input)
	if err != nil {
		return nil, zero, value.ErrInvalid
	}
	request.ContentLength = int64(len(body))
	request.Header.Set("Accept", media)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", media)
	}
	response, err := transport.RoundTrip(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	maximum := int64(contracts.ClusterObservationBytes)
	if method == http.MethodGet {
		maximum = contracts.ClusterObservationLocatorBytes
	}
	if err != nil || response == nil || response.Body == nil || response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || response.TLS == nil || response.TLS.ServerName != name || response.ContentLength < 1 || response.ContentLength > maximum || len(response.TransferEncoding) != 0 || len(response.Trailer) != 0 {
		return nil, zero, value.ErrUnavailable
	}
	for _, forbidden := range []string{"Content-Encoding", "Set-Cookie", "Location"} {
		if len(response.Header.Values(forbidden)) != 0 {
			return nil, zero, value.ErrUnavailable
		}
	}
	if len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != media || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return nil, zero, value.ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(data)) != response.ContentLength || int64(len(data)) > maximum || requestCall.Err() != nil || len(response.Trailer) != 0 {
		clear(data)
		return nil, zero, value.ErrUnavailable
	}
	last, err := f.peers(requestCall, q, connection, expected)
	if err != nil || !first.Valid(f.now()) || !first.SamePeers(last) || requestCall.Err() != nil || f.root.Err() != nil {
		clear(data)
		return nil, zero, value.ErrUnavailable
	}
	last.Interval.FreshUntil = identity.Earlier(until, last.Interval.FreshUntil)
	if !last.Valid(f.now()) {
		clear(data)
		return nil, zero, value.ErrUnavailable
	}
	return data, last, nil
}
