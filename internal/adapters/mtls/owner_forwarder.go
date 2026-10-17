package mtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Inputs are protected composition, never worker/developer configuration. Worker
// trust is selected by the exact current stored profile, never a wire argument.
type OwnerForwarderConfig struct {
	Pool           fleet.OwnerPool
	WorkerTrust    *WorkerTrustCatalog
	Client         *OwnerCredentials
	OwnerRoots     *x509.CertPool
	Routes         app.OwnerRouteReader
	Authentication *app.OwnerAuthenticator
	Owners         evidence.WorkerOwnerLookup
	Workers        evidence.WorkerEnrollmentBindings
	Now            func() time.Time
	Concurrency    int
}
type OwnerForwarder struct {
	config   OwnerForwarderConfig
	verifier *OwnerPeerVerifier
	root     context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	dial     func(context.Context, string, string) (net.Conn, error)
}

func NewOwnerForwarder(ctx context.Context, config OwnerForwarderConfig) (*OwnerForwarder, error) {
	if ctx == nil || ctx.Err() != nil || !config.Pool.Valid() || !config.WorkerTrust.ForInstallation(config.Pool.InstallationID) || config.Client == nil || config.Routes == nil || config.Authentication == nil || config.Owners == nil || config.Workers == nil || config.Now == nil || config.Concurrency < 1 || config.Concurrency > 16 {
		return nil, artifact.ErrInvalid
	}
	b := config.Client.binding
	if config.Client.usage != "client" || b.InstallationID != config.Pool.InstallationID || b.ClusterID != config.Pool.ClusterID || b.IssuerEpoch != config.Pool.IssuerEpoch {
		return nil, artifact.ErrInvalid
	}
	verifier, err := NewOwnerPeerVerifierForPool(config.OwnerRoots, config.Pool, config.Now)
	if err != nil {
		return nil, err
	}
	config.OwnerRoots = config.OwnerRoots.Clone()
	root, cancel := context.WithCancel(ctx)
	return &OwnerForwarder{config, verifier, root, cancel, make(chan struct{}, config.Concurrency), (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext}, nil
}
func (f *OwnerForwarder) Close() {
	if f != nil && f.cancel != nil {
		f.cancel()
	}
}

func forwardTarget(w value.DownloadWorker) value.WorkerCredentialTarget {
	return value.WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
}
func sameForwardWorker(a, b value.DownloadWorker) bool {
	return a.Binding == b.Binding && a.Job == b.Job && a.Intent.ID == b.Intent.ID && a.Intent.SessionID == b.Intent.SessionID && a.Intent.Generation == b.Intent.Generation && a.Intent.Profile == b.Intent.Profile && a.Intent.Authority.Scope == b.Intent.Authority.Scope && a.Intent.CreatedAt.Equal(b.Intent.CreatedAt) && a.Intent.RunUntil.Equal(b.Intent.RunUntil)
}
func (f *OwnerForwarder) worker(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
	o, e := f.config.Workers.ReadDownloadWorkerEnrollment(ctx, session, worker)
	if e != nil || ctx.Err() != nil || !o.Valid(f.config.Now()) || o.Worker.Intent.ID != worker || o.Worker.Intent.SessionID != session || o.Worker.Intent.Profile.InstallationID != f.config.Pool.InstallationID {
		return value.DownloadWorkerIdentity{}, artifact.ErrDownloadUnavailable
	}
	return o, nil
}
func (f *OwnerForwarder) workerVerifier(p value.DownloadWorkerProfile) (*KeyPeerVerifier, error) {
	roots, err := f.config.WorkerTrust.IssuerRoots(p, f.config.Now())
	if err != nil {
		return nil, err
	}
	return NewKeyPeerVerifier(roots, p.InstallationID, f.config.Now)
}
func (f *OwnerForwarder) currentLocator(ctx context.Context, expected value.WorkerOwnerLease) bool {
	l, e := f.config.Owners.ReadWorkerOwner(ctx, expected.Request.SessionID, expected.Request.WorkerID)
	return e == nil && ctx.Err() == nil && l.Equal(expected) && l.Valid(f.config.Now())
}
func (f *OwnerForwarder) peers(ctx context.Context, connection *OwnerConnection, client fleet.OwnerCertificate) (fleet.AuthenticatedOwner, time.Time, error) {
	var zero fleet.AuthenticatedOwner
	start := f.config.Now()
	ctx, end := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer end()
	local, err := f.config.Authentication.CheckOwnerClient(ctx, f.config.Client)
	if err != nil {
		return zero, time.Time{}, artifact.ErrDownloadUnavailable
	}
	peer, err := f.config.Authentication.AuthenticateOwner(ctx, connection)
	current, e := f.config.Client.ClientCertificate()
	if err != nil || e != nil || ctx.Err() != nil || !sameOwnerCertificate(current, client) || !peer.Valid(f.config.Now()) || peer.Certificate.Usage != "server" || peer.Pool != f.config.Pool || !f.config.Now().Before(local) {
		return zero, time.Time{}, artifact.ErrDownloadUnavailable
	}
	until := identity.Earlier(start.Add(5*time.Second), identity.Earlier(local, peer.ValidUntil))
	if !f.config.Now().Before(until) {
		return zero, time.Time{}, artifact.ErrDownloadExpired
	}
	return peer, until, nil
}
func sameForwardPeer(a, b fleet.AuthenticatedOwner) bool {
	return sameOwnerCertificate(a.Certificate, b.Certificate) && a.EnrollmentID == b.EnrollmentID && a.Pool == b.Pool && a.Pod == b.Pod && a.ReplicaSetUID == b.ReplicaSetUID && a.ConfigurationRevision == b.ConfigurationRevision && a.ProtectionDigest == b.ProtectionDigest
}

// BeginWorkerEnrollment retains the original remote owner's live connection
// through downstream response delivery. Close is mandatory on every path.
func (f *OwnerForwarder) BeginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	var zero evidence.WorkerEnrollmentDelivery
	if f == nil || ctx == nil || ctx.Err() != nil || f.root.Err() != nil || installation != f.config.Pool.InstallationID || !value.UUID(session) || !value.UUID(worker) || !contracts.ValidWorkerToken(token) || len(csr) < 32 || len(csr) > 8192 {
		return zero, artifact.ErrInvalid
	}
	if _, err := EnrollmentKey(csr); err != nil {
		return zero, artifact.ErrInvalid
	}
	select {
	case f.slots <- struct{}{}:
	default:
		return zero, artifact.ErrDownloadCapacity
	}
	start := f.config.Now()
	call, cancel := context.WithDeadline(ctx, start.Add(30*time.Second))
	var cleanups []func()
	cleanups = append(cleanups, func() { <-f.slots })
	retained := false
	release := sync.OnceFunc(func() {
		cancel()
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	})
	defer func() {
		if !retained {
			release()
		}
	}()
	stopRoot := context.AfterFunc(f.root, cancel)
	cleanups = append(cleanups, func() { stopRoot() })
	secret := bytes.Clone(token)
	defer clear(secret)
	csr = bytes.Clone(csr)
	lease, err := f.config.Owners.ReadWorkerOwner(call, session, worker)
	if err != nil || !lease.Valid(f.config.Now()) || lease.Request.InstallationID != installation || lease.Request.SessionID != session || lease.Request.WorkerID != worker || call.Err() != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	call, end := context.WithDeadline(call, lease.Request.Until)
	cleanups = append(cleanups, end)
	initial, err := f.worker(call, session, worker)
	if err != nil {
		return zero, err
	}
	if _, err = f.workerVerifier(initial.Worker.Intent.Profile); err != nil {
		return zero, err
	}
	call, endWorker := context.WithDeadline(call, initial.Worker.Intent.RunUntil)
	cleanups = append(cleanups, endWorker)
	binding := fleet.OwnerBinding{InstallationID: installation, ClusterID: f.config.Pool.ClusterID, IssuerEpoch: f.config.Pool.IssuerEpoch, PodUID: lease.Request.PodUID, ProcessEpoch: lease.Request.ProcessEpoch}
	route, err := f.config.Routes.CurrentOwnerRoute(call, binding)
	if err != nil || !route.Valid(f.config.Now()) || route.Endpoint.Binding != binding || route.Endpoint.Pool != f.config.Pool {
		return zero, artifact.ErrDownloadUnavailable
	}
	route.Configuration.Configuration = route.Configuration.Configuration.Clone()
	route.Endpoint.Addresses = slices.Clone(route.Endpoint.Addresses)
	name, err := OwnerServerName(binding)
	if err != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	client, err := f.config.Client.ClientCertificate()
	if err != nil {
		return zero, err
	}
	deadline, _ := call.Deadline()
	deadline = identity.Earlier(deadline, client.NotAfter)
	setupUntil := identity.Earlier(route.FreshUntil, identity.Earlier(initial.FreshUntil, deadline))
	setup, stopSetup := context.WithDeadline(call, setupUntil)
	defer stopSetup()
	var raw net.Conn
	// Two pinned Pod addresses at most; fallback is only before any HTTP bytes.
	for _, address := range route.Endpoint.Addresses {
		if setup.Err() != nil || f.root.Err() != nil {
			break
		}
		raw, err = f.dial(setup, "tcp", net.JoinHostPort(address, strconv.Itoa(route.Endpoint.Pool.Port)))
		if err == nil && raw != nil {
			break
		}
		if raw != nil {
			raw.Close()
			raw = nil
		}
	}
	if err != nil || raw == nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	cleanups = append(cleanups, func() { raw.Close() })
	interrupted := make(chan struct{})
	stopClose := context.AfterFunc(call, func() { raw.Close(); close(interrupted) })
	cleanups = append(cleanups, func() {
		if !stopClose() {
			<-interrupted
		}
	})
	if raw.SetDeadline(deadline) != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: f.config.OwnerRoots, ServerName: name, Time: f.config.Now, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if f.root.Err() != nil || call.Err() != nil {
			return nil, artifact.ErrDownloadExpired
		}
		cert, e := f.config.Client.GetClientCertificate(info)
		if e != nil || cert == nil || len(cert.Certificate) == 0 || artifact.Digest(sha256.Sum256(cert.Certificate[0])) != client.Digest {
			return nil, artifact.ErrDownloadExpired
		}
		return cert, nil
	}
	conn := tls.Client(raw, tlsConfig)
	if conn.HandshakeContext(setup) != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	state := conn.ConnectionState()
	if state.DidResume || state.NegotiatedProtocol != "http/1.1" {
		return zero, artifact.ErrDownloadUnavailable
	}
	connection, err := NewOwnerServerConnection(f.verifier, &state, binding)
	if err != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	peer, sendUntil, err := f.peers(setup, connection, client)
	if err != nil || peer.ConfigurationRevision != route.Configuration.Configuration.Revision || peer.Pod != route.Endpoint.Pod || peer.ReplicaSetUID != route.Endpoint.ReplicaSetUID || !f.currentLocator(setup, lease) || !initial.Valid(f.config.Now()) || !route.Valid(f.config.Now()) || setup.Err() != nil || f.root.Err() != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	if _, err = f.workerVerifier(initial.Worker.Intent.Profile); err != nil {
		return zero, err
	}
	sendUntil = identity.Earlier(sendUntil, setupUntil)
	if raw.SetWriteDeadline(sendUntil) != nil || raw.SetReadDeadline(deadline) != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	request := contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: installation, SessionID: session, WorkerID: worker, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), CSR: csr}
	in := contracts.OwnerRelayRequest{Format: contracts.OwnerRelayFormat, Locator: contracts.OwnerRelayLocator{RequestID: lease.Request.ID, PodUID: lease.Request.PodUID, ProcessEpoch: lease.Request.ProcessEpoch, Fence: lease.Fence, Started: lease.Started, Until: lease.Request.Until}, Enrollment: request}
	b, err := json.Marshal(in)
	if err != nil || len(b) > contracts.OwnerRelayMaxRequest {
		return zero, artifact.ErrInvalid
	}
	defer clear(b)
	host := net.JoinHostPort(name, strconv.Itoa(route.Endpoint.Pool.Port))
	req, err := http.NewRequestWithContext(call, http.MethodPost, "https://"+host+contracts.OwnerRelayPath, io.NopCloser(bytes.NewReader(b)))
	if err != nil {
		return zero, artifact.ErrInvalid
	}
	req.ContentLength = int64(len(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(secret))
	req.Header.Set("Accept", contracts.OwnerRelayContentType)
	var supplied atomic.Bool
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	tr := &http.Transport{Protocols: protocols, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 4096, ResponseHeaderTimeout: 30 * time.Second,
		DialTLSContext: func(c context.Context, network, address string) (net.Conn, error) {
			current, err := f.config.Client.ClientCertificate()
			if err != nil || !sameOwnerCertificate(current, client) || c.Err() != nil || call.Err() != nil || f.root.Err() != nil || network != "tcp" || address != host || !f.config.Now().Before(sendUntil) || !supplied.CompareAndSwap(false, true) {
				return nil, artifact.ErrDownloadUnavailable
			}
			return conn, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, artifact.ErrDownloadUnavailable },
	}
	cleanups = append(cleanups, tr.CloseIdleConnections)
	// Fresh one-use transport, non-replayable body, no redirect/cookie/proxy client.
	response, err := tr.RoundTrip(req)
	if response != nil && response.Body != nil {
		cleanups = append(cleanups, func() { response.Body.Close() })
	}
	if err != nil || response == nil || response.StatusCode != 200 || response.ProtoMajor != 1 || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != contracts.OwnerRelayContentType || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Set-Cookie")) != 0 || len(response.Header.Values("Location")) != 0 || response.ContentLength != -1 || len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" || len(response.Trailer) != 0 {
		return zero, artifact.ErrDownloadUnavailable
	}
	frame, err := contracts.DecodeOwnerRelayResponse(response.Body)
	if err != nil || frame.Format != contracts.OwnerRelayFormat || !f.config.Now().Before(frame.Until) || frame.Until.After(lease.Request.Until) {
		return zero, artifact.ErrIntegrity
	}
	// The certificate frame is not a completed response. EOF, extra data or any
	// transport error loses remote ownership. One bounded reader owns the body
	// until Close, and cleanup closes its socket and joins it.
	streamDone := make(chan struct{})
	go func() {
		var extra [1]byte
		_, _ = io.ReadFull(response.Body, extra[:])
		cancel()
		close(streamDone)
	}()
	cleanups = append(cleanups, func() { raw.Close(); <-streamDone })
	out := frame.Enrollment
	if out.Format != request.Format || out.InstallationID != installation || out.SessionID != session || out.WorkerID != worker || out.Nonce != request.Nonce || out.Chain == nil {
		return zero, artifact.ErrIntegrity
	}
	workerVerifier, err := f.workerVerifier(initial.Worker.Intent.Profile)
	if err != nil {
		return zero, err
	}
	cert, identity, err := checkWorkerCertificate(workerVerifier, forwardTarget(initial.Worker), f.config.Now, start, csr, out.Certificate, out.Chain)
	if err != nil {
		return zero, err
	}
	last, until, err := f.peers(call, connection, client)
	if err != nil || !sameForwardPeer(peer, last) || !f.currentLocator(call, lease) {
		return zero, artifact.ErrDownloadUnavailable
	}
	current, err := f.worker(call, session, worker)
	if err != nil || !sameForwardWorker(initial.Worker, current.Worker) || !current.Valid(f.config.Now()) || call.Err() != nil || f.root.Err() != nil || !f.config.Now().Before(until) || !f.config.Now().Before(deadline) || !identity.Valid(f.config.Now()) || f.config.Now().Before(start) {
		return zero, artifact.ErrDownloadExpired
	}
	workerVerifier, err = f.workerVerifier(current.Worker.Intent.Profile)
	if err != nil {
		return zero, err
	}
	cert, identity, err = checkWorkerCertificate(workerVerifier, forwardTarget(current.Worker), f.config.Now, start, csr, out.Certificate, out.Chain)
	if err != nil {
		return zero, err
	}
	deadline = earlierOwnerDeadline(deadline, frame.Until, until, current.FreshUntil, identity.NotAfter)
	if !f.config.Now().Before(deadline) || raw.SetReadDeadline(deadline) != nil {
		return zero, artifact.ErrDownloadExpired
	}
	live, stopLive := context.WithDeadline(call, deadline)
	stopLifetime := context.AfterFunc(live, cancel)
	cleanups = append(cleanups, func() { stopLifetime(); stopLive() })
	if live.Err() != nil || f.root.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	retained = true
	return &ownerForwardDelivery{live, value.WorkerCertificate{Peer: identity, DER: cert.Certificate[0], ChainDER: cert.Certificate[1:]}, release}, nil
}

func earlierOwnerDeadline(first time.Time, rest ...time.Time) time.Time {
	for _, d := range rest {
		if d.Before(first) {
			first = d
		}
	}
	return first
}

type ownerForwardDelivery struct {
	ctx         context.Context
	certificate value.WorkerCertificate
	release     func()
}

func (d *ownerForwardDelivery) Context() context.Context             { return d.ctx }
func (d *ownerForwardDelivery) Certificate() value.WorkerCertificate { return d.certificate }
func (d *ownerForwardDelivery) Close()                               { d.release() }

// Finite callers explicitly release ownership on return. Worker ingress uses
// BeginWorkerEnrollment so that ownership survives its final response flush.
func (f *OwnerForwarder) ForwardWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (value.WorkerCertificate, error) {
	d, err := f.BeginWorkerEnrollment(ctx, installation, session, worker, token, csr)
	if err != nil {
		return value.WorkerCertificate{}, err
	}
	defer d.Close()
	if d.Context().Err() != nil {
		return value.WorkerCertificate{}, artifact.ErrDownloadExpired
	}
	return d.Certificate(), nil
}
