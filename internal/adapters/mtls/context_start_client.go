package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	execution "asservat.local/asservat/internal/application/execution"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
)

// ContextStartExchangesPerOwner bounds concurrent exchanges to one owner
// process (ADR-271): a second standby per cluster keeps a query or attach
// possible while the other is attached, querying or reopening. The hub's
// per-cluster standby limit still applies.
const ContextStartExchangesPerOwner = 2

// ContextStartClient has one installed pool and connector, no caller URL or
// callback. Every Open is one outbound POST, never a retry of attached work.
// Its reserved connection count is separate from the hub's capture admission.
type ContextStartClient struct {
	root      context.Context
	cancel    context.CancelFunc
	rootID    string
	pool      value.OwnerPool
	roots     *x509.CertPool
	verifier  *OwnerPeerVerifier
	routes    app.OwnerRouteReader
	owners    OwnerPeerAuthenticator
	address   string // ADR-172 fixed dial endpoint; empty dials current route addresses
	connector *ConnectorProcessCredentials
	process   execution.APIProcessReader
	now       func() time.Time
	dial      func(context.Context, string, string) (net.Conn, error)
	mu        sync.Mutex
	closed    bool
	maximum   int
	active    map[*ContextStartExchange]struct{}
}

// OwnerPeerAuthenticator authenticates the hub owner of an actual TLS session:
// the hub's own OwnerAuthenticator, or the regional delegation (ADR-172).
type OwnerPeerAuthenticator interface {
	AuthenticateOwner(context.Context, app.OwnerPeerConnection) (value.AuthenticatedOwner, error)
}

func NewContextStartClient(ctx context.Context, rootID string, pool value.OwnerPool, roots *x509.CertPool, routes app.OwnerRouteReader, owners *app.OwnerAuthenticator, connector *ConnectorProcessCredentials, process execution.APIProcessReader, maximum int, now func() time.Time) (*ContextStartClient, error) {
	if routes == nil || owners == nil || owners.Now == nil {
		return nil, value.ErrInvalid
	}
	return newContextStartClient(ctx, rootID, pool, roots, routes, "", owners, connector, process, maximum, now)
}

// NewRegionalContextStartClient dials one installer-pinned host:port with the
// exact SNI and HTTP authority of each owner (ADR-157/172). It reads no route
// and authenticates owners through the given delegated authenticator.
func NewRegionalContextStartClient(ctx context.Context, rootID string, pool value.OwnerPool, roots *x509.CertPool, address string, owners OwnerPeerAuthenticator, connector *ConnectorProcessCredentials, process execution.APIProcessReader, maximum int, now func() time.Time) (*ContextStartClient, error) {
	host, port, e := net.SplitHostPort(address)
	number, pe := strconv.Atoi(port)
	if e != nil || pe != nil || number < 1 || number > 65535 || host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@?#% \t\r\n") || owners == nil {
		return nil, value.ErrInvalid
	}
	return newContextStartClient(ctx, rootID, pool, roots, nil, address, owners, connector, process, maximum, now)
}

func newContextStartClient(ctx context.Context, rootID string, pool value.OwnerPool, roots *x509.CertPool, routes app.OwnerRouteReader, address string, owners OwnerPeerAuthenticator, connector *ConnectorProcessCredentials, process execution.APIProcessReader, maximum int, now func() time.Time) (*ContextStartClient, error) {
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(rootID) || !pool.Valid() || pool.NativePort == 0 || roots == nil || len(roots.Subjects()) == 0 || (routes == nil) == (address == "") || owners == nil || connector == nil || process == nil || maximum < 1 || maximum > 16 || now == nil {
		return nil, value.ErrInvalid
	}
	verifier, e := NewOwnerPeerVerifierForPool(roots, pool, now)
	if e != nil {
		return nil, e
	}
	if connector.profile.RootID != rootID || connector.profile.Binding.InstallationID != pool.InstallationID || connector.profile.Binding.IssuerEpoch != pool.IssuerEpoch {
		return nil, value.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	return &ContextStartClient{root: root, cancel: cancel, rootID: rootID, pool: pool, roots: roots.Clone(), verifier: verifier, routes: routes, owners: owners, address: address, connector: connector, process: process, now: now, dial: (&net.Dialer{}).DialContext, maximum: maximum, active: make(map[*ContextStartExchange]struct{})}, nil
}

// ContextStartExchange owns the actual one-socket HTTP/2 request. The transport
// wrapper takes these exact I/O handles, not copied authentication fields.
// Close interrupts the socket/body and joins setup, including the Hello writer.
type ContextStartExchange struct {
	client             *ContextStartClient
	owner              value.OwnerBinding
	ctx                context.Context
	cancel             context.CancelFunc
	mu                 sync.Mutex
	raw                net.Conn
	reader             *io.PipeReader
	writer             *io.PipeWriter
	response           *http.Response
	transport          *http.Transport
	receiver           value.APIContextReceiver
	check              app.APIContextReceiverCheck
	closed             bool
	interrupted        sync.Once
	joined             sync.Once
	opened             chan struct{}
	done               chan struct{}
	stopRoot, stopWork func() bool
	rootDone, workDone chan struct{}
}

func (e *ContextStartExchange) Context() context.Context           { return e.ctx }
func (e *ContextStartExchange) Receiver() value.APIContextReceiver { return e.receiver }
func (e *ContextStartExchange) Check(ctx context.Context) (value.APIContextReceiver, error) {
	if e == nil || ctx == nil || e.ctx.Err() != nil || ctx.Err() != nil || e.check == nil {
		return value.APIContextReceiver{}, value.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	ended := make(chan struct{})
	stop := context.AfterFunc(e.ctx, func() { cancel(); close(ended) })
	defer func() {
		if !stop() {
			<-ended
		}
	}()
	return e.check(call)
}
func (e *ContextStartExchange) IO() (*http.Response, *io.PipeWriter, net.Conn, error) {
	if e == nil {
		return nil, nil, nil, value.ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil || e.response == nil || e.writer == nil || e.raw == nil {
		return nil, nil, nil, value.ErrUnavailable
	}
	return e.response, e.writer, e.raw, nil
}
func (e *ContextStartExchange) interrupt() {
	e.interrupted.Do(func() {
		e.cancel()
		e.mu.Lock()
		e.closed = true
		raw, r, w, resp, tr := e.raw, e.reader, e.writer, e.response, e.transport
		e.mu.Unlock()
		if w != nil {
			_ = w.CloseWithError(value.ErrUnavailable)
		}
		if r != nil {
			_ = r.CloseWithError(value.ErrUnavailable)
		}
		if raw != nil {
			_ = raw.SetDeadline(time.Now())
			_ = raw.Close()
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		if tr != nil {
			tr.CloseIdleConnections()
		}
	})
}
func (e *ContextStartExchange) Close() {
	if e == nil {
		return
	}
	e.interrupt()
	<-e.opened
	e.joined.Do(func() {
		if e.stopRoot != nil && !e.stopRoot() {
			<-e.rootDone
		}
		if e.stopWork != nil && !e.stopWork() {
			<-e.workDone
		}
		e.client.mu.Lock()
		delete(e.client.active, e)
		e.client.mu.Unlock()
		close(e.done)
	})
	<-e.done
}
func (c *ContextStartClient) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	list := make([]*ContextStartExchange, 0, len(c.active))
	for e := range c.active {
		list = append(list, e)
	}
	c.mu.Unlock()
	for _, e := range list {
		e.Close()
	}
}
func (c *ContextStartClient) local(ctx context.Context, expected *value.APIContextChannel) (ConnectorProcessObservation, value.APIContextExecutor, time.Time, error) {
	return c.localWithReader(ctx, expected, nil)
}

func (c *ContextStartClient) localWithReader(ctx context.Context, expected *value.APIContextChannel, reader ContextStartProcessReader) (ConnectorProcessObservation, value.APIContextExecutor, time.Time, error) {
	var zero ConnectorProcessObservation
	started := c.now()
	call, stop := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer stop()
	until, _ := call.Deadline()
	var observed ConnectorProcessObservation
	var process executionvalue.APIProcessObservation
	var e error
	if reader == nil {
		reader, _ = c.process.(ContextStartProcessReader)
	}
	if reader != nil {
		process, observed, e = reader.ReadAPIProcessConnector(call, c.connector)
	} else {
		observed, e = c.connector.ObserveConnectorProcess(call)
		if e == nil {
			local, stop := context.WithDeadline(call, observed.ValidUntil)
			process, e = c.process.ReadAPIProcess(local)
			stop()
		}
	}
	if e != nil {
		return zero, value.APIContextExecutor{}, time.Time{}, e
	}
	if !process.Valid(c.now()) {
		return zero, value.APIContextExecutor{}, time.Time{}, value.ErrUnavailable
	}
	until = identity.Earlier(until, observed.ValidUntil)
	b := process.Binding
	p := observed.Registration.Process
	executor := value.APIContextExecutor{NamespaceUID: b.NamespaceUID, AccountUID: b.AccountUID, PodUID: b.PodUID, ProcessEpoch: b.ProcessEpoch, StartupDigest: b.StartupDigest, ImageDigest: b.ImageDigest}
	if !identity.Fresh(observed.ObservedAt, observed.ValidUntil, c.now(), 5*time.Second) || !observed.Registration.Valid(c.now()) || !observed.Configuration.Valid(c.now()) || observed.Request.Process != p ||
		!executor.Valid() || b.InstallationID != p.Binding.InstallationID || b.ClusterID != p.Binding.ClusterID || b.IssuerEpoch != p.Binding.IssuerEpoch || b.PodUID != p.PodUID || b.ProcessEpoch == p.ProcessEpoch || observed.Configuration.Profile.RootID != c.rootID {
		return zero, value.APIContextExecutor{}, time.Time{}, value.ErrDenied
	}
	until = identity.Earlier(until, process.ValidUntil)
	if expected != nil && (expected.RootID != c.rootID || expected.Connector != p || expected.ConnectorLeaf != observed.Registration.Certificate.Digest || expected.Executor != executor) {
		return zero, value.APIContextExecutor{}, time.Time{}, value.ErrDenied
	}
	if call.Err() != nil || !c.now().Before(until) {
		return zero, value.APIContextExecutor{}, time.Time{}, value.ErrUnavailable
	}
	return observed, executor, until, nil
}
func (c *ContextStartClient) current(ctx context.Context, channel value.APIContextChannel, remote *OwnerConnection) (value.APIContextReceiver, error) {
	return c.currentWithReader(ctx, channel, remote, nil, false)
}

func (c *ContextStartClient) currentWithReader(ctx context.Context, channel value.APIContextChannel, remote *OwnerConnection, reader ContextStartProcessReader, afterOwner bool) (value.APIContextReceiver, error) {
	return c.currentWithOpeningDiagnostic(ctx, channel, remote, reader, afterOwner, nil)
}

func (c *ContextStartClient) currentWithOpeningDiagnostic(ctx context.Context, channel value.APIContextChannel, remote *OwnerConnection, reader ContextStartProcessReader, afterOwner bool, diagnostic *contextStartOpeningDiagnostic) (value.APIContextReceiver, error) {
	var zero value.APIContextReceiver
	started := c.now()
	call, stop := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer stop()
	if afterOwner {
		diagnostic.at("process-closing")
	} else {
		diagnostic.at("process-first")
	}
	localStart := time.Now()
	_, _, until, e := c.localWithReader(call, &channel, reader)
	auditapp.MarkStep(ctx, "r-local", localStart)
	if e != nil {
		return zero, receiverCheckStep{"local", e}
	}
	diagnostic.bound(until)
	call, stopLocal := context.WithDeadline(call, until)
	defer stopLocal()
	if afterOwner {
		diagnostic.at("owner-closing")
	} else {
		diagnostic.at("owner-first")
	}
	ownerStart := time.Now()
	owner, e := c.owners.AuthenticateOwner(call, remote)
	auditapp.MarkStep(ctx, "r-owner", ownerStart)
	if e != nil || !owner.Valid(c.now()) || owner.Certificate.Binding != channel.Hub || owner.Pool != c.pool {
		return zero, receiverCheckStep{"owner", value.ErrDenied}
	}
	until = identity.Earlier(until, owner.ValidUntil)
	diagnostic.bound(until)
	if afterOwner {
		diagnostic.at("process-final")
		// Finish may have shortened the local bound before the owner read; the
		// read above carries that bound into it. This final cheap read also
		// detects a local change while owner authentication was blocking.
		finalCall, stopFinal := context.WithDeadline(call, until)
		_, _, finalUntil, err := c.localWithReader(finalCall, &channel, reader)
		stopFinal()
		if err != nil {
			return zero, err
		}
		until = identity.Earlier(until, finalUntil)
		diagnostic.bound(until)
	}
	out := value.APIContextReceiver{Channel: channel, ObservedAt: started, ValidUntil: until}
	if call.Err() != nil || c.root.Err() != nil || !out.Valid(c.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

// OpenDiscovered preserves the original complete discovery cutoff through
// setup. It is distinct from the longer, non-authorizing standby residency.
func (c *ContextStartClient) OpenDiscovered(ctx context.Context, owner value.OwnerBinding, observed value.APIContextOwnerCandidates) (*ContextStartExchange, error) {
	diagnostic := newContextStartOpeningDiagnostic(ctx, observed.ValidUntil)
	if c == nil || !observed.Valid(c.now()) || observed.Pool != c.pool {
		return nil, diagnostic.wrap(value.ErrUnavailable)
	}
	found := false
	for _, b := range observed.Owners {
		if b == owner {
			found = true
		}
	}
	if !found {
		return nil, diagnostic.wrap(value.ErrDenied)
	}
	return c.open(ctx, owner, observed.ValidUntil)
}

// Open is for an independently selected exact installed owner. It still reads
// the current accepted route before dialing and cannot select an arbitrary URL.
func (c *ContextStartClient) Open(ctx context.Context, owner value.OwnerBinding) (*ContextStartExchange, error) {
	if c == nil {
		return nil, value.ErrInvalid
	}
	return c.open(ctx, owner, c.now().Add(5*time.Second))
}
func (c *ContextStartClient) open(ctx context.Context, owner value.OwnerBinding, discoveryUntil time.Time) (result *ContextStartExchange, resultErr error) {
	diagnostic := newContextStartOpeningDiagnostic(ctx, discoveryUntil)
	// Registered first: observe the refusal only after every existing join.
	defer func() { resultErr = diagnostic.wrap(resultErr) }()
	if c == nil || ctx == nil || ctx.Err() != nil || !owner.Valid() || owner.InstallationID != c.pool.InstallationID || owner.ClusterID != c.pool.ClusterID || owner.IssuerEpoch != c.pool.IssuerEpoch {
		return nil, value.ErrInvalid
	}
	start := c.now()
	until, ok := ctx.Deadline()
	if !ok || !start.Before(until) || until.After(start.Add(30*time.Second)) {
		return nil, value.ErrInvalid
	}
	c.mu.Lock()
	same := 0
	for e := range c.active {
		if e.owner == owner {
			same++
		}
	}
	if c.closed || c.root.Err() != nil || len(c.active) >= c.maximum || same >= ContextStartExchangesPerOwner {
		c.mu.Unlock()
		return nil, value.ErrUnavailable
	}
	work, cancel := context.WithCancel(ctx)
	exchange := &ContextStartExchange{client: c, owner: owner, ctx: work, cancel: cancel, opened: make(chan struct{}), done: make(chan struct{})}
	c.active[exchange] = struct{}{}
	c.mu.Unlock()
	success := false
	exchange.rootDone, exchange.workDone = make(chan struct{}), make(chan struct{})
	exchange.stopRoot = context.AfterFunc(c.root, func() { exchange.interrupt(); close(exchange.rootDone) })
	exchange.stopWork = context.AfterFunc(work, func() { exchange.interrupt(); close(exchange.workDone) })
	defer func() {
		close(exchange.opened)
		if !success {
			exchange.Close()
		}
	}()
	diagnostic.bound(identity.Earlier(start.Add(5*time.Second), discoveryUntil))
	diagnostic.at("setup-begin")
	setup, stopSetup := context.WithDeadline(work, identity.Earlier(start.Add(5*time.Second), discoveryUntil))
	defer stopSetup()
	setupDone := make(chan struct{})
	stopSetupIO := context.AfterFunc(setup, func() { exchange.interrupt(); close(setupDone) })
	defer func() {
		if !stopSetupIO() {
			<-setupDone
		}
	}()
	var owned ContextStartProcessSetup
	defer func() {
		if owned != nil {
			owned.Close()
		}
	}()
	if producer, ok := c.process.(ContextStartProcessSetupReader); ok {
		var err error
		owned, err = producer.BeginAPIContextSetup(setup, c.connector)
		if err != nil || owned == nil {
			diagnostic.setupStep(err)
			return nil, value.ErrUnavailable
		}
	}
	diagnostic.at("process-open")
	local, executor, bound, e := c.localWithReader(setup, nil, owned)
	if e != nil {
		return nil, e
	}
	diagnostic.bound(bound)
	setup, stopLocal := context.WithDeadline(setup, bound)
	defer stopLocal()
	addresses := []string{c.address}
	if c.address == "" {
		diagnostic.at("route")
		route, e := c.routes.CurrentOwnerRoute(setup, owner)
		if e != nil || !route.Valid(c.now()) || route.Endpoint.Binding != owner || route.Endpoint.Pool != c.pool {
			return nil, value.ErrUnavailable
		}
		bound = identity.Earlier(bound, route.FreshUntil)
		addresses = addresses[:0]
		for _, a := range route.Endpoint.Addresses {
			addresses = append(addresses, net.JoinHostPort(a, strconv.Itoa(c.pool.NativePort)))
		}
	}
	diagnostic.bound(bound)
	diagnostic.at("channel")
	setup, stopRoute := context.WithDeadline(setup, bound)
	defer stopRoute()
	channel := value.APIContextChannel{RootID: c.rootID, ExchangeID: uuid.NewString(), Challenge: uuid.NewString(), Hub: owner, Connector: local.Registration.Process, ConnectorLeaf: local.Registration.Certificate.Digest, Executor: executor}
	if !channel.Valid() {
		return nil, value.ErrDenied
	}
	name, e := OwnerServerName(owner)
	if e != nil {
		return nil, e
	}
	diagnostic.at("dial")
	var raw net.Conn
	for _, address := range addresses {
		if setup.Err() != nil {
			break
		}
		raw, e = c.dial(setup, "tcp", address)
		if e == nil && raw != nil {
			break
		}
		if raw != nil {
			_ = raw.Close()
			raw = nil
		}
	}
	if e != nil || raw == nil {
		return nil, value.ErrUnavailable
	}
	exchange.mu.Lock()
	if exchange.closed {
		exchange.mu.Unlock()
		_ = raw.Close()
		return nil, value.ErrUnavailable
	}
	exchange.raw = raw
	exchange.mu.Unlock()
	if raw.SetDeadline(bound) != nil {
		return nil, value.ErrUnavailable
	}
	diagnostic.at("tls")
	config := &tls.Config{RootCAs: c.roots.Clone(), MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, ServerName: name, Time: c.now, SessionTicketsDisabled: true}
	config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if setup.Err() != nil || work.Err() != nil {
			return nil, value.ErrUnavailable
		}
		cert, e := c.connector.GetClientCertificate(info)
		if e != nil || cert == nil || len(cert.Certificate) == 0 || artifact.Digest(sha256.Sum256(cert.Certificate[0])) != channel.ConnectorLeaf {
			return nil, value.ErrDenied
		}
		return cert, nil
	}
	socket := tls.Client(raw, config)
	if socket.HandshakeContext(setup) != nil {
		return nil, value.ErrDenied
	}
	state := socket.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		return nil, value.ErrDenied
	}
	diagnostic.at("peer")
	remote, e := NewOwnerServerConnection(c.verifier, &state, owner)
	if e != nil {
		return nil, e
	}
	check := func(call context.Context) (value.APIContextReceiver, error) { return c.current(call, channel, remote) }
	// Only this opening uses the private setup handle. The closure retained
	// by the returned exchange deliberately keeps the full current path.
	receiver, e := c.currentWithOpeningDiagnostic(setup, channel, remote, owned, false, diagnostic)
	if e != nil {
		return nil, e
	}
	bound = identity.Earlier(bound, receiver.ValidUntil)
	diagnostic.bound(bound)
	if setup.Err() != nil || !c.now().Before(bound) || socket.SetDeadline(bound) != nil {
		return nil, value.ErrUnavailable
	}
	// The standard HTTP/2 transport owns framing/flow control. Exactly one
	// already authenticated socket may be handed over, and the body has no replay.
	var used atomic.Bool
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 0, MaxResponseHeaderBytes: 4096, ResponseHeaderTimeout: 5 * time.Second, TLSClientConfig: config,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if !used.CompareAndSwap(false, true) {
				return nil, value.ErrUnavailable
			}
			return socket, nil
		}}
	reader, writer := io.Pipe()
	exchange.mu.Lock()
	if exchange.closed {
		exchange.mu.Unlock()
		reader.Close()
		writer.Close()
		return nil, value.ErrUnavailable
	}
	exchange.reader, exchange.writer, exchange.transport = reader, writer, tr
	exchange.mu.Unlock()
	// Set deadline callbacks for the smallest original observation too: socket
	// deadlines alone cannot interrupt a blocked HTTP/2 request-body pipe.
	phase, stopPhase := context.WithDeadline(setup, bound)
	defer stopPhase()
	phaseDone := make(chan struct{})
	stopPhaseIO := context.AfterFunc(phase, func() { exchange.interrupt(); close(phaseDone) })
	defer func() {
		if !stopPhaseIO() {
			<-phaseDone
		}
	}()
	diagnostic.at("hello")
	endpoint := "https://" + net.JoinHostPort(name, strconv.Itoa(c.pool.NativePort)) + contracts.APIContextStartPath
	request, e := http.NewRequestWithContext(work, http.MethodPost, endpoint, reader)
	if e != nil {
		return nil, value.ErrInvalid
	}
	request.Header.Set("Content-Type", contracts.APIContextStartMedia)
	request.Header.Set("Accept", contracts.APIContextStartMedia)
	hello, e := contracts.EncodeAPIContextHello(contracts.APIContextHello{Format: contracts.APIContextExchangeFormat, Channel: contextStartChannelWire(channel), StandbyUntil: until.UTC().Truncate(time.Microsecond)})
	if e != nil {
		return nil, e
	}
	// ADR-207: the private setup may lend its actual initial closing source,
	// once, within the same original interval. Other readers retain ADR-178's
	// independent source read. The hub still verifies the received source.
	diagnostic.at("source")
	var source []byte
	if owned != nil {
		var observed value.ConnectorIdentitySource
		observed, e = owned.Source(phase)
		if e == nil && (!observed.Valid(c.now()) || !observed.Observation.SameSource(local.Configuration) || observed.Observation.FreshUntil.Before(bound) || phase.Err() != nil) {
			e = value.ErrUnavailable
		}
		if e == nil {
			source, e = encodeContextStartSourceFrame(observed, channel.ExchangeID)
		}
	} else {
		source, e = contextStartSourceFrame(setup, c.connector.source, channel.ExchangeID)
	}
	if e != nil {
		clear(hello)
		return nil, value.ErrUnavailable
	}
	diagnostic.at("headers")
	wrote := make(chan error, 1)
	go func() {
		defer clear(hello)
		defer clear(source)
		e := contracts.WriteAPIContextFrame(writer, contracts.APIContextFrame{Kind: contracts.APIContextHelloFrame, Payload: hello})
		if e == nil {
			e = contracts.WriteAPIContextFrame(writer, contracts.APIContextFrame{Kind: contracts.APIContextSourceFrame, Payload: source})
		}
		wrote <- e
	}()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return value.ErrDenied }}
	response, e := client.Do(request)
	if e != nil {
		exchange.interrupt()
		<-wrote
		if response != nil {
			response.Body.Close()
		}
		return nil, value.ErrUnavailable
	}
	exchange.mu.Lock()
	closed := exchange.closed
	if !closed {
		exchange.response = response
	}
	exchange.mu.Unlock()
	if closed {
		response.Body.Close()
		<-wrote
		return nil, value.ErrUnavailable
	}
	header := response.Header.Values("Content-Type")
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || response.ContentLength != -1 || len(response.TransferEncoding) != 0 || response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.NegotiatedProtocol != "h2" || len(header) != 1 || header[0] != contracts.APIContextStartMedia || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Location")) != 0 {
		exchange.interrupt()
		<-wrote
		return nil, value.ErrDenied
	}
	diagnostic.at("hello")
	if e = <-wrote; e != nil || phase.Err() != nil || !c.now().Before(bound) {
		return nil, value.ErrUnavailable
	}
	// Header completion does not grant a capture. Future frames independently
	// retain a current peer bound and the original signed human request interval.
	diagnostic.at("finish")
	if owned != nil {
		if e = owned.Finish(phase); e != nil || phase.Err() != nil {
			return nil, value.ErrUnavailable
		}
	}
	final, e := c.currentWithOpeningDiagnostic(phase, channel, remote, owned, owned != nil, diagnostic)
	if e != nil || !final.Valid(c.now()) || phase.Err() != nil {
		return nil, value.ErrUnavailable
	}
	diagnostic.bound(final.ValidUntil)
	diagnostic.at("close")
	if owned != nil {
		// Join before publishing the exchange or releasing setup ownership.
		// A cancellation/expiry during cleanup must not return a positive Open.
		owned.Close()
		owned = nil
	}
	if phase.Err() != nil || work.Err() != nil || c.root.Err() != nil || !final.Valid(c.now()) || !c.now().Before(bound) {
		return nil, value.ErrUnavailable
	}
	if socket.SetDeadline(until) != nil {
		return nil, value.ErrUnavailable
	}
	exchange.mu.Lock()
	if exchange.closed {
		exchange.mu.Unlock()
		return nil, value.ErrUnavailable
	}
	exchange.receiver, exchange.check = final, check
	exchange.mu.Unlock()
	success = true
	return exchange, nil
}

// contextStartSourceFrame encodes the first ADR-178 source frame (sequence 0).
func contextStartSourceFrame(ctx context.Context, source app.ConnectorIdentitySourceReader, exchange string) ([]byte, error) {
	if source == nil || ctx == nil {
		return nil, value.ErrInvalid
	}
	observed, e := source.ReadConnectorIdentitySource(ctx)
	if e != nil {
		return nil, e
	}
	return encodeContextStartSourceFrame(observed, exchange)
}

func encodeContextStartSourceFrame(observed value.ConnectorIdentitySource, exchange string) ([]byte, error) {
	raw, e := json.Marshal(observed)
	if e != nil {
		return nil, value.ErrInvalid
	}
	return contracts.EncodeAPIContextSource(contracts.APIContextSource{Format: contracts.APIContextExchangeFormat, ExchangeID: exchange, Sequence: 0, Source: raw})
}

// receiverCheckStep keeps the returned error and names which half of a current
// receiver check failed (the local process proof or the owner authentication),
// for the stream's fixed diagnostics only.
type receiverCheckStep struct {
	step string
	err  error
}

func (e receiverCheckStep) Error() string             { return e.err.Error() }
func (e receiverCheckStep) Unwrap() error             { return e.err }
func (e receiverCheckStep) ReceiverCheckStep() string { return e.step }
