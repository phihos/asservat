package bootstrap

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
)

// OwnerLocalObservationReceiver is the closed v2 common-SNI locator GET
// and exact-SNI one-use claim POST composition. It does not select a listener,
// installed profile, arbitrary route or retry. Its concrete dependencies come
// only from the original accepted backend. Pending slots retain uncertain
// deliveries until the original end; active HTTP work has a separate same-size
// process ceiling. Neither promises installation-wide capacity.
type OwnerLocalObservationReceiver struct {
	root                                         context.Context
	cancel                                       context.CancelFunc
	pin                                          value.OwnerObservationPin
	binding                                      value.OwnerBinding
	server                                       *mtls.OwnerCredentials
	registry                                     app.OwnerCertificateRegistry
	native                                       ownerLocalNativeReader
	holder                                       *wire.HubObservationOperationHolder
	pending                                      *ownerLocalObservationPending
	commonName, commonHost, exactName, exactHost string
	now                                          func() time.Time
	mu                                           sync.Mutex
	closed                                       bool
	active, maximum                              int
	joined                                       sync.WaitGroup
	refusedMu                                    sync.Mutex
	refusedLast                                  string
	timing                                       func(string)
}

// refused logs one closed claim refusal stage, any nested fixed step and the
// cause per change, for operator diagnostics (ADR-197); never remote text.
func (h *OwnerLocalObservationReceiver) refused(stage string, err error) {
	if err == nil {
		err = value.ErrUnavailable
	}
	line := stage + " (" + regionalCause(err) + ")"
	var step interface{ FixedStep() string }
	if errors.As(err, &step) {
		line = stage + "/" + step.FixedStep() + " (" + regionalCause(err) + ")"
	}
	h.refusedMu.Lock()
	defer h.refusedMu.Unlock()
	if line != h.refusedLast {
		h.refusedLast = line
		fmt.Fprintln(os.Stderr, "owner local claim refused: "+line)
	}
}

// Private test seams have no deployment representation. Public construction
// requires the original scoped SQL adapter and concrete native caller reader.
type ownerLocalNativeOperation interface {
	app.OwnerNativeObservationOperation
	Claim(context.Context, []byte, string) (time.Time, error)
}
type ownerLocalNativeReader interface {
	begin(context.Context, value.OwnerObservationRequest, value.OwnerBinding, []byte, string) (ownerLocalNativeOperation, error)
}
type ownerLocalNativeReaderAdapter struct {
	reader *kube.OwnerLocalObservationOperationReader
}

func (r ownerLocalNativeReaderAdapter) begin(ctx context.Context, q value.OwnerObservationRequest, b value.OwnerBinding, token []byte, pod string) (ownerLocalNativeOperation, error) {
	return r.reader.Begin(ctx, q, b, token, pod)
}

type ownedOwnerLocalNative struct {
	ownerLocalNativeOperation
	cancel context.CancelFunc
	once   sync.Once
}

func (n *ownedOwnerLocalNative) Close() {
	n.once.Do(func() { n.cancel(); n.ownerLocalNativeOperation.Close() })
}

func NewOwnerLocalObservationReceiver(ctx context.Context, pin value.OwnerObservationPin, server *mtls.OwnerCredentials, registry *postgres.OwnerEnrollments, native *kube.OwnerLocalObservationOperationReader, holder *wire.HubObservationOperationHolder, maximum int, now func() time.Time) (*OwnerLocalObservationReceiver, error) {
	if registry == nil || native == nil {
		return nil, value.ErrInvalid
	}
	h, err := newOwnerLocalObservationReceiver(ctx, pin, server, registry, ownerLocalNativeReaderAdapter{native}, holder, maximum, now)
	if h != nil {
		h.timing = eventLog(os.Stderr, "owner local claim timing")
	}
	return h, err
}
func newOwnerLocalObservationReceiver(ctx context.Context, pin value.OwnerObservationPin, server *mtls.OwnerCredentials, registry app.OwnerCertificateRegistry, native ownerLocalNativeReader, holder *wire.HubObservationOperationHolder, maximum int, now func() time.Time) (*OwnerLocalObservationReceiver, error) {
	if ctx == nil || ctx.Err() != nil || !pin.Valid() || pin.Pool.NativeCandidateLimit == 0 || server == nil || registry == nil || native == nil || holder == nil || maximum < 1 || maximum > 16 || now == nil {
		return nil, value.ErrInvalid
	}
	leaf, err := server.ServingCertificate()
	if err != nil || leaf.Usage != "server" || leaf.Binding.InstallationID != pin.Pool.InstallationID || leaf.Binding.ClusterID != pin.Pool.ClusterID || leaf.Binding.IssuerEpoch != pin.Pool.IssuerEpoch {
		return nil, value.ErrInvalid
	}
	common, ce := mtls.OwnerBootstrapServerName(pin.Pool)
	exact, ee := mtls.OwnerServerName(leaf.Binding)
	if ce != nil || ee != nil {
		return nil, value.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	pending, err := newOwnerLocalObservationPending(root, pin, leaf.Binding, maximum, now)
	if err != nil {
		cancel()
		return nil, err
	}
	port := strconv.Itoa(pin.Pool.OperationListenPort())
	return &OwnerLocalObservationReceiver{root: root, cancel: cancel, pin: pin, binding: leaf.Binding, server: server, registry: registry, native: native, holder: holder, pending: pending, commonName: common, commonHost: net.JoinHostPort(common, port), exactName: exact, exactHost: net.JoinHostPort(exact, port), maximum: maximum, now: now}, nil
}

// This per-operation decorator always performs the real scoped read. It only
// retains restrictive earlier cutoffs and exact first identity, never a cached
// authority value. A shorter accepted source/recovery date reaches the next
// native/SQL/stream call, including reads made inside the existing coordinator.
type ownerLocalObservationRegistry struct {
	root     context.Context
	pin      value.OwnerObservationPin
	server   *mtls.OwnerCredentials
	leaf     value.OwnerCertificate
	registry app.OwnerCertificateRegistry
	now      func() time.Time
	mu       sync.Mutex
	end      time.Time
	first    *value.OwnerRegistrationObservation
	closed   bool
}

func (r *ownerLocalObservationRegistry) until(ctx context.Context) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, value.ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	end, finite := ctx.Deadline()
	if !finite || ctx.Err() != nil || r.root.Err() != nil || r.closed || !r.now().Before(r.end) {
		return time.Time{}, value.ErrUnavailable
	}
	return identity.Earlier(end, r.end), nil
}
func (r *ownerLocalObservationRegistry) ReadOwnerRegistration(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	var zero value.OwnerRegistrationObservation
	end, err := r.until(ctx)
	if err != nil || leaf != r.leaf {
		return zero, value.ErrUnavailable
	}
	call, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(r.root, func() { cancel(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	current, err := r.server.ServingCertificate()
	if err != nil || current != leaf {
		return zero, value.ErrUnavailable
	}
	v, err := r.registry.ReadOwnerRegistration(call, leaf)
	if err != nil {
		return zero, err
	}
	verified, err := r.server.VerifyServingCertificate(v.Configuration)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || verified != leaf || call.Err() != nil || r.root.Err() != nil || r.closed || !r.now().Before(r.end) || !v.Valid(r.now()) || v.Certificate != leaf || v.Enrollment.Pool != r.pin.Pool || v.Enrollment.SourceUID != r.pin.SourceUID || v.Configuration.Configuration.Pool != r.pin.Pool || v.Configuration.Configuration.Revision.UID != r.pin.SourceUID || r.first != nil && (v.Certificate != r.first.Certificate || v.Enrollment != r.first.Enrollment || !v.Configuration.Configuration.Equal(r.first.Configuration.Configuration)) {
		r.closed = true
		return zero, value.ErrUnavailable
	}
	r.end = identity.Earlier(r.end, v.FreshUntil)
	v.Configuration.Configuration = v.Configuration.Configuration.Clone()
	if r.first == nil {
		first := v
		first.Configuration.Configuration = first.Configuration.Configuration.Clone()
		r.first = &first
	}
	// Preserve the actual observed dates; only restrict the returned cutoff.
	v.FreshUntil = identity.Earlier(v.FreshUntil, r.end)
	if !v.Valid(r.now()) {
		r.closed = true
		return zero, value.ErrUnavailable
	}
	return v, nil
}

func (h *OwnerLocalObservationReceiver) enter() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.root.Err() != nil || h.active >= h.maximum {
		return false
	}
	h.active++
	h.joined.Add(1)
	return true
}
func (h *OwnerLocalObservationReceiver) leave() {
	h.mu.Lock()
	h.active--
	h.mu.Unlock()
	h.joined.Done()
}
func (h *OwnerLocalObservationReceiver) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.pending.Close()
	h.joined.Wait()
}
func (h *OwnerLocalObservationReceiver) CommonAuthority() string {
	if h == nil {
		return ""
	}
	return h.commonHost
}
func (h *OwnerLocalObservationReceiver) ExactAuthority() string {
	if h == nil {
		return ""
	}
	return h.exactHost
}
func (h *OwnerLocalObservationReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.Body == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.DidResume || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || r.ProtoMajor != 2 || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.URL.RawPath != "" || r.URL.Fragment != "" || r.URL.RequestURI() != r.RequestURI || len(r.TransferEncoding) != 0 {
		ownerOperationUnavailable(w)
		return
	}
	lookup := r.Method == http.MethodGet && r.URL.Path == contracts.ClusterObservationLocalLocatorPath && r.TLS.ServerName == h.commonName && r.Host == h.commonHost && r.ContentLength == 0 && len(r.Header.Values("Content-Type")) == 0 && ownerOperationHeader(r, "Accept", contracts.ClusterObservationLocalLocatorMedia)
	claim := r.Method == http.MethodPost && r.RequestURI == contracts.ClusterObservationLocalClaimPath && r.URL.Path == contracts.ClusterObservationLocalClaimPath && r.URL.RawQuery == "" && r.TLS.ServerName == h.exactName && r.Host == h.exactHost && r.ContentLength > 0 && r.ContentLength <= contracts.ClusterObservationClaimBytes && ownerOperationHeader(r, "Content-Type", contracts.ClusterObservationLocalClaimMedia) && ownerOperationHeader(r, "Accept", contracts.ClusterObservationLocalClaimMedia)
	if !lookup && !claim {
		ownerOperationUnavailable(w)
		return
	}
	for _, key := range []string{"Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(key)) != 0 {
			ownerOperationUnavailable(w)
			return
		}
	}
	token, validToken := ownerLocalObservationToken(r)
	if !validToken || len(r.TLS.PeerCertificates) != 0 {
		ownerOperationUnavailable(w)
		return
	}
	defer clear(token)
	end, finite := r.Context().Deadline()
	if !finite || !h.now().Before(end) || end.After(h.now().Add(5*time.Second)) || !h.enter() {
		ownerOperationUnavailable(w)
		return
	}
	defer h.leave()
	call, cancel := context.WithDeadline(r.Context(), end)
	defer cancel()
	rootDone := make(chan struct{})
	stopRoot := context.AfterFunc(h.root, func() { cancel(); close(rootDone) })
	defer func() {
		if !stopRoot() {
			<-rootDone
		}
	}()
	control := http.NewResponseController(w)
	if control.SetReadDeadline(end) != nil || control.SetWriteDeadline(end) != nil {
		ownerOperationUnavailable(w)
		return
	}
	ioDone := make(chan struct{})
	stopIO := context.AfterFunc(call, func() {
		_ = control.SetReadDeadline(time.Now())
		_ = control.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
		close(ioDone)
	})
	defer func() {
		if !stopIO() {
			<-ioDone
		}
	}()
	defer r.Body.Close()
	var q value.ClusterObservationLocatorQuery
	var input value.ClusterObservationClaim
	var podUID string
	if lookup {
		v, err := contracts.DecodeClusterObservationLocalLocatorTarget(r.RequestURI)
		podUID = v.PodUID
		q = value.ClusterObservationLocatorQuery{RootID: v.Query.RootID, ClusterID: v.Query.ClusterID, RequestID: v.Query.RequestID, Challenge: v.Query.Challenge, RequestedAt: ownerOperationTime(v.Query.RequestedAt), NotAfter: ownerOperationTime(v.Query.NotAfter)}
		if err != nil || !q.Valid(h.now()) {
			ownerOperationUnavailable(w)
			return
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(r.Body, contracts.ClusterObservationClaimBytes+1))
		defer clear(body)
		if err != nil || len(body) != int(r.ContentLength) || call.Err() != nil {
			ownerOperationUnavailable(w)
			return
		}
		v, err := contracts.DecodeClusterObservationLocalClaim(body)
		podUID = v.PodUID
		request, _, re := wire.ParseRequest(v.Request, h.now())
		input = value.ClusterObservationClaim{Request: request, Locator: ownerOperationLocator(v.Locator)}
		if err != nil || re != nil || !input.Matches(h.binding, h.now()) {
			h.refused("decode", errors.Join(err, re))
			ownerOperationUnavailable(w)
			return
		}
		q = request.LocatorQuery()
		end = identity.Earlier(end, input.Locator.Interval.FreshUntil)
	}
	end = identity.Earlier(end, q.NotAfter)
	if q.RootID != h.pin.RootID || call.Err() != nil || !h.now().Before(end) {
		ownerOperationUnavailable(w)
		return
	}
	bounded, stop := context.WithDeadline(call, end)
	defer stop()
	narrowDone := make(chan struct{})
	stopNarrow := context.AfterFunc(bounded, func() {
		_ = control.SetReadDeadline(time.Now())
		_ = control.SetWriteDeadline(time.Now())
		_ = r.Body.Close()
		close(narrowDone)
	})
	defer func() {
		if !stopNarrow() {
			<-narrowDone
		}
	}()
	if control.SetReadDeadline(end) != nil || control.SetWriteDeadline(end) != nil {
		ownerOperationUnavailable(w)
		return
	}
	if lookup {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		defer clear(body)
		if err != nil || len(body) != 0 || bounded.Err() != nil {
			ownerOperationUnavailable(w)
			return
		}
	}
	// The original receiving socket is actual TLS. This purpose authenticates
	// HWORK by its dedicated online token, never an invented owner client leaf.
	server, err := h.server.ServingCertificate()
	if err != nil || server.Binding != h.binding {
		ownerOperationUnavailable(w)
		return
	}
	if lookup {
		h.locate(w, bounded, control, q, podUID, token, server)
	} else {
		h.claim(w, bounded, control, input, podUID, token, server)
	}
}
func ownerLocalObservationToken(r *http.Request) ([]byte, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, false
	}
	token := []byte(strings.TrimPrefix(values[0], "Bearer "))
	if len(token) == 0 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) || bytes.ContainsAny(token, " \t\r\n") {
		clear(token)
		return nil, false
	}
	return token, true
}
func ownerLocalQueryWire(q value.ClusterObservationLocatorQuery) contracts.ClusterObservationOperationLocatorQuery {
	return contracts.ClusterObservationOperationLocatorQuery{Format: contracts.ClusterObservationOperationLocatorFormat, RootID: q.RootID, ClusterID: q.ClusterID, RequestID: q.RequestID, Challenge: q.Challenge, RequestedAt: q.RequestedAt.UTC().Format(time.RFC3339Nano), NotAfter: q.NotAfter.UTC().Format(time.RFC3339Nano)}
}
func (h *OwnerLocalObservationReceiver) locate(w http.ResponseWriter, ctx context.Context, control *http.ResponseController, q value.ClusterObservationLocatorQuery, podUID string, token []byte, server value.OwnerCertificate) {
	e, err := h.pending.reserve(ctx, q, podUID, token, server)
	if err != nil {
		ownerOperationUnavailable(w)
		return
	}
	defer e.finishGET()
	registration := &ownerLocalObservationRegistry{root: e.work, pin: h.pin, server: h.server, leaf: server, registry: h.registry, now: h.now, end: e.end}
	first, err := registration.ReadOwnerRegistration(e.work, server)
	if err != nil {
		ownerOperationUnavailable(w)
		return
	}
	request := value.OwnerObservationRequest{RootID: q.RootID, ID: q.RequestID, Challenge: q.Challenge, RequestedAt: q.RequestedAt, NotAfter: q.NotAfter}
	// This context is owned through the native handle, not cancelled at GET exit.
	nativeCall, cancelNative := context.WithDeadline(e.work, identity.Earlier(e.end, first.FreshUntil))
	original, err := h.native.begin(nativeCall, request, h.binding, token, podUID)
	if err != nil || original == nil {
		cancelNative()
		if original != nil {
			original.Close()
		}
		ownerOperationUnavailable(w)
		return
	}
	native := &ownedOwnerLocalNative{ownerLocalNativeOperation: original, cancel: cancelNative}
	retained := false
	defer func() {
		if !retained {
			native.Close()
		}
	}()
	operation, err := mtls.NewOwnerObservationOperation(nativeCall, h.pin, request, h.server, registration, native, h.now)
	if err != nil {
		ownerOperationUnavailable(w)
		return
	}
	defer func() {
		if !retained {
			operation.Close()
		}
	}()
	facts, err := native.Original(nativeCall)
	end, ee := registration.until(nativeCall)
	if err != nil || ee != nil {
		ownerOperationUnavailable(w)
		return
	}
	end = identity.Earlier(end, facts.FreshUntil)
	lookup, stopLookup := context.WithDeadline(e.work, end)
	defer stopLookup()
	local, found, err := h.holder.LookupAvailable(lookup, q.RootID, q.ClusterID)
	if err != nil {
		ownerOperationUnavailable(w)
		return
	}
	response := contracts.ClusterObservationLocalLocator{Format: contracts.ClusterObservationLocalLocatorFormat, PodUID: podUID, Query: ownerLocalQueryWire(q)}
	if found {
		// Retain the newly narrowed original cutoff beyond GET completion.
		// A temporary lookup context would cancel the reserved stream on return;
		// e.work alone would lose the shorter current SQL/native observation.
		reservationCall, cancelReservation := context.WithDeadline(e.work, end)
		reservation, err := h.holder.ReserveLocator(reservationCall, local, q)
		if err != nil {
			cancelReservation()
			ownerOperationUnavailable(w)
			return
		}
		defer func() {
			if !retained {
				cancelReservation()
				reservation.Close()
			}
		}()
		end = identity.Earlier(end, identity.Earlier(local.FreshUntil, reservation.Until()))
		locator := value.ClusterObservationLocator{RootID: q.RootID, ClusterID: q.ClusterID, RequestID: q.RequestID, Challenge: q.Challenge, Holder: h.binding, ExchangeID: local.ExchangeID, Sequence: local.Sequence, Interval: value.ClusterObservationInterval{ObservedAt: local.ObservedAt, FreshUntil: end}}
		if !locator.Matches(q, h.binding, h.now()) || lookup.Err() != nil || ctx.Err() != nil || e.retain(locator, operation, native, registration, reservation, cancelReservation) != nil {
			ownerOperationUnavailable(w)
			return
		}
		retained = true
		wireLocator := ownerOperationLocatorWire(locator)
		response.Locator = &wireLocator
	}
	body, err := contracts.EncodeClusterObservationLocalLocator(response)
	defer clear(body)
	if err != nil || ctx.Err() != nil || lookup.Err() != nil || !h.now().Before(end) || control.SetWriteDeadline(end) != nil {
		ownerOperationUnavailable(w)
		return
	}
	if found {
		if _, err = e.possibleDelivery(); err != nil {
			ownerOperationUnavailable(w)
			return
		}
	}
	// Even an unknown absence reply retains the same spent pending marker.
	ownerOperationWrite(w, control, contracts.ClusterObservationLocalLocatorMedia, body)
}
func (h *OwnerLocalObservationReceiver) claim(w http.ResponseWriter, ctx context.Context, control *http.ResponseController, input value.ClusterObservationClaim, podUID string, token []byte, server value.OwnerCertificate) {
	// Fixed step durations only, for operator diagnostics.
	var steps []string
	mark := func(step string, start time.Time) {
		steps = append(steps, step+auditapp.DurationBucket(time.Since(start)))
	}
	defer func() {
		if h.timing != nil {
			h.timing(strings.Join(steps, " "))
		}
	}()
	started := time.Now()
	pending, err := h.pending.claim(ctx, input, podUID, token, server)
	if err != nil {
		h.refused("pending", err)
		ownerOperationUnavailable(w)
		return
	}
	defer pending.Close()
	mark("pending", started)
	started = time.Now()
	r, err := pending.registry.ReadOwnerRegistration(pending.call, server)
	if err != nil {
		h.refused("registration", err)
		ownerOperationUnavailable(w)
		return
	}
	current, stopCurrent := context.WithDeadline(pending.call, r.FreshUntil)
	defer stopCurrent()
	mark("registration", started)
	started = time.Now()
	end, err := pending.native.Claim(current, token, podUID)
	if err != nil {
		h.refused("native-claim", err)
		ownerOperationUnavailable(w)
		return
	}
	call, stop := context.WithDeadline(current, end)
	defer stop()
	mark("native-claim", started)
	started = time.Now()
	selected, err := pending.reservation.Select(call, input.Request)
	if err != nil {
		h.refused("select", err)
		ownerOperationUnavailable(w)
		return
	}
	standby, ok := selected.Conversation().(*regionalObservationOperationStandby)
	if !ok || standby.bind(pending.operation) != nil {
		selected.Close()
		h.refused("bind", nil)
		ownerOperationUnavailable(w)
		return
	}
	mark("select", started)
	started = time.Now()
	result, err := selected.Observe()
	mark("observe", started)
	if err != nil {
		h.refused("observe", err)
		ownerOperationUnavailable(w)
		return
	}
	end = identity.Earlier(end, result.Interval.FreshUntil)
	final, stopFinal := context.WithDeadline(call, end)
	defer stopFinal()
	started = time.Now()
	ownerEnd, err := pending.operation.CheckFinal(final)
	mark("final", started)
	if err != nil {
		h.refused("final", err)
		ownerOperationUnavailable(w)
		return
	}
	end = identity.Earlier(end, ownerEnd)
	result = result.Restrict(input.Request.RequestedAt, end)
	digest, de := wire.RequestDigest(input.Request)
	if de != nil || !result.Matches(input.Request, digest, h.now()) {
		h.refused("result", de)
		ownerOperationUnavailable(w)
		return
	}
	body, err := contracts.EncodeClusterObservationResult(wire.ResultWire(result))
	defer clear(body)
	if err != nil || final.Err() != nil || !h.now().Before(end) || control.SetWriteDeadline(end) != nil {
		h.refused("write", err)
		ownerOperationUnavailable(w)
		return
	}
	ownerOperationWrite(w, control, contracts.ClusterObservationLocalClaimMedia, body)
}
