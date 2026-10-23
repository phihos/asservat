// Package native owns only the private native-evidence wire. Certificate
// enrollment and public browser/MCP authentication remain separate handlers.
package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Stream = contracts.NativeStream

// Conversation belongs to an existing admitted operation. Serve cannot return
// until its child work joins. Close must be idempotent and join operation-owned
// routing/capacity; transport closes both directions before releasing the slot.
type Conversation interface {
	Gate() *evidence.NativeFrameGate
	Serve(context.Context, Stream) error
	Close() error
}
type Admission interface {
	OpenNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (Conversation, error)
}

// Parker is implemented by an admission whose idle workers may wait for
// their own operation instead of being answered at once (HubWorkerAdmission).
type Parker interface {
	ParkNative(context.Context, contracts.NativeHello, *evidence.NativeIdle) bool
}

type Handler struct {
	path, host string
	admission  Admission
	slots      chan struct{}
	// Refused, when set, reports a refused admission or conversation with its
	// closed stage only (ADR-197). It is set before serving and never changes
	// a response.
	Refused func(context.Context, string, error)
}

func NewHandler(path, host string, admission Admission, limit int) (*Handler, error) {
	if path != contracts.NativeWorkerPath && path != contracts.NativeOwnerPath || host == "" || strings.ContainsAny(host, "/\\ \r\n\t") || admission == nil || limit < 1 || limit > 16 {
		return nil, contracts.ErrNativeProtocol
	}
	return &Handler{path: path, host: host, admission: admission, slots: make(chan struct{}, limit)}, nil
}
func unavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, "Unavailable", http.StatusNotFound)
}
func oneHeader(r *http.Request, name, value string) bool {
	v := r.Header.Values(name)
	return len(v) == 1 && v[0] == value
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil || r.URL == nil || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" || r.ProtoMajor != 2 || r.Method != http.MethodPost || r.Host != h.host || r.URL.Path != h.path || r.RequestURI != h.path || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.User != nil || r.ContentLength != -1 || len(r.TransferEncoding) != 0 || !oneHeader(r, "Content-Type", contracts.NativeExchangeMedia) || !oneHeader(r, "Accept", contracts.NativeExchangeMedia) {
		unavailable(w)
		return
	}
	for _, name := range []string{"Authorization", "Cookie", "Origin", "Referer", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Content-Encoding", "Idempotency-Key", "X-Idempotency-Key"} {
		if len(r.Header.Values(name)) != 0 {
			unavailable(w)
			return
		}
	}
	if !h.acquire() {
		unavailable(w)
		return
	}
	held := true
	defer func() {
		if held {
			<-h.slots
		}
	}()
	started := time.Now()
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		unavailable(w)
		return
	}
	f, err := contracts.ReadNativeFrame(r.Body)
	if err != nil || f.Kind != contracts.NativeHelloFrame {
		clear(f.Payload)
		unavailable(w)
		return
	}
	hello, err := contracts.DecodeNativeHello(f.Payload)
	clear(f.Payload)
	defer clear(hello.WorkerToken)
	if err != nil || !value.AcquisitionParentFor(hello.Reference.SessionID, hello.Reference.QueryID).Valid() || !value.UUID(hello.Reference.InstallationID) || !value.UUID(hello.Reference.WorkerID) || hello.Format != contracts.NativeExchangeFormat || !contracts.ValidWorkerNonce(hello.Nonce) || !contracts.ValidWorkerToken(hello.WorkerToken) || len(hello.WorkerLeaf) > 16<<10 || h.path == contracts.NativeWorkerPath && len(hello.WorkerLeaf) != 0 || h.path == contracts.NativeOwnerPath && len(hello.WorkerLeaf) == 0 || h.path == contracts.NativeWorkerPath && (hello.Reference.OperationID != "" || hello.Reference.Fence != 0) {
		unavailable(w)
		return
	}
	// An approved projection conversation may span its operation (at most the
	// evidence-read window); every other request keeps five seconds. The
	// operation, its leases and each frame's current check bound it further.
	lifetime := 5 * time.Second
	if hello.Reference.QueryID != "" {
		lifetime = value.NativeLeaseWindow(value.NativeProjection)
	}
	ctx, stop := context.WithDeadline(r.Context(), started.Add(lifetime))
	defer stop()
	conversation, err := h.admission.OpenNative(ctx, r.TLS, hello)
	var idle *evidence.NativeIdle
	// A parked idle request holds no slot: only admitted work counts. After a
	// wake-up the complete admission runs again under a newly taken slot; if
	// none is free, or it is still idle, the request answers idle as before.
	if parker, ok := h.admission.(Parker); ok && conversation == nil && h.path == contracts.NativeWorkerPath && errors.As(err, &idle) && idle != nil {
		<-h.slots
		held = false
		if parker.ParkNative(ctx, hello, idle) && h.acquire() {
			held = true
			conversation, err = h.admission.OpenNative(ctx, r.TLS, hello)
			idle = nil
		}
	}
	if conversation == nil && h.path == contracts.NativeWorkerPath && errors.As(err, &idle) && idle.Valid(time.Now()) && idle.Worker.Worker.Intent.ID == hello.Reference.WorkerID && idle.Worker.Worker.Intent.Parent == value.AcquisitionParentFor(hello.Reference.SessionID, hello.Reference.QueryID) && idle.Proof.Binding.InstallationID == hello.Reference.InstallationID && ctx.Err() == nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Asservat-Native-Disposition", "no-command")
		w.Header().Set("Asservat-Native-Nonce", hello.Nonce)
		w.Header().Set("Asservat-Native-Installation", hello.Reference.InstallationID)
		if hello.Reference.QueryID != "" {
			w.Header().Set("Asservat-Native-Query", hello.Reference.QueryID)
		} else {
			w.Header().Set("Asservat-Native-Session", hello.Reference.SessionID)
		}
		w.Header().Set("Asservat-Native-Worker", hello.Reference.WorkerID)
		w.Header().Set("Asservat-Native-Until", idle.Until.UTC().Format(time.RFC3339Nano))
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil || conversation == nil {
		if conversation != nil {
			conversation.Close()
		}
		h.refused(ctx, "admission", err)
		unavailable(w)
		return
	}
	defer conversation.Close()
	gate := conversation.Gate()
	if gate == nil {
		unavailable(w)
		return
	}
	lease, err := gate.Check(ctx)
	ref := hello.Reference
	if err != nil {
		h.refused(ctx, "check", err)
	}
	if err != nil || lease.Operation.Reference.InstallationID != ref.InstallationID || lease.Operation.Reference.Parent() != value.AcquisitionParentFor(ref.SessionID, ref.QueryID) || lease.Operation.Reference.WorkerID != ref.WorkerID || h.path == contracts.NativeOwnerPath && (lease.Operation.Reference.OperationID != ref.OperationID || lease.Operation.Reference.Fence != ref.Fence) {
		unavailable(w)
		return
	}
	// The first context slice has one <=5s native exchange. A long-lived reader
	// needs separately admitted subsequent leases, never a renewed ContextIdentity.
	stream := newServerStream(r, w, gate)
	defer stream.Close()
	if controller.SetWriteDeadline(lease.Until) != nil || ctx.Err() != nil {
		unavailable(w)
		return
	}
	// The five-second Hello read deadline set at request start bounds only the
	// Hello. An attached projection conversation (up to the evidence-read
	// window) reads under its checked lease; otherwise a slow admission left
	// the first result read past that deadline (installed native87). Every
	// frame read still sets its own lease deadline.
	if lease.Operation.Kind == value.NativeProjection && controller.SetReadDeadline(lease.Until) != nil {
		unavailable(w)
		return
	}
	w.Header().Set("Content-Type", contracts.NativeExchangeMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	h.refused(stream.Context(), "serve", conversation.Serve(stream.Context(), stream))
}
func (h *Handler) acquire() bool {
	select {
	case h.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (h *Handler) refused(ctx context.Context, stage string, err error) {
	if err != nil && h.Refused != nil {
		h.Refused(ctx, stage, err)
	}
}

type serverStream struct {
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	r                                      *http.Request
	w                                      http.ResponseWriter
	controller                             *http.ResponseController
	gate                                   *evidence.NativeFrameGate
	mu                                     sync.Mutex
	reads, writes, readFrames, writeFrames int
	closed, interrupted, doneClosed        bool
	done                                   chan struct{}
	checked                                value.NativeLease
	checkedAt                              time.Time
}

func newServerStream(r *http.Request, w http.ResponseWriter, gate *evidence.NativeFrameGate) *serverStream {
	ctx, cancel := context.WithCancel(r.Context())
	s := &serverStream{ctx: ctx, cancel: cancel, r: r, w: w, controller: http.NewResponseController(w), gate: gate, done: make(chan struct{}), readFrames: 1}
	context.AfterFunc(gate.Context(), s.interrupt)
	context.AfterFunc(ctx, s.interrupt)
	return s
}
func (s *serverStream) Context() context.Context { return s.ctx }

// frameCheck is the per-frame current check. An approved projection
// conversation shares one successful complete check across its frame checks
// for evidence.NativeRecheckInterval (installed native85: two complete
// worker/hub/operation checks around every frame cost the read more than
// three seconds). Revocation is seen at the first frame check after that
// interval; admission, consumption and terminal checks remain complete.
// Downloads keep a complete check at every frame.
func (s *serverStream) frameCheck(ctx context.Context) (value.NativeLease, error) {
	s.mu.Lock()
	l, at := s.checked, s.checkedAt
	s.mu.Unlock()
	if now := time.Now(); !at.IsZero() && l.Operation.Kind == value.NativeProjection && !now.Before(at) && now.Sub(at) < evidence.NativeRecheckInterval && now.Before(l.Until) && s.gate.Context().Err() == nil && ctx.Err() == nil {
		return l, nil
	}
	l, err := s.gate.Check(ctx)
	if err == nil {
		s.mu.Lock()
		s.checked, s.checkedAt = l, time.Now()
		s.mu.Unlock()
	}
	return l, err
}
func (s *serverStream) finishLocked() {
	if s.closed && s.interrupted && s.reads == 0 && s.writes == 0 && !s.doneClosed {
		s.doneClosed = true
		close(s.done)
	}
}
func (s *serverStream) interrupt() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	// Deadlines wake actual HTTP/2 reads/writes. Nothing resets a failed stream.
	s.controller.SetReadDeadline(time.Now())
	s.controller.SetWriteDeadline(time.Now())
	s.r.Body.Close()
	s.mu.Lock()
	s.interrupted = true
	s.finishLocked()
	s.mu.Unlock()
}
func (s *serverStream) Close() error { s.interrupt(); <-s.done; return nil }
func (s *serverStream) begin(ctx context.Context, read, terminal bool) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, contracts.ErrNativeProtocol
	}
	check := s.frameCheck
	if terminal {
		check = s.gate.TerminalLease
	}
	lease, err := check(ctx)
	if err != nil {
		s.interrupt()
		return nil, nil, frameRefusal("gate", err)
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || read && (s.reads != 0 || s.readFrames >= contracts.NativeMaximumFrames) || !read && (s.writes != 0 || s.writeFrames >= contracts.NativeMaximumFrames) {
		s.mu.Unlock()
		return nil, nil, contracts.ErrNativeProtocol
	}
	if read {
		s.reads++
		s.readFrames++
	} else {
		s.writes++
		s.writeFrames++
	}
	s.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, lease.Until)
	finished := make(chan struct{})
	stop := context.AfterFunc(call, func() { s.interrupt(); close(finished) })
	end := func() {
		if !stop() {
			<-finished
		}
		cancel()
		s.mu.Lock()
		if read {
			s.reads--
		} else {
			s.writes--
		}
		s.finishLocked()
		s.mu.Unlock()
	}
	if read {
		err = s.controller.SetReadDeadline(lease.Until)
	} else {
		err = s.controller.SetWriteDeadline(lease.Until)
	}
	if err != nil {
		end()
		s.interrupt()
		return nil, nil, contracts.ErrNativeProtocol
	}
	return call, end, nil
}
func (s *serverStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	call, end, err := s.begin(ctx, true, false)
	if err != nil {
		return contracts.NativeFrame{}, err
	}
	defer end()
	f, err := contracts.ReadNativeFrame(s.r.Body)
	stage := "read"
	if err == nil {
		stage = "gate-after"
		_, err = s.frameCheck(call)
	}
	if err != nil || call.Err() != nil || s.ctx.Err() != nil {
		clear(f.Payload)
		s.interrupt()
		return contracts.NativeFrame{}, frameRefusal(stage, err)
	}
	return f, nil
}
func (s *serverStream) Send(ctx context.Context, f contracts.NativeFrame) error {
	return s.send(ctx, f, false)
}

// SendTerminal is deliberately absent from the general NativeStream contract.
// Only the relay's already validated zero-byte final marker uses this path;
// hub production uses its separate private exact-completion proof below.
func (s *serverStream) SendTerminal(ctx context.Context, f contracts.NativeFrame) error {
	a, e := contracts.DecodeNativeAcknowledge(f.Payload)
	l, leaseErr := s.gate.TerminalLease(ctx)
	if e != nil || leaseErr != nil || f.Kind != contracts.NativeDoneFrame || a.Format != contracts.NativeExchangeFormat || a.Reference != nativeReference(l.Operation) || !contracts.ValidWorkerNonce(a.Nonce) || a.Bytes != 0 || (a.Phase != "closed" && a.Phase != "joined") {
		return contracts.ErrNativeProtocol
	}
	return s.send(ctx, f, true)
}

// sendCompleted is private to this transport package: the hub may use it only
// after its exact original SQL close. It cannot send any evidence or new work.
func (s *serverStream) sendCompleted(ctx context.Context, f contracts.NativeFrame, proof nativeCompletionProof) error {
	lease, err := s.gate.TerminalLease(ctx)
	a, decode := contracts.DecodeNativeAcknowledge(f.Payload)
	switch {
	case err != nil:
		return frameRefusal("terminal-lease", err)
	case proof.gate != s.gate:
		return step("proof-gate", contracts.ErrNativeProtocol)
	case decode != nil || !proof.lease.Valid(time.Now()) || !lease.Operation.Equal(proof.lease.Operation) || lease.Sequence != proof.lease.Sequence || lease.Certificate != proof.lease.Certificate || lease.Until.After(proof.lease.Until):
		return step("proof-lease", contracts.ErrNativeProtocol)
	case f.Kind != contracts.NativeDoneFrame || a.Format != contracts.NativeExchangeFormat || a.Reference != nativeReference(proof.lease.Operation) || a.Nonce != proof.nonce || a.Phase != proof.phase || a.Bytes != 0 || (a.Phase != "closed" && a.Phase != "joined"):
		return step("proof-frame", contracts.ErrNativeProtocol)
	}
	return s.send(ctx, f, true)
}

func (s *serverStream) send(ctx context.Context, f contracts.NativeFrame, terminal bool) error {
	call, end, err := s.begin(ctx, false, terminal)
	if err != nil {
		return err
	}
	defer end()
	if call.Err() != nil || s.ctx.Err() != nil || s.gate.Context().Err() != nil {
		s.interrupt()
		return contracts.ErrNativeProtocol
	}
	if err = contracts.WriteNativeFrame(s.w, f); err == nil {
		err = s.controller.Flush()
	}
	// Done is the positive final marker. The peer may close normally as soon as
	// it receives it, so all blocking authority checks must precede its write.
	// Hub completion first checks current authority and exact SQL closure; both
	// its terminal send and validated relay closure use only the
	// original gate snapshot after the hub may have retired itself. Successful
	// flush completes only transport delivery; application metadata authority
	// and accounting still have their independent final gates.
	if f.Kind == contracts.NativeDoneFrame {
		// The peer closing its stream, or the hub retiring the gate, after a
		// flushed Done is its normal end, not a failed delivery; the stream
		// and gate contexts are checked before the write only.
		if err != nil {
			s.interrupt()
			return contracts.ErrNativeProtocol
		}
		return nil
	}
	stage := "write"
	if err == nil {
		stage = "gate-after"
		_, err = s.frameCheck(call)
	}
	deadline, bounded := call.Deadline()
	if err != nil || !bounded || !time.Now().Before(deadline) || call.Err() != nil || s.ctx.Err() != nil || s.gate.Context().Err() != nil {
		s.interrupt()
		return frameRefusal(stage, err)
	}
	return nil
}

// frameRefusal keeps the protocol refusal and names the frame stage with the
// gate's own closed stage, if any, for the operator report only.
func frameRefusal(stage string, cause error) error {
	return step(stage, &causeLabel{contracts.ErrNativeProtocol, cause})
}

// causeLabel unwraps only to its returned error; the cause contributes its
// closed FixedStep label and nothing else.
type causeLabel struct{ err, cause error }

func (e *causeLabel) Error() string { return e.err.Error() }
func (e *causeLabel) Unwrap() error { return e.err }
func (e *causeLabel) FixedStep() string {
	var inner interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &inner) {
		return inner.FixedStep()
	}
	return "refused"
}
