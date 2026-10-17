// Package native owns only the private native-evidence wire. Certificate
// enrollment and public browser/MCP authentication remain separate handlers.
package native

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
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

type Handler struct {
	path, host string
	admission  Admission
	slots      chan struct{}
}

func NewHandler(path, host string, admission Admission, limit int) (*Handler, error) {
	if path != contracts.NativeWorkerPath && path != contracts.NativeOwnerPath || host == "" || strings.ContainsAny(host, "/\\ \r\n\t") || admission == nil || limit < 1 || limit > 16 {
		return nil, contracts.ErrNativeProtocol
	}
	return &Handler{path, host, admission, make(chan struct{}, limit)}, nil
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
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		unavailable(w)
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 5*time.Second)
	defer stop()
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
	if err != nil || hello.Format != contracts.NativeExchangeFormat || !contracts.ValidWorkerNonce(hello.Nonce) || !contracts.ValidWorkerToken(hello.WorkerToken) || len(hello.WorkerLeaf) > 16<<10 || h.path == contracts.NativeWorkerPath && len(hello.WorkerLeaf) != 0 || h.path == contracts.NativeOwnerPath && len(hello.WorkerLeaf) == 0 || h.path == contracts.NativeWorkerPath && (hello.Reference.OperationID != "" || hello.Reference.Fence != 0) {
		unavailable(w)
		return
	}
	conversation, err := h.admission.OpenNative(ctx, r.TLS, hello)
	var idle *evidence.NativeIdle
	if conversation == nil && h.path == contracts.NativeWorkerPath && errors.As(err, &idle) && idle.Valid(time.Now()) && idle.Worker.Worker.Intent.ID == hello.Reference.WorkerID && idle.Worker.Worker.Intent.SessionID == hello.Reference.SessionID && idle.Proof.Binding.InstallationID == hello.Reference.InstallationID && ctx.Err() == nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Asservat-Native-Disposition", "no-command")
		w.Header().Set("Asservat-Native-Nonce", hello.Nonce)
		w.Header().Set("Asservat-Native-Installation", hello.Reference.InstallationID)
		w.Header().Set("Asservat-Native-Session", hello.Reference.SessionID)
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
	if err != nil || lease.Operation.Reference.InstallationID != ref.InstallationID || lease.Operation.Reference.SessionID != ref.SessionID || lease.Operation.Reference.WorkerID != ref.WorkerID || h.path == contracts.NativeOwnerPath && (lease.Operation.Reference.OperationID != ref.OperationID || lease.Operation.Reference.Fence != ref.Fence) {
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
	w.Header().Set("Content-Type", contracts.NativeExchangeMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	_ = conversation.Serve(stream.Context(), stream)
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
}

func newServerStream(r *http.Request, w http.ResponseWriter, gate *evidence.NativeFrameGate) *serverStream {
	ctx, cancel := context.WithCancel(r.Context())
	s := &serverStream{ctx: ctx, cancel: cancel, r: r, w: w, controller: http.NewResponseController(w), gate: gate, done: make(chan struct{}), readFrames: 1}
	context.AfterFunc(gate.Context(), s.interrupt)
	context.AfterFunc(ctx, s.interrupt)
	return s
}
func (s *serverStream) Context() context.Context { return s.ctx }
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
	check := s.gate.Check
	if terminal {
		check = s.gate.TerminalLease
	}
	lease, err := check(ctx)
	if err != nil {
		s.interrupt()
		return nil, nil, contracts.ErrNativeProtocol
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
	if err == nil {
		_, err = s.gate.Check(call)
	}
	if err != nil || call.Err() != nil || s.ctx.Err() != nil {
		clear(f.Payload)
		s.interrupt()
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
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
	if err != nil || decode != nil || proof.gate != s.gate || !proof.lease.Valid(time.Now()) || !lease.Operation.Equal(proof.lease.Operation) || lease.Sequence != proof.lease.Sequence || lease.Certificate != proof.lease.Certificate || lease.Until.After(proof.lease.Until) || f.Kind != contracts.NativeDoneFrame || a.Format != contracts.NativeExchangeFormat || a.Reference != nativeReference(proof.lease.Operation) || a.Nonce != proof.nonce || a.Phase != proof.phase || a.Bytes != 0 || (a.Phase != "closed" && a.Phase != "joined") {
		return contracts.ErrNativeProtocol
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
	if err == nil && f.Kind != contracts.NativeDoneFrame {
		_, err = s.gate.Check(call)
	}
	deadline, bounded := call.Deadline()
	if err != nil || !bounded || !time.Now().Before(deadline) || call.Err() != nil || s.ctx.Err() != nil || s.gate.Context().Err() != nil {
		s.interrupt()
		return contracts.ErrNativeProtocol
	}
	return nil
}
