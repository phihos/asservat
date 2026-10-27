package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"sync"
)

// RemoteContextSource belongs to one actual browser/CLI response. Its exact
// metadata-preparation identity must come from the admitted context session;
// current SQL independently verifies that original positive outcome. No source
// constructor reads storage, unwraps keys or invents a human identity.
type RemoteContextSource struct {
	owner        context.Context
	cancel       context.CancelFunc
	idle         chan struct{}
	mu           sync.Mutex
	attachment   *NativeAttachment
	request      ContextDownloadRequest
	preparation  artifact.DownloadPreparation
	closed, busy bool
	// One remote conversation serves one whole delivery lease window, chunk
	// by chunk (ADR-248): next is the next native offset, pending a chunk
	// returned but not yet acknowledged by the final sink.
	active     *attachedExchange
	activeStop func()
	lease      artifact.DownloadDeliveryLease
	next       int64
	pending    bool
}

var _ CurrentNativeResponseSource = (*RemoteContextSource)(nil)

func NewRemoteContextSource(ctx context.Context, a *NativeAttachment, r ContextDownloadRequest, p artifact.DownloadPreparation) (*RemoteContextSource, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || !p.Valid() || p.SessionID != r.SessionID || p.SessionID != a.config.Enrollment.Worker.Intent.SessionID || r.Scope != a.config.Enrollment.Worker.Intent.Authority.Scope || !(NativeContextSource{r.Expectation, r.Copies}).Valid(r.Scope.Version) {
		return nil, artifact.ErrInvalid
	}
	r.Expectation = cloneNativeSource(NativeContextSource{r.Expectation, r.Copies}).Expectation
	owner, cancel := context.WithCancel(ctx)
	s := &RemoteContextSource{owner: owner, cancel: cancel, attachment: a, request: r, preparation: p}
	context.AfterFunc(owner, s.Close)
	return s, nil
}

// Calling the legacy lease-only facets is always denied for a remote source.
func (*RemoteContextSource) Describe(context.Context, artifact.DownloadSession, artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadUnavailable
}
func (*RemoteContextSource) ReadChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) (NativeResponseChunk, error) {
	return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
}
func (s *RemoteContextSource) enter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.owner.Err() != nil || s.busy || s.active != nil {
		return false
	}
	return s.enterLocked()
}
func (s *RemoteContextSource) enterLocked() bool {
	s.busy = true
	s.idle = make(chan struct{})
	return true
}
func (s *RemoteContextSource) leave() { s.mu.Lock(); s.busy = false; close(s.idle); s.mu.Unlock() }
func (s *RemoteContextSource) DescribeCurrent(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	if s == nil || ctx == nil || session.ID != s.request.SessionID || session.Scope != s.request.Scope || a.Scope != session.Scope || !s.enter() {
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadUnavailable
	}
	defer s.leave()
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.owner, cancel)
	defer func() { stop(); cancel() }()
	ctx = call
	check, e := s.attachment.current(ctx, current, s.request)
	if e != nil {
		return artifact.NativeDownloadMetadata{}, 0, e
	}
	exchange, e := s.attachment.open(ctx, s.request, value.NativeObserve, s.preparation.BatchID, s.preparation.Generation, artifact.DownloadDeliveryLease{}, check)
	if e != nil {
		return artifact.NativeDownloadMetadata{}, 0, e
	}
	defer exchange.Close()
	m, e := exchange.Prepared(ctx)
	if e != nil {
		return artifact.NativeDownloadMetadata{}, 0, e
	}
	latest, e := check(ctx)
	if e != nil {
		return artifact.NativeDownloadMetadata{}, 0, e
	}
	if !validRegionalMetadata(s.request, m) {
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrIntegrity
	}
	m.ReadUntil = latest.AccessUntil
	m.DeleteBy = latest.DeleteBy
	return m, NativeWindowReadWork(s.request.Expectation.Type()), nil
}

// ReadChunkCurrent returns the next chunk of the lease's window. The first
// chunk (at the window offset) opens one private conversation for the whole
// window under the current identity and the lease's own deadline; every later
// chunk must follow the previous one's final-sink acknowledgement in the same
// window and lease. A failed chunk ends the conversation; the window is not
// retried here.
func (s *RemoteContextSource) ReadChunkCurrent(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease, offset, length int64) (NativeResponseChunk, error) {
	if s == nil || ctx == nil || !lease.Valid(s.attachment.config.Now()) || lease.Authority.Scope != s.request.Scope || length < 1 || length > artifact.DeliveryBytes || !lease.Allows(offset, length, s.attachment.config.Now()) {
		return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	s.mu.Lock()
	ok := !s.closed && s.owner.Err() == nil && !s.busy && (s.active == nil && offset == lease.Offset || s.active != nil && !s.pending && lease == s.lease && offset == s.next)
	if ok {
		ok = s.enterLocked()
	}
	exchange := s.active
	s.mu.Unlock()
	if !ok {
		return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	defer s.leave()
	if exchange == nil {
		var e error
		if exchange, e = s.openWindow(ctx, current, lease); e != nil {
			return NativeResponseChunk{}, e
		}
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.owner, cancel)
	defer func() { stop(); cancel() }()
	chunk, e := exchange.ReadChunk(call, lease, offset, length)
	s.mu.Lock()
	if e == nil && s.closed {
		e = artifact.ErrDownloadUnavailable
	}
	if e != nil {
		finish := s.activeStop
		s.active, s.activeStop, s.pending = nil, nil, false
		s.mu.Unlock()
		clear(chunk.Bytes)
		exchange.Close()
		if finish != nil {
			finish()
		}
		return NativeResponseChunk{}, e
	}
	s.pending, s.next = true, offset+length
	s.mu.Unlock()
	return chunk, nil
}

// openWindow opens the window's conversation. It belongs to this source and
// the lease (cancelled by Close and ending at the lease deadline), not to the
// first chunk's call, whose cancellation still stops the opening itself.
func (s *RemoteContextSource) openWindow(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease) (*attachedExchange, error) {
	window, cancel := context.WithDeadline(context.WithoutCancel(ctx), lease.Until)
	stopOwner := context.AfterFunc(s.owner, cancel)
	finish := func() { stopOwner(); cancel() }
	stopCall := context.AfterFunc(ctx, cancel)
	check, e := s.attachment.current(window, current, s.request)
	var exchange *attachedExchange
	if e == nil {
		exchange, e = s.attachment.open(window, s.request, value.NativeResponse, lease.ResponseID, lease.Generation, lease, check)
	}
	if !stopCall() && e == nil {
		e = artifact.ErrDownloadUnavailable // the first chunk's call ended while opening
	}
	if e != nil {
		if exchange != nil {
			exchange.Close()
		}
		finish()
		return nil, e
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		exchange.Close()
		finish()
		return nil, artifact.ErrDownloadUnavailable
	}
	s.active, s.activeStop, s.lease, s.next, s.pending = exchange, finish, lease, lease.Offset, false
	s.mu.Unlock()
	return exchange, nil
}

// AcknowledgeNativeChunk acknowledges the pending chunk's final-sink write.
// The window's last chunk (or a failed acknowledgement) joins and closes the
// conversation; earlier chunks keep it open for the next chunk.
func (s *RemoteContextSource) AcknowledgeNativeChunk(ctx context.Context, lease artifact.DownloadDeliveryLease, offset, length int64) error {
	if s == nil {
		return artifact.ErrInvalid
	}
	s.mu.Lock()
	active := s.active
	finish := s.activeStop
	if s.closed || s.busy || active == nil || !s.pending || s.lease != lease || offset+length != s.next {
		s.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	last := s.next == lease.Offset+lease.Length
	s.busy = true
	s.idle = make(chan struct{})
	s.mu.Unlock()
	e := active.AcknowledgeNativeChunk(ctx, lease, offset, length)
	var closeErr error
	if e != nil || last {
		closeErr = active.Close()
		if finish != nil {
			finish()
		}
	}
	s.mu.Lock()
	s.pending = false
	if e != nil || last {
		s.active = nil
		s.activeStop = nil
	}
	s.busy = false
	close(s.idle)
	s.mu.Unlock()
	if e != nil {
		return e
	}
	return closeErr
}
func (s *RemoteContextSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	active := s.active
	busy, idle := s.busy, s.idle
	s.mu.Unlock()
	if active != nil {
		active.Close()
	}
	if busy {
		<-idle
	}
	s.mu.Lock()
	finish := s.activeStop
	s.activeStop = nil
	s.active = nil
	s.mu.Unlock()
	if finish != nil {
		finish()
	}
}
