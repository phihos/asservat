package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"sync"
)

// ContextNativeResponse is owned by one actual HTTP request. Describe pins only
// immutable cached facts. The later content phase constructs a native exchange
// from its own fresh identity batch; the metadata batch is never retained or
// renewed. No constructor dispatches, prepares, reads payload or unwraps.
type ContextNativeResponse struct {
	owner                   context.Context
	cancel                  context.CancelFunc
	runtime                 *ContextNativeRuntime
	mu                      sync.Mutex
	closed, busy, described bool
	idle                    chan struct{}
	closeDone               chan struct{}
	session                 artifact.DownloadSession
	key                     contextNativeMetadataKey
	release                 func()
	// One remote source serves one delivery lease window chunk by chunk
	// (ADR-248): next is the next native offset, pending a chunk returned but
	// not yet acknowledged, effect the window's request context.
	remote    *RemoteContextSource
	remoteEnd context.CancelFunc
	effect    context.Context
	lease     artifact.DownloadDeliveryLease
	next      int64
	pending   bool
}

var _ CurrentNativeResponseSource = (*ContextNativeResponse)(nil)

func NewContextNativeResponse(ctx context.Context, r *ContextNativeRuntime) (*ContextNativeResponse, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.bound != nil || r.metadata == nil {
		return nil, artifact.ErrInvalid
	}
	owner, cancel := context.WithCancel(ctx)
	return &ContextNativeResponse{owner: owner, cancel: cancel, runtime: r, closeDone: make(chan struct{})}, nil
}
func (*ContextNativeResponse) Describe(context.Context, artifact.DownloadSession, artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadUnavailable
}
func (*ContextNativeResponse) ReadChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) (NativeResponseChunk, error) {
	return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
}
func (s *ContextNativeResponse) enter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.owner.Err() != nil || s.busy {
		return false
	}
	s.busy = true
	s.idle = make(chan struct{})
	return true
}
func (s *ContextNativeResponse) leave() { s.mu.Lock(); s.busy = false; close(s.idle); s.mu.Unlock() }
func (s *ContextNativeResponse) owned(ctx context.Context) (context.Context, context.CancelFunc) {
	call, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(s.owner, func() { defer close(joined); cancel() })
	return call, func() {
		if !stop() {
			<-joined
		}
		cancel()
	}
}

// These private entry points consume only the response coordinator's exact
// short authority. The public Current methods remain independently checked.
func (s *ContextNativeResponse) describeChecked(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	return s.describeCurrent(ctx, current, session, a, true)
}
func (s *ContextNativeResponse) readChunkChecked(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease, offset, length int64) (NativeResponseChunk, error) {
	return s.readChunkCurrent(ctx, current, lease, offset, length, true)
}

func (s *ContextNativeResponse) DescribeCurrent(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error) {
	return s.describeCurrent(ctx, current, session, a, false)
}
func (s *ContextNativeResponse) describeCurrent(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority, checked bool) (artifact.NativeDownloadMetadata, int64, error) {
	if s == nil || ctx == nil || !a.Valid(s.runtime.config.Now()) || session.Scope != a.Scope || !s.enter() {
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadUnavailable
	}
	defer s.leave()
	s.mu.Lock()
	already := s.described
	s.mu.Unlock()
	if already {
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadConflict
	}
	call, end := s.owned(ctx)
	defer end()
	var observed *artifact.DownloadAuthority
	if checked {
		observed = &a
	}
	facts, key, release, e := s.runtime.preparedAuthority(call, current, session, true, observed)
	if e != nil {
		return artifact.NativeDownloadMetadata{}, 0, e
	}
	if !facts.Valid() || release == nil {
		if release != nil {
			release()
		}
		return artifact.NativeDownloadMetadata{}, 0, ErrDownloadMetadataUnavailable
	}
	s.mu.Lock()
	if s.closed || call.Err() != nil {
		s.mu.Unlock()
		release()
		return artifact.NativeDownloadMetadata{}, 0, artifact.ErrDownloadExpired
	}
	s.session, s.key, s.release, s.described = session, key, release, true
	s.mu.Unlock()
	t, _ := artifact.NativeTypeForFormat(facts.Native.Format)
	return facts.Native, NativeWindowReadWork(t), nil
}
func (s *ContextNativeResponse) ReadChunkCurrent(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease, offset, length int64) (NativeResponseChunk, error) {
	return s.readChunkCurrent(ctx, current, lease, offset, length, false)
}
func (s *ContextNativeResponse) readChunkCurrent(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease, offset, length int64, checked bool) (NativeResponseChunk, error) {
	var zero NativeResponseChunk
	if s == nil || ctx == nil || !lease.Valid(s.runtime.config.Now()) || length < 1 || length > artifact.DeliveryBytes || !lease.Allows(offset, length, s.runtime.config.Now()) || !s.enter() {
		return zero, artifact.ErrDownloadUnavailable
	}
	defer s.leave()
	s.mu.Lock()
	session, described, active, effect := s.session, s.described, s.remote, s.effect
	continuing := active != nil && !s.pending && lease == s.lease && offset == s.next
	s.mu.Unlock()
	if !described || lease.Authority.Scope != session.Scope || active != nil && !continuing || active == nil && offset != lease.Offset {
		return zero, artifact.ErrDownloadUnavailable
	}
	if active == nil {
		var e error
		if active, effect, e = s.openWindow(ctx, current, lease, checked); e != nil {
			return zero, e
		}
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(effect, cancel)
	chunk, e := active.ReadChunkCurrent(call, current, lease, offset, length)
	stop()
	cancel()
	s.mu.Lock()
	if e == nil && (s.closed || effect.Err() != nil) {
		e = artifact.ErrDownloadExpired
	}
	if e != nil {
		end := s.remoteEnd
		s.remote, s.remoteEnd, s.pending = nil, nil, false
		s.mu.Unlock()
		clear(chunk.Bytes)
		active.Close()
		if end != nil {
			end()
		}
		return zero, e
	}
	s.pending, s.next = true, offset+length
	s.mu.Unlock()
	return chunk, nil
}

// openWindow checks the current attachment and opens the remote source for
// one delivery lease window. The original piece, request and current batch
// own the window until its last chunk's final-sink acknowledgement and joined
// native cleanup; they end at the lease deadline, not with the first chunk's
// call, whose cancellation still stops the opening itself.
func (s *ContextNativeResponse) openWindow(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease, checked bool) (*RemoteContextSource, context.Context, error) {
	s.mu.Lock()
	session, key := s.session, s.key
	s.mu.Unlock()
	base, cancelBase := context.WithDeadline(context.WithoutCancel(ctx), lease.Until)
	stopCall := context.AfterFunc(ctx, cancelBase)
	call, ownerEnd := s.owned(base)
	var bound *ContextNativeRuntime
	var work context.Context
	var requestEnd context.CancelFunc
	var initial artifact.DownloadAuthority
	var e error
	if checked {
		bound, work, requestEnd, initial, e = s.runtime.beginResponseRequest(call, current, session, lease.Authority)
	} else {
		bound, work, requestEnd, initial, e = s.runtime.beginRequest(call, current, session)
	}
	if e != nil {
		stopCall()
		ownerEnd()
		cancelBase()
		return nil, nil, e
	}
	effect, stopEffect := context.WithDeadline(work, bound.bound.Deadline())
	end := func() { stopEffect(); requestEnd(); ownerEnd(); cancelBase() }
	fail := func(e error) (*RemoteContextSource, context.Context, error) {
		stopCall()
		end()
		return nil, nil, e
	}
	observed, a, e := bound.attachmentWithAuthority(work, session, initial)
	if e != nil {
		return fail(e)
	}
	currentKey, e := contextMetadataKey(session, observed, a)
	if e != nil || currentKey != key || observed.NativeBusy || observed.NativeUncertain || !observed.ResponseBusy {
		return fail(artifact.ErrDownloadUnavailable)
	}
	remote, e := bound.remote(work, session, observed, a)
	if e != nil {
		return fail(e)
	}
	if !stopCall() {
		remote.Close()
		return fail(artifact.ErrDownloadUnavailable)
	}
	s.mu.Lock()
	if s.closed || effect.Err() != nil {
		s.mu.Unlock()
		remote.Close()
		end()
		return nil, nil, artifact.ErrDownloadExpired
	}
	s.remote, s.remoteEnd, s.effect, s.lease, s.next, s.pending = remote, end, effect, lease, lease.Offset, false
	s.mu.Unlock()
	return remote, effect, nil
}

// AcknowledgeNativeChunk forwards the final sink's acknowledgement of the
// pending chunk. The window's last chunk, or a failed acknowledgement, closes
// the remote source and ends the window's request.
func (s *ContextNativeResponse) AcknowledgeNativeChunk(ctx context.Context, lease artifact.DownloadDeliveryLease, offset, length int64) error {
	if s == nil || ctx == nil || !s.enter() {
		return artifact.ErrDownloadUnavailable
	}
	defer s.leave()
	s.mu.Lock()
	remote, end, actual, pending, next := s.remote, s.remoteEnd, s.lease, s.pending, s.next
	s.mu.Unlock()
	if remote == nil || lease != actual || !pending || offset+length != next {
		return artifact.ErrDownloadUnavailable
	}
	e := remote.AcknowledgeNativeChunk(ctx, lease, offset, length)
	last := next == lease.Offset+lease.Length
	if e != nil || last {
		remote.Close()
		end()
	}
	s.mu.Lock()
	s.pending = false
	if e != nil || last {
		s.remote, s.remoteEnd = nil, nil
	}
	s.mu.Unlock()
	return e
}
func (s *ContextNativeResponse) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return
	}
	s.closed = true
	s.cancel()
	busy, idle := s.busy, s.idle
	s.mu.Unlock()
	if busy {
		<-idle
	}
	s.mu.Lock()
	remote, end, release := s.remote, s.remoteEnd, s.release
	s.remote, s.remoteEnd, s.release = nil, nil, nil
	s.mu.Unlock()
	if remote != nil {
		remote.Close()
	}
	if end != nil {
		end()
	}
	if release != nil {
		release()
	}
	close(s.closeDone)
}
