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
	active       *attachedExchange
	activeStop   func()
	lease        artifact.DownloadDeliveryLease
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
	return m, ContextDownloadReadWork, nil
}
func (s *RemoteContextSource) ReadChunkCurrent(ctx context.Context, current identities.CurrentIdentity, lease artifact.DownloadDeliveryLease, offset, length int64) (NativeResponseChunk, error) {
	if s == nil || ctx == nil || !lease.Valid(s.attachment.config.Now()) || lease.Authority.Scope != s.request.Scope || offset != lease.Offset || length != lease.Length || length < 1 || length > artifact.MaxContextBytes || !s.enter() {
		return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	defer s.leave()
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.owner, cancel)
	keep := false
	defer func() {
		if !keep {
			stop()
			cancel()
		}
	}()
	ctx = call
	check, e := s.attachment.current(ctx, current, s.request)
	if e != nil {
		return NativeResponseChunk{}, e
	}
	exchange, e := s.attachment.open(ctx, s.request, value.NativeResponse, lease.ResponseID, lease.Generation, lease, check)
	if e != nil {
		return NativeResponseChunk{}, e
	}
	chunk, e := exchange.ReadChunk(ctx, lease, offset, length)
	if e != nil {
		exchange.Close()
		return NativeResponseChunk{}, e
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		clear(chunk.Bytes)
		exchange.Close()
		return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	s.active = exchange
	s.activeStop = func() { stop(); cancel() }
	keep = true
	s.lease = lease
	s.mu.Unlock()
	return chunk, nil
}
func (s *RemoteContextSource) AcknowledgeNativeChunk(ctx context.Context, lease artifact.DownloadDeliveryLease, offset, length int64) error {
	if s == nil {
		return artifact.ErrInvalid
	}
	s.mu.Lock()
	active := s.active
	finish := s.activeStop
	if s.closed || s.busy || active == nil || s.lease != lease {
		s.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	s.busy = true
	s.idle = make(chan struct{})
	s.mu.Unlock()
	e := active.AcknowledgeNativeChunk(ctx, lease, offset, length)
	closeErr := active.Close()
	if finish != nil {
		finish()
	}
	s.mu.Lock()
	s.active = nil
	s.activeStop = nil
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
