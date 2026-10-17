package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"sync"
)

// The only production caller is the positive SQL Stop boundary. No public ID
// alone can cancel work, and cancellation never refunds durable accounting.
type DownloadActiveTransfers interface {
	CancelDownloadTransfers(context.Context, artifact.DownloadStopDecision) error
}
type contextNativeTransfer struct {
	session   string
	principal identity.Principal
	cancel    context.CancelFunc
	joined    chan struct{}
}
type contextNativeTransfers struct {
	mu     sync.Mutex
	live   map[*contextNativeTransfer]struct{}
	closed bool
}

func newContextNativeTransfers() *contextNativeTransfers {
	return &contextNativeTransfers{live: make(map[*contextNativeTransfer]struct{})}
}

// Configured describes complete constructor wiring, not current readiness or
// evidence authority. Every request still checks actual current sources/SQL.
func (r *ContextNativeRuntime) Configured() bool {
	return r != nil && r.bound == nil && r.metadata != nil && r.active != nil && r.config.Now != nil && r.config.Serving != nil
}
func (t DownloadResponseTransfer) Configured() bool { return t.valid() }

// BeginContent retains a local slot before the first SQL/current check. A Stop
// which committed before registration is therefore caught by that check. The
// returned release must run only after source/reader/response cleanup joins.
func (r *ContextNativeRuntime) BeginContent(ctx context.Context, id string, p identity.Principal) (context.Context, func(), error) {
	if !r.Configured() || ctx == nil || ctx.Err() != nil || !authorization.UUID(id) || !p.Valid() {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	return r.active.begin(ctx, id, p)
}
func (a *contextNativeTransfers) begin(ctx context.Context, id string, p identity.Principal) (context.Context, func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || len(a.live) >= 16 || ctx.Err() != nil {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	owner, cancel := context.WithCancel(ctx)
	h := &contextNativeTransfer{session: id, principal: p, cancel: cancel, joined: make(chan struct{})}
	a.live[h] = struct{}{}
	var once sync.Once
	release := func() { once.Do(func() { cancel(); a.mu.Lock(); delete(a.live, h); close(h.joined); a.mu.Unlock() }) }
	return owner, release, nil
}
func (r *ContextNativeRuntime) CancelDownloadTransfers(ctx context.Context, d artifact.DownloadStopDecision) error {
	if r == nil || r.active == nil || ctx == nil || !d.Valid() {
		return artifact.ErrDownloadUnavailable
	}
	return r.active.cancel(ctx, d.DownloadID, d.Actor)
}
func (a *contextNativeTransfers) cancel(ctx context.Context, id string, p identity.Principal) error {
	a.mu.Lock()
	var joins []chan struct{}
	for h := range a.live {
		if h.session == id && h.principal == p {
			h.cancel()
			joins = append(joins, h.joined)
		}
	}
	a.mu.Unlock()
	for _, done := range joins {
		select {
		case <-done:
		case <-ctx.Done():
			return artifact.ErrDownloadUnavailable
		}
	}
	if ctx.Err() != nil {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (a *contextNativeTransfers) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	var joins []chan struct{}
	for h := range a.live {
		h.cancel()
		joins = append(joins, h.joined)
	}
	a.mu.Unlock()
	for _, done := range joins {
		<-done
	}
}
