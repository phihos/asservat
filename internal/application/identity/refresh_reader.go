package identity

import (
	value "asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// PausingReader is optional and browser-only. Busy alone remains insufficient.
// Evidence consumers call this port only after their exact SQL42 response exists.
type PausingReader interface {
	ReaderIdentity
	OwnedRefreshPause(context.Context, value.RefreshResponseBinding) (value.RefreshPause, error)
}

type BrowserRefreshReader struct {
	*LiveReader
	pauses  BrowserRefreshPauseReader
	session [32]byte
}

// NewBrowserRefreshReader is a content GET constructor, never refresh admission.
// It retains the actual original cookie inside C02 only, authenticates through
// the existing read-only live reader, and cannot recover an initially denied GET.
func NewBrowserRefreshReader(ctx context.Context, sessions BrowserSessionResolver, pauses BrowserRefreshPauseReader, cookie string, principal value.Principal, until time.Time, now func() time.Time) (*BrowserRefreshReader, error) {
	if pauses == nil {
		return nil, value.ErrUnavailable
	}
	key, err := sessionKey(cookie)
	if err != nil {
		return nil, err
	}
	reader, err := NewBrowserLiveReader(ctx, sessions, cookie, principal, until, now)
	if err != nil {
		return nil, err
	}
	return &BrowserRefreshReader{LiveReader: reader, pauses: pauses, session: key}, nil
}

// OwnedRefreshPause checks scheduling-only association. Original live connection
// cancellation and the reader's monotonically shortened hard end remain binding;
// supplying Background cannot detach this observation. Close joins it through a
// reader batch slot, just like a blocked identity observation.
func (r *BrowserRefreshReader) OwnedRefreshPause(ctx context.Context, response value.RefreshResponseBinding) (value.RefreshPause, error) {
	if r == nil || r.LiveReader == nil || ctx == nil || !response.Valid() {
		return value.RefreshPause{}, value.ErrDenied
	}
	r.mu.Lock()
	now := r.now()
	if r.closed || r.ctx.Err() != nil || ctx.Err() != nil || now.Before(r.started) || !now.Before(r.until) {
		r.mu.Unlock()
		return value.RefreshPause{}, value.ErrDenied
	}
	if r.active != nil {
		r.mu.Unlock()
		return value.RefreshPause{}, ErrReaderBusy
	}
	until := value.Earlier(r.until, now.Add(5*time.Second))
	call, cancel := context.WithDeadline(ctx, until)
	unlink := context.AfterFunc(r.ctx, cancel)
	slot := &LiveIdentityBatch{reader: r.LiveReader, ctx: call, cancel: cancel, stopOwner: unlink, until: until}
	slot.work.Add(1)
	r.active = slot
	r.mu.Unlock()
	defer slot.Close()
	defer slot.work.Done()
	pause, err := r.pauses.BrowserRefreshPause(call, r.session, r.principal, response)
	if err != nil {
		return value.RefreshPause{}, err
	}
	bound, valid := r.bound()
	pause.ValidUntil = value.Earlier(pause.ValidUntil, value.Earlier(until, bound))
	if !valid || call.Err() != nil || !pause.Valid(r.now()) || !pause.Matches(response) || pause.Owner.SessionID != r.session {
		return value.RefreshPause{}, value.ErrDenied
	}
	return pause, nil
}
