package identity

import (
	"context"
	"errors"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// ErrReaderBusy means the preceding batch (including any blocked observation)
// still owns this reader. It is distinct from a provider session refresh claim.
var ErrReaderBusy = errors.New("native reader batch active")

// IdentityBatch is one owned short observation, never a remote worker port.
type IdentityBatch interface {
	CurrentIdentity
	Close()
}

// ReaderIdentity is supplied only by the authenticated content ingress. Tests
// may fake this port; requests cannot supply an implementation.
type ReaderIdentity interface {
	BeginBatch(context.Context) (IdentityBatch, error)
	Close()
}

// LiveReader belongs to one authenticated native-content HTTP request. It is not
// CurrentIdentity, a permit, a serializable credential, or a worker-side proxy.
// The transport supplies the independently resolved original actor/client and
// hard transfer deadline; authorization still runs for every returned batch.
type LiveReader struct {
	mu        sync.Mutex
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
	principal value.Principal
	started   time.Time
	until     time.Time
	now       func() time.Time
	shorten   *time.Timer
	closed    bool
	active    *LiveIdentityBatch
	newBatch  func(context.Context) (CurrentIdentity, value.Identity, error)
}

// LiveIdentityBatch retains the original <=5s CurrentIdentity interval. Close
// cancels and joins observations before releasing the reader's sole batch slot.
// Consumers must retain it through their last checked write/flush and Close it
// before beginning another batch. Neither Close nor a new batch renews it.
type LiveIdentityBatch struct {
	mu        sync.Mutex
	closeOnce sync.Once
	work      sync.WaitGroup
	reader    *LiveReader
	ctx       context.Context
	cancel    context.CancelFunc
	stopOwner func() bool
	current   CurrentIdentity
	until     time.Time
	closed    bool
}

func newLiveReader(owner context.Context, principal value.Principal, until time.Time, now func() time.Time) (*LiveReader, error) {
	if owner == nil || now == nil || !principal.Valid() || owner.Err() != nil {
		return nil, value.ErrUnavailable
	}
	started := now()
	if !started.Before(until) {
		return nil, value.ErrDenied
	}
	if deadline, ok := owner.Deadline(); ok {
		until = value.Earlier(until, deadline)
	}
	if !started.Before(until) {
		return nil, value.ErrDenied
	}
	ctx, cancel := context.WithDeadline(owner, until)
	return &LiveReader{ctx: ctx, cancel: cancel, principal: principal, started: started, until: until, now: now}, nil
}

// NewBrowserLiveReader never refreshes credentials. Only the original opaque
// session is read; a later cookie cannot replace it. Origin/CSRF policy belongs
// to the authenticated transport before this private constructor.
func NewBrowserLiveReader(owner context.Context, sessions BrowserSessionResolver, cookie string, principal value.Principal, until time.Time, now func() time.Time) (*LiveReader, error) {
	if sessions == nil {
		return nil, value.ErrUnavailable
	}
	r, err := newLiveReader(owner, principal, until, now)
	if err != nil {
		return nil, err
	}
	observed := liveBrowserSessions{r, sessions}
	r.newBatch = func(ctx context.Context) (CurrentIdentity, value.Identity, error) {
		current, v, err := NewBrowserRequest(ctx, observed, cookie, false, now)
		return current, v.Identity, err
	}
	return r.authenticate()
}

// NewBearerLiveReader retains the exact presented token only inside this hub
// request. Each new batch uses the pinned verifier; no token is fabricated,
// refreshed, exposed, or forwarded to acquisition workers.
func NewBearerLiveReader(owner context.Context, resolver Resolver, token string, principal value.Principal, until time.Time, now func() time.Time) (*LiveReader, error) {
	if resolver == nil {
		return nil, value.ErrUnavailable
	}
	r, err := newLiveReader(owner, principal, until, now)
	if err != nil {
		return nil, err
	}
	r.newBatch = func(ctx context.Context) (CurrentIdentity, value.Identity, error) {
		return NewBearerRequest(ctx, liveBearerResolver{r, resolver}, token, now)
	}
	return r.authenticate()
}

func (r *LiveReader) authenticate() (*LiveReader, error) {
	b, err := r.BeginBatch(r.ctx)
	if err != nil {
		r.Close()
		return nil, err
	}
	b.Close()
	return r, nil
}

type liveBrowserSessions struct {
	reader   *LiveReader
	sessions BrowserSessionResolver
}

type liveBearerResolver struct {
	reader   *LiveReader
	resolver Resolver
}

func (s liveBearerResolver) Resolve(ctx context.Context, token string) (value.Identity, error) {
	i, err := s.resolver.Resolve(ctx, token)
	if ctx.Err() == nil && errors.Is(err, value.ErrDenied) {
		s.reader.terminate()
	}
	return i, err
}

func (s liveBrowserSessions) Resolve(ctx context.Context, cookie string, _ bool) (SessionView, error) {
	v, err := s.sessions.Resolve(ctx, cookie, false)
	if ctx.Err() == nil && errors.Is(err, value.ErrDenied) {
		s.reader.terminate()
	}
	// Retain a trustworthy shortening even if a later observation in this batch
	// fails. The source has resolved this exact cookie and expected principal.
	if err == nil && v.Identity.Principal == s.reader.principal && v.Identity.Valid(s.reader.now()) && !v.ExpiresAt.IsZero() {
		s.reader.shortenUntil(v.ExpiresAt)
	}
	return v, err
}

// A known denial ends this GET. Do not wait here: the source calling this method
// is itself counted work. The owner subsequently calls Close to join it.
func (r *LiveReader) terminate() {
	r.mu.Lock()
	r.closed = true
	if r.shorten != nil {
		r.shorten.Stop()
	}
	r.cancel()
	r.mu.Unlock()
}

func (r *LiveReader) shortenUntil(until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !until.Before(r.until) {
		return
	}
	r.until = until
	if r.shorten != nil {
		r.shorten.Stop()
	}
	remaining := until.Sub(r.now())
	if remaining <= 0 {
		r.cancel()
		return
	}
	r.shorten = time.AfterFunc(remaining, r.cancel)
}

func (r *LiveReader) bound() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	return r.until, !r.closed && r.ctx.Err() == nil && !now.Before(r.started) && now.Before(r.until)
}

func (r *LiveReader) BeginBatch(ctx context.Context) (IdentityBatch, error) {
	if r == nil || r.now == nil || r.ctx == nil || ctx == nil || ctx.Err() != nil {
		return nil, value.ErrDenied
	}
	r.mu.Lock()
	now := r.now()
	if r.closed || r.ctx.Err() != nil || now.Before(r.started) || !now.Before(r.until) {
		r.mu.Unlock()
		return nil, value.ErrDenied
	}
	if r.active != nil {
		r.mu.Unlock()
		return nil, ErrReaderBusy
	}
	batchCtx, cancel := context.WithDeadline(ctx, value.Earlier(r.until, now.Add(5*time.Second)))
	b := &LiveIdentityBatch{reader: r, ctx: batchCtx, cancel: cancel}
	b.stopOwner = context.AfterFunc(r.ctx, cancel)
	b.work.Add(1) // Includes authentication until it actually joins after cancel.
	r.active = b
	newBatch := r.newBatch
	r.mu.Unlock()
	current, initial, err := newBatch(batchCtx)
	until, alive := r.bound()
	if err == nil && initial.Principal != r.principal {
		r.terminate()
	}
	if err == nil && (!alive || batchCtx.Err() != nil || current == nil || initial.Principal != r.principal || !initial.Valid(r.now()) || !r.now().Before(until)) {
		err = value.ErrDenied
	}
	b.mu.Lock()
	if b.closed && err == nil {
		err = value.ErrDenied
	}
	if err == nil {
		b.current = current
		b.until = initial.ValidUntil
	}
	b.mu.Unlock()
	b.work.Done()
	if err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

func (b *LiveIdentityBatch) ResolveIdentity(ctx context.Context) (value.Identity, error) {
	if b == nil || ctx == nil || ctx.Err() != nil {
		return value.Identity{}, value.ErrDenied
	}
	b.mu.Lock()
	if b.closed || b.current == nil || b.ctx.Err() != nil {
		b.mu.Unlock()
		return value.Identity{}, value.ErrDenied
	}
	b.work.Add(1)
	current := b.current
	b.mu.Unlock()
	defer b.work.Done()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		// Ordinary expiry of this observation is not expiry of the reader.
		// A source denial is terminal via the resolver above; a contradiction
		// while this original interval remains live is also terminal.
		b.mu.Lock()
		stillLive := !b.closed && b.reader.now().Before(b.until)
		b.mu.Unlock()
		if errors.Is(err, value.ErrDenied) && ctx.Err() == nil && b.ctx.Err() == nil && stillLive {
			b.reader.terminate()
		}
		return value.Identity{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reader.mu.Lock()
	defer b.reader.mu.Unlock()
	now := b.reader.now()
	i.ValidUntil = value.Earlier(i.ValidUntil, b.reader.until)
	if b.closed || b.ctx.Err() != nil || ctx.Err() != nil || b.reader.closed || b.reader.ctx.Err() != nil || now.Before(b.reader.started) || i.Principal != b.reader.principal || !i.Valid(now) {
		return value.Identity{}, value.ErrDenied
	}
	b.until = value.Earlier(b.until, i.ValidUntil)
	return i, nil
}

func (b *LiveIdentityBatch) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.cancel()
		b.mu.Unlock()
		b.stopOwner()
		b.work.Wait()
		b.mu.Lock()
		b.current = nil
		b.mu.Unlock()
		b.reader.mu.Lock()
		if b.reader.active == b {
			b.reader.active = nil
		}
		b.reader.mu.Unlock()
	})
}

func (r *LiveReader) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		if r.shorten != nil {
			r.shorten.Stop()
		}
		active := r.active
		r.cancel()
		r.mu.Unlock()
		active.Close()
		r.mu.Lock()
		r.newBatch = nil // Release the private credential closure after all reads join.
		r.mu.Unlock()
	})
}
