package identity

import (
	"context"
	"slices"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// CurrentIdentity is a current request-owned identity observation, not an
// execution permit. Production transports construct it from their independently
// configured credential resolver; no request field can supply an implementation.
type CurrentIdentity interface {
	ResolveIdentity(context.Context) (value.Identity, error)
}

type BrowserSessionResolver interface {
	Resolve(context.Context, string, bool) (SessionView, error)
}

type currentRequest struct {
	mu      sync.Mutex
	until   time.Time
	owner   context.Context
	initial value.Identity
	started time.Time
	now     func() time.Time
	resolve func(context.Context) (value.Identity, error)
}

func cloneIdentity(i value.Identity) value.Identity {
	i.Scopes, i.Groups = slices.Clone(i.Scopes), slices.Clone(i.Groups)
	return i
}

func sameIdentitySet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func bindCurrentRequest(ctx context.Context, started time.Time, lifetime time.Duration, initial value.Identity, resolve func(context.Context) (value.Identity, error), now func() time.Time) (CurrentIdentity, value.Identity, error) {
	n := now()
	initial.ValidUntil = value.Earlier(initial.ValidUntil, started.Add(lifetime))
	if ctx.Err() != nil || n.Before(started) || !initial.Valid(n) {
		return nil, value.Identity{}, value.ErrDenied
	}
	i := cloneIdentity(initial)
	return &currentRequest{owner: ctx, initial: i, started: started, now: now, resolve: resolve, until: i.ValidUntil}, cloneIdentity(i), nil
}

// NewBearerRequest authenticates one request through the configured verifier.
// The resolver must already pin the intended resource/client policy. The returned
// snapshot is for presentation, principal accounting and the original deadline;
// consumers must use CurrentIdentity for subsequent authorization checks.
func NewBearerRequest(ctx context.Context, resolver Resolver, token string, now func() time.Time) (CurrentIdentity, value.Identity, error) {
	return NewBearerRequestWithin(ctx, resolver, token, now, 5*time.Second)
}

// NewBearerRequestWithin is NewBearerRequest for a transport whose request may
// be an evidence read: lifetime is at most value.EvidenceReadRequestWindow and
// only caps the request, never the resolver's own identity interval. The
// transport must shorten every other request to its own operation window.
func NewBearerRequestWithin(ctx context.Context, resolver Resolver, token string, now func() time.Time, lifetime time.Duration) (CurrentIdentity, value.Identity, error) {
	if ctx == nil || resolver == nil || now == nil || ctx.Err() != nil || lifetime <= 0 || lifetime > value.EvidenceReadRequestWindow {
		return nil, value.Identity{}, value.ErrUnavailable
	}
	started := now()
	initialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolve := func(c context.Context) (value.Identity, error) { return resolver.Resolve(c, token) }
	i, err := resolve(initialCtx)
	if err != nil {
		return nil, value.Identity{}, err
	}
	if initialCtx.Err() != nil {
		return nil, value.Identity{}, value.ErrDenied
	}
	return bindCurrentRequest(ctx, started, lifetime, i, resolve, now)
}

// NewBrowserRequest accepts only the private session cookie after the transport
// has checked origin/CSRF. Refresh is allowed only at this initial ingress when
// requested; every later current check is read-only. Provider tokens never cross
// this boundary, and a replacement login cannot continue an old request.
func NewBrowserRequest(ctx context.Context, sessions BrowserSessionResolver, cookie string, allowRefresh bool, now func() time.Time) (CurrentIdentity, SessionView, error) {
	return NewBrowserRequestWithin(ctx, sessions, cookie, allowRefresh, now, 5*time.Second)
}

// NewBrowserRequestWithin is NewBrowserRequest for an operation whose request
// window (audit.OperationRequestWindow) may be an evidence read, matching MCP.
func NewBrowserRequestWithin(ctx context.Context, sessions BrowserSessionResolver, cookie string, allowRefresh bool, now func() time.Time, lifetime time.Duration) (CurrentIdentity, SessionView, error) {
	if ctx == nil || sessions == nil || now == nil || ctx.Err() != nil || lifetime <= 0 || lifetime > value.EvidenceReadRequestWindow {
		return nil, SessionView{}, value.ErrUnavailable
	}
	started := now()
	initialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := sessions.Resolve(initialCtx, cookie, allowRefresh)
	if err != nil {
		return nil, SessionView{}, err
	}
	if initialCtx.Err() != nil || !now().Before(v.ExpiresAt) {
		return nil, SessionView{}, value.ErrDenied
	}
	v.Identity.ValidUntil = value.Earlier(v.Identity.ValidUntil, v.ExpiresAt)
	originalExpiry := v.ExpiresAt
	resolve := func(c context.Context) (value.Identity, error) {
		current, err := sessions.Resolve(c, cookie, false)
		if err != nil {
			return value.Identity{}, err
		}
		if !now().Before(current.ExpiresAt) || current.ExpiresAt.After(originalExpiry) {
			return value.Identity{}, value.ErrDenied
		}
		current.Identity.ValidUntil = value.Earlier(current.Identity.ValidUntil, current.ExpiresAt)
		return current.Identity, nil
	}
	h, i, err := bindCurrentRequest(ctx, started, lifetime, v.Identity, resolve, now)
	if err != nil {
		return nil, SessionView{}, err
	}
	v.Identity = i
	return h, v, nil
}

func (r *currentRequest) ResolveIdentity(ctx context.Context) (value.Identity, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.owner.Err() != nil {
		return value.Identity{}, value.ErrDenied
	}
	n := r.now()
	r.mu.Lock()
	until := r.until
	r.mu.Unlock()
	if n.Before(r.started) || !r.initial.Valid(n) || !n.Before(until) {
		return value.Identity{}, value.ErrDenied
	}
	// A caller cannot detach this check from the original HTTP request by passing
	// Background. Link both cancellations for the entire blocking observation.
	currentCtx, cancel := context.WithTimeout(ctx, until.Sub(n))
	stop := context.AfterFunc(r.owner, cancel)
	defer func() { stop(); cancel() }()
	if r.owner.Err() != nil {
		return value.Identity{}, value.ErrDenied
	}
	i, err := r.resolve(currentCtx)
	if err != nil {
		return value.Identity{}, err
	}
	n = r.now()
	if currentCtx.Err() != nil || r.owner.Err() != nil || n.Before(r.started) || !r.initial.Valid(n) || !i.Valid(n) || i.Principal != r.initial.Principal || i.Policy != r.initial.Policy || !sameIdentitySet(i.Scopes, r.initial.Scopes) || !sameIdentitySet(i.Groups, r.initial.Groups) {
		return value.Identity{}, value.ErrDenied
	}
	// Once any observation shortens this request, a later or concurrently
	// completing provider read cannot restore the longer original interval.
	r.mu.Lock()
	defer r.mu.Unlock()
	n = r.now()
	if currentCtx.Err() != nil || r.owner.Err() != nil || n.Before(r.started) || !r.initial.Valid(n) {
		return value.Identity{}, value.ErrDenied
	}
	i.ValidUntil = value.Earlier(i.ValidUntil, r.until)
	if !i.Valid(n) {
		return value.Identity{}, value.ErrDenied
	}
	r.until = i.ValidUntil
	return cloneIdentity(i), nil
}

// ShortenRequest caps a request identity at until, for a transport that
// learns after authentication that the request is not an evidence read. It
// can only shorten: every result keeps the inner identity's own ValidUntil.
func ShortenRequest(current CurrentIdentity, until time.Time, now func() time.Time) CurrentIdentity {
	return shortenedRequest{inner: current, until: until, now: now}
}

type shortenedRequest struct {
	inner CurrentIdentity
	until time.Time
	now   func() time.Time
}

func (r shortenedRequest) ResolveIdentity(ctx context.Context) (value.Identity, error) {
	if r.inner == nil || r.now == nil || ctx == nil || !r.now().Before(r.until) {
		return value.Identity{}, value.ErrDenied
	}
	bounded, cancel := context.WithDeadline(ctx, r.until)
	defer cancel()
	i, err := r.inner.ResolveIdentity(bounded)
	if err != nil {
		return value.Identity{}, err
	}
	i.ValidUntil = value.Earlier(i.ValidUntil, r.until)
	if bounded.Err() != nil || !i.Valid(r.now()) {
		return value.Identity{}, value.ErrDenied
	}
	return i, nil
}
