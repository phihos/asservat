package evidence

import (
	"context"
	"slices"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// workerCurrentCheck belongs to one live hub request. It neither serializes
// identity nor renews a request when routing, SQL or provider work blocks.
// One complete authority observation belongs to the original <=5s operation.
// Later checks are local; SQL effects retain their independent current fences.
// Explicit source/attachment bounds may shorten, but cannot restore, its bound.
type workerCurrentCheck struct {
	mu             sync.Mutex
	owner          context.Context
	observation    artifact.DownloadAuthority
	scope          artifact.DownloadScope
	started, until time.Time
	now            func() time.Time
}

func newWorkerCurrentCheck(ctx context.Context, source identities.CurrentIdentity, authority CurrentDownloadAuthority, scope artifact.DownloadScope, now func() time.Time) (*workerCurrentCheck, error) {
	c, _, err := newWorkerCurrentObservation(ctx, source, authority, scope, now)
	return c, err
}

// Every new operation obtains one complete observation. Reusing it through
// Check never repeats authentication or renews any original deadline.
func newWorkerCurrentObservation(ctx context.Context, source identities.CurrentIdentity, authority CurrentDownloadAuthority, scope artifact.DownloadScope, now func() time.Time) (*workerCurrentCheck, artifact.DownloadAuthority, error) {
	var zero artifact.DownloadAuthority
	if ctx == nil || ctx.Err() != nil || source == nil || authority == nil || !scope.Valid() || now == nil {
		return nil, zero, artifact.ErrInvalid
	}
	started := now()
	until := started.Add(artifact.DownloadLease)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	initial, err := source.ResolveIdentity(call)
	callErr := call.Err()
	cancel()
	if err != nil || callErr != nil || ctx.Err() != nil || now().Before(started) || !initial.Valid(now()) || initial.Principal != scope.Principal || !slices.Contains(initial.Scopes, "evidence:read") || !slices.Contains(initial.Scopes, "evidence:download") {
		return nil, zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, initial.ValidUntil)
	call, cancel = context.WithDeadline(ctx, until)
	a, err := authority.CheckDownloadCurrent(call, source, scope)
	callErr = call.Err()
	cancel()
	if err != nil || callErr != nil || ctx.Err() != nil || now().Before(started) || !a.Valid(now()) || !a.Environment.Valid(now()) || !a.Retention.Valid(now()) || a.Scope != scope {
		return nil, zero, artifact.ErrDownloadUnavailable
	}
	c := &workerCurrentCheck{owner: ctx, observation: a, scope: scope, started: started, until: identity.Earlier(until, a.ValidUntil), now: now}
	a, err = c.Check(ctx)
	if err != nil {
		return nil, zero, err
	}
	return c, a, nil
}

// The response has already reconstructed its complete short authority from its
// owned ordinary observation and current safety facts. Bind that exact value to
// the same current identity batch, keeping its original CheckedAt/ValidUntil.
// This private handoff never creates another response or a renewable authority.
func newWorkerResponseObservation(ctx context.Context, source identities.CurrentIdentity, a artifact.DownloadAuthority, scope artifact.DownloadScope, now func() time.Time) (*workerCurrentCheck, artifact.DownloadAuthority, error) {
	var zero artifact.DownloadAuthority
	if ctx == nil || ctx.Err() != nil || source == nil || !scope.Valid() || now == nil {
		return nil, zero, artifact.ErrInvalid
	}
	started := now()
	if !a.Valid(started) || !a.Environment.Valid(started) || !a.Retention.Valid(started) || a.Scope != scope {
		return nil, zero, artifact.ErrDownloadUnavailable
	}
	until := identity.Earlier(started.Add(artifact.DownloadLease), a.ValidUntil)
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	call, cancel := context.WithDeadline(ctx, until)
	i, err := source.ResolveIdentity(call)
	callErr := call.Err()
	cancel()
	if err != nil || callErr != nil || ctx.Err() != nil || now().Before(started) || !i.Valid(now()) || i.Principal != scope.Principal || i.Policy != a.IdentityRevision || !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Scopes, "evidence:download") {
		return nil, zero, artifact.ErrDownloadUnavailable
	}
	c := &workerCurrentCheck{owner: ctx, observation: a, scope: scope, started: started, until: identity.Earlier(until, i.ValidUntil), now: now}
	a, err = c.Check(ctx)
	if err != nil {
		return nil, zero, err
	}
	return c, a, nil
}

func (c *workerCurrentCheck) Deadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.until
}
func (c *workerCurrentCheck) narrow(until time.Time) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.until = identity.Earlier(c.until, until)
	n := c.now()
	if c.owner.Err() != nil || n.Before(c.started) || !n.Before(c.until) {
		return time.Time{}, artifact.ErrDownloadExpired
	}
	return c.until, nil
}
func (c *workerCurrentCheck) Check(ctx context.Context) (artifact.DownloadAuthority, error) {
	var zero artifact.DownloadAuthority
	if c == nil || ctx == nil || ctx.Err() != nil || c.owner.Err() != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.now()
	a := c.observation
	a.ValidUntil = c.until
	if ctx.Err() != nil || c.owner.Err() != nil || n.Before(c.started) || !n.Before(c.until) || !a.Valid(n) || !a.Environment.Valid(n) || !a.Retention.Valid(n) || a.Scope != c.scope {
		return zero, artifact.ErrDownloadExpired
	}
	return a, nil
}

// Each finite coordinator call shortens subsequent effect contexts when an
// independently read source/attachment is stricter. Existing children retain
// their earlier bound; this never renews the request or creates background work.
func workerEffectContext(ctx *context.Context, bound func() time.Time) (shorten, finish func()) {
	var mu sync.Mutex
	var cancels []context.CancelFunc
	closed := false
	return func() {
			if bound == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			until := bound()
			if existing, ok := (*ctx).Deadline(); ok && !until.Before(existing) {
				return
			}
			call, cancel := context.WithDeadline(*ctx, until)
			*ctx = call
			if closed {
				cancel()
			} else {
				cancels = append(cancels, cancel)
			}
		}, func() {
			mu.Lock()
			defer mu.Unlock()
			closed = true
			for i := len(cancels) - 1; i >= 0; i-- {
				cancels[i]()
			}
			cancels = nil
		}
}
