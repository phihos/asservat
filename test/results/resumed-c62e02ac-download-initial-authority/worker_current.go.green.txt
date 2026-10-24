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
// Multiple current observations may shorten, but cannot restore, its bound.
type workerCurrentCheck struct {
	mu             sync.Mutex
	owner          context.Context
	source         identities.CurrentIdentity
	authority      CurrentDownloadAuthority
	initial        identity.Identity
	scope          artifact.DownloadScope
	started, until time.Time
	now            func() time.Time
}

func newWorkerCurrentCheck(ctx context.Context, source identities.CurrentIdentity, authority CurrentDownloadAuthority, scope artifact.DownloadScope, now func() time.Time) (*workerCurrentCheck, error) {
	c, _, err := newWorkerCurrentObservation(ctx, source, authority, scope, now)
	return c, err
}

// The initial observation can be consumed by an immediately following read.
// It is not cached by Check: every later check still observes current authority.
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
	initial.Groups, initial.Scopes = slices.Clone(initial.Groups), slices.Clone(initial.Scopes)
	c := &workerCurrentCheck{owner: ctx, source: source, authority: authority, initial: initial, scope: scope, started: started, until: identity.Earlier(until, initial.ValidUntil), now: now}
	a, err := c.Check(ctx)
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
	until, err := c.narrow(c.Deadline())
	if err != nil {
		return zero, err
	}
	call, cancel := context.WithDeadline(ctx, until)
	stop := context.AfterFunc(c.owner, cancel)
	defer func() { stop(); cancel() }()
	latest, err := c.source.ResolveIdentity(call)
	if err != nil || call.Err() != nil || !downloadSameIdentity(c.initial, latest, c.now()) {
		return zero, artifact.ErrDownloadUnavailable
	}
	until, err = c.narrow(latest.ValidUntil)
	if err != nil {
		return zero, err
	}
	gate, end := context.WithDeadline(call, until)
	defer end()
	a, err := c.authority.CheckDownloadCurrent(gate, c.source, c.scope)
	if err != nil || gate.Err() != nil || !a.Valid(c.now()) || !a.Environment.Valid(c.now()) || !a.Retention.Valid(c.now()) || a.Scope != c.scope {
		return zero, artifact.ErrDownloadUnavailable
	}
	// Preserve this restrictive observation even if final identity later fails.
	until, err = c.narrow(a.ValidUntil)
	if err != nil {
		return zero, err
	}
	final, stopFinal := context.WithDeadline(gate, until)
	latest, err = c.source.ResolveIdentity(final)
	finalErr := final.Err()
	stopFinal()
	if err != nil || finalErr != nil || !downloadSameIdentity(c.initial, latest, c.now()) {
		return zero, artifact.ErrDownloadUnavailable
	}
	until, err = c.narrow(latest.ValidUntil)
	if err != nil || ctx.Err() != nil || gate.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	a.ValidUntil = until
	if !a.Valid(c.now()) {
		return zero, artifact.ErrDownloadExpired
	}
	return a, nil
}

// Each finite coordinator call shortens subsequent effect contexts when a newer
// observation is stricter. Existing children also retain their earlier bound;
// this helper never renews the request or creates background work.
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
