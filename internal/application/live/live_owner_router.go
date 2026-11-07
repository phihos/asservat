package live

import (
	"context"
	"fmt"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
)

// OwnerCommandRoute is a protected exact-owner route supplied by bootstrap.
// It contains no public endpoint and cannot adopt another owner's session.
type OwnerCommandRoute interface {
	OwnerID() string
	Begin(context.Context, CurrentIdentity, Command, RouteKeys) (CommandDelivery, error)
}
type OwnerCommandLookup interface {
	LocateLiveOwner(context.Context, RouteKeys) (OwnerCommandRoute, bool, error)
}

type RoutedService struct {
	local  *Service
	lookup OwnerCommandLookup
}

func NewRoutedService(local *Service, lookup OwnerCommandLookup) (*RoutedService, error) {
	if local == nil || lookup == nil {
		return nil, fmt.Errorf("%w: live_owner_router:30", v.ErrInvalid)
	}
	return &RoutedService{local, lookup}, nil
}
func (s *RoutedService) List(ctx context.Context, current CurrentIdentity, target targets.WorkloadRequest, cursor string, limit int) (v.SourcePage, string, error) {
	return s.local.List(ctx, current, target, cursor, limit)
}
func (s *RoutedService) BeginLiveCommand(ctx context.Context, current CurrentIdentity, c Command) (CommandDelivery, error) {
	if s == nil || s.local == nil || s.lookup == nil || ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: live_owner_router:39", v.ErrUnavailable)
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	transferred := false
	defer func() {
		if !transferred {
			cancel()
		}
	}()
	ctx = call
	c = c.Clone()
	keys, err := s.local.OwnerRouteKeys(ctx, current, c)
	if err != nil {
		return nil, err
	}
	route, found, err := s.lookup.LocateLiveOwner(ctx, keys)
	if err != nil {
		return nil, err
	}
	if found {
		if route == nil || route.OwnerID() == "" {
			return nil, fmt.Errorf("%w: live_owner_router:60", v.ErrUnavailable)
		}
		if route.OwnerID() != s.local.cfg.OwnerID {
			d, e := route.Begin(ctx, current, c, keys)
			if e != nil {
				return nil, e
			}
			transferred = true
			return &cancelCommandDelivery{CommandDelivery: d, cancel: cancel}, nil
		}
	} else if c.Open == nil {
		return nil, fmt.Errorf("%w: live_owner_router:71", v.ErrUnavailable)
	}
	d, e := s.local.BeginOwnedLocalCommand(ctx, current, c, keys)
	if e != nil {
		return nil, e
	}
	transferred = true
	return &cancelCommandDelivery{CommandDelivery: d, cancel: cancel}, nil
}

// The four direct methods preserve the existing interface. Public transports
// use BeginLiveCommand to retain remote ownership through the final response.
func (s *RoutedService) Open(ctx context.Context, current CurrentIdentity, r v.Open) (v.Watch, error) {
	d, e := s.BeginLiveCommand(ctx, current, Command{Open: &r})
	if e != nil {
		return v.Watch{}, e
	}
	defer d.Close(ctx)
	out := d.Result()
	if out.Watch == nil {
		return v.Watch{}, fmt.Errorf("%w: live_owner_router:91", v.ErrUnavailable)
	}
	return *out.Watch, nil
}
func (s *RoutedService) Read(ctx context.Context, current CurrentIdentity, r v.Read) (v.Batch, error) {
	d, e := s.BeginLiveCommand(ctx, current, Command{Read: &r})
	if e != nil {
		return v.Batch{}, e
	}
	defer d.Close(ctx)
	out := d.Result()
	if out.Batch == nil {
		return v.Batch{}, fmt.Errorf("%w: live_owner_router:103", v.ErrUnavailable)
	}
	return *out.Batch, nil
}
func (s *RoutedService) Update(ctx context.Context, current CurrentIdentity, r v.Update, close bool) (v.Watch, error) {
	d, e := s.BeginLiveCommand(ctx, current, Command{Update: &r, Close: close})
	if e != nil {
		return v.Watch{}, e
	}
	defer d.Close(ctx)
	out := d.Result()
	if out.Watch == nil {
		return v.Watch{}, fmt.Errorf("%w: live_owner_router:115", v.ErrUnavailable)
	}
	return *out.Watch, nil
}

// BeginOwnedLocalCommand executes only the existing service methods. keys bind
// the original ingress callback; the service independently resolves that live
// identity and checks its exact original session actor/client before effects.
func (s *Service) BeginOwnedLocalCommand(ctx context.Context, current CurrentIdentity, c Command, keys RouteKeys) (CommandDelivery, error) {
	if s == nil || !c.Valid() || ctx == nil || ctx.Err() != nil || !keys.Actor.Valid() || !keys.Policy.Valid() || !s.cfg.Now().Before(keys.Until) {
		return nil, fmt.Errorf("%w: live_owner_router:125", v.ErrInvalid)
	}
	current = routeBoundIdentity{inner: current, keys: keys, now: s.cfg.Now}
	var result CommandResult
	var err error
	switch {
	case c.Open != nil:
		var w v.Watch
		w, err = s.Open(ctx, current, *c.Open)
		result.Watch = &w
	case c.Read != nil:
		var b v.Batch
		b, err = s.Read(ctx, current, *c.Read)
		result.Batch = &b
	default:
		var w v.Watch
		w, err = s.Update(ctx, current, *c.Update, c.Close)
		result.Watch = &w
	}
	if err != nil {
		return nil, err
	}
	until := keys.Until
	if end, ok := ctx.Deadline(); ok {
		until = minTime(until, end)
	}
	if result.Batch != nil {
		if result.Batch.DisclosureUntil.IsZero() {
			return nil, fmt.Errorf("%w: live_owner_router:153", v.ErrUnavailable)
		}
		until = minTime(until, result.Batch.DisclosureUntil)
	}
	if result.Watch != nil {
		until = minTime(until, result.Watch.ExpiresAt)
	}
	if !s.cfg.Now().Before(until) || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: live_owner_router:161", v.ErrUnavailable)
	}
	owned, cancel := context.WithDeadline(ctx, until)
	return &localCommandDelivery{ctx: owned, cancel: cancel, result: result, until: until, now: s.cfg.Now}, nil
}

type localCommandDelivery struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	result CommandResult
	until  time.Time
	now    func() time.Time
}

func (d *localCommandDelivery) Result() CommandResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.result
	if out.Watch != nil {
		w := cloneWatch(*out.Watch)
		out.Watch = &w
	}
	if out.Batch != nil {
		b := v.CloneBatch(*out.Batch)
		out.Batch = &b
	}
	return out
}
func (d *localCommandDelivery) Done() <-chan struct{} { return d.ctx.Done() }
func (d *localCommandDelivery) CheckDisclosure(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || d.ctx.Err() != nil || !d.now().Before(d.until) {
		return identity.ErrDenied
	}
	return nil
}
func (d *localCommandDelivery) Close(context.Context) error {
	d.cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.result.Batch != nil {
		clear(d.result.Batch.Rows)
	}
	d.result = CommandResult{}
	return nil
}

// Every existing identity check still reaches the actual ingress resolver. This
// wrapper only narrows its original bound and rejects actor/client/policy swaps;
// it never manufactures an observation or caches a callback response.
type routeBoundIdentity struct {
	inner CurrentIdentity
	keys  RouteKeys
	now   func() time.Time
}

func (b routeBoundIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if b.inner == nil || ctx == nil || ctx.Err() != nil || !b.now().Before(b.keys.Until) {
		return identity.Identity{}, identity.ErrDenied
	}
	call, end := context.WithDeadline(ctx, b.keys.Until)
	defer end()
	i, e := b.inner.ResolveIdentity(call)
	if e != nil || !i.Valid(b.now()) || i.Principal != b.keys.Actor || i.Policy != b.keys.Policy || call.Err() != nil || !b.now().Before(b.keys.Until) {
		return identity.Identity{}, identity.ErrDenied
	}
	i.ValidUntil = minTime(i.ValidUntil, b.keys.Until)
	return i, nil
}

type cancelCommandDelivery struct {
	CommandDelivery
	cancel context.CancelFunc
}

func (d *cancelCommandDelivery) Close(ctx context.Context) error {
	defer d.cancel()
	return d.CommandDelivery.Close(ctx)
}
