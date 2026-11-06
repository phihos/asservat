package live

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
)

// Command is the closed private routing companion to the four existing public
// watch operations. It contains no caller-selected owner or identity authority.
type Command struct {
	Open   *v.Open   `json:"open,omitempty"`
	Read   *v.Read   `json:"read,omitempty"`
	Update *v.Update `json:"update,omitempty"`
	Close  bool      `json:"close,omitempty"`
}

func (c Command) Valid() bool {
	count := 0
	if c.Open != nil {
		count++
		if !c.Open.Valid() {
			return false
		}
	}
	if c.Read != nil {
		count++
		if !c.Read.Valid() {
			return false
		}
	}
	if c.Update != nil {
		count++
		if !c.Update.Valid() || !c.Close && c.Update.Mode == "" && c.Update.Filter == nil {
			return false
		}
	}
	return count == 1 && (!c.Close || c.Update != nil)
}
func (c Command) Clone() Command {
	if c.Open != nil {
		r := *c.Open
		r.Handles = slices.Clone(r.Handles)
		r.Filter = v.CloneFilter(r.Filter)
		c.Open = &r
	}
	if c.Read != nil {
		r := *c.Read
		c.Read = &r
	}
	if c.Update != nil {
		r := *c.Update
		if r.Filter != nil {
			f := v.CloneFilter(*r.Filter)
			r.Filter = &f
		}
		c.Update = &r
	}
	return c
}

type CommandResult struct {
	Watch *v.Watch `json:"watch,omitempty"`
	Batch *v.Batch `json:"batch,omitempty"`
}

// CommandDelivery owns transient result bytes through the original ingress's
// acknowledged audit and final response write. Close must cancel and join even
// when its supplied context is already cancelled. Result never performs effects.
type CommandDelivery interface {
	Result() CommandResult
	Done() <-chan struct{}
	CheckDisclosure(context.Context) error
	Close(context.Context) error
}
type OwnedCommands interface {
	BeginLiveCommand(context.Context, CurrentIdentity, Command) (CommandDelivery, error)
}

// RouteKeys are minimized locator inputs, not authority. PrincipalKey keeps the
// existing cross-client human budget identity; OpenKey additionally binds the
// complete client principal. The receiving original session still checks the
// exact current actor/client before any source read. No new durable actor state.
type RouteKeys struct {
	PrincipalKey, OpenKey, RequestDigest [32]byte
	Actor                                identity.Principal
	Policy                               identity.Revision
	Until                                time.Time
	WatchID                              string
}

func (s *Service) OwnerRouteKeys(ctx context.Context, current CurrentIdentity, c Command) (RouteKeys, error) {
	var out RouteKeys
	if s == nil || !c.Valid() {
		return out, v.ErrInvalid
	}
	i, err := s.actor(ctx, current)
	if err != nil {
		return out, err
	}
	out.Actor, out.Policy, out.Until = i.Principal, i.Policy, i.ValidUntil
	if end, ok := ctx.Deadline(); ok {
		out.Until = minTime(out.Until, end)
	}
	out.PrincipalKey, err = s.account("principal", struct {
		Issuer, Subject string
		Kind            identity.Kind
	}{i.Principal.Issuer, i.Principal.Subject, i.Principal.Kind})
	if err != nil {
		return RouteKeys{}, err
	}
	if c.Open != nil {
		r := *c.Open
		if r.Duration == 0 {
			r.Duration = v.DefaultLimits().Duration
		}
		if r.Output == 0 {
			r.Output = v.DefaultLimits().Output
		}
		if r.Filter.All == nil {
			r.Filter.All = []v.Predicate{}
		}
		out.OpenKey, err = s.account("open-key", struct {
			Principal identity.Principal
			Key       string
		}{i.Principal, r.Key})
		if err == nil {
			out.RequestDigest, err = s.account("selection", r)
		}
	} else if c.Read != nil {
		out.WatchID = c.Read.ID
	} else {
		out.WatchID = c.Update.ID
	}
	if err != nil {
		return RouteKeys{}, err
	}
	return out, nil
}
