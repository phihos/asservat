package delivery

import (
	"context"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

// NodeWorkDelivery is receive-only. The public retained queue and receipts
// contain Work alone; private material is never serialized by this value.
type NodeWorkDelivery struct {
	collector.Work
	ProfileAuthorization            []byte `json:"-"`
	ProfileAuthorizationUnavailable bool   `json:"-"`
}

type ProfileAuthorizationSource interface {
	ReadNodeProfileAuthorization(context.Context, collector.Identity, collector.Work) ([]byte, error)
}

// ProfileAuthorization reuses the original retained work and process pins both
// before and after the independent protected material read.
func (c *NodeChannel) ProfileAuthorization(ctx context.Context, peer NodePeer, epoch string, work collector.Work) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || work.Profile == nil || !work.Profile.AuthorizationRequired {
		return nil, ErrNodeInvalid
	}
	current := func() (collector.Identity, ProfileAuthorizationSource, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		e, err := c.current(peer, epoch)
		if err != nil {
			return collector.Identity{}, nil, err
		}
		pending, ok := e.captures[work.ID]
		reader, available := c.profileSink.(ProfileAuthorizationSource)
		if !ok || pending.cancelOnly || pending.profile == nil || *pending.profile != *work.Profile || !available || !c.view(e, c.now()).ProfileAuthorizationAvailable() || !c.now().Before(work.NotAfter) || ctx.Err() != nil {
			return collector.Identity{}, nil, ErrNodeDenied
		}
		for _, queued := range e.work {
			if queued.ID == work.ID && queued.Sequence == work.Sequence && queued.NotAfter.Equal(work.NotAfter) {
				return e.id, reader, nil
			}
		}
		return collector.Identity{}, nil, ErrNodeDenied
	}
	id, reader, err := current()
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithDeadline(ctx, work.NotAfter)
	defer cancel()
	value, readErr := reader.ReadNodeProfileAuthorization(bounded, id, work)
	if fresh, _, err := current(); err != nil {
		clear(value)
		return nil, err
	} else if fresh != id {
		clear(value)
		return nil, ErrNodeDenied
	}
	if readErr != nil || !execution.ValidGoProfileAuthorization(value) || bounded.Err() != nil {
		clear(value)
		return nil, ErrNodeUnavailable
	}
	return value, nil
}
