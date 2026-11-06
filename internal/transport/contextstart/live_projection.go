package contextstart

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/node"
	"context"
	"sync"
	"time"
)

const queryLiveProjection = "read-live-projection"

type liveProjectionTargets interface {
	ReadLiveProjections(context.Context, []collector.LiveRead) ([]v.NodeReply, error)
}

func liveBatchWire(requests []collector.LiveRead) []contracts.NodeLiveRead {
	out := make([]contracts.NodeLiveRead, len(requests))
	for n, r := range requests {
		out[n] = node.WireLiveRead(r)
	}
	return out
}
func liveBatchValues(wire []contracts.NodeLiveRead) ([]collector.LiveRead, bool) {
	if len(wire) < 1 || len(wire) > v.MaxSources {
		return nil, false
	}
	out := make([]collector.LiveRead, len(wire))
	for n, r := range wire {
		value, ok := node.DomainLiveRead(r)
		if !ok {
			return nil, false
		}
		out[n] = value
	}
	return out, validLiveBatch(out)
}
func validLiveBatch(requests []collector.LiveRead) bool {
	if len(requests) < 1 || len(requests) > v.MaxSources {
		return false
	}
	first := requests[0]
	seen := map[string]bool{}
	budget := 0
	for _, r := range requests {
		if !r.Valid() || r.Inspect || r.Root() != first.Root() || r.ClusterID != first.ClusterID || seen[r.SourceID()] || r.ReplyBytes < 1024 {
			return false
		}
		seen[r.SourceID()] = true
		budget += r.ReplyBytes
	}
	return budget <= 28<<10
}

// ReadLiveBatch is a private composed reader, not a public operation or permit.
// Current source authority and accounted owner precede dispatch. One bounded
// query uses one existing standby for all sixteen original source references.
func (t Targets) ReadLiveBatch(ctx context.Context, requests []collector.LiveRead) ([]v.NodeReply, error) {
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil || !validLiveBatch(requests) {
		return nil, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type group struct {
		indices  []int
		requests []collector.LiveRead
	}
	groups := map[[2]string]*group{}
	for n, r := range requests {
		k := [2]string{}
		if r.Manual != nil {
			k = [2]string{r.Manual.ExecutorPodUID, r.Manual.ExecutorEpoch}
		}
		g := groups[k]
		if g == nil {
			g = &group{}
			groups[k] = g
		}
		g.indices = append(g.indices, n)
		g.requests = append(g.requests, r)
	}
	out := make([]v.NodeReply, len(requests))
	errs := make(chan error, len(groups))
	var wg sync.WaitGroup
	for key, g := range groups {
		wg.Add(1)
		go func(key [2]string, g *group) {
			defer wg.Done()
			values, e := t.readLiveGroup(call, g.requests, key)
			if e != nil {
				errs <- e
				return
			}
			for n, p := range values {
				out[g.indices[n]] = p
			}
		}(key, g)
	}
	wg.Wait()
	close(errs)
	if len(errs) > 0 || call.Err() != nil {
		for n := range out {
			clear(out[n].Rows)
		}
		return nil, targets.ErrUnavailable
	}
	return out, nil
}
func (t Targets) readLiveGroup(call context.Context, requests []collector.LiveRead, owner [2]string) ([]v.NodeReply, error) {
	var wire []contracts.NodeLiveResult
	var until time.Time
	var e error
	if owner[0] == "" {
		until, e = t.Router.Query(call, requests[0].ClusterID, queryLiveProjection, liveBatchWire(requests), &wire)
	} else {
		until, e = t.Router.QueryProcess(call, requests[0].ClusterID, queryLiveProjection, liveBatchWire(requests), &wire, owner[0], owner[1])
	}
	if e != nil || call.Err() != nil || !t.Now().Before(until) || len(wire) != len(requests) {
		return nil, targets.ErrUnavailable
	}
	out := make([]v.NodeReply, len(wire))
	for n, value := range wire {
		r := requests[n]
		p, e := node.DomainLiveReply(value)
		if e == nil {
			p, e = v.BindManualLiveReply(r, p)
		}
		if e != nil || value.Epoch != r.Epoch() || p.SourceID != r.SourceID() || p.Fence != r.Fence() || p.BootID != r.Boot() || !p.Position.Follows(v.Position{Sequence: r.AfterSequence, Lost: r.AfterLost, ClockLost: r.AfterClockLost, Unsupported: r.AfterUnsupported, SensorLost: r.AfterSensorLost}) {
			return nil, targets.ErrUnavailable
		}
		if r.Manual != nil && (p.Manual == nil || !p.Manual.SameBinding(*r.Manual) || !p.Manual.StartedAt.Equal(r.Manual.StartedAt) || !p.Manual.HardUntil.Equal(r.Manual.HardUntil)) {
			return nil, targets.ErrUnavailable
		}
		if r.Manual == nil && p.Manual != nil {
			return nil, targets.ErrUnavailable
		}
		out[n] = p
	}
	return out, nil
}
