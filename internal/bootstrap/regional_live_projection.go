package bootstrap

import (
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"sync"
)

// ReadLiveProjection passes an already authorized exact-source request through
// the existing node registry. This method has no arm/renew/snapshot interface.
func (t reportedTargets) ReadLiveProjections(ctx context.Context, requests []collector.LiveRead) ([]v.NodeReply, error) {
	if ctx == nil || ctx.Err() != nil || len(requests) < 1 || len(requests) > v.MaxSources || t.recordings == nil {
		return nil, targets.ErrUnavailable
	}
	reader, ok := t.recordings.nodes.(liveNodeReader)
	if !ok {
		return nil, targets.ErrUnsupported
	}
	for _, r := range requests {
		if !r.Valid() {
			return nil, targets.ErrInvalid
		}
	}
	out := make([]v.NodeReply, len(requests))
	errs := make([]error, len(requests))
	var wg sync.WaitGroup
	for n, r := range requests {
		wg.Add(1)
		go func(n int, r collector.LiveRead) {
			defer wg.Done()
			var held *heldRecording
			if r.Manual != nil {
				t.recordings.mu.Lock()
				var valid bool
				held, valid = t.recordings.manualReadHolderLocked(r)
				t.recordings.mu.Unlock()
				if !valid {
					errs[n] = targets.ErrUnavailable
					return
				}
			}
			out[n], errs[n] = reader.ReadLive(ctx, r)
			if r.Manual != nil {
				t.recordings.mu.Lock()
				again, valid := t.recordings.manualReadHolderLocked(r)
				t.recordings.mu.Unlock()
				if !valid || again != held {
					clear(out[n].Rows)
					out[n] = v.NodeReply{}
					errs[n] = targets.ErrUnavailable
				}
			}
		}(n, r)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			for n := range out {
				clear(out[n].Rows)
			}
			return nil, targets.ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		for n := range out {
			clear(out[n].Rows)
		}
		return nil, ctx.Err()
	}
	return out, nil
}
