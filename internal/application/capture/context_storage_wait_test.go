package capture

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

type staleStorage struct {
	reads      atomic.Int32
	freshAfter int32 // reads before the binding is fresh; 0 = never
	now        func() time.Time
}

func (s *staleStorage) ContextStorage(context.Context, authorization.Target) (ContextStorageObservation, error) {
	if n := s.reads.Add(1); s.freshAfter == 0 || n <= s.freshAfter {
		return ContextStorageObservation{}, value.ErrChanged
	}
	var v ContextStorageObservation
	v.Binding.FreshUntil = s.now().Add(3 * time.Second)
	return v, nil
}

type countingRefresh struct{ demands atomic.Int32 }

func (c *countingRefresh) DemandCapacityRefresh(context.Context, targets.Request) error {
	c.demands.Add(1)
	return nil
}

// ADR-200: a stale binding records one demand and waits for the refresh;
// a refresh that never comes ends at the caller's original deadline.
func TestContextInvestigationAwaitsRefreshedStorage(t *testing.T) {
	for _, freshAfter := range []int32{2, 0} {
		storage := &staleStorage{freshAfter: freshAfter, now: time.Now}
		refresh := &countingRefresh{}
		s := ContextInvestigation{Storage: storage, Refresh: refresh, Now: time.Now}
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		started := time.Now()
		s.awaitStorage(ctx, targets.PodResolution{})
		elapsed := time.Since(started)
		cancel()
		if refresh.demands.Load() != 1 {
			t.Fatal("demands", freshAfter, refresh.demands.Load())
		}
		if freshAfter > 0 && (storage.reads.Load() != freshAfter+1 || elapsed > time.Second) {
			t.Fatal("did not stop at the fresh read", storage.reads.Load(), elapsed)
		}
		if freshAfter == 0 && elapsed < 1400*time.Millisecond {
			t.Fatal("returned before the original deadline", elapsed)
		}
	}
}
