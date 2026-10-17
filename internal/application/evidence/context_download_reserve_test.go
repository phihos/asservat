package evidence

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
)

type refusingSessions struct {
	ContextDownloadControlLedger
	failures int32 // refusals before success; -1 refuses forever
	err      error
	calls    atomic.Int32
}

func (s *refusingSessions) ReserveDownload(context.Context, DownloadReservation) (artifact.DownloadSession, error) {
	if n := s.calls.Add(1); s.failures < 0 || n <= s.failures {
		return artifact.DownloadSession{}, s.err
	}
	return artifact.DownloadSession{ID: "reserved"}, nil
}

type countingDownloadRefresh struct{ calls atomic.Int32 }

func (c *countingDownloadRefresh) DemandDownloadRefresh(context.Context, string) error {
	c.calls.Add(1)
	return nil
}

// ADR-200: a stale-binding refusal re-arms the demand once and is retried
// within the original deadline; any other refusal returns at once.
func TestContextDownloadReserveRetriesStaleBindingWithinDeadline(t *testing.T) {
	for _, c := range []struct {
		name      string
		failures  int32
		err       error
		reserved  bool
		demands   int32
		minCalls  int32
		atLeastMs int64
	}{
		{"refreshed in time", 2, privacy.ErrUnavailable, true, 1, 3, 0},
		{"permanent refusal", 1, artifact.ErrInvalid, false, 0, 1, 0},
		{"never refreshed", -1, privacy.ErrUnavailable, false, 1, 2, 750},
	} {
		t.Run(c.name, func(t *testing.T) {
			sessions := &refusingSessions{failures: c.failures, err: c.err}
			refresh := &countingDownloadRefresh{}
			s := ContextDownloadCoordinator{Sessions: sessions, Refresh: refresh}
			ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
			defer cancel()
			started := time.Now()
			session, err := s.reserve(ctx, DownloadReservation{Session: artifact.DownloadSession{AllocationID: "00000000-0000-4000-8000-000000000001"}})
			if (err == nil) != c.reserved || c.reserved && session.ID != "reserved" || !c.reserved && !errors.Is(err, c.err) {
				t.Fatal("result", session, err)
			}
			if refresh.calls.Load() != c.demands || sessions.calls.Load() < c.minCalls || time.Since(started).Milliseconds() < c.atLeastMs {
				t.Fatal("demands", refresh.calls.Load(), "reservations", sessions.calls.Load(), time.Since(started))
			}
		})
	}
}
