package evidence

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

type independentStops struct {
	*stopFixture
	rows                             []DownloadStopSnapshot
	claimed, attempted, acknowledged []string
}

func (f *independentStops) PendingDownloadStops(context.Context) ([]DownloadStopSnapshot, error) {
	return f.rows, nil
}
func (f *independentStops) ClaimDownloadStopWrite(_ context.Context, d artifact.DownloadStopDecision) (bool, error) {
	f.claimed = append(f.claimed, d.DownloadID)
	return true, nil
}
func (f *independentStops) CreateDownloadStop(_ context.Context, d artifact.DownloadStopDecision) (audit.Receipt, error) {
	f.attempted = append(f.attempted, d.DownloadID)
	if d.DownloadID == f.rows[0].Decision.DownloadID {
		return audit.Receipt{}, artifact.ErrDownloadUnavailable
	}
	r := f.receipt()
	r.Key = artifact.DownloadStopKey(d.RootID, d.DownloadID)
	return r, nil
}
func (f *independentStops) AcknowledgeDownloadStop(_ context.Context, d artifact.DownloadStopDecision, _ audit.Receipt) error {
	f.acknowledged = append(f.acknowledged, d.DownloadID)
	return nil
}
func TestPendingStopFailureDoesNotStarveAnotherPrepaidObligation(t *testing.T) {
	base, _ := newStopFixture(t)
	second := base.snapshot
	second.Decision.DownloadID = "99999999-9999-4999-8999-999999999999"
	f := &independentStops{stopFixture: base, rows: []DownloadStopSnapshot{base.snapshot, second}}
	s := ContextDownloadStopCoordinator{Ledger: f, Acknowledgements: f, Objects: f, Now: time.Now}
	e := s.ReconcilePending(t.Context(), f)
	if e == nil || len(f.claimed) != 2 || len(f.attempted) != 2 || len(f.acknowledged) != 1 || f.acknowledged[0] != second.Decision.DownloadID {
		t.Fatal("earliest failed Stop starved an independent obligation", e, f.claimed, f.attempted, f.acknowledged)
	}
}
func TestPendingStopCancellationDoesNotStartAnotherClaim(t *testing.T) {
	base, _ := newStopFixture(t)
	f := &independentStops{stopFixture: base, rows: []DownloadStopSnapshot{base.snapshot}}
	s := ContextDownloadStopCoordinator{Ledger: f, Acknowledgements: f, Objects: f, Now: time.Now}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := s.ReconcilePending(ctx, f); e == nil || len(f.claimed) != 0 {
		t.Fatal("canceled pass admitted work", e, f.claimed)
	}
}
