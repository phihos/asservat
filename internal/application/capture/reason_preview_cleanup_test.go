package capture

import (
	"context"
	"errors"
	"testing"
	"time"
)

type reasonPreviewCleanup struct {
	calls int
	until time.Time
	fail  bool
}

func (p *reasonPreviewCleanup) DeleteExpiredContextPreviews(ctx context.Context) (int64, error) {
	p.calls++
	p.until, _ = ctx.Deadline()
	if p.fail {
		return 0, errors.New("synthetic failed cleanup")
	}
	return 1000, nil
}
func TestReasonPreviewCleanupIndependentOfHistoryAndPaced(t *testing.T) {
	now := time.Now()
	f := &reasonPreviewCleanup{fail: true}
	s := HistoryParameterService{PreviewCleanup: f}
	if s.configured() {
		t.Fatal("test needs unavailable history dependencies")
	}
	ctx, end := context.WithDeadline(context.Background(), now.Add(2*time.Second))
	defer end()
	next, err := s.cleanupExpiredPreviews(ctx, time.Time{}, now)
	if err == nil || f.calls != 1 || f.until.After(now.Add(2*time.Second)) || !next.Equal(now.Add(30*time.Second)) {
		t.Fatal("cleanup needs original caller bound and finite pacing", err)
	}
	if _, err = s.cleanupExpiredPreviews(ctx, next, now.Add(29*time.Second)); err != nil || f.calls != 1 {
		t.Fatal("failure retried without existing30s spacing")
	}
	if _, err = s.cleanupExpiredPreviews(ctx, next, next); err == nil || f.calls != 2 {
		t.Fatal("cleanup failure incorrectly disabled later expiry work")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.Run(cancelled, nil); err != nil {
		t.Fatal("unavailable history prevented owning cleanup lifecycle", err)
	}
}
