package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A response-only admission observation may be consumed, but the persisted
// first-write RequestUntil remains an actual effect cutoff. Exercise the real
// publisher with a live caller and a completed-read that consumes the final
// microsecond before the first PUT; no metadata or later write lease revives it.
func TestCaptureOperationPhaseSeparationKeepsOriginalFirstWriteCutoff(t *testing.T) {
	s, f, in := capturePublisher(t)
	f.now = in.RequestUntil.Add(-time.Microsecond)
	f.afterPassive = func() { f.now = in.RequestUntil }
	ctx, cancel := context.WithDeadline(context.Background(), in.WriteUntil)
	defer cancel()
	if _, err := s.AcknowledgedCaptureIntent(ctx, in.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired original first-write bound accepted", err)
	}
	if f.writes != 0 || f.paired != 0 || f.snap.Outcome != nil || ctx.Err() != nil {
		t.Fatal("first-write expiry caused effects or consumed caller lifetime", f.writes, f.paired, ctx.Err())
	}
	if !f.snap.Intent.RequestUntil.Equal(in.RequestUntil) || !f.snap.Intent.WriteUntil.Equal(in.WriteUntil) {
		t.Fatal("original audit cutoffs changed")
	}
}
