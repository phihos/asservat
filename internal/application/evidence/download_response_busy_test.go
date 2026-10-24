package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	identityvalue "asservat.local/asservat/internal/domain/identity"
)

type busyReader struct {
	busy  int // BeginBatch calls answering Busy; negative means always
	calls int
}

type busyBatch struct{ identities.CurrentIdentity }

func (busyBatch) Close() {}

func (r *busyReader) BeginBatch(context.Context) (identities.IdentityBatch, error) {
	r.calls++
	if r.busy < 0 || r.calls <= r.busy {
		return nil, identityvalue.ErrSessionBusy
	}
	return busyBatch{}, nil
}
func (r *busyReader) Close() {}

func TestResponseBeginContinuesAfterBriefSessionBusy(t *testing.T) {
	r := &busyReader{busy: 3}
	c := responseCurrent{reader: r, now: time.Now}
	b, e := c.begin(t.Context())
	if e != nil || b == nil || r.calls != 4 {
		t.Fatal("busy-then-current session did not continue", e, r.calls)
	}
}

func TestResponseBeginFailsClosedWhenSessionStaysBusy(t *testing.T) {
	r := &busyReader{busy: -1}
	c := responseCurrent{reader: r, now: time.Now}
	start := time.Now()
	b, e := c.begin(t.Context())
	elapsed := time.Since(start)
	if b != nil || !errors.Is(e, identityvalue.ErrSessionBusy) || elapsed < sessionBusyWait || elapsed > sessionBusyWait+time.Second {
		t.Fatal("persistently busy session was not refused within the bound", e, elapsed)
	}
	// The original deadline wins over the busy bound.
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start = time.Now()
	if _, e = c.begin(ctx); !errors.Is(e, identityvalue.ErrSessionBusy) || time.Since(start) > time.Second {
		t.Fatal("busy wait outlived the original deadline", e, time.Since(start))
	}
}

func TestResponseBeginDoesNotRetryDenial(t *testing.T) {
	c := responseCurrent{reader: deniedReader{}, now: time.Now}
	if _, e := c.begin(t.Context()); !errors.Is(e, identityvalue.ErrDenied) {
		t.Fatal(e)
	}
}

type deniedReader struct{}

func (deniedReader) BeginBatch(context.Context) (identities.IdentityBatch, error) {
	return nil, identityvalue.ErrDenied
}
func (deniedReader) Close() {}
