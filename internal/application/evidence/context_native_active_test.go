package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

func TestNativeContentStopKeepsSlotsUntilJoinedAndDoesNotCrossPrincipal(t *testing.T) {
	a := newContextNativeTransfers()
	p := identity.Principal{Issuer: "https://issuer.test", Subject: "owner", ClientID: "browser", Kind: identity.Human}
	other := p
	other.Subject = "other"
	c1, r1, e := a.begin(t.Context(), "session", p)
	if e != nil {
		t.Fatal(e)
	}
	c2, r2, e := a.begin(t.Context(), "session", p)
	if e != nil {
		t.Fatal(e)
	}
	c3, r3, e := a.begin(t.Context(), "session", other)
	if e != nil {
		t.Fatal(e)
	}
	defer r3()
	stop, end := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer end()
	done := make(chan error, 1)
	go func() { done <- a.cancel(stop, "session", p) }()
	<-c1.Done()
	<-c2.Done()
	if c3.Err() != nil {
		t.Fatal("another actor cancelled")
	}
	a.mu.Lock()
	retained := len(a.live)
	a.mu.Unlock()
	if retained != 3 {
		t.Fatal("cancel released unjoined registrations")
	}
	r1()
	if e := <-done; e == nil {
		t.Fatal("blocked close reported joined")
	}
	a.mu.Lock()
	retained = len(a.live)
	a.mu.Unlock()
	if retained != 2 {
		t.Fatal("timeout released unknown work")
	}
	r2()
	if e := a.cancel(t.Context(), "session", p); e != nil {
		t.Fatal(e)
	}
	// Late registration after a restrictive decision does not inherit a sticky
	// permission. It must still pass SQL; registration itself makes no claim.
	late, release, e := a.begin(t.Context(), "session", p)
	if e != nil {
		t.Fatal(e)
	}
	if late.Err() != nil {
		t.Fatal("registration invented a durable SQL decision")
	}
	release()
}
func TestNativeContentRegistryCloseJoinsAndCannotReuseUnjoinedCapacity(t *testing.T) {
	a := newContextNativeTransfers()
	p := identity.Principal{Issuer: "https://issuer.test", Subject: "owner", ClientID: "browser", Kind: identity.Human}
	var releases []func()
	var calls []context.Context
	for range 16 {
		ctx, r, e := a.begin(t.Context(), "session", p)
		if e != nil {
			t.Fatal(e)
		}
		releases = append(releases, r)
		calls = append(calls, ctx)
	}
	if _, _, e := a.begin(t.Context(), "session", p); e == nil {
		t.Fatal("unbounded registrations")
	}
	closed := make(chan struct{})
	go func() { a.close(); close(closed) }()
	for _, ctx := range calls {
		<-ctx.Done()
	}
	select {
	case <-closed:
		t.Fatal("runtime close skipped joins")
	default:
	}
	for _, r := range releases {
		r()
	}
	<-closed
	if _, _, e := a.begin(t.Context(), "session", p); e == nil {
		t.Fatal("closed runtime reused")
	}
}

type stopActiveOrder struct {
	f     *stopFixture
	fail  bool
	calls int
}

func (a *stopActiveOrder) CancelDownloadTransfers(ctx context.Context, d artifact.DownloadStopDecision) error {
	a.calls++
	if a.f.stops != 1 || a.f.creates != 0 || d != a.f.snapshot.Decision {
		return artifact.ErrIntegrity
	}
	if a.fail {
		return artifact.ErrDownloadUnavailable
	}
	return ctx.Err()
}
func TestNativeContentStopRestrictionBeforeJoinedCancellationBeforeAudit(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f, s := newStopFixture(t)
		active := &stopActiveOrder{f: f, fail: fail}
		s.Active = active
		d := f.snapshot.Decision
		out, e := s.CancelContextDownload(t.Context(), f, d.DownloadID, "same-key", d.RequestID)
		if active.calls != 1 || f.stops != 1 {
			t.Fatal("stop boundary not executed")
		}
		if fail {
			if e == nil || out.DownloadID != "" || f.creates != 0 || f.acks != 0 {
				t.Fatal("unjoined cancellation claimed completion")
			}
		} else if e != nil || f.creates != 1 || f.acks != 1 {
			t.Fatal("joined cancellation skipped audit", e)
		}
	}
}
