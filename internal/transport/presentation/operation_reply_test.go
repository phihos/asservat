package presentation

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/audit"
)

func ownedReplyFixture(t *testing.T, ctx context.Context, guard *replyGuardFixture, cleanup time.Time) OperationReply {
	t.Helper()
	until, _ := ctx.Deadline()
	r, e := ownOperationReply(ctx, OperationReply{Body: []byte("prepared output"), ValidUntil: until}, guard, cleanup, func(context.Context, audit.OperationOutcome) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = r.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(r.Body)), MetadataUntil: until}); e != nil {
		t.Fatal(e)
	}
	return r
}

func TestOperationReplyCleanupSurvivesExpiredPublicRequest(t *testing.T) {
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		cleanup := time.Now().Add(time.Second)
		g := &replyGuardFixture{close: func(c context.Context) error {
			d, ok := c.Deadline()
			if !ok || !d.Equal(cleanup) || c.Err() != nil || !time.Now().Before(d) {
				return errors.New("cleanup inherited public expiry")
			}
			return nil
		}}
		r := ownedReplyFixture(t, ctx, g, cleanup)
		if expired {
			<-ctx.Done()
		} else {
			cancel()
		}
		if err := r.Close(ctx); err != nil || g.closes.Load() != 1 {
			t.Fatal("cleanup skipped", expired, err)
		}
		cancel()
	}
}

func TestOperationReplyCanceledCloseWaiterDoesNotClaimJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered, join := make(chan struct{}), make(chan struct{})
	g := &replyGuardFixture{close: func(context.Context) error { close(entered); <-join; return errors.New("remote closure uncertain") }}
	r := ownedReplyFixture(t, ctx, g, time.Now().Add(time.Second))
	done := make(chan error, 2)
	go func() { done <- r.Close(ctx) }()
	<-entered
	wait, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	go func() { done <- r.Close(wait) }()
	select {
	case <-done:
		t.Fatal("unjoined cleanup reported completion")
	case <-time.After(10 * time.Millisecond):
	}
	close(join)
	for range 2 {
		if <-done == nil {
			t.Fatal("uncertain closure became success")
		}
	}
	if g.closes.Load() != 1 || !bytes.Equal(r.Body, make([]byte, len(r.Body))) {
		t.Fatal("cleanup was replayed or bytes retained")
	}
}

func TestOperationReplyCloseCancelsAndJoinsDisclosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{})
	g := &replyGuardFixture{check: func(c context.Context) error { close(entered); <-c.Done(); return c.Err() }}
	r := ownedReplyFixture(t, ctx, g, time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- r.CheckDisclosure(ctx) }()
	<-entered
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if <-done == nil || g.closes.Load() != 1 {
		t.Fatal("close did not join disclosure")
	}
}

func TestOperationReplyRejectsMutationAndExpiredCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	g := &replyGuardFixture{}
	r := ownedReplyFixture(t, ctx, g, time.Now().Add(time.Second))
	r.Body[0] = 'x'
	if r.CheckDisclosure(ctx) == nil || g.checks.Load() != 0 {
		t.Fatal("mutated audited output disclosed")
	}
	_ = r.Close(ctx)
	// An expired prepaid cutoff is never turned into a positive joined result,
	// even if a broken adapter returns nil without inspecting its context.
	r = ownedReplyFixture(t, ctx, &replyGuardFixture{close: func(context.Context) error { return nil }}, time.Now().Add(time.Second))
	r.boundCleanup(time.Now().Add(-time.Second))
	if r.Close(ctx) == nil {
		t.Fatal("expired cleanup reported joined")
	}
}
