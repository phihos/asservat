package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/fleet"
)

func TestRouterQueryExcludesAttachmentUntilJoinedResult(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
	standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{})
		done <- e
	}()
	var job *queryJob
	select {
	case job = <-standby.query:
	case <-ctx.Done():
		t.Fatal("query was not dispatched")
	}
	// Cancellation after handoff must retain exclusive ownership until the
	// actual query has joined, including its frame cancellation callbacks.
	cancel()
	select {
	case <-done:
		t.Fatal("cancelled query returned before joined result")
	default:
	}
	attachCtx, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	attachment, err := router.Attach(attachCtx, cluster, w.Work.CaptureID)
	if attachment != nil {
		defer func() { standby.Finish(); attachment.Close() }()
	}
	if !errors.Is(err, fleet.ErrUnavailable) {
		t.Error("attachment selected an in-flight query", err)
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, e := router.Query(short, cluster, queryResolvePod, struct{}{}, &struct{}{}); !errors.Is(e, fleet.ErrUnavailable) || short.Err() != context.DeadlineExceeded {
		t.Error("busy query did not respect its own deadline", e)
	}
	stop()
	job.result <- queryResult{until: receiver.Window.Until()}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterWaitingQueryWakesWhenJoinedQueryReleasesStandby(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
	standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	query := func(done chan error) {
		_, e := router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{})
		done <- e
	}
	go query(firstDone)
	first := <-standby.query
	go query(secondDone)
	select {
	case second := <-standby.query:
		second.result <- queryResult{err: fleet.ErrUnavailable}
		first.result <- queryResult{err: fleet.ErrUnavailable}
		<-firstDone
		<-secondDone
		t.Fatal("second query dispatched before first joined")
	case err := <-secondDone:
		first.result <- queryResult{err: fleet.ErrUnavailable}
		<-firstDone
		t.Fatal("second query did not wait for availability", err)
	case <-time.After(30 * time.Millisecond):
	}
	first.result <- queryResult{until: receiver.Window.Until()}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-standby.query:
		second.result <- queryResult{until: receiver.Window.Until()}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("released standby did not wake waiting query")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if standby.queryBusy {
		t.Fatal("joined queries retained busy")
	}
}

func TestRouterCancellationBeforeHandoffReleasesBusyWithoutRefund(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
	standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	// No Serve receives this handoff. Only the waiting caller can release it.
	if _, err := router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{}); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal(err)
	}
	router.mu.Lock()
	busy := standby.queryBusy
	router.mu.Unlock()
	if busy {
		t.Fatal("cancelled handoff retained busy")
	}
	attachCtx, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	attachment, err := router.Attach(attachCtx, cluster, w.Work.CaptureID)
	if err != nil {
		t.Fatal("cancelled handoff blocked subsequent attachment", err)
	}
	standby.Finish()
	attachment.Close()
}

func TestRouterTerminalQueryWithdrawnBeforeJoinedResult(t *testing.T) {
	f := newRouterStreamFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The fixture has no source feed: query returns before doing any I/O.
	// Keep socket cleanup blocked to expose result-publication ordering.
	_, err := f.router.Query(ctx, f.receiver.Channel.Connector.Binding.ClusterID, queryResolvePod, struct{}{}, &struct{}{})
	if err == nil {
		t.Fatal("invalid query unexpectedly succeeded")
	}
	f.router.mu.Lock()
	live, busy := f.standby.liveLocked(), f.standby.queryBusy
	f.router.mu.Unlock()
	if live || busy {
		t.Fatal("terminal query published a reusable standby", live, busy)
	}
	select {
	case <-f.handled:
		t.Fatal("terminal query released socket capacity before joined cleanup")
	default:
	}
}

func TestRouterReusesSingleConnectorSlotForSequentialQueries(t *testing.T) {
	w := workFixture().Work
	cluster := w.Channel.Connector.Binding.ClusterID
	router, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	defer router.Close()
	receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(time.Now(), identity.Recheck)}
	s, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Finish()
	ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-s.query:
				j.result <- queryResult{until: time.Now().Add(time.Second)}
			}
		}
	}()
	for n := 1; n <= 24; n++ {
		if _, err := router.Query(ctx, cluster, queryResolvePod, nil, nil); err != nil {
			t.Fatalf("query %d on original exchange: %v", n, err)
		}
	}
}

// History attaches to an exchange that covers ordinary work and narrows to
// its remaining residency (installed run 41525755470).
func TestRouterAttachHistoryNarrowsToAnAgedStandby(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	// Twelve seconds of residency: idle and not retired (it covers a
	// five-second work plus the margin), but short of ten plus the margin.
	residence, endResidence := context.WithTimeout(context.Background(), 12*time.Second)
	defer endResidence()
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
	standby, err := router.RegisterStandby(residence, receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	call, end := context.WithTimeout(context.Background(), HistoryAttachLimit)
	defer end()
	a, err := router.AttachHistory(call, cluster, w.Work.CaptureID)
	if err != nil || a == nil {
		t.Fatal("try attach refused an idle standby that covers ordinary work", err)
	}
	limit, _ := standby.Context().Deadline()
	if d, ok := a.ctx.Deadline(); !ok || d.After(limit.Add(-standbyMargin)) {
		t.Fatal("attachment outlives its standby's residency margin", d, limit)
	}
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	standby.Finish()
	<-closed
}
