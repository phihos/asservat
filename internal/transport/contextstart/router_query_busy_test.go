package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestRouterQueryExcludesAttachmentUntilJoinedResult(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
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
	short, stop := context.WithTimeout(context.Background(), time.Second)
	started := time.Now()
	if _, e := router.Query(short, cluster, queryResolvePod, struct{}{}, &struct{}{}); !errors.Is(e, fleet.ErrUnavailable) || time.Since(started) > 100*time.Millisecond {
		t.Error("busy query did not preserve execution reserve", e, time.Since(started))
	}
	stop()
	router.mu.Lock()
	queries := standby.queries
	router.mu.Unlock()
	if queries != 1 {
		t.Error("another query reserved the busy standby", queries)
	}
	job.result <- queryResult{until: receiver.ValidUntil}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterWaitingQueryWakesWhenJoinedQueryReleasesStandby(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
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
	router.mu.Lock()
	spent := standby.queries
	router.mu.Unlock()
	if spent != 1 {
		t.Error("busy standby consumed another query count", spent)
	}
	first.result <- queryResult{until: receiver.ValidUntil}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-standby.query:
		second.result <- queryResult{until: receiver.ValidUntil}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("released standby did not wake waiting query")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if standby.queryBusy || standby.queries != 2 {
		t.Fatal("joined queries retained busy or refunded count", standby.queryBusy, standby.queries)
	}
}

func TestRouterCancellationBeforeHandoffReleasesBusyWithoutRefund(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
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
	busy, spent := standby.queryBusy, standby.queries
	router.mu.Unlock()
	if busy || spent != 1 {
		t.Fatal("cancelled handoff retained busy or refunded count", busy, spent)
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
	live, busy, spent := f.standby.liveLocked(), f.standby.queryBusy, f.standby.queries
	f.router.mu.Unlock()
	if live || busy || spent != 1 {
		t.Fatal("terminal query published a reusable standby", live, busy, spent)
	}
	select {
	case <-f.handled:
		t.Fatal("terminal query released socket capacity before joined cleanup")
	default:
	}
}

// ADR-270 source work spends queries every tick. A standby whose last query
// completed is retired while its cluster has another standby, so the region
// opens a queryable replacement; a lone one stays for an attach (ADR-179).
func TestRouterRetiresExhaustedStandbyOnlyWithAnother(t *testing.T) {
	for _, c := range []struct{ last, other bool }{{false, true}, {true, false}, {true, true}} {
		w := workFixture()
		cluster := w.Work.Target.ClusterID
		router, err := NewRouter(RouterLimits{Standby: 2, Captures: 1, Clusters: []ClusterLimit{{cluster, 2, 1}}})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		register := func(exchange string) *Standby {
			channel := w.Work.Channel
			channel.ExchangeID = exchange
			receiver := fleet.APIContextReceiver{Channel: channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			s, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		var other *Standby
		if c.other {
			other = register("00000000-0000-4000-8000-000000000099")
		}
		// Registered last, so the query selects it.
		standby := register(w.Work.Channel.ExchangeID)
		if c.last {
			router.mu.Lock()
			standby.queries = contracts.APIContextMaximumQueries - 1
			router.mu.Unlock()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		done := make(chan error, 1)
		go func() {
			_, e := router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{})
			done <- e
		}()
		(<-standby.query).result <- queryResult{until: now.Add(5 * time.Second)}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		cancel()
		if retired := standby.ctx.Err() != nil; retired != (c.last && c.other) {
			t.Fatal("exhausted standby retirement", c, retired)
		}
		standby.Finish()
		other.Finish()
		router.Close()
	}
}

// TryAttach never waits: without an idle standby it fails at once.
func TestRouterTryAttachDoesNotWait(t *testing.T) {
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := router.TryAttach(ctx, cluster, w.Work.CaptureID); !errors.Is(err, fleet.ErrUnavailable) || time.Since(started) > 100*time.Millisecond {
		t.Fatal("try attach waited or succeeded without a standby", err, time.Since(started))
	}
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	call, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if a, err := router.TryAttach(call, cluster, w.Work.CaptureID); err != nil || a == nil {
		t.Fatal("try attach refused an idle standby", err)
	}
}
