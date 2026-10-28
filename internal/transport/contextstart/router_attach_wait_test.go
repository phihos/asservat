package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
)

// Real framing and joined handler/socket lifetime, synthetic peer and effect
// authority. Each read consumes its conversation; the next read needs a fresh
// registration, never replay of the previous work.
func TestHistoryAttachmentWaitsAfterJoinedExchange(t *testing.T) {
	w, receiver, bundle, copies := historyFixture()
	cluster := receiver.Channel.Connector.Binding.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	effects := 0
	run := func(a *Attachment, ctx context.Context, r fleet.APIContextReceiver, standby *Standby) {
		t.Helper()
		deadline, _ := ctx.Deadline()
		actual, err := a.ctx.Deadline()
		if !err || !actual.Equal(deadline) {
			t.Fatal("attachment renewed original deadline")
		}
		work := w
		work.Channel = r.Channel
		work.Authority.Operation = "read"
		work.Authority.BundleDigest = artifact.Digest{}
		work.Authority.CopiesDigest = capture.HistoryCopiesDigest(copies)
		work.Authority.NotAfter = deadline
		hub, region := historyStreamPair(t, t.Context(), r)
		joined := make(chan struct{})
		go func() { defer close(joined); _ = standby.Serve(hub, time.Now); _ = hub.Close(); standby.Finish() }()
		local := &HistoryLocal{Verifier: historyVerifierFunc(func(context.Context, []byte, fleet.APIContextReceiver) (fleetapp.AuthenticatedHistoryWork, error) {
			return fleetapp.AuthenticatedHistoryWork{Work: work, KeyID: "synthetic", TrustRevision: workFixture().TrustRevision, VerifiedAt: work.Authority.StartedAt, ValidUntil: deadline}, nil
		}), Effects: historyEffectsFunc(func(context.Context, capture.HistoryOperationAuthority, capture.HistoryCiphertexts, artifact.Copies) (fleetapp.HistoryReply, error) {
			effects++
			return fleetapp.HistoryReply{Copies: copies, Bundle: bundle}, nil
		})}
		regional := make(chan error, 1)
		go func() {
			frame, current, e := region.AwaitWork(ctx)
			if e == nil && frame.Kind == contracts.HistoryWorkFrame {
				e = serveRegionalHistory(ctx, region, current, frame.Payload, local, time.Now)
			}
			clear(frame.Payload)
			regional <- e
		}()
		reply, e := a.RunHistory(ctx, work, []byte("synthetic signature"), capture.HistoryCiphertexts{}, copies)
		reply.Bundle.Clear()
		regionalErr := <-regional
		a.Close()
		<-joined
		if e != nil || regionalErr != nil {
			t.Fatal("history exchange", e, regionalErr)
		}
	}
	register := func(exchange string) (fleet.APIContextReceiver, *Standby) {
		t.Helper()
		r := receiver
		r.Channel.ExchangeID = exchange
		r.ObservedAt = time.Now()
		r.ValidUntil = r.ObservedAt.Add(5 * time.Second)
		s, e := router.RegisterStandby(t.Context(), r, func(context.Context) (fleet.APIContextReceiver, error) { return r, nil })
		if e != nil {
			t.Fatal(e)
		}
		return r, s
	}
	first, s := register(receiver.Channel.ExchangeID)
	ctx, cancel := context.WithTimeout(t.Context(), 4500*time.Millisecond)
	defer cancel()
	a, err := router.Attach(ctx, cluster, w.Authority.Expectation.CaptureID)
	if err != nil {
		t.Fatal(err)
	}
	run(a, ctx, first, s)
	nextCtx, end := context.WithTimeout(t.Context(), 4500*time.Millisecond)
	defer end()
	type result struct {
		a   *Attachment
		err error
	}
	waiting := make(chan result, 1)
	go func() {
		a, e := router.Attach(nextCtx, cluster, w.Authority.Expectation.CaptureID)
		waiting <- result{a, e}
	}()
	select {
	case early := <-waiting:
		t.Fatalf("next history read refused before fresh registration: %v", early.err)
	case <-time.After(150 * time.Millisecond):
	}
	second, next := register("00000000-0000-4000-8000-000000000098")
	defer next.Finish()
	got := <-waiting
	if got.err != nil {
		t.Fatal(got.err)
	}
	run(got.a, nextCtx, second, next)
	if effects != 2 {
		t.Fatal("history work was lost or replayed", effects)
	}
}

func TestRouterAttachmentWaitPreservesRefusals(t *testing.T) {
	w, r, _, _ := historyFixture()
	cluster := r.Channel.Connector.Binding.ClusterID
	router, e := NewRouter(RouterLimits{Standby: 2, Captures: 2, Clusters: []ClusterLimit{{cluster, 2, 2}}})
	if e != nil {
		t.Fatal(e)
	}
	defer router.Close()
	immediate := func(ctx context.Context, capture string, want error) {
		t.Helper()
		began := time.Now()
		a, e := router.Attach(ctx, cluster, capture)
		if a != nil || !errors.Is(e, want) || time.Since(began) > 100*time.Millisecond {
			t.Fatalf("expected immediate %v, got %v in %s", want, e, time.Since(began))
		}
	}
	short, end := context.WithTimeout(t.Context(), time.Second)
	defer end()
	immediate(short, w.Authority.Expectation.CaptureID, fleet.ErrUnavailable)
	immediate(t.Context(), w.Authority.Expectation.CaptureID, fleet.ErrInvalid)
	ctx, cancel := context.WithTimeout(t.Context(), 4500*time.Millisecond)
	defer cancel()
	immediate(ctx, "bad-id", fleet.ErrInvalid)
	s, e := router.RegisterStandby(t.Context(), r, func(context.Context) (fleet.APIContextReceiver, error) { return r, nil })
	if e != nil {
		t.Fatal(e)
	}
	a, e := router.Attach(ctx, cluster, w.Authority.Expectation.CaptureID)
	if e != nil {
		t.Fatal(e)
	}
	immediate(ctx, w.Authority.Expectation.CaptureID, fleet.ErrCapacity)
	// Fill both real reservations, keeping duplicate refusal separate from cap.
	secondReceiver := r
	secondReceiver.Channel.ExchangeID = "00000000-0000-4000-8000-000000000097"
	second, e := router.RegisterStandby(t.Context(), secondReceiver, func(context.Context) (fleet.APIContextReceiver, error) { return secondReceiver, nil })
	if e != nil {
		t.Fatal(e)
	}
	other, e := router.Attach(ctx, cluster, "00000000-0000-4000-8000-000000000098")
	if e != nil {
		t.Fatal(e)
	}
	immediate(ctx, "00000000-0000-4000-8000-000000000099", fleet.ErrCapacity)
	s.Finish()
	a.Close()
	second.Finish()
	other.Close()
	// A missing replacement exhausts only the original wait allowance, leaving
	// the full query reserve and no capture reservation behind.
	tail, endTail := context.WithTimeout(t.Context(), queryReserve+150*time.Millisecond)
	began := time.Now()
	_, e = router.Attach(tail, cluster, w.Authority.Expectation.CaptureID)
	elapsed := time.Since(began)
	deadline, _ := tail.Deadline()
	endTail()
	if !errors.Is(e, fleet.ErrUnavailable) || elapsed < 100*time.Millisecond || elapsed > 500*time.Millisecond || time.Until(deadline) < 2*time.Second {
		t.Fatal("wait consumed query reserve", e, elapsed)
	}
	waitCtx, stop := context.WithTimeout(t.Context(), 4500*time.Millisecond)
	done := make(chan error, 1)
	go func() { _, e := router.Attach(waitCtx, cluster, w.Authority.Expectation.CaptureID); done <- e }()
	select {
	case e := <-done:
		t.Fatal("did not wait", e)
	case <-time.After(50 * time.Millisecond):
	}
	stop()
	select {
	case e := <-done:
		if !errors.Is(e, fleet.ErrUnavailable) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join")
	}
	router.mu.Lock()
	count := len(router.captures)
	router.mu.Unlock()
	if count != 0 {
		t.Fatal("wait reserved capture", count)
	}
}
