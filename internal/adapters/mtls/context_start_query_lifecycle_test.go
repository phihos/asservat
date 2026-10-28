package mtls

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// ADR-179 allows independent pre-work queries on the same passive standby.
// The first query completes under its short original caller bound. Its retained
// socket deadline must not cancel a later caller during a fresh peer check.
func TestContextStartCompletedQueryDeadlineDoesNotCancelNextQuery(t *testing.T) {
	for _, phase := range []string{"current-check", "idle-gap", "work", "history-list", "history-stream-cutoff"} {
		t.Run(phase, func(t *testing.T) { contextStartCompletedQueryLifecycle(t, phase) })
	}
}

func contextStartCompletedQueryLifecycle(t *testing.T, phase string) {
	f := newContextStartTLSFixture(t)
	controller := make(chan *http.ResponseController, 1)
	if phase == "history-stream-cutoff" {
		f.intercept = func(w http.ResponseWriter, _ *http.Request) bool {
			controller <- http.NewResponseController(w)
			return false
		}
	}
	regional := &restartRegion{regionalOperationsFixture: &regionalOperationsFixture{t: t, process: f.api}}
	f.targets = regional
	originalRoutes := f.owners.Routes
	var hold atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	f.owners.Routes = forwardRoutes(func(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
		if hold.CompareAndSwap(true, false) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return value.OwnerRoute{}, ctx.Err()
			}
		}
		return originalRoutes.CurrentOwnerRoute(ctx, b)
	})
	exchange, stream := f.open(t)
	work, signer, signed, _ := f.work(t, exchange.Receiver())
	regional.work = work
	local := contextstart.RegionalLocal{Process: regional, Targets: regional, Local: regional, Starts: regional, Output: regional, Collector: regional, Source: f.connector, Now: time.Now}
	regionalDone := make(chan struct{})
	go func() {
		defer close(regionalDone)
		_ = contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
	}()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = stream.Close()
		select {
		case <-regionalDone:
		case <-time.After(time.Second):
			t.Error("regional query owner did not join")
		}
	})
	var lastEvent string
	hub := contextstart.Targets{Router: f.router, Now: time.Now, Report: func(event, timing string) { lastEvent = event; t.Log(event, timing) }}
	first, stopFirst := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer stopFirst()
	firstUntil, _ := first.Deadline()
	resolved, err := hub.ResolveWorkload(first, targets.WorkloadRequest{ClusterID: work.Target.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"})
	if err != nil {
		t.Fatal("first query", err)
	}
	if first.Err() != nil || !time.Now().Before(firstUntil) {
		t.Fatal("first query did not complete within its original caller bound", first.Err())
	}
	// ADR-260 keeps the completed API metadata's original producer interval.
	// firstUntil still bounds the query I/O and drives the socket-cutoff checks
	// below; it does not replace the producer's first-read observation cutoff.
	if !resolved.Valid(time.Now()) || !resolved.FreshUntil.Equal(resolved.ObservedAt.Add(5*time.Second)) {
		t.Fatal("first answer changed the producer's API observation interval", resolved)
	}
	if phase == "work" {
		ctx, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		attachment, err := f.router.Attach(ctx, work.Target.ClusterID, work.CaptureID)
		if err != nil {
			t.Fatal("attach after completed query", err)
		}
		defer attachment.Close()
		if _, err = attachment.Receiver(ctx); err != nil {
			t.Fatal(err)
		}
		if !time.Now().Before(firstUntil) {
			t.Fatal("work was not admitted before completed query cutoff")
		}
		state, err := attachment.Run(work, signed, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
			time.Sleep(time.Until(firstUntil) + 20*time.Millisecond)
			return readProcessRun(ctx, ops)
		})
		if err != nil || state != "StoredPendingVerification" {
			t.Fatal("completed query cutoff interrupted independently leased work", state, err)
		}
		return
	}
	if phase == "idle-gap" {
		time.Sleep(time.Until(firstUntil) + 20*time.Millisecond)
		if exchange.Context().Err() != nil {
			t.Fatal("completed query cutoff ended the idle standby")
		}
	}
	second, stopSecond := context.WithTimeout(context.Background(), 4*time.Second)
	defer stopSecond()
	secondUntil, _ := second.Deadline()
	history := phase == "history-list" || phase == "history-stream-cutoff"
	hold.Store(phase == "current-check" || history)
	result := make(chan error, 1)
	go func() {
		var err error
		if history {
			// Actual browser discovery first resolves diagnostics, then asks
			// history for the named workload (including when scaled to zero).
			var observation targets.RestartObservation
			observation, err = hub.ObserveWorkloadRestarts(second, targets.RestartRequest{WorkloadRequest: targets.WorkloadRequest{ClusterID: work.Target.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}})
			if err == nil && (observation.Workload.UID != work.Target.WorkloadUID || len(observation.Pods) != 0) {
				err = targets.ErrUnavailable
			}
		} else {
			_, err = hub.ResolvePod(second, resolved.Request)
		}
		result <- err
	}()
	if phase == "current-check" || history {
		select {
		case <-entered:
		case err := <-result:
			t.Fatal("second query did not reach its fresh peer check", err)
		case <-time.After(time.Second):
			t.Fatal("second query peer check did not start")
		}
		if phase == "history-stream-cutoff" {
			// Induce a real HTTP/2 write cutoff while the second query owns
			// its current route check. This identifies a diagnostic boundary;
			// it does not establish why the installed stream was interrupted.
			if err := (<-controller).SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, value.ErrUnavailable) || lastEvent != "restarts/read/http2-deadline" || second.Err() != nil {
					t.Fatal("history stream cutoff was not a closed target refusal within original caller time", lastEvent, err, second.Err())
				}
			case <-second.Done():
				t.Fatal("cutoff did not cancel and join the current route read")
			}
			return
		}
		// Cross only the completed first query's bound. The current query, its
		// current proof, and the original passive residence still have time.
		timer := time.NewTimer(time.Until(firstUntil) + 20*time.Millisecond)
		defer timer.Stop()
		<-timer.C
		releaseOnce.Do(func() { close(release) })
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("completed query's deadline cancelled the next query with %s left: %v", time.Until(secondUntil).Round(time.Millisecond), err)
		}
	case <-second.Done():
		t.Fatal("second query exceeded its own original deadline")
	}
}
