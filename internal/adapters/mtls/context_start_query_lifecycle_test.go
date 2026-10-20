package mtls

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// The hub's HTTP/2 write deadline is an active stream timer, even when the
// handler is idle. This differs from the region's raw socket write deadline.
func TestContextStartHTTP2WriteDeadlineEndsIdleStream(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Error(err)
			return
		}
		w.WriteHeader(http.StatusOK)
		if err := controller.Flush(); err != nil {
			t.Error(err)
			return
		}
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 {
		t.Fatal("fixture did not use HTTP/2")
	}
	_, err = io.ReadAll(response.Body)
	if err == nil || ctx.Err() != nil {
		t.Fatal("idle stream did not end at its independent write deadline", err, ctx.Err())
	}
	t.Logf("idle HTTP/2 stream ended with no read deadline: %v", err)
}

// ADR-179 allows independent pre-work queries on the same passive standby.
// The first query completes under its short original caller bound. Its retained
// socket deadline must not cancel a later caller during a fresh peer check.
func TestContextStartCompletedQueryDeadlineDoesNotCancelNextQuery(t *testing.T) {
	for _, phase := range []string{"current-check", "idle-gap", "work"} {
		t.Run(phase, func(t *testing.T) { contextStartCompletedQueryLifecycle(t, phase) })
	}
}

func contextStartCompletedQueryLifecycle(t *testing.T, phase string) {
	f := newContextStartTLSFixture(t)
	regional := &regionalOperationsFixture{t: t, process: f.api}
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
	hub := contextstart.Targets{Router: f.router, Now: time.Now, Report: func(event, timing string) { t.Log(event, timing) }}
	first, stopFirst := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer stopFirst()
	firstUntil, _ := first.Deadline()
	resolved, err := hub.ResolveWorkload(first, targets.WorkloadRequest{ClusterID: work.Target.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"})
	if err != nil {
		t.Fatal("first query", err)
	}
	if resolved.FreshUntil.After(firstUntil) {
		t.Fatal("first answer outlived its original caller")
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
	hold.Store(phase == "current-check")
	result := make(chan error, 1)
	go func() {
		_, err := hub.ResolvePod(second, resolved.Request)
		result <- err
	}()
	if phase == "current-check" {
		select {
		case <-entered:
		case err := <-result:
			t.Fatal("second query did not reach its fresh peer check", err)
		case <-time.After(time.Second):
			t.Fatal("second query peer check did not start")
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
