package contextstart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

// The stream owns cancellation independently of its HTTP request. Hold its
// socket cleanup to expose the interval before the handler can call Finish.
type routerStreamFixture struct {
	router        *Router
	standby       *Standby
	stream        *frameStream
	receiver      fleet.APIContextReceiver
	interrupting  chan struct{}
	releaseSocket chan struct{}
	handled       chan struct{}
	releaseOnce   sync.Once
}

func newRouterStreamFixture(t *testing.T) *routerStreamFixture {
	t.Helper()
	w := workFixture()
	cluster := w.Work.Target.ClusterID
	r, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: w.VerifiedAt, ValidUntil: w.ValidUntil}
	check := func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }
	standby, err := r.RegisterStandby(context.Background(), receiver, check)
	if err != nil {
		t.Fatal(err)
	}
	f := &routerStreamFixture{router: r, standby: standby, receiver: receiver, interrupting: make(chan struct{}), releaseSocket: make(chan struct{}), handled: make(chan struct{})}
	f.stream, err = newFrameStream(standby.Context(), receiver.Channel, check, bytes.NewReader(nil), io.Discard, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() {
		close(f.interrupting)
		<-f.releaseSocket
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = standby.Serve(f.stream, time.Now)
		_ = f.stream.Close()
		standby.Finish()
		close(f.handled)
	}()
	t.Cleanup(func() {
		f.releaseOnce.Do(func() { close(f.releaseSocket) })
		standby.cancel()
		awaitRouterStream(t, f.handled, "handler cleanup")
		r.Close()
	})
	return f
}

func awaitRouterStream(t *testing.T, done <-chan struct{}, phase string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s did not finish", phase)
	}
}

func TestRouterWithdrawsCancelledStreamBeforeSocketCleanup(t *testing.T) {
	f := newRouterStreamFixture(t)
	go f.stream.interruptAt(streamRead, streamOther)
	awaitRouterStream(t, f.interrupting, "stream interruption")
	select {
	case <-f.standby.Context().Done():
	case <-time.After(100 * time.Millisecond):
		t.Error("stream cancellation left the standby current")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cluster := f.receiver.Channel.Connector.Binding.ClusterID
	if _, err := f.router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{}); !errors.Is(err, fleet.ErrUnavailable) {
		t.Errorf("dead standby query returned %v", err)
	}
	f.router.mu.Lock()
	queries := f.standby.queries
	f.router.mu.Unlock()
	if queries != 0 {
		t.Error("query selected the cancelled stream")
	}
	attachment, err := f.router.Attach(ctx, cluster, workFixture().Work.CaptureID)
	if err == nil {
		t.Error("capture selected the cancelled stream")
	}
	select {
	case <-f.handled:
		t.Fatal("handler released its standby before socket cleanup joined")
	default:
	}
	replacement := f.receiver
	replacement.Channel.ExchangeID = "00000000-0000-4000-8000-000000000098"
	if _, err := f.router.RegisterStandby(context.Background(), replacement, func(context.Context) (fleet.APIContextReceiver, error) { return replacement, nil }); !errors.Is(err, fleet.ErrCapacity) {
		t.Fatalf("closing standby stopped counting against capacity: %v", err)
	}
	f.releaseOnce.Do(func() { close(f.releaseSocket) })
	awaitRouterStream(t, f.handled, "joined stream cleanup")
	if attachment != nil {
		attachment.Close()
	}
	next, err := f.router.RegisterStandby(context.Background(), replacement, func(context.Context) (fleet.APIContextReceiver, error) { return replacement, nil })
	if err != nil {
		t.Fatal("joined standby did not release capacity", err)
	}
	next.Finish()
}

func TestRouterStreamCancellationKeepsCaptureChargedUntilJoined(t *testing.T) {
	f := newRouterStreamFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), f.receiver.ValidUntil)
	defer cancel()
	w := workFixture().Work
	w.Channel = f.receiver.Channel
	attachment, err := f.router.Attach(ctx, w.Target.ClusterID, w.CaptureID)
	if err != nil {
		t.Fatal(err)
	}
	entered, cancelled, releaseOperation, operationReturned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var operationOnce sync.Once
	t.Cleanup(func() { operationOnce.Do(func() { close(releaseOperation) }) })
	runDone := make(chan struct{})
	go func() {
		_, _ = attachment.Run(w, []byte("signed"), func(call context.Context, _ *HubOperations) (string, error) {
			close(entered)
			<-call.Done()
			close(cancelled)
			<-releaseOperation
			close(operationReturned)
			return "Unavailable", call.Err()
		})
		close(runDone)
	}()
	awaitRouterStream(t, entered, "hub operation")
	go f.stream.interruptAt(streamRead, streamOther)
	awaitRouterStream(t, cancelled, "hub operation cancellation")
	closed := make(chan struct{})
	go func() { attachment.Close(); close(closed) }()
	assertCharged := func() {
		t.Helper()
		select {
		case <-closed:
			t.Fatal("capture released before operation and socket cleanup joined")
		default:
		}
		f.router.mu.Lock()
		charged := len(f.router.captures) == 1 && f.router.clusters[w.Target.ClusterID].captures == 1
		f.router.mu.Unlock()
		if !charged {
			t.Fatal("cancelled capture stopped counting against capacity")
		}
	}
	assertCharged()
	operationOnce.Do(func() { close(releaseOperation) })
	awaitRouterStream(t, operationReturned, "hub operation return")
	assertCharged()
	f.releaseOnce.Do(func() { close(f.releaseSocket) })
	awaitRouterStream(t, f.handled, "socket join")
	awaitRouterStream(t, closed, "capture release")
	awaitRouterStream(t, runDone, "capture dispatch")
	f.router.mu.Lock()
	defer f.router.mu.Unlock()
	if len(f.router.captures) != 0 || f.router.clusters[w.Target.ClusterID].captures != 0 {
		t.Fatal("joined capture did not release capacity")
	}
}
