package bootstrap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInstalledWorkerChildrenCancelAndJoinEveryOriginalOwner(t *testing.T) {
	for _, first := range []int{0, 1, 2, 3} {
		t.Run([]string{"configuration", "capacity", "cleanup", "permission"}[first], func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
			defer cancel()
			deadline, _ := ctx.Deadline()
			entered, canceled := make(chan int, 4), make(chan int, 4)
			trigger, closing := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(closing) }) }
			defer release()
			failure := errors.New("fixed child failed")
			child := func(n int) func(context.Context) error {
				return func(call context.Context) error {
					if got, ok := call.Deadline(); !ok || !got.Equal(deadline) {
						t.Error("child deadline changed")
					}
					entered <- n
					if n == first {
						<-trigger
						return failure
					}
					<-call.Done()
					canceled <- n
					<-closing
					return call.Err()
				}
			}
			done := make(chan error, 1)
			go func() { done <- runInstalledWorkerChildren(ctx, child(0), child(1), child(2), child(3)) }()
			for n := 0; n < 4; n++ {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("child did not start")
				}
			}
			close(trigger)
			for n := 0; n < 3; n++ {
				select {
				case <-canceled:
				case <-ctx.Done():
					t.Fatal("sibling not canceled")
				}
			}
			select {
			case <-done:
				t.Fatal("reported joined while owners were closing")
			default:
			}
			release()
			select {
			case err := <-done:
				if !errors.Is(err, failure) {
					t.Fatal("lost original failure", err)
				}
			case <-ctx.Done():
				t.Fatal("children did not join")
			}
		})
	}
}

func TestInstalledWorkerLeaseCancellationStopsAllAndDoesNotRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 4)
	var calls atomic.Int32
	child := func(call context.Context) error {
		calls.Add(1)
		entered <- struct{}{}
		<-call.Done()
		return call.Err()
	}
	done := make(chan error, 1)
	go func() { done <- runInstalledWorkerChildren(ctx, child, child, child, child) }()
	for n := 0; n < 4; n++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("child did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("lost Lease cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join")
	}
	if calls.Load() != 4 {
		t.Fatal("child restarted after cancellation")
	}
	if runInstalledWorkerChildren(ctx, child, child, child, child) == nil || calls.Load() != 4 {
		t.Fatal("canceled Lease started work")
	}
}

func TestCaptureCleanupCloseRetainsPoolsUntilActualOwnerCompletion(t *testing.T) {
	root, cancel := context.WithCancel(context.Background())
	d := &CaptureCleanupWorkerDeployment{root: root, cancel: cancel, running: true, lastSweepPending: true}
	var poolsClosed atomic.Bool
	d.closers = []func(){func() { poolsClosed.Store(true) }}
	d.owners.Add(1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(d.owners.Done) }
	defer release()
	closed := make(chan struct{})
	go func() { d.Close(); close(closed) }()
	select {
	case <-root.Done():
	case <-time.After(time.Second):
		t.Fatal("cleanup root not canceled")
	}
	if poolsClosed.Load() {
		t.Fatal("pool closed while an owner was still active")
	}
	select {
	case <-closed:
		t.Fatal("Close fabricated completion")
	default:
	}
	release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join")
	}
	if !poolsClosed.Load() || !d.LastSweepPending() {
		t.Fatal("closed worker claimed a clean sweep")
	}
	if d.Run(context.Background()) == nil {
		t.Fatal("closed worker resumed")
	}
	d.Close()
}
