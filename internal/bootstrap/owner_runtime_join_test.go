package bootstrap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerRuntimeJoinsBlockedChildAfterCancellation(t *testing.T) {
	fixture, config, listener := newRuntimeFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	// The independently called readiness reader deliberately ignores cancellation
	// until a positive test-owned release. This is not a new authority provider.
	fixture.mutateProof = func(*fleet.OwnerEnrollmentProof) { once.Do(func() { close(entered) }); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime, e := NewOwnerRuntime(ctx, config)
	if e != nil {
		close(release)
		t.Fatal(e)
	}
	finished := make(chan error, 1)
	go func() { finished <- runtime.Run(listener) }()
	joined := false
	t.Cleanup(func() {
		cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		if !joined {
			<-finished
		}
		runtime.Close()
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("readiness child did not enter")
	}
	cancel()
	// Cross the old six-second detach timeout only after the actual blocked child
	// is known to exist. No sleep substitutes for that ownership handshake.
	oldTimeout := time.NewTimer(6250 * time.Millisecond)
	defer oldTimeout.Stop()
	select {
	case e := <-finished:
		joined = true
		t.Fatal("Run returned while original child remained blocked", e)
	case <-oldTimeout.C:
	}
	if runtime.Ready() {
		t.Fatal("cancelled runtime retained readiness")
	}
	if _, _, e := runtime.server.ReadinessRequest(); e == nil {
		t.Fatal("cancelled runtime retained server key authority")
	}
	close(release)
	select {
	case e := <-finished:
		joined = true
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("released child did not join")
	}
}
