package bootstrap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ADR-329/330: a delivery is sent on change only: an unchanged digest sends
// nothing, a burst coalesces, a failure is retried, and nothing is resent
// periodically.
func TestDeliverOnChangeSendsOnlyChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resync, trigger := make(chan struct{}, 1), make(chan struct{}, 1)
	var mu sync.Mutex
	digest, sends, fail := "a", 0, false
	sent := make(chan struct{}, 16)
	build := func(context.Context) (string, func(context.Context) error, error) {
		mu.Lock()
		defer mu.Unlock()
		d := digest
		return d, func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			sends++
			sent <- struct{}{}
			if fail {
				return errors.New("hub unavailable")
			}
			return nil
		}, nil
	}
	done := make(chan struct{})
	go func() { defer close(done); deliverOnChange(ctx, resync, trigger, "test", build) }()
	<-sent // the first delivery after start compares with the hub
	trigger <- struct{}{}
	time.Sleep(1200 * time.Millisecond)
	mu.Lock()
	if sends != 1 {
		t.Fatal("unchanged digest sent again", sends)
	}
	mu.Unlock()
	resync <- struct{}{}
	select {
	case <-sent: // unchanged local digest is compared to the new hub
	case <-time.After(3 * time.Second):
		t.Fatal("unchanged delivery never compared with the reconnected hub")
	}
	mu.Lock()
	digest, fail = "b", true
	mu.Unlock()
	trigger <- struct{}{}
	<-sent // changed: sent, fails
	<-sent // retried after deliveryRetry
	mu.Lock()
	fail = false
	mu.Unlock()
	cancel()
	<-done
}
