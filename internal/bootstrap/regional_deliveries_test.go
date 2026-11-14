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
	enrolled, trigger := make(chan struct{}), make(chan struct{}, 1)
	close(enrolled)
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
	go func() { defer close(done); deliverOnChange(ctx, enrolled, trigger, "test", build) }()
	<-sent // the first delivery after start compares with the hub
	trigger <- struct{}{}
	time.Sleep(1200 * time.Millisecond)
	mu.Lock()
	if sends != 1 {
		t.Fatal("unchanged digest sent again", sends)
	}
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
