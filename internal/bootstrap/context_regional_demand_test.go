package bootstrap

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"asservat.local/asservat/internal/transport/contextstart"
)

type regionalDemandClient struct {
	opened chan connectorlifecycle.WorkHint
	closed bool
}

func (c *regionalDemandClient) OpenRequested(_ context.Context, owner fleet.OwnerBinding, until time.Time) (*mtls.ContextStartExchange, error) {
	c.opened <- connectorlifecycle.WorkHint{Owner: owner, Until: until}
	return nil, fleet.ErrUnavailable
}

func (c *regionalDemandClient) Close() { c.closed = true }

func TestRegionalDemandKeepsIdleSubscriptionWithoutOpeningExchanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		hints := make(chan connectorlifecycle.WorkHint)
		reconnect := make(chan struct{})
		client := &regionalDemandClient{opened: make(chan connectorlifecycle.WorkHint, 4)}
		subscriptions := 0
		regional := RegionalContextStartConnections{Client: client, Concurrency: 2, Local: contextstart.RegionalLocal{Now: time.Now},
			Watch: func(ctx context.Context, receive func(connectorlifecycle.WorkHint)) (bool, error) {
				subscriptions++
				for {
					select {
					case hint := <-hints:
						receive(hint)
					case <-reconnect:
						return true, fleet.ErrUnavailable
					case <-ctx.Done():
						return true, ctx.Err()
					}
				}
			},
		}
		done := make(chan error, 1)
		go func() { done <- regional.Run(ctx) }()
		synctest.Wait()
		idle := func(wantSubs int) {
			t.Helper()
			time.Sleep(90 * time.Second) // Three former standby lifetimes.
			synctest.Wait()
			if len(client.opened) != 0 || subscriptions != wantSubs {
				t.Fatalf("idle connector opened %d exchanges across %d subscriptions, want 0 across %d", len(client.opened), subscriptions, wantSubs)
			}
		}
		idle(1)
		owner := fleet.OwnerBinding{InstallationID: connectorTestID("01"), ClusterID: connectorTestID("02"), IssuerEpoch: connectorTestID("03"), PodUID: connectorTestID("04"), ProcessEpoch: connectorTestID("05")}
		hint := connectorlifecycle.WorkHint{Cluster: connectorTestID("06"), Owner: owner, Until: time.Now().Add(5 * time.Second)}
		hints <- hint
		synctest.Wait()
		select {
		case got := <-client.opened:
			if got.Owner != hint.Owner || !got.Until.Equal(hint.Until) {
				t.Fatal("opening changed owner or deadline", got)
			}
		default:
			t.Fatal("waiting caller did not open an exchange")
		}
		reconnect <- struct{}{}
		idle(2) // Reconnecting cannot replay an old hint or restart standby renewal.
		stop()
		if err := <-done; !errors.Is(err, context.Canceled) || !client.closed {
			t.Fatal("connector shutdown", err, client.closed)
		}
	})
}

func TestRegionalDisconnectBacksOffAndCancels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, stop := context.WithCancel(t.Context())
		calls := 0
		var last time.Time
		run := RegionalContextStartConnections{Client: &regionalDemandClient{}, Concurrency: 1, Local: contextstart.RegionalLocal{Now: time.Now},
			Watch: func(context.Context, func(connectorlifecycle.WorkHint)) (bool, error) {
				calls++
				now := time.Now()
				if calls > 1 {
					base := time.Second << min(calls-2, 5)
					base = min(base, 30*time.Second)
					if calls == 9 {
						base = time.Second
					} // preceding handshake succeeded
					if dt := now.Sub(last); dt < base || dt >= 2*base {
						t.Errorf("attempt %d waited %s, base %s", calls, dt, base)
					}
				}
				last = now
				if calls == 9 {
					stop()
				}
				return calls == 8, errors.New("disconnected")
			}}
		if err := run.Run(ctx); !errors.Is(err, context.Canceled) || calls != 9 {
			t.Fatal(calls, err)
		}
	})
}

func TestRegionalCancelsDuringReconnectWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, stop := context.WithCancel(t.Context())
		started := time.Now()
		calls := 0
		run := RegionalContextStartConnections{Client: &regionalDemandClient{}, Concurrency: 1, Local: contextstart.RegionalLocal{Now: time.Now},
			Watch: func(context.Context, func(connectorlifecycle.WorkHint)) (bool, error) {
				calls++
				return false, errors.New("offline")
			}}
		done := make(chan error, 1)
		go func() { done <- run.Run(ctx) }()
		synctest.Wait()
		stop()
		if err := <-done; !errors.Is(err, context.Canceled) || calls != 1 || !time.Now().Equal(started) {
			t.Fatal("cancellation waited for reconnect", calls, time.Since(started), err)
		}
	})
}
