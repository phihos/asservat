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
			Watch: func(ctx context.Context, receive func(connectorlifecycle.WorkHint)) error {
				subscriptions++
				for {
					select {
					case hint := <-hints:
						receive(hint)
					case <-reconnect:
						return fleet.ErrUnavailable
					case <-ctx.Done():
						return ctx.Err()
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
