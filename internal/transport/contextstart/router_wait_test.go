package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// A query that finds no idle standby waits, within its original deadline less
// queryReserve, for the next registration; without that room it fails at once.
func TestRouterQueryWaitsForNextStandbyWithinDeadline(t *testing.T) {
	work := workFixture()
	cluster := work.Work.Channel.Connector.Binding.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	short, end := context.WithTimeout(context.Background(), 2*time.Second)
	started := time.Now()
	if _, err := router.Query(short, cluster, queryResolvePod, struct{}{}, &struct{}{}); !errors.Is(err, fleet.ErrUnavailable) || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("no room to wait must fail at once: %v after %s", err, time.Since(started))
	}
	end()
	ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{})
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	now := time.Now()
	receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	standby, err := router.RegisterStandby(ctx, receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	select {
	case job := <-standby.query:
		job.result <- queryResult{until: now.Add(time.Second)}
	case err := <-done:
		t.Fatalf("query did not wait for the registered standby: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Installed native 95: a burst of target queries spent the only standby's
// query budget, and every later query failed at `router` until that standby's
// thirty-second residency ended. A waiting query now withdraws the spent idle
// standby, so the region can register a fresh one within the query's own wait.
func TestRouterQueryWithdrawsSpentStandbyForReplacement(t *testing.T) {
	work := workFixture()
	cluster := work.Work.Channel.Connector.Binding.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	register := func(exchange string) (*Standby, fleet.APIContextReceiver) {
		t.Helper()
		now := time.Now()
		channel := work.Work.Channel
		channel.ExchangeID = exchange
		receiver := fleet.APIContextReceiver{Channel: channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
		standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
		if err != nil {
			t.Fatal(err)
		}
		return standby, receiver
	}
	ask := func(ctx context.Context) chan error {
		done := make(chan error, 1)
		go func() {
			_, err := router.Query(ctx, cluster, queryResolvePod, struct{}{}, &struct{}{})
			done <- err
		}()
		return done
	}
	spent, receiver := register(work.Work.Channel.ExchangeID)
	defer spent.Finish()
	for i := 0; i < contracts.APIContextMaximumQueries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
		done := ask(ctx)
		job := <-spent.query
		job.result <- queryResult{until: receiver.ValidUntil}
		if err := <-done; err != nil {
			t.Fatal(i, err)
		}
		cancel()
	}
	// Without a waiting query the spent standby stays registered for work.
	if spent.ctx.Err() != nil {
		t.Fatal("spent standby withdrawn without a waiting query")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
	defer cancel()
	done := ask(ctx)
	select {
	case <-spent.ctx.Done():
	case err := <-done:
		t.Fatalf("query ended without withdrawing the spent standby: %v", err)
	case <-time.After(time.Second):
		t.Fatal("spent standby was not withdrawn")
	}
	// The handler joins and releases the reservation; the region reopens.
	spent.Finish()
	fresh, receiver := register("00000000-0000-4000-8000-000000000099")
	defer fresh.Finish()
	select {
	case job := <-fresh.query:
		job.result <- queryResult{until: receiver.ValidUntil}
	case err := <-done:
		t.Fatalf("query did not use the replacement standby: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
