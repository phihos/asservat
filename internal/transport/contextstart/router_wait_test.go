package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

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
