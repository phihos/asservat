package contextstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/fleet"
)

// A query can use its original deadline to wait for the next registration.
func TestRouterQueryWaitsForNextStandbyWithinDeadline(t *testing.T) {
	work := workFixture()
	cluster := work.Work.Channel.Connector.Binding.ClusterID
	router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	short, end := context.WithTimeout(context.Background(), 30*time.Millisecond)
	if _, err := router.Query(short, cluster, queryResolvePod, struct{}{}, &struct{}{}); !errors.Is(err, fleet.ErrUnavailable) || short.Err() != context.DeadlineExceeded {
		t.Fatal("registration exceeded query deadline", err)
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
	receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
	standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
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
