package contextstart

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func TestRouterReannouncesOnlyWaitingExchanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		work := workFixture().Work
		first := work.Channel.Connector.Binding.ClusterID
		const second = "00000000-0000-4000-8000-000000000098"
		router, err := NewRouter([]ClusterLimit{{first, 1, 1}, {second, 1, 1}})
		if err != nil {
			t.Fatal(err)
		}
		defer router.Close()
		type hint struct {
			cluster string
			until   time.Time
		}
		hints := make(chan hint, 8)
		router.RequestExchange = func(ctx context.Context, cluster string) error {
			until, _ := ctx.Deadline()
			hints <- hint{cluster, until}
			return nil
		}
		until := time.Now().Add(5 * time.Second)
		queryCtx, cancel := context.WithDeadline(t.Context(), until)
		defer cancel()
		attachCtx, stop := context.WithDeadline(t.Context(), until)
		defer stop()
		wantHint := func(cluster string) {
			t.Helper()
			select {
			case got := <-hints:
				if got.cluster != cluster || !got.until.Equal(until) {
					t.Fatalf("demand for %s has wrong cluster or original deadline: %+v", cluster, got)
				}
			default:
				t.Fatal("missing demand for", cluster)
			}
		}
		noHint := func() {
			t.Helper()
			select {
			case got := <-hints:
				t.Fatal("unexpected exchange demand", got)
			default:
			}
		}
		router.ResendDemand("")
		noHint()

		query := make(chan error, 1)
		go func() {
			_, err := router.Query(queryCtx, first, queryResolvePod, struct{}{}, &struct{}{})
			query <- err
		}()
		synctest.Wait()
		wantHint(first)
		attach := make(chan error, 1)
		go func() {
			_, err := router.Attach(attachCtx, second, work.CaptureID)
			attach <- err
		}()
		synctest.Wait()
		wantHint(second)
		time.Sleep(time.Second)
		noHint() // No periodic demand while the connector is idle.
		router.ResendDemand(second)
		wantHint(second)
		noHint()

		stop()
		if err := <-attach; !errors.Is(err, fleet.ErrUnavailable) {
			t.Fatal("cancelled attachment", err)
		}
		router.ResendDemand("")
		wantHint(first)
		noHint()

		now := time.Now()
		receiver := fleet.APIContextReceiver{Channel: work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(until)}
		standby, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
		if err != nil {
			t.Fatal(err)
		}
		defer standby.Finish()
		job := <-standby.query
		gotDeadline, _ := job.ctx.Deadline()
		if !gotDeadline.Equal(until) {
			t.Fatalf("dispatched query deadline %v, want %v", gotDeadline, until)
		}
		router.ResendDemand(first)
		noHint() // An attached but unfinished operation must never be reannounced.
		job.result <- queryResult{until: until}
		if err := <-query; err != nil {
			t.Fatal(err)
		}
		router.ResendDemand("")
		noHint()
	})
}

func TestRouterRefusesIneligibleDemandBeforeSignallingConnector(t *testing.T) {
	work := workFixture().Work
	cluster := work.Channel.Connector.Binding.ClusterID
	router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	router.RequestExchange = func(context.Context, string) error {
		t.Error("refused request signalled the connector")
		return nil
	}
	short, end := context.WithTimeout(t.Context(), time.Second)
	defer end()
	if _, err := router.Query(short, cluster, queryResolvePod, nil, nil); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("query without room for an exchange", err)
	}
	if _, err := router.Attach(short, cluster, work.CaptureID); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("capture without room for an exchange", err)
	}
	long, stop := context.WithTimeout(t.Context(), 6*time.Second)
	defer stop()
	if _, err := router.Query(long, cluster, queryResolvePod, nil, nil); !errors.Is(err, fleet.ErrInvalid) {
		t.Fatal("query with a deadline beyond five seconds", err)
	}
	valid, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const absent = "00000000-0000-4000-8000-000000000097"
	if _, err := router.Query(valid, absent, queryResolvePod, nil, nil); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("query for unregistered cluster", err)
	}
	if _, err := router.Attach(valid, absent, work.CaptureID); !errors.Is(err, fleet.ErrCapacity) {
		t.Fatal("capture for unregistered cluster", err)
	}
	router.ResendDemand("")
}
