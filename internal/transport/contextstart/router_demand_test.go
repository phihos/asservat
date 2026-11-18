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

func TestHistoryWaitsForOneDemandThroughReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := workFixture().Work
		cluster := w.Channel.Connector.Binding.ClusterID
		router, err := NewRouter([]ClusterLimit{{cluster, 1, 1}})
		if err != nil {
			t.Fatal(err)
		}
		defer router.Close()
		ctx, cancel := context.WithTimeout(t.Context(), HistoryAttachLimit)
		defer cancel()
		signals := 0
		router.RequestExchange = func(call context.Context, _ string) error {
			if until, _ := call.Deadline(); !until.Equal(time.Now().Add(HistoryAttachLimit)) && signals == 0 {
				t.Fatal("history deadline changed")
			}
			signals++
			return nil
		}
		result := make(chan *Attachment, 1)
		go func() { a, _ := router.AttachHistory(ctx, cluster, w.CaptureID); result <- a }()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		if signals != 1 {
			t.Fatalf("history signalled %d times before reconnect", signals)
		}
		router.ResendDemand(cluster)
		if signals != 2 {
			t.Fatal("waiting history lost across reconnect")
		}
		now := time.Now()
		receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(now, identity.Recheck)}
		s, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
		if err != nil {
			t.Fatal(err)
		}
		a := <-result
		if a == nil {
			t.Fatal("history failed after delayed registration")
		}
		router.ResendDemand(cluster)
		if signals != 2 {
			t.Fatal("reannounced attached history")
		}
		s.Finish()
		a.Close()
	})
}

func TestForeignOwnerDemandReleasesSingleConnectorSlot(t *testing.T) {
	for _, scenario := range []struct {
		name                   string
		inFlight, disconnected bool
	}{
		{"completed query", false, false},
		{"in-flight query", true, false},
		{"missed notification while idle", false, true},
		{"missed notification during query", true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := workFixture().Work
				cluster := w.Channel.Connector.Binding.ClusterID
				first, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
				second, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
				defer first.Close()
				defer second.Close()
				start := func(r *Router) *Standby {
					receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(time.Now(), identity.Recheck)}
					s, err := r.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
					if err != nil {
						t.Fatal(err)
					}
					return s
				}
				only := start(first)
				defer only.Finish()
				ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				query := func(r *Router) <-chan error {
					done := make(chan error, 1)
					go func() { _, err := r.Query(ctx, cluster, queryResolvePod, nil, nil); done <- err }()
					return done
				}
				a := query(first)
				job := <-only.query
				second.RequestExchange = func(context.Context, string) error {
					if !scenario.disconnected {
						first.YieldIdle(cluster)
					}
					return nil
				}
				if !scenario.inFlight {
					job.result <- queryResult{until: time.Now().Add(time.Second)}
					if err := <-a; err != nil {
						t.Fatal(err)
					}
				}
				b := query(second)
				synctest.Wait()
				// The connector received B's demand while A alone was
				// disconnected. Reconnecting A must make that slot available.
				if scenario.disconnected {
					first.ResendDemand("")
				}
				if scenario.inFlight {
					if only.Context().Err() != nil {
						t.Fatal("yield interrupted query")
					}
					job.result <- queryResult{until: time.Now().Add(time.Second)}
					if err := <-a; err != nil {
						t.Fatal(err)
					}
				}
				if only.Context().Err() == nil {
					t.Fatal("completed exchange retained connector slot")
				}
				only.Finish()
				replacement := start(second)
				defer replacement.Finish()
				job = <-replacement.query
				job.result <- queryResult{until: time.Now().Add(time.Second)}
				if err := <-b; err != nil {
					t.Fatal("second owner query", err)
				}
			})
		})
	}
}

// The sole connector slot may already be opening for A when B requests it.
func TestForeignDemandBeforeRegistrationReleasesAfterOriginalQuery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := workFixture().Work
		cluster := w.Channel.Connector.Binding.ClusterID
		first, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
		second, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
		defer first.Close()
		defer second.Close()
		first.RequestExchange = func(context.Context, string) error { return nil }
		second.RequestExchange = func(context.Context, string) error { first.YieldIdle(cluster); return nil }
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		query := func(r *Router) <-chan error {
			done := make(chan error, 1)
			go func() { _, err := r.Query(ctx, cluster, queryResolvePod, nil, nil); done <- err }()
			synctest.Wait()
			return done
		}
		register := func(r *Router) *Standby {
			receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(time.Now(), identity.Recheck)}
			s, err := r.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		a := query(first)
		b := query(second)
		s := register(first)
		defer s.Finish()
		job := <-s.query
		if s.ctx.Err() != nil {
			t.Fatal("cancelled local demand before delivery")
		}
		job.result <- queryResult{until: time.Now().Add(time.Second)}
		if err := <-a; err != nil {
			t.Fatal(err)
		}
		if s.ctx.Err() == nil {
			t.Fatal("first replica kept the one connector slot after its query")
		}
		s.Finish()
		next := register(second)
		defer next.Finish()
		job = <-next.query
		job.result <- queryResult{until: time.Now().Add(time.Second)}
		if err := <-b; err != nil {
			t.Fatal(err)
		}
	})
}

// A delayed registration for the first hub must not strand the only connector
// slot when that hub cannot use it. The second caller keeps its original wait.
func TestForeignDemandSurvivesUnclaimedRegistration(t *testing.T) {
	for _, scenario := range []string{"canceled before claim", "replacement process"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := workFixture().Work
				cluster := w.Channel.Connector.Binding.ClusterID
				first, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
				second, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
				defer first.Close()
				defer second.Close()
				// Hold the local query inside demand publication until after the
				// connector has registered, before the caller can claim it.
				published := make(chan struct{})
				first.RequestExchange = func(call context.Context, _ string) error { <-published; return call.Err() }
				second.RequestExchange = func(context.Context, string) error { first.YieldIdle(cluster); return nil }
				ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
				defer stop()
				local, cancel := context.WithCancel(ctx)
				defer cancel()
				a := make(chan error, 1)
				go func() {
					_, err := first.QueryProcess(local, cluster, queryResolvePod, nil, nil, w.Channel.Executor.PodUID, w.Channel.Executor.ProcessEpoch)
					a <- err
				}()
				synctest.Wait()
				b := make(chan error, 1)
				go func() { _, err := second.Query(ctx, cluster, queryResolvePod, nil, nil); b <- err }()
				synctest.Wait()
				if scenario == "replacement process" {
					w.Channel.Executor.ProcessEpoch = "00000000-0000-4000-8000-000000000098"
				}
				receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(time.Now(), identity.Recheck)}
				check := func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }
				s, err := first.RegisterStandby(t.Context(), receiver, check)
				if scenario == "canceled before claim" {
					if err != nil {
						t.Fatal(err)
					}
					cancel()
				} else if err != nil && !errors.Is(err, fleet.ErrUnavailable) {
					t.Fatal(err)
				}
				close(published)
				synctest.Wait()
				if s != nil {
					defer s.Finish()
					if s.Context().Err() == nil {
						t.Fatal("unclaimed socket still occupies the single connector slot")
					}
					s.Finish()
				}
				next, err := second.RegisterStandby(t.Context(), receiver, check)
				if err != nil {
					t.Fatal(err)
				}
				defer next.Finish()
				job := <-next.query
				job.result <- queryResult{until: time.Now().Add(time.Second)}
				if err := <-b; err != nil {
					t.Fatal("second owner query", err)
				}
				cancel()
				if err := <-a; !errors.Is(err, fleet.ErrUnavailable) {
					t.Fatal("canceled or process-pinned local query", err)
				}
			})
		})
	}
}

func TestColdAttachSharesCallerDeadlineWithPublishedDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := workFixture().Work
		cluster := w.Channel.Connector.Binding.ClusterID
		router, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
		defer router.Close()
		deadline := time.Now().Add(9 * time.Second)
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()
		var demand context.Context
		router.RequestExchange = func(c context.Context, _ string) error { demand = c; return nil }
		result := make(chan *Attachment, 1)
		go func() { a, _ := router.Attach(ctx, cluster, w.CaptureID); result <- a }()
		synctest.Wait()
		if until, ok := demand.Deadline(); !ok || !until.Equal(deadline) {
			t.Fatal("hint has another lifetime", until)
		}
		time.Sleep(6 * time.Second)
		select {
		case <-result:
			t.Fatal("gave up while original demand remained live")
		default:
		}
		r := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(time.Now(), identity.Recheck)}
		s, err := router.RegisterStandby(t.Context(), r, func(context.Context) (fleet.APIContextReceiver, error) { return r, nil })
		if err != nil {
			t.Fatal(err)
		}
		a := <-result
		if a == nil {
			t.Fatal("lost live attachment")
		}
		s.Finish()
		defer a.Close()
		r.Channel.ExchangeID = "00000000-0000-4000-8000-000000000098"
		if late, err := router.RegisterStandby(t.Context(), r, func(context.Context) (fleet.APIContextReceiver, error) { return r, nil }); late != nil || !errors.Is(err, fleet.ErrUnavailable) {
			if late != nil {
				late.Finish()
			}
			t.Fatal("orphan opening occupied connector capacity", err)
		}
		if until, _ := a.ctx.Deadline(); !until.Equal(deadline) || demand.Err() == nil {
			t.Fatal("attachment changed its original bound or left demand pending", until)
		}
	})
}

func TestRouterCloseEndsWaitsAndDemand(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "awaiting registration", true: "publishing demand"}[blocked], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := workFixture().Work
				cluster := w.Channel.Connector.Binding.ClusterID
				r, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				var notifications int
				r.RequestExchange = func(ctx context.Context, _ string) error {
					notifications++
					if blocked {
						<-ctx.Done()
						return ctx.Err()
					}
					return nil
				}
				done := make(chan error, 1)
				go func() { _, err := r.Attach(ctx, cluster, w.CaptureID); done <- err }()
				synctest.Wait()
				r.Close()
				r.ResendDemand(cluster)
				r.Close()
				synctest.Wait()
				select {
				case err := <-done:
					if err == nil || ctx.Err() != nil {
						t.Fatal("wait did not end at router closure", err)
					}
				default:
					t.Fatal("router closure left a pending request")
				}
				if stop, err := r.request(ctx, cluster, nil); err == nil || stop != nil {
					t.Fatal("demand accepted after closure")
				}
				if notifications != 1 {
					t.Fatalf("published %d notifications for one closed request", notifications)
				}
			})
		})
	}
}
