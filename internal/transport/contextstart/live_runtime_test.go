package contextstart

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestReadLiveRuntimeUsesRealFramedQueryAndValidatesAnswer(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := collector.LiveRuntimeRequest{ClusterID: workFixture().Work.Channel.Connector.Binding.ClusterID}
	for _, tc := range []struct {
		name   string
		mutate func(*collector.LiveRuntimeSnapshot)
		valid  bool
	}{
		{name: "accepted", valid: true},
		{name: "wrong cluster", mutate: func(s *collector.LiveRuntimeSnapshot) { s.ClusterID = "00000000-0000-4000-8000-000000000002" }},
		{name: "expired", mutate: func(s *collector.LiveRuntimeSnapshot) { s.FreshUntil = now }},
		{name: "incomplete totals", mutate: func(s *collector.LiveRuntimeSnapshot) { s.RatesComplete = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			answer := collector.LiveRuntimeSnapshot{ClusterID: request.ClusterID, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Nodes: 1, RatesComplete: true,
				Live: &collector.LiveActivity{Cohorts: 2, ScanEvents: 20, DeliveredRows: 4}, Rates: collector.LiveActivityRates{ScanEventsPerSecond: 2.5, DeliveredRowsPerSecond: 0.5}}
			if tc.mutate != nil {
				tc.mutate(&answer)
			}
			f := newQueryLifecycleFixture(t, ctx, nil, func(reply contracts.APIContextOperationReply) contracts.APIContextFrame {
				if reply.Method != queryReadLiveRuntime {
					t.Error("wrong method", reply.Method)
				}
				reply.Body, _ = json.Marshal(answer)
				return queryAnswerFrame(t, reply)
			})
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{request.ClusterID, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			standby, err := router.RegisterStandby(t.Context(), f.receiver, func(context.Context) (fleet.APIContextReceiver, error) { return f.receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer standby.Finish()
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				select {
				case job := <-standby.query:
					until, err := f.stream.query(job.ctx, job.method, job.in, job.out)
					job.result <- queryResult{until: until, err: err}
				case <-ctx.Done():
				}
			}()
			hub := Targets{Router: router, Now: func() time.Time { return now }}
			got, err := hub.ReadLiveRuntime(ctx, request)
			<-joined
			if tc.valid {
				if err != nil || got.ClusterID != request.ClusterID || got.Live.ScanEvents != 20 || got.Rates.ScanEventsPerSecond != 2.5 {
					t.Fatal("valid live aggregate changed", got, err)
				}
			} else if err == nil {
				t.Fatal("invalid live aggregate accepted", got)
			}
		})
	}
}
