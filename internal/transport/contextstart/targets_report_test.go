package contextstart

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

func TestQueryStepNamesWhereAQueryStopped(t *testing.T) {
	ctx, d := NewStreamDiagnosticContext(context.Background())
	if got := queryStep(fleet.ErrUnavailable, d); got != "router" {
		t.Fatalf("no interruption: %q", got)
	}
	if got := queryStep(errQueryAnswer{targets.ErrUnavailable}, d); got != "answer/"+queryFailureLabel(targets.ErrUnavailable) {
		t.Fatalf("answer: %q", got)
	}
	s := &frameStream{}
	s.record(streamHubQueryCheck, streamExpired)
	recordStreamDiagnostic(ctx, s, fleet.ErrUnavailable, streamHubQuery)
	if got := queryStep(fleet.ErrUnavailable, d); got != "hub-query-check/deadline" {
		t.Fatalf("first interruption: %q", got)
	}
	for _, stage := range []streamStage{streamHubQuery, streamHubQuerySource, streamHubQueryCheck, streamRegionalQueryOwner, streamRegionalQueryWrite} {
		if (StreamInterruption{stage: stage}).Stage() == "unknown" {
			t.Fatalf("stage %d has no name", stage)
		}
	}
}

// A successful exchange can return an answer whose original receiver or
// regional deadline has elapsed by final validation. Drive the router's actual
// query handoff, advancing only the target consumer's clock, without a sleep.
func TestTargetQueryReportsFinalValidationInsteadOfTransportSuccess(t *testing.T) {
	now := time.Now().UTC()
	work := workFixture()
	request := targets.Request{
		ClusterID: work.Work.Channel.Connector.Binding.ClusterID,
		Namespace: configuration.NamespaceRef{Name: "app", UID: "namespace"},
		Workload:  configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: "deployment"},
		PodName:   "app-0", PodUID: "pod",
	}
	for _, tc := range []struct {
		name, label string
		change      func(*targets.PodResolution, *time.Time)
	}{
		{name: "accepted", label: "ok"},
		{name: "receiver-expired", label: "result/receiver-expired", change: func(_ *targets.PodResolution, until *time.Time) { *until = now }},
		{name: "resolution-expired", label: "result/resolution-expired", change: func(out *targets.PodResolution, _ *time.Time) { out.FreshUntil = now }},
		{name: "both-expired", label: "result/both-expired", change: func(out *targets.PodResolution, until *time.Time) { out.FreshUntil, *until = now, now }},
		{name: "future-observation", label: "result/invalid", change: func(out *targets.PodResolution, _ *time.Time) { out.ObservedAt = now.Add(time.Second) }},
		{name: "wrong-class", label: "result/class", change: func(out *targets.PodResolution, _ *time.Time) { out.ExecutionClass = artifact.ContextNodeExecution }},
		{name: "wrong-cluster", label: "result/cluster", change: func(out *targets.PodResolution, _ *time.Time) {
			out.Request.ClusterID = work.Work.Channel.Hub.ClusterID
		}},
		{name: "replacement-pod", label: "result/request", change: func(out *targets.PodResolution, _ *time.Time) {
			out.Request.PodUID, out.Pin.UID = "replacement", "replacement"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{request.ClusterID, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			observed := time.Now()
			receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: observed, ValidUntil: observed.Add(5 * time.Second)}
			standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer standby.Finish()
			var reports, timings []string
			hub := Targets{Router: router, Now: func() time.Time { return now }, Report: func(step, timing string) {
				reports = append(reports, step)
				timings = append(timings, timing)
			}}
			type resolution struct {
				pod targets.PodResolution
				err error
			}
			done := make(chan resolution, 1)
			go func() {
				pod, err := hub.ResolvePod(ctx, request)
				done <- resolution{pod, err}
			}()
			var job *queryJob
			select {
			case job = <-standby.query:
			case <-ctx.Done():
				t.Fatal("query was not dispatched", ctx.Err())
			}
			if job.method != queryResolvePod || job.in != request {
				t.Fatal("query changed the pinned request")
			}
			out := targets.PodResolution{
				ExecutionClass: artifact.ContextAPIExecution, Request: request,
				Pin:                artifact.PinnedPod{Namespace: "app", NamespaceUID: "namespace", Name: "app-0", UID: "pod", ControllerUID: "replicaset"},
				PodResourceVersion: "1", WorkloadResourceVersion: "1",
				ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(3 * time.Second),
			}
			until := now.Add(2 * time.Second)
			if tc.change != nil {
				tc.change(&out, &until)
			}
			*job.out.(*targets.PodResolution) = out
			// This is a successfully decoded exchange; failure can only come
			// from the target consumer's later validation.
			job.result <- queryResult{until: until}
			got := <-done
			if tc.label == "ok" {
				if got.err != nil || !got.pod.Valid(now) || !got.pod.FreshUntil.Equal(until) || got.pod.ObservedAt != out.ObservedAt {
					t.Fatal("accepted resolution lost an original bound", got)
				}
			} else if !errors.Is(got.err, targets.ErrUnavailable) || got.pod != (targets.PodResolution{}) {
				t.Fatal("invalid resolution was accepted", got)
			}
			if len(reports) != 1 || reports[0] != tc.label || len(timings) != 1 || !strings.HasPrefix(timings[0], "start") {
				t.Fatalf("final result %q reported %q", tc.label, reports)
			}
		})
	}
}

func TestTargetQueryExpiredResultNamesOriginalCallerDeadline(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(-time.Second))
	defer cancel()
	if got := queryResultStep(ctx, now, now, now); got != "result/deadline" {
		t.Fatal("caller deadline was mislabelled as a source expiry", got)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if got := queryResultStep(cancelled, now, now, now); got != "result/cancelled" {
		t.Fatal("caller cancellation was mislabelled as a source expiry", got)
	}
}
