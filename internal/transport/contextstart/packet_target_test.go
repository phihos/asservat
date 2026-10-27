package contextstart

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

func TestPacketTargetOneQueryPreservesEveryOriginalBound(t *testing.T) {
	for _, mode := range []string{"producer-shorter", "available", "receiver-expired", "target-expired", "wrong-pod", "wrong-class", "unavailable", "invalid-answer"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			work := workFixture()
			request := targets.Request{ClusterID: work.Work.Channel.Connector.Binding.ClusterID, Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "deployment"}, PodName: "app-0", PodUID: "pod"}
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{request.ClusterID, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			standby, err := router.RegisterStandby(context.Background(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer standby.Finish()
			hub := Targets{Router: router, Now: func() time.Time { return now }}
			type result struct {
				p   targets.PodResolution
				err error
			}
			done := make(chan result, 1)
			go func() { p, e := hub.ResolvePacketRecorder(ctx, request); done <- result{p, e} }()
			var job *queryJob
			select {
			case job = <-standby.query:
			case <-ctx.Done():
				t.Fatal("combined query absent", ctx.Err())
			}
			if job.method != queryResolvePacketRecorder || job.in != request {
				t.Fatal("not one exact packet target query", job.method)
			}
			out := targets.RecorderResolution{Target: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: "namespace", Name: "app-0", UID: "pod", ControllerUID: "replicaset"}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(3 * time.Second)}, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable}}
			until := now.Add(2 * time.Second)
			switch mode {
			case "producer-shorter":
				out.Target.FreshUntil = now.Add(500 * time.Millisecond)
			case "receiver-expired":
				until = now
			case "target-expired":
				out.Target.FreshUntil = now
			case "wrong-pod":
				out.Target.Request.PodUID = "replacement"
				out.Target.Pin.UID = "replacement"
			case "wrong-class":
				out.Target.ExecutionClass = artifact.ContextNodeExecution
			case "unavailable":
				out.Recorder.Outcome = targets.RecorderUnavailable
			case "invalid-answer":
				out.Recorder.Outcome = "invented"
			}
			*job.out.(*targets.RecorderResolution) = out
			job.result <- queryResult{until: until}
			got := <-done
			if mode == "available" || mode == "producer-shorter" {
				want := out.Target.FreshUntil

				if got.err != nil || !got.p.Valid(now) || got.p.Request != request || got.p.ObservedAt != out.Target.ObservedAt || !got.p.FreshUntil.Equal(want) || got.p.Pin.NodeName != "" {
					t.Fatal("lost own target observation or accepted expired transport", got)
				}
			} else if got.err == nil || got.p != (targets.PodResolution{}) {
				t.Fatal("invalid readiness returned a target", got)
			}
			select {
			case <-standby.query:
				t.Fatal("second recorder RPC dispatched")
			default:
			}
		})
	}
}
