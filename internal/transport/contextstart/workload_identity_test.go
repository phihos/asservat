package contextstart

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"testing"
	"time"
)

func TestWorkloadIdentityQueryRetainsOriginalRootAndDeadlines(t *testing.T) {
	for _, mode := range []string{"current", "shorter-observation", "wrong-reference", "wrong-cluster", "wrong-namespace", "empty-root", "expired-observation", "overlong-observation", "expired-receiver", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			work := workFixture()
			request := targets.WorkloadRequest{ClusterID: work.Work.Channel.Connector.Binding.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}
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
				root targets.WorkloadIdentityResolution
				err  error
			}
			done := make(chan result, 1)
			go func() { r, e := hub.ResolveWorkloadIdentity(ctx, request); done <- result{r, e} }()
			var job *queryJob
			select {
			case job = <-standby.query:
			case <-ctx.Done():
				t.Fatal("identity query missing", ctx.Err())
			}
			if job.method != queryResolveWorkloadIdentity || job.in != request {
				t.Fatal("different target query", job.method, job.in)
			}
			out := targets.WorkloadIdentityResolution{Reference: request, ClusterID: request.ClusterID, Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "deployment"}, ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(3 * time.Second)}
			until := now.Add(2 * time.Second)
			switch mode {
			case "shorter-observation":
				out.FreshUntil = now.Add(time.Millisecond)
			case "wrong-reference":
				out.Reference.Name = "other"
				out.Workload.Name = "other"
			case "wrong-cluster":
				out.ClusterID = "00000000-0000-4000-8000-000000009999"
				out.Reference.ClusterID = out.ClusterID
			case "wrong-namespace":
				out.Namespace.Name = "other"
				out.Reference.Namespace = "other"
			case "empty-root":
				out.Workload.UID = ""
			case "expired-observation":
				out.FreshUntil = now
			case "overlong-observation":
				out.FreshUntil = now.Add(5 * time.Second)
			case "expired-receiver":
				until = now
			case "cancelled":
				cancel()
			}
			*job.out.(*targets.WorkloadIdentityResolution) = out
			job.result <- queryResult{until: until}
			got := <-done
			if mode == "current" || mode == "shorter-observation" {
				if got.err != nil || got.root != out || !got.root.Valid(now) {
					t.Fatal("identity or earliest observation changed", got)
				}
			} else if got.err == nil || got.root != (targets.WorkloadIdentityResolution{}) {
				t.Fatal("invalid/cancelled metadata accepted", got)
			}
			select {
			case <-standby.query:
				t.Fatal("identity query reselected a Pod or retried")
			default:
			}
		})
	}
}
